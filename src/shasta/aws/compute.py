"""AWS compute security checks: EC2, EKS, ECS.

Closes a major gap relative to the Azure scanner: until this module
existed, there was no AWS coverage for IMDSv2 enforcement (Capital One
breach vector), public IP inventory, EKS private cluster status,
ECS task hardening, or AMI freshness.

Every check in this module is regional. The runner iterates
``client.get_enabled_regions()`` via ``client.for_region(r)`` per
Engineering Principle #3.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from botocore.exceptions import ClientError

from shasta.aws.client import AWSClient
from shasta.evidence.models import (
    CheckDomain,
    ComplianceStatus,
    Finding,
    Severity,
)


# Module-level marker so the structural multi-region smoke test knows
# this module is regional, not global. See tests/test_aws/test_aws_sweep_smoke.py.
IS_GLOBAL = False


# AMIs older than this without active Image Builder pipelines are flagged.
# Patch Tuesday cadence + ~30 days reasonable buffer.
AMI_AGE_DAYS_THRESHOLD = 90


# ECS task definition fields whose value is a security risk.
ECS_RISKY_LINUX_PARAMETERS = {
    "privileged",  # Container runs as privileged
}


def run_all_aws_compute_checks(client: AWSClient) -> list[Finding]:
    """Run all AWS compute compliance checks across every enabled region."""
    findings: list[Finding] = []
    account_id = client.account_info.account_id if client.account_info else "unknown"
    region = client.account_info.region if client.account_info else "us-east-1"

    try:
        regions = client.get_enabled_regions()
    except ClientError:
        regions = [region]

    for r in regions:
        try:
            rc = client.for_region(r)
            findings.extend(check_ec2_imdsv2_enforced(rc, account_id, r))
            findings.extend(check_ec2_public_ips(rc, account_id, r))
            findings.extend(check_ec2_instance_profile_attached(rc, account_id, r))
            findings.extend(check_ami_age(rc, account_id, r))
            findings.extend(check_eks_private_endpoint(rc, account_id, r))
            findings.extend(check_eks_audit_logging(rc, account_id, r))
            findings.extend(check_eks_secrets_encryption(rc, account_id, r))
            findings.extend(check_ecs_task_privileged(rc, account_id, r))
            findings.extend(check_ecs_task_root_user(rc, account_id, r))
        except ClientError:
            continue

    return findings


# ---------------------------------------------------------------------------
# EC2
# ---------------------------------------------------------------------------


def _list_running_instances(ec2: Any) -> list[dict]:
    """Return all running and stopped EC2 instances in the current region."""
    out: list[dict] = []
    try:
        paginator = ec2.get_paginator("describe_instances")
        for page in paginator.paginate(
            Filters=[{"Name": "instance-state-name", "Values": ["running", "stopped"]}]
        ):
            for reservation in page.get("Reservations", []):
                out.extend(reservation.get("Instances", []))
    except ClientError:
        pass
    return out


def check_ec2_imdsv2_enforced(
    client: AWSClient, account_id: str, region: str
) -> list[Finding]:
    """[CIS AWS 5.6] EC2 instances must enforce IMDSv2 (HttpTokens=required).

    Capital One was breached in 2019 because IMDSv1 allowed an SSRF on a
    web app to reach the instance metadata service and steal IAM role
    credentials. IMDSv2 requires a session token (PUT method) which SSRF
    cannot trivially perform.
    """
    findings: list[Finding] = []
    try:
        ec2 = client.client("ec2")
    except ClientError as e:
        return [Finding.not_assessed(
            check_id="ec2-imdsv2-enforced",
            title="Unable to check EC2 IMDSv2 enforcement",
            description=f"API call failed: {e}",
            domain=CheckDomain.COMPUTE,
            resource_type="AWS::EC2::Instance",
            account_id=account_id,
            region=region,
        )]

    instances = _list_running_instances(ec2)
    if not instances:
        return []

    imdsv1_only: list[dict] = []
    enforced = 0
    for inst in instances:
        instance_id = inst.get("InstanceId", "unknown")
        meta = inst.get("MetadataOptions", {}) or {}
        http_tokens = meta.get("HttpTokens", "optional")
        if http_tokens == "required":
            enforced += 1
        else:
            imdsv1_only.append(
                {
                    "instance_id": instance_id,
                    "name": next(
                        (
                            t["Value"]
                            for t in (inst.get("Tags") or [])
                            if t.get("Key") == "Name"
                        ),
                        "",
                    ),
                    "http_tokens": http_tokens,
                }
            )

    if not imdsv1_only:
        return [
            Finding(
                check_id="ec2-imdsv2-enforced",
                title=f"All {enforced} EC2 instance(s) enforce IMDSv2",
                description="Every running/stopped instance has HttpTokens=required.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.COMPUTE,
                resource_type="AWS::EC2::Instance",
                resource_id=f"arn:aws:ec2:{region}:{account_id}:instance/*",
                region=region,
                account_id=account_id,
                soc2_controls=["CC6.1", "CC6.6"],
                cis_aws_controls=["5.6"],
                details={"instance_count": enforced},
            )
        ]
    return [
        Finding(
            check_id="ec2-imdsv2-enforced",
            title=f"{len(imdsv1_only)} EC2 instance(s) allow IMDSv1",
            description=(
                f"{len(imdsv1_only)} of {len(instances)} instance(s) have HttpTokens=optional, "
                "which means an SSRF on a web app running on the instance can reach 169.254.169.254 "
                "and steal the instance role credentials (the Capital One 2019 breach pattern). "
                "IMDSv2 requires a session token via PUT, which SSRF generally cannot perform."
            ),
            severity=Severity.HIGH,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.COMPUTE,
            resource_type="AWS::EC2::Instance",
            resource_id=f"arn:aws:ec2:{region}:{account_id}:instance/*",
            region=region,
            account_id=account_id,
            remediation=(
                "aws ec2 modify-instance-metadata-options --instance-id <id> "
                "--http-tokens required --http-endpoint enabled --http-put-response-hop-limit 1"
            ),
            soc2_controls=["CC6.1", "CC6.6"],
            cis_aws_controls=["5.6"],
            details={
                "imdsv1_instances": imdsv1_only[:20],
                "total_instances": len(instances),
            },
        )
    ]


def check_ec2_public_ips(
    client: AWSClient, account_id: str, region: str
) -> list[Finding]:
    """EC2 instances with public IPv4 addresses should be inventoried.

    A public IP on an EC2 instance is not necessarily wrong, but it should be
    a deliberate decision (NAT gateway, bastion, public load balancer backend).
    Inventorying them surfaces drift from the "private subnets only" pattern.
    """
    try:
        ec2 = client.client("ec2")
    except ClientError as e:
        return [Finding.not_assessed(
            check_id="ec2-public-ips",
            title="Unable to check EC2 public IPs",
            description=f"API call failed: {e}",
            domain=CheckDomain.COMPUTE,
            resource_type="AWS::EC2::Instance",
            account_id=account_id,
            region=region,
        )]

    instances = _list_running_instances(ec2)
    if not instances:
        return []

    with_public: list[dict] = []
    for inst in instances:
        public_ip = inst.get("PublicIpAddress")
        if public_ip:
            with_public.append(
                {
                    "instance_id": inst.get("InstanceId", "unknown"),
                    "public_ip": public_ip,
                    "name": next(
                        (
                            t["Value"]
                            for t in (inst.get("Tags") or [])
                            if t.get("Key") == "Name"
                        ),
                        "",
                    ),
                }
            )

    if not with_public:
        return [
            Finding(
                check_id="ec2-public-ips",
                title=f"No EC2 instances with public IPv4 in {region}",
                description="All running/stopped instances are in private subnets without public IPs.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.COMPUTE,
                resource_type="AWS::EC2::Instance",
                resource_id=f"arn:aws:ec2:{region}:{account_id}:instance/*",
                region=region,
                account_id=account_id,
                soc2_controls=["CC6.6"],
                cis_aws_controls=["5.x"],
            )
        ]
    return [
        Finding(
            check_id="ec2-public-ips",
            title=f"{len(with_public)} EC2 instance(s) with public IPv4",
            description=(
                f"{len(with_public)} instances have public IPv4 addresses attached. "
                "Each is a potential attack surface — verify each is intentional "
                "(bastion, NAT, customer-facing app) and not drift from a private-subnet "
                "design."
            ),
            severity=Severity.LOW,
            status=ComplianceStatus.PARTIAL,
            domain=CheckDomain.COMPUTE,
            resource_type="AWS::EC2::Instance",
            resource_id=f"arn:aws:ec2:{region}:{account_id}:instance/*",
            region=region,
            account_id=account_id,
            remediation=(
                "Move workloads behind a load balancer or NAT gateway. For instances that "
                "must be public, document why and ensure the security group allows only "
                "the required ports from the required source IP ranges."
            ),
            soc2_controls=["CC6.6"],
            cis_aws_controls=["5.x"],
            details={"public_instances": with_public[:20]},
        )
    ]


def check_ec2_instance_profile_attached(
    client: AWSClient, account_id: str, region: str
) -> list[Finding]:
    """[CIS AWS 1.18] EC2 instances should have an IAM instance profile attached.

    Without an instance profile, the only way an app on the instance can call
    AWS APIs is via long-lived access keys baked into the AMI or fetched from
    a config file — both anti-patterns.
    """
    try:
        ec2 = client.client("ec2")
    except ClientError as e:
        return [Finding.not_assessed(
            check_id="ec2-instance-profile",
            title="Unable to check EC2 instance profiles",
            description=f"API call failed: {e}",
            domain=CheckDomain.IAM,
            resource_type="AWS::EC2::Instance",
            account_id=account_id,
            region=region,
        )]

    instances = _list_running_instances(ec2)
    if not instances:
        return []

    no_profile: list[str] = []
    for inst in instances:
        if not inst.get("IamInstanceProfile"):
            no_profile.append(inst.get("InstanceId", "unknown"))

    if not no_profile:
        return [
            Finding(
                check_id="ec2-instance-profile",
                title=f"All {len(instances)} EC2 instance(s) have an IAM instance profile",
                description="Every running/stopped instance has an IAM role attached.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.IAM,
                resource_type="AWS::EC2::Instance",
                resource_id=f"arn:aws:ec2:{region}:{account_id}:instance/*",
                region=region,
                account_id=account_id,
                soc2_controls=["CC6.1", "CC6.2"],
                cis_aws_controls=["1.18"],
            )
        ]
    return [
        Finding(
            check_id="ec2-instance-profile",
            title=f"{len(no_profile)} EC2 instance(s) without an IAM instance profile",
            description=(
                "Instances without an instance profile cannot use IAM-managed credentials, "
                "so app code must rely on static keys (which need rotation, vaulting, and "
                "access reviews) or run with no AWS access at all."
            ),
            severity=Severity.MEDIUM,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.IAM,
            resource_type="AWS::EC2::Instance",
            resource_id=f"arn:aws:ec2:{region}:{account_id}:instance/*",
            region=region,
            account_id=account_id,
            remediation=(
                "Create a least-privilege IAM role and attach it: "
                "aws ec2 associate-iam-instance-profile --instance-id <id> "
                "--iam-instance-profile Name=<profile-name>"
            ),
            soc2_controls=["CC6.1", "CC6.2"],
            cis_aws_controls=["1.18"],
            details={"instances_without_profile": no_profile[:20]},
        )
    ]


def check_ami_age(
    client: AWSClient, account_id: str, region: str
) -> list[Finding]:
    """EC2 instances should run on AMIs younger than the threshold (default 90 days).

    Stale AMIs accumulate unpatched CVEs. The right pattern is rebuilding the
    AMI on a regular cadence (Image Builder pipeline) and rolling instances.
    """
    try:
        ec2 = client.client("ec2")
    except ClientError as e:
        return [Finding.not_assessed(
            check_id="ec2-ami-age",
            title="Unable to check AMI age",
            description=f"API call failed: {e}",
            domain=CheckDomain.COMPUTE,
            resource_type="AWS::EC2::Image",
            account_id=account_id,
            region=region,
        )]

    instances = _list_running_instances(ec2)
    if not instances:
        return []

    # Collect unique AMI IDs in use
    ami_ids = {inst.get("ImageId") for inst in instances if inst.get("ImageId")}
    if not ami_ids:
        return []

    try:
        ami_resp = ec2.describe_images(ImageIds=list(ami_ids))
        amis = {a["ImageId"]: a for a in ami_resp.get("Images", [])}
    except ClientError as e:
        return [Finding.not_assessed(
            check_id="ec2-ami-age",
            title="Unable to check AMI age",
            description=f"API call failed: {e}",
            domain=CheckDomain.COMPUTE,
            resource_type="AWS::EC2::Image",
            account_id=account_id,
            region=region,
        )]

    threshold = datetime.now(timezone.utc) - timedelta(days=AMI_AGE_DAYS_THRESHOLD)
    stale_amis: list[dict] = []
    for ami_id, ami in amis.items():
        creation = ami.get("CreationDate")
        if not creation:
            continue
        try:
            created = datetime.fromisoformat(creation.replace("Z", "+00:00"))
        except (ValueError, TypeError):
            continue
        if created < threshold:
            stale_amis.append(
                {
                    "ami_id": ami_id,
                    "name": ami.get("Name", ""),
                    "created": creation,
                    "age_days": (datetime.now(timezone.utc) - created).days,
                }
            )

    instances_on_stale = sum(1 for i in instances if i.get("ImageId") in {a["ami_id"] for a in stale_amis})

    if not stale_amis:
        return [
            Finding(
                check_id="ec2-ami-age",
                title=f"All AMIs in use are <{AMI_AGE_DAYS_THRESHOLD} days old",
                description=f"{len(amis)} unique AMI(s) in use, all within the freshness threshold.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.COMPUTE,
                resource_type="AWS::EC2::Image",
                resource_id=f"arn:aws:ec2:{region}:{account_id}:image/*",
                region=region,
                account_id=account_id,
                soc2_controls=["CC7.1"],
                cis_aws_controls=["5.x"],
            )
        ]
    return [
        Finding(
            check_id="ec2-ami-age",
            title=f"{len(stale_amis)} AMI(s) older than {AMI_AGE_DAYS_THRESHOLD} days running {instances_on_stale} instance(s)",
            description=(
                "Stale AMIs accumulate unpatched CVEs between rebuilds. Each instance "
                "running a stale AMI is shipping a snapshot of the security state from "
                "the day the AMI was baked. Modern patterns rebuild the AMI on a regular "
                "cadence and roll instances."
            ),
            severity=Severity.MEDIUM,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.COMPUTE,
            resource_type="AWS::EC2::Image",
            resource_id=f"arn:aws:ec2:{region}:{account_id}:image/*",
            region=region,
            account_id=account_id,
            remediation=(
                "Set up an EC2 Image Builder pipeline that rebuilds your base AMI on a "
                "schedule (weekly or biweekly), bakes in the latest patches, and triggers "
                "an Auto Scaling Group instance refresh to roll instances."
            ),
            soc2_controls=["CC7.1"],
            cis_aws_controls=["5.x"],
            details={"stale_amis": stale_amis[:10], "instances_on_stale": instances_on_stale},
        )
    ]


# ---------------------------------------------------------------------------
# EKS
# ---------------------------------------------------------------------------


def _list_eks_clusters(client: AWSClient) -> list[dict]:
    try:
        eks = client.client("eks")
        names = eks.list_clusters().get("clusters", [])
        out = []
        for name in names:
            try:
                out.append(eks.describe_cluster(name=name).get("cluster", {}))
            except ClientError:
                continue
        return out
    except ClientError:
        return []


def check_eks_private_endpoint(
    client: AWSClient, account_id: str, region: str
) -> list[Finding]:
    """[CIS AWS 5.4.x] EKS API server endpoint should be private (or at least restricted).

    A public EKS API endpoint is reachable from anywhere on the internet. Even
    with IAM auth, it's a brute-force / credential-spray surface. Private cluster
    + bastion is the recommended pattern.
    """
    findings: list[Finding] = []
    for cluster in _list_eks_clusters(client):
        name = cluster.get("name", "unknown")
        arn = cluster.get("arn", "")
        rva = cluster.get("resourcesVpcConfig", {}) or {}
        public = bool(rva.get("endpointPublicAccess", True))
        private = bool(rva.get("endpointPrivateAccess", False))
        cidrs = rva.get("publicAccessCidrs", []) or []
        cidr_unrestricted = "0.0.0.0/0" in cidrs

        if private and not public:
            severity = Severity.INFO
            status = ComplianceStatus.PASS
            title = f"EKS cluster '{name}' has private endpoint only"
            desc = "Private endpoint enabled, public endpoint disabled."
        elif public and not cidr_unrestricted and cidrs:
            severity = Severity.LOW
            status = ComplianceStatus.PARTIAL
            title = f"EKS cluster '{name}' has public endpoint with CIDR allowlist"
            desc = f"Public endpoint active but restricted to: {', '.join(cidrs[:5])}."
        else:
            severity = Severity.HIGH
            status = ComplianceStatus.FAIL
            title = f"EKS cluster '{name}' has unrestricted public API endpoint"
            desc = (
                "API server reachable from 0.0.0.0/0. Anyone on the internet can attempt "
                "to authenticate. Even with IAM/OIDC auth, the endpoint is a credential-"
                "spray surface."
            )

        findings.append(
            Finding(
                check_id="eks-private-endpoint",
                title=title,
                description=desc,
                severity=severity,
                status=status,
                domain=CheckDomain.NETWORKING,
                resource_type="AWS::EKS::Cluster",
                resource_id=arn,
                region=region,
                account_id=account_id,
                remediation=(
                    "aws eks update-cluster-config --name <cluster> "
                    "--resources-vpc-config endpointPublicAccess=false,endpointPrivateAccess=true"
                )
                if status != ComplianceStatus.PASS
                else "",
                soc2_controls=["CC6.6"],
                cis_aws_controls=["5.4.x"],
                details={
                    "cluster": name,
                    "endpoint_public": public,
                    "endpoint_private": private,
                    "public_cidrs": cidrs,
                },
            )
        )
    return findings


def check_eks_audit_logging(
    client: AWSClient, account_id: str, region: str
) -> list[Finding]:
    """[CIS AWS 5.4.x] EKS control plane logging should include audit + authenticator.

    Without these log types, you cannot reconstruct who did what in the cluster
    after a security incident. EKS lets you enable api / audit / authenticator /
    controllerManager / scheduler — all five are recommended for SOC 2.
    """
    findings: list[Finding] = []
    REQUIRED = {"api", "audit", "authenticator"}

    for cluster in _list_eks_clusters(client):
        name = cluster.get("name", "unknown")
        arn = cluster.get("arn", "")
        logging = (cluster.get("logging") or {}).get("clusterLogging", []) or []
        enabled_types: set[str] = set()
        for entry in logging:
            if entry.get("enabled"):
                enabled_types.update(entry.get("types", []))

        missing = REQUIRED - enabled_types
        if not missing:
            findings.append(
                Finding(
                    check_id="eks-audit-logging",
                    title=f"EKS cluster '{name}' has required control plane logs enabled",
                    description=f"Enabled log types: {', '.join(sorted(enabled_types))}.",
                    severity=Severity.INFO,
                    status=ComplianceStatus.PASS,
                    domain=CheckDomain.LOGGING,
                    resource_type="AWS::EKS::Cluster",
                    resource_id=arn,
                    region=region,
                    account_id=account_id,
                    soc2_controls=["CC7.1", "CC8.1"],
                    cis_aws_controls=["5.4.x"],
                    details={"cluster": name, "enabled_types": sorted(enabled_types)},
                )
            )
        else:
            findings.append(
                Finding(
                    check_id="eks-audit-logging",
                    title=f"EKS cluster '{name}' missing log types: {', '.join(sorted(missing))}",
                    description=(
                        f"Required EKS control plane log types not enabled: {', '.join(sorted(missing))}. "
                        "Without audit + authenticator logs, you cannot reconstruct who issued "
                        "kubectl commands during an incident."
                    ),
                    severity=Severity.MEDIUM,
                    status=ComplianceStatus.FAIL,
                    domain=CheckDomain.LOGGING,
                    resource_type="AWS::EKS::Cluster",
                    resource_id=arn,
                    region=region,
                    account_id=account_id,
                    remediation=(
                        f"aws eks update-cluster-config --name {name} "
                        '--logging \'{"clusterLogging":[{"types":["api","audit","authenticator","controllerManager","scheduler"],"enabled":true}]}\''
                    ),
                    soc2_controls=["CC7.1", "CC8.1"],
                    cis_aws_controls=["5.4.x"],
                    details={
                        "cluster": name,
                        "enabled_types": sorted(enabled_types),
                        "missing_types": sorted(missing),
                    },
                )
            )
    return findings


def check_eks_secrets_encryption(
    client: AWSClient, account_id: str, region: str
) -> list[Finding]:
    """[CIS AWS 5.4.x] EKS clusters should encrypt Kubernetes secrets with KMS.

    By default, Kubernetes secrets are stored base64-encoded (not encrypted) in
    etcd. EKS supports envelope encryption with a customer-managed KMS key —
    enabling it means a stolen etcd backup is not the same as stolen secrets.
    """
    findings: list[Finding] = []
    for cluster in _list_eks_clusters(client):
        name = cluster.get("name", "unknown")
        arn = cluster.get("arn", "")
        encryption_config = cluster.get("encryptionConfig") or []
        secrets_encrypted = any(
            "secrets" in (e.get("resources") or []) for e in encryption_config
        )

        if secrets_encrypted:
            findings.append(
                Finding(
                    check_id="eks-secrets-encryption",
                    title=f"EKS cluster '{name}' encrypts Kubernetes secrets with KMS",
                    description="Envelope encryption configured for the 'secrets' resource type.",
                    severity=Severity.INFO,
                    status=ComplianceStatus.PASS,
                    domain=CheckDomain.ENCRYPTION,
                    resource_type="AWS::EKS::Cluster",
                    resource_id=arn,
                    region=region,
                    account_id=account_id,
                    soc2_controls=["CC6.7"],
                    cis_aws_controls=["5.4.x"],
                )
            )
        else:
            findings.append(
                Finding(
                    check_id="eks-secrets-encryption",
                    title=f"EKS cluster '{name}' has no envelope encryption for secrets",
                    description=(
                        "Kubernetes secrets are stored base64-encoded in etcd, not encrypted. "
                        "A stolen etcd snapshot or compromised control plane node exposes "
                        "every secret in the cluster — service account tokens, image pull "
                        "secrets, app credentials."
                    ),
                    severity=Severity.MEDIUM,
                    status=ComplianceStatus.FAIL,
                    domain=CheckDomain.ENCRYPTION,
                    resource_type="AWS::EKS::Cluster",
                    resource_id=arn,
                    region=region,
                    account_id=account_id,
                    remediation=(
                        "Envelope encryption can only be enabled at cluster creation OR via "
                        "associate-encryption-config on existing clusters since EKS 1.22+. "
                        "Run: aws eks associate-encryption-config --cluster-name <name> "
                        "--encryption-config resources=secrets,provider={keyArn=<kms-key-arn>}"
                    ),
                    soc2_controls=["CC6.7"],
                    cis_aws_controls=["5.4.x"],
                )
            )
    return findings


# ---------------------------------------------------------------------------
# ECS
# ---------------------------------------------------------------------------


def _list_ecs_task_definitions(client: AWSClient) -> list[dict]:
    """Return ACTIVE task definitions only (latest revision per family)."""
    try:
        ecs = client.client("ecs")
        # families gives us one entry per family; we get the latest active revision
        family_resp = ecs.list_task_definition_families(status="ACTIVE")
        families = family_resp.get("families", [])
        out = []
        for fam in families[:200]:  # cap to avoid runaway scans
            try:
                td = ecs.describe_task_definition(taskDefinition=fam).get("taskDefinition", {})
                out.append(td)
            except ClientError:
                continue
        return out
    except ClientError:
        return []


def check_ecs_task_privileged(
    client: AWSClient, account_id: str, region: str
) -> list[Finding]:
    """[CIS AWS 5.x] ECS task definitions should not run containers in privileged mode.

    Privileged containers can access the host kernel, mount filesystems, and
    escape the container boundary. They are almost never needed in production
    application workloads.
    """
    task_defs = _list_ecs_task_definitions(client)
    if not task_defs:
        return []

    privileged: list[dict] = []
    for td in task_defs:
        family = td.get("family", "unknown")
        for cd in td.get("containerDefinitions", []) or []:
            if cd.get("privileged"):
                privileged.append(
                    {
                        "family": family,
                        "container": cd.get("name", "unknown"),
                        "revision": td.get("revision"),
                    }
                )

    if not privileged:
        return [
            Finding(
                check_id="ecs-task-privileged",
                title=f"No privileged containers in {len(task_defs)} ECS task def(s)",
                description="No container definition sets privileged=true.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.COMPUTE,
                resource_type="AWS::ECS::TaskDefinition",
                resource_id=f"arn:aws:ecs:{region}:{account_id}:task-definition/*",
                region=region,
                account_id=account_id,
                soc2_controls=["CC6.1", "CC6.6"],
                cis_aws_controls=["5.x"],
            )
        ]
    return [
        Finding(
            check_id="ecs-task-privileged",
            title=f"{len(privileged)} privileged container(s) in ECS task definitions",
            description=(
                "Privileged containers can mount host filesystems, load kernel modules, "
                "and escape the container boundary. They should only be used for very "
                "specific systems-level workloads (e.g. node-exporter, network plugins), "
                "never for application code."
            ),
            severity=Severity.HIGH,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.COMPUTE,
            resource_type="AWS::ECS::TaskDefinition",
            resource_id=f"arn:aws:ecs:{region}:{account_id}:task-definition/*",
            region=region,
            account_id=account_id,
            remediation=(
                "Remove privileged=true from the container definition. If a system-level "
                "capability is genuinely required, grant it specifically via linuxParameters.capabilities.add "
                "instead of opening the entire privileged surface."
            ),
            soc2_controls=["CC6.1", "CC6.6"],
            cis_aws_controls=["5.x"],
            details={"privileged_containers": privileged[:20]},
        )
    ]


def check_ecs_task_root_user(
    client: AWSClient, account_id: str, region: str
) -> list[Finding]:
    """[CIS AWS 5.x] ECS task definitions should not run containers as root (uid 0).

    Containers running as root that are exploited give the attacker root inside
    the container — which, combined with any kernel CVE or container escape
    bug, can compromise the host.
    """
    task_defs = _list_ecs_task_definitions(client)
    if not task_defs:
        return []

    root_running: list[dict] = []
    for td in task_defs:
        family = td.get("family", "unknown")
        for cd in td.get("containerDefinitions", []) or []:
            user = cd.get("user", "")
            # Empty string means root by default
            is_root = (user == "" or user == "root" or user == "0" or user.startswith("0:"))
            if is_root:
                root_running.append(
                    {
                        "family": family,
                        "container": cd.get("name", "unknown"),
                        "user": user or "<default=root>",
                    }
                )

    if not root_running:
        return [
            Finding(
                check_id="ecs-task-root-user",
                title=f"No containers running as root in {len(task_defs)} ECS task def(s)",
                description="Every container definition has an explicit non-root user.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.COMPUTE,
                resource_type="AWS::ECS::TaskDefinition",
                resource_id=f"arn:aws:ecs:{region}:{account_id}:task-definition/*",
                region=region,
                account_id=account_id,
                soc2_controls=["CC6.1", "CC6.6"],
                cis_aws_controls=["5.x"],
            )
        ]
    return [
        Finding(
            check_id="ecs-task-root-user",
            title=f"{len(root_running)} ECS container(s) running as root",
            description=(
                f"{len(root_running)} container definition(s) have no explicit non-root user "
                "(or use uid 0). Containerized apps almost never need root — set USER in the "
                "Dockerfile and 'user' in the task definition."
            ),
            severity=Severity.MEDIUM,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.COMPUTE,
            resource_type="AWS::ECS::TaskDefinition",
            resource_id=f"arn:aws:ecs:{region}:{account_id}:task-definition/*",
            region=region,
            account_id=account_id,
            remediation=(
                "In the Dockerfile add `USER 1000` (or your non-root uid). In the task "
                "definition set 'user': '1000' on the container. Verify the app can write "
                "to whatever directories it needs (often /tmp)."
            ),
            soc2_controls=["CC6.1", "CC6.6"],
            cis_aws_controls=["5.x"],
            details={"root_containers": root_running[:20]},
        )
    ]
