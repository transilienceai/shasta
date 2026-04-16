"""Encryption checks for SOC 2 compliance.

Covers:
  CC6.7 — Data protection at rest (EBS volumes, RDS instances)
  A1.2  — Recovery / backups (RDS automated backups, multi-AZ)
"""

from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from shasta.aws.client import AWSClient
from shasta.evidence.models import CheckDomain, ComplianceStatus, Finding, Severity


def run_all_encryption_checks(client: AWSClient) -> list[Finding]:
    """Run all EBS and RDS encryption checks across every enabled region."""
    findings: list[Finding] = []
    account_id = client.account_info.account_id if client.account_info else "unknown"
    region = client.account_info.region if client.account_info else "us-east-1"

    try:
        regions = client.get_enabled_regions()
    except ClientError:
        regions = [region]

    # Multi-region rollup checks (per-region settings)
    findings.extend(check_ebs_encryption_default(client, account_id, region, regions))

    # Per-region resource checks
    for r in regions:
        try:
            rc = client.for_region(r)
            findings.extend(check_ebs_volumes(rc, account_id, r))
            findings.extend(check_rds_encryption(rc, account_id, r))
            findings.extend(check_rds_public_access(rc, account_id, r))
            findings.extend(check_rds_backups(rc, account_id, r))
            findings.extend(check_efs_encryption(rc, account_id, r))
            findings.extend(check_sns_topic_encryption(rc, account_id, r))
            findings.extend(check_sqs_queue_encryption(rc, account_id, r))
            findings.extend(check_secrets_manager_rotation(rc, account_id, r))
            findings.extend(check_acm_expiring_certificates(rc, account_id, r))
        except ClientError:
            continue

    return findings


# ---------------------------------------------------------------------------
# CIS AWS v3.0 Stage 1 — EFS, SNS, SQS, Secrets Manager, ACM
# ---------------------------------------------------------------------------


def check_efs_encryption(client: AWSClient, account_id: str, region: str) -> list[Finding]:
    """[CIS AWS 2.4] EFS file systems must be encrypted at rest."""
    findings: list[Finding] = []
    try:
        efs = client.client("efs")
        fs_list = efs.describe_file_systems().get("FileSystems", [])
    except ClientError as e:
        return [Finding.not_assessed(
            check_id="efs-encryption",
            title="Unable to check EFS encryption",
            description=f"API call failed: {e}",
            domain=CheckDomain.ENCRYPTION,
            resource_type="AWS::EFS::FileSystem",
            account_id=account_id,
            region=region,
        )]

    for fs in fs_list:
        fs_id = fs.get("FileSystemId", "unknown")
        encrypted = bool(fs.get("Encrypted", False))
        arn = f"arn:aws:elasticfilesystem:{region}:{account_id}:file-system/{fs_id}"
        if encrypted:
            findings.append(
                Finding(
                    check_id="efs-encryption",
                    title=f"EFS file system '{fs_id}' is encrypted",
                    description=f"KMS key: {fs.get('KmsKeyId', 'aws-managed')}.",
                    severity=Severity.INFO,
                    status=ComplianceStatus.PASS,
                    domain=CheckDomain.ENCRYPTION,
                    resource_type="AWS::EFS::FileSystem",
                    resource_id=arn,
                    region=region,
                    account_id=account_id,
                    soc2_controls=["CC6.7"],
                    cis_aws_controls=["2.4"],
                    details={"file_system_id": fs_id, "kms_key_id": fs.get("KmsKeyId")},
                )
            )
        else:
            findings.append(
                Finding(
                    check_id="efs-encryption",
                    title=f"EFS file system '{fs_id}' is NOT encrypted",
                    description=(
                        "EFS encryption can only be enabled at creation. An unencrypted file "
                        "system means data is stored in clear on Amazon's disks."
                    ),
                    severity=Severity.HIGH,
                    status=ComplianceStatus.FAIL,
                    domain=CheckDomain.ENCRYPTION,
                    resource_type="AWS::EFS::FileSystem",
                    resource_id=arn,
                    region=region,
                    account_id=account_id,
                    remediation=(
                        "Create a new encrypted EFS file system, replicate the data via "
                        "AWS DataSync, then cut over and delete the old one."
                    ),
                    soc2_controls=["CC6.7"],
                    cis_aws_controls=["2.4"],
                    details={"file_system_id": fs_id},
                )
            )

    return findings


def check_sns_topic_encryption(client: AWSClient, account_id: str, region: str) -> list[Finding]:
    """[CIS AWS] SNS topics should be encrypted at rest with KMS."""
    findings: list[Finding] = []
    try:
        sns = client.client("sns")
        paginator = sns.get_paginator("list_topics")
        topics: list[str] = []
        for page in paginator.paginate():
            topics.extend(t["TopicArn"] for t in page.get("Topics", []))
    except ClientError as e:
        return [Finding.not_assessed(
            check_id="sns-encryption",
            title="Unable to check SNS topic encryption",
            description=f"API call failed: {e}",
            domain=CheckDomain.ENCRYPTION,
            resource_type="AWS::SNS::Topic",
            account_id=account_id,
            region=region,
        )]

    encrypted = 0
    unencrypted: list[str] = []
    for arn in topics:
        try:
            attrs = sns.get_topic_attributes(TopicArn=arn).get("Attributes", {})
            if attrs.get("KmsMasterKeyId"):
                encrypted += 1
            else:
                unencrypted.append(arn)
        except ClientError:
            continue

    if not topics:
        return []

    if not unencrypted:
        return [
            Finding(
                check_id="sns-encryption",
                title=f"All {encrypted} SNS topic(s) encrypted with KMS",
                description="Every SNS topic has a KmsMasterKeyId set.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.ENCRYPTION,
                resource_type="AWS::SNS::Topic",
                resource_id=f"arn:aws:sns:{region}:{account_id}:*",
                region=region,
                account_id=account_id,
                soc2_controls=["CC6.7"],
                cis_aws_controls=["2.5"],
            )
        ]
    return [
        Finding(
            check_id="sns-encryption",
            title=f"{len(unencrypted)} SNS topic(s) without KMS encryption",
            description=(
                f"{len(unencrypted)} of {len(topics)} SNS topics have no KmsMasterKeyId. "
                "Messages in flight may carry sensitive data and at-rest queue contents are "
                "stored unencrypted."
            ),
            severity=Severity.MEDIUM,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.ENCRYPTION,
            resource_type="AWS::SNS::Topic",
            resource_id=f"arn:aws:sns:{region}:{account_id}:*",
            region=region,
            account_id=account_id,
            remediation=(
                "aws sns set-topic-attributes --topic-arn <arn> "
                "--attribute-name KmsMasterKeyId --attribute-value alias/aws/sns"
            ),
            soc2_controls=["CC6.7"],
            cis_aws_controls=["2.5"],
            details={"unencrypted_topics": unencrypted[:20], "total": len(topics)},
        )
    ]


def check_sqs_queue_encryption(client: AWSClient, account_id: str, region: str) -> list[Finding]:
    """[CIS AWS] SQS queues should be encrypted at rest with KMS or SSE."""
    findings: list[Finding] = []
    try:
        sqs = client.client("sqs")
        queues = sqs.list_queues().get("QueueUrls", [])
    except ClientError as e:
        return [Finding.not_assessed(
            check_id="sqs-encryption",
            title="Unable to check SQS queue encryption",
            description=f"API call failed: {e}",
            domain=CheckDomain.ENCRYPTION,
            resource_type="AWS::SQS::Queue",
            account_id=account_id,
            region=region,
        )]

    encrypted = 0
    unencrypted: list[str] = []
    for q in queues:
        try:
            attrs = sqs.get_queue_attributes(QueueUrl=q, AttributeNames=["All"]).get(
                "Attributes", {}
            )
            if attrs.get("KmsMasterKeyId") or attrs.get("SqsManagedSseEnabled") == "true":
                encrypted += 1
            else:
                unencrypted.append(q)
        except ClientError:
            continue

    if not queues:
        return []

    if not unencrypted:
        return [
            Finding(
                check_id="sqs-encryption",
                title=f"All {encrypted} SQS queue(s) encrypted",
                description="Every queue uses KMS or SQS-managed SSE.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.ENCRYPTION,
                resource_type="AWS::SQS::Queue",
                resource_id=f"arn:aws:sqs:{region}:{account_id}:*",
                region=region,
                account_id=account_id,
                soc2_controls=["CC6.7"],
                cis_aws_controls=["2.6"],
            )
        ]
    return [
        Finding(
            check_id="sqs-encryption",
            title=f"{len(unencrypted)} SQS queue(s) without encryption at rest",
            description=(
                f"{len(unencrypted)} of {len(queues)} queues have neither KMS nor SQS-managed SSE."
            ),
            severity=Severity.MEDIUM,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.ENCRYPTION,
            resource_type="AWS::SQS::Queue",
            resource_id=f"arn:aws:sqs:{region}:{account_id}:*",
            region=region,
            account_id=account_id,
            remediation=(
                "aws sqs set-queue-attributes --queue-url <url> "
                "--attributes SqsManagedSseEnabled=true"
            ),
            soc2_controls=["CC6.7"],
            cis_aws_controls=["2.6"],
            details={"unencrypted_queues": unencrypted[:20]},
        )
    ]


def check_secrets_manager_rotation(
    client: AWSClient, account_id: str, region: str
) -> list[Finding]:
    """[CIS AWS] Secrets Manager secrets should have automatic rotation enabled."""
    findings: list[Finding] = []
    try:
        sm = client.client("secretsmanager")
        paginator = sm.get_paginator("list_secrets")
        secrets = []
        for page in paginator.paginate():
            secrets.extend(page.get("SecretList", []))
    except ClientError as e:
        return [Finding.not_assessed(
            check_id="secrets-manager-rotation",
            title="Unable to check Secrets Manager rotation",
            description=f"API call failed: {e}",
            domain=CheckDomain.ENCRYPTION,
            resource_type="AWS::SecretsManager::Secret",
            account_id=account_id,
            region=region,
        )]

    if not secrets:
        return []

    no_rotation = [s for s in secrets if not s.get("RotationEnabled")]
    if not no_rotation:
        return [
            Finding(
                check_id="secrets-manager-rotation",
                title=f"All {len(secrets)} secret(s) have rotation enabled",
                description="Every Secrets Manager secret has automatic rotation configured.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.ENCRYPTION,
                resource_type="AWS::SecretsManager::Secret",
                resource_id=f"arn:aws:secretsmanager:{region}:{account_id}:secret/*",
                region=region,
                account_id=account_id,
                soc2_controls=["CC6.1", "CC6.7"],
                cis_aws_controls=["1.10"],
            )
        ]
    return [
        Finding(
            check_id="secrets-manager-rotation",
            title=f"{len(no_rotation)} of {len(secrets)} secret(s) lack automatic rotation",
            description=(
                "Secrets without automatic rotation accumulate risk — credentials cycle outside "
                "any policy and stale secrets persist after staff turnover."
            ),
            severity=Severity.MEDIUM,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.ENCRYPTION,
            resource_type="AWS::SecretsManager::Secret",
            resource_id=f"arn:aws:secretsmanager:{region}:{account_id}:secret/*",
            region=region,
            account_id=account_id,
            remediation=(
                "For each secret, attach a Lambda rotation function and enable rotation "
                "with a 30-90 day schedule. AWS provides templates for common backends."
            ),
            soc2_controls=["CC6.1", "CC6.7"],
            cis_aws_controls=["1.10"],
            details={
                "secrets_without_rotation": [s.get("Name") for s in no_rotation[:20]],
                "total": len(secrets),
            },
        )
    ]


def check_acm_expiring_certificates(
    client: AWSClient, account_id: str, region: str
) -> list[Finding]:
    """[CIS AWS] ACM certificates expiring within 30 days should be flagged."""
    from datetime import datetime, timedelta, timezone

    findings: list[Finding] = []
    try:
        acm = client.client("acm")
        paginator = acm.get_paginator("list_certificates")
        certs = []
        for page in paginator.paginate():
            certs.extend(page.get("CertificateSummaryList", []))
    except ClientError as e:
        return [Finding.not_assessed(
            check_id="acm-expiring-certs",
            title="Unable to check ACM certificates",
            description=f"API call failed: {e}",
            domain=CheckDomain.ENCRYPTION,
            resource_type="AWS::CertificateManager::Certificate",
            account_id=account_id,
            region=region,
        )]

    if not certs:
        return []

    threshold = datetime.now(timezone.utc) + timedelta(days=30)
    expiring: list[dict] = []
    for c in certs:
        not_after = c.get("NotAfter")
        if not_after and not_after < threshold:
            expiring.append(
                {
                    "arn": c.get("CertificateArn"),
                    "domain": c.get("DomainName"),
                    "expires": not_after.isoformat() if not_after else None,
                }
            )

    if not expiring:
        return [
            Finding(
                check_id="acm-expiring-certs",
                title=f"All {len(certs)} ACM cert(s) valid for >30 days",
                description="No certificates expiring within the next 30 days.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.ENCRYPTION,
                resource_type="AWS::CertificateManager::Certificate",
                resource_id=f"arn:aws:acm:{region}:{account_id}:certificate/*",
                region=region,
                account_id=account_id,
                soc2_controls=["CC6.1", "CC6.7"],
                cis_aws_controls=["2.x"],
            )
        ]
    return [
        Finding(
            check_id="acm-expiring-certs",
            title=f"{len(expiring)} ACM cert(s) expiring within 30 days",
            description=(
                "Expired certificates break TLS for whatever they're attached to (CloudFront, "
                "ALB, API Gateway). Set up renewal alarms or use ACM auto-renewal."
            ),
            severity=Severity.HIGH,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.ENCRYPTION,
            resource_type="AWS::CertificateManager::Certificate",
            resource_id=f"arn:aws:acm:{region}:{account_id}:certificate/*",
            region=region,
            account_id=account_id,
            remediation=(
                "ACM auto-renews public DNS-validated certs ~60 days before expiry. For "
                "imported certs, replace them. For email-validated certs, switch to DNS validation."
            ),
            soc2_controls=["CC6.1", "CC6.7"],
            cis_aws_controls=["2.x"],
            details={"expiring": expiring[:20]},
        )
    ]


def check_ebs_encryption_default(
    client: AWSClient,
    account_id: str,
    region: str,
    regions: list[str] | None = None,
) -> list[Finding]:
    """CC6.7 — Check EBS encryption-by-default across every enabled region.

    Emits one PASS finding listing regions where it's enabled, and one FAIL
    finding per region where it's disabled.
    """
    findings: list[Finding] = []

    if regions is None:
        try:
            regions = client.get_enabled_regions()
        except ClientError:
            regions = [region]

    enabled_regions: list[str] = []
    disabled_regions: list[str] = []

    for r in regions:
        try:
            ec2 = client.for_region(r).client("ec2")
            response = ec2.get_ebs_encryption_by_default()
            if response.get("EbsEncryptionByDefault", False):
                enabled_regions.append(r)
            else:
                disabled_regions.append(r)
        except ClientError:
            continue

    if enabled_regions:
        findings.append(
            Finding(
                check_id="ebs-encryption-by-default",
                title=f"EBS encryption by default is enabled in {len(enabled_regions)} region(s)",
                description=f"EBS encryption by default is enabled in: {', '.join(sorted(enabled_regions))}. All new EBS volumes in these regions will be automatically encrypted.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.ENCRYPTION,
                resource_type="AWS::EC2::EBSEncryption",
                resource_id=f"arn:aws:ec2:{enabled_regions[0]}:{account_id}:ebs-default-encryption",
                region=enabled_regions[0],
                account_id=account_id,
                soc2_controls=["CC6.7"],
                details={
                    "enabled_regions": sorted(enabled_regions),
                    "disabled_regions": sorted(disabled_regions),
                },
            )
        )

    for r in sorted(disabled_regions):
        findings.append(
            Finding(
                check_id="ebs-encryption-by-default",
                title=f"EBS encryption by default is NOT enabled in {r}",
                description=f"EBS encryption by default is disabled in {r}. New EBS volumes will be created unencrypted unless explicitly specified. An engineer could accidentally create an unencrypted volume.",
                severity=Severity.HIGH,
                status=ComplianceStatus.FAIL,
                domain=CheckDomain.ENCRYPTION,
                resource_type="AWS::EC2::EBSEncryption",
                resource_id=f"arn:aws:ec2:{r}:{account_id}:ebs-default-encryption",
                region=r,
                account_id=account_id,
                remediation=f"Enable EBS encryption by default in {r}: AWS Console > EC2 > Settings > EBS encryption > Enable. Or via CLI: aws ec2 enable-ebs-encryption-by-default --region {r}",
                soc2_controls=["CC6.7"],
                details={"enabled": False, "region": r},
            )
        )

    return findings


def check_ebs_volumes(client: AWSClient, account_id: str, region: str) -> list[Finding]:
    """CC6.7 — Check that all existing EBS volumes are encrypted."""
    findings = []
    ec2 = client.client("ec2")

    try:
        paginator = ec2.get_paginator("describe_volumes")
        unencrypted = []
        encrypted_count = 0
        total = 0

        for page in paginator.paginate():
            for vol in page["Volumes"]:
                total += 1
                vol_id = vol["VolumeId"]
                is_encrypted = vol.get("Encrypted", False)

                if not is_encrypted:
                    # Get name tag
                    name = ""
                    for tag in vol.get("Tags", []):
                        if tag["Key"] == "Name":
                            name = tag["Value"]

                    attachments = vol.get("Attachments", [])
                    attached_to = (
                        attachments[0].get("InstanceId", "unattached")
                        if attachments
                        else "unattached"
                    )

                    unencrypted.append(
                        {
                            "volume_id": vol_id,
                            "name": name,
                            "size_gb": vol.get("Size", 0),
                            "state": vol.get("State", ""),
                            "attached_to": attached_to,
                        }
                    )
                else:
                    encrypted_count += 1

        if total == 0:
            return []  # No volumes, nothing to check

        if unencrypted:
            for vol in unencrypted:
                findings.append(
                    Finding(
                        check_id="ebs-volume-encrypted",
                        title=f"EBS volume {vol['volume_id']} is NOT encrypted",
                        description=f"EBS volume {vol['volume_id']}"
                        + (f" ({vol['name']})" if vol["name"] else "")
                        + f" ({vol['size_gb']} GB, attached to {vol['attached_to']}) is not encrypted. Data at rest on this volume is not protected.",
                        severity=Severity.HIGH,
                        status=ComplianceStatus.FAIL,
                        domain=CheckDomain.ENCRYPTION,
                        resource_type="AWS::EC2::Volume",
                        resource_id=vol["volume_id"],
                        region=region,
                        account_id=account_id,
                        remediation=f"EBS volumes cannot be encrypted in-place. Create an encrypted snapshot, then create a new encrypted volume from it, and swap. Enable EBS encryption by default to prevent future unencrypted volumes.",
                        soc2_controls=["CC6.7"],
                        details=vol,
                    )
                )
        else:
            findings.append(
                Finding(
                    check_id="ebs-volume-encrypted",
                    title=f"All {total} EBS volumes are encrypted",
                    description=f"All {total} EBS volume(s) in this region are encrypted at rest.",
                    severity=Severity.INFO,
                    status=ComplianceStatus.PASS,
                    domain=CheckDomain.ENCRYPTION,
                    resource_type="AWS::EC2::Volume",
                    resource_id=f"arn:aws:ec2:{region}:{account_id}:volumes",
                    region=region,
                    account_id=account_id,
                    soc2_controls=["CC6.7"],
                    details={"total": total, "encrypted": encrypted_count},
                )
            )

    except ClientError as e:
        return [Finding.not_assessed(
            check_id="ebs-volume-encrypted",
            title="Unable to check EBS volume encryption",
            description=f"API call failed: {e}",
            domain=CheckDomain.ENCRYPTION,
            resource_type="AWS::EC2::Volume",
            account_id=account_id,
            region=region,
        )]

    return findings


def check_rds_encryption(client: AWSClient, account_id: str, region: str) -> list[Finding]:
    """CC6.7 — Check that all RDS instances have encryption at rest enabled."""
    findings = []
    rds = client.client("rds")

    try:
        paginator = rds.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            for db in page["DBInstances"]:
                db_id = db["DBInstanceIdentifier"]
                db_arn = db["DBInstanceArn"]
                encrypted = db.get("StorageEncrypted", False)
                engine = db.get("Engine", "unknown")
                instance_class = db.get("DBInstanceClass", "unknown")

                if encrypted:
                    kms_key = db.get("KmsKeyId", "default")
                    findings.append(
                        Finding(
                            check_id="rds-encryption-at-rest",
                            title=f"RDS instance '{db_id}' is encrypted",
                            description=f"RDS instance '{db_id}' ({engine}, {instance_class}) has storage encryption enabled.",
                            severity=Severity.INFO,
                            status=ComplianceStatus.PASS,
                            domain=CheckDomain.ENCRYPTION,
                            resource_type="AWS::RDS::DBInstance",
                            resource_id=db_arn,
                            region=region,
                            account_id=account_id,
                            soc2_controls=["CC6.7"],
                            details={
                                "db_id": db_id,
                                "engine": engine,
                                "encrypted": True,
                                "kms_key": kms_key,
                            },
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            check_id="rds-encryption-at-rest",
                            title=f"RDS instance '{db_id}' is NOT encrypted",
                            description=f"RDS instance '{db_id}' ({engine}, {instance_class}) does not have storage encryption enabled. Database data at rest is not protected.",
                            severity=Severity.HIGH,
                            status=ComplianceStatus.FAIL,
                            domain=CheckDomain.ENCRYPTION,
                            resource_type="AWS::RDS::DBInstance",
                            resource_id=db_arn,
                            region=region,
                            account_id=account_id,
                            remediation=f"RDS encryption cannot be enabled on an existing unencrypted instance. Create an encrypted snapshot, restore to a new encrypted instance, then switch over. Enable encryption for all new instances.",
                            soc2_controls=["CC6.7"],
                            details={"db_id": db_id, "engine": engine, "encrypted": False},
                        )
                    )
    except ClientError as e:
        return [Finding.not_assessed(
            check_id="rds-encryption-at-rest",
            title="Unable to check RDS encryption",
            description=f"API call failed: {e}",
            domain=CheckDomain.ENCRYPTION,
            resource_type="AWS::RDS::DBInstance",
            account_id=account_id,
            region=region,
        )]

    return findings


def check_rds_public_access(client: AWSClient, account_id: str, region: str) -> list[Finding]:
    """CC6.6 — Check that RDS instances are not publicly accessible."""
    findings = []
    rds = client.client("rds")

    try:
        paginator = rds.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            for db in page["DBInstances"]:
                db_id = db["DBInstanceIdentifier"]
                db_arn = db["DBInstanceArn"]
                publicly_accessible = db.get("PubliclyAccessible", False)

                if publicly_accessible:
                    endpoint = db.get("Endpoint", {}).get("Address", "unknown")
                    findings.append(
                        Finding(
                            check_id="rds-no-public-access",
                            title=f"RDS instance '{db_id}' is publicly accessible",
                            description=f"RDS instance '{db_id}' (endpoint: {endpoint}) is configured as publicly accessible. Databases should never be directly reachable from the internet.",
                            severity=Severity.CRITICAL,
                            status=ComplianceStatus.FAIL,
                            domain=CheckDomain.ENCRYPTION,
                            resource_type="AWS::RDS::DBInstance",
                            resource_id=db_arn,
                            region=region,
                            account_id=account_id,
                            remediation=f"Modify RDS instance '{db_id}' to set PubliclyAccessible = false. Access should be through private subnets or VPN only.",
                            soc2_controls=["CC6.6", "CC6.7"],
                            details={
                                "db_id": db_id,
                                "publicly_accessible": True,
                                "endpoint": endpoint,
                            },
                        )
                    )
    except ClientError as e:
        return [Finding.not_assessed(
            check_id="rds-no-public-access",
            title="Unable to check RDS public access",
            description=f"API call failed: {e}",
            domain=CheckDomain.ENCRYPTION,
            resource_type="AWS::RDS::DBInstance",
            account_id=account_id,
            region=region,
        )]

    return findings


def check_rds_backups(client: AWSClient, account_id: str, region: str) -> list[Finding]:
    """A1.2 — Check that RDS instances have automated backups enabled."""
    findings = []
    rds = client.client("rds")

    try:
        paginator = rds.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            for db in page["DBInstances"]:
                db_id = db["DBInstanceIdentifier"]
                db_arn = db["DBInstanceArn"]
                retention = db.get("BackupRetentionPeriod", 0)
                multi_az = db.get("MultiAZ", False)

                issues = []
                if retention == 0:
                    issues.append("Automated backups disabled (retention = 0)")
                elif retention < 7:
                    issues.append(f"Backup retention only {retention} days (recommend 7+)")

                if not multi_az:
                    issues.append("Not Multi-AZ (single point of failure)")

                if issues:
                    findings.append(
                        Finding(
                            check_id="rds-backup-enabled",
                            title=f"RDS instance '{db_id}' has backup/availability issues",
                            description=f"RDS instance '{db_id}': {'; '.join(issues)}",
                            severity=Severity.HIGH if retention == 0 else Severity.MEDIUM,
                            status=ComplianceStatus.FAIL,
                            domain=CheckDomain.ENCRYPTION,
                            resource_type="AWS::RDS::DBInstance",
                            resource_id=db_arn,
                            region=region,
                            account_id=account_id,
                            remediation=f"Enable automated backups with 7+ day retention for '{db_id}'. Consider enabling Multi-AZ for production databases.",
                            soc2_controls=["CC6.7"],
                            details={
                                "db_id": db_id,
                                "retention_days": retention,
                                "multi_az": multi_az,
                            },
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            check_id="rds-backup-enabled",
                            title=f"RDS instance '{db_id}' has backups and Multi-AZ enabled",
                            description=f"RDS instance '{db_id}' has {retention}-day backup retention and Multi-AZ enabled.",
                            severity=Severity.INFO,
                            status=ComplianceStatus.PASS,
                            domain=CheckDomain.ENCRYPTION,
                            resource_type="AWS::RDS::DBInstance",
                            resource_id=db_arn,
                            region=region,
                            account_id=account_id,
                            soc2_controls=["CC6.7"],
                            details={
                                "db_id": db_id,
                                "retention_days": retention,
                                "multi_az": multi_az,
                            },
                        )
                    )
    except ClientError as e:
        return [Finding.not_assessed(
            check_id="rds-backup-enabled",
            title="Unable to check RDS backups",
            description=f"API call failed: {e}",
            domain=CheckDomain.ENCRYPTION,
            resource_type="AWS::RDS::DBInstance",
            account_id=account_id,
            region=region,
        )]

    return findings
