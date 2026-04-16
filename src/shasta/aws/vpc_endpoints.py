"""Cross-cutting VPC endpoint walker.

A single sweep across the most security-sensitive AWS services and reports
which ones lack VPC interface/gateway endpoints. Without VPC endpoints,
traffic from EC2/ECS/EKS to S3/KMS/SecretsManager/etc. traverses the public
internet — even when the resources are in your own account.

Mirrors the Azure private_endpoints.py walker.
"""

from __future__ import annotations

from botocore.exceptions import ClientError

from shasta.aws.client import AWSClient
from shasta.evidence.models import (
    CheckDomain,
    ComplianceStatus,
    Finding,
    Severity,
)


# Services that strongly benefit from a VPC endpoint when used from inside a VPC.
# Maps endpoint service-name suffix to (display name, severity).
EXPECTED_VPC_ENDPOINTS = {
    "s3": ("S3", Severity.HIGH),
    "dynamodb": ("DynamoDB", Severity.HIGH),
    "kms": ("KMS", Severity.HIGH),
    "secretsmanager": ("Secrets Manager", Severity.HIGH),
    "ssm": ("Systems Manager", Severity.MEDIUM),
    "ssmmessages": ("SSM Messages", Severity.MEDIUM),
    "ec2messages": ("EC2 Messages", Severity.MEDIUM),
    "ecr.api": ("ECR API", Severity.MEDIUM),
    "ecr.dkr": ("ECR Docker", Severity.MEDIUM),
    "logs": ("CloudWatch Logs", Severity.MEDIUM),
    "monitoring": ("CloudWatch Monitoring", Severity.LOW),
    "sns": ("SNS", Severity.LOW),
    "sqs": ("SQS", Severity.LOW),
    "sts": ("STS", Severity.MEDIUM),
}


def run_all_aws_vpc_endpoint_checks(client: AWSClient) -> list[Finding]:
    findings: list[Finding] = []
    account_id = client.account_info.account_id if client.account_info else "unknown"
    region = client.account_info.region if client.account_info else "us-east-1"

    try:
        regions = client.get_enabled_regions()
    except ClientError:
        regions = [region]

    for r in regions:
        try:
            findings.extend(_check_region(client.for_region(r), account_id, r))
        except ClientError:
            continue

    return findings


def _check_region(client: AWSClient, account_id: str, region: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        ec2 = client.client("ec2")
        vpcs = ec2.describe_vpcs().get("Vpcs", [])
        endpoints = ec2.describe_vpc_endpoints().get("VpcEndpoints", [])
    except ClientError as e:
        return [Finding.not_assessed(
            check_id="aws-vpc-endpoints",
            title="Unable to check VPC endpoints",
            description=f"API call failed: {e}",
            domain=CheckDomain.NETWORKING,
            resource_type="AWS::EC2::VPC",
            account_id=account_id,
            region=region,
        )]

    if not vpcs:
        return []

    # Build set of existing endpoint service suffixes per VPC
    by_vpc: dict[str, set[str]] = {}
    for ep in endpoints:
        vpc_id = ep.get("VpcId", "")
        # ServiceName is like 'com.amazonaws.us-east-1.s3' or 'com.amazonaws.us-east-1.ecr.api'
        svc = ep.get("ServiceName", "")
        parts = svc.split(".", 3)
        suffix = parts[3] if len(parts) >= 4 else svc
        by_vpc.setdefault(vpc_id, set()).add(suffix)

    for vpc in vpcs:
        vpc_id = vpc.get("VpcId", "")
        if vpc.get("IsDefault"):
            continue  # Don't flag the default VPC; it's expected to be deleted/empty
        present = by_vpc.get(vpc_id, set())
        missing_high: list[str] = []
        missing_medium: list[str] = []
        missing_low: list[str] = []

        for suffix, (display, sev) in EXPECTED_VPC_ENDPOINTS.items():
            if suffix in present:
                continue
            if sev == Severity.HIGH:
                missing_high.append(display)
            elif sev == Severity.MEDIUM:
                missing_medium.append(display)
            else:
                missing_low.append(display)

        if not (missing_high or missing_medium):
            findings.append(
                Finding(
                    check_id="aws-vpc-endpoints",
                    title=f"VPC '{vpc_id}' has all critical VPC endpoints",
                    description=(
                        f"VPC has endpoints for all high/medium-priority services. "
                        f"{len(present)} endpoints total."
                    ),
                    severity=Severity.INFO,
                    status=ComplianceStatus.PASS,
                    domain=CheckDomain.NETWORKING,
                    resource_type="AWS::EC2::VPC",
                    resource_id=f"arn:aws:ec2:{region}:{account_id}:vpc/{vpc_id}",
                    region=region,
                    account_id=account_id,
                    soc2_controls=["CC6.6"],
                    cis_aws_controls=["5.x"],
                    details={"vpc": vpc_id, "endpoint_count": len(present)},
                )
            )
        else:
            severity = Severity.HIGH if missing_high else Severity.MEDIUM
            findings.append(
                Finding(
                    check_id="aws-vpc-endpoints",
                    title=(
                        f"VPC '{vpc_id}' missing {len(missing_high)} high + "
                        f"{len(missing_medium)} medium-priority VPC endpoints"
                    ),
                    description=(
                        f"Missing high-priority endpoints: {', '.join(missing_high) or 'none'}. "
                        f"Missing medium: {', '.join(missing_medium) or 'none'}. "
                        "Without VPC endpoints, EC2/ECS/EKS traffic to AWS services traverses "
                        "the public internet via NAT, even when the AWS resources are in your "
                        "own account. This adds NAT cost, latency, and (worst) makes data flows "
                        "subject to internet-facing controls."
                    ),
                    severity=severity,
                    status=ComplianceStatus.FAIL,
                    domain=CheckDomain.NETWORKING,
                    resource_type="AWS::EC2::VPC",
                    resource_id=f"arn:aws:ec2:{region}:{account_id}:vpc/{vpc_id}",
                    region=region,
                    account_id=account_id,
                    remediation=(
                        "Create gateway endpoints for S3 and DynamoDB (free), and interface "
                        "endpoints for KMS, Secrets Manager, SSM, ECR, Logs, STS. Use the "
                        "AWS PrivateLink module in Terraform for one-shot deploy."
                    ),
                    soc2_controls=["CC6.6"],
                    cis_aws_controls=["5.x"],
                    details={
                        "vpc": vpc_id,
                        "missing_high": missing_high,
                        "missing_medium": missing_medium,
                        "missing_low": missing_low,
                    },
                )
            )

    return findings
