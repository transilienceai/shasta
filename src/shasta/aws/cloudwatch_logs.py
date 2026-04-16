"""Cross-cutting CloudWatch Logs encryption + retention walker.

CIS AWS expects log groups to be encrypted with a customer-managed KMS key
and to have an explicit retention policy. This module walks every log group
in every region and reports both gaps in a single sweep.
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


# Log groups that don't need a retention policy (e.g. ephemeral / lambda streams)
RETENTION_EXEMPT_PREFIXES = ()

MIN_RETENTION_DAYS = 90


def run_all_aws_cloudwatch_log_checks(client: AWSClient) -> list[Finding]:
    findings: list[Finding] = []
    account_id = client.account_info.account_id if client.account_info else "unknown"
    region = client.account_info.region if client.account_info else "us-east-1"

    try:
        regions = client.get_enabled_regions()
    except ClientError:
        regions = [region]

    for r in regions:
        try:
            findings.extend(_check_region_log_groups(client.for_region(r), account_id, r))
        except ClientError:
            continue

    return findings


def _check_region_log_groups(client: AWSClient, account_id: str, region: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        logs = client.client("logs")
        paginator = logs.get_paginator("describe_log_groups")
        groups: list[dict] = []
        for page in paginator.paginate():
            groups.extend(page.get("logGroups", []))
    except ClientError as e:
        return [Finding.not_assessed(
            check_id="cwl-kms-encryption",
            title="Unable to check CloudWatch log groups",
            description=f"API call failed: {e}",
            domain=CheckDomain.ENCRYPTION,
            resource_type="AWS::Logs::LogGroup",
            account_id=account_id,
            region=region,
        )]

    if not groups:
        return []

    no_kms: list[str] = []
    no_retention: list[str] = []
    short_retention: list[dict] = []
    for g in groups:
        name = g.get("logGroupName", "")
        if not g.get("kmsKeyId"):
            no_kms.append(name)
        retention = g.get("retentionInDays")
        if retention is None:
            no_retention.append(name)
        elif int(retention) < MIN_RETENTION_DAYS:
            short_retention.append({"name": name, "days": retention})

    # Encryption rollup
    if not no_kms:
        findings.append(
            Finding(
                check_id="cwl-kms-encryption",
                title=f"All {len(groups)} CloudWatch log group(s) encrypted with KMS",
                description="Every log group in this region has a kmsKeyId set.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.ENCRYPTION,
                resource_type="AWS::Logs::LogGroup",
                resource_id=f"arn:aws:logs:{region}:{account_id}:log-group:*",
                region=region,
                account_id=account_id,
                soc2_controls=["CC6.7"],
                cis_aws_controls=["3.x"],
            )
        )
    else:
        findings.append(
            Finding(
                check_id="cwl-kms-encryption",
                title=f"{len(no_kms)} of {len(groups)} log group(s) without KMS encryption",
                description=(
                    "Log groups without an explicit KMS key are encrypted with the AWS-owned "
                    "default key. Application logs frequently contain credentials, PII, or "
                    "session tokens — they deserve customer-managed key protection."
                ),
                severity=Severity.MEDIUM,
                status=ComplianceStatus.FAIL,
                domain=CheckDomain.ENCRYPTION,
                resource_type="AWS::Logs::LogGroup",
                resource_id=f"arn:aws:logs:{region}:{account_id}:log-group:*",
                region=region,
                account_id=account_id,
                remediation=(
                    "aws logs associate-kms-key --log-group-name <name> --kms-key-id <key-arn>"
                ),
                soc2_controls=["CC6.7"],
                cis_aws_controls=["3.x"],
                details={"log_groups_without_kms": no_kms[:30], "total": len(groups)},
            )
        )

    # Retention rollup
    if not no_retention and not short_retention:
        findings.append(
            Finding(
                check_id="cwl-retention",
                title=f"All {len(groups)} log group(s) have retention >= {MIN_RETENTION_DAYS} days",
                description="Every log group has an explicit, sufficient retention policy.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.LOGGING,
                resource_type="AWS::Logs::LogGroup",
                resource_id=f"arn:aws:logs:{region}:{account_id}:log-group:*",
                region=region,
                account_id=account_id,
                soc2_controls=["CC7.1"],
                cis_aws_controls=["3.x"],
            )
        )
    else:
        findings.append(
            Finding(
                check_id="cwl-retention",
                title=(
                    f"{len(no_retention)} log group(s) with infinite retention, "
                    f"{len(short_retention)} with retention < {MIN_RETENTION_DAYS} days"
                ),
                description=(
                    "Log groups with infinite retention accumulate cost indefinitely; log "
                    "groups with retention < 90 days lose audit evidence too fast for SOC 2."
                ),
                severity=Severity.LOW,
                status=ComplianceStatus.PARTIAL,
                domain=CheckDomain.LOGGING,
                resource_type="AWS::Logs::LogGroup",
                resource_id=f"arn:aws:logs:{region}:{account_id}:log-group:*",
                region=region,
                account_id=account_id,
                remediation=(
                    f"aws logs put-retention-policy --log-group-name <name> "
                    f"--retention-in-days {MIN_RETENTION_DAYS}  "
                    "(or 180 / 365 for compliance-critical groups)"
                ),
                soc2_controls=["CC7.1"],
                cis_aws_controls=["3.x"],
                details={
                    "no_retention": no_retention[:20],
                    "short_retention": short_retention[:20],
                },
            )
        )

    return findings
