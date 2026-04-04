"""Vulnerability management checks for SOC 2 compliance.

Covers:
  CC7.1 — Vulnerability scanning and management (AWS Inspector)
"""

from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from transilience_compliance.aws.client import AWSClient
from transilience_compliance.evidence.models import CheckDomain, ComplianceStatus, Finding, Severity


def run_all_vulnerability_checks(client: AWSClient) -> list[Finding]:
    """Run all vulnerability management checks."""
    findings: list[Finding] = []
    account_id = client.account_info.account_id if client.account_info else "unknown"
    region = client.account_info.region if client.account_info else "us-east-1"

    findings.extend(check_inspector_enabled(client, account_id, region))
    findings.extend(check_inspector_findings(client, account_id, region))

    return findings


def check_inspector_enabled(client: AWSClient, account_id: str, region: str) -> list[Finding]:
    """CC7.1 — Check that AWS Inspector is enabled for vulnerability scanning."""
    try:
        inspector = client.client("inspector2")
        status = inspector.batch_get_account_status(
            accountIds=[account_id]
        )

        accounts = status.get("accounts", [])
        if not accounts:
            return [_inspector_not_enabled(account_id, region)]

        acct = accounts[0]
        state = acct.get("state", {}).get("status", "DISABLED")

        if state in ("ENABLED", "ENABLING"):
            # Check which scan types are active
            resource_state = acct.get("resourceState", {})
            ec2_status = resource_state.get("ec2", {}).get("status", "DISABLED")
            ecr_status = resource_state.get("ecr", {}).get("status", "DISABLED")
            lambda_status = resource_state.get("lambda", {}).get("status", "DISABLED")

            active_types = []
            if ec2_status in ("ENABLED", "ENABLING"):
                active_types.append("EC2")
            if ecr_status in ("ENABLED", "ENABLING"):
                active_types.append("ECR")
            if lambda_status in ("ENABLED", "ENABLING"):
                active_types.append("Lambda")

            return [
                Finding(
                    check_id="inspector-enabled",
                    title=f"AWS Inspector is enabled (scanning: {', '.join(active_types) or 'none'})",
                    description=f"AWS Inspector is active and scanning {', '.join(active_types)} resources for vulnerabilities.",
                    severity=Severity.INFO,
                    status=ComplianceStatus.PASS,
                    domain=CheckDomain.MONITORING,
                    resource_type="AWS::Inspector2::Detector",
                    resource_id=f"arn:aws:inspector2:{region}:{account_id}",
                    region=region,
                    account_id=account_id,
                    soc2_controls=["CC7.1"],
                    details={"status": state, "ec2": ec2_status, "ecr": ecr_status, "lambda": lambda_status},
                )
            ]
        else:
            return [_inspector_not_enabled(account_id, region)]

    except ClientError as e:
        if "AccessDenied" in str(e) or "not enabled" in str(e).lower():
            return [_inspector_not_enabled(account_id, region)]
        raise


def _inspector_not_enabled(account_id: str, region: str) -> Finding:
    return Finding(
        check_id="inspector-enabled",
        title="AWS Inspector is NOT enabled",
        description="AWS Inspector is not enabled. Without vulnerability scanning, you cannot detect known software vulnerabilities in your EC2 instances, Lambda functions, or container images. This is required for SOC 2 CC7.1.",
        severity=Severity.HIGH,
        status=ComplianceStatus.FAIL,
        domain=CheckDomain.MONITORING,
        resource_type="AWS::Inspector2::Detector",
        resource_id=f"arn:aws:inspector2:{region}:{account_id}",
        region=region,
        account_id=account_id,
        remediation="Enable AWS Inspector in the AWS Console or via Terraform. Enable scanning for EC2, ECR, and Lambda.",
        soc2_controls=["CC7.1"],
    )


def check_inspector_findings(client: AWSClient, account_id: str, region: str) -> list[Finding]:
    """CC7.1 — Check for unresolved critical/high Inspector findings."""
    findings = []

    try:
        inspector = client.client("inspector2")

        # Get finding counts by severity using ACCOUNT aggregation
        response = inspector.list_finding_aggregations(
            aggregationType="ACCOUNT",
            maxResults=10,
        )

        severity_counts = {}
        total = 0
        for agg in response.get("responses", []):
            acct_agg = agg.get("accountAggregation", {})
            if acct_agg:
                counts = acct_agg.get("severityCounts", {})
                severity_counts = {
                    "CRITICAL": counts.get("critical", 0),
                    "HIGH": counts.get("high", 0),
                    "MEDIUM": counts.get("medium", 0),
                    "LOW": counts.get("all", 0) - counts.get("critical", 0) - counts.get("high", 0) - counts.get("medium", 0),
                }
                total = counts.get("all", 0)
                break

        critical = severity_counts.get("CRITICAL", 0)
        high = severity_counts.get("HIGH", 0)
        medium = severity_counts.get("MEDIUM", 0)

        if critical > 0 or high > 0:
            findings.append(
                Finding(
                    check_id="inspector-critical-findings",
                    title=f"Inspector: {critical} critical, {high} high vulnerability findings",
                    description=f"AWS Inspector has found {critical} critical and {high} high severity vulnerabilities across your resources. These represent known exploitable weaknesses that should be patched.",
                    severity=Severity.CRITICAL if critical > 0 else Severity.HIGH,
                    status=ComplianceStatus.FAIL,
                    domain=CheckDomain.MONITORING,
                    resource_type="AWS::Inspector2::Finding",
                    resource_id=f"arn:aws:inspector2:{region}:{account_id}:findings",
                    region=region,
                    account_id=account_id,
                    remediation=f"Review Inspector findings in the AWS Console. Patch or mitigate the {critical + high} critical/high vulnerabilities. Focus on critical findings first.",
                    soc2_controls=["CC7.1"],
                    details={"severity_counts": severity_counts, "total": total},
                )
            )
        elif total > 0:
            findings.append(
                Finding(
                    check_id="inspector-critical-findings",
                    title=f"Inspector: {total} findings (no critical/high)",
                    description=f"AWS Inspector found {total} vulnerability findings, but none are critical or high severity. {medium} are medium severity.",
                    severity=Severity.INFO,
                    status=ComplianceStatus.PASS,
                    domain=CheckDomain.MONITORING,
                    resource_type="AWS::Inspector2::Finding",
                    resource_id=f"arn:aws:inspector2:{region}:{account_id}:findings",
                    region=region,
                    account_id=account_id,
                    soc2_controls=["CC7.1"],
                    details={"severity_counts": severity_counts, "total": total},
                )
            )
        else:
            findings.append(
                Finding(
                    check_id="inspector-critical-findings",
                    title="Inspector: No vulnerability findings",
                    description="AWS Inspector has not detected any vulnerabilities. This may mean your resources are well-patched, or Inspector hasn't completed its initial scan yet.",
                    severity=Severity.INFO,
                    status=ComplianceStatus.PASS,
                    domain=CheckDomain.MONITORING,
                    resource_type="AWS::Inspector2::Finding",
                    resource_id=f"arn:aws:inspector2:{region}:{account_id}:findings",
                    region=region,
                    account_id=account_id,
                    soc2_controls=["CC7.1"],
                    details={"severity_counts": severity_counts, "total": 0},
                )
            )

    except ClientError as e:
        if "not enabled" in str(e).lower() or "AccessDenied" in str(e):
            pass  # Inspector not enabled — already caught by check_inspector_enabled
        else:
            raise

    return findings
