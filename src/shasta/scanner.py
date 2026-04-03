"""Shasta compliance scanner — orchestrates all check modules."""

from __future__ import annotations

from shasta.aws.client import AWSClient
from shasta.aws.encryption import run_all_encryption_checks
from shasta.aws.iam import run_all_iam_checks
from shasta.aws.logging_checks import run_all_logging_checks
from shasta.aws.networking import run_all_networking_checks
from shasta.aws.storage import run_all_storage_checks
from shasta.aws.vulnerabilities import run_all_vulnerability_checks
from shasta.compliance.mapper import enrich_findings_with_controls
from shasta.evidence.models import CheckDomain, Finding, ScanResult


def run_full_scan(
    client: AWSClient,
    domains: list[CheckDomain] | None = None,
    framework: str = "soc2",  # "soc2", "iso27001", or "both"
    include_github: bool = False,
    github_token: str | None = None,
    github_repos: list[str] | None = None,
) -> ScanResult:
    """Run compliance checks across specified domains (or all if None).

    Args:
        framework: Which compliance framework to map findings to.
            "soc2" — SOC 2 Trust Service Criteria (default)
            "iso27001" — ISO 27001:2022 Annex A
            "both" — map to both frameworks simultaneously
    """
    if domains is None:
        domains = [
            CheckDomain.IAM,
            CheckDomain.NETWORKING,
            CheckDomain.STORAGE,
            CheckDomain.ENCRYPTION,
            CheckDomain.MONITORING,
        ]

    account_id = client.account_info.account_id if client.account_info else "unknown"
    region = client.account_info.region if client.account_info else "us-east-1"

    scan = ScanResult(
        account_id=account_id,
        region=region,
        domains_scanned=domains,
    )

    domain_runners = {
        CheckDomain.IAM: run_all_iam_checks,
        CheckDomain.NETWORKING: run_all_networking_checks,
        CheckDomain.STORAGE: run_all_storage_checks,
        CheckDomain.ENCRYPTION: run_all_encryption_checks,
        CheckDomain.MONITORING: run_all_logging_checks,
    }

    for domain in domains:
        runner = domain_runners.get(domain)
        if runner:
            findings = runner(client)
            scan.findings.extend(findings)

    # Vulnerability checks (part of monitoring but separate runner)
    if CheckDomain.MONITORING in domains:
        scan.findings.extend(run_all_vulnerability_checks(client))

    # GitHub checks (optional)
    if include_github and github_token and github_repos:
        from shasta.integrations.github import run_github_checks
        scan.findings.extend(run_github_checks(github_token, github_repos))

    # Enrich findings with compliance framework mappings
    if framework in ("soc2", "both"):
        enrich_findings_with_controls(scan.findings)
    if framework in ("iso27001", "both"):
        from shasta.compliance.iso27001_mapper import enrich_findings_with_iso27001
        enrich_findings_with_iso27001(scan.findings)

    scan.complete()
    return scan
