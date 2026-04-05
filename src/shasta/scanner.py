"""Shasta compliance scanner — orchestrates all check modules.

Supports multi-cloud scanning (AWS + Azure) with unified compliance
framework mapping.
"""

from __future__ import annotations

from typing import Any

from shasta.compliance.mapper import enrich_findings_with_controls
from shasta.evidence.models import CheckDomain, CloudProvider, Finding, ScanResult


def run_full_scan(
    client: Any = None,
    *,
    azure_client: Any = None,
    domains: list[CheckDomain] | None = None,
    framework: str = "soc2",  # "soc2", "iso27001", or "both"
    include_github: bool = False,
    github_token: str | None = None,
    github_repos: list[str] | None = None,
) -> ScanResult:
    """Run compliance checks across specified domains (or all if None).

    Supports AWS, Azure, or both simultaneously.

    Args:
        client: AWSClient instance (positional for backward compatibility).
        azure_client: AzureClient instance for Azure scanning.
        domains: Which check domains to scan. Defaults to all.
        framework: Which compliance framework to map findings to.
            "soc2" -- SOC 2 Trust Service Criteria (default)
            "iso27001" -- ISO 27001:2022 Annex A
            "both" -- map to both frameworks simultaneously
        include_github: Whether to include GitHub checks.
        github_token: GitHub personal access token.
        github_repos: List of "owner/repo" strings to check.
    """
    if domains is None:
        domains = [
            CheckDomain.IAM,
            CheckDomain.NETWORKING,
            CheckDomain.STORAGE,
            CheckDomain.ENCRYPTION,
            CheckDomain.MONITORING,
        ]

    # Determine primary account info for the ScanResult
    account_id = "unknown"
    region = "unknown"
    cloud_provider = CloudProvider.AWS

    if client is not None:
        account_id = client.account_info.account_id if client.account_info else "unknown"
        region = client.account_info.region if client.account_info else "us-east-1"
        cloud_provider = CloudProvider.AWS
    elif azure_client is not None:
        account_id = (
            azure_client.account_info.subscription_id if azure_client.account_info else "unknown"
        )
        region = azure_client.account_info.region if azure_client.account_info else "unknown"
        cloud_provider = CloudProvider.AZURE

    scan = ScanResult(
        account_id=account_id,
        region=region,
        cloud_provider=cloud_provider,
        domains_scanned=domains,
    )

    # ----- AWS checks -----
    if client is not None:
        scan.findings.extend(_run_aws_checks(client, domains))

        # AWS vulnerability checks (part of monitoring but separate runner)
        if CheckDomain.MONITORING in domains:
            from shasta.aws.vulnerabilities import run_all_vulnerability_checks

            scan.findings.extend(run_all_vulnerability_checks(client))

    # ----- Azure checks -----
    if azure_client is not None:
        scan.findings.extend(_run_azure_checks(azure_client, domains))

    # ----- GitHub checks (cloud-agnostic) -----
    if include_github and github_token and github_repos:
        from shasta.integrations.github import run_github_checks

        scan.findings.extend(run_github_checks(github_token, github_repos))

    # Enrich findings with compliance framework mappings
    if framework in ("soc2", "both"):
        enrich_findings_with_controls(scan.findings)
    if framework in ("iso27001", "both"):
        from shasta.compliance.iso27001_mapper import enrich_findings_with_iso27001

        enrich_findings_with_iso27001(scan.findings)

    # Store multi-cloud info in scan details if both providers scanned
    if client is not None and azure_client is not None:
        scan.cloud_provider = CloudProvider.AWS  # Primary
        # Both account IDs available via findings

    scan.complete()
    return scan


def _run_aws_checks(client: Any, domains: list[CheckDomain]) -> list[Finding]:
    """Run AWS-specific checks across requested domains."""
    from shasta.aws.encryption import run_all_encryption_checks
    from shasta.aws.iam import run_all_iam_checks
    from shasta.aws.logging_checks import run_all_logging_checks
    from shasta.aws.networking import run_all_networking_checks
    from shasta.aws.storage import run_all_storage_checks

    aws_domain_runners = {
        CheckDomain.IAM: run_all_iam_checks,
        CheckDomain.NETWORKING: run_all_networking_checks,
        CheckDomain.STORAGE: run_all_storage_checks,
        CheckDomain.ENCRYPTION: run_all_encryption_checks,
        CheckDomain.MONITORING: run_all_logging_checks,
    }

    findings: list[Finding] = []
    for domain in domains:
        runner = aws_domain_runners.get(domain)
        if runner:
            findings.extend(runner(client))
    return findings


def _run_azure_checks(azure_client: Any, domains: list[CheckDomain]) -> list[Finding]:
    """Run Azure-specific checks across requested domains."""
    from shasta.azure.encryption import run_all_azure_encryption_checks
    from shasta.azure.iam import run_all_azure_iam_checks
    from shasta.azure.monitoring import run_all_azure_monitoring_checks
    from shasta.azure.networking import run_all_azure_networking_checks
    from shasta.azure.storage import run_all_azure_storage_checks

    azure_domain_runners = {
        CheckDomain.IAM: run_all_azure_iam_checks,
        CheckDomain.NETWORKING: run_all_azure_networking_checks,
        CheckDomain.STORAGE: run_all_azure_storage_checks,
        CheckDomain.ENCRYPTION: run_all_azure_encryption_checks,
        CheckDomain.MONITORING: run_all_azure_monitoring_checks,
    }

    findings: list[Finding] = []
    for domain in domains:
        runner = azure_domain_runners.get(domain)
        if runner:
            findings.extend(runner(azure_client))
    return findings
