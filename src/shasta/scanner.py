"""Shasta compliance scanner — orchestrates all check modules.

Supports multi-cloud scanning (AWS + Azure) with unified compliance
framework mapping and multi-region AWS scanning.
"""

from __future__ import annotations

from typing import Any

from shasta.compliance.mapper import enrich_findings_with_controls
from shasta.evidence.models import CheckDomain, CloudProvider, Finding, ScanResult

# Domains where AWS checks are global (not per-region)
_AWS_GLOBAL_DOMAINS = {CheckDomain.IAM}

# Domains where AWS checks are regional
_AWS_REGIONAL_DOMAINS = {
    CheckDomain.NETWORKING,
    CheckDomain.STORAGE,
    CheckDomain.ENCRYPTION,
    CheckDomain.MONITORING,
}


def run_full_scan(
    client: Any = None,
    *,
    azure_client: Any = None,
    domains: list[CheckDomain] | None = None,
    regions: list[str] | None = None,
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
        regions: AWS regions to scan. None = configured region only.
            ["all"] = all enabled regions. Or a specific list like
            ["us-east-1", "eu-west-1"].
        framework: Which compliance framework to map findings to.
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
        if regions:
            scan.findings.extend(_run_aws_checks_multi_region(client, domains, regions))
            scan.region = ",".join(regions) if regions != ["all"] else "all"
        else:
            scan.findings.extend(_run_aws_checks(client, domains))

            # Vulnerability checks (part of monitoring but separate runner)
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
    # "both" = SOC 2 + ISO 27001 (backward compat), "all" = all frameworks
    if framework in ("soc2", "both", "all"):
        enrich_findings_with_controls(scan.findings)
    if framework in ("iso27001", "both", "all"):
        from shasta.compliance.iso27001_mapper import enrich_findings_with_iso27001

        enrich_findings_with_iso27001(scan.findings)
    if framework in ("hipaa", "all"):
        from shasta.compliance.hipaa_mapper import enrich_findings_with_hipaa

        enrich_findings_with_hipaa(scan.findings)

    # Store multi-cloud info in scan details if both providers scanned
    if client is not None and azure_client is not None:
        scan.cloud_provider = CloudProvider.AWS  # Primary

    scan.complete()
    return scan


def _run_aws_checks(client: Any, domains: list[CheckDomain]) -> list[Finding]:
    """Run AWS-specific checks across requested domains (single region)."""
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

    findings.extend(_run_aws_extras(client, domains))
    return findings


def _run_aws_extras(client: Any, domains: list[CheckDomain]) -> list[Finding]:
    """Run the Stage 2/3 AWS modules: databases, serverless, backup, walkers."""
    extras: list[Finding] = []

    if CheckDomain.STORAGE in domains or CheckDomain.ENCRYPTION in domains:
        try:
            from shasta.aws.databases import run_all_aws_database_checks

            extras.extend(run_all_aws_database_checks(client))
        except Exception:
            pass

    if CheckDomain.COMPUTE in domains or CheckDomain.MONITORING in domains:
        try:
            from shasta.aws.serverless import run_all_aws_serverless_checks

            extras.extend(run_all_aws_serverless_checks(client))
        except Exception:
            pass

    # Stage 1 of the AWS-to-Azure parity sweep: compute and KMS modules
    if CheckDomain.COMPUTE in domains:
        try:
            from shasta.aws.compute import run_all_aws_compute_checks

            extras.extend(run_all_aws_compute_checks(client))
        except Exception:
            pass

    if CheckDomain.ENCRYPTION in domains:
        try:
            from shasta.aws.kms import run_all_aws_kms_checks

            extras.extend(run_all_aws_kms_checks(client))
        except Exception:
            pass

    # Stage 2 of the AWS-to-Azure parity sweep: CloudFront (global) and
    # data warehouse / cache / graph DB modules
    if CheckDomain.NETWORKING in domains:
        try:
            from shasta.aws.cloudfront import run_all_aws_cloudfront_checks

            extras.extend(run_all_aws_cloudfront_checks(client))
        except Exception:
            pass

    if CheckDomain.STORAGE in domains or CheckDomain.ENCRYPTION in domains:
        try:
            from shasta.aws.data_warehouse import run_all_aws_data_warehouse_checks

            extras.extend(run_all_aws_data_warehouse_checks(client))
        except Exception:
            pass

    if CheckDomain.MONITORING in domains:
        try:
            from shasta.aws.backup import run_all_aws_backup_checks

            extras.extend(run_all_aws_backup_checks(client))
        except Exception:
            pass

        try:
            from shasta.aws.organizations import run_all_aws_organizations_checks

            extras.extend(run_all_aws_organizations_checks(client))
        except Exception:
            pass

        try:
            from shasta.aws.cloudwatch_logs import run_all_aws_cloudwatch_log_checks

            extras.extend(run_all_aws_cloudwatch_log_checks(client))
        except Exception:
            pass

    if CheckDomain.NETWORKING in domains:
        try:
            from shasta.aws.vpc_endpoints import run_all_aws_vpc_endpoint_checks

            extras.extend(run_all_aws_vpc_endpoint_checks(client))
        except Exception:
            pass

    return extras


def _run_aws_checks_multi_region(
    client: Any, domains: list[CheckDomain], regions: list[str]
) -> list[Finding]:
    """Run AWS checks across multiple regions.

    IAM checks are global — run once with the original client.
    Networking, storage, encryption, monitoring are regional — run per region.
    """
    from shasta.aws.encryption import run_all_encryption_checks
    from shasta.aws.iam import run_all_iam_checks
    from shasta.aws.logging_checks import run_all_logging_checks
    from shasta.aws.networking import run_all_networking_checks
    from shasta.aws.storage import run_all_storage_checks
    from shasta.aws.vulnerabilities import run_all_vulnerability_checks

    aws_domain_runners = {
        CheckDomain.NETWORKING: run_all_networking_checks,
        CheckDomain.STORAGE: run_all_storage_checks,
        CheckDomain.ENCRYPTION: run_all_encryption_checks,
        CheckDomain.MONITORING: run_all_logging_checks,
    }

    findings: list[Finding] = []

    # Resolve "all" to actual region list
    if regions == ["all"]:
        regions = client.get_enabled_regions()

    # Global checks (IAM) — run once
    if CheckDomain.IAM in domains:
        findings.extend(run_all_iam_checks(client))

    # Regional checks — run per region
    regional_domains = [d for d in domains if d in _AWS_REGIONAL_DOMAINS]
    for region_name in regions:
        regional_client = client.for_region(region_name)
        regional_client.validate_credentials()

        for domain in regional_domains:
            runner = aws_domain_runners.get(domain)
            if runner:
                findings.extend(runner(regional_client))

        # Vulnerability checks per region
        if CheckDomain.MONITORING in domains:
            findings.extend(run_all_vulnerability_checks(regional_client))

    return findings


def _run_azure_checks(azure_client: Any, domains: list[CheckDomain]) -> list[Finding]:
    """Run Azure-specific checks across requested domains for one subscription."""
    from shasta.azure.encryption import run_all_azure_encryption_checks
    from shasta.azure.iam import run_all_azure_iam_checks
    from shasta.azure.monitoring import run_all_azure_monitoring_checks
    from shasta.azure.networking import run_all_azure_networking_checks
    from shasta.azure.storage import run_all_azure_storage_checks

    azure_domain_runners: dict = {
        CheckDomain.IAM: run_all_azure_iam_checks,
        CheckDomain.NETWORKING: run_all_azure_networking_checks,
        CheckDomain.STORAGE: run_all_azure_storage_checks,
        CheckDomain.ENCRYPTION: run_all_azure_encryption_checks,
        CheckDomain.MONITORING: run_all_azure_monitoring_checks,
    }

    # Add COMPUTE domain if available
    try:
        from shasta.azure.compute import run_all_azure_compute_checks

        azure_domain_runners[CheckDomain.COMPUTE] = run_all_azure_compute_checks
    except ImportError:
        pass

    findings: list[Finding] = []
    for domain in domains:
        runner = azure_domain_runners.get(domain)
        if runner:
            findings.extend(runner(azure_client))

    # Run additional Stage 2/3 modules unconditionally when their domain is requested.
    findings.extend(_run_azure_extras(azure_client, domains))
    return findings


def _run_azure_extras(azure_client: Any, domains: list[CheckDomain]) -> list[Finding]:
    """Run the Stage 2/3 Azure modules: databases, app service, backup, walkers, governance."""
    extras: list[Finding] = []

    # Stage 2: new resource-type modules
    if CheckDomain.STORAGE in domains:
        try:
            from shasta.azure.databases import run_all_azure_database_checks

            extras.extend(run_all_azure_database_checks(azure_client))
        except Exception:
            pass

    if CheckDomain.COMPUTE in domains:
        try:
            from shasta.azure.appservice import run_all_azure_appservice_checks

            extras.extend(run_all_azure_appservice_checks(azure_client))
        except Exception:
            pass

    if CheckDomain.MONITORING in domains:
        try:
            from shasta.azure.backup import run_all_azure_backup_checks

            extras.extend(run_all_azure_backup_checks(azure_client))
        except Exception:
            pass

    # Stage 3: cross-cutting walkers — run when networking or monitoring is requested
    if CheckDomain.NETWORKING in domains:
        try:
            from shasta.azure.private_endpoints import (
                run_all_azure_private_endpoint_checks,
            )

            extras.extend(run_all_azure_private_endpoint_checks(azure_client))
        except Exception:
            pass

    if CheckDomain.MONITORING in domains:
        try:
            from shasta.azure.diagnostic_settings import (
                run_all_azure_diagnostic_settings_checks,
            )

            extras.extend(run_all_azure_diagnostic_settings_checks(azure_client))
        except Exception:
            pass

        try:
            from shasta.azure.governance import run_all_azure_governance_checks

            extras.extend(run_all_azure_governance_checks(azure_client))
        except Exception:
            pass

    # Entra ID hardening checks (CIS/MCSB gaps beyond iam.py)
    if CheckDomain.IAM in domains:
        try:
            from shasta.azure.entra import run_all_azure_entra_checks

            extras.extend(run_all_azure_entra_checks(azure_client))
        except Exception:
            pass

    return extras


def run_azure_multi_subscription(
    azure_client: Any,
    domains: list[CheckDomain],
    subscription_ids: list[str] | None = None,
) -> list[Finding]:
    """Run Azure checks across multiple subscriptions, mirroring the AWS multi-region pattern.

    If ``subscription_ids`` is None, every subscription the credential can see
    is scanned.
    """
    findings: list[Finding] = []
    if subscription_ids is None:
        subs = azure_client.list_subscriptions()
        subscription_ids = [s["subscription_id"] for s in subs if s.get("subscription_id")]

    for sid in subscription_ids:
        try:
            sib = azure_client.for_subscription(sid)
            sib.validate_credentials()
            findings.extend(_run_azure_checks(sib, domains))
        except Exception:
            continue
    return findings
