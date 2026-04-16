"""Cross-cutting diagnostic settings walker.

CIS Azure 5.1.4–5.1.7 expects diagnostic settings on every security-relevant
resource type. Rather than implementing a check per resource type, this
module declares a matrix of {resource_type: expected_log_categories} and
walks the subscription once.
"""

from __future__ import annotations

from typing import Any

from shasta.azure.client import AzureClient
from shasta.evidence.models import (
    CheckDomain,
    CloudProvider,
    ComplianceStatus,
    Finding,
    Severity,
)

# Resource types and the log categories CIS / MCSB expect on each.
EXPECTED_DIAGNOSTIC_CATEGORIES: dict[str, list[str]] = {
    "Microsoft.KeyVault/vaults": ["AuditEvent"],
    "Microsoft.Sql/servers/databases": [
        "SQLSecurityAuditEvents",
        "DevOpsOperationsAudit",
    ],
    "Microsoft.Storage/storageAccounts/blobServices/default": [
        "StorageRead",
        "StorageWrite",
        "StorageDelete",
    ],
    "Microsoft.Network/networkSecurityGroups": [
        "NetworkSecurityGroupEvent",
        "NetworkSecurityGroupRuleCounter",
    ],
    "Microsoft.Web/sites": [
        "AppServiceHTTPLogs",
        "AppServiceConsoleLogs",
        "AppServiceAppLogs",
        "AppServiceAuditLogs",
    ],
    "Microsoft.ContainerService/managedClusters": [
        "kube-apiserver",
        "kube-audit",
        "kube-audit-admin",
        "guard",
    ],
    "Microsoft.RecoveryServices/vaults": [
        "AzureBackupReport",
        "CoreAzureBackup",
        "AddonAzureBackupAlerts",
    ],
}


def run_all_azure_diagnostic_settings_checks(client: AzureClient) -> list[Finding]:
    """Walk every covered resource type and check diagnostic settings."""
    findings: list[Finding] = []
    sub_id = client.account_info.subscription_id if client.account_info else "unknown"
    region = client.account_info.region if client.account_info else "unknown"

    try:
        from azure.mgmt.monitor import MonitorManagementClient
        from azure.mgmt.resource import ResourceManagementClient
    except ImportError:
        return [Finding.not_assessed(
            check_id="azure-diagnostic-settings",
            title="Unable to check diagnostic settings (SDK not installed)",
            description="azure-mgmt-monitor or azure-mgmt-resource package not installed.",
            domain=CheckDomain.LOGGING,
            resource_type="Azure::Monitor::DiagnosticSetting",
            account_id=sub_id,
            region=region,
            cloud_provider=CloudProvider.AZURE,
        )]

    monitor = client.mgmt_client(MonitorManagementClient)
    rm = client.mgmt_client(ResourceManagementClient)

    # Group resources by type. Resource Manager returns lowercase types in some
    # SDK versions; normalise to the canonical CIS form for matching.
    type_lookup = {k.lower(): k for k in EXPECTED_DIAGNOSTIC_CATEGORIES}
    resources_by_type: dict[str, list[Any]] = {k: [] for k in EXPECTED_DIAGNOSTIC_CATEGORIES}

    for r in rm.resources.list():
        rt = (getattr(r, "type", "") or "").lower()
        canonical = type_lookup.get(rt)
        if canonical:
            resources_by_type[canonical].append(r)

    for resource_type, expected in EXPECTED_DIAGNOSTIC_CATEGORIES.items():
        for r in resources_by_type[resource_type]:
            findings.append(
                _check_resource_diagnostics(monitor, r, resource_type, expected, sub_id, region)
            )

    return findings


def _check_resource_diagnostics(
    monitor: Any,
    resource: Any,
    resource_type: str,
    expected: list[str],
    sub_id: str,
    region: str,
) -> Finding:
    rid = resource.id or ""
    name = resource.name or "unknown"
    loc = resource.location or region

    try:
        settings = list(monitor.diagnostic_settings.list(rid))
    except Exception:
        settings = []

    enabled_categories: set[str] = set()
    destinations: set[str] = set()
    for s in settings:
        for log in getattr(s, "logs", None) or []:
            if getattr(log, "enabled", False):
                cat = getattr(log, "category", None)
                if cat:
                    enabled_categories.add(cat)
        if getattr(s, "workspace_id", None):
            destinations.add("LogAnalytics")
        if getattr(s, "storage_account_id", None):
            destinations.add("Storage")
        if getattr(s, "event_hub_authorization_rule_id", None):
            destinations.add("EventHub")

    missing = [c for c in expected if c not in enabled_categories]
    short_type = resource_type.split("/")[-1]

    if not missing and destinations:
        return Finding(
            check_id="azure-diagnostic-settings",
            title=f"{short_type} '{name}' has all expected diagnostic categories",
            description=(
                f"All required log categories ({', '.join(expected)}) are enabled and forwarded "
                f"to {', '.join(sorted(destinations))}."
            ),
            severity=Severity.INFO,
            status=ComplianceStatus.PASS,
            domain=CheckDomain.LOGGING,
            resource_type=f"Azure::{resource_type.replace('/', '::')}",
            resource_id=rid,
            region=loc,
            account_id=sub_id,
            cloud_provider=CloudProvider.AZURE,
            soc2_controls=["CC7.1", "CC7.2"],
            cis_azure_controls=["5.1.4", "5.1.5", "5.1.6", "5.1.7"],
            mcsb_controls=["LT-3", "LT-4"],
            details={
                "expected": expected,
                "enabled": sorted(enabled_categories),
                "destinations": sorted(destinations),
            },
        )

    if not settings:
        title = f"{short_type} '{name}' has no diagnostic settings"
        desc = (
            f"No diagnostic setting is configured. Expected categories ({', '.join(expected)}) "
            "are not exported anywhere — security events on this resource are invisible to "
            "Log Analytics, Sentinel, and long-term audit storage."
        )
    else:
        title = f"{short_type} '{name}' missing categories: {', '.join(missing)}"
        desc = (
            f"Diagnostic settings exist but the following expected log categories are not "
            f"enabled: {', '.join(missing)}."
        )

    return Finding(
        check_id="azure-diagnostic-settings",
        title=title,
        description=desc,
        severity=Severity.MEDIUM,
        status=ComplianceStatus.FAIL,
        domain=CheckDomain.LOGGING,
        resource_type=f"Azure::{resource_type.replace('/', '::')}",
        resource_id=rid,
        region=loc,
        account_id=sub_id,
        cloud_provider=CloudProvider.AZURE,
        remediation=(
            "Add a diagnostic setting on this resource enabling the missing log categories and "
            "send them to Log Analytics. Portal: <resource> > Monitoring > Diagnostic settings."
        ),
        soc2_controls=["CC7.1", "CC7.2"],
        cis_azure_controls=["5.1.4", "5.1.5", "5.1.6", "5.1.7"],
        mcsb_controls=["LT-3", "LT-4"],
        details={
            "expected": expected,
            "enabled": sorted(enabled_categories),
            "missing": missing,
            "destinations": sorted(destinations),
        },
    )
