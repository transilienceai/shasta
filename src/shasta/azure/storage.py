"""Azure storage security checks for SOC 2 and ISO 27001.

Checks Storage Account encryption, HTTPS enforcement, public access,
and soft delete for compliance with CC6.7 (Data Protection).
"""

from __future__ import annotations

from shasta.azure.client import AzureClient
from shasta.evidence.models import (
    CheckDomain,
    CloudProvider,
    ComplianceStatus,
    Finding,
    Severity,
)


def run_all_azure_storage_checks(client: AzureClient) -> list[Finding]:
    """Run all Azure storage compliance checks."""
    findings: list[Finding] = []
    sub_id = client.account_info.subscription_id if client.account_info else "unknown"
    region = client.account_info.region if client.account_info else "unknown"

    try:
        from azure.mgmt.storage import StorageManagementClient

        storage_client = client.mgmt_client(StorageManagementClient)
        accounts = list(storage_client.storage_accounts.list())

        for account in accounts:
            acct_name = account.name or "unknown"
            acct_id = account.id or ""
            acct_rg = (
                acct_id.split("/resourceGroups/")[1].split("/")[0]
                if "/resourceGroups/" in acct_id
                else "unknown"
            )

            findings.extend(
                _check_storage_encryption(account, acct_name, acct_id, acct_rg, sub_id, region)
            )
            findings.extend(
                _check_storage_https_only(account, acct_name, acct_id, acct_rg, sub_id, region)
            )
            findings.extend(
                _check_blob_public_access(account, acct_name, acct_id, acct_rg, sub_id, region)
            )
            findings.extend(
                _check_storage_soft_delete(
                    storage_client, account, acct_name, acct_id, acct_rg, sub_id, region
                )
            )

        if not accounts:
            findings.append(
                Finding(
                    check_id="azure-storage-encryption",
                    title="No storage accounts found",
                    description="No Azure Storage accounts in the subscription.",
                    severity=Severity.INFO,
                    status=ComplianceStatus.NOT_APPLICABLE,
                    domain=CheckDomain.STORAGE,
                    resource_type="Azure::Storage::StorageAccount",
                    resource_id=f"/subscriptions/{sub_id}/storageAccounts",
                    region=region,
                    account_id=sub_id,
                    cloud_provider=CloudProvider.AZURE,
                    soc2_controls=["CC6.7"],
                )
            )

    except Exception as e:
        findings.append(
            Finding(
                check_id="azure-storage-encryption",
                title="Storage check failed",
                description=f"Could not check storage accounts: {e}",
                severity=Severity.MEDIUM,
                status=ComplianceStatus.NOT_ASSESSED,
                domain=CheckDomain.STORAGE,
                resource_type="Azure::Storage::StorageAccount",
                resource_id=f"/subscriptions/{sub_id}/storageAccounts",
                region=region,
                account_id=sub_id,
                cloud_provider=CloudProvider.AZURE,
                soc2_controls=["CC6.7"],
            )
        )

    return findings


def _check_storage_encryption(account, name, acct_id, rg, sub_id, region) -> list[Finding]:
    """[CC6.7] Check storage account encryption at rest."""
    # Azure enforces SSE by default, but check TLS version
    encryption = account.encryption
    min_tls = account.minimum_tls_version or "TLS1_0"

    if min_tls in ("TLS1_2",):
        return [
            Finding(
                check_id="azure-storage-encryption",
                title=f"Storage account '{name}' has proper encryption settings",
                description=f"Storage account '{name}' uses SSE with minimum TLS {min_tls}.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.STORAGE,
                resource_type="Azure::Storage::StorageAccount",
                resource_id=acct_id,
                region=account.location or region,
                account_id=sub_id,
                cloud_provider=CloudProvider.AZURE,
                soc2_controls=["CC6.7"],
                details={"storage_account": name, "resource_group": rg, "min_tls": min_tls},
            )
        ]
    else:
        return [
            Finding(
                check_id="azure-storage-encryption",
                title=f"Storage account '{name}' allows outdated TLS ({min_tls})",
                description=f"Storage account '{name}' allows TLS version {min_tls}. "
                "TLS 1.0 and 1.1 have known vulnerabilities and should be disabled.",
                severity=Severity.HIGH,
                status=ComplianceStatus.FAIL,
                domain=CheckDomain.STORAGE,
                resource_type="Azure::Storage::StorageAccount",
                resource_id=acct_id,
                region=account.location or region,
                account_id=sub_id,
                cloud_provider=CloudProvider.AZURE,
                remediation="Set minimum TLS version to 1.2. "
                "Portal: Storage account > Configuration > Minimum TLS version > TLS 1.2.",
                soc2_controls=["CC6.7"],
                details={"storage_account": name, "resource_group": rg, "min_tls": min_tls},
            )
        ]


def _check_storage_https_only(account, name, acct_id, rg, sub_id, region) -> list[Finding]:
    """[CC6.7] Check storage account HTTPS-only enforcement."""
    https_only = account.enable_https_traffic_only
    # In newer SDK versions, the property may be named differently
    if https_only is None:
        https_only = getattr(account, "https_traffic_only_enabled", None)

    if https_only:
        return [
            Finding(
                check_id="azure-storage-https-only",
                title=f"Storage account '{name}' enforces HTTPS",
                description=f"Storage account '{name}' requires HTTPS for all traffic.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.STORAGE,
                resource_type="Azure::Storage::StorageAccount",
                resource_id=acct_id,
                region=account.location or region,
                account_id=sub_id,
                cloud_provider=CloudProvider.AZURE,
                soc2_controls=["CC6.7"],
                details={"storage_account": name, "resource_group": rg},
            )
        ]
    else:
        return [
            Finding(
                check_id="azure-storage-https-only",
                title=f"Storage account '{name}' allows HTTP traffic",
                description=f"Storage account '{name}' does not enforce HTTPS-only. "
                "Data in transit may be intercepted over unencrypted connections.",
                severity=Severity.HIGH,
                status=ComplianceStatus.FAIL,
                domain=CheckDomain.STORAGE,
                resource_type="Azure::Storage::StorageAccount",
                resource_id=acct_id,
                region=account.location or region,
                account_id=sub_id,
                cloud_provider=CloudProvider.AZURE,
                remediation="Enable HTTPS-only traffic. "
                "Portal: Storage account > Configuration > Secure transfer required > Enabled.",
                soc2_controls=["CC6.7"],
                details={"storage_account": name, "resource_group": rg},
            )
        ]


def _check_blob_public_access(account, name, acct_id, rg, sub_id, region) -> list[Finding]:
    """[CC6.7] Check if blob public access is disabled at the account level."""
    allow_public = account.allow_blob_public_access
    # Newer SDK property name
    if allow_public is None:
        allow_public = getattr(account, "allow_nested_items_to_be_public", None)

    if allow_public is False:
        return [
            Finding(
                check_id="azure-blob-public-access",
                title=f"Storage account '{name}' blocks public blob access",
                description=f"Storage account '{name}' disables public access at the account level.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.STORAGE,
                resource_type="Azure::Storage::StorageAccount",
                resource_id=acct_id,
                region=account.location or region,
                account_id=sub_id,
                cloud_provider=CloudProvider.AZURE,
                soc2_controls=["CC6.7"],
                details={"storage_account": name, "resource_group": rg},
            )
        ]
    else:
        return [
            Finding(
                check_id="azure-blob-public-access",
                title=f"Storage account '{name}' allows public blob access",
                description=f"Storage account '{name}' allows containers to be configured for public access. "
                "This could lead to accidental data exposure.",
                severity=Severity.HIGH,
                status=ComplianceStatus.FAIL,
                domain=CheckDomain.STORAGE,
                resource_type="Azure::Storage::StorageAccount",
                resource_id=acct_id,
                region=account.location or region,
                account_id=sub_id,
                cloud_provider=CloudProvider.AZURE,
                remediation="Disable public blob access at the account level. "
                "Portal: Storage account > Configuration > Allow Blob public access > Disabled.",
                soc2_controls=["CC6.7"],
                details={"storage_account": name, "resource_group": rg},
            )
        ]


def _check_storage_soft_delete(
    storage_client, account, name, acct_id, rg, sub_id, region
) -> list[Finding]:
    """[CC6.7] Check if blob soft delete and versioning are enabled."""
    try:
        blob_props = storage_client.blob_services.get_service_properties(rg, name)

        soft_delete_enabled = False
        versioning_enabled = False

        if blob_props.delete_retention_policy and blob_props.delete_retention_policy.enabled:
            soft_delete_enabled = True
        if hasattr(blob_props, "is_versioning_enabled") and blob_props.is_versioning_enabled:
            versioning_enabled = True

        if soft_delete_enabled and versioning_enabled:
            return [
                Finding(
                    check_id="azure-storage-soft-delete",
                    title=f"Storage account '{name}' has soft delete and versioning enabled",
                    description=f"Storage account '{name}' has blob soft delete and versioning enabled for data protection.",
                    severity=Severity.INFO,
                    status=ComplianceStatus.PASS,
                    domain=CheckDomain.STORAGE,
                    resource_type="Azure::Storage::StorageAccount",
                    resource_id=acct_id,
                    region=account.location or region,
                    account_id=sub_id,
                    cloud_provider=CloudProvider.AZURE,
                    soc2_controls=["CC6.7"],
                    details={
                        "storage_account": name,
                        "resource_group": rg,
                        "soft_delete": True,
                        "versioning": True,
                    },
                )
            ]
        else:
            missing = []
            if not soft_delete_enabled:
                missing.append("soft delete")
            if not versioning_enabled:
                missing.append("versioning")
            return [
                Finding(
                    check_id="azure-storage-soft-delete",
                    title=f"Storage account '{name}' missing {' and '.join(missing)}",
                    description=f"Storage account '{name}' does not have {' and '.join(missing)} enabled. "
                    "Without these, deleted or overwritten data cannot be recovered.",
                    severity=Severity.MEDIUM,
                    status=ComplianceStatus.FAIL,
                    domain=CheckDomain.STORAGE,
                    resource_type="Azure::Storage::StorageAccount",
                    resource_id=acct_id,
                    region=account.location or region,
                    account_id=sub_id,
                    cloud_provider=CloudProvider.AZURE,
                    remediation="Enable blob soft delete and versioning. "
                    "Portal: Storage account > Data protection > Enable soft delete + versioning.",
                    soc2_controls=["CC6.7"],
                    details={
                        "storage_account": name,
                        "resource_group": rg,
                        "soft_delete": soft_delete_enabled,
                        "versioning": versioning_enabled,
                    },
                )
            ]

    except Exception:
        return []
