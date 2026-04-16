"""Azure Backup / Recovery Services Vault security checks.

Covers MCSB BR-2 and CIS 9.x backup-and-recovery requirements:
soft delete, immutable vaults, cross-region restore, redundancy,
CMK encryption, and Multi-User Authorization.
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


def run_all_azure_backup_checks(client: AzureClient) -> list[Finding]:
    """Run all Recovery Services Vault checks."""
    findings: list[Finding] = []
    sub_id = client.account_info.subscription_id if client.account_info else "unknown"
    region = client.account_info.region if client.account_info else "unknown"

    findings.extend(check_rsv_exists(client, sub_id, region))
    findings.extend(check_rsv_soft_delete(client, sub_id, region))
    findings.extend(check_rsv_immutability(client, sub_id, region))
    findings.extend(check_rsv_cross_region_restore(client, sub_id, region))
    findings.extend(check_rsv_redundancy(client, sub_id, region))
    findings.extend(check_rsv_cmk(client, sub_id, region))
    findings.extend(check_rsv_mua(client, sub_id, region))
    findings.extend(check_rsv_public_access(client, sub_id, region))

    return findings


def _iter_vaults(client: AzureClient):
    try:
        from azure.mgmt.recoveryservices import RecoveryServicesClient
        from azure.mgmt.recoveryservicesbackup.activestamp import (
            RecoveryServicesBackupClient,
        )
    except ImportError:
        return

    rs = client.mgmt_client(RecoveryServicesClient)
    backup = client.mgmt_client(RecoveryServicesBackupClient)
    for vault in rs.vaults.list_by_subscription_id():
        sid = vault.id or ""
        rg = sid.split("/resourceGroups/")[1].split("/")[0] if "/resourceGroups/" in sid else ""
        yield rs, backup, vault, rg


def _vault_finding(
    check_id: str,
    title: str,
    description: str,
    severity: Severity,
    status: ComplianceStatus,
    vault,
    sub_id: str,
    region: str,
    cis: list[str] | None = None,
    mcsb: list[str] | None = None,
    remediation: str = "",
    details: dict | None = None,
) -> Finding:
    return Finding(
        check_id=check_id,
        title=title,
        description=description,
        severity=severity,
        status=status,
        domain=CheckDomain.LOGGING,
        resource_type="Azure::RecoveryServices::Vault",
        resource_id=vault.id or "",
        region=vault.location or region,
        account_id=sub_id,
        cloud_provider=CloudProvider.AZURE,
        remediation=remediation,
        soc2_controls=["A1.1", "A1.2", "CC9.1"],
        cis_azure_controls=cis or [],
        mcsb_controls=mcsb or ["BR-1", "BR-2"],
        details=details or {"vault": vault.name},
    )


def check_rsv_exists(client: AzureClient, subscription_id: str, region: str) -> list[Finding]:
    """[MCSB BR-1] At least one Recovery Services Vault should exist per subscription."""
    try:
        vaults = list(client.mgmt_client(_rs_class()).vaults.list_by_subscription_id())
    except Exception as e:
        return [Finding.not_assessed(
            check_id="azure-rsv-exists",
            title="Unable to check Recovery Services Vaults",
            description=f"API call failed: {e}",
            domain=CheckDomain.LOGGING,
            resource_type="Azure::RecoveryServices::Vault",
            account_id=subscription_id,
            region=region,
            cloud_provider=CloudProvider.AZURE,
        )]
    if vaults:
        return [
            Finding(
                check_id="azure-rsv-exists",
                title=f"{len(vaults)} Recovery Services Vault(s) present",
                description="Subscription has Recovery Services Vault(s) provisioned for backups.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.LOGGING,
                resource_type="Azure::RecoveryServices::Vault",
                resource_id=f"/subscriptions/{subscription_id}/recoveryServicesVaults",
                region=region,
                account_id=subscription_id,
                cloud_provider=CloudProvider.AZURE,
                soc2_controls=["A1.1", "A1.2"],
                mcsb_controls=["BR-1"],
                details={"vault_count": len(vaults)},
            )
        ]
    return [
        Finding(
            check_id="azure-rsv-exists",
            title="No Recovery Services Vault in subscription",
            description=(
                "No Recovery Services Vault is provisioned. Without RSV, you cannot back up "
                "Azure VMs, SQL on VM, Azure Files, AKS, or PostgreSQL via Azure Backup."
            ),
            severity=Severity.HIGH,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.LOGGING,
            resource_type="Azure::RecoveryServices::Vault",
            resource_id=f"/subscriptions/{subscription_id}/recoveryServicesVaults",
            region=region,
            account_id=subscription_id,
            cloud_provider=CloudProvider.AZURE,
            remediation=(
                "Create a Recovery Services Vault and assign backup policies to production "
                "workloads. Portal: Recovery Services vaults > Create."
            ),
            soc2_controls=["A1.1", "A1.2"],
            mcsb_controls=["BR-1"],
        )
    ]


def _rs_class():
    from azure.mgmt.recoveryservices import RecoveryServicesClient

    return RecoveryServicesClient


def check_rsv_soft_delete(client: AzureClient, subscription_id: str, region: str) -> list[Finding]:
    """[MCSB BR-2] Soft delete must be enabled (preferably 'AlwaysON') on every RSV."""
    findings: list[Finding] = []
    try:
        for _rs, backup, vault, rg in _iter_vaults(client):
            try:
                cfg = backup.backup_resource_vault_configs.get(vault.name, rg)
            except Exception:
                continue
            soft_delete_state = getattr(cfg, "soft_delete_feature_state", "") or "Disabled"
            ok = str(soft_delete_state).lower() in ("enabled", "alwayson")
            always_on = str(soft_delete_state).lower() == "alwayson"
            findings.append(
                _vault_finding(
                    "azure-rsv-soft-delete",
                    f"RSV '{vault.name}' soft delete = {soft_delete_state}",
                    (
                        "Soft delete is enabled (irreversible 'AlwaysON' if so)."
                        if ok
                        else "Soft delete is disabled — backup data can be permanently destroyed by an attacker with vault access."
                    ),
                    Severity.INFO if always_on else (Severity.LOW if ok else Severity.HIGH),
                    ComplianceStatus.PASS if ok else ComplianceStatus.FAIL,
                    vault,
                    subscription_id,
                    region,
                    mcsb=["BR-2"],
                    remediation=(
                        ""
                        if ok
                        else "Set soft delete to AlwaysON on the vault (Recovery Services vault > Properties > Security Settings)."
                    ),
                    details={"vault": vault.name, "state": soft_delete_state},
                )
            )
    except Exception as e:
        return [Finding.not_assessed(
            check_id="azure-rsv-soft-delete",
            title="Unable to check RSV soft delete",
            description=f"API call failed: {e}",
            domain=CheckDomain.LOGGING,
            resource_type="Azure::RecoveryServices::Vault",
            account_id=subscription_id,
            region=region,
            cloud_provider=CloudProvider.AZURE,
        )]
    return findings


def check_rsv_immutability(client: AzureClient, subscription_id: str, region: str) -> list[Finding]:
    """[MCSB BR-2.3] Vault should have immutability enabled and locked."""
    findings: list[Finding] = []
    try:
        for _rs, _b, vault, _rg in _iter_vaults(client):
            props = getattr(vault, "properties", None)
            immut = getattr(props, "security_settings", None) if props else None
            immut_settings = getattr(immut, "immutability_settings", None) if immut else None
            state = getattr(immut_settings, "state", None) if immut_settings else None
            ok = str(state).lower() in ("unlocked", "locked")
            locked = str(state).lower() == "locked"
            findings.append(
                _vault_finding(
                    "azure-rsv-immutability",
                    f"RSV '{vault.name}' immutability state = {state or 'Disabled'}",
                    (
                        "Immutability is locked — recovery points cannot be deleted before expiry."
                        if locked
                        else (
                            "Immutability enabled but unlocked — should be locked for production."
                            if ok
                            else "Immutability disabled — backups can be deleted before retention expires."
                        )
                    ),
                    Severity.INFO if locked else (Severity.LOW if ok else Severity.MEDIUM),
                    ComplianceStatus.PASS
                    if locked
                    else (ComplianceStatus.PARTIAL if ok else ComplianceStatus.FAIL),
                    vault,
                    subscription_id,
                    region,
                    mcsb=["BR-2"],
                    remediation=(
                        ""
                        if locked
                        else "Enable immutability and lock it: Vault > Properties > Immutability > Enabled, then Lock."
                    ),
                    details={"vault": vault.name, "state": state},
                )
            )
    except Exception as e:
        return [Finding.not_assessed(
            check_id="azure-rsv-immutability",
            title="Unable to check RSV immutability",
            description=f"API call failed: {e}",
            domain=CheckDomain.LOGGING,
            resource_type="Azure::RecoveryServices::Vault",
            account_id=subscription_id,
            region=region,
            cloud_provider=CloudProvider.AZURE,
        )]
    return findings


def check_rsv_cross_region_restore(
    client: AzureClient, subscription_id: str, region: str
) -> list[Finding]:
    """[MCSB BR-2] Cross Region Restore should be enabled on GRS vaults."""
    findings: list[Finding] = []
    try:
        for _rs, _b, vault, _rg in _iter_vaults(client):
            props = getattr(vault, "properties", None)
            redundancy = getattr(props, "redundancy_settings", None) if props else None
            crr = (
                str(getattr(redundancy, "cross_region_restore", "Disabled") or "Disabled")
                if redundancy
                else "Disabled"
            )
            ok = crr.lower() == "enabled"
            findings.append(
                _vault_finding(
                    "azure-rsv-crr",
                    f"RSV '{vault.name}' cross-region restore = {crr}",
                    "CRR enabled."
                    if ok
                    else "CRR not enabled — paired-region failover unavailable.",
                    Severity.INFO if ok else Severity.LOW,
                    ComplianceStatus.PASS if ok else ComplianceStatus.PARTIAL,
                    vault,
                    subscription_id,
                    region,
                    mcsb=["BR-2"],
                    remediation=(
                        ""
                        if ok
                        else "Enable Cross Region Restore: Vault > Properties > Backup Configuration > Cross Region Restore."
                    ),
                )
            )
    except Exception as e:
        return [Finding.not_assessed(
            check_id="azure-rsv-crr",
            title="Unable to check RSV cross-region restore",
            description=f"API call failed: {e}",
            domain=CheckDomain.LOGGING,
            resource_type="Azure::RecoveryServices::Vault",
            account_id=subscription_id,
            region=region,
            cloud_provider=CloudProvider.AZURE,
        )]
    return findings


def check_rsv_redundancy(client: AzureClient, subscription_id: str, region: str) -> list[Finding]:
    """[MCSB BR-2] Storage redundancy should be GRS or GZRS, not LRS."""
    findings: list[Finding] = []
    try:
        for _rs, _b, vault, _rg in _iter_vaults(client):
            props = getattr(vault, "properties", None)
            redundancy = getattr(props, "redundancy_settings", None) if props else None
            stype = (
                str(getattr(redundancy, "standard_tier_storage_redundancy", "LRS") or "LRS")
                if redundancy
                else "LRS"
            )
            ok = stype.upper() in ("GRS", "GZRS")
            findings.append(
                _vault_finding(
                    "azure-rsv-redundancy",
                    f"RSV '{vault.name}' storage type = {stype}",
                    "Geo-redundant storage."
                    if ok
                    else "Locally-redundant only — region loss = data loss.",
                    Severity.INFO if ok else Severity.MEDIUM,
                    ComplianceStatus.PASS if ok else ComplianceStatus.FAIL,
                    vault,
                    subscription_id,
                    region,
                    mcsb=["BR-2"],
                    remediation=(
                        ""
                        if ok
                        else "Switch to GRS or GZRS — must be done before any backup item is registered."
                    ),
                )
            )
    except Exception as e:
        return [Finding.not_assessed(
            check_id="azure-rsv-redundancy",
            title="Unable to check RSV storage redundancy",
            description=f"API call failed: {e}",
            domain=CheckDomain.LOGGING,
            resource_type="Azure::RecoveryServices::Vault",
            account_id=subscription_id,
            region=region,
            cloud_provider=CloudProvider.AZURE,
        )]
    return findings


def check_rsv_cmk(client: AzureClient, subscription_id: str, region: str) -> list[Finding]:
    """[MCSB DP-5] Vault should be encrypted with customer-managed key."""
    findings: list[Finding] = []
    try:
        for _rs, _b, vault, _rg in _iter_vaults(client):
            props = getattr(vault, "properties", None)
            enc = getattr(props, "encryption", None) if props else None
            kvp = getattr(enc, "key_vault_properties", None) if enc else None
            uri = getattr(kvp, "key_uri", None) if kvp else None
            ok = bool(uri)
            findings.append(
                _vault_finding(
                    "azure-rsv-cmk",
                    f"RSV '{vault.name}' CMK encryption {'enabled' if ok else 'disabled'}",
                    "CMK encryption configured." if ok else "Vault uses platform-managed keys.",
                    Severity.INFO if ok else Severity.LOW,
                    ComplianceStatus.PASS if ok else ComplianceStatus.PARTIAL,
                    vault,
                    subscription_id,
                    region,
                    mcsb=["DP-5"],
                    remediation=(
                        ""
                        if ok
                        else "Configure CMK from a Key Vault key URI with auto-rotation and UAMI."
                    ),
                    details={"vault": vault.name, "key_uri": uri},
                )
            )
    except Exception as e:
        return [Finding.not_assessed(
            check_id="azure-rsv-cmk",
            title="Unable to check RSV CMK encryption",
            description=f"API call failed: {e}",
            domain=CheckDomain.LOGGING,
            resource_type="Azure::RecoveryServices::Vault",
            account_id=subscription_id,
            region=region,
            cloud_provider=CloudProvider.AZURE,
        )]
    return findings


def check_rsv_mua(client: AzureClient, subscription_id: str, region: str) -> list[Finding]:
    """[MCSB BR-2] Multi-User Authorization (MUA) should be enabled on critical vaults."""
    findings: list[Finding] = []
    try:
        for _rs, _b, vault, _rg in _iter_vaults(client):
            props = getattr(vault, "properties", None)
            sec = getattr(props, "security_settings", None) if props else None
            mua = getattr(sec, "multi_user_authorization", None) if sec else None
            ok = str(mua or "").lower() == "enabled"
            findings.append(
                _vault_finding(
                    "azure-rsv-mua",
                    f"RSV '{vault.name}' MUA = {mua or 'Disabled'}",
                    "Multi-User Authorization protects against rogue admin destruction."
                    if ok
                    else "MUA disabled — a single compromised admin can delete backups even with soft delete.",
                    Severity.INFO if ok else Severity.LOW,
                    ComplianceStatus.PASS if ok else ComplianceStatus.PARTIAL,
                    vault,
                    subscription_id,
                    region,
                    mcsb=["BR-2"],
                    remediation=(
                        ""
                        if ok
                        else "Configure a Resource Guard in a separate subscription and link it to the vault."
                    ),
                )
            )
    except Exception as e:
        return [Finding.not_assessed(
            check_id="azure-rsv-mua",
            title="Unable to check RSV multi-user authorization",
            description=f"API call failed: {e}",
            domain=CheckDomain.LOGGING,
            resource_type="Azure::RecoveryServices::Vault",
            account_id=subscription_id,
            region=region,
            cloud_provider=CloudProvider.AZURE,
        )]
    return findings


def check_rsv_public_access(
    client: AzureClient, subscription_id: str, region: str
) -> list[Finding]:
    """RSV publicNetworkAccess should be Disabled where Private Endpoint exists."""
    findings: list[Finding] = []
    try:
        for _rs, _b, vault, _rg in _iter_vaults(client):
            props = getattr(vault, "properties", None)
            pna = getattr(props, "public_network_access", "Enabled") if props else "Enabled"
            ok = str(pna).lower() == "disabled"
            findings.append(
                _vault_finding(
                    "azure-rsv-public-access",
                    f"RSV '{vault.name}' publicNetworkAccess={pna}",
                    "Vault is private."
                    if ok
                    else "Vault data plane is reachable from public internet.",
                    Severity.INFO if ok else Severity.LOW,
                    ComplianceStatus.PASS if ok else ComplianceStatus.PARTIAL,
                    vault,
                    subscription_id,
                    region,
                    mcsb=["NS-2"],
                    remediation=(
                        ""
                        if ok
                        else "Set publicNetworkAccess=Disabled and create Private Endpoint connections."
                    ),
                )
            )
    except Exception as e:
        return [Finding.not_assessed(
            check_id="azure-rsv-public-access",
            title="Unable to check RSV public access",
            description=f"API call failed: {e}",
            domain=CheckDomain.LOGGING,
            resource_type="Azure::RecoveryServices::Vault",
            account_id=subscription_id,
            region=region,
            cloud_provider=CloudProvider.AZURE,
        )]
    return findings
