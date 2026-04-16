"""Azure encryption checks for SOC 2 and ISO 27001.

Checks disk encryption, SQL TDE, Key Vault configuration, and SQL public access
for compliance with CC6.7 (Data Protection) and ISO A.8.24 (Cryptography).
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


def run_all_azure_encryption_checks(client: AzureClient) -> list[Finding]:
    """Run all Azure encryption compliance checks."""
    findings: list[Finding] = []
    sub_id = client.account_info.subscription_id if client.account_info else "unknown"
    region = client.account_info.region if client.account_info else "unknown"

    findings.extend(check_disk_encryption(client, sub_id, region))
    findings.extend(check_sql_tde(client, sub_id, region))
    findings.extend(check_sql_auditing(client, sub_id, region))
    findings.extend(check_sql_entra_admin(client, sub_id, region))
    findings.extend(check_sql_min_tls(client, sub_id, region))
    findings.extend(check_keyvault_config(client, sub_id, region))
    findings.extend(check_keyvault_rbac_mode(client, sub_id, region))
    findings.extend(check_keyvault_public_access(client, sub_id, region))
    findings.extend(check_keyvault_key_expiry(client, sub_id, region))
    findings.extend(check_sql_public_access(client, sub_id, region))

    return findings


def check_disk_encryption(client: AzureClient, subscription_id: str, region: str) -> list[Finding]:
    """[CC6.7] Check that all managed disks have encryption enabled."""
    findings: list[Finding] = []

    try:
        from azure.mgmt.compute import ComputeManagementClient

        compute = client.mgmt_client(ComputeManagementClient)

        disks = list(compute.disks.list())
        unencrypted = []
        encrypted_count = 0

        for disk in disks:
            disk_name = disk.name or "unknown"
            disk_id = disk.id or ""

            # All Azure managed disks have SSE with platform-managed keys by default.
            # We check if encryption is explicitly set or if customer-managed keys are used.
            encryption_type = "Unknown"
            if disk.encryption and disk.encryption.type:
                encryption_type = disk.encryption.type
            elif disk.encryption_settings_collection:
                encryption_type = "ADE"  # Azure Disk Encryption

            # Azure enforces SSE by default, so a disk without explicit encryption
            # settings is still encrypted with platform-managed keys.
            # We flag only if encryption is explicitly disabled (rare).
            if encryption_type and encryption_type.lower() in ("none", "unencrypted"):
                unencrypted.append({"name": disk_name, "id": disk_id, "type": encryption_type})
            else:
                encrypted_count += 1

        if unencrypted:
            findings.append(
                Finding(
                    check_id="azure-disk-encryption",
                    title=f"Unencrypted managed disks found ({len(unencrypted)})",
                    description=f"{len(unencrypted)} managed disk(s) do not have encryption enabled.",
                    severity=Severity.HIGH,
                    status=ComplianceStatus.FAIL,
                    domain=CheckDomain.ENCRYPTION,
                    resource_type="Azure::Compute::Disk",
                    resource_id=unencrypted[0]["id"],
                    region=region,
                    account_id=subscription_id,
                    cloud_provider=CloudProvider.AZURE,
                    remediation="Enable Server-Side Encryption (SSE) on managed disks. "
                    "For enhanced protection, use customer-managed keys via Key Vault.",
                    soc2_controls=["CC6.7"],
                    details={"unencrypted_disks": unencrypted},
                )
            )
        else:
            findings.append(
                Finding(
                    check_id="azure-disk-encryption",
                    title=f"All managed disks are encrypted ({encrypted_count} disks)",
                    description=f"All {encrypted_count} managed disk(s) have encryption enabled (SSE with platform or customer-managed keys).",
                    severity=Severity.INFO,
                    status=ComplianceStatus.PASS,
                    domain=CheckDomain.ENCRYPTION,
                    resource_type="Azure::Compute::Disk",
                    resource_id=f"/subscriptions/{subscription_id}/disks",
                    region=region,
                    account_id=subscription_id,
                    cloud_provider=CloudProvider.AZURE,
                    soc2_controls=["CC6.7"],
                    details={"encrypted_count": encrypted_count},
                )
            )

        if not disks:
            findings[-1] = Finding(
                check_id="azure-disk-encryption",
                title="No managed disks found",
                description="No managed disks in the subscription.",
                severity=Severity.INFO,
                status=ComplianceStatus.NOT_APPLICABLE,
                domain=CheckDomain.ENCRYPTION,
                resource_type="Azure::Compute::Disk",
                resource_id=f"/subscriptions/{subscription_id}/disks",
                region=region,
                account_id=subscription_id,
                cloud_provider=CloudProvider.AZURE,
                soc2_controls=["CC6.7"],
            )

    except Exception as e:
        findings.append(
            Finding(
                check_id="azure-disk-encryption",
                title="Disk encryption check failed",
                description=f"Could not check managed disk encryption: {e}",
                severity=Severity.MEDIUM,
                status=ComplianceStatus.NOT_ASSESSED,
                domain=CheckDomain.ENCRYPTION,
                resource_type="Azure::Compute::Disk",
                resource_id=f"/subscriptions/{subscription_id}/disks",
                region=region,
                account_id=subscription_id,
                cloud_provider=CloudProvider.AZURE,
                soc2_controls=["CC6.7"],
            )
        )

    return findings


def check_sql_tde(client: AzureClient, subscription_id: str, region: str) -> list[Finding]:
    """[CC6.7] Check that SQL databases have Transparent Data Encryption enabled."""
    findings: list[Finding] = []

    try:
        from azure.mgmt.sql import SqlManagementClient

        sql_client = client.mgmt_client(SqlManagementClient)

        servers = list(sql_client.servers.list())

        for server in servers:
            server_name = server.name or "unknown"
            server_id = server.id or ""
            server_rg = (
                server_id.split("/resourceGroups/")[1].split("/")[0]
                if "/resourceGroups/" in server_id
                else "unknown"
            )

            databases = list(sql_client.databases.list_by_server(server_rg, server_name))
            for db in databases:
                db_name = db.name or "unknown"
                if db_name == "master":
                    continue  # Skip system database

                db_id = db.id or ""
                try:
                    tde = sql_client.transparent_data_encryptions.get(
                        server_rg, server_name, db_name, "current"
                    )
                    tde_state = tde.state if tde else "Unknown"
                except Exception:
                    tde_state = "Unknown"

                if tde_state and tde_state.lower() == "enabled":
                    findings.append(
                        Finding(
                            check_id="azure-sql-tde",
                            title=f"TDE enabled on '{server_name}/{db_name}'",
                            description=f"SQL Database '{db_name}' on server '{server_name}' has Transparent Data Encryption enabled.",
                            severity=Severity.INFO,
                            status=ComplianceStatus.PASS,
                            domain=CheckDomain.ENCRYPTION,
                            resource_type="Azure::Sql::Database",
                            resource_id=db_id,
                            region=server.location or region,
                            account_id=subscription_id,
                            cloud_provider=CloudProvider.AZURE,
                            soc2_controls=["CC6.7"],
                            details={
                                "server": server_name,
                                "database": db_name,
                                "tde_state": tde_state,
                            },
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            check_id="azure-sql-tde",
                            title=f"TDE not enabled on '{server_name}/{db_name}'",
                            description=f"SQL Database '{db_name}' on server '{server_name}' does not have TDE enabled. "
                            "Data at rest is not encrypted.",
                            severity=Severity.HIGH,
                            status=ComplianceStatus.FAIL,
                            domain=CheckDomain.ENCRYPTION,
                            resource_type="Azure::Sql::Database",
                            resource_id=db_id,
                            region=server.location or region,
                            account_id=subscription_id,
                            cloud_provider=CloudProvider.AZURE,
                            remediation="Enable TDE on the database. "
                            "Portal: SQL Database > Transparent data encryption > Enable.",
                            soc2_controls=["CC6.7"],
                            details={
                                "server": server_name,
                                "database": db_name,
                                "tde_state": tde_state,
                            },
                        )
                    )

    except Exception as e:
        findings.append(
            Finding(
                check_id="azure-sql-tde",
                title="SQL TDE check failed",
                description=f"Could not check SQL Transparent Data Encryption: {e}",
                severity=Severity.MEDIUM,
                status=ComplianceStatus.NOT_ASSESSED,
                domain=CheckDomain.ENCRYPTION,
                resource_type="Azure::Sql::Database",
                resource_id=f"/subscriptions/{subscription_id}/sqlDatabases",
                region=region,
                account_id=subscription_id,
                cloud_provider=CloudProvider.AZURE,
                soc2_controls=["CC6.7"],
            )
        )

    return findings


def check_keyvault_config(client: AzureClient, subscription_id: str, region: str) -> list[Finding]:
    """[CC6.7] Check Key Vault soft-delete and purge protection."""
    findings: list[Finding] = []

    try:
        from azure.mgmt.keyvault import KeyVaultManagementClient

        kv_client = client.mgmt_client(KeyVaultManagementClient)

        vaults = list(kv_client.vaults.list_by_subscription())

        for vault in vaults:
            vault_name = vault.name or "unknown"
            vault_id = vault.id or ""
            props = vault.properties

            soft_delete = props.enable_soft_delete if props else None
            purge_protection = props.enable_purge_protection if props else None

            if soft_delete and purge_protection:
                findings.append(
                    Finding(
                        check_id="azure-keyvault-config",
                        title=f"Key Vault '{vault_name}' has soft delete + purge protection",
                        description=f"Key Vault '{vault_name}' has both soft delete and purge protection enabled.",
                        severity=Severity.INFO,
                        status=ComplianceStatus.PASS,
                        domain=CheckDomain.ENCRYPTION,
                        resource_type="Azure::KeyVault::Vault",
                        resource_id=vault_id,
                        region=vault.location or region,
                        account_id=subscription_id,
                        cloud_provider=CloudProvider.AZURE,
                        soc2_controls=["CC6.7"],
                        details={
                            "vault_name": vault_name,
                            "soft_delete": True,
                            "purge_protection": True,
                        },
                    )
                )
            else:
                missing = []
                if not soft_delete:
                    missing.append("soft delete")
                if not purge_protection:
                    missing.append("purge protection")

                findings.append(
                    Finding(
                        check_id="azure-keyvault-config",
                        title=f"Key Vault '{vault_name}' missing {' and '.join(missing)}",
                        description=f"Key Vault '{vault_name}' does not have {' and '.join(missing)} enabled. "
                        "Without purge protection, deleted keys/secrets can be permanently lost.",
                        severity=Severity.HIGH,
                        status=ComplianceStatus.FAIL,
                        domain=CheckDomain.ENCRYPTION,
                        resource_type="Azure::KeyVault::Vault",
                        resource_id=vault_id,
                        region=vault.location or region,
                        account_id=subscription_id,
                        cloud_provider=CloudProvider.AZURE,
                        remediation="Enable purge protection on the Key Vault. Note: this cannot be disabled once enabled. "
                        "Portal: Key Vault > Properties > Purge protection > Enable.",
                        soc2_controls=["CC6.7"],
                        details={
                            "vault_name": vault_name,
                            "soft_delete": bool(soft_delete),
                            "purge_protection": bool(purge_protection),
                        },
                    )
                )

    except Exception as e:
        findings.append(
            Finding(
                check_id="azure-keyvault-config",
                title="Key Vault check failed",
                description=f"Could not check Key Vault configuration: {e}",
                severity=Severity.MEDIUM,
                status=ComplianceStatus.NOT_ASSESSED,
                domain=CheckDomain.ENCRYPTION,
                resource_type="Azure::KeyVault::Vault",
                resource_id=f"/subscriptions/{subscription_id}/keyVaults",
                region=region,
                account_id=subscription_id,
                cloud_provider=CloudProvider.AZURE,
                soc2_controls=["CC6.7"],
            )
        )

    return findings


def check_sql_public_access(
    client: AzureClient, subscription_id: str, region: str
) -> list[Finding]:
    """[CC6.6, CC6.7] Check SQL Server public network access setting."""
    findings: list[Finding] = []

    try:
        from azure.mgmt.sql import SqlManagementClient

        sql_client = client.mgmt_client(SqlManagementClient)

        servers = list(sql_client.servers.list())

        for server in servers:
            server_name = server.name or "unknown"
            server_id = server.id or ""
            server_rg = (
                server_id.split("/resourceGroups/")[1].split("/")[0]
                if "/resourceGroups/" in server_id
                else "unknown"
            )

            public_access = getattr(server, "public_network_access", None)

            if public_access and public_access.lower() == "disabled":
                findings.append(
                    Finding(
                        check_id="azure-sql-public-access",
                        title=f"SQL Server '{server_name}' has public access disabled",
                        description=f"SQL Server '{server_name}' does not allow public network access.",
                        severity=Severity.INFO,
                        status=ComplianceStatus.PASS,
                        domain=CheckDomain.ENCRYPTION,
                        resource_type="Azure::Sql::Server",
                        resource_id=server_id,
                        region=server.location or region,
                        account_id=subscription_id,
                        cloud_provider=CloudProvider.AZURE,
                        soc2_controls=["CC6.6", "CC6.7"],
                        details={
                            "server": server_name,
                            "resource_group": server_rg,
                            "public_access": "disabled",
                        },
                    )
                )
            else:
                # Also check firewall rules for overly permissive access
                fw_rules = list(sql_client.firewall_rules.list_by_server(server_rg, server_name))
                allow_all_azure = any(
                    r.start_ip_address == "0.0.0.0" and r.end_ip_address == "0.0.0.0"
                    for r in fw_rules
                )
                allow_all = any(
                    r.start_ip_address == "0.0.0.0" and r.end_ip_address == "255.255.255.255"
                    for r in fw_rules
                )

                severity = (
                    Severity.CRITICAL
                    if allow_all
                    else (Severity.HIGH if allow_all_azure else Severity.MEDIUM)
                )

                findings.append(
                    Finding(
                        check_id="azure-sql-public-access",
                        title=f"SQL Server '{server_name}' has public access enabled",
                        description=f"SQL Server '{server_name}' allows public network access"
                        + (" with allow-all-Azure firewall rule" if allow_all_azure else "")
                        + (
                            ". Firewall allows ALL IPs (0.0.0.0 - 255.255.255.255)"
                            if allow_all
                            else ""
                        )
                        + ". This exposes the database to the internet.",
                        severity=severity,
                        status=ComplianceStatus.FAIL,
                        domain=CheckDomain.ENCRYPTION,
                        resource_type="Azure::Sql::Server",
                        resource_id=server_id,
                        region=server.location or region,
                        account_id=subscription_id,
                        cloud_provider=CloudProvider.AZURE,
                        remediation="Disable public network access on SQL Server and use Private Endpoints. "
                        "Portal: SQL Server > Networking > Public access > Disable.",
                        soc2_controls=["CC6.6", "CC6.7"],
                        details={
                            "server": server_name,
                            "resource_group": server_rg,
                            "public_access": "enabled",
                            "firewall_rules": len(fw_rules),
                            "allow_all_azure": allow_all_azure,
                            "allow_all_ips": allow_all,
                        },
                    )
                )

    except Exception as e:
        findings.append(
            Finding(
                check_id="azure-sql-public-access",
                title="SQL public access check failed",
                description=f"Could not check SQL Server public access: {e}",
                severity=Severity.MEDIUM,
                status=ComplianceStatus.NOT_ASSESSED,
                domain=CheckDomain.ENCRYPTION,
                resource_type="Azure::Sql::Server",
                resource_id=f"/subscriptions/{subscription_id}/sqlServers",
                region=region,
                account_id=subscription_id,
                cloud_provider=CloudProvider.AZURE,
                soc2_controls=["CC6.6", "CC6.7"],
            )
        )

    return findings


# ---------------------------------------------------------------------------
# CIS Azure v3.0 Encryption / SQL / Key Vault checks (Stage 1 additions)
# ---------------------------------------------------------------------------


def _iter_sql_servers(client: AzureClient):
    """Yield (sql_client, server, server_rg) for every SQL server in the subscription."""
    try:
        from azure.mgmt.sql import SqlManagementClient
    except ImportError:
        return
    sql = client.mgmt_client(SqlManagementClient)
    for server in sql.servers.list():
        sid = server.id or ""
        rg = sid.split("/resourceGroups/")[1].split("/")[0] if "/resourceGroups/" in sid else ""
        yield sql, server, rg


def check_sql_auditing(client: AzureClient, subscription_id: str, region: str) -> list[Finding]:
    """[CIS 4.1.1] Server-level SQL auditing must be enabled with retention ≥ 90 days."""
    findings: list[Finding] = []
    found_any = False
    try:
        for sql, server, rg in _iter_sql_servers(client):
            found_any = True
            try:
                audit = sql.server_blob_auditing_policies.get(rg, server.name)
            except Exception:
                continue
            state = (getattr(audit, "state", "") or "Disabled").lower()
            retention = int(getattr(audit, "retention_days", 0) or 0)
            ok = state == "enabled" and (retention == 0 or retention >= 90)
            if ok:
                findings.append(
                    Finding(
                        check_id="azure-sql-auditing",
                        title=f"SQL Server '{server.name}' auditing enabled (retention {retention or 'unlimited'} d)",
                        description="Server-level blob auditing is enabled with adequate retention.",
                        severity=Severity.INFO,
                        status=ComplianceStatus.PASS,
                        domain=CheckDomain.ENCRYPTION,
                        resource_type="Azure::Sql::Server",
                        resource_id=server.id or "",
                        region=server.location or region,
                        account_id=subscription_id,
                        cloud_provider=CloudProvider.AZURE,
                        soc2_controls=["CC7.1", "CC7.2"],
                        cis_azure_controls=["4.1.1", "4.1.6"],
                        details={"server": server.name, "retention_days": retention},
                    )
                )
            else:
                findings.append(
                    Finding(
                        check_id="azure-sql-auditing",
                        title=f"SQL Server '{server.name}' auditing not configured to spec",
                        description=(
                            f"Auditing state={state}, retention={retention}d. CIS requires "
                            "auditing enabled with retention ≥ 90 days. Without server-level "
                            "auditing, anomalous queries and DDL changes leave no trace."
                        ),
                        severity=Severity.HIGH,
                        status=ComplianceStatus.FAIL,
                        domain=CheckDomain.ENCRYPTION,
                        resource_type="Azure::Sql::Server",
                        resource_id=server.id or "",
                        region=server.location or region,
                        account_id=subscription_id,
                        cloud_provider=CloudProvider.AZURE,
                        remediation=(
                            "Enable server-level auditing and target Log Analytics with retention "
                            "≥90 days. Portal: SQL Server > Auditing > Enable > Log Analytics."
                        ),
                        soc2_controls=["CC7.1", "CC7.2"],
                        cis_azure_controls=["4.1.1", "4.1.6"],
                        details={
                            "server": server.name,
                            "state": state,
                            "retention_days": retention,
                        },
                    )
                )
    except Exception as e:
        return [
            Finding(
                check_id="azure-sql-auditing",
                title="SQL auditing check failed",
                description=f"Could not enumerate SQL auditing policies: {e}",
                severity=Severity.MEDIUM,
                status=ComplianceStatus.NOT_ASSESSED,
                domain=CheckDomain.ENCRYPTION,
                resource_type="Azure::Sql::Server",
                resource_id=f"/subscriptions/{subscription_id}/sqlServers",
                region=region,
                account_id=subscription_id,
                cloud_provider=CloudProvider.AZURE,
                soc2_controls=["CC7.1", "CC7.2"],
                cis_azure_controls=["4.1.1"],
            )
        ]
    if not found_any:
        return []
    return findings


def check_sql_entra_admin(client: AzureClient, subscription_id: str, region: str) -> list[Finding]:
    """[CIS 4.1.3] SQL Server should have an Entra ID (Azure AD) admin configured."""
    findings: list[Finding] = []
    try:
        for sql, server, rg in _iter_sql_servers(client):
            try:
                admins = list(sql.server_azure_ad_administrators.list_by_server(rg, server.name))
            except Exception:
                admins = []
            if admins:
                findings.append(
                    Finding(
                        check_id="azure-sql-entra-admin",
                        title=f"SQL Server '{server.name}' has Entra ID admin",
                        description=f"Entra ID admin configured: {admins[0].login or 'unknown'}.",
                        severity=Severity.INFO,
                        status=ComplianceStatus.PASS,
                        domain=CheckDomain.ENCRYPTION,
                        resource_type="Azure::Sql::Server",
                        resource_id=server.id or "",
                        region=server.location or region,
                        account_id=subscription_id,
                        cloud_provider=CloudProvider.AZURE,
                        soc2_controls=["CC6.1", "CC6.2"],
                        cis_azure_controls=["4.1.3"],
                        details={"server": server.name, "admin": admins[0].login or ""},
                    )
                )
            else:
                findings.append(
                    Finding(
                        check_id="azure-sql-entra-admin",
                        title=f"SQL Server '{server.name}' has no Entra ID admin",
                        description=(
                            "No Entra ID administrator is configured. Without one, only SQL "
                            "authentication can manage the server, which means no MFA, no "
                            "Conditional Access, and credentials cycling outside identity governance."
                        ),
                        severity=Severity.MEDIUM,
                        status=ComplianceStatus.FAIL,
                        domain=CheckDomain.ENCRYPTION,
                        resource_type="Azure::Sql::Server",
                        resource_id=server.id or "",
                        region=server.location or region,
                        account_id=subscription_id,
                        cloud_provider=CloudProvider.AZURE,
                        remediation=(
                            "Set an Entra ID admin (group preferred). Portal: SQL Server > "
                            "Microsoft Entra ID > Set admin."
                        ),
                        soc2_controls=["CC6.1", "CC6.2"],
                        cis_azure_controls=["4.1.3"],
                        details={"server": server.name},
                    )
                )
    except Exception as e:
        return [Finding.not_assessed(
            check_id="azure-sql-entra-admin",
            title="Unable to check SQL Server Entra ID admin",
            description=f"API call failed: {e}",
            domain=CheckDomain.ENCRYPTION,
            resource_type="Azure::Sql::Server",
            account_id=subscription_id,
            region=region,
            cloud_provider=CloudProvider.AZURE,
        )]
    return findings


def check_sql_min_tls(client: AzureClient, subscription_id: str, region: str) -> list[Finding]:
    """[CIS 4.1.x] SQL Server minimalTlsVersion should be 1.2 or higher."""
    findings: list[Finding] = []
    try:
        for _sql, server, _rg in _iter_sql_servers(client):
            min_tls = getattr(server, "minimal_tls_version", None) or "None"
            ok = min_tls in ("1.2", "1.3")
            if ok:
                findings.append(
                    Finding(
                        check_id="azure-sql-min-tls",
                        title=f"SQL Server '{server.name}' enforces TLS {min_tls}",
                        description=f"minimalTlsVersion = {min_tls}.",
                        severity=Severity.INFO,
                        status=ComplianceStatus.PASS,
                        domain=CheckDomain.ENCRYPTION,
                        resource_type="Azure::Sql::Server",
                        resource_id=server.id or "",
                        region=server.location or region,
                        account_id=subscription_id,
                        cloud_provider=CloudProvider.AZURE,
                        soc2_controls=["CC6.1", "CC6.7"],
                        cis_azure_controls=["4.1.7"],
                        details={"server": server.name, "min_tls": min_tls},
                    )
                )
            else:
                findings.append(
                    Finding(
                        check_id="azure-sql-min-tls",
                        title=f"SQL Server '{server.name}' min TLS = {min_tls}",
                        description=(
                            f"minimalTlsVersion = {min_tls}. Allows TLS 1.0/1.1 with known "
                            "cryptographic weaknesses."
                        ),
                        severity=Severity.MEDIUM,
                        status=ComplianceStatus.FAIL,
                        domain=CheckDomain.ENCRYPTION,
                        resource_type="Azure::Sql::Server",
                        resource_id=server.id or "",
                        region=server.location or region,
                        account_id=subscription_id,
                        cloud_provider=CloudProvider.AZURE,
                        remediation=(
                            "az sql server update -g <rg> -n <server> --minimal-tls-version 1.2"
                        ),
                        soc2_controls=["CC6.1", "CC6.7"],
                        cis_azure_controls=["4.1.7"],
                        details={"server": server.name, "min_tls": min_tls},
                    )
                )
    except Exception as e:
        return [Finding.not_assessed(
            check_id="azure-sql-min-tls",
            title="Unable to check SQL Server minimum TLS version",
            description=f"API call failed: {e}",
            domain=CheckDomain.ENCRYPTION,
            resource_type="Azure::Sql::Server",
            account_id=subscription_id,
            region=region,
            cloud_provider=CloudProvider.AZURE,
        )]
    return findings


def _iter_keyvaults(client: AzureClient):
    try:
        from azure.mgmt.keyvault import KeyVaultManagementClient
    except ImportError:
        return
    kv = client.mgmt_client(KeyVaultManagementClient)
    for v in kv.vaults.list_by_subscription():
        yield kv, v


def check_keyvault_rbac_mode(
    client: AzureClient, subscription_id: str, region: str
) -> list[Finding]:
    """[CIS 8.5] Key Vault should use RBAC, not legacy access policies."""
    findings: list[Finding] = []
    try:
        for _kv, vault in _iter_keyvaults(client):
            props = vault.properties
            rbac = bool(getattr(props, "enable_rbac_authorization", False))
            if rbac:
                findings.append(
                    Finding(
                        check_id="azure-keyvault-rbac-mode",
                        title=f"Key Vault '{vault.name}' uses RBAC",
                        description="Vault permission model is Azure RBAC.",
                        severity=Severity.INFO,
                        status=ComplianceStatus.PASS,
                        domain=CheckDomain.ENCRYPTION,
                        resource_type="Azure::KeyVault::Vault",
                        resource_id=vault.id or "",
                        region=vault.location or region,
                        account_id=subscription_id,
                        cloud_provider=CloudProvider.AZURE,
                        soc2_controls=["CC6.1", "CC6.2"],
                        cis_azure_controls=["8.5"],
                        details={"vault": vault.name},
                    )
                )
            else:
                findings.append(
                    Finding(
                        check_id="azure-keyvault-rbac-mode",
                        title=f"Key Vault '{vault.name}' uses legacy access policies",
                        description=(
                            "Vault uses access policies (vault local model) instead of RBAC. "
                            "Access policies don't integrate with PIM or Conditional Access "
                            "and can't be reviewed centrally."
                        ),
                        severity=Severity.MEDIUM,
                        status=ComplianceStatus.FAIL,
                        domain=CheckDomain.ENCRYPTION,
                        resource_type="Azure::KeyVault::Vault",
                        resource_id=vault.id or "",
                        region=vault.location or region,
                        account_id=subscription_id,
                        cloud_provider=CloudProvider.AZURE,
                        remediation=(
                            "Migrate to RBAC: Key Vault > Access configuration > "
                            "Permission model > Azure role-based access control. Re-grant access "
                            "via Key Vault Administrator / Secrets User / Crypto User roles."
                        ),
                        soc2_controls=["CC6.1", "CC6.2"],
                        cis_azure_controls=["8.5"],
                        details={"vault": vault.name},
                    )
                )
    except Exception as e:
        return [Finding.not_assessed(
            check_id="azure-keyvault-rbac-mode",
            title="Unable to check Key Vault RBAC mode",
            description=f"API call failed: {e}",
            domain=CheckDomain.ENCRYPTION,
            resource_type="Azure::KeyVault::Vault",
            account_id=subscription_id,
            region=region,
            cloud_provider=CloudProvider.AZURE,
        )]
    return findings


def check_keyvault_public_access(
    client: AzureClient, subscription_id: str, region: str
) -> list[Finding]:
    """[CIS 8.7] Key Vault publicNetworkAccess should be Disabled with private endpoint."""
    findings: list[Finding] = []
    try:
        for _kv, vault in _iter_keyvaults(client):
            props = vault.properties
            pna = getattr(props, "public_network_access", "") or "Enabled"
            net_acls = getattr(props, "network_acls", None)
            default_action = getattr(net_acls, "default_action", "Allow") if net_acls else "Allow"
            if str(pna).lower() == "disabled" or str(default_action).lower() == "deny":
                findings.append(
                    Finding(
                        check_id="azure-keyvault-public-access",
                        title=f"Key Vault '{vault.name}' restricts public network access",
                        description=f"publicNetworkAccess={pna}, defaultAction={default_action}",
                        severity=Severity.INFO,
                        status=ComplianceStatus.PASS,
                        domain=CheckDomain.ENCRYPTION,
                        resource_type="Azure::KeyVault::Vault",
                        resource_id=vault.id or "",
                        region=vault.location or region,
                        account_id=subscription_id,
                        cloud_provider=CloudProvider.AZURE,
                        soc2_controls=["CC6.6", "CC6.7"],
                        cis_azure_controls=["8.6", "8.7"],
                        mcsb_controls=["NS-2"],
                        details={"vault": vault.name, "pna": pna, "default_action": default_action},
                    )
                )
            else:
                findings.append(
                    Finding(
                        check_id="azure-keyvault-public-access",
                        title=f"Key Vault '{vault.name}' is reachable from the public internet",
                        description=(
                            f"publicNetworkAccess={pna}, network defaultAction={default_action}. "
                            "Anyone with the right Entra ID identity can attempt key/secret access "
                            "from anywhere on the internet. Combined with a stolen token or "
                            "managed identity hijack, this is a direct path to secrets."
                        ),
                        severity=Severity.HIGH,
                        status=ComplianceStatus.FAIL,
                        domain=CheckDomain.ENCRYPTION,
                        resource_type="Azure::KeyVault::Vault",
                        resource_id=vault.id or "",
                        region=vault.location or region,
                        account_id=subscription_id,
                        cloud_provider=CloudProvider.AZURE,
                        remediation=(
                            "Set publicNetworkAccess = Disabled and create a Private Endpoint. "
                            "Alternatively set networkAcls.defaultAction = Deny and allow only "
                            "specific VNets/IPs."
                        ),
                        soc2_controls=["CC6.6", "CC6.7"],
                        cis_azure_controls=["8.6", "8.7"],
                        mcsb_controls=["NS-2"],
                        details={"vault": vault.name, "pna": pna, "default_action": default_action},
                    )
                )
    except Exception as e:
        return [Finding.not_assessed(
            check_id="azure-keyvault-public-access",
            title="Unable to check Key Vault public access",
            description=f"API call failed: {e}",
            domain=CheckDomain.ENCRYPTION,
            resource_type="Azure::KeyVault::Vault",
            account_id=subscription_id,
            region=region,
            cloud_provider=CloudProvider.AZURE,
        )]
    return findings


def check_keyvault_key_expiry(
    client: AzureClient, subscription_id: str, region: str
) -> list[Finding]:
    """[CIS 8.3, 8.4] Every key and secret in Key Vault should have an expiration date."""
    findings: list[Finding] = []
    try:
        from azure.keyvault.keys import KeyClient
        from azure.keyvault.secrets import SecretClient
    except ImportError:
        return []

    try:
        for _kv, vault in _iter_keyvaults(client):
            vault_uri = (
                getattr(vault.properties, "vault_uri", None)
                or f"https://{vault.name}.vault.azure.net"
            )
            keys_no_exp: list[str] = []
            secrets_no_exp: list[str] = []
            try:
                key_client = KeyClient(vault_uri=vault_uri, credential=client.credential)
                for k in key_client.list_properties_of_keys():
                    if k.expires_on is None:
                        keys_no_exp.append(k.name or "")
            except Exception:
                pass
            try:
                sec_client = SecretClient(vault_uri=vault_uri, credential=client.credential)
                for s in sec_client.list_properties_of_secrets():
                    if s.expires_on is None:
                        secrets_no_exp.append(s.name or "")
            except Exception:
                pass

            total_missing = len(keys_no_exp) + len(secrets_no_exp)
            if total_missing == 0:
                findings.append(
                    Finding(
                        check_id="azure-keyvault-key-expiry",
                        title=f"Key Vault '{vault.name}' — all keys/secrets have expiry",
                        description="Every key and secret has an expiration date set.",
                        severity=Severity.INFO,
                        status=ComplianceStatus.PASS,
                        domain=CheckDomain.ENCRYPTION,
                        resource_type="Azure::KeyVault::Vault",
                        resource_id=vault.id or "",
                        region=vault.location or region,
                        account_id=subscription_id,
                        cloud_provider=CloudProvider.AZURE,
                        soc2_controls=["CC6.7"],
                        cis_azure_controls=["8.3", "8.4"],
                        details={"vault": vault.name},
                    )
                )
            else:
                findings.append(
                    Finding(
                        check_id="azure-keyvault-key-expiry",
                        title=f"Key Vault '{vault.name}' — {total_missing} key(s)/secret(s) lack expiry",
                        description=(
                            f"{len(keys_no_exp)} key(s) and {len(secrets_no_exp)} secret(s) have "
                            "no expiration date. Without expiry, stale credentials accumulate "
                            "indefinitely and rotation cannot be enforced via policy."
                        ),
                        severity=Severity.MEDIUM,
                        status=ComplianceStatus.FAIL,
                        domain=CheckDomain.ENCRYPTION,
                        resource_type="Azure::KeyVault::Vault",
                        resource_id=vault.id or "",
                        region=vault.location or region,
                        account_id=subscription_id,
                        cloud_provider=CloudProvider.AZURE,
                        remediation=(
                            "Set expiration on every key/secret. Use rotation policies on keys "
                            "(properties > rotation policy) and update consuming apps to fetch by "
                            "version-less URI."
                        ),
                        soc2_controls=["CC6.7"],
                        cis_azure_controls=["8.3", "8.4"],
                        details={
                            "vault": vault.name,
                            "keys_without_expiry": keys_no_exp[:20],
                            "secrets_without_expiry": secrets_no_exp[:20],
                        },
                    )
                )
    except Exception as e:
        return [Finding.not_assessed(
            check_id="azure-keyvault-key-expiry",
            title="Unable to check Key Vault key/secret expiry",
            description=f"API call failed: {e}",
            domain=CheckDomain.ENCRYPTION,
            resource_type="Azure::KeyVault::Vault",
            account_id=subscription_id,
            region=region,
            cloud_provider=CloudProvider.AZURE,
        )]
    return findings
