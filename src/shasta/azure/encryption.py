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
    findings.extend(check_keyvault_config(client, sub_id, region))
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
