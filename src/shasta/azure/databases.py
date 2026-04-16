"""Azure database security checks for Cosmos DB, PostgreSQL, and MySQL.

Covers CIS Azure v3.0 sections 4.3 (PostgreSQL), 4.4 (MySQL), and 4.5 (Cosmos).
Each check returns one Finding per database server / account.
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


def run_all_azure_database_checks(client: AzureClient) -> list[Finding]:
    """Run all Azure database (Cosmos / PostgreSQL / MySQL) checks."""
    findings: list[Finding] = []
    sub_id = client.account_info.subscription_id if client.account_info else "unknown"
    region = client.account_info.region if client.account_info else "unknown"

    findings.extend(check_cosmos_disable_local_auth(client, sub_id, region))
    findings.extend(check_cosmos_public_network_access(client, sub_id, region))
    findings.extend(check_cosmos_firewall_rules(client, sub_id, region))
    findings.extend(check_cosmos_metadata_write_disabled(client, sub_id, region))
    findings.extend(check_cosmos_cmk(client, sub_id, region))
    findings.extend(check_postgresql_secure_transport(client, sub_id, region))
    findings.extend(check_postgresql_log_settings(client, sub_id, region))
    findings.extend(check_postgresql_public_access(client, sub_id, region))
    findings.extend(check_mysql_secure_transport(client, sub_id, region))
    findings.extend(check_mysql_tls_version(client, sub_id, region))
    findings.extend(check_mysql_audit_log(client, sub_id, region))

    return findings


# ---------------------------------------------------------------------------
# Cosmos DB
# ---------------------------------------------------------------------------


def _iter_cosmos_accounts(client: AzureClient):
    try:
        from azure.mgmt.cosmosdb import CosmosDBManagementClient
    except ImportError:
        return
    cosmos = client.mgmt_client(CosmosDBManagementClient)
    for acct in cosmos.database_accounts.list():
        yield cosmos, acct


def _cosmos_finding(
    check_id: str,
    title: str,
    description: str,
    severity: Severity,
    status: ComplianceStatus,
    acct: Any,
    sub_id: str,
    region: str,
    cis: list[str],
    remediation: str = "",
    details: dict | None = None,
) -> Finding:
    return Finding(
        check_id=check_id,
        title=title,
        description=description,
        severity=severity,
        status=status,
        domain=CheckDomain.STORAGE,
        resource_type="Azure::Cosmos::DatabaseAccount",
        resource_id=acct.id or "",
        region=acct.location or region,
        account_id=sub_id,
        cloud_provider=CloudProvider.AZURE,
        remediation=remediation,
        soc2_controls=["CC6.1", "CC6.7"],
        cis_azure_controls=cis,
        details=details or {"account": acct.name},
    )


def check_cosmos_disable_local_auth(
    client: AzureClient, subscription_id: str, region: str
) -> list[Finding]:
    """[CIS 4.5] Cosmos DB accounts should disable local (key) auth."""
    findings: list[Finding] = []
    try:
        for _c, acct in _iter_cosmos_accounts(client):
            disable_local = bool(getattr(acct, "disable_local_auth", False))
            if disable_local:
                findings.append(
                    _cosmos_finding(
                        "azure-cosmos-disable-local-auth",
                        f"Cosmos account '{acct.name}' has local auth disabled",
                        "Account uses Entra ID-only authentication. Account keys cannot be used.",
                        Severity.INFO,
                        ComplianceStatus.PASS,
                        acct,
                        subscription_id,
                        region,
                        ["4.5.1"],
                    )
                )
            else:
                findings.append(
                    _cosmos_finding(
                        "azure-cosmos-disable-local-auth",
                        f"Cosmos account '{acct.name}' allows key-based auth",
                        "disableLocalAuth is false. Account keys grant full access without "
                        "Entra ID identity, RBAC, or audit attribution.",
                        Severity.HIGH,
                        ComplianceStatus.FAIL,
                        acct,
                        subscription_id,
                        region,
                        ["4.5.1"],
                        remediation="az cosmosdb update -g <rg> -n <acct> --disable-local-auth true",
                    )
                )
    except Exception as e:
        return [Finding.not_assessed(
            check_id="azure-cosmos-disable-local-auth",
            title="Unable to check Cosmos DB local auth",
            description=f"API call failed: {e}",
            domain=CheckDomain.STORAGE,
            resource_type="Azure::Cosmos::DatabaseAccount",
            account_id=subscription_id,
            region=region,
            cloud_provider=CloudProvider.AZURE,
        )]
    return findings


def check_cosmos_public_network_access(
    client: AzureClient, subscription_id: str, region: str
) -> list[Finding]:
    """[CIS 4.5] Cosmos DB publicNetworkAccess should be Disabled with private endpoints."""
    findings: list[Finding] = []
    try:
        for _c, acct in _iter_cosmos_accounts(client):
            pna = getattr(acct, "public_network_access", "") or "Enabled"
            if str(pna).lower() == "disabled":
                findings.append(
                    _cosmos_finding(
                        "azure-cosmos-public-access",
                        f"Cosmos account '{acct.name}' has public access disabled",
                        f"publicNetworkAccess={pna}.",
                        Severity.INFO,
                        ComplianceStatus.PASS,
                        acct,
                        subscription_id,
                        region,
                        ["4.5.2"],
                    )
                )
            else:
                findings.append(
                    _cosmos_finding(
                        "azure-cosmos-public-access",
                        f"Cosmos account '{acct.name}' allows public network access",
                        f"publicNetworkAccess={pna}. Combined with shared keys this is a direct "
                        "exfiltration path.",
                        Severity.HIGH,
                        ComplianceStatus.FAIL,
                        acct,
                        subscription_id,
                        region,
                        ["4.5.2"],
                        remediation="Set publicNetworkAccess=Disabled and create a Private Endpoint.",
                    )
                )
    except Exception as e:
        return [Finding.not_assessed(
            check_id="azure-cosmos-public-access",
            title="Unable to check Cosmos DB public network access",
            description=f"API call failed: {e}",
            domain=CheckDomain.STORAGE,
            resource_type="Azure::Cosmos::DatabaseAccount",
            account_id=subscription_id,
            region=region,
            cloud_provider=CloudProvider.AZURE,
        )]
    return findings


def check_cosmos_firewall_rules(
    client: AzureClient, subscription_id: str, region: str
) -> list[Finding]:
    """[CIS 4.5] Cosmos DB should not have an empty IP firewall when public access is enabled."""
    findings: list[Finding] = []
    try:
        for _c, acct in _iter_cosmos_accounts(client):
            ip_rules = list(getattr(acct, "ip_rules", []) or [])
            vnet_rules = list(getattr(acct, "virtual_network_rules", []) or [])
            pna = str(getattr(acct, "public_network_access", "") or "Enabled").lower()
            if pna != "enabled":
                continue
            allow_all = any(
                str(getattr(r, "ip_address_or_range", "")) in ("0.0.0.0", "0.0.0.0/0")
                for r in ip_rules
            )
            if (not ip_rules and not vnet_rules) or allow_all:
                findings.append(
                    _cosmos_finding(
                        "azure-cosmos-firewall",
                        f"Cosmos account '{acct.name}' has open firewall",
                        "Public access is enabled with no IP/VNet restrictions"
                        + (" and an allow-all rule" if allow_all else "")
                        + ". Any network can reach the data plane.",
                        Severity.HIGH,
                        ComplianceStatus.FAIL,
                        acct,
                        subscription_id,
                        region,
                        ["4.5.3"],
                        remediation="Add explicit IP/VNet rules or disable public network access.",
                        details={
                            "account": acct.name,
                            "ip_rules": len(ip_rules),
                            "vnet_rules": len(vnet_rules),
                        },
                    )
                )
            else:
                findings.append(
                    _cosmos_finding(
                        "azure-cosmos-firewall",
                        f"Cosmos account '{acct.name}' firewall is restricted",
                        f"{len(ip_rules)} IP rule(s), {len(vnet_rules)} VNet rule(s).",
                        Severity.INFO,
                        ComplianceStatus.PASS,
                        acct,
                        subscription_id,
                        region,
                        ["4.5.3"],
                    )
                )
    except Exception as e:
        return [Finding.not_assessed(
            check_id="azure-cosmos-firewall",
            title="Unable to check Cosmos DB firewall rules",
            description=f"API call failed: {e}",
            domain=CheckDomain.STORAGE,
            resource_type="Azure::Cosmos::DatabaseAccount",
            account_id=subscription_id,
            region=region,
            cloud_provider=CloudProvider.AZURE,
        )]
    return findings


def check_cosmos_metadata_write_disabled(
    client: AzureClient, subscription_id: str, region: str
) -> list[Finding]:
    """[CIS 4.5] disableKeyBasedMetadataWriteAccess should be true."""
    findings: list[Finding] = []
    try:
        for _c, acct in _iter_cosmos_accounts(client):
            disabled = bool(getattr(acct, "disable_key_based_metadata_write_access", False))
            findings.append(
                _cosmos_finding(
                    "azure-cosmos-metadata-write",
                    f"Cosmos account '{acct.name}' metadata-write {'restricted' if disabled else 'open'}",
                    "disableKeyBasedMetadataWriteAccess is "
                    + ("true." if disabled else "false — keys can modify databases/containers."),
                    Severity.INFO if disabled else Severity.MEDIUM,
                    ComplianceStatus.PASS if disabled else ComplianceStatus.FAIL,
                    acct,
                    subscription_id,
                    region,
                    ["4.5.4"],
                    remediation=(
                        ""
                        if disabled
                        else "Set disableKeyBasedMetadataWriteAccess=true to require ARM-level RBAC for schema changes."
                    ),
                )
            )
    except Exception as e:
        return [Finding.not_assessed(
            check_id="azure-cosmos-metadata-write",
            title="Unable to check Cosmos DB metadata write access",
            description=f"API call failed: {e}",
            domain=CheckDomain.STORAGE,
            resource_type="Azure::Cosmos::DatabaseAccount",
            account_id=subscription_id,
            region=region,
            cloud_provider=CloudProvider.AZURE,
        )]
    return findings


def check_cosmos_cmk(client: AzureClient, subscription_id: str, region: str) -> list[Finding]:
    """[CIS 4.5] Cosmos DB should use customer-managed encryption keys."""
    findings: list[Finding] = []
    try:
        for _c, acct in _iter_cosmos_accounts(client):
            cmk_uri = getattr(acct, "key_vault_key_uri", None)
            if cmk_uri:
                findings.append(
                    _cosmos_finding(
                        "azure-cosmos-cmk",
                        f"Cosmos account '{acct.name}' uses CMK encryption",
                        "Customer-managed key URI present.",
                        Severity.INFO,
                        ComplianceStatus.PASS,
                        acct,
                        subscription_id,
                        region,
                        ["4.5.5"],
                        details={"account": acct.name, "key_uri": cmk_uri},
                    )
                )
            else:
                findings.append(
                    _cosmos_finding(
                        "azure-cosmos-cmk",
                        f"Cosmos account '{acct.name}' uses platform-managed keys",
                        "No customer-managed key configured. Compliance regimes (PCI, HIPAA "
                        "BAA, FedRAMP High) typically require BYOK for sensitive data.",
                        Severity.LOW,
                        ComplianceStatus.FAIL,
                        acct,
                        subscription_id,
                        region,
                        ["4.5.5"],
                        remediation="Configure CMK from a Key Vault key URI when re-creating the account.",
                    )
                )
    except Exception as e:
        return [Finding.not_assessed(
            check_id="azure-cosmos-cmk",
            title="Unable to check Cosmos DB CMK encryption",
            description=f"API call failed: {e}",
            domain=CheckDomain.STORAGE,
            resource_type="Azure::Cosmos::DatabaseAccount",
            account_id=subscription_id,
            region=region,
            cloud_provider=CloudProvider.AZURE,
        )]
    return findings


# ---------------------------------------------------------------------------
# PostgreSQL Flexible Server
# ---------------------------------------------------------------------------


def _iter_postgres_servers(client: AzureClient):
    try:
        from azure.mgmt.rdbms.postgresql_flexibleservers import PostgreSQLManagementClient
    except ImportError:
        return
    pg = client.mgmt_client(PostgreSQLManagementClient)
    for server in pg.servers.list():
        yield pg, server


def _pg_param(pg, rg: str, server_name: str, name: str) -> str | None:
    try:
        cfg = pg.configurations.get(rg, server_name, name)
        return getattr(cfg, "value", None)
    except Exception:
        return None


def _server_rg(server) -> str:
    sid = server.id or ""
    return sid.split("/resourceGroups/")[1].split("/")[0] if "/resourceGroups/" in sid else ""


def check_postgresql_secure_transport(
    client: AzureClient, subscription_id: str, region: str
) -> list[Finding]:
    """[CIS 4.3.1] PostgreSQL Flexible Server require_secure_transport = ON."""
    findings: list[Finding] = []
    try:
        for pg, server in _iter_postgres_servers(client):
            rg = _server_rg(server)
            val = _pg_param(pg, rg, server.name, "require_secure_transport")
            ok = (val or "").lower() == "on"
            findings.append(
                Finding(
                    check_id="azure-postgres-secure-transport",
                    title=f"PostgreSQL '{server.name}' require_secure_transport={val or 'unknown'}",
                    description=(
                        "Secure transport enforced."
                        if ok
                        else "Plaintext connections allowed — TLS must be enforced server-side."
                    ),
                    severity=Severity.INFO if ok else Severity.HIGH,
                    status=ComplianceStatus.PASS if ok else ComplianceStatus.FAIL,
                    domain=CheckDomain.ENCRYPTION,
                    resource_type="Azure::DBforPostgreSQL::FlexibleServer",
                    resource_id=server.id or "",
                    region=server.location or region,
                    account_id=subscription_id,
                    cloud_provider=CloudProvider.AZURE,
                    remediation=(
                        ""
                        if ok
                        else "az postgres flexible-server parameter set --name require_secure_transport --value on -g <rg> -s <server>"
                    ),
                    soc2_controls=["CC6.1", "CC6.7"],
                    cis_azure_controls=["4.3.1"],
                    details={"server": server.name, "value": val},
                )
            )
    except Exception as e:
        return [Finding.not_assessed(
            check_id="azure-postgres-secure-transport",
            title="Unable to check PostgreSQL secure transport",
            description=f"API call failed: {e}",
            domain=CheckDomain.ENCRYPTION,
            resource_type="Azure::DBforPostgreSQL::FlexibleServer",
            account_id=subscription_id,
            region=region,
            cloud_provider=CloudProvider.AZURE,
        )]
    return findings


def check_postgresql_log_settings(
    client: AzureClient, subscription_id: str, region: str
) -> list[Finding]:
    """[CIS 4.3.x] PostgreSQL log_connections, log_disconnections, log_checkpoints should be ON."""
    findings: list[Finding] = []
    try:
        for pg, server in _iter_postgres_servers(client):
            rg = _server_rg(server)
            wanted = ["log_connections", "log_disconnections", "log_checkpoints"]
            actual = {k: (_pg_param(pg, rg, server.name, k) or "").lower() for k in wanted}
            missing = [k for k, v in actual.items() if v != "on"]
            if not missing:
                findings.append(
                    Finding(
                        check_id="azure-postgres-log-settings",
                        title=f"PostgreSQL '{server.name}' has connection logging enabled",
                        description="log_connections, log_disconnections, and log_checkpoints are all ON.",
                        severity=Severity.INFO,
                        status=ComplianceStatus.PASS,
                        domain=CheckDomain.LOGGING,
                        resource_type="Azure::DBforPostgreSQL::FlexibleServer",
                        resource_id=server.id or "",
                        region=server.location or region,
                        account_id=subscription_id,
                        cloud_provider=CloudProvider.AZURE,
                        soc2_controls=["CC7.1", "CC7.2"],
                        cis_azure_controls=["4.3.2", "4.3.3", "4.3.4"],
                        details={"server": server.name, "settings": actual},
                    )
                )
            else:
                findings.append(
                    Finding(
                        check_id="azure-postgres-log-settings",
                        title=f"PostgreSQL '{server.name}' missing log settings: {', '.join(missing)}",
                        description=(
                            "One or more connection-logging parameters are not ON. Without these, "
                            "anomalous connection patterns and brute-force attempts leave no record."
                        ),
                        severity=Severity.MEDIUM,
                        status=ComplianceStatus.FAIL,
                        domain=CheckDomain.LOGGING,
                        resource_type="Azure::DBforPostgreSQL::FlexibleServer",
                        resource_id=server.id or "",
                        region=server.location or region,
                        account_id=subscription_id,
                        cloud_provider=CloudProvider.AZURE,
                        remediation=(
                            "Set each missing parameter to ON via "
                            "`az postgres flexible-server parameter set`."
                        ),
                        soc2_controls=["CC7.1", "CC7.2"],
                        cis_azure_controls=["4.3.2", "4.3.3", "4.3.4"],
                        details={"server": server.name, "settings": actual, "missing": missing},
                    )
                )
    except Exception as e:
        return [Finding.not_assessed(
            check_id="azure-postgres-log-settings",
            title="Unable to check PostgreSQL log settings",
            description=f"API call failed: {e}",
            domain=CheckDomain.LOGGING,
            resource_type="Azure::DBforPostgreSQL::FlexibleServer",
            account_id=subscription_id,
            region=region,
            cloud_provider=CloudProvider.AZURE,
        )]
    return findings


def check_postgresql_public_access(
    client: AzureClient, subscription_id: str, region: str
) -> list[Finding]:
    """[CIS 4.3.x] PostgreSQL Flexible Server should not allow public access."""
    findings: list[Finding] = []
    try:
        for _pg, server in _iter_postgres_servers(client):
            net = getattr(server, "network", None)
            pna = getattr(net, "public_network_access", "") if net else ""
            ok = str(pna).lower() == "disabled"
            findings.append(
                Finding(
                    check_id="azure-postgres-public-access",
                    title=f"PostgreSQL '{server.name}' publicNetworkAccess={pna or 'Enabled'}",
                    description=(
                        "Server is private (VNet-injected)."
                        if ok
                        else "Server is reachable from the public internet."
                    ),
                    severity=Severity.INFO if ok else Severity.HIGH,
                    status=ComplianceStatus.PASS if ok else ComplianceStatus.FAIL,
                    domain=CheckDomain.NETWORKING,
                    resource_type="Azure::DBforPostgreSQL::FlexibleServer",
                    resource_id=server.id or "",
                    region=server.location or region,
                    account_id=subscription_id,
                    cloud_provider=CloudProvider.AZURE,
                    remediation=(
                        ""
                        if ok
                        else "Re-create the server with VNet integration or set publicNetworkAccess=Disabled and use Private Endpoint."
                    ),
                    soc2_controls=["CC6.6"],
                    cis_azure_controls=["4.3.7"],
                    details={"server": server.name, "public_access": pna},
                )
            )
    except Exception as e:
        return [Finding.not_assessed(
            check_id="azure-postgres-public-access",
            title="Unable to check PostgreSQL public access",
            description=f"API call failed: {e}",
            domain=CheckDomain.NETWORKING,
            resource_type="Azure::DBforPostgreSQL::FlexibleServer",
            account_id=subscription_id,
            region=region,
            cloud_provider=CloudProvider.AZURE,
        )]
    return findings


# ---------------------------------------------------------------------------
# MySQL Flexible Server
# ---------------------------------------------------------------------------


def _iter_mysql_servers(client: AzureClient):
    try:
        from azure.mgmt.rdbms.mysql_flexibleservers import MySQLManagementClient
    except ImportError:
        return
    my = client.mgmt_client(MySQLManagementClient)
    for server in my.servers.list():
        yield my, server


def _my_param(my, rg: str, server_name: str, name: str) -> str | None:
    try:
        cfg = my.configurations.get(rg, server_name, name)
        return getattr(cfg, "value", None)
    except Exception:
        return None


def check_mysql_secure_transport(
    client: AzureClient, subscription_id: str, region: str
) -> list[Finding]:
    """[CIS 4.4.1] MySQL require_secure_transport = ON."""
    findings: list[Finding] = []
    try:
        for my, server in _iter_mysql_servers(client):
            rg = _server_rg(server)
            val = _my_param(my, rg, server.name, "require_secure_transport")
            ok = (val or "").lower() == "on"
            findings.append(
                Finding(
                    check_id="azure-mysql-secure-transport",
                    title=f"MySQL '{server.name}' require_secure_transport={val or 'unknown'}",
                    description=(
                        "Secure transport enforced." if ok else "Plaintext connections allowed."
                    ),
                    severity=Severity.INFO if ok else Severity.HIGH,
                    status=ComplianceStatus.PASS if ok else ComplianceStatus.FAIL,
                    domain=CheckDomain.ENCRYPTION,
                    resource_type="Azure::DBforMySQL::FlexibleServer",
                    resource_id=server.id or "",
                    region=server.location or region,
                    account_id=subscription_id,
                    cloud_provider=CloudProvider.AZURE,
                    remediation=(
                        ""
                        if ok
                        else "az mysql flexible-server parameter set --name require_secure_transport --value ON -g <rg> -s <server>"
                    ),
                    soc2_controls=["CC6.1", "CC6.7"],
                    cis_azure_controls=["4.4.1"],
                    details={"server": server.name, "value": val},
                )
            )
    except Exception as e:
        return [Finding.not_assessed(
            check_id="azure-mysql-secure-transport",
            title="Unable to check MySQL secure transport",
            description=f"API call failed: {e}",
            domain=CheckDomain.ENCRYPTION,
            resource_type="Azure::DBforMySQL::FlexibleServer",
            account_id=subscription_id,
            region=region,
            cloud_provider=CloudProvider.AZURE,
        )]
    return findings


def check_mysql_tls_version(
    client: AzureClient, subscription_id: str, region: str
) -> list[Finding]:
    """[CIS 4.4.2] MySQL tls_version should include only TLSv1.2/TLSv1.3."""
    findings: list[Finding] = []
    try:
        for my, server in _iter_mysql_servers(client):
            rg = _server_rg(server)
            val = _my_param(my, rg, server.name, "tls_version") or ""
            tls_versions = {v.strip() for v in val.split(",") if v.strip()}
            ok = tls_versions and tls_versions.issubset({"TLSv1.2", "TLSv1.3"})
            findings.append(
                Finding(
                    check_id="azure-mysql-tls-version",
                    title=f"MySQL '{server.name}' tls_version={val or 'unset'}",
                    description=(
                        "Only TLS 1.2/1.3 enabled."
                        if ok
                        else "Server allows TLS 1.0/1.1 (or unset)."
                    ),
                    severity=Severity.INFO if ok else Severity.MEDIUM,
                    status=ComplianceStatus.PASS if ok else ComplianceStatus.FAIL,
                    domain=CheckDomain.ENCRYPTION,
                    resource_type="Azure::DBforMySQL::FlexibleServer",
                    resource_id=server.id or "",
                    region=server.location or region,
                    account_id=subscription_id,
                    cloud_provider=CloudProvider.AZURE,
                    remediation=(
                        ""
                        if ok
                        else "az mysql flexible-server parameter set --name tls_version --value 'TLSv1.2,TLSv1.3' -g <rg> -s <server>"
                    ),
                    soc2_controls=["CC6.1", "CC6.7"],
                    cis_azure_controls=["4.4.2"],
                    details={"server": server.name, "value": val},
                )
            )
    except Exception as e:
        return [Finding.not_assessed(
            check_id="azure-mysql-tls-version",
            title="Unable to check MySQL TLS version",
            description=f"API call failed: {e}",
            domain=CheckDomain.ENCRYPTION,
            resource_type="Azure::DBforMySQL::FlexibleServer",
            account_id=subscription_id,
            region=region,
            cloud_provider=CloudProvider.AZURE,
        )]
    return findings


def check_mysql_audit_log(client: AzureClient, subscription_id: str, region: str) -> list[Finding]:
    """[CIS 4.4.3] MySQL audit_log_enabled = ON."""
    findings: list[Finding] = []
    try:
        for my, server in _iter_mysql_servers(client):
            rg = _server_rg(server)
            val = _my_param(my, rg, server.name, "audit_log_enabled")
            ok = (val or "").lower() == "on"
            findings.append(
                Finding(
                    check_id="azure-mysql-audit-log",
                    title=f"MySQL '{server.name}' audit_log_enabled={val or 'unknown'}",
                    description=("Audit log is enabled." if ok else "Audit log is disabled."),
                    severity=Severity.INFO if ok else Severity.MEDIUM,
                    status=ComplianceStatus.PASS if ok else ComplianceStatus.FAIL,
                    domain=CheckDomain.LOGGING,
                    resource_type="Azure::DBforMySQL::FlexibleServer",
                    resource_id=server.id or "",
                    region=server.location or region,
                    account_id=subscription_id,
                    cloud_provider=CloudProvider.AZURE,
                    remediation=(
                        ""
                        if ok
                        else "az mysql flexible-server parameter set --name audit_log_enabled --value ON -g <rg> -s <server>"
                    ),
                    soc2_controls=["CC7.1", "CC7.2"],
                    cis_azure_controls=["4.4.3"],
                    details={"server": server.name, "value": val},
                )
            )
    except Exception as e:
        return [Finding.not_assessed(
            check_id="azure-mysql-audit-log",
            title="Unable to check MySQL audit log",
            description=f"API call failed: {e}",
            domain=CheckDomain.LOGGING,
            resource_type="Azure::DBforMySQL::FlexibleServer",
            account_id=subscription_id,
            region=region,
            cloud_provider=CloudProvider.AZURE,
        )]
    return findings
