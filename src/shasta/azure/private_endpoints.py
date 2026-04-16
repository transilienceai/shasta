"""Cross-cutting Private Endpoint walker for Azure resources.

A single sweep across the most security-sensitive PaaS resource types,
emitting one finding per resource where a Private Endpoint is missing.
This catches the highest-leverage network-exposure findings without
duplicating per-service code.
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


def run_all_azure_private_endpoint_checks(client: AzureClient) -> list[Finding]:
    """Walk every supported PaaS service and report Private Endpoint coverage.

    Catches Storage, Key Vault, SQL, Cosmos, Container Registry, App Service,
    and Cognitive Services / OpenAI in a single pass.
    """
    findings: list[Finding] = []
    sub_id = client.account_info.subscription_id if client.account_info else "unknown"
    region = client.account_info.region if client.account_info else "unknown"

    findings.extend(_walk_storage(client, sub_id, region))
    findings.extend(_walk_keyvaults(client, sub_id, region))
    findings.extend(_walk_sql_servers(client, sub_id, region))
    findings.extend(_walk_cosmos(client, sub_id, region))
    findings.extend(_walk_acr(client, sub_id, region))
    findings.extend(_walk_app_service(client, sub_id, region))
    findings.extend(_walk_cognitive(client, sub_id, region))

    return findings


def _pe_finding(
    resource_type: str,
    name: str,
    rid: str,
    rg: str,
    location: str,
    sub_id: str,
    has_pe: bool,
    pe_count: int,
    cis_id: str | None = None,
) -> Finding:
    return Finding(
        check_id=f"azure-private-endpoint-{resource_type.split('::')[-1].lower()}",
        title=(
            f"{resource_type.split('::')[-1]} '{name}' has {pe_count} private endpoint(s)"
            if has_pe
            else f"{resource_type.split('::')[-1]} '{name}' has no private endpoint"
        ),
        description=(
            "At least one Private Endpoint is attached, traffic can be kept off the public network."
            if has_pe
            else (
                "No Private Endpoint connection found. The resource is reachable via its public "
                "endpoint, increasing the blast radius of credential theft and policy "
                "misconfiguration."
            )
        ),
        severity=Severity.INFO if has_pe else Severity.MEDIUM,
        status=ComplianceStatus.PASS if has_pe else ComplianceStatus.FAIL,
        domain=CheckDomain.NETWORKING,
        resource_type=resource_type,
        resource_id=rid,
        region=location,
        account_id=sub_id,
        cloud_provider=CloudProvider.AZURE,
        remediation=(
            ""
            if has_pe
            else "Create a Private Endpoint targeting this resource and disable publicNetworkAccess."
        ),
        soc2_controls=["CC6.6"],
        cis_azure_controls=[cis_id] if cis_id else [],
        mcsb_controls=["NS-2"],
        details={"name": name, "resource_group": rg, "private_endpoints": pe_count},
    )


def _rg_from_id(rid: str) -> str:
    return rid.split("/resourceGroups/")[1].split("/")[0] if "/resourceGroups/" in rid else ""


def _walk_storage(client: AzureClient, sub_id: str, region: str) -> list[Finding]:
    try:
        from azure.mgmt.storage import StorageManagementClient

        sc = client.mgmt_client(StorageManagementClient)
        out = []
        for acct in sc.storage_accounts.list():
            pec = list(getattr(acct, "private_endpoint_connections", None) or [])
            out.append(
                _pe_finding(
                    "Azure::Storage::StorageAccount",
                    acct.name,
                    acct.id or "",
                    _rg_from_id(acct.id or ""),
                    acct.location or region,
                    sub_id,
                    bool(pec),
                    len(pec),
                )
            )
        return out
    except Exception as e:
        return [Finding.not_assessed(
            check_id="azure-private-endpoint-storageaccount",
            title="Unable to check Storage private endpoints",
            description=f"API call failed: {e}",
            domain=CheckDomain.NETWORKING,
            resource_type="Azure::Storage::StorageAccount",
            account_id=sub_id,
            region=region,
            cloud_provider=CloudProvider.AZURE,
        )]


def _walk_keyvaults(client: AzureClient, sub_id: str, region: str) -> list[Finding]:
    try:
        from azure.mgmt.keyvault import KeyVaultManagementClient

        kv = client.mgmt_client(KeyVaultManagementClient)
        out = []
        for vault in kv.vaults.list_by_subscription():
            props = vault.properties
            pec = list(getattr(props, "private_endpoint_connections", None) or [])
            out.append(
                _pe_finding(
                    "Azure::KeyVault::Vault",
                    vault.name,
                    vault.id or "",
                    _rg_from_id(vault.id or ""),
                    vault.location or region,
                    sub_id,
                    bool(pec),
                    len(pec),
                    cis_id="8.7",
                )
            )
        return out
    except Exception as e:
        return [Finding.not_assessed(
            check_id="azure-private-endpoint-vault",
            title="Unable to check Key Vault private endpoints",
            description=f"API call failed: {e}",
            domain=CheckDomain.NETWORKING,
            resource_type="Azure::KeyVault::Vault",
            account_id=sub_id,
            region=region,
            cloud_provider=CloudProvider.AZURE,
        )]


def _walk_sql_servers(client: AzureClient, sub_id: str, region: str) -> list[Finding]:
    try:
        from azure.mgmt.sql import SqlManagementClient

        sql = client.mgmt_client(SqlManagementClient)
        out = []
        for server in sql.servers.list():
            try:
                pec = list(
                    sql.private_endpoint_connections.list_by_server(
                        _rg_from_id(server.id or ""), server.name
                    )
                )
            except Exception:
                pec = list(getattr(server, "private_endpoint_connections", None) or [])
            out.append(
                _pe_finding(
                    "Azure::Sql::Server",
                    server.name,
                    server.id or "",
                    _rg_from_id(server.id or ""),
                    server.location or region,
                    sub_id,
                    bool(pec),
                    len(pec),
                )
            )
        return out
    except Exception as e:
        return [Finding.not_assessed(
            check_id="azure-private-endpoint-server",
            title="Unable to check SQL Server private endpoints",
            description=f"API call failed: {e}",
            domain=CheckDomain.NETWORKING,
            resource_type="Azure::Sql::Server",
            account_id=sub_id,
            region=region,
            cloud_provider=CloudProvider.AZURE,
        )]


def _walk_cosmos(client: AzureClient, sub_id: str, region: str) -> list[Finding]:
    try:
        from azure.mgmt.cosmosdb import CosmosDBManagementClient

        c = client.mgmt_client(CosmosDBManagementClient)
        out = []
        for acct in c.database_accounts.list():
            pec = list(getattr(acct, "private_endpoint_connections", None) or [])
            out.append(
                _pe_finding(
                    "Azure::Cosmos::DatabaseAccount",
                    acct.name,
                    acct.id or "",
                    _rg_from_id(acct.id or ""),
                    acct.location or region,
                    sub_id,
                    bool(pec),
                    len(pec),
                )
            )
        return out
    except Exception as e:
        return [Finding.not_assessed(
            check_id="azure-private-endpoint-databaseaccount",
            title="Unable to check Cosmos DB private endpoints",
            description=f"API call failed: {e}",
            domain=CheckDomain.NETWORKING,
            resource_type="Azure::Cosmos::DatabaseAccount",
            account_id=sub_id,
            region=region,
            cloud_provider=CloudProvider.AZURE,
        )]


def _walk_acr(client: AzureClient, sub_id: str, region: str) -> list[Finding]:
    try:
        from azure.mgmt.containerregistry import ContainerRegistryManagementClient

        acr = client.mgmt_client(ContainerRegistryManagementClient)
        out = []
        for reg in acr.registries.list():
            try:
                pec = list(
                    acr.private_endpoint_connections.list(_rg_from_id(reg.id or ""), reg.name)
                )
            except Exception:
                pec = []
            out.append(
                _pe_finding(
                    "Azure::ContainerRegistry::Registry",
                    reg.name,
                    reg.id or "",
                    _rg_from_id(reg.id or ""),
                    reg.location or region,
                    sub_id,
                    bool(pec),
                    len(pec),
                )
            )
        return out
    except Exception as e:
        return [Finding.not_assessed(
            check_id="azure-private-endpoint-registry",
            title="Unable to check Container Registry private endpoints",
            description=f"API call failed: {e}",
            domain=CheckDomain.NETWORKING,
            resource_type="Azure::ContainerRegistry::Registry",
            account_id=sub_id,
            region=region,
            cloud_provider=CloudProvider.AZURE,
        )]


def _walk_app_service(client: AzureClient, sub_id: str, region: str) -> list[Finding]:
    try:
        from azure.mgmt.web import WebSiteManagementClient

        web = client.mgmt_client(WebSiteManagementClient)
        out = []
        for app in web.web_apps.list():
            try:
                pec = list(
                    web.web_apps.get_private_endpoint_connection_list(
                        _rg_from_id(app.id or ""), app.name
                    )
                )
            except Exception:
                pec = []
            out.append(
                _pe_finding(
                    "Azure::Web::Site",
                    app.name,
                    app.id or "",
                    _rg_from_id(app.id or ""),
                    app.location or region,
                    sub_id,
                    bool(pec),
                    len(pec),
                )
            )
        return out
    except Exception as e:
        return [Finding.not_assessed(
            check_id="azure-private-endpoint-site",
            title="Unable to check App Service private endpoints",
            description=f"API call failed: {e}",
            domain=CheckDomain.NETWORKING,
            resource_type="Azure::Web::Site",
            account_id=sub_id,
            region=region,
            cloud_provider=CloudProvider.AZURE,
        )]


def _walk_cognitive(client: AzureClient, sub_id: str, region: str) -> list[Finding]:
    try:
        from azure.mgmt.cognitiveservices import CognitiveServicesManagementClient

        cs = client.mgmt_client(CognitiveServicesManagementClient)
        out: list[Finding] = []
        for acct in cs.accounts.list():
            props = getattr(acct, "properties", None)
            pec = list(getattr(props, "private_endpoint_connections", None) or []) if props else []
            out.append(
                _pe_finding(
                    "Azure::CognitiveServices::Account",
                    acct.name,
                    acct.id or "",
                    _rg_from_id(acct.id or ""),
                    acct.location or region,
                    sub_id,
                    bool(pec),
                    len(pec),
                )
            )
        return out
    except Exception as e:
        return [Finding.not_assessed(
            check_id="azure-private-endpoint-account",
            title="Unable to check Cognitive Services private endpoints",
            description=f"API call failed: {e}",
            domain=CheckDomain.NETWORKING,
            resource_type="Azure::CognitiveServices::Account",
            account_id=sub_id,
            region=region,
            cloud_provider=CloudProvider.AZURE,
        )]
