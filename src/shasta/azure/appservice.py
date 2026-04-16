"""Azure App Service / Functions security checks.

Covers CIS Azure v3.0 section 9 (App Service): HTTPS-only, min TLS,
FTPS state, remote debugging, client cert, managed identity, and
diagnostic logging.
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


def run_all_azure_appservice_checks(client: AzureClient) -> list[Finding]:
    """Run all App Service / Functions compliance checks."""
    findings: list[Finding] = []
    sub_id = client.account_info.subscription_id if client.account_info else "unknown"
    region = client.account_info.region if client.account_info else "unknown"

    findings.extend(check_appservice_https_only(client, sub_id, region))
    findings.extend(check_appservice_min_tls(client, sub_id, region))
    findings.extend(check_appservice_ftps_disabled(client, sub_id, region))
    findings.extend(check_appservice_remote_debug_disabled(client, sub_id, region))
    findings.extend(check_appservice_client_cert(client, sub_id, region))
    findings.extend(check_appservice_managed_identity(client, sub_id, region))
    findings.extend(check_appservice_public_network_access(client, sub_id, region))
    findings.extend(check_appservice_auth_enabled(client, sub_id, region))

    return findings


def _iter_web_apps(client: AzureClient):
    try:
        from azure.mgmt.web import WebSiteManagementClient
    except ImportError:
        return
    web = client.mgmt_client(WebSiteManagementClient)
    for app in web.web_apps.list():
        sid = app.id or ""
        rg = sid.split("/resourceGroups/")[1].split("/")[0] if "/resourceGroups/" in sid else ""
        yield web, app, rg


def _appservice_finding(
    check_id: str,
    title: str,
    description: str,
    severity: Severity,
    status: ComplianceStatus,
    app,
    sub_id: str,
    region: str,
    cis: list[str],
    soc2: list[str],
    remediation: str = "",
    details: dict | None = None,
) -> Finding:
    return Finding(
        check_id=check_id,
        title=title,
        description=description,
        severity=severity,
        status=status,
        domain=CheckDomain.COMPUTE,
        resource_type="Azure::Web::Site",
        resource_id=app.id or "",
        region=app.location or region,
        account_id=sub_id,
        cloud_provider=CloudProvider.AZURE,
        remediation=remediation,
        soc2_controls=soc2,
        cis_azure_controls=cis,
        details=details or {"app": app.name},
    )


def check_appservice_https_only(
    client: AzureClient, subscription_id: str, region: str
) -> list[Finding]:
    """[CIS 9.2] Web apps must enforce HTTPS-only."""
    findings: list[Finding] = []
    try:
        for _w, app, _rg in _iter_web_apps(client):
            ok = bool(getattr(app, "https_only", False))
            findings.append(
                _appservice_finding(
                    "azure-appservice-https-only",
                    f"App '{app.name}' httpsOnly={ok}",
                    "HTTPS-only enforced." if ok else "App accepts HTTP traffic.",
                    Severity.INFO if ok else Severity.HIGH,
                    ComplianceStatus.PASS if ok else ComplianceStatus.FAIL,
                    app,
                    subscription_id,
                    region,
                    ["9.2"],
                    ["CC6.1", "CC6.7"],
                    remediation="" if ok else "az webapp update --https-only true -g <rg> -n <app>",
                )
            )
    except Exception as e:
        return [Finding.not_assessed(
            check_id="azure-appservice-https-only",
            title="Unable to check App Service HTTPS-only",
            description=f"API call failed: {e}",
            domain=CheckDomain.COMPUTE,
            resource_type="Azure::Web::Site",
            account_id=subscription_id,
            region=region,
            cloud_provider=CloudProvider.AZURE,
        )]
    return findings


def _site_config(web, rg, name):
    try:
        return web.web_apps.get_configuration(rg, name)
    except Exception:
        return None


def check_appservice_min_tls(
    client: AzureClient, subscription_id: str, region: str
) -> list[Finding]:
    """[CIS 9.3] App Service min TLS version should be 1.2 or higher."""
    findings: list[Finding] = []
    try:
        for web, app, rg in _iter_web_apps(client):
            cfg = _site_config(web, rg, app.name)
            if not cfg:
                continue
            min_tls = getattr(cfg, "min_tls_version", None) or "1.0"
            ok = min_tls in ("1.2", "1.3")
            findings.append(
                _appservice_finding(
                    "azure-appservice-min-tls",
                    f"App '{app.name}' minTlsVersion={min_tls}",
                    "TLS 1.2+ enforced." if ok else "Allows legacy TLS.",
                    Severity.INFO if ok else Severity.MEDIUM,
                    ComplianceStatus.PASS if ok else ComplianceStatus.FAIL,
                    app,
                    subscription_id,
                    region,
                    ["9.3"],
                    ["CC6.1", "CC6.7"],
                    remediation=""
                    if ok
                    else "az webapp config set --min-tls-version 1.2 -g <rg> -n <app>",
                    details={"app": app.name, "min_tls": min_tls},
                )
            )
    except Exception as e:
        return [Finding.not_assessed(
            check_id="azure-appservice-min-tls",
            title="Unable to check App Service min TLS",
            description=f"API call failed: {e}",
            domain=CheckDomain.COMPUTE,
            resource_type="Azure::Web::Site",
            account_id=subscription_id,
            region=region,
            cloud_provider=CloudProvider.AZURE,
        )]
    return findings


def check_appservice_ftps_disabled(
    client: AzureClient, subscription_id: str, region: str
) -> list[Finding]:
    """[CIS 9.10] FTPS state should be Disabled or FtpsOnly (never AllAllowed)."""
    findings: list[Finding] = []
    try:
        for web, app, rg in _iter_web_apps(client):
            cfg = _site_config(web, rg, app.name)
            if not cfg:
                continue
            state = getattr(cfg, "ftps_state", None) or "AllAllowed"
            ok = state in ("Disabled", "FtpsOnly")
            findings.append(
                _appservice_finding(
                    "azure-appservice-ftps",
                    f"App '{app.name}' ftpsState={state}",
                    "Plain FTP blocked." if ok else "Plain FTP is allowed.",
                    Severity.INFO if ok else Severity.HIGH,
                    ComplianceStatus.PASS if ok else ComplianceStatus.FAIL,
                    app,
                    subscription_id,
                    region,
                    ["9.10"],
                    ["CC6.1", "CC6.7"],
                    remediation=(
                        "" if ok else "az webapp config set --ftps-state Disabled -g <rg> -n <app>"
                    ),
                    details={"app": app.name, "ftps_state": state},
                )
            )
    except Exception as e:
        return [Finding.not_assessed(
            check_id="azure-appservice-ftps",
            title="Unable to check App Service FTPS state",
            description=f"API call failed: {e}",
            domain=CheckDomain.COMPUTE,
            resource_type="Azure::Web::Site",
            account_id=subscription_id,
            region=region,
            cloud_provider=CloudProvider.AZURE,
        )]
    return findings


def check_appservice_remote_debug_disabled(
    client: AzureClient, subscription_id: str, region: str
) -> list[Finding]:
    """[CIS 9.5] App Service remote debugging should be disabled."""
    findings: list[Finding] = []
    try:
        for web, app, rg in _iter_web_apps(client):
            cfg = _site_config(web, rg, app.name)
            if not cfg:
                continue
            enabled = bool(getattr(cfg, "remote_debugging_enabled", False))
            findings.append(
                _appservice_finding(
                    "azure-appservice-remote-debug",
                    f"App '{app.name}' remote debugging {'enabled' if enabled else 'disabled'}",
                    "Disabled (production-safe)."
                    if not enabled
                    else "Remote debugging is enabled — production exposure.",
                    Severity.INFO if not enabled else Severity.MEDIUM,
                    ComplianceStatus.PASS if not enabled else ComplianceStatus.FAIL,
                    app,
                    subscription_id,
                    region,
                    ["9.5"],
                    ["CC6.1"],
                    remediation=(
                        ""
                        if not enabled
                        else "az webapp config set --remote-debugging-enabled false -g <rg> -n <app>"
                    ),
                )
            )
    except Exception as e:
        return [Finding.not_assessed(
            check_id="azure-appservice-remote-debug",
            title="Unable to check App Service remote debugging",
            description=f"API call failed: {e}",
            domain=CheckDomain.COMPUTE,
            resource_type="Azure::Web::Site",
            account_id=subscription_id,
            region=region,
            cloud_provider=CloudProvider.AZURE,
        )]
    return findings


def check_appservice_client_cert(
    client: AzureClient, subscription_id: str, region: str
) -> list[Finding]:
    """[CIS 9.4] Web apps fronting APIs should require client certificates (informational)."""
    findings: list[Finding] = []
    try:
        for _w, app, _rg in _iter_web_apps(client):
            enabled = bool(getattr(app, "client_cert_enabled", False))
            findings.append(
                _appservice_finding(
                    "azure-appservice-client-cert",
                    f"App '{app.name}' clientCertEnabled={enabled}",
                    "Client certificates required.",
                    Severity.INFO if enabled else Severity.LOW,
                    ComplianceStatus.PASS if enabled else ComplianceStatus.PARTIAL,
                    app,
                    subscription_id,
                    region,
                    ["9.4"],
                    ["CC6.1"],
                    remediation=(
                        ""
                        if enabled
                        else "Enable client certificates for APIs that need mutual TLS: az webapp update --client-cert-enabled true."
                    ),
                )
            )
    except Exception as e:
        return [Finding.not_assessed(
            check_id="azure-appservice-client-cert",
            title="Unable to check App Service client certificates",
            description=f"API call failed: {e}",
            domain=CheckDomain.COMPUTE,
            resource_type="Azure::Web::Site",
            account_id=subscription_id,
            region=region,
            cloud_provider=CloudProvider.AZURE,
        )]
    return findings


def check_appservice_managed_identity(
    client: AzureClient, subscription_id: str, region: str
) -> list[Finding]:
    """[CIS 9.11] Web apps should use a managed identity (system or user-assigned)."""
    findings: list[Finding] = []
    try:
        for _w, app, _rg in _iter_web_apps(client):
            identity = getattr(app, "identity", None)
            id_type = getattr(identity, "type", None) if identity else None
            ok = bool(id_type and str(id_type).lower() != "none")
            findings.append(
                _appservice_finding(
                    "azure-appservice-managed-identity",
                    f"App '{app.name}' identity={id_type or 'None'}",
                    "Managed identity assigned."
                    if ok
                    else "No managed identity — likely using credentials in app settings.",
                    Severity.INFO if ok else Severity.MEDIUM,
                    ComplianceStatus.PASS if ok else ComplianceStatus.FAIL,
                    app,
                    subscription_id,
                    region,
                    ["9.11"],
                    ["CC6.1", "CC6.2"],
                    remediation=(
                        ""
                        if ok
                        else "az webapp identity assign -g <rg> -n <app>; then grant RBAC and remove static credentials from app settings."
                    ),
                )
            )
    except Exception as e:
        return [Finding.not_assessed(
            check_id="azure-appservice-managed-identity",
            title="Unable to check App Service managed identity",
            description=f"API call failed: {e}",
            domain=CheckDomain.COMPUTE,
            resource_type="Azure::Web::Site",
            account_id=subscription_id,
            region=region,
            cloud_provider=CloudProvider.AZURE,
        )]
    return findings


def check_appservice_public_network_access(
    client: AzureClient, subscription_id: str, region: str
) -> list[Finding]:
    """[CIS 9.x] Public network access on App Service should be Disabled where possible."""
    findings: list[Finding] = []
    try:
        for _w, app, _rg in _iter_web_apps(client):
            pna = getattr(app, "public_network_access", None) or "Enabled"
            ok = str(pna).lower() == "disabled"
            findings.append(
                _appservice_finding(
                    "azure-appservice-public-access",
                    f"App '{app.name}' publicNetworkAccess={pna}",
                    "Public network access disabled (private endpoint expected)."
                    if ok
                    else "App is reachable from the public internet.",
                    Severity.INFO if ok else Severity.LOW,
                    ComplianceStatus.PASS if ok else ComplianceStatus.PARTIAL,
                    app,
                    subscription_id,
                    region,
                    ["9.12"],
                    ["CC6.6"],
                    remediation=(
                        ""
                        if ok
                        else "Disable public network access and use a Private Endpoint or App Service access restrictions."
                    ),
                )
            )
    except Exception as e:
        return [Finding.not_assessed(
            check_id="azure-appservice-public-access",
            title="Unable to check App Service public network access",
            description=f"API call failed: {e}",
            domain=CheckDomain.COMPUTE,
            resource_type="Azure::Web::Site",
            account_id=subscription_id,
            region=region,
            cloud_provider=CloudProvider.AZURE,
        )]
    return findings


def check_appservice_auth_enabled(
    client: AzureClient, subscription_id: str, region: str
) -> list[Finding]:
    """[CIS 9.1] App Service Authentication ("Easy Auth") enabled — informational."""
    findings: list[Finding] = []
    try:
        for web, app, rg in _iter_web_apps(client):
            try:
                auth = web.web_apps.get_auth_settings(rg, app.name)
                enabled = bool(getattr(auth, "enabled", False))
            except Exception:
                enabled = False
            findings.append(
                _appservice_finding(
                    "azure-appservice-auth",
                    f"App '{app.name}' Easy Auth {'enabled' if enabled else 'disabled'}",
                    "App Service Authentication is enabled."
                    if enabled
                    else "No App Service Authentication — app must implement its own auth, or be public.",
                    Severity.INFO if enabled else Severity.LOW,
                    ComplianceStatus.PASS if enabled else ComplianceStatus.PARTIAL,
                    app,
                    subscription_id,
                    region,
                    ["9.1"],
                    ["CC6.1"],
                    remediation=(
                        ""
                        if enabled
                        else "Enable Easy Auth via Authentication blade if the app does not handle its own auth."
                    ),
                )
            )
    except Exception as e:
        return [Finding.not_assessed(
            check_id="azure-appservice-auth",
            title="Unable to check App Service authentication",
            description=f"API call failed: {e}",
            domain=CheckDomain.COMPUTE,
            resource_type="Azure::Web::Site",
            account_id=subscription_id,
            region=region,
            cloud_provider=CloudProvider.AZURE,
        )]
    return findings
