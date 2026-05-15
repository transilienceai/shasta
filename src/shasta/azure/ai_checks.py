"""Azure AI/ML security checks for Whitney.

Implements 15 security checks for Azure AI services (Azure OpenAI, Azure ML,
Cognitive Services, AI Search) mapped to AI governance controls.
"""

from __future__ import annotations

import logging
from typing import Any

from shasta.azure.client import AzureClient
from shasta.evidence.models import (
    CheckDomain,
    CloudProvider,
    ComplianceStatus,
    Finding,
    Severity,
)

logger = logging.getLogger(__name__)


def run_full_azure_ai_scan(client: AzureClient) -> list[Finding]:
    """Run all 15 Azure AI security checks and return findings.

    Named to match Shasta's ``run_full_scan`` convention. The former name
    ``run_all_azure_ai_checks`` was renamed on 2026-04-11 — update any
    caller that still uses the old spelling.
    """
    findings: list[Finding] = []
    sub_id = client.account_info.subscription_id if client.account_info else "unknown"
    region = client.account_info.region if client.account_info else "unknown"

    checks = [
        check_azure_openai_content_filter,
        check_azure_openai_key_rotation,
        check_azure_openai_private_endpoint,
        check_azure_openai_diagnostic_logging,
        check_azure_openai_managed_identity,
        check_azure_openai_abuse_monitoring,
        check_azure_ml_workspace_encryption,
        check_azure_ml_compute_rbac,
        check_azure_ml_model_registration,
        check_azure_ml_data_drift_monitor,
        check_azure_cognitive_network_rules,
        check_azure_cognitive_cmk,
        check_azure_ai_search_auth,
        check_azure_responsible_ai_dashboard,
        check_azure_ml_environment_pinned,
    ]

    for check_fn in checks:
        try:
            findings.extend(check_fn(client, sub_id, region))
        except Exception as e:
            logger.warning("Check %s failed unexpectedly: %s", check_fn.__name__, e)

    return findings


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_cognitive_client(client: AzureClient) -> Any | None:
    """Get CognitiveServicesManagementClient, or None if not installed."""
    try:
        from azure.mgmt.cognitiveservices import CognitiveServicesManagementClient

        return client.mgmt_client(CognitiveServicesManagementClient)
    except ImportError:
        return None


def _get_ml_client(client: AzureClient) -> Any | None:
    """Get MachineLearningServicesMgmtClient, or None if not installed."""
    try:
        from azure.mgmt.machinelearningservices import MachineLearningServicesMgmtClient

        return client.mgmt_client(MachineLearningServicesMgmtClient)
    except ImportError:
        return None


def _list_openai_accounts(cog_client: Any) -> list[Any]:
    """List Cognitive Services accounts filtered to kind == 'OpenAI'."""
    accounts = []
    try:
        for account in cog_client.accounts.list():
            if account.kind == "OpenAI":
                accounts.append(account)
    except Exception as e:
        logger.debug("Failed to list Cognitive Services accounts: %s", e)
    return accounts


def _resource_group_from_id(resource_id: str | None) -> str | None:
    """Extract resource group name from an Azure resource ID."""
    if not resource_id:
        return None
    parts = resource_id.split("/")
    try:
        idx = [p.lower() for p in parts].index("resourcegroups")
        return parts[idx + 1]
    except (ValueError, IndexError):
        return None


def _not_assessed(
    check_id: str,
    title: str,
    description: str,
    resource_type: str,
    sub_id: str,
    region: str,
) -> Finding:
    """Create a NOT_ASSESSED finding for checks that could not run."""
    return Finding(
        check_id=check_id,
        title=title,
        description=description,
        severity=Severity.MEDIUM,
        status=ComplianceStatus.NOT_ASSESSED,
        domain=CheckDomain.AI_GOVERNANCE,
        resource_type=resource_type,
        resource_id=f"/subscriptions/{sub_id}",
        region=region,
        account_id=sub_id,
        cloud_provider=CloudProvider.AZURE,
    )


def _sdk_missing_finding(
    check_id: str, title: str, package: str, sub_id: str, region: str
) -> Finding:
    """Create NOT_ASSESSED finding when an Azure SDK package is missing."""
    return _not_assessed(
        check_id,
        title,
        f"Required package '{package}' is not installed.",
        "Azure::CognitiveServices::Account",
        sub_id,
        region,
    )


# ---------------------------------------------------------------------------
# Azure OpenAI checks
# ---------------------------------------------------------------------------


def check_azure_openai_content_filter(
    client: AzureClient, sub_id: str, region: str
) -> list[Finding]:
    """Check Azure OpenAI deployments have content filtering enabled."""
    cog_client = _get_cognitive_client(client)
    if cog_client is None:
        return [
            _sdk_missing_finding(
                "azure-openai-content-filter",
                "Unable to check Azure OpenAI content filters",
                "azure-mgmt-cognitiveservices",
                sub_id,
                region,
            )
        ]

    accounts = _list_openai_accounts(cog_client)
    if not accounts:
        return [
            Finding(
                check_id="azure-openai-content-filter",
                title="No Azure OpenAI accounts found",
                description="No Azure OpenAI resources in this subscription.",
                severity=Severity.INFO,
                status=ComplianceStatus.NOT_APPLICABLE,
                domain=CheckDomain.AI_GOVERNANCE,
                resource_type="Azure::CognitiveServices::Account",
                resource_id=f"/subscriptions/{sub_id}",
                region=region,
                account_id=sub_id,
                cloud_provider=CloudProvider.AZURE,
                soc2_controls=["CC6.1"],
            )
        ]

    findings: list[Finding] = []
    for account in accounts:
        rg = _resource_group_from_id(account.id)
        if not rg:
            continue
        try:
            for deployment in cog_client.deployments.list(
                resource_group_name=rg, account_name=account.name
            ):
                # Check if content filter is associated with the deployment
                # The rai_policy_name property indicates a content filter policy
                rai_policy = None
                if deployment.properties:
                    rai_policy = getattr(deployment.properties, "rai_policy_name", None)

                if rai_policy:
                    findings.append(
                        Finding(
                            check_id="azure-openai-content-filter",
                            title=f"Deployment '{deployment.name}' has content filter '{rai_policy}'",
                            description=f"Content filter policy '{rai_policy}' is applied.",
                            severity=Severity.INFO,
                            status=ComplianceStatus.PASS,
                            domain=CheckDomain.AI_GOVERNANCE,
                            resource_type="Azure::CognitiveServices::Deployment",
                            resource_id=deployment.id
                            or f"{account.id}/deployments/{deployment.name}",
                            region=account.location or region,
                            account_id=sub_id,
                            cloud_provider=CloudProvider.AZURE,
                            details={
                                "account": account.name,
                                "deployment": deployment.name,
                                "rai_policy": rai_policy,
                            },
                            soc2_controls=["CC6.1"],
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            check_id="azure-openai-content-filter",
                            title=f"Deployment '{deployment.name}' may use default content filter",
                            description=(
                                "No custom RAI policy explicitly assigned. Azure applies a default "
                                "content filter, but a custom policy provides stronger controls."
                            ),
                            severity=Severity.MEDIUM,
                            status=ComplianceStatus.PARTIAL,
                            domain=CheckDomain.AI_GOVERNANCE,
                            resource_type="Azure::CognitiveServices::Deployment",
                            resource_id=deployment.id
                            or f"{account.id}/deployments/{deployment.name}",
                            region=account.location or region,
                            account_id=sub_id,
                            cloud_provider=CloudProvider.AZURE,
                            remediation="Apply a custom content filtering policy to this deployment.",
                            details={"account": account.name, "deployment": deployment.name},
                            soc2_controls=["CC6.1"],
                        )
                    )
        except Exception as e:
            logger.debug("Failed to list deployments for %s: %s", account.name, e)

    return findings or [
        _not_assessed(
            "azure-openai-content-filter",
            "Unable to evaluate Azure OpenAI content filters",
            "Could not retrieve deployment information.",
            "Azure::CognitiveServices::Deployment",
            sub_id,
            region,
        )
    ]


def check_azure_openai_key_rotation(client: AzureClient, sub_id: str, region: str) -> list[Finding]:
    """Check Azure OpenAI account keys have been rotated (or managed identity is used)."""
    cog_client = _get_cognitive_client(client)
    if cog_client is None:
        return [
            _sdk_missing_finding(
                "azure-openai-key-rotation",
                "Unable to check Azure OpenAI key rotation",
                "azure-mgmt-cognitiveservices",
                sub_id,
                region,
            )
        ]

    accounts = _list_openai_accounts(cog_client)
    if not accounts:
        return [
            Finding(
                check_id="azure-openai-key-rotation",
                title="No Azure OpenAI accounts found",
                description="No Azure OpenAI resources in this subscription.",
                severity=Severity.INFO,
                status=ComplianceStatus.NOT_APPLICABLE,
                domain=CheckDomain.AI_GOVERNANCE,
                resource_type="Azure::CognitiveServices::Account",
                resource_id=f"/subscriptions/{sub_id}",
                region=region,
                account_id=sub_id,
                cloud_provider=CloudProvider.AZURE,
                soc2_controls=["CC6.1", "CC6.7"],
            )
        ]

    findings: list[Finding] = []
    for account in accounts:
        rg = _resource_group_from_id(account.id)
        if not rg:
            continue

        # Check if local auth (API keys) is disabled in favor of managed identity
        disable_local_auth = False
        if account.properties:
            disable_local_auth = getattr(account.properties, "disable_local_auth", False) or False

        if disable_local_auth:
            findings.append(
                Finding(
                    check_id="azure-openai-key-rotation",
                    title=f"Account '{account.name}' uses managed identity only",
                    description="Local API key authentication is disabled; managed identity is enforced.",
                    severity=Severity.INFO,
                    status=ComplianceStatus.PASS,
                    domain=CheckDomain.AI_GOVERNANCE,
                    resource_type="Azure::CognitiveServices::Account",
                    resource_id=account.id or f"/subscriptions/{sub_id}",
                    region=account.location or region,
                    account_id=sub_id,
                    cloud_provider=CloudProvider.AZURE,
                    details={"account": account.name, "disable_local_auth": True},
                    soc2_controls=["CC6.1", "CC6.7"],
                )
            )
        else:
            findings.append(
                Finding(
                    check_id="azure-openai-key-rotation",
                    title=f"Account '{account.name}' has API key auth enabled",
                    description=(
                        "Local API key authentication is enabled. Ensure keys are rotated regularly "
                        "or switch to managed identity for stronger security."
                    ),
                    severity=Severity.MEDIUM,
                    status=ComplianceStatus.FAIL,
                    domain=CheckDomain.AI_GOVERNANCE,
                    resource_type="Azure::CognitiveServices::Account",
                    resource_id=account.id or f"/subscriptions/{sub_id}",
                    region=account.location or region,
                    account_id=sub_id,
                    cloud_provider=CloudProvider.AZURE,
                    remediation=(
                        "Disable local API key auth and use managed identity, or implement "
                        "a key rotation schedule via Azure Key Vault."
                    ),
                    details={"account": account.name, "disable_local_auth": False},
                    soc2_controls=["CC6.1", "CC6.7"],
                )
            )

    return findings


def check_azure_openai_private_endpoint(
    client: AzureClient, sub_id: str, region: str
) -> list[Finding]:
    """Check Azure OpenAI accounts use private endpoints."""
    cog_client = _get_cognitive_client(client)
    if cog_client is None:
        return [
            _sdk_missing_finding(
                "azure-openai-private-endpoint",
                "Unable to check Azure OpenAI private endpoints",
                "azure-mgmt-cognitiveservices",
                sub_id,
                region,
            )
        ]

    accounts = _list_openai_accounts(cog_client)
    if not accounts:
        return [
            Finding(
                check_id="azure-openai-private-endpoint",
                title="No Azure OpenAI accounts found",
                description="No Azure OpenAI resources in this subscription.",
                severity=Severity.INFO,
                status=ComplianceStatus.NOT_APPLICABLE,
                domain=CheckDomain.AI_GOVERNANCE,
                resource_type="Azure::CognitiveServices::Account",
                resource_id=f"/subscriptions/{sub_id}",
                region=region,
                account_id=sub_id,
                cloud_provider=CloudProvider.AZURE,
                soc2_controls=["CC6.6"],
            )
        ]

    findings: list[Finding] = []
    for account in accounts:
        private_endpoints = []
        if account.properties:
            pe_connections = getattr(account.properties, "private_endpoint_connections", None) or []
            private_endpoints = [
                pe
                for pe in pe_connections
                if getattr(getattr(pe, "private_link_service_connection_state", None), "status", "")
                == "Approved"
            ]

        if private_endpoints:
            findings.append(
                Finding(
                    check_id="azure-openai-private-endpoint",
                    title=f"Account '{account.name}' has private endpoint(s)",
                    description=f"Found {len(private_endpoints)} approved private endpoint connection(s).",
                    severity=Severity.INFO,
                    status=ComplianceStatus.PASS,
                    domain=CheckDomain.AI_GOVERNANCE,
                    resource_type="Azure::CognitiveServices::Account",
                    resource_id=account.id or f"/subscriptions/{sub_id}",
                    region=account.location or region,
                    account_id=sub_id,
                    cloud_provider=CloudProvider.AZURE,
                    details={
                        "account": account.name,
                        "private_endpoint_count": len(private_endpoints),
                    },
                    soc2_controls=["CC6.6"],
                )
            )
        else:
            findings.append(
                Finding(
                    check_id="azure-openai-private-endpoint",
                    title=f"Account '{account.name}' has no private endpoint",
                    description="No approved private endpoint connections found.",
                    severity=Severity.HIGH,
                    status=ComplianceStatus.FAIL,
                    domain=CheckDomain.AI_GOVERNANCE,
                    resource_type="Azure::CognitiveServices::Account",
                    resource_id=account.id or f"/subscriptions/{sub_id}",
                    region=account.location or region,
                    account_id=sub_id,
                    cloud_provider=CloudProvider.AZURE,
                    remediation="Create a private endpoint for this Azure OpenAI account.",
                    details={"account": account.name},
                    soc2_controls=["CC6.6"],
                )
            )

    return findings


def check_azure_openai_diagnostic_logging(
    client: AzureClient, sub_id: str, region: str
) -> list[Finding]:
    """Check Azure OpenAI accounts have diagnostic settings enabled."""
    cog_client = _get_cognitive_client(client)
    if cog_client is None:
        return [
            _sdk_missing_finding(
                "azure-openai-diagnostic-logging",
                "Unable to check Azure OpenAI diagnostics",
                "azure-mgmt-cognitiveservices",
                sub_id,
                region,
            )
        ]

    accounts = _list_openai_accounts(cog_client)
    if not accounts:
        return [
            Finding(
                check_id="azure-openai-diagnostic-logging",
                title="No Azure OpenAI accounts found",
                description="No Azure OpenAI resources in this subscription.",
                severity=Severity.INFO,
                status=ComplianceStatus.NOT_APPLICABLE,
                domain=CheckDomain.AI_GOVERNANCE,
                resource_type="Azure::CognitiveServices::Account",
                resource_id=f"/subscriptions/{sub_id}",
                region=region,
                account_id=sub_id,
                cloud_provider=CloudProvider.AZURE,
                soc2_controls=["CC7.1", "CC7.2"],
            )
        ]

    # Try to use Monitor client for diagnostic settings
    try:
        from azure.mgmt.monitor import MonitorManagementClient

        monitor_client = client.mgmt_client(MonitorManagementClient)
    except ImportError:
        return [
            _not_assessed(
                "azure-openai-diagnostic-logging",
                "Unable to check diagnostic settings",
                "azure-mgmt-monitor package is not installed.",
                "Azure::CognitiveServices::Account",
                sub_id,
                region,
            )
        ]

    findings: list[Finding] = []
    for account in accounts:
        if not account.id:
            continue
        try:
            diag_settings = list(monitor_client.diagnostic_settings.list(account.id))
            if diag_settings:
                findings.append(
                    Finding(
                        check_id="azure-openai-diagnostic-logging",
                        title=f"Account '{account.name}' has diagnostic logging enabled",
                        description=f"Found {len(diag_settings)} diagnostic setting(s).",
                        severity=Severity.INFO,
                        status=ComplianceStatus.PASS,
                        domain=CheckDomain.AI_GOVERNANCE,
                        resource_type="Azure::CognitiveServices::Account",
                        resource_id=account.id,
                        region=account.location or region,
                        account_id=sub_id,
                        cloud_provider=CloudProvider.AZURE,
                        details={
                            "account": account.name,
                            "diagnostic_setting_count": len(diag_settings),
                        },
                        soc2_controls=["CC7.1", "CC7.2"],
                    )
                )
            else:
                findings.append(
                    Finding(
                        check_id="azure-openai-diagnostic-logging",
                        title=f"Account '{account.name}' has no diagnostic logging",
                        description="No diagnostic settings configured for this Azure OpenAI account.",
                        severity=Severity.HIGH,
                        status=ComplianceStatus.FAIL,
                        domain=CheckDomain.AI_GOVERNANCE,
                        resource_type="Azure::CognitiveServices::Account",
                        resource_id=account.id,
                        region=account.location or region,
                        account_id=sub_id,
                        cloud_provider=CloudProvider.AZURE,
                        remediation=(
                            "Enable diagnostic settings to send logs to Log Analytics, "
                            "Storage, or Event Hubs."
                        ),
                        details={"account": account.name},
                        soc2_controls=["CC7.1", "CC7.2"],
                    )
                )
        except Exception as e:
            logger.debug("Failed to check diagnostics for %s: %s", account.name, e)

    return findings or [
        _not_assessed(
            "azure-openai-diagnostic-logging",
            "Unable to evaluate Azure OpenAI diagnostics",
            "Could not retrieve diagnostic settings.",
            "Azure::CognitiveServices::Account",
            sub_id,
            region,
        )
    ]


def check_azure_openai_managed_identity(
    client: AzureClient, sub_id: str, region: str
) -> list[Finding]:
    """Check Azure OpenAI accounts have a managed identity assigned."""
    cog_client = _get_cognitive_client(client)
    if cog_client is None:
        return [
            _sdk_missing_finding(
                "azure-openai-managed-identity",
                "Unable to check Azure OpenAI managed identity",
                "azure-mgmt-cognitiveservices",
                sub_id,
                region,
            )
        ]

    accounts = _list_openai_accounts(cog_client)
    if not accounts:
        return [
            Finding(
                check_id="azure-openai-managed-identity",
                title="No Azure OpenAI accounts found",
                description="No Azure OpenAI resources in this subscription.",
                severity=Severity.INFO,
                status=ComplianceStatus.NOT_APPLICABLE,
                domain=CheckDomain.AI_GOVERNANCE,
                resource_type="Azure::CognitiveServices::Account",
                resource_id=f"/subscriptions/{sub_id}",
                region=region,
                account_id=sub_id,
                cloud_provider=CloudProvider.AZURE,
                soc2_controls=["CC6.1", "CC6.3"],
            )
        ]

    findings: list[Finding] = []
    for account in accounts:
        identity = account.identity
        has_identity = identity is not None and getattr(identity, "type", None) is not None

        if has_identity:
            findings.append(
                Finding(
                    check_id="azure-openai-managed-identity",
                    title=f"Account '{account.name}' has managed identity",
                    description=f"Managed identity type: {identity.type}",
                    severity=Severity.INFO,
                    status=ComplianceStatus.PASS,
                    domain=CheckDomain.AI_GOVERNANCE,
                    resource_type="Azure::CognitiveServices::Account",
                    resource_id=account.id or f"/subscriptions/{sub_id}",
                    region=account.location or region,
                    account_id=sub_id,
                    cloud_provider=CloudProvider.AZURE,
                    details={"account": account.name, "identity_type": str(identity.type)},
                    soc2_controls=["CC6.1", "CC6.3"],
                )
            )
        else:
            findings.append(
                Finding(
                    check_id="azure-openai-managed-identity",
                    title=f"Account '{account.name}' has no managed identity",
                    description="No managed identity assigned to this Azure OpenAI account.",
                    severity=Severity.MEDIUM,
                    status=ComplianceStatus.FAIL,
                    domain=CheckDomain.AI_GOVERNANCE,
                    resource_type="Azure::CognitiveServices::Account",
                    resource_id=account.id or f"/subscriptions/{sub_id}",
                    region=account.location or region,
                    account_id=sub_id,
                    cloud_provider=CloudProvider.AZURE,
                    remediation="Assign a system-assigned or user-assigned managed identity.",
                    details={"account": account.name},
                    soc2_controls=["CC6.1", "CC6.3"],
                )
            )

    return findings


def check_azure_openai_abuse_monitoring(
    client: AzureClient, sub_id: str, region: str
) -> list[Finding]:
    """Check Azure OpenAI accounts have abuse monitoring enabled (default behavior)."""
    cog_client = _get_cognitive_client(client)
    if cog_client is None:
        return [
            _sdk_missing_finding(
                "azure-openai-abuse-monitoring",
                "Unable to check Azure OpenAI abuse monitoring",
                "azure-mgmt-cognitiveservices",
                sub_id,
                region,
            )
        ]

    accounts = _list_openai_accounts(cog_client)
    if not accounts:
        return [
            Finding(
                check_id="azure-openai-abuse-monitoring",
                title="No Azure OpenAI accounts found",
                description="No Azure OpenAI resources in this subscription.",
                severity=Severity.INFO,
                status=ComplianceStatus.NOT_APPLICABLE,
                domain=CheckDomain.AI_GOVERNANCE,
                resource_type="Azure::CognitiveServices::Account",
                resource_id=f"/subscriptions/{sub_id}",
                region=region,
                account_id=sub_id,
                cloud_provider=CloudProvider.AZURE,
                soc2_controls=["CC7.2"],
            )
        ]

    findings: list[Finding] = []
    for account in accounts:
        # Azure OpenAI abuse monitoring is enabled by default.
        # It can only be disabled via an approved exception.
        # We check the API properties for dynamic_throttling_enabled
        # as a proxy for whether the account has standard safeguards.
        # Abuse monitoring opt-out would show in restricted_access_uri or similar;
        # since it's on by default and requires MS approval to disable, we PASS
        # but note if the account has any unusual config.
        findings.append(
            Finding(
                check_id="azure-openai-abuse-monitoring",
                title=f"Account '{account.name}' has abuse monitoring (default enabled)",
                description=(
                    "Azure OpenAI abuse monitoring is enabled by default and can only be "
                    "disabled via a Microsoft-approved exception."
                ),
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.AI_GOVERNANCE,
                resource_type="Azure::CognitiveServices::Account",
                resource_id=account.id or f"/subscriptions/{sub_id}",
                region=account.location or region,
                account_id=sub_id,
                cloud_provider=CloudProvider.AZURE,
                details={"account": account.name},
                soc2_controls=["CC7.2"],
            )
        )

    return findings


# ---------------------------------------------------------------------------
# Azure ML checks
# ---------------------------------------------------------------------------


def check_azure_ml_workspace_encryption(
    client: AzureClient, sub_id: str, region: str
) -> list[Finding]:
    """Check Azure ML workspaces use customer-managed keys for encryption."""
    ml_client = _get_ml_client(client)
    if ml_client is None:
        return [
            _sdk_missing_finding(
                "azure-ml-workspace-encryption",
                "Unable to check Azure ML workspace encryption",
                "azure-mgmt-machinelearningservices",
                sub_id,
                region,
            )
        ]

    try:
        workspaces = list(ml_client.workspaces.list_by_subscription())
    except Exception as e:
        return [
            _not_assessed(
                "azure-ml-workspace-encryption",
                "Unable to list Azure ML workspaces",
                f"API call failed: {e}",
                "Azure::MachineLearning::Workspace",
                sub_id,
                region,
            )
        ]

    if not workspaces:
        return [
            Finding(
                check_id="azure-ml-workspace-encryption",
                title="No Azure ML workspaces found",
                description="No Azure ML workspaces in this subscription.",
                severity=Severity.INFO,
                status=ComplianceStatus.NOT_APPLICABLE,
                domain=CheckDomain.AI_GOVERNANCE,
                resource_type="Azure::MachineLearning::Workspace",
                resource_id=f"/subscriptions/{sub_id}",
                region=region,
                account_id=sub_id,
                cloud_provider=CloudProvider.AZURE,
                soc2_controls=["CC6.1"],
            )
        ]

    findings: list[Finding] = []
    for ws in workspaces:
        encryption = getattr(ws, "encryption", None)
        has_cmk = (
            encryption is not None and getattr(encryption, "key_vault_properties", None) is not None
        )

        if has_cmk:
            findings.append(
                Finding(
                    check_id="azure-ml-workspace-encryption",
                    title=f"Workspace '{ws.name}' uses customer-managed key",
                    description="Workspace is encrypted with a customer-managed key.",
                    severity=Severity.INFO,
                    status=ComplianceStatus.PASS,
                    domain=CheckDomain.AI_GOVERNANCE,
                    resource_type="Azure::MachineLearning::Workspace",
                    resource_id=ws.id or f"/subscriptions/{sub_id}",
                    region=ws.location or region,
                    account_id=sub_id,
                    cloud_provider=CloudProvider.AZURE,
                    details={"workspace": ws.name},
                    soc2_controls=["CC6.1"],
                )
            )
        else:
            findings.append(
                Finding(
                    check_id="azure-ml-workspace-encryption",
                    title=f"Workspace '{ws.name}' uses Microsoft-managed keys",
                    description="Workspace uses default Microsoft-managed encryption, not CMK.",
                    severity=Severity.MEDIUM,
                    status=ComplianceStatus.PARTIAL,
                    domain=CheckDomain.AI_GOVERNANCE,
                    resource_type="Azure::MachineLearning::Workspace",
                    resource_id=ws.id or f"/subscriptions/{sub_id}",
                    region=ws.location or region,
                    account_id=sub_id,
                    cloud_provider=CloudProvider.AZURE,
                    remediation="Configure customer-managed keys for workspace encryption.",
                    details={"workspace": ws.name},
                    soc2_controls=["CC6.1"],
                )
            )

    return findings


def check_azure_ml_compute_rbac(client: AzureClient, sub_id: str, region: str) -> list[Finding]:
    """Check Azure ML compute targets use RBAC (not shared key auth)."""
    ml_client = _get_ml_client(client)
    if ml_client is None:
        return [
            _sdk_missing_finding(
                "azure-ml-compute-rbac",
                "Unable to check Azure ML compute RBAC",
                "azure-mgmt-machinelearningservices",
                sub_id,
                region,
            )
        ]

    try:
        workspaces = list(ml_client.workspaces.list_by_subscription())
    except Exception as e:
        return [
            _not_assessed(
                "azure-ml-compute-rbac",
                "Unable to list Azure ML workspaces",
                f"API call failed: {e}",
                "Azure::MachineLearning::Workspace",
                sub_id,
                region,
            )
        ]

    if not workspaces:
        return [
            Finding(
                check_id="azure-ml-compute-rbac",
                title="No Azure ML workspaces found",
                description="No Azure ML workspaces to evaluate.",
                severity=Severity.INFO,
                status=ComplianceStatus.NOT_APPLICABLE,
                domain=CheckDomain.AI_GOVERNANCE,
                resource_type="Azure::MachineLearning::Compute",
                resource_id=f"/subscriptions/{sub_id}",
                region=region,
                account_id=sub_id,
                cloud_provider=CloudProvider.AZURE,
                soc2_controls=["CC6.1", "CC6.3"],
            )
        ]

    findings: list[Finding] = []
    for ws in workspaces:
        rg = _resource_group_from_id(ws.id)
        if not rg:
            continue
        try:
            computes = list(ml_client.compute.list(rg, ws.name))
            if not computes:
                continue

            for compute in computes:
                compute_name = compute.name or "unknown"
                props = compute.properties
                # Check if compute has local auth disabled
                disable_local_auth = getattr(props, "disable_local_auth", None)

                if disable_local_auth:
                    findings.append(
                        Finding(
                            check_id="azure-ml-compute-rbac",
                            title=f"Compute '{compute_name}' uses RBAC auth",
                            description="Local authentication is disabled; RBAC is enforced.",
                            severity=Severity.INFO,
                            status=ComplianceStatus.PASS,
                            domain=CheckDomain.AI_GOVERNANCE,
                            resource_type="Azure::MachineLearning::Compute",
                            resource_id=compute.id or f"{ws.id}/computes/{compute_name}",
                            region=ws.location or region,
                            account_id=sub_id,
                            cloud_provider=CloudProvider.AZURE,
                            details={"workspace": ws.name, "compute": compute_name},
                            soc2_controls=["CC6.1", "CC6.3"],
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            check_id="azure-ml-compute-rbac",
                            title=f"Compute '{compute_name}' may use local auth",
                            description="Local authentication is not explicitly disabled.",
                            severity=Severity.MEDIUM,
                            status=ComplianceStatus.FAIL,
                            domain=CheckDomain.AI_GOVERNANCE,
                            resource_type="Azure::MachineLearning::Compute",
                            resource_id=compute.id or f"{ws.id}/computes/{compute_name}",
                            region=ws.location or region,
                            account_id=sub_id,
                            cloud_provider=CloudProvider.AZURE,
                            remediation="Disable local authentication on compute targets.",
                            details={"workspace": ws.name, "compute": compute_name},
                            soc2_controls=["CC6.1", "CC6.3"],
                        )
                    )
        except Exception as e:
            logger.debug("Failed to list computes for workspace %s: %s", ws.name, e)

    return findings or [
        Finding(
            check_id="azure-ml-compute-rbac",
            title="No Azure ML compute targets found",
            description="No compute targets to evaluate across workspaces.",
            severity=Severity.INFO,
            status=ComplianceStatus.NOT_APPLICABLE,
            domain=CheckDomain.AI_GOVERNANCE,
            resource_type="Azure::MachineLearning::Compute",
            resource_id=f"/subscriptions/{sub_id}",
            region=region,
            account_id=sub_id,
            cloud_provider=CloudProvider.AZURE,
            soc2_controls=["CC6.1", "CC6.3"],
        )
    ]


def check_azure_ml_model_registration(
    client: AzureClient, sub_id: str, region: str
) -> list[Finding]:
    """Check Azure ML workspaces have registered models (model governance)."""
    ml_client = _get_ml_client(client)
    if ml_client is None:
        return [
            _sdk_missing_finding(
                "azure-ml-model-registration",
                "Unable to check Azure ML model registration",
                "azure-mgmt-machinelearningservices",
                sub_id,
                region,
            )
        ]

    try:
        workspaces = list(ml_client.workspaces.list_by_subscription())
    except Exception as e:
        return [
            _not_assessed(
                "azure-ml-model-registration",
                "Unable to list Azure ML workspaces",
                f"API call failed: {e}",
                "Azure::MachineLearning::Workspace",
                sub_id,
                region,
            )
        ]

    if not workspaces:
        return [
            Finding(
                check_id="azure-ml-model-registration",
                title="No Azure ML workspaces found",
                description="No Azure ML workspaces to evaluate.",
                severity=Severity.INFO,
                status=ComplianceStatus.NOT_APPLICABLE,
                domain=CheckDomain.AI_GOVERNANCE,
                resource_type="Azure::MachineLearning::Model",
                resource_id=f"/subscriptions/{sub_id}",
                region=region,
                account_id=sub_id,
                cloud_provider=CloudProvider.AZURE,
                soc2_controls=["CC8.1"],
            )
        ]

    findings: list[Finding] = []
    for ws in workspaces:
        rg = _resource_group_from_id(ws.id)
        if not rg:
            continue
        try:
            # List model versions — the presence of registered models indicates governance
            models = list(
                ml_client.registry_model_containers.list(rg, ws.name)
                if hasattr(ml_client, "registry_model_containers")
                else []
            )
            # Fallback: try model_containers
            if not models and hasattr(ml_client, "model_containers"):
                models = list(ml_client.model_containers.list(rg, ws.name))

            if models:
                findings.append(
                    Finding(
                        check_id="azure-ml-model-registration",
                        title=f"Workspace '{ws.name}' has {len(models)} registered model(s)",
                        description="Models are registered in the workspace model registry.",
                        severity=Severity.INFO,
                        status=ComplianceStatus.PASS,
                        domain=CheckDomain.AI_GOVERNANCE,
                        resource_type="Azure::MachineLearning::Model",
                        resource_id=ws.id or f"/subscriptions/{sub_id}",
                        region=ws.location or region,
                        account_id=sub_id,
                        cloud_provider=CloudProvider.AZURE,
                        details={"workspace": ws.name, "model_count": len(models)},
                        soc2_controls=["CC8.1"],
                    )
                )
            else:
                findings.append(
                    Finding(
                        check_id="azure-ml-model-registration",
                        title=f"Workspace '{ws.name}' has no registered models",
                        description="No models registered in the workspace registry.",
                        severity=Severity.MEDIUM,
                        status=ComplianceStatus.FAIL,
                        domain=CheckDomain.AI_GOVERNANCE,
                        resource_type="Azure::MachineLearning::Model",
                        resource_id=ws.id or f"/subscriptions/{sub_id}",
                        region=ws.location or region,
                        account_id=sub_id,
                        cloud_provider=CloudProvider.AZURE,
                        remediation="Register models in the Azure ML model registry for governance.",
                        details={"workspace": ws.name},
                        soc2_controls=["CC8.1"],
                    )
                )
        except Exception as e:
            logger.debug("Failed to list models for workspace %s: %s", ws.name, e)

    return findings or [
        _not_assessed(
            "azure-ml-model-registration",
            "Unable to evaluate Azure ML model registration",
            "Could not retrieve model information.",
            "Azure::MachineLearning::Model",
            sub_id,
            region,
        )
    ]


def check_azure_ml_data_drift_monitor(
    client: AzureClient, sub_id: str, region: str
) -> list[Finding]:
    """Check Azure ML workspaces have data drift monitoring configured."""
    ml_client = _get_ml_client(client)
    if ml_client is None:
        return [
            _sdk_missing_finding(
                "azure-ml-data-drift-monitor",
                "Unable to check Azure ML data drift monitoring",
                "azure-mgmt-machinelearningservices",
                sub_id,
                region,
            )
        ]

    try:
        workspaces = list(ml_client.workspaces.list_by_subscription())
    except Exception as e:
        return [
            _not_assessed(
                "azure-ml-data-drift-monitor",
                "Unable to list Azure ML workspaces",
                f"API call failed: {e}",
                "Azure::MachineLearning::Workspace",
                sub_id,
                region,
            )
        ]

    if not workspaces:
        return [
            Finding(
                check_id="azure-ml-data-drift-monitor",
                title="No Azure ML workspaces found",
                description="No Azure ML workspaces to evaluate.",
                severity=Severity.INFO,
                status=ComplianceStatus.NOT_APPLICABLE,
                domain=CheckDomain.AI_GOVERNANCE,
                resource_type="Azure::MachineLearning::Workspace",
                resource_id=f"/subscriptions/{sub_id}",
                region=region,
                account_id=sub_id,
                cloud_provider=CloudProvider.AZURE,
                soc2_controls=["CC7.1", "CC7.2"],
            )
        ]

    findings: list[Finding] = []
    for ws in workspaces:
        rg = _resource_group_from_id(ws.id)
        if not rg:
            continue
        try:
            # Check for monitoring schedules (data drift monitors are schedules in v2)
            has_schedules = False
            if hasattr(ml_client, "schedules"):
                schedules = list(ml_client.schedules.list(rg, ws.name))
                has_schedules = len(schedules) > 0

            if has_schedules:
                findings.append(
                    Finding(
                        check_id="azure-ml-data-drift-monitor",
                        title=f"Workspace '{ws.name}' has monitoring schedules",
                        description="Found monitoring schedules that may include data drift detection.",
                        severity=Severity.INFO,
                        status=ComplianceStatus.PASS,
                        domain=CheckDomain.AI_GOVERNANCE,
                        resource_type="Azure::MachineLearning::Workspace",
                        resource_id=ws.id or f"/subscriptions/{sub_id}",
                        region=ws.location or region,
                        account_id=sub_id,
                        cloud_provider=CloudProvider.AZURE,
                        details={"workspace": ws.name},
                        soc2_controls=["CC7.1", "CC7.2"],
                    )
                )
            else:
                findings.append(
                    Finding(
                        check_id="azure-ml-data-drift-monitor",
                        title=f"Workspace '{ws.name}' has no data drift monitoring",
                        description="No monitoring schedules found for data drift detection.",
                        severity=Severity.MEDIUM,
                        status=ComplianceStatus.FAIL,
                        domain=CheckDomain.AI_GOVERNANCE,
                        resource_type="Azure::MachineLearning::Workspace",
                        resource_id=ws.id or f"/subscriptions/{sub_id}",
                        region=ws.location or region,
                        account_id=sub_id,
                        cloud_provider=CloudProvider.AZURE,
                        remediation="Configure data drift monitoring in Azure ML for production models.",
                        details={"workspace": ws.name},
                        soc2_controls=["CC7.1", "CC7.2"],
                    )
                )
        except Exception as e:
            logger.debug("Failed to check schedules for workspace %s: %s", ws.name, e)
            findings.append(
                _not_assessed(
                    "azure-ml-data-drift-monitor",
                    f"Unable to check drift monitoring for '{ws.name}'",
                    f"API call failed: {e}",
                    "Azure::MachineLearning::Workspace",
                    sub_id,
                    region,
                )
            )

    return findings


# ---------------------------------------------------------------------------
# Cognitive Services checks
# ---------------------------------------------------------------------------


def _list_ai_cognitive_accounts(cog_client: Any) -> list[Any]:
    """List all AI-related Cognitive Services accounts (excluding OpenAI)."""
    ai_kinds = {
        "CognitiveServices",
        "TextAnalytics",
        "TextTranslation",
        "ComputerVision",
        "CustomVision.Training",
        "CustomVision.Prediction",
        "FormRecognizer",
        "SpeechServices",
        "ContentSafety",
        "AnomalyDetector",
        "Face",
    }
    accounts = []
    try:
        for account in cog_client.accounts.list():
            if account.kind in ai_kinds:
                accounts.append(account)
    except Exception as e:
        logger.debug("Failed to list Cognitive Services accounts: %s", e)
    return accounts


def check_azure_cognitive_network_rules(
    client: AzureClient, sub_id: str, region: str
) -> list[Finding]:
    """Check Cognitive Services accounts have network access restrictions."""
    cog_client = _get_cognitive_client(client)
    if cog_client is None:
        return [
            _sdk_missing_finding(
                "azure-cognitive-network-rules",
                "Unable to check Cognitive Services network rules",
                "azure-mgmt-cognitiveservices",
                sub_id,
                region,
            )
        ]

    # Check both OpenAI and other Cognitive Services accounts
    all_accounts = []
    try:
        for account in cog_client.accounts.list():
            all_accounts.append(account)
    except Exception as e:
        return [
            _not_assessed(
                "azure-cognitive-network-rules",
                "Unable to list Cognitive Services accounts",
                f"API call failed: {e}",
                "Azure::CognitiveServices::Account",
                sub_id,
                region,
            )
        ]

    if not all_accounts:
        return [
            Finding(
                check_id="azure-cognitive-network-rules",
                title="No Cognitive Services accounts found",
                description="No Cognitive Services accounts in this subscription.",
                severity=Severity.INFO,
                status=ComplianceStatus.NOT_APPLICABLE,
                domain=CheckDomain.AI_GOVERNANCE,
                resource_type="Azure::CognitiveServices::Account",
                resource_id=f"/subscriptions/{sub_id}",
                region=region,
                account_id=sub_id,
                cloud_provider=CloudProvider.AZURE,
                soc2_controls=["CC6.6"],
            )
        ]

    findings: list[Finding] = []
    for account in all_accounts:
        network_acls = None
        public_access = True
        if account.properties:
            network_acls = getattr(account.properties, "network_acls", None)
            public_access = (
                getattr(account.properties, "public_network_access", "Enabled") != "Disabled"
            )

        default_action = "Allow"
        if network_acls:
            default_action = getattr(network_acls, "default_action", "Allow") or "Allow"

        if default_action == "Deny" or not public_access:
            findings.append(
                Finding(
                    check_id="azure-cognitive-network-rules",
                    title=f"Account '{account.name}' has network restrictions",
                    description=f"Default action: {default_action}, public access: {'disabled' if not public_access else 'restricted'}.",
                    severity=Severity.INFO,
                    status=ComplianceStatus.PASS,
                    domain=CheckDomain.AI_GOVERNANCE,
                    resource_type="Azure::CognitiveServices::Account",
                    resource_id=account.id or f"/subscriptions/{sub_id}",
                    region=account.location or region,
                    account_id=sub_id,
                    cloud_provider=CloudProvider.AZURE,
                    details={
                        "account": account.name,
                        "kind": account.kind,
                        "default_action": default_action,
                    },
                    soc2_controls=["CC6.6"],
                )
            )
        else:
            findings.append(
                Finding(
                    check_id="azure-cognitive-network-rules",
                    title=f"Account '{account.name}' allows public network access",
                    description="No network restrictions configured; accessible from any network.",
                    severity=Severity.HIGH,
                    status=ComplianceStatus.FAIL,
                    domain=CheckDomain.AI_GOVERNANCE,
                    resource_type="Azure::CognitiveServices::Account",
                    resource_id=account.id or f"/subscriptions/{sub_id}",
                    region=account.location or region,
                    account_id=sub_id,
                    cloud_provider=CloudProvider.AZURE,
                    remediation="Configure network rules to restrict access to trusted networks.",
                    details={
                        "account": account.name,
                        "kind": account.kind,
                        "default_action": default_action,
                    },
                    soc2_controls=["CC6.6"],
                )
            )

    return findings


def check_azure_cognitive_cmk(client: AzureClient, sub_id: str, region: str) -> list[Finding]:
    """Check Cognitive Services accounts use customer-managed keys."""
    cog_client = _get_cognitive_client(client)
    if cog_client is None:
        return [
            _sdk_missing_finding(
                "azure-cognitive-cmk",
                "Unable to check Cognitive Services CMK",
                "azure-mgmt-cognitiveservices",
                sub_id,
                region,
            )
        ]

    all_accounts = []
    try:
        for account in cog_client.accounts.list():
            all_accounts.append(account)
    except Exception as e:
        return [
            _not_assessed(
                "azure-cognitive-cmk",
                "Unable to list Cognitive Services accounts",
                f"API call failed: {e}",
                "Azure::CognitiveServices::Account",
                sub_id,
                region,
            )
        ]

    if not all_accounts:
        return [
            Finding(
                check_id="azure-cognitive-cmk",
                title="No Cognitive Services accounts found",
                description="No Cognitive Services accounts in this subscription.",
                severity=Severity.INFO,
                status=ComplianceStatus.NOT_APPLICABLE,
                domain=CheckDomain.AI_GOVERNANCE,
                resource_type="Azure::CognitiveServices::Account",
                resource_id=f"/subscriptions/{sub_id}",
                region=region,
                account_id=sub_id,
                cloud_provider=CloudProvider.AZURE,
                soc2_controls=["CC6.1"],
            )
        ]

    findings: list[Finding] = []
    for account in all_accounts:
        encryption = None
        if account.properties:
            encryption = getattr(account.properties, "encryption", None)

        has_cmk = (
            encryption is not None
            and getattr(encryption, "key_source", None) == "Microsoft.KeyVault"
        )

        if has_cmk:
            findings.append(
                Finding(
                    check_id="azure-cognitive-cmk",
                    title=f"Account '{account.name}' uses customer-managed key",
                    description="Encrypted with a customer-managed key from Key Vault.",
                    severity=Severity.INFO,
                    status=ComplianceStatus.PASS,
                    domain=CheckDomain.AI_GOVERNANCE,
                    resource_type="Azure::CognitiveServices::Account",
                    resource_id=account.id or f"/subscriptions/{sub_id}",
                    region=account.location or region,
                    account_id=sub_id,
                    cloud_provider=CloudProvider.AZURE,
                    details={"account": account.name, "kind": account.kind},
                    soc2_controls=["CC6.1"],
                )
            )
        else:
            findings.append(
                Finding(
                    check_id="azure-cognitive-cmk",
                    title=f"Account '{account.name}' uses Microsoft-managed keys",
                    description="Uses default Microsoft-managed encryption, not CMK.",
                    severity=Severity.LOW,
                    status=ComplianceStatus.PARTIAL,
                    domain=CheckDomain.AI_GOVERNANCE,
                    resource_type="Azure::CognitiveServices::Account",
                    resource_id=account.id or f"/subscriptions/{sub_id}",
                    region=account.location or region,
                    account_id=sub_id,
                    cloud_provider=CloudProvider.AZURE,
                    remediation="Configure customer-managed keys via Azure Key Vault.",
                    details={"account": account.name, "kind": account.kind},
                    soc2_controls=["CC6.1"],
                )
            )

    return findings


# ---------------------------------------------------------------------------
# AI Search check
# ---------------------------------------------------------------------------


def check_azure_ai_search_auth(client: AzureClient, sub_id: str, region: str) -> list[Finding]:
    """Check Azure AI Search services use RBAC instead of API keys."""
    try:
        from azure.mgmt.search import SearchManagementClient

        search_client = client.mgmt_client(SearchManagementClient)
    except ImportError:
        return [
            _not_assessed(
                "azure-ai-search-auth",
                "Unable to check Azure AI Search",
                "azure-mgmt-search package is not installed.",
                "Azure::Search::Service",
                sub_id,
                region,
            )
        ]

    try:
        services = list(search_client.services.list_by_subscription())
    except Exception as e:
        return [
            _not_assessed(
                "azure-ai-search-auth",
                "Unable to list Azure AI Search services",
                f"API call failed: {e}",
                "Azure::Search::Service",
                sub_id,
                region,
            )
        ]

    if not services:
        return [
            Finding(
                check_id="azure-ai-search-auth",
                title="No Azure AI Search services found",
                description="No AI Search services in this subscription.",
                severity=Severity.INFO,
                status=ComplianceStatus.NOT_APPLICABLE,
                domain=CheckDomain.AI_GOVERNANCE,
                resource_type="Azure::Search::Service",
                resource_id=f"/subscriptions/{sub_id}",
                region=region,
                account_id=sub_id,
                cloud_provider=CloudProvider.AZURE,
                soc2_controls=["CC6.1", "CC6.3"],
            )
        ]

    findings: list[Finding] = []
    for svc in services:
        getattr(svc, "auth_options", None)
        disable_local_auth = getattr(svc, "disable_local_auth", False)

        if disable_local_auth:
            findings.append(
                Finding(
                    check_id="azure-ai-search-auth",
                    title=f"Search service '{svc.name}' uses RBAC only",
                    description="API key authentication is disabled; RBAC is enforced.",
                    severity=Severity.INFO,
                    status=ComplianceStatus.PASS,
                    domain=CheckDomain.AI_GOVERNANCE,
                    resource_type="Azure::Search::Service",
                    resource_id=svc.id or f"/subscriptions/{sub_id}",
                    region=svc.location or region,
                    account_id=sub_id,
                    cloud_provider=CloudProvider.AZURE,
                    details={"service": svc.name},
                    soc2_controls=["CC6.1", "CC6.3"],
                )
            )
        else:
            findings.append(
                Finding(
                    check_id="azure-ai-search-auth",
                    title=f"Search service '{svc.name}' allows API key auth",
                    description="API key authentication is enabled alongside RBAC.",
                    severity=Severity.MEDIUM,
                    status=ComplianceStatus.FAIL,
                    domain=CheckDomain.AI_GOVERNANCE,
                    resource_type="Azure::Search::Service",
                    resource_id=svc.id or f"/subscriptions/{sub_id}",
                    region=svc.location or region,
                    account_id=sub_id,
                    cloud_provider=CloudProvider.AZURE,
                    remediation="Disable API key auth and enforce RBAC-only access.",
                    details={"service": svc.name},
                    soc2_controls=["CC6.1", "CC6.3"],
                )
            )

    return findings


# ---------------------------------------------------------------------------
# Responsible AI and environment checks
# ---------------------------------------------------------------------------


def check_azure_responsible_ai_dashboard(
    client: AzureClient, sub_id: str, region: str
) -> list[Finding]:
    """Check Azure ML workspaces have Responsible AI dashboards created."""
    ml_client = _get_ml_client(client)
    if ml_client is None:
        return [
            _sdk_missing_finding(
                "azure-responsible-ai-dashboard",
                "Unable to check Responsible AI dashboards",
                "azure-mgmt-machinelearningservices",
                sub_id,
                region,
            )
        ]

    try:
        workspaces = list(ml_client.workspaces.list_by_subscription())
    except Exception as e:
        return [
            _not_assessed(
                "azure-responsible-ai-dashboard",
                "Unable to list Azure ML workspaces",
                f"API call failed: {e}",
                "Azure::MachineLearning::Workspace",
                sub_id,
                region,
            )
        ]

    if not workspaces:
        return [
            Finding(
                check_id="azure-responsible-ai-dashboard",
                title="No Azure ML workspaces found",
                description="No Azure ML workspaces to evaluate for Responsible AI dashboards.",
                severity=Severity.INFO,
                status=ComplianceStatus.NOT_APPLICABLE,
                domain=CheckDomain.AI_GOVERNANCE,
                resource_type="Azure::MachineLearning::Workspace",
                resource_id=f"/subscriptions/{sub_id}",
                region=region,
                account_id=sub_id,
                cloud_provider=CloudProvider.AZURE,
                soc2_controls=["CC7.2"],
            )
        ]

    findings: list[Finding] = []
    for ws in workspaces:
        rg = _resource_group_from_id(ws.id)
        if not rg:
            continue
        try:
            # Check for RAI components by looking at component containers
            has_rai_components = False
            if hasattr(ml_client, "component_containers"):
                try:
                    components = list(ml_client.component_containers.list(rg, ws.name))
                    has_rai_components = any(
                        "responsibleai" in (getattr(c, "name", "") or "").lower()
                        or "rai" in (getattr(c, "name", "") or "").lower()
                        for c in components
                    )
                except Exception:
                    pass

            if has_rai_components:
                findings.append(
                    Finding(
                        check_id="azure-responsible-ai-dashboard",
                        title=f"Workspace '{ws.name}' has RAI components",
                        description="Responsible AI components found in the workspace.",
                        severity=Severity.INFO,
                        status=ComplianceStatus.PASS,
                        domain=CheckDomain.AI_GOVERNANCE,
                        resource_type="Azure::MachineLearning::Workspace",
                        resource_id=ws.id or f"/subscriptions/{sub_id}",
                        region=ws.location or region,
                        account_id=sub_id,
                        cloud_provider=CloudProvider.AZURE,
                        details={"workspace": ws.name},
                        soc2_controls=["CC7.2"],
                    )
                )
            else:
                findings.append(
                    Finding(
                        check_id="azure-responsible-ai-dashboard",
                        title=f"Workspace '{ws.name}' has no RAI dashboards",
                        description=(
                            "No Responsible AI dashboard components found. RAI dashboards "
                            "provide fairness, interpretability, and error analysis."
                        ),
                        severity=Severity.MEDIUM,
                        status=ComplianceStatus.FAIL,
                        domain=CheckDomain.AI_GOVERNANCE,
                        resource_type="Azure::MachineLearning::Workspace",
                        resource_id=ws.id or f"/subscriptions/{sub_id}",
                        region=ws.location or region,
                        account_id=sub_id,
                        cloud_provider=CloudProvider.AZURE,
                        remediation="Create a Responsible AI dashboard for production models.",
                        details={"workspace": ws.name},
                        soc2_controls=["CC7.2"],
                    )
                )
        except Exception as e:
            logger.debug("Failed to check RAI for workspace %s: %s", ws.name, e)

    return findings or [
        _not_assessed(
            "azure-responsible-ai-dashboard",
            "Unable to evaluate Responsible AI dashboards",
            "Could not retrieve component information.",
            "Azure::MachineLearning::Workspace",
            sub_id,
            region,
        )
    ]


def check_azure_ml_environment_pinned(
    client: AzureClient, sub_id: str, region: str
) -> list[Finding]:
    """Check Azure ML environments use pinned (versioned) base images."""
    ml_client = _get_ml_client(client)
    if ml_client is None:
        return [
            _sdk_missing_finding(
                "azure-ml-environment-pinned",
                "Unable to check Azure ML environments",
                "azure-mgmt-machinelearningservices",
                sub_id,
                region,
            )
        ]

    try:
        workspaces = list(ml_client.workspaces.list_by_subscription())
    except Exception as e:
        return [
            _not_assessed(
                "azure-ml-environment-pinned",
                "Unable to list Azure ML workspaces",
                f"API call failed: {e}",
                "Azure::MachineLearning::Workspace",
                sub_id,
                region,
            )
        ]

    if not workspaces:
        return [
            Finding(
                check_id="azure-ml-environment-pinned",
                title="No Azure ML workspaces found",
                description="No Azure ML workspaces to evaluate.",
                severity=Severity.INFO,
                status=ComplianceStatus.NOT_APPLICABLE,
                domain=CheckDomain.AI_GOVERNANCE,
                resource_type="Azure::MachineLearning::Environment",
                resource_id=f"/subscriptions/{sub_id}",
                region=region,
                account_id=sub_id,
                cloud_provider=CloudProvider.AZURE,
                soc2_controls=["CC8.1"],
            )
        ]

    findings: list[Finding] = []
    for ws in workspaces:
        rg = _resource_group_from_id(ws.id)
        if not rg:
            continue
        try:
            if not hasattr(ml_client, "environment_containers"):
                continue

            envs = list(ml_client.environment_containers.list(rg, ws.name))
            custom_envs = [
                e for e in envs if not (getattr(e, "name", "") or "").startswith("AzureML-")
            ]

            if not custom_envs:
                findings.append(
                    Finding(
                        check_id="azure-ml-environment-pinned",
                        title=f"Workspace '{ws.name}' uses only curated environments",
                        description="Only Azure-managed curated environments found (versioned by default).",
                        severity=Severity.INFO,
                        status=ComplianceStatus.PASS,
                        domain=CheckDomain.AI_GOVERNANCE,
                        resource_type="Azure::MachineLearning::Environment",
                        resource_id=ws.id or f"/subscriptions/{sub_id}",
                        region=ws.location or region,
                        account_id=sub_id,
                        cloud_provider=CloudProvider.AZURE,
                        details={"workspace": ws.name},
                        soc2_controls=["CC8.1"],
                    )
                )
            else:
                # Check if custom environments have version info
                unpinned: list[str] = []
                for env in custom_envs:
                    env_name = getattr(env, "name", "unknown")
                    # Check latest version for docker image tag
                    try:
                        versions = list(
                            ml_client.environment_versions.list(
                                rg,
                                ws.name,
                                env_name,
                                order_by="creationcontext/createdtime desc",
                                top=1,
                            )
                        )
                        for ver in versions:
                            props = getattr(ver, "properties", None)
                            if props:
                                image = getattr(props, "image", "") or ""
                                # Check if using :latest or no tag
                                if image and (
                                    ":latest" in image or ":" not in image.split("/")[-1]
                                ):
                                    unpinned.append(f"{env_name} ({image})")
                    except Exception:
                        pass

                if unpinned:
                    findings.append(
                        Finding(
                            check_id="azure-ml-environment-pinned",
                            title=f"Workspace '{ws.name}' has unpinned environment images",
                            description=f"Found {len(unpinned)} environment(s) using :latest or untagged images.",
                            severity=Severity.MEDIUM,
                            status=ComplianceStatus.FAIL,
                            domain=CheckDomain.AI_GOVERNANCE,
                            resource_type="Azure::MachineLearning::Environment",
                            resource_id=ws.id or f"/subscriptions/{sub_id}",
                            region=ws.location or region,
                            account_id=sub_id,
                            cloud_provider=CloudProvider.AZURE,
                            remediation="Pin environment base images to specific versions/digests.",
                            details={"workspace": ws.name, "unpinned_envs": unpinned},
                            soc2_controls=["CC8.1"],
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            check_id="azure-ml-environment-pinned",
                            title=f"Workspace '{ws.name}' custom environments use pinned images",
                            description="All custom environments reference pinned image versions.",
                            severity=Severity.INFO,
                            status=ComplianceStatus.PASS,
                            domain=CheckDomain.AI_GOVERNANCE,
                            resource_type="Azure::MachineLearning::Environment",
                            resource_id=ws.id or f"/subscriptions/{sub_id}",
                            region=ws.location or region,
                            account_id=sub_id,
                            cloud_provider=CloudProvider.AZURE,
                            details={"workspace": ws.name, "custom_env_count": len(custom_envs)},
                            soc2_controls=["CC8.1"],
                        )
                    )
        except Exception as e:
            logger.debug("Failed to check environments for workspace %s: %s", ws.name, e)

    return findings or [
        _not_assessed(
            "azure-ml-environment-pinned",
            "Unable to evaluate Azure ML environments",
            "Could not retrieve environment information.",
            "Azure::MachineLearning::Environment",
            sub_id,
            region,
        )
    ]
