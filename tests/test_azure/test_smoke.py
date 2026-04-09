"""Smoke tests for Azure modules.

These tests do NOT hit Azure. They verify that:
1. Every check module imports cleanly.
2. Every public ``run_all_*`` runner has the expected signature.
3. The cross-cutting matrix / constant tables are well-formed.
4. Multi-subscription helpers exist on AzureClient.

Live-cloud integration tests for Azure are out of scope here; the goal is
to prevent regressions from ImportError, signature drift, and broken
constant tables.
"""

from __future__ import annotations

import importlib
import inspect

import pytest

from shasta.evidence.models import CheckDomain, CloudProvider, Finding, Severity


AZURE_MODULES = [
    "shasta.azure.iam",
    "shasta.azure.storage",
    "shasta.azure.networking",
    "shasta.azure.encryption",
    "shasta.azure.monitoring",
    "shasta.azure.compute",
    "shasta.azure.databases",
    "shasta.azure.appservice",
    "shasta.azure.backup",
    "shasta.azure.private_endpoints",
    "shasta.azure.diagnostic_settings",
    "shasta.azure.governance",
]

EXPECTED_RUNNERS = {
    "shasta.azure.iam": "run_all_azure_iam_checks",
    "shasta.azure.storage": "run_all_azure_storage_checks",
    "shasta.azure.networking": "run_all_azure_networking_checks",
    "shasta.azure.encryption": "run_all_azure_encryption_checks",
    "shasta.azure.monitoring": "run_all_azure_monitoring_checks",
    "shasta.azure.compute": "run_all_azure_compute_checks",
    "shasta.azure.databases": "run_all_azure_database_checks",
    "shasta.azure.appservice": "run_all_azure_appservice_checks",
    "shasta.azure.backup": "run_all_azure_backup_checks",
    "shasta.azure.private_endpoints": "run_all_azure_private_endpoint_checks",
    "shasta.azure.diagnostic_settings": "run_all_azure_diagnostic_settings_checks",
    "shasta.azure.governance": "run_all_azure_governance_checks",
}


@pytest.mark.parametrize("mod_name", AZURE_MODULES)
def test_module_imports(mod_name: str) -> None:
    importlib.import_module(mod_name)


@pytest.mark.parametrize("mod_name,runner_name", list(EXPECTED_RUNNERS.items()))
def test_runner_exists_and_takes_client(mod_name: str, runner_name: str) -> None:
    mod = importlib.import_module(mod_name)
    runner = getattr(mod, runner_name)
    sig = inspect.signature(runner)
    params = list(sig.parameters)
    assert params, f"{runner_name} should accept at least one positional argument (client)"
    assert params[0] in ("client", "azure_client")


def test_diagnostic_matrix_well_formed() -> None:
    from shasta.azure.diagnostic_settings import EXPECTED_DIAGNOSTIC_CATEGORIES

    assert EXPECTED_DIAGNOSTIC_CATEGORIES, "matrix should not be empty"
    for resource_type, categories in EXPECTED_DIAGNOSTIC_CATEGORIES.items():
        assert "/" in resource_type, f"{resource_type} should be a fully-qualified ARM type"
        assert categories, f"{resource_type} should declare at least one expected category"
        assert all(isinstance(c, str) and c for c in categories)


def test_defender_required_plans_complete() -> None:
    from shasta.azure.monitoring import DEFENDER_REQUIRED_PLANS

    # CIS Azure v3.0 enumerates 14 Defender plans; we should track at least 10.
    assert len(DEFENDER_REQUIRED_PLANS) >= 10
    assert "VirtualMachines" in DEFENDER_REQUIRED_PLANS
    assert "KeyVaults" in DEFENDER_REQUIRED_PLANS


def test_activity_log_alert_operations_cover_cis_5_2() -> None:
    from shasta.azure.monitoring import ACTIVITY_LOG_ALERT_OPERATIONS

    cis_ids = {entry[1] for entry in ACTIVITY_LOG_ALERT_OPERATIONS}
    # CIS Azure 5.2.1 - 5.2.8 should all be present in some form
    for required in ("5.2.1", "5.2.2", "5.2.5", "5.2.6", "5.2.7", "5.2.8"):
        assert required in cis_ids, f"Missing CIS {required} in Activity Log alert mapping"


def test_finding_model_has_cis_and_mcsb_fields() -> None:
    f = Finding(
        check_id="x",
        title="t",
        description="d",
        severity=Severity.INFO,
        status="pass",
        domain=CheckDomain.IAM,
        resource_type="X",
        resource_id="r",
        region="eastus",
        account_id="sub",
        cloud_provider=CloudProvider.AZURE,
        cis_azure_controls=["1.1.1"],
        mcsb_controls=["IM-6"],
    )
    assert f.cis_azure_controls == ["1.1.1"]
    assert f.mcsb_controls == ["IM-6"]


def test_azure_client_has_multi_subscription_helpers() -> None:
    from shasta.azure.client import AzureClient

    assert hasattr(AzureClient, "list_subscriptions")
    assert hasattr(AzureClient, "for_subscription")


def test_run_azure_multi_subscription_exists() -> None:
    from shasta.scanner import run_azure_multi_subscription

    sig = inspect.signature(run_azure_multi_subscription)
    assert "azure_client" in sig.parameters
    assert "domains" in sig.parameters
    assert "subscription_ids" in sig.parameters


def test_iam_check_functions_are_callable() -> None:
    from shasta.azure import iam

    expected = [
        "check_legacy_auth_blocked",
        "check_mfa_for_azure_management",
        "check_pim_eligibility",
        "check_classic_administrators",
        "check_custom_role_wildcards",
        "check_guest_invitation_restrictions",
    ]
    for name in expected:
        assert callable(getattr(iam, name)), f"iam.{name} missing or not callable"


def test_encryption_check_functions_are_callable() -> None:
    from shasta.azure import encryption

    expected = [
        "check_sql_auditing",
        "check_sql_entra_admin",
        "check_sql_min_tls",
        "check_keyvault_rbac_mode",
        "check_keyvault_public_access",
        "check_keyvault_key_expiry",
    ]
    for name in expected:
        assert callable(getattr(encryption, name)), f"encryption.{name} missing"


def test_storage_check_functions_are_callable() -> None:
    from shasta.azure import storage

    expected = [
        "_check_shared_key_access",
        "_check_cross_tenant_replication",
        "_check_network_default_deny",
    ]
    for name in expected:
        assert callable(getattr(storage, name)), f"storage.{name} missing"


def test_networking_modern_flow_logs_check_callable() -> None:
    from shasta.azure import networking

    assert callable(getattr(networking, "check_vnet_flow_logs_modern"))
    assert callable(getattr(networking, "check_network_watcher_per_region"))


def test_azure_terraform_templates_registered() -> None:
    """Every Stage 1-3 check that has a TF-amenable fix should have a template."""
    from shasta.remediation.engine import EXPLANATIONS, TERRAFORM_TEMPLATES

    azure_tf = [k for k in TERRAFORM_TEMPLATES if k.startswith("azure-")]
    azure_exp = [k for k in EXPLANATIONS if k.startswith("azure-")]

    assert len(azure_tf) >= 25, (
        f"Expected at least 25 Azure Terraform templates, found {len(azure_tf)}"
    )
    # Every Azure TF template must have a matching explanation
    missing_exp = [k for k in azure_tf if k not in EXPLANATIONS]
    assert not missing_exp, f"Azure TF templates missing EXPLANATIONS: {missing_exp}"

    # And every Azure explanation should have a TF template (or be intentionally TF-less)
    assert len(azure_exp) >= len(azure_tf)


@pytest.mark.parametrize(
    "check_id",
    [
        "azure-storage-shared-key-access",
        "azure-storage-cross-tenant-replication",
        "azure-storage-network-default-deny",
        "azure-keyvault-rbac-mode",
        "azure-keyvault-public-access",
        "azure-sql-min-tls",
        "azure-sql-auditing",
        "azure-sql-entra-admin",
        "azure-postgres-secure-transport",
        "azure-postgres-log-settings",
        "azure-mysql-secure-transport",
        "azure-cosmos-disable-local-auth",
        "azure-appservice-https-only",
        "azure-appservice-managed-identity",
        "azure-rsv-immutability",
        "azure-vnet-flow-logs-modern",
        "azure-defender-per-plan",
        "azure-activity-log-alerts",
        "azure-resource-locks",
        "azure-security-initiative",
    ],
)
def test_azure_terraform_template_renders(check_id: str) -> None:
    """Each Azure template renders to non-empty Terraform when fed a synthetic Finding."""
    from shasta.remediation.engine import TERRAFORM_TEMPLATES

    fn = TERRAFORM_TEMPLATES[check_id]
    f = Finding(
        check_id=check_id,
        title="t",
        description="d",
        severity=Severity.HIGH,
        status="fail",
        domain=CheckDomain.STORAGE,
        resource_type="X",
        resource_id="r",
        region="eastus",
        account_id="sub",
        cloud_provider=CloudProvider.AZURE,
        details={
            "storage_account": "mysa",
            "vault": "mykv",
            "server": "mysrv",
            "app": "myapp",
            "account": "mycos",
            "resource_group": "rg1",
            "missing_regions": ["eastus", "westus"],
            "disabled": [{"plan": "KeyVaults"}],
        },
    )
    out = fn(f)
    assert isinstance(out, str)
    assert out.strip(), f"{check_id} produced empty output"
    assert "azurerm_" in out or "azurerm." in out, (
        f"{check_id} output does not look like azurerm Terraform"
    )
