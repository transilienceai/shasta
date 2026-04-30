"""Smoke tests for GCP modules.

These tests do NOT hit GCP. They verify that:
1. Every check module imports cleanly.
2. Every public ``run_all_*`` runner exists and accepts a client argument.
3. Multi-project helpers exist on GCPClient.
4. All GCP Terraform templates render to non-empty output.
"""

from __future__ import annotations

import importlib
import inspect

import pytest

from shasta.evidence.models import CheckDomain, CloudProvider, Finding, Severity


GCP_MODULES = [
    "shasta.gcp.iam",
    "shasta.gcp.networking",
    "shasta.gcp.storage",
    "shasta.gcp.encryption",
    "shasta.gcp.logging_checks",
    "shasta.gcp.compute",
    "shasta.gcp.cloud_run",
]

EXPECTED_RUNNERS = {
    "shasta.gcp.iam": "run_all_gcp_iam_checks",
    "shasta.gcp.networking": "run_all_gcp_networking_checks",
    "shasta.gcp.storage": "run_all_gcp_storage_checks",
    "shasta.gcp.encryption": "run_all_gcp_encryption_checks",
    "shasta.gcp.logging_checks": "run_all_gcp_logging_checks",
    "shasta.gcp.compute": "run_all_gcp_compute_checks",
    "shasta.gcp.cloud_run": "run_all_gcp_cloud_run_checks",
}

GLOBAL_MODULES = {
    "shasta.gcp.iam",
    "shasta.gcp.storage",
    "shasta.gcp.encryption",
    "shasta.gcp.logging_checks",
}

REGIONAL_MODULES = {
    "shasta.gcp.networking",
    "shasta.gcp.compute",
    "shasta.gcp.cloud_run",
}


@pytest.mark.parametrize("mod_name", GCP_MODULES)
def test_module_imports(mod_name: str) -> None:
    importlib.import_module(mod_name)


@pytest.mark.parametrize("mod_name,runner_name", list(EXPECTED_RUNNERS.items()))
def test_runner_exists_and_takes_client(mod_name: str, runner_name: str) -> None:
    mod = importlib.import_module(mod_name)
    runner = getattr(mod, runner_name)
    sig = inspect.signature(runner)
    params = list(sig.parameters)
    assert params, f"{runner_name} should accept at least one positional argument (client)"
    assert params[0] in ("client", "gcp_client")


@pytest.mark.parametrize("mod_name", GLOBAL_MODULES)
def test_global_module_flag(mod_name: str) -> None:
    mod = importlib.import_module(mod_name)
    assert hasattr(mod, "IS_GLOBAL"), f"{mod_name} should declare IS_GLOBAL"
    assert mod.IS_GLOBAL is True, f"{mod_name} should be IS_GLOBAL=True"


@pytest.mark.parametrize("mod_name", REGIONAL_MODULES)
def test_regional_module_flag(mod_name: str) -> None:
    mod = importlib.import_module(mod_name)
    assert hasattr(mod, "IS_GLOBAL"), f"{mod_name} should declare IS_GLOBAL"
    assert mod.IS_GLOBAL is False, f"{mod_name} should be IS_GLOBAL=False"


def test_scanner_gcp_integration() -> None:
    """scanner.py exposes _run_gcp_checks and run_gcp_multi_project."""
    from shasta import scanner

    assert callable(getattr(scanner, "_run_gcp_checks", None))
    assert callable(getattr(scanner, "run_gcp_multi_project", None))


def test_run_gcp_checks_returns_list(mock_gcp_client) -> None:
    """_run_gcp_checks returns a list (possibly empty) without raising."""
    from unittest.mock import patch

    from shasta.scanner import _run_gcp_checks

    # Patch all runners to return empty lists to avoid needing live GCP SDK
    with (
        patch("shasta.gcp.iam.run_all_gcp_iam_checks", return_value=[]),
        patch("shasta.gcp.networking.run_all_gcp_networking_checks", return_value=[]),
        patch("shasta.gcp.storage.run_all_gcp_storage_checks", return_value=[]),
        patch("shasta.gcp.encryption.run_all_gcp_encryption_checks", return_value=[]),
        patch("shasta.gcp.logging_checks.run_all_gcp_logging_checks", return_value=[]),
        patch("shasta.gcp.compute.run_all_gcp_compute_checks", return_value=[]),
        patch("shasta.gcp.cloud_run.run_all_gcp_cloud_run_checks", return_value=[]),
    ):
        findings = _run_gcp_checks(mock_gcp_client, list(CheckDomain))
    assert isinstance(findings, list)


def test_run_gcp_multi_project(mock_gcp_client) -> None:
    """run_gcp_multi_project iterates provided project_ids."""
    from unittest.mock import patch

    from shasta.scanner import run_gcp_multi_project

    mock_gcp_client.list_projects.return_value = [
        {"project_id": "proj-a"},
        {"project_id": "proj-b"},
    ]
    mock_gcp_client.validate_credentials.return_value = None

    with patch("shasta.scanner._run_gcp_checks", return_value=[]) as mock_run:
        results = run_gcp_multi_project(
            mock_gcp_client, [CheckDomain.IAM], ["proj-a", "proj-b"]
        )
    assert isinstance(results, list)
    assert mock_run.call_count == 2


def test_gcp_cloud_provider_enum() -> None:
    from shasta.evidence.models import CloudProvider

    assert CloudProvider.GCP == "gcp"


def test_gcp_finding_has_cis_gcp_controls_field() -> None:
    f = Finding(
        check_id="gcp-iam-test",
        title="t",
        description="d",
        severity=Severity.HIGH,
        status="pass",
        domain=CheckDomain.IAM,
        resource_type="ServiceAccount",
        resource_id="sa@proj.iam.gserviceaccount.com",
        region="global",
        account_id="test-project",
        cloud_provider=CloudProvider.GCP,
        cis_gcp_controls=["1.4", "1.5"],
    )
    assert f.cis_gcp_controls == ["1.4", "1.5"]


@pytest.mark.parametrize(
    "check_id",
    [
        "gcp-iam-primitive-roles",
        "gcp-iam-service-account-not-admin",
        "gcp-firewall-unrestricted-ssh",
        "gcp-firewall-unrestricted-rdp",
        "gcp-vpc-flow-logs",
        "gcp-kms-key-rotation",
        "gcp-storage-bucket-public-access",
        "gcp-storage-uniform-access",
        "gcp-logging-audit-config",
        "gcp-logging-metric-alerting",
        "gcp-compute-os-login",
        "gcp-compute-serial-port",
        "gcp-sql-require-ssl",
        "gcp-gke-workload-identity",
        "gcp-gke-private-cluster",
        "gcp-cloudrun-no-unauth-access",
        "gcp-cloudrun-no-default-sa",
        "gcp-cloudrun-ingress-restricted",
        "gcp-cloudrun-binary-authorization",
        "gcp-cloudrun-no-plaintext-secrets",
    ],
)
def test_gcp_terraform_template_renders(check_id: str) -> None:
    """Each GCP template renders to non-empty Terraform when fed a synthetic Finding."""
    from shasta.remediation.engine import TERRAFORM_TEMPLATES

    assert check_id in TERRAFORM_TEMPLATES, f"{check_id} not in TERRAFORM_TEMPLATES"

    fn = TERRAFORM_TEMPLATES[check_id]
    f = Finding(
        check_id=check_id,
        title="t",
        description="d",
        severity=Severity.HIGH,
        status="fail",
        domain=CheckDomain.IAM,
        resource_type="Project",
        resource_id="test-project",
        region="global",
        account_id="test-project",
        cloud_provider=CloudProvider.GCP,
        details={
            "project_id": "test-project",
            "bucket": "my-bucket",
            "keyring": "my-keyring",
            "key": "my-key",
            "location": "global",
            "cluster": "my-cluster",
            "instance": "my-sql-instance",
        },
    )
    out = fn(f)
    assert isinstance(out, str)
    assert out.strip(), f"{check_id} produced empty output"
    assert "google_" in out, f"{check_id} output does not look like google Terraform"


@pytest.mark.parametrize(
    "check_id",
    [
        "gcp-iam-primitive-roles",
        "gcp-iam-service-account-not-admin",
        "gcp-firewall-unrestricted-ssh",
        "gcp-firewall-unrestricted-rdp",
        "gcp-vpc-flow-logs",
        "gcp-kms-key-rotation",
        "gcp-storage-bucket-public-access",
        "gcp-storage-uniform-access",
        "gcp-logging-audit-config",
        "gcp-logging-metric-alerting",
        "gcp-compute-os-login",
        "gcp-compute-serial-port",
        "gcp-sql-require-ssl",
        "gcp-gke-workload-identity",
        "gcp-gke-private-cluster",
        "gcp-cloudrun-no-unauth-access",
        "gcp-cloudrun-no-default-sa",
        "gcp-cloudrun-ingress-restricted",
        "gcp-cloudrun-binary-authorization",
        "gcp-cloudrun-no-plaintext-secrets",
    ],
)
def test_gcp_explanation_exists(check_id: str) -> None:
    """Every GCP template check ID must have an explanation entry."""
    from shasta.remediation.engine import EXPLANATIONS

    assert check_id in EXPLANATIONS, f"{check_id} missing from EXPLANATIONS"
    entry = EXPLANATIONS[check_id]
    assert entry.get("explanation"), f"{check_id} has empty explanation"
    assert entry.get("steps"), f"{check_id} has no remediation steps"
