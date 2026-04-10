"""Smoke tests for the Stage 1-3 AWS parity sweep.

Verifies that the new AWS modules import cleanly, expose the expected
public runners, that the Finding model carries the new cis_aws_controls
field, and that the new AWS Terraform templates render to non-empty
azurerm-style snippets when fed a synthetic Finding.
"""

from __future__ import annotations

import importlib
import inspect

import pytest

from shasta.evidence.models import (
    CheckDomain,
    CloudProvider,
    Finding,
    Severity,
)


NEW_AWS_MODULES = [
    "shasta.aws.databases",
    "shasta.aws.serverless",
    "shasta.aws.backup",
    "shasta.aws.vpc_endpoints",
    "shasta.aws.cloudwatch_logs",
    "shasta.aws.organizations",
    "shasta.aws.compute",
    "shasta.aws.kms",
    "shasta.aws.cloudfront",
    "shasta.aws.data_warehouse",
]

EXPECTED_RUNNERS = {
    "shasta.aws.databases": "run_all_aws_database_checks",
    "shasta.aws.serverless": "run_all_aws_serverless_checks",
    "shasta.aws.backup": "run_all_aws_backup_checks",
    "shasta.aws.vpc_endpoints": "run_all_aws_vpc_endpoint_checks",
    "shasta.aws.cloudwatch_logs": "run_all_aws_cloudwatch_log_checks",
    "shasta.aws.organizations": "run_all_aws_organizations_checks",
    "shasta.aws.compute": "run_all_aws_compute_checks",
    "shasta.aws.kms": "run_all_aws_kms_checks",
    "shasta.aws.cloudfront": "run_all_aws_cloudfront_checks",
    "shasta.aws.data_warehouse": "run_all_aws_data_warehouse_checks",
}

# Modules that are intentionally GLOBAL — no per-region iteration. The
# multi-region structural smoke test below skips these. CloudFront is
# global. Organizations is global. IAM is also global but lives in
# src/shasta/aws/iam.py which is wired through the main scanner path,
# not _run_aws_extras.
GLOBAL_AWS_MODULES = {
    "shasta.aws.organizations",
    "shasta.aws.cloudfront",
}


@pytest.mark.parametrize("mod_name", NEW_AWS_MODULES)
def test_module_imports(mod_name: str) -> None:
    importlib.import_module(mod_name)


@pytest.mark.parametrize("mod_name,runner_name", list(EXPECTED_RUNNERS.items()))
def test_runner_exists_and_takes_client(mod_name: str, runner_name: str) -> None:
    mod = importlib.import_module(mod_name)
    runner = getattr(mod, runner_name)
    sig = inspect.signature(runner)
    params = list(sig.parameters)
    assert params, f"{runner_name} should accept at least one positional argument (client)"
    assert params[0] == "client"


@pytest.mark.parametrize("mod_name,runner_name", list(EXPECTED_RUNNERS.items()))
def test_runner_iterates_regions_unless_global(mod_name: str, runner_name: str) -> None:
    """Engineering Principle #3: every regional runner must iterate enabled regions.

    Skips modules in GLOBAL_AWS_MODULES (organizations, IAM, CloudFront) and
    modules with module-level IS_GLOBAL = True. The check inspects the
    runner's source for client.get_enabled_regions() + client.for_region(.
    """
    if mod_name in GLOBAL_AWS_MODULES:
        return
    mod = importlib.import_module(mod_name)
    if getattr(mod, "IS_GLOBAL", False):
        return
    runner = getattr(mod, runner_name)
    src = inspect.getsource(runner)
    assert "get_enabled_regions" in src, (
        f"{runner_name} must call client.get_enabled_regions() — see Engineering Principle #3 "
        f"in ENGINEERING_PRINCIPLES.md. If this module is intentionally global, set "
        f"IS_GLOBAL = True at the module level."
    )
    assert "for_region" in src, (
        f"{runner_name} must use client.for_region(r) inside the loop — see Engineering "
        f"Principle #3 in ENGINEERING_PRINCIPLES.md."
    )


def test_finding_model_has_cis_aws_field() -> None:
    f = Finding(
        check_id="x",
        title="t",
        description="d",
        severity=Severity.INFO,
        status="pass",
        domain=CheckDomain.IAM,
        resource_type="X",
        resource_id="r",
        region="us-east-1",
        account_id="123456789012",
        cloud_provider=CloudProvider.AWS,
        cis_aws_controls=["1.20", "3.5"],
    )
    assert f.cis_aws_controls == ["1.20", "3.5"]


def test_lambda_eol_runtimes_table_is_current() -> None:
    """The deprecated runtimes table should include known-EOL runtimes for 2026."""
    from shasta.aws.serverless import DEPRECATED_LAMBDA_RUNTIMES

    for r in ("python3.7", "python3.8", "nodejs14.x", "nodejs16.x", "go1.x"):
        assert r in DEPRECATED_LAMBDA_RUNTIMES, f"{r} should be flagged as deprecated"


def test_vpc_endpoint_expectations_table() -> None:
    """The VPC endpoint walker must cover the high-leverage services."""
    from shasta.aws.vpc_endpoints import EXPECTED_VPC_ENDPOINTS

    for svc in ("s3", "dynamodb", "kms", "secretsmanager"):
        assert svc in EXPECTED_VPC_ENDPOINTS, f"{svc} should be in the expected endpoints table"


def test_aws_terraform_templates_registered() -> None:
    from shasta.remediation.engine import EXPLANATIONS, TERRAFORM_TEMPLATES

    aws_tf = [k for k in TERRAFORM_TEMPLATES if not k.startswith("azure-")]
    # After Stage 2 of the parity sweep, we expect at least 75 AWS templates
    assert len(aws_tf) >= 75, f"Expected >=75 AWS Terraform templates, found {len(aws_tf)}"

    missing_exp = [k for k in aws_tf if k not in EXPLANATIONS]
    assert not missing_exp, f"AWS TF templates missing EXPLANATIONS: {missing_exp}"


def test_cloudfront_module_is_global() -> None:
    """CloudFront is a global service — module must declare IS_GLOBAL = True."""
    from shasta.aws.cloudfront import IS_GLOBAL

    assert IS_GLOBAL is True


def test_data_warehouse_module_is_regional() -> None:
    from shasta.aws.data_warehouse import IS_GLOBAL

    assert IS_GLOBAL is False


def test_compute_module_constants_exist() -> None:
    """compute.py should expose module-level constants for the audit + smoke tests."""
    from shasta.aws.compute import AMI_AGE_DAYS_THRESHOLD, IS_GLOBAL

    assert IS_GLOBAL is False
    assert AMI_AGE_DAYS_THRESHOLD >= 30


def test_kms_module_is_regional() -> None:
    from shasta.aws.kms import IS_GLOBAL

    assert IS_GLOBAL is False


def test_cloudwatch_cis_4_x_table_complete() -> None:
    """The CIS 4.x event table should cover sections 4.1 through 4.15."""
    from shasta.aws.logging_checks import CLOUDWATCH_CIS_4_X_EVENTS

    cis_ids = {entry[0] for entry in CLOUDWATCH_CIS_4_X_EVENTS}
    for section in [f"4.{i}" for i in range(1, 16)]:
        assert section in cis_ids, f"CIS {section} missing from CLOUDWATCH_CIS_4_X_EVENTS"


@pytest.mark.parametrize(
    "check_id",
    [
        "cloudtrail-kms-encryption",
        "cloudtrail-log-validation",
        "cloudtrail-s3-object-lock",
        "security-hub-enabled",
        "iam-access-analyzer",
        "efs-encryption",
        "sns-encryption",
        "sqs-encryption",
        "secrets-manager-rotation",
        "elb-listener-tls",
        "elb-access-logs",
        "elb-drop-invalid-headers",
        "rds-iam-auth",
        "rds-deletion-protection",
        "dynamodb-pitr",
        "dynamodb-kms",
        "lambda-runtime-eol",
        "lambda-dlq",
        "apigw-waf",
        "aws-backup-vault-lock",
        "aws-vpc-endpoints",
        "cwl-kms-encryption",
        "aws-org-scps",
        # Stage 1 of the parity sweep
        "ec2-imdsv2-enforced",
        "ec2-instance-profile",
        "eks-private-endpoint",
        "eks-audit-logging",
        "eks-secrets-encryption",
        "ecs-task-privileged",
        "ecs-task-root-user",
        "kms-key-rotation",
        "kms-key-policy-wildcards",
        "iam-policy-wildcards",
        "iam-role-trust-external",
        "cloudwatch-alarms-cis-4",
        "aws-config-conformance-packs",
        # Stage 2 of the parity sweep
        "cloudfront-https-only",
        "cloudfront-min-tls",
        "cloudfront-waf",
        "cloudfront-oac",
        "redshift-encryption",
        "redshift-public-access",
        "redshift-audit-logging",
        "elasticache-transit-encryption",
        "elasticache-at-rest-encryption",
        "elasticache-auth-token",
        "neptune-encryption",
        "rds-force-ssl",
        "rds-postgres-log-settings",
        "lambda-function-url-auth",
        "lambda-layer-origin",
        "apigw-client-cert",
        "apigw-authorizer",
        "apigw-throttling",
        "apigw-request-validation",
        "s3-object-ownership",
        "s3-access-logging",
        "s3-kms-cmk",
        "aws-backup-cross-region-copy",
        "aws-backup-vault-access-policy",
    ],
)
def test_aws_terraform_template_renders(check_id: str) -> None:
    from shasta.remediation.engine import TERRAFORM_TEMPLATES

    fn = TERRAFORM_TEMPLATES[check_id]
    f = Finding(
        check_id=check_id,
        title="t",
        description="d",
        severity=Severity.HIGH,
        status="fail",
        domain=CheckDomain.MONITORING,
        resource_type="X",
        resource_id="r",
        region="us-east-1",
        account_id="123456789012",
        cloud_provider=CloudProvider.AWS,
        details={
            "trail": "main",
            "bucket": "cloudtrail-logs",
            "vault": "primary",
            "db": "mydb",
            "file_system_id": "fs-abc",
            "deprecated": [{"name": "fn1", "runtime": "python3.7"}],
        },
    )
    out = fn(f)
    assert isinstance(out, str)
    assert out.strip(), f"{check_id} produced empty output"
    assert "aws_" in out or "resource" in out, f"{check_id} doesn't look like aws Terraform"
