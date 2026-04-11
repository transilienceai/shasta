"""Integrity tests: verify that every claimed feature actually exists.

These tests catch the "empty stub" problem — where a directory or file
exists but contains no real implementation, yet the README claims it
as a feature. They also verify that documented counts (check counts,
framework control counts, policy counts) match reality.

If any of these tests fail, either the code is missing or the
documentation is wrong. Fix whichever is inaccurate.
"""

from __future__ import annotations

import importlib
import inspect
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# Module existence and non-emptiness
# ---------------------------------------------------------------------------


class TestModulesExistAndHaveCode:
    """Every Whitney subpackage must have real Python files with real functions."""

    @pytest.mark.parametrize(
        "module_path",
        [
            "whitney.code.scanner",
            "whitney.code.checks",
            "whitney.code.patterns",
            "whitney.cloud.aws_checks",
            "whitney.cloud.azure_checks",
            "whitney.discovery.aws_ai",
            "whitney.discovery.azure_ai",
            "whitney.compliance.iso42001",
            "whitney.compliance.eu_ai_act",
            "whitney.compliance.owasp_llm_top10",
            "whitney.compliance.owasp_agentic",
            "whitney.compliance.nist_ai_rmf",
            "whitney.compliance.mitre_atlas",
            "whitney.compliance.mapper",
            "whitney.compliance.scorer",
            "whitney.policies.generator",
            "whitney.sbom.scanner",
        ],
    )
    def test_module_imports_and_has_content(self, module_path):
        """Module must import successfully and contain public members (functions, classes, or data)."""
        mod = importlib.import_module(module_path)
        public_members = [
            name
            for name, obj in inspect.getmembers(mod)
            if not name.startswith("_")
            and not inspect.ismodule(obj)
        ]
        assert len(public_members) >= 1, (
            f"{module_path} imports but has no public members — is it a stub?"
        )


class TestNoEmptyStubDirectories:
    """Every Whitney subdirectory must contain at least one .py file with content beyond __init__.py."""

    @pytest.mark.parametrize(
        "subdir",
        ["code", "cloud", "discovery", "compliance", "policies", "sbom"],
    )
    def test_subdir_has_real_code(self, subdir):
        whitney_root = Path("src/whitney") / subdir
        py_files = [
            f for f in whitney_root.glob("*.py") if f.name != "__init__.py"
        ]
        assert len(py_files) >= 1, (
            f"src/whitney/{subdir}/ has no .py files besides __init__.py — empty stub"
        )
        for py_file in py_files:
            content = py_file.read_text(encoding="utf-8")
            # Must have more than just a docstring — real code (def, class, or data assignments)
            has_code = "def " in content or "class " in content or " = " in content
            assert has_code, (
                f"{py_file} has no functions, classes, or data — empty stub"
            )


# ---------------------------------------------------------------------------
# Claimed counts match reality
# ---------------------------------------------------------------------------


class TestCodeCheckCounts:
    """README claims 20 code checks — verify."""

    def test_all_checks_list_has_20(self):
        from whitney.code.checks import ALL_CHECKS

        assert len(ALL_CHECKS) == 20, (
            f"README claims 20 code checks but ALL_CHECKS has {len(ALL_CHECKS)}"
        )

    def test_each_check_is_callable(self):
        from whitney.code.checks import ALL_CHECKS

        for check_fn in ALL_CHECKS:
            assert callable(check_fn), f"{check_fn} is not callable"

    def test_each_check_returns_list_on_empty_repo(self, tmp_path):
        from whitney.code.checks import ALL_CHECKS

        for check_fn in ALL_CHECKS:
            result = check_fn(tmp_path)
            assert isinstance(result, list), (
                f"{check_fn.__name__} doesn't return a list"
            )


class TestComplianceFrameworkCounts:
    """Verify each framework has the claimed number of items."""

    def test_iso42001_has_11_controls(self):
        from whitney.compliance.iso42001 import ISO42001_CONTROLS

        assert len(ISO42001_CONTROLS) == 11

    def test_eu_ai_act_has_8_obligations(self):
        from whitney.compliance.eu_ai_act import EU_AI_ACT_OBLIGATIONS

        assert len(EU_AI_ACT_OBLIGATIONS) == 8

    def test_owasp_llm_has_10_risks(self):
        from whitney.compliance.owasp_llm_top10 import OWASP_LLM_TOP10

        assert len(OWASP_LLM_TOP10) == 10

    def test_owasp_agentic_has_10_risks(self):
        from whitney.compliance.owasp_agentic import OWASP_AGENTIC_TOP10

        assert len(OWASP_AGENTIC_TOP10) == 10

    def test_nist_ai_rmf_has_19_categories(self):
        from whitney.compliance.nist_ai_rmf import NIST_AI_RMF_CATEGORIES

        assert len(NIST_AI_RMF_CATEGORIES) == 19

    def test_mitre_atlas_has_15_techniques(self):
        from whitney.compliance.mitre_atlas import ATLAS_TECHNIQUES

        assert len(ATLAS_TECHNIQUES) == 15


class TestPolicyCounts:
    """README claims 7 AI governance policies — verify."""

    def test_policies_dict_has_7(self):
        from whitney.policies.generator import POLICIES

        assert len(POLICIES) == 7

    def test_all_policies_render(self):
        from whitney.policies.generator import generate_policy, POLICIES

        for policy_id in POLICIES:
            result = generate_policy(policy_id, company_name="IntegrityTest")
            assert "IntegrityTest" in result, (
                f"Policy {policy_id} didn't render with company name"
            )
            assert len(result) > 100, (
                f"Policy {policy_id} rendered but is suspiciously short ({len(result)} chars)"
            )


class TestSBOMProducesOutput:
    """AI SBOM must produce valid CycloneDX output, not empty stubs."""

    def test_code_scan_produces_cyclonedx(self, tmp_path):
        from tests.test_whitney.conftest import write_file
        from whitney.sbom.scanner import scan_ai_sbom_code_only

        write_file(tmp_path, "requirements.txt", "openai==1.3.0\n")
        result = scan_ai_sbom_code_only(tmp_path)
        assert result["bomFormat"] == "CycloneDX"
        assert result["specVersion"] == "1.5"
        assert len(result["components"]) >= 1


# ---------------------------------------------------------------------------
# Scorer produces all claimed framework scores
# ---------------------------------------------------------------------------


class TestScorerProducesAllFrameworks:
    """The scorer must produce scores for every framework we claim to support."""

    def test_score_has_all_framework_fields(self):
        from whitney.compliance.scorer import calculate_ai_governance_score

        score = calculate_ai_governance_score([])

        # ISO 42001
        assert hasattr(score, "score_percentage")
        assert hasattr(score, "grade")
        # EU AI Act
        assert hasattr(score, "eu_score_percentage")
        assert hasattr(score, "eu_grade")
        # OWASP LLM Top 10
        assert hasattr(score, "owasp_llm_score")
        assert hasattr(score, "owasp_llm_grade")
        # OWASP Agentic AI
        assert hasattr(score, "owasp_agentic_score")
        assert hasattr(score, "owasp_agentic_grade")
        # NIST AI RMF
        assert hasattr(score, "nist_score")
        assert hasattr(score, "nist_grade")
        # MITRE ATLAS
        assert hasattr(score, "atlas_score")
        assert hasattr(score, "atlas_grade")
        # Combined
        assert hasattr(score, "combined_score")
        assert hasattr(score, "combined_grade")


# ---------------------------------------------------------------------------
# Mapper enriches findings with ALL frameworks
# ---------------------------------------------------------------------------


class TestMapperEnrichesAllFrameworks:
    """The mapper must add all 6 framework cross-references to findings."""

    def test_enrichment_adds_all_framework_keys(self):
        from shasta.evidence.models import ComplianceStatus

        from tests.test_whitney.conftest import _make_finding
        from whitney.compliance.mapper import enrich_findings_with_ai_controls

        findings = [
            _make_finding("code-prompt-injection-risk", ComplianceStatus.FAIL)
        ]
        enrich_findings_with_ai_controls(findings)

        details = findings[0].details
        assert "iso42001_controls" in details, "Missing ISO 42001 enrichment"
        assert "eu_ai_act" in details, "Missing EU AI Act enrichment"
        assert "owasp_llm_top10" in details, "Missing OWASP LLM Top 10 enrichment"
        assert "owasp_agentic" in details, "Missing OWASP Agentic enrichment"
        assert "nist_ai_rmf" in details, "Missing NIST AI RMF enrichment"
        assert "mitre_atlas" in details, "Missing MITRE ATLAS enrichment"


# ---------------------------------------------------------------------------
# Cloud check functions exist and are callable
# ---------------------------------------------------------------------------


class TestCloudCheckFunctionsExist:
    """Verify the claimed 15 AWS + 15 Azure check functions actually exist."""

    def test_aws_has_15_checks(self):
        from whitney.cloud import aws_checks

        check_fns = [
            name
            for name, obj in inspect.getmembers(aws_checks)
            if inspect.isfunction(obj) and name.startswith("check_")
        ]
        assert len(check_fns) == 15, (
            f"Claimed 15 AWS checks but found {len(check_fns)}: {check_fns}"
        )

    def test_azure_has_15_checks(self):
        from whitney.cloud import azure_checks

        check_fns = [
            name
            for name, obj in inspect.getmembers(azure_checks)
            if inspect.isfunction(obj) and name.startswith("check_")
        ]
        assert len(check_fns) == 15, (
            f"Claimed 15 Azure checks but found {len(check_fns)}: {check_fns}"
        )
