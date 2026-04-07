"""End-to-end validation of Whitney against the vuln-ai-app target.

Proves that Whitney actually works by scanning a deliberately vulnerable
AI application and verifying all expected findings are produced.

Usage:
    py -3.12 -m pytest tests/integration/validate_whitney.py -v

Requires:
    vuln-ai-app repo at E:/Projects/vuln-ai-app
"""

from __future__ import annotations

from pathlib import Path

import pytest

VULN_APP_PATH = Path("E:/Projects/vuln-ai-app")

# Skip all tests if vuln-ai-app doesn't exist
pytestmark = pytest.mark.skipif(
    not VULN_APP_PATH.is_dir(),
    reason="vuln-ai-app not found at E:/Projects/vuln-ai-app",
)

# All 15 check IDs that should fire
ALL_CODE_CHECK_IDS = {
    "code-ai-api-key-exposed",
    "code-ai-key-in-env-file",
    "code-prompt-injection-risk",
    "code-no-output-validation",
    "code-pii-in-prompts",
    "code-model-endpoint-public",
    "code-agent-unrestricted-tools",
    "code-rag-no-access-control",
    "code-no-rate-limiting",
    "code-meta-prompt-exposed",
    "code-ai-logging-insufficient",
    "code-outdated-ai-sdk",
    "code-training-data-unencrypted",
    "code-no-model-versioning",
    "code-no-fallback-handler",
}


# ---------------------------------------------------------------------------
# Code Scanning Validation
# ---------------------------------------------------------------------------


class TestCodeScanValidation:
    """Validate Whitney's code scanner against vuln-ai-app."""

    @pytest.fixture(autouse=True)
    def scan(self):
        from whitney.code.scanner import scan_repository

        self.findings = scan_repository(VULN_APP_PATH)
        self.check_ids = {f.check_id for f in self.findings}

    def test_all_15_checks_triggered(self):
        """Every Whitney code check should fire against vuln-ai-app."""
        missing = ALL_CODE_CHECK_IDS - self.check_ids
        assert not missing, f"Checks not triggered: {missing}"

    def test_minimum_findings_count(self):
        """Should find at least 15 issues (one per check minimum)."""
        assert len(self.findings) >= 15

    def test_critical_findings_present(self):
        assert "code-ai-api-key-exposed" in self.check_ids
        assert "code-ai-key-in-env-file" in self.check_ids

    def test_high_findings_present(self):
        assert "code-prompt-injection-risk" in self.check_ids
        assert "code-no-output-validation" in self.check_ids
        assert "code-pii-in-prompts" in self.check_ids
        assert "code-model-endpoint-public" in self.check_ids
        assert "code-agent-unrestricted-tools" in self.check_ids

    def test_findings_have_file_paths(self):
        """Every finding should reference a specific file."""
        for f in self.findings:
            assert "file_path" in f.details
            assert f.details["file_path"]

    def test_findings_have_line_numbers(self):
        """Every finding should reference a specific line."""
        for f in self.findings:
            assert "line_number" in f.details
            assert f.details["line_number"] > 0

    def test_findings_have_code_snippets(self):
        """Every finding should include a code snippet."""
        for f in self.findings:
            assert "code_snippet" in f.details
            assert f.details["code_snippet"]

    def test_findings_have_remediation(self):
        """Every finding should include remediation guidance."""
        for f in self.findings:
            assert f.remediation


# ---------------------------------------------------------------------------
# AI SBOM Validation
# ---------------------------------------------------------------------------


class TestAISBOMValidation:
    """Validate Whitney's AI SBOM against vuln-ai-app."""

    @pytest.fixture(autouse=True)
    def scan(self):
        from whitney.sbom.scanner import scan_ai_sbom_code_only

        self.sbom = scan_ai_sbom_code_only(VULN_APP_PATH)

    def test_cyclonedx_format(self):
        assert self.sbom["bomFormat"] == "CycloneDX"
        assert self.sbom["specVersion"] == "1.5"

    def test_discovers_ai_sdks(self):
        sdk_names = {
            c["name"]
            for c in self.sbom["components"]
            if any(p["value"] == "sdk" for p in c["properties"] if p["name"] == "shasta:component_type")
        }
        assert "openai" in sdk_names
        assert "langchain" in sdk_names
        assert "anthropic" in sdk_names

    def test_discovers_models(self):
        model_names = {
            c["name"]
            for c in self.sbom["components"]
            if any(
                p["value"] == "model" for p in c["properties"] if p["name"] == "shasta:component_type"
            )
        }
        assert "gpt-4" in model_names

    def test_finds_vulnerabilities(self):
        assert len(self.sbom["vulnerabilities"]) >= 1
        cves = {v["id"] for v in self.sbom["vulnerabilities"]}
        assert "CVE-2023-46229" in cves  # langchain

    def test_components_have_purls(self):
        for c in self.sbom["components"]:
            assert c["purl"], f"Component {c['name']} missing PURL"


# ---------------------------------------------------------------------------
# Compliance Scoring Validation
# ---------------------------------------------------------------------------


class TestComplianceScoringValidation:
    """Validate end-to-end compliance scoring pipeline."""

    @pytest.fixture(autouse=True)
    def scan_and_score(self):
        from whitney.code.scanner import scan_repository
        from whitney.compliance.mapper import enrich_findings_with_ai_controls
        from whitney.compliance.scorer import calculate_ai_governance_score

        self.findings = scan_repository(VULN_APP_PATH)
        enrich_findings_with_ai_controls(self.findings)
        self.score = calculate_ai_governance_score(self.findings)

    def test_iso42001_score_is_f(self):
        """Vuln app should get an F on ISO 42001."""
        assert self.score.grade == "F"
        assert self.score.score_percentage == 0.0

    def test_eu_ai_act_score_is_f(self):
        """Vuln app should get an F on EU AI Act."""
        assert self.score.eu_grade == "F"
        assert self.score.eu_score_percentage == 0.0

    def test_combined_score_is_f(self):
        assert self.score.combined_grade == "F"

    def test_iso_controls_mostly_failing(self):
        assert self.score.failing >= 4

    def test_policy_required_controls_identified(self):
        assert self.score.requires_policy >= 3
        assert self.score.eu_requires_policy >= 3

    def test_findings_enriched_with_controls(self):
        """Findings should have ISO 42001 and EU AI Act mappings."""
        enriched = [f for f in self.findings if f.details.get("iso42001_controls")]
        assert len(enriched) >= 5


# ---------------------------------------------------------------------------
# Policy Generation Validation
# ---------------------------------------------------------------------------


class TestPolicyGenerationValidation:
    """Validate AI policy generation."""

    def test_generates_all_7_policies(self, tmp_path):
        from whitney.policies.generator import generate_all_policies

        paths = generate_all_policies(company_name="TestCorp", output_path=tmp_path)
        assert len(paths) == 7
        for p in paths:
            assert p.exists()
            content = p.read_text(encoding="utf-8")
            assert "TestCorp" in content
            assert content.startswith("# ")

    def test_list_policies_metadata(self):
        from whitney.policies.generator import list_policies

        policies = list_policies()
        assert len(policies) == 7
        all_controls = set()
        for p in policies:
            all_controls.update(p["controls"])
        # Verify all requires_policy controls are covered
        assert "AI-5.2" in all_controls
        assert "AI-6.1" in all_controls
        assert "AI-8.2" in all_controls
        assert "AI-A.2" in all_controls
        assert "EUAI-9" in all_controls
        assert "EUAI-11" in all_controls
        assert "EUAI-14" in all_controls
        assert "EUAI-52" in all_controls
