"""Tests for Whitney finding-to-control mapping and enrichment."""

from shasta.evidence.models import ComplianceStatus, Severity

from whitney.compliance.mapper import (
    enrich_findings_with_ai_controls,
    get_iso42001_control_summary,
    get_eu_ai_act_obligation_summary,
)
from whitney.compliance.iso42001 import ISO42001_CONTROLS
from whitney.compliance.eu_ai_act import EU_AI_ACT_OBLIGATIONS
from tests.test_whitney.conftest import _make_finding


class TestEnrichFindingsWithAIControls:
    """Test that findings get ISO 42001 and EU AI Act control IDs added."""

    def test_enriches_with_iso42001(self):
        findings = [_make_finding("code-prompt-injection-risk", ComplianceStatus.FAIL)]
        enriched = enrich_findings_with_ai_controls(findings)
        assert "iso42001_controls" in enriched[0].details
        assert "AI-A.8" in enriched[0].details["iso42001_controls"]

    def test_enriches_with_eu_ai_act(self):
        findings = [_make_finding("code-prompt-injection-risk", ComplianceStatus.FAIL)]
        enriched = enrich_findings_with_ai_controls(findings)
        assert "eu_ai_act" in enriched[0].details
        assert "EUAI-15" in enriched[0].details["eu_ai_act"]

    def test_unknown_check_gets_empty_lists(self):
        findings = [_make_finding("nonexistent-check", ComplianceStatus.PASS)]
        enriched = enrich_findings_with_ai_controls(findings)
        assert enriched[0].details["iso42001_controls"] == []
        assert enriched[0].details["eu_ai_act"] == []

    def test_mutates_in_place(self):
        findings = [_make_finding("code-pii-in-prompts", ComplianceStatus.FAIL)]
        result = enrich_findings_with_ai_controls(findings)
        assert result is findings  # same list reference

    def test_multiple_findings(self):
        findings = [
            _make_finding("code-prompt-injection-risk", ComplianceStatus.FAIL),
            _make_finding("code-pii-in-prompts", ComplianceStatus.FAIL),
            _make_finding("code-ai-logging-insufficient", ComplianceStatus.PASS),
        ]
        enriched = enrich_findings_with_ai_controls(findings)
        for f in enriched:
            assert "iso42001_controls" in f.details
            assert "eu_ai_act" in f.details


class TestGetISO42001ControlSummary:
    """Test ISO 42001 control summary aggregation."""

    def test_all_controls_present(self):
        summary = get_iso42001_control_summary([])
        assert len(summary) == len(ISO42001_CONTROLS)
        for ctrl_id in ISO42001_CONTROLS:
            assert ctrl_id in summary

    def test_default_status_not_assessed(self):
        summary = get_iso42001_control_summary([])
        for ctrl_id, data in summary.items():
            ctrl = ISO42001_CONTROLS[ctrl_id]
            if ctrl.requires_policy and not ctrl.check_ids:
                assert data["overall_status"] == "requires_policy"
            else:
                assert data["overall_status"] == "not_assessed"

    def test_pass_finding_sets_pass(self):
        findings = [_make_finding("code-prompt-injection-risk", ComplianceStatus.PASS)]
        summary = get_iso42001_control_summary(findings)
        assert summary["AI-A.8"]["overall_status"] == "pass"
        assert summary["AI-A.8"]["pass_count"] == 1

    def test_fail_overrides_pass(self):
        findings = [
            _make_finding("code-prompt-injection-risk", ComplianceStatus.PASS),
            _make_finding("code-ai-api-key-exposed", ComplianceStatus.FAIL),
        ]
        summary = get_iso42001_control_summary(findings)
        # Both map to AI-A.8 — fail overrides pass
        assert summary["AI-A.8"]["overall_status"] == "fail"
        assert summary["AI-A.8"]["fail_count"] == 1
        assert summary["AI-A.8"]["pass_count"] == 1

    def test_partial_status(self):
        findings = [_make_finding("code-prompt-injection-risk", ComplianceStatus.PARTIAL)]
        summary = get_iso42001_control_summary(findings)
        assert summary["AI-A.8"]["overall_status"] == "partial"
        assert summary["AI-A.8"]["partial_count"] == 1

    def test_summary_has_all_fields(self):
        summary = get_iso42001_control_summary([])
        for data in summary.values():
            assert "id" in data
            assert "title" in data
            assert "clause" in data
            assert "guidance" in data
            assert "requires_policy" in data
            assert "has_automated_checks" in data
            assert "findings" in data
            assert "pass_count" in data
            assert "fail_count" in data
            assert "partial_count" in data
            assert "overall_status" in data


class TestGetEUAIActObligationSummary:
    """Test EU AI Act obligation summary aggregation."""

    def test_all_obligations_present(self):
        summary = get_eu_ai_act_obligation_summary([])
        assert len(summary) == len(EU_AI_ACT_OBLIGATIONS)
        for obl_id in EU_AI_ACT_OBLIGATIONS:
            assert obl_id in summary

    def test_default_status_not_assessed(self):
        summary = get_eu_ai_act_obligation_summary([])
        for obl_id, data in summary.items():
            obl = EU_AI_ACT_OBLIGATIONS[obl_id]
            if obl.requires_policy and not obl.check_ids:
                assert data["overall_status"] == "requires_policy"
            else:
                assert data["overall_status"] == "not_assessed"

    def test_pass_finding_sets_pass(self):
        findings = [_make_finding("code-prompt-injection-risk", ComplianceStatus.PASS)]
        summary = get_eu_ai_act_obligation_summary(findings)
        assert summary["EUAI-15"]["overall_status"] == "pass"

    def test_fail_finding_sets_fail(self):
        findings = [_make_finding("code-prompt-injection-risk", ComplianceStatus.FAIL)]
        summary = get_eu_ai_act_obligation_summary(findings)
        assert summary["EUAI-15"]["overall_status"] == "fail"

    def test_summary_has_article_field(self):
        summary = get_eu_ai_act_obligation_summary([])
        for data in summary.values():
            assert "article" in data
            assert "risk_level" in data
