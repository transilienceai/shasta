"""Tests for OWASP LLM Top 10 v2.0 framework definitions."""

from shasta.compliance.ai.owasp_llm_top10 import (
    OWASP_LLM_TOP10,
    OWASPLLMRisk,
    get_automated_owasp_llm_risks,
    get_owasp_llm_risk,
    get_owasp_llm_risks_for_check,
)


class TestOWASPLLMTop10:
    """Verify the risk definitions are complete."""

    def test_total_risks_count(self):
        assert len(OWASP_LLM_TOP10) == 10

    def test_all_risks_have_required_fields(self):
        for risk_id, risk in OWASP_LLM_TOP10.items():
            assert isinstance(risk, OWASPLLMRisk)
            assert risk.id == risk_id
            assert risk.title
            assert risk.description

    def test_risk_ids_follow_pattern(self):
        for risk_id in OWASP_LLM_TOP10:
            assert risk_id.startswith("LLM")

    def test_all_risks_have_check_ids(self):
        """Every OWASP LLM risk should be covered by at least one check."""
        for risk in OWASP_LLM_TOP10.values():
            assert len(risk.check_ids) >= 1, f"{risk.id} has no check_ids"


class TestGetOWASPLLMRisk:
    def test_lookup_valid_id(self):
        risk = get_owasp_llm_risk("LLM01")
        assert risk is not None
        assert risk.title == "Prompt Injection"

    def test_lookup_invalid_id(self):
        assert get_owasp_llm_risk("LLM99") is None


class TestGetOWASPLLMRisksForCheck:
    def test_prompt_injection_maps_to_llm01(self):
        risks = get_owasp_llm_risks_for_check("code-prompt-injection-risk")
        risk_ids = [r.id for r in risks]
        assert "LLM01" in risk_ids

    def test_api_key_maps_to_llm06_and_llm10(self):
        risks = get_owasp_llm_risks_for_check("code-ai-api-key-exposed")
        risk_ids = [r.id for r in risks]
        assert "LLM06" in risk_ids
        assert "LLM10" in risk_ids

    def test_unknown_check_returns_empty(self):
        assert get_owasp_llm_risks_for_check("nonexistent") == []


class TestGetAutomatedRisks:
    def test_all_risks_are_automated(self):
        automated = get_automated_owasp_llm_risks()
        assert len(automated) == 10  # All 10 have check_ids

    def test_returns_only_automated(self):
        for risk in get_automated_owasp_llm_risks():
            assert len(risk.check_ids) > 0
