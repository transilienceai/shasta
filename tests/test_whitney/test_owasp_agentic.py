"""Tests for OWASP Agentic AI Top 10 framework definitions."""

from shasta.compliance.ai.owasp_agentic import (
    OWASP_AGENTIC_TOP10,
    OWASPAgenticRisk,
    get_automated_owasp_agentic_risks,
    get_owasp_agentic_risk,
    get_owasp_agentic_risks_for_check,
)


class TestOWASPAgenticTop10:
    def test_total_risks_count(self):
        assert len(OWASP_AGENTIC_TOP10) == 10

    def test_all_risks_have_required_fields(self):
        for risk_id, risk in OWASP_AGENTIC_TOP10.items():
            assert isinstance(risk, OWASPAgenticRisk)
            assert risk.id == risk_id
            assert risk.title
            assert risk.description

    def test_risk_ids_follow_pattern(self):
        for risk_id in OWASP_AGENTIC_TOP10:
            assert risk_id.startswith("AGENTIC")


class TestGetOWASPAgenticRisk:
    def test_lookup_valid_id(self):
        risk = get_owasp_agentic_risk("AGENTIC01")
        assert risk is not None
        assert risk.title == "Excessive Agency and Autonomy"

    def test_lookup_invalid_id(self):
        assert get_owasp_agentic_risk("AGENTIC99") is None


class TestGetOWASPAgenticRisksForCheck:
    def test_agent_tools_maps_to_agentic01_and_02(self):
        risks = get_owasp_agentic_risks_for_check("code-agent-unrestricted-tools")
        risk_ids = [r.id for r in risks]
        assert "AGENTIC01" in risk_ids
        assert "AGENTIC02" in risk_ids

    def test_logging_maps_to_agentic05(self):
        risks = get_owasp_agentic_risks_for_check("code-ai-logging-insufficient")
        risk_ids = [r.id for r in risks]
        assert "AGENTIC05" in risk_ids

    def test_unknown_check_returns_empty(self):
        assert get_owasp_agentic_risks_for_check("nonexistent") == []


class TestGetAutomatedRisks:
    def test_returns_only_automated(self):
        automated = get_automated_owasp_agentic_risks()
        assert len(automated) >= 7  # Some risks have future check_ids
        for risk in automated:
            assert len(risk.check_ids) > 0

    def test_mcp_risks_exist_but_have_future_checks(self):
        """AGENTIC03 (MCP) and AGENTIC06 (multi-agent) are defined but have no checks yet."""
        mcp = get_owasp_agentic_risk("AGENTIC03")
        assert mcp is not None
        assert mcp.title == "Insecure MCP Server Configuration"
