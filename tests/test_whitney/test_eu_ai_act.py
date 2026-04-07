"""Tests for EU AI Act obligation framework definitions."""

from whitney.compliance.eu_ai_act import (
    EU_AI_ACT_OBLIGATIONS,
    EUAIActObligation,
    get_eu_ai_act_obligation,
    get_eu_ai_act_obligations_for_check,
    get_automated_eu_ai_act_obligations,
    get_policy_required_eu_ai_act_obligations,
)


class TestEUAIActObligations:
    """Verify the obligation definitions are complete and well-formed."""

    def test_total_obligations_count(self):
        assert len(EU_AI_ACT_OBLIGATIONS) == 8

    def test_all_obligations_have_required_fields(self):
        for obl_id, obl in EU_AI_ACT_OBLIGATIONS.items():
            assert isinstance(obl, EUAIActObligation)
            assert obl.id == obl_id
            assert obl.title
            assert obl.description
            assert obl.article
            assert obl.risk_level in ("high", "limited", "minimal")

    def test_obligation_ids_follow_pattern(self):
        for obl_id in EU_AI_ACT_OBLIGATIONS:
            assert obl_id.startswith("EUAI-")

    def test_high_risk_obligations(self):
        high_risk = [o for o in EU_AI_ACT_OBLIGATIONS.values() if o.risk_level == "high"]
        assert len(high_risk) >= 7  # Articles 9-15

    def test_limited_risk_obligations(self):
        limited = [o for o in EU_AI_ACT_OBLIGATIONS.values() if o.risk_level == "limited"]
        assert len(limited) >= 1  # Article 52


class TestGetEUAIActObligation:
    """Test single obligation lookup."""

    def test_lookup_valid_id(self):
        obl = get_eu_ai_act_obligation("EUAI-9")
        assert obl is not None
        assert obl.title == "Risk Management System"
        assert obl.article == "Art. 9"

    def test_lookup_invalid_id(self):
        assert get_eu_ai_act_obligation("EUAI-99") is None

    def test_lookup_all_ids(self):
        for obl_id in EU_AI_ACT_OBLIGATIONS:
            assert get_eu_ai_act_obligation(obl_id) is not None


class TestGetEUAIActObligationsForCheck:
    """Test check_id to obligation mapping."""

    def test_known_check_maps_to_obligation(self):
        obligations = get_eu_ai_act_obligations_for_check("code-prompt-injection-risk")
        assert len(obligations) >= 1
        obl_ids = [o.id for o in obligations]
        assert "EUAI-15" in obl_ids

    def test_unknown_check_returns_empty(self):
        obligations = get_eu_ai_act_obligations_for_check("nonexistent-check-id")
        assert obligations == []

    def test_logging_check_maps_to_record_keeping(self):
        obligations = get_eu_ai_act_obligations_for_check("code-ai-logging-insufficient")
        obl_ids = [o.id for o in obligations]
        assert "EUAI-12" in obl_ids


class TestGetAutomatedObligations:
    """Test filtering for automated obligations."""

    def test_returns_only_automated(self):
        automated = get_automated_eu_ai_act_obligations()
        assert len(automated) > 0
        for obl in automated:
            assert len(obl.check_ids) > 0

    def test_excludes_policy_only(self):
        automated = get_automated_eu_ai_act_obligations()
        automated_ids = {o.id for o in automated}
        # EUAI-9 is policy-only
        assert "EUAI-9" not in automated_ids


class TestGetPolicyRequiredObligations:
    """Test filtering for policy-required obligations."""

    def test_returns_only_policy_required(self):
        policy = get_policy_required_eu_ai_act_obligations()
        assert len(policy) > 0
        for obl in policy:
            assert obl.requires_policy is True

    def test_includes_risk_management(self):
        policy = get_policy_required_eu_ai_act_obligations()
        policy_ids = {o.id for o in policy}
        assert "EUAI-9" in policy_ids

    def test_includes_transparency(self):
        policy = get_policy_required_eu_ai_act_obligations()
        policy_ids = {o.id for o in policy}
        assert "EUAI-52" in policy_ids
