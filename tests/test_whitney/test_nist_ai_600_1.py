"""Tests for NIST AI 600-1 Generative AI Profile framework definitions."""

from whitney.compliance.nist_ai_600_1 import (
    NIST_AI_600_1_RISKS,
    NISTAI6001Risk,
    get_automated_nist_ai_600_1_risks,
    get_nist_ai_600_1_risk,
    get_nist_ai_600_1_risks_for_check,
    get_policy_required_nist_ai_600_1_risks,
)


class TestNISTAI6001Risks:
    def test_total_risks_count(self):
        assert len(NIST_AI_600_1_RISKS) == 12

    def test_all_risks_have_required_fields(self):
        for risk_id, risk in NIST_AI_600_1_RISKS.items():
            assert isinstance(risk, NISTAI6001Risk)
            assert risk.id == risk_id
            assert risk.id.startswith("GAI-")
            assert risk.title
            assert risk.description

    def test_all_risks_have_rmf_crosswalk(self):
        """Every 600-1 risk should reference parent RMF categories."""
        for risk_id, risk in NIST_AI_600_1_RISKS.items():
            assert risk.nist_rmf_crosswalk, (
                f"{risk_id} has no NIST RMF crosswalk references"
            )


class TestGetNISTAI6001Risk:
    def test_lookup_valid_id(self):
        risk = get_nist_ai_600_1_risk("GAI-7")
        assert risk is not None
        assert risk.title == "Prompt Injection"

    def test_lookup_invalid_id(self):
        assert get_nist_ai_600_1_risk("GAI-99") is None


class TestGetRisksForCheck:
    def test_prompt_injection_maps_to_gai7(self):
        risks = get_nist_ai_600_1_risks_for_check("code-prompt-injection-risk")
        risk_ids = [r.id for r in risks]
        assert "GAI-7" in risk_ids

    def test_pii_maps_to_gai2(self):
        risks = get_nist_ai_600_1_risks_for_check("code-pii-in-prompts")
        risk_ids = [r.id for r in risks]
        assert "GAI-2" in risk_ids

    def test_outdated_sdk_maps_to_supply_chain(self):
        risks = get_nist_ai_600_1_risks_for_check("code-outdated-ai-sdk")
        risk_ids = [r.id for r in risks]
        assert "GAI-9" in risk_ids

    def test_unknown_check_returns_empty(self):
        assert get_nist_ai_600_1_risks_for_check("nonexistent") == []


class TestGetAutomatedRisks:
    def test_returns_only_automated(self):
        automated = get_automated_nist_ai_600_1_risks()
        assert len(automated) >= 10  # 10 of 12 have automated checks
        for risk in automated:
            assert len(risk.check_ids) > 0

    def test_automated_excludes_policy_only(self):
        automated = get_automated_nist_ai_600_1_risks()
        automated_ids = {r.id for r in automated}
        # GAI-3 (bias) and GAI-12 (environmental) are policy-only
        assert "GAI-3" not in automated_ids
        assert "GAI-12" not in automated_ids


class TestGetPolicyRequired:
    def test_returns_only_policy_required(self):
        policy = get_policy_required_nist_ai_600_1_risks()
        assert len(policy) == 2  # GAI-3, GAI-12
        for risk in policy:
            assert risk.requires_policy is True
        policy_ids = {r.id for r in policy}
        assert policy_ids == {"GAI-3", "GAI-12"}
