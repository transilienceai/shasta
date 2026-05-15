"""Tests for MITRE ATLAS framework definitions."""

from shasta.compliance.ai.mitre_atlas import (
    ATLAS_TECHNIQUES,
    ATLASTechnique,
    get_atlas_tactics,
    get_atlas_technique,
    get_atlas_techniques_by_tactic,
    get_atlas_techniques_for_check,
    get_automated_atlas_techniques,
)


class TestATLASTechniques:
    def test_total_techniques_count(self):
        assert len(ATLAS_TECHNIQUES) == 15

    def test_all_techniques_have_required_fields(self):
        for tech_id, tech in ATLAS_TECHNIQUES.items():
            assert isinstance(tech, ATLASTechnique)
            assert tech.id == tech_id
            assert tech.title
            assert tech.description
            assert tech.tactic

    def test_technique_ids_follow_pattern(self):
        for tech_id in ATLAS_TECHNIQUES:
            assert tech_id.startswith("AML.T")


class TestGetATLASTechnique:
    def test_lookup_valid_id(self):
        tech = get_atlas_technique("AML.T0051")
        assert tech is not None
        assert tech.title == "LLM Prompt Injection"
        assert tech.tactic == "Initial Access"

    def test_lookup_invalid_id(self):
        assert get_atlas_technique("AML.T9999") is None


class TestGetTechniquesForCheck:
    def test_prompt_injection_maps_to_aml_t0051(self):
        techs = get_atlas_techniques_for_check("code-prompt-injection-risk")
        tech_ids = [t.id for t in techs]
        assert "AML.T0051" in tech_ids

    def test_training_data_maps_to_poisoning(self):
        techs = get_atlas_techniques_for_check("code-training-data-unencrypted")
        tech_ids = [t.id for t in techs]
        assert "AML.T0010" in tech_ids

    def test_unknown_check_returns_empty(self):
        assert get_atlas_techniques_for_check("nonexistent") == []


class TestGetAutomatedTechniques:
    def test_returns_only_automated(self):
        automated = get_automated_atlas_techniques()
        assert len(automated) >= 12
        for tech in automated:
            assert len(tech.check_ids) > 0


class TestGetTactics:
    def test_returns_unique_tactics(self):
        tactics = get_atlas_tactics()
        assert len(tactics) >= 7
        assert "Initial Access" in tactics
        assert "Reconnaissance" in tactics
        assert "Exfiltration" in tactics
        assert "Impact" in tactics

    def test_get_techniques_by_tactic(self):
        initial = get_atlas_techniques_by_tactic("Initial Access")
        assert len(initial) >= 1
        for tech in initial:
            assert tech.tactic == "Initial Access"
