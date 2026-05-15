"""Tests for NIST AI RMF framework definitions."""

from shasta.compliance.ai.nist_ai_rmf import (
    NIST_AI_RMF_CATEGORIES,
    NISTAIRMFCategory,
    get_automated_nist_ai_rmf_categories,
    get_nist_ai_rmf_categories_by_function,
    get_nist_ai_rmf_categories_for_check,
    get_nist_ai_rmf_category,
    get_policy_required_nist_ai_rmf_categories,
)


class TestNISTAIRMFCategories:
    def test_total_categories_count(self):
        assert len(NIST_AI_RMF_CATEGORIES) == 19

    def test_all_categories_have_required_fields(self):
        for cat_id, cat in NIST_AI_RMF_CATEGORIES.items():
            assert isinstance(cat, NISTAIRMFCategory)
            assert cat.id == cat_id
            assert cat.title
            assert cat.description
            assert cat.function in ("GOVERN", "MAP", "MEASURE", "MANAGE")

    def test_function_distribution(self):
        govern = get_nist_ai_rmf_categories_by_function("GOVERN")
        map_cats = get_nist_ai_rmf_categories_by_function("MAP")
        measure = get_nist_ai_rmf_categories_by_function("MEASURE")
        manage = get_nist_ai_rmf_categories_by_function("MANAGE")
        assert len(govern) == 6
        assert len(map_cats) == 5
        assert len(measure) == 4
        assert len(manage) == 4


class TestGetNISTCategory:
    def test_lookup_valid_id(self):
        cat = get_nist_ai_rmf_category("GOVERN-1")
        assert cat is not None
        assert cat.title == "Policies and Procedures"
        assert cat.function == "GOVERN"

    def test_lookup_invalid_id(self):
        assert get_nist_ai_rmf_category("GOVERN-99") is None


class TestGetCategoriesForCheck:
    def test_logging_maps_to_measure3(self):
        cats = get_nist_ai_rmf_categories_for_check("code-ai-logging-insufficient")
        cat_ids = [c.id for c in cats]
        assert "MEASURE-3" in cat_ids

    def test_outdated_sdk_maps_to_supply_chain(self):
        cats = get_nist_ai_rmf_categories_for_check("code-outdated-ai-sdk")
        cat_ids = [c.id for c in cats]
        assert "GOVERN-6" in cat_ids

    def test_unknown_check_returns_empty(self):
        assert get_nist_ai_rmf_categories_for_check("nonexistent") == []


class TestGetAutomatedCategories:
    def test_returns_only_automated(self):
        automated = get_automated_nist_ai_rmf_categories()
        assert len(automated) >= 7
        for cat in automated:
            assert len(cat.check_ids) > 0


class TestGetPolicyRequired:
    def test_returns_only_policy_required(self):
        policy = get_policy_required_nist_ai_rmf_categories()
        assert len(policy) >= 8
        for cat in policy:
            assert cat.requires_policy is True

    def test_govern_categories_mostly_require_policy(self):
        govern = get_nist_ai_rmf_categories_by_function("GOVERN")
        policy_govern = [c for c in govern if c.requires_policy]
        assert len(policy_govern) >= 5  # 5 of 6 GOVERN categories need policy
