"""Tests for AI governance compliance scorer (ISO 42001 + EU AI Act).

Mirrors the structure of tests/test_compliance/test_scorer.py.
"""

import pytest

from whitney.compliance.scorer import (
    AIGovernanceScore,
    calculate_ai_governance_score,
    _score_to_grade,
)
from shasta.evidence.models import ComplianceStatus, Severity

from tests.test_whitney.conftest import _make_finding


# ---------------------------------------------------------------------------
# Check IDs that map to ISO 42001 and/or EU AI Act controls
# ---------------------------------------------------------------------------

# Maps to AI-A.8 (ISO 42001) and EUAI-15 (EU AI Act)
PROMPT_INJECTION = "code-prompt-injection-risk"
# Maps to AI-A.8 (ISO 42001)
API_KEY_EXPOSED = "code-ai-api-key-exposed"
# Maps to AI-8.4 + AI-A.5 (ISO) and EUAI-10 (EU)
PII_IN_PROMPTS = "code-pii-in-prompts"
# Maps to AI-8.5 (ISO) and EUAI-12 (EU)
LOGGING_INSUFFICIENT = "code-ai-logging-insufficient"
# Maps to AI-8.3 (ISO)
NO_MODEL_VERSIONING = "code-no-model-versioning"
# Maps to AI-8.4 (ISO) and EUAI-10 (EU)
TRAINING_DATA = "code-training-data-unencrypted"


class TestCalculateScoreEmpty:
    """Tests for edge case: empty findings list."""

    def test_empty_findings_score_100(self):
        score = calculate_ai_governance_score([])
        assert score.score_percentage == 100.0

    def test_empty_findings_grade_a(self):
        score = calculate_ai_governance_score([])
        assert score.grade == "A"

    def test_empty_findings_eu_score_100(self):
        score = calculate_ai_governance_score([])
        assert score.eu_score_percentage == 100.0
        assert score.eu_grade == "A"

    def test_empty_findings_combined_100(self):
        score = calculate_ai_governance_score([])
        assert score.combined_score == 100.0
        assert score.combined_grade == "A"

    def test_empty_findings_zero_counts(self):
        score = calculate_ai_governance_score([])
        assert score.passing == 0
        assert score.failing == 0
        assert score.partial == 0


class TestCalculateScoreAllPass:
    """Tests for all PASS findings."""

    def test_all_pass_score_100(self):
        findings = [
            _make_finding(PROMPT_INJECTION, ComplianceStatus.PASS),
            _make_finding(API_KEY_EXPOSED, ComplianceStatus.PASS),
            _make_finding(PII_IN_PROMPTS, ComplianceStatus.PASS),
            _make_finding(LOGGING_INSUFFICIENT, ComplianceStatus.PASS),
        ]
        score = calculate_ai_governance_score(findings)
        assert score.score_percentage == 100.0

    def test_all_pass_grade_a(self):
        findings = [
            _make_finding(PROMPT_INJECTION, ComplianceStatus.PASS),
            _make_finding(PII_IN_PROMPTS, ComplianceStatus.PASS),
        ]
        score = calculate_ai_governance_score(findings)
        assert score.grade == "A"

    def test_all_pass_eu_grade_a(self):
        findings = [
            _make_finding(PROMPT_INJECTION, ComplianceStatus.PASS),
            _make_finding(PII_IN_PROMPTS, ComplianceStatus.PASS),
        ]
        score = calculate_ai_governance_score(findings)
        assert score.eu_grade == "A"

    def test_all_pass_counts(self):
        findings = [
            _make_finding(PROMPT_INJECTION, ComplianceStatus.PASS),
            _make_finding(API_KEY_EXPOSED, ComplianceStatus.PASS),
        ]
        score = calculate_ai_governance_score(findings)
        assert score.passing >= 1
        assert score.failing == 0


class TestCalculateScoreAllFail:
    """Tests for all FAIL findings."""

    def test_all_fail_score_0(self):
        findings = [
            _make_finding(PROMPT_INJECTION, ComplianceStatus.FAIL),
            _make_finding(API_KEY_EXPOSED, ComplianceStatus.FAIL),
            _make_finding(PII_IN_PROMPTS, ComplianceStatus.FAIL),
            _make_finding(LOGGING_INSUFFICIENT, ComplianceStatus.FAIL),
        ]
        score = calculate_ai_governance_score(findings)
        assert score.score_percentage == 0.0

    def test_all_fail_grade_f(self):
        findings = [
            _make_finding(PROMPT_INJECTION, ComplianceStatus.FAIL),
            _make_finding(PII_IN_PROMPTS, ComplianceStatus.FAIL),
        ]
        score = calculate_ai_governance_score(findings)
        assert score.grade == "F"

    def test_all_fail_eu_grade_f(self):
        findings = [
            _make_finding(PROMPT_INJECTION, ComplianceStatus.FAIL),
            _make_finding(PII_IN_PROMPTS, ComplianceStatus.FAIL),
        ]
        score = calculate_ai_governance_score(findings)
        assert score.eu_grade == "F"

    def test_all_fail_counts(self):
        findings = [
            _make_finding(PROMPT_INJECTION, ComplianceStatus.FAIL),
            _make_finding(API_KEY_EXPOSED, ComplianceStatus.FAIL),
        ]
        score = calculate_ai_governance_score(findings)
        assert score.failing >= 1
        assert score.passing == 0


class TestCalculateScoreMixed:
    """Tests for mixed PASS/FAIL/PARTIAL findings."""

    def test_mixed_score_between_0_and_100(self):
        findings = [
            _make_finding(PROMPT_INJECTION, ComplianceStatus.FAIL),
            _make_finding(API_KEY_EXPOSED, ComplianceStatus.PASS),
            _make_finding(PII_IN_PROMPTS, ComplianceStatus.PASS),
        ]
        score = calculate_ai_governance_score(findings)
        assert 0.0 < score.score_percentage < 100.0

    def test_partial_counts_as_half(self):
        """A control with PARTIAL findings gets 0.5 weight in score."""
        findings = [
            _make_finding(PROMPT_INJECTION, ComplianceStatus.PARTIAL),
            _make_finding(PII_IN_PROMPTS, ComplianceStatus.PASS),
        ]
        score = calculate_ai_governance_score(findings)
        # Partial controls contribute 0.5, pass contributes 1.0
        assert score.score_percentage < 100.0
        assert score.score_percentage > 0.0

    def test_mixed_has_both_pass_and_fail(self):
        """Use check_ids mapping to different controls to get both pass and fail."""
        findings = [
            # Maps to AI-8.4 (ISO)
            _make_finding(PII_IN_PROMPTS, ComplianceStatus.PASS),
            # Maps to AI-A.8 (ISO) — different control
            _make_finding(PROMPT_INJECTION, ComplianceStatus.FAIL),
        ]
        score = calculate_ai_governance_score(findings)
        assert score.passing >= 1
        assert score.failing >= 1

    def test_fail_overrides_pass_on_same_control(self):
        """If a control has both PASS and FAIL findings, status is 'fail'."""
        findings = [
            # Both map to AI-A.8 — one pass, one fail
            _make_finding(PROMPT_INJECTION, ComplianceStatus.PASS),
            _make_finding(API_KEY_EXPOSED, ComplianceStatus.FAIL),
        ]
        score = calculate_ai_governance_score(findings)
        # AI-A.8 should be failing because it has at least one FAIL
        assert score.failing >= 1


class TestCalculateScoreNotAssessed:
    """Tests for NOT_ASSESSED findings."""

    def test_all_not_assessed_score_100(self):
        findings = [
            _make_finding(PROMPT_INJECTION, ComplianceStatus.NOT_ASSESSED),
            _make_finding(API_KEY_EXPOSED, ComplianceStatus.NOT_ASSESSED),
        ]
        score = calculate_ai_governance_score(findings)
        assert score.score_percentage == 100.0
        assert score.grade == "A"


class TestCombinedScore:
    """Tests for combined ISO 42001 + EU AI Act scoring."""

    def test_combined_score_with_all_pass(self):
        findings = [
            _make_finding(PROMPT_INJECTION, ComplianceStatus.PASS),
            _make_finding(PII_IN_PROMPTS, ComplianceStatus.PASS),
        ]
        score = calculate_ai_governance_score(findings)
        assert score.combined_score == 100.0
        assert score.combined_grade == "A"

    def test_combined_score_with_all_fail(self):
        findings = [
            _make_finding(PROMPT_INJECTION, ComplianceStatus.FAIL),
            _make_finding(PII_IN_PROMPTS, ComplianceStatus.FAIL),
        ]
        score = calculate_ai_governance_score(findings)
        assert score.combined_score == 0.0
        assert score.combined_grade == "F"


class TestGrading:
    """Test grade boundaries."""

    def test_grade_boundaries(self):
        assert _score_to_grade(100.0) == "A"
        assert _score_to_grade(90.0) == "A"
        assert _score_to_grade(89.9) == "B"
        assert _score_to_grade(80.0) == "B"
        assert _score_to_grade(79.9) == "C"
        assert _score_to_grade(70.0) == "C"
        assert _score_to_grade(69.9) == "D"
        assert _score_to_grade(60.0) == "D"
        assert _score_to_grade(59.9) == "F"
        assert _score_to_grade(0.0) == "F"


class TestAIGovernanceScoreDataclass:
    """Verify the AIGovernanceScore dataclass fields are populated."""

    def test_all_fields_present(self):
        findings = [
            _make_finding(PROMPT_INJECTION, ComplianceStatus.PASS),
        ]
        score = calculate_ai_governance_score(findings)
        assert isinstance(score, AIGovernanceScore)
        # ISO 42001 fields
        assert isinstance(score.total_controls, int)
        assert isinstance(score.passing, int)
        assert isinstance(score.failing, int)
        assert isinstance(score.partial, int)
        assert isinstance(score.not_assessed, int)
        assert isinstance(score.requires_policy, int)
        assert isinstance(score.score_percentage, float)
        assert isinstance(score.grade, str)
        # EU AI Act fields
        assert isinstance(score.eu_total_obligations, int)
        assert isinstance(score.eu_passing, int)
        assert isinstance(score.eu_failing, int)
        assert isinstance(score.eu_partial, int)
        assert isinstance(score.eu_not_assessed, int)
        assert isinstance(score.eu_requires_policy, int)
        assert isinstance(score.eu_score_percentage, float)
        assert isinstance(score.eu_grade, str)
        # Combined
        assert isinstance(score.combined_score, float)
        assert isinstance(score.combined_grade, str)

    def test_total_controls_count(self):
        """ISO 42001 has 11 controls."""
        score = calculate_ai_governance_score([])
        assert score.total_controls == 11

    def test_eu_total_obligations_count(self):
        """EU AI Act has 8 obligations."""
        score = calculate_ai_governance_score([])
        assert score.eu_total_obligations == 8
