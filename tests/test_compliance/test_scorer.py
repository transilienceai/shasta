"""Tests for SOC 2 compliance scorer."""

from shasta.compliance.scorer import ComplianceScore, calculate_score
from shasta.evidence.models import (
    CheckDomain,
    CloudProvider,
    ComplianceStatus,
    Finding,
    Severity,
)


def _make_finding(
    check_id: str,
    status: ComplianceStatus,
    soc2_controls: list[str] | None = None,
    severity: Severity = Severity.HIGH,
    domain: CheckDomain = CheckDomain.IAM,
) -> Finding:
    """Helper to create a Finding with sensible defaults."""
    return Finding(
        check_id=check_id,
        title=f"Test finding: {check_id}",
        description=f"Description for {check_id}",
        severity=severity,
        status=status,
        domain=domain,
        resource_type="AWS::IAM::User",
        resource_id="arn:aws:iam::123456789012:user/test",
        region="us-east-1",
        account_id="123456789012",
        cloud_provider=CloudProvider.AWS,
        soc2_controls=soc2_controls or [],
    )


class TestCalculateScoreEmpty:
    """Tests for edge case: empty findings list."""

    def test_empty_findings_score_100(self):
        score = calculate_score([])
        # No findings means all controls are not_assessed or requires_policy;
        # the scorer treats that as 100.0 because nothing has failed.
        assert score.score_percentage == 100.0

    def test_empty_findings_grade_a(self):
        score = calculate_score([])
        assert score.grade == "A"

    def test_empty_findings_zero_totals(self):
        score = calculate_score([])
        assert score.total_findings == 0
        assert score.findings_passed == 0
        assert score.findings_failed == 0
        assert score.findings_partial == 0


class TestCalculateScoreAllPass:
    """Tests for all PASS findings."""

    def test_all_pass_score_100(self):
        findings = [
            _make_finding("iam-password-policy", ComplianceStatus.PASS, ["CC6.1"]),
            _make_finding("iam-user-mfa", ComplianceStatus.PASS, ["CC6.1"]),
            _make_finding("iam-root-mfa", ComplianceStatus.PASS, ["CC6.1"]),
        ]
        score = calculate_score(findings)
        assert score.score_percentage == 100.0

    def test_all_pass_grade_a(self):
        findings = [
            _make_finding("iam-password-policy", ComplianceStatus.PASS, ["CC6.1"]),
            _make_finding("iam-user-mfa", ComplianceStatus.PASS, ["CC6.1"]),
        ]
        score = calculate_score(findings)
        assert score.grade == "A"

    def test_all_pass_finding_counts(self):
        findings = [
            _make_finding("iam-password-policy", ComplianceStatus.PASS, ["CC6.1"]),
            _make_finding("iam-user-mfa", ComplianceStatus.PASS, ["CC6.1"]),
        ]
        score = calculate_score(findings)
        assert score.findings_passed == 2
        assert score.findings_failed == 0


class TestCalculateScoreAllFail:
    """Tests for all FAIL findings."""

    def test_all_fail_score_0(self):
        findings = [
            _make_finding("iam-password-policy", ComplianceStatus.FAIL, ["CC6.1"]),
            _make_finding("iam-user-mfa", ComplianceStatus.FAIL, ["CC6.1"]),
            _make_finding("iam-root-mfa", ComplianceStatus.FAIL, ["CC6.1"]),
        ]
        score = calculate_score(findings)
        assert score.score_percentage == 0.0

    def test_all_fail_grade_f(self):
        findings = [
            _make_finding("iam-password-policy", ComplianceStatus.FAIL, ["CC6.1"]),
            _make_finding("iam-user-mfa", ComplianceStatus.FAIL, ["CC6.1"]),
        ]
        score = calculate_score(findings)
        assert score.grade == "F"

    def test_all_fail_finding_counts(self):
        findings = [
            _make_finding("iam-password-policy", ComplianceStatus.FAIL, ["CC6.1"]),
            _make_finding("iam-user-mfa", ComplianceStatus.FAIL, ["CC6.1"]),
        ]
        score = calculate_score(findings)
        assert score.findings_failed == 2
        assert score.findings_passed == 0


class TestCalculateScoreMixed:
    """Tests for mixed PASS/FAIL/PARTIAL findings."""

    def test_mixed_weighted_score(self):
        """One control (CC6.1) gets FAIL from one finding, PASS from another.
        The control-level status is 'fail' (worst case), so it counts as failing.
        Other controls with only PASS findings count as passing.
        Score depends on ratio of passing to total assessed controls.
        """
        findings = [
            # CC6.1 — has a failure, so control is 'fail'
            _make_finding("iam-password-policy", ComplianceStatus.FAIL, ["CC6.1"]),
            _make_finding("iam-user-mfa", ComplianceStatus.PASS, ["CC6.1"]),
            # CC6.6 — all pass
            _make_finding(
                "sg-no-unrestricted-ingress",
                ComplianceStatus.PASS,
                ["CC6.6"],
                domain=CheckDomain.NETWORKING,
            ),
        ]
        score = calculate_score(findings)
        # CC6.1 is fail, CC6.6 is pass. That's 2 assessed, 1 passing.
        # But there are many more framework controls that are not_assessed.
        # assessed = passing_controls + failing_controls + partial_controls
        assert score.failing >= 1
        assert score.passing >= 1
        assert 0.0 < score.score_percentage < 100.0

    def test_partial_counts_as_half(self):
        """A control with only PARTIAL findings gets 0.5 weight in score."""
        findings = [
            # CC6.1 — partial
            _make_finding("iam-password-policy", ComplianceStatus.PARTIAL, ["CC6.1"]),
            # CC6.6 — pass
            _make_finding(
                "sg-no-unrestricted-ingress",
                ComplianceStatus.PASS,
                ["CC6.6"],
                domain=CheckDomain.NETWORKING,
            ),
        ]
        score = calculate_score(findings)
        # 2 assessed controls: 1 pass (1.0) + 1 partial (0.5) = 1.5 / 2 = 75%
        assert score.score_percentage == 75.0
        assert score.grade == "C"

    def test_mixed_finding_counts(self):
        findings = [
            _make_finding("iam-password-policy", ComplianceStatus.PASS, ["CC6.1"]),
            _make_finding("iam-user-mfa", ComplianceStatus.FAIL, ["CC6.1"]),
            _make_finding("iam-root-mfa", ComplianceStatus.PARTIAL, ["CC6.1"]),
        ]
        score = calculate_score(findings)
        assert score.findings_passed == 1
        assert score.findings_failed == 1
        assert score.findings_partial == 1
        assert score.total_findings == 3


class TestCalculateScoreNotAssessed:
    """Tests for NOT_ASSESSED findings."""

    def test_all_not_assessed_score_100(self):
        findings = [
            _make_finding("iam-password-policy", ComplianceStatus.NOT_ASSESSED, ["CC6.1"]),
            _make_finding("iam-user-mfa", ComplianceStatus.NOT_ASSESSED, ["CC6.1"]),
        ]
        score = calculate_score(findings)
        # NOT_ASSESSED findings don't affect control status as pass/fail/partial,
        # so all controls remain not_assessed, and score defaults to 100.0.
        assert score.score_percentage == 100.0
        assert score.grade == "A"


class TestGrading:
    """Test grade boundaries."""

    def test_grade_a_at_90(self):
        # Need exactly 90% — set up controls so that 90% of assessed pass.
        # This is hard to control exactly via findings because the framework
        # has many controls. Instead, verify score_to_grade via the scorer output.
        # We already test A (100%) and F (0%) above. Verify boundary behavior
        # by constructing specific pass/fail patterns.
        from shasta.compliance.scorer import _score_to_grade

        assert _score_to_grade(90.0) == "A"
        assert _score_to_grade(89.9) == "B"
        assert _score_to_grade(80.0) == "B"
        assert _score_to_grade(79.9) == "C"
        assert _score_to_grade(70.0) == "C"
        assert _score_to_grade(69.9) == "D"
        assert _score_to_grade(60.0) == "D"
        assert _score_to_grade(59.9) == "F"
        assert _score_to_grade(0.0) == "F"
        assert _score_to_grade(100.0) == "A"


class TestComplianceScoreDataclass:
    """Verify the ComplianceScore dataclass fields are populated."""

    def test_all_fields_present(self):
        findings = [
            _make_finding("iam-password-policy", ComplianceStatus.PASS, ["CC6.1"]),
        ]
        score = calculate_score(findings)
        assert isinstance(score, ComplianceScore)
        assert isinstance(score.total_controls, int)
        assert isinstance(score.passing, int)
        assert isinstance(score.failing, int)
        assert isinstance(score.partial, int)
        assert isinstance(score.not_assessed, int)
        assert isinstance(score.requires_policy, int)
        assert isinstance(score.score_percentage, float)
        assert isinstance(score.grade, str)
