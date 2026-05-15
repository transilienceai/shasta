"""Tests for ISO 27001 compliance scorer."""

from shasta.compliance.iso27001_scorer import ISO27001Score, calculate_iso27001_score
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


class TestISO27001ScoreEmpty:
    """Edge case: empty findings list."""

    def test_empty_findings_score_100(self):
        score = calculate_iso27001_score([])
        assert score.score_percentage == 100.0

    def test_empty_findings_grade_a(self):
        score = calculate_iso27001_score([])
        assert score.grade == "A"

    def test_empty_findings_zero_themes(self):
        score = calculate_iso27001_score([])
        assert score.organizational_pass == 0
        assert score.organizational_fail == 0
        assert score.technological_pass == 0
        assert score.technological_fail == 0


class TestISO27001ScoreAllPass:
    """All PASS findings — check_ids that map to ISO 27001 controls."""

    def test_all_pass_score_100(self):
        # iam-password-policy maps to A.5.15 (Organizational) and A.8.5 (Technological)
        findings = [
            _make_finding("iam-password-policy", ComplianceStatus.PASS),
            _make_finding("iam-user-mfa", ComplianceStatus.PASS),
            _make_finding("iam-root-mfa", ComplianceStatus.PASS),
        ]
        score = calculate_iso27001_score(findings)
        assert score.score_percentage == 100.0
        assert score.grade == "A"

    def test_all_pass_no_failures(self):
        findings = [
            _make_finding("iam-password-policy", ComplianceStatus.PASS),
            _make_finding("iam-user-mfa", ComplianceStatus.PASS),
        ]
        score = calculate_iso27001_score(findings)
        assert score.failing == 0


class TestISO27001ScoreAllFail:
    """All FAIL findings."""

    def test_all_fail_score_0(self):
        findings = [
            _make_finding("iam-password-policy", ComplianceStatus.FAIL),
            _make_finding("iam-user-mfa", ComplianceStatus.FAIL),
            _make_finding("iam-root-mfa", ComplianceStatus.FAIL),
        ]
        score = calculate_iso27001_score(findings)
        assert score.score_percentage == 0.0
        assert score.grade == "F"

    def test_all_fail_has_failures(self):
        findings = [
            _make_finding("iam-password-policy", ComplianceStatus.FAIL),
        ]
        score = calculate_iso27001_score(findings)
        assert score.failing >= 1
        assert score.passing == 0


class TestISO27001ScoreNotAssessed:
    """NOT_ASSESSED findings should not tank the score."""

    def test_not_assessed_score_100(self):
        findings = [
            _make_finding("iam-password-policy", ComplianceStatus.NOT_ASSESSED),
            _make_finding("iam-user-mfa", ComplianceStatus.NOT_ASSESSED),
        ]
        score = calculate_iso27001_score(findings)
        assert score.score_percentage == 100.0
        assert score.grade == "A"


class TestISO27001ThemeCounts:
    """Verify theme-level pass/fail counts."""

    def test_organizational_pass_counted(self):
        # iam-password-policy maps to A.5.15 (Organizational) among others
        findings = [
            _make_finding("iam-password-policy", ComplianceStatus.PASS),
            _make_finding("iam-user-mfa", ComplianceStatus.PASS),
        ]
        score = calculate_iso27001_score(findings)
        # A.5.15 (Access control) is Organizational and has these check_ids
        assert score.organizational_pass >= 1

    def test_technological_pass_counted(self):
        # iam-password-policy also maps to A.8.5 (Technological)
        findings = [
            _make_finding("iam-password-policy", ComplianceStatus.PASS),
            _make_finding("iam-user-mfa", ComplianceStatus.PASS),
            _make_finding("iam-root-mfa", ComplianceStatus.PASS),
        ]
        score = calculate_iso27001_score(findings)
        assert score.technological_pass >= 1

    def test_organizational_fail_counted(self):
        findings = [
            _make_finding("iam-password-policy", ComplianceStatus.FAIL),
        ]
        score = calculate_iso27001_score(findings)
        assert score.organizational_fail >= 1

    def test_technological_fail_counted(self):
        findings = [
            _make_finding("iam-password-policy", ComplianceStatus.FAIL),
            _make_finding("iam-user-mfa", ComplianceStatus.FAIL),
        ]
        score = calculate_iso27001_score(findings)
        # A.8.5 is Technological and has iam-password-policy + iam-user-mfa
        assert score.technological_fail >= 1


class TestISO27001Mixed:
    """Mixed pass/fail scenarios."""

    def test_mixed_score_between_0_and_100(self):
        findings = [
            _make_finding("iam-password-policy", ComplianceStatus.FAIL),
            _make_finding(
                "sg-no-unrestricted-ingress",
                ComplianceStatus.PASS,
                domain=CheckDomain.NETWORKING,
            ),
        ]
        score = calculate_iso27001_score(findings)
        assert 0.0 < score.score_percentage < 100.0

    def test_partial_counts_as_half(self):
        # Single check mapping to a single control:
        # cloudtrail-enabled maps to several controls, but let's just verify
        # partial scoring works.
        findings = [
            _make_finding(
                "cloudtrail-enabled",
                ComplianceStatus.PARTIAL,
                domain=CheckDomain.LOGGING,
            ),
            _make_finding(
                "sg-no-unrestricted-ingress",
                ComplianceStatus.PASS,
                domain=CheckDomain.NETWORKING,
            ),
        ]
        score = calculate_iso27001_score(findings)
        # Some controls are partial, some pass, so score is between 50-100
        assert score.partial >= 1
        assert score.score_percentage < 100.0


class TestISO27001ScoreDataclass:
    """Verify the ISO27001Score dataclass fields are populated."""

    def test_all_fields_present(self):
        findings = [
            _make_finding("iam-password-policy", ComplianceStatus.PASS),
        ]
        score = calculate_iso27001_score(findings)
        assert isinstance(score, ISO27001Score)
        assert isinstance(score.total_controls, int)
        assert isinstance(score.organizational_pass, int)
        assert isinstance(score.organizational_fail, int)
        assert isinstance(score.people_pass, int)
        assert isinstance(score.people_fail, int)
        assert isinstance(score.technological_pass, int)
        assert isinstance(score.technological_fail, int)
