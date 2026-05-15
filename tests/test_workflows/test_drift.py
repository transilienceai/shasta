"""Tests for compliance drift detection."""

from shasta.evidence.models import (
    CheckDomain,
    CloudProvider,
    ComplianceStatus,
    Finding,
    ScanResult,
    Severity,
)
from shasta.workflows.drift import DriftReport, detect_drift


def _make_finding(
    check_id: str,
    status: ComplianceStatus,
    resource_id: str = "arn:aws:iam::123456789012:user/test",
    soc2_controls: list[str] | None = None,
    severity: Severity = Severity.HIGH,
    domain: CheckDomain = CheckDomain.IAM,
) -> Finding:
    return Finding(
        check_id=check_id,
        title=f"Test finding: {check_id}",
        description=f"Description for {check_id}",
        severity=severity,
        status=status,
        domain=domain,
        resource_type="AWS::IAM::User",
        resource_id=resource_id,
        region="us-east-1",
        account_id="123456789012",
        cloud_provider=CloudProvider.AWS,
        soc2_controls=soc2_controls or ["CC6.1"],
    )


def _make_scan(findings: list[Finding]) -> ScanResult:
    return ScanResult(
        account_id="123456789012",
        region="us-east-1",
        cloud_provider=CloudProvider.AWS,
        domains_scanned=[CheckDomain.IAM],
        findings=findings,
    )


class TestDriftPreviousNone:
    """First scan — previous=None."""

    def test_trend_initial(self):
        current = _make_scan(
            [
                _make_finding("iam-password-policy", ComplianceStatus.PASS),
            ]
        )
        report = detect_drift(current, None)
        assert report.trend == "initial"

    def test_no_crash_on_none(self):
        current = _make_scan([])
        report = detect_drift(current, None)
        assert isinstance(report, DriftReport)

    def test_previous_scan_id_none(self):
        current = _make_scan([])
        report = detect_drift(current, None)
        assert report.previous_scan_id == "none"

    def test_no_new_or_resolved(self):
        current = _make_scan(
            [
                _make_finding("iam-password-policy", ComplianceStatus.FAIL),
            ]
        )
        report = detect_drift(current, None)
        assert report.new_findings == []
        assert report.resolved_findings == []


class TestDriftStable:
    """Same scan twice — no changes."""

    def test_same_scan_stable(self):
        findings = [
            _make_finding("iam-password-policy", ComplianceStatus.FAIL),
            _make_finding("iam-user-mfa", ComplianceStatus.PASS),
        ]
        scan1 = _make_scan(findings)
        scan2 = _make_scan(findings)
        report = detect_drift(scan2, scan1)
        assert report.trend == "stable"

    def test_same_scan_no_new_findings(self):
        findings = [
            _make_finding("iam-password-policy", ComplianceStatus.FAIL),
        ]
        scan1 = _make_scan(findings)
        scan2 = _make_scan(findings)
        report = detect_drift(scan2, scan1)
        assert report.new_findings == []

    def test_same_scan_no_resolved_findings(self):
        findings = [
            _make_finding("iam-password-policy", ComplianceStatus.FAIL),
        ]
        scan1 = _make_scan(findings)
        scan2 = _make_scan(findings)
        report = detect_drift(scan2, scan1)
        assert report.resolved_findings == []

    def test_same_scan_unchanged_count(self):
        findings = [
            _make_finding("iam-password-policy", ComplianceStatus.FAIL),
            _make_finding(
                "sg-no-unrestricted-ingress",
                ComplianceStatus.FAIL,
                resource_id="sg-12345",
                domain=CheckDomain.NETWORKING,
            ),
        ]
        scan1 = _make_scan(findings)
        scan2 = _make_scan(findings)
        report = detect_drift(scan2, scan1)
        assert report.unchanged_findings == 2

    def test_stable_score_delta_zero(self):
        findings = [
            _make_finding("iam-password-policy", ComplianceStatus.FAIL),
        ]
        scan1 = _make_scan(findings)
        scan2 = _make_scan(findings)
        report = detect_drift(scan2, scan1)
        assert report.score_delta == 0.0


class TestDriftDegrading:
    """New failures added — score should drop."""

    def test_new_failure_degrading(self):
        prev_findings = [
            _make_finding("iam-password-policy", ComplianceStatus.PASS),
            _make_finding("iam-user-mfa", ComplianceStatus.PASS),
            _make_finding(
                "sg-no-unrestricted-ingress",
                ComplianceStatus.PASS,
                resource_id="sg-12345",
                domain=CheckDomain.NETWORKING,
            ),
        ]
        curr_findings = [
            _make_finding("iam-password-policy", ComplianceStatus.FAIL),
            _make_finding("iam-user-mfa", ComplianceStatus.FAIL),
            _make_finding("iam-root-mfa", ComplianceStatus.FAIL),
            _make_finding(
                "sg-no-unrestricted-ingress",
                ComplianceStatus.FAIL,
                resource_id="sg-12345",
                domain=CheckDomain.NETWORKING,
            ),
        ]
        prev = _make_scan(prev_findings)
        curr = _make_scan(curr_findings)
        report = detect_drift(curr, prev)
        assert report.trend == "degrading"

    def test_new_findings_populated(self):
        prev_findings = [
            _make_finding("iam-password-policy", ComplianceStatus.PASS),
        ]
        curr_findings = [
            _make_finding("iam-password-policy", ComplianceStatus.PASS),
            _make_finding("iam-user-mfa", ComplianceStatus.FAIL),
        ]
        prev = _make_scan(prev_findings)
        curr = _make_scan(curr_findings)
        report = detect_drift(curr, prev)
        new_check_ids = [f.check_id for f in report.new_findings]
        assert "iam-user-mfa" in new_check_ids

    def test_new_findings_change_type(self):
        prev = _make_scan([])
        curr = _make_scan(
            [
                _make_finding("iam-password-policy", ComplianceStatus.FAIL),
            ]
        )
        report = detect_drift(curr, prev)
        assert len(report.new_findings) >= 1
        assert all(f.change_type == "new" for f in report.new_findings)


class TestDriftImproving:
    """Failures resolved — score should improve."""

    def test_resolved_failure_improving(self):
        prev_findings = [
            _make_finding("iam-password-policy", ComplianceStatus.FAIL),
            _make_finding("iam-user-mfa", ComplianceStatus.FAIL),
            _make_finding("iam-root-mfa", ComplianceStatus.FAIL),
            _make_finding(
                "sg-no-unrestricted-ingress",
                ComplianceStatus.FAIL,
                resource_id="sg-12345",
                domain=CheckDomain.NETWORKING,
            ),
        ]
        curr_findings = [
            _make_finding("iam-password-policy", ComplianceStatus.PASS),
            _make_finding("iam-user-mfa", ComplianceStatus.PASS),
            _make_finding("iam-root-mfa", ComplianceStatus.PASS),
            _make_finding(
                "sg-no-unrestricted-ingress",
                ComplianceStatus.PASS,
                resource_id="sg-12345",
                domain=CheckDomain.NETWORKING,
            ),
        ]
        prev = _make_scan(prev_findings)
        curr = _make_scan(curr_findings)
        report = detect_drift(curr, prev)
        assert report.trend == "improving"

    def test_resolved_findings_populated(self):
        prev_findings = [
            _make_finding("iam-password-policy", ComplianceStatus.FAIL),
            _make_finding("iam-user-mfa", ComplianceStatus.FAIL),
        ]
        curr_findings = [
            _make_finding("iam-password-policy", ComplianceStatus.PASS),
            _make_finding("iam-user-mfa", ComplianceStatus.PASS),
        ]
        prev = _make_scan(prev_findings)
        curr = _make_scan(curr_findings)
        report = detect_drift(curr, prev)
        resolved_check_ids = [f.check_id for f in report.resolved_findings]
        assert "iam-password-policy" in resolved_check_ids
        assert "iam-user-mfa" in resolved_check_ids

    def test_resolved_findings_change_type(self):
        prev = _make_scan(
            [
                _make_finding("iam-password-policy", ComplianceStatus.FAIL),
            ]
        )
        curr = _make_scan(
            [
                _make_finding("iam-password-policy", ComplianceStatus.PASS),
            ]
        )
        report = detect_drift(curr, prev)
        assert len(report.resolved_findings) >= 1
        assert all(f.change_type == "resolved" for f in report.resolved_findings)

    def test_positive_score_delta(self):
        prev_findings = [
            _make_finding("iam-password-policy", ComplianceStatus.FAIL),
            _make_finding("iam-user-mfa", ComplianceStatus.FAIL),
            _make_finding("iam-root-mfa", ComplianceStatus.FAIL),
            _make_finding(
                "sg-no-unrestricted-ingress",
                ComplianceStatus.FAIL,
                resource_id="sg-12345",
                domain=CheckDomain.NETWORKING,
            ),
        ]
        curr_findings = [
            _make_finding("iam-password-policy", ComplianceStatus.PASS),
            _make_finding("iam-user-mfa", ComplianceStatus.PASS),
            _make_finding("iam-root-mfa", ComplianceStatus.PASS),
            _make_finding(
                "sg-no-unrestricted-ingress",
                ComplianceStatus.PASS,
                resource_id="sg-12345",
                domain=CheckDomain.NETWORKING,
            ),
        ]
        prev = _make_scan(prev_findings)
        curr = _make_scan(curr_findings)
        report = detect_drift(curr, prev)
        assert report.score_delta > 0
