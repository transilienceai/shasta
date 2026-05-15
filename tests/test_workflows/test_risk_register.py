"""Tests for risk register workflow."""

import pytest

from shasta.evidence.models import (
    CheckDomain,
    CloudProvider,
    ComplianceStatus,
    Finding,
    Severity,
)
from shasta.workflows.risk_register import (
    FINDING_TO_RISK,
    RiskItem,
    auto_seed_from_findings,
    build_register,
    calculate_risk,
)


def _make_finding(
    check_id: str,
    status: ComplianceStatus,
    soc2_controls: list[str] | None = None,
    severity: Severity = Severity.HIGH,
    domain: CheckDomain = CheckDomain.IAM,
    cloud_provider: CloudProvider = CloudProvider.AWS,
) -> Finding:
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
        cloud_provider=cloud_provider,
        soc2_controls=soc2_controls or ["CC6.1"],
    )


class TestCalculateRisk:
    """Test all 9 combinations of likelihood x impact."""

    @pytest.mark.parametrize(
        "likelihood, impact, expected_score, expected_level",
        [
            ("low", "low", 1, "low"),
            ("low", "medium", 2, "low"),
            ("low", "high", 3, "medium"),
            ("medium", "low", 2, "low"),
            ("medium", "medium", 4, "medium"),
            ("medium", "high", 6, "high"),
            ("high", "low", 3, "medium"),
            ("high", "medium", 6, "high"),
            ("high", "high", 9, "high"),
        ],
    )
    def test_risk_score_and_level(self, likelihood, impact, expected_score, expected_level):
        score, level = calculate_risk(likelihood, impact)
        assert score == expected_score
        assert level == expected_level

    def test_unknown_likelihood_defaults_to_1(self):
        score, level = calculate_risk("unknown", "high")
        assert score == 3  # 1 * 3
        assert level == "medium"

    def test_unknown_impact_defaults_to_1(self):
        score, level = calculate_risk("high", "unknown")
        assert score == 3  # 3 * 1
        assert level == "medium"


class TestAutoSeedFromFindings:
    """Test auto-seeding risk items from scan findings."""

    def test_fail_findings_seed_risks(self):
        findings = [
            _make_finding("iam-password-policy", ComplianceStatus.FAIL),
            _make_finding("iam-user-mfa", ComplianceStatus.FAIL),
        ]
        risks = auto_seed_from_findings(findings, "123456789012")
        assert len(risks) == 2
        related = {r.related_finding for r in risks}
        assert "iam-password-policy" in related
        assert "iam-user-mfa" in related

    def test_pass_findings_dont_seed(self):
        findings = [
            _make_finding("iam-password-policy", ComplianceStatus.PASS),
            _make_finding("iam-user-mfa", ComplianceStatus.PASS),
        ]
        risks = auto_seed_from_findings(findings, "123456789012")
        assert len(risks) == 0

    def test_partial_findings_seed_risks(self):
        findings = [
            _make_finding("iam-password-policy", ComplianceStatus.PARTIAL),
        ]
        risks = auto_seed_from_findings(findings, "123456789012")
        assert len(risks) == 1

    def test_not_assessed_doesnt_seed(self):
        findings = [
            _make_finding("iam-password-policy", ComplianceStatus.NOT_ASSESSED),
        ]
        risks = auto_seed_from_findings(findings, "123456789012")
        assert len(risks) == 0

    def test_azure_check_ids_produce_risks(self):
        findings = [
            _make_finding(
                "azure-conditional-access-mfa",
                ComplianceStatus.FAIL,
                cloud_provider=CloudProvider.AZURE,
            ),
            _make_finding(
                "azure-nsg-unrestricted-ingress",
                ComplianceStatus.FAIL,
                cloud_provider=CloudProvider.AZURE,
                domain=CheckDomain.NETWORKING,
            ),
        ]
        risks = auto_seed_from_findings(findings, "sub-12345")
        assert len(risks) == 2
        related = {r.related_finding for r in risks}
        assert "azure-conditional-access-mfa" in related
        assert "azure-nsg-unrestricted-ingress" in related

    def test_unknown_check_ids_silently_skipped(self):
        findings = [
            _make_finding("totally-unknown-check", ComplianceStatus.FAIL),
            _make_finding("another-unknown", ComplianceStatus.FAIL),
        ]
        risks = auto_seed_from_findings(findings, "123456789012")
        assert len(risks) == 0  # No crash, no risks

    def test_deduplication_by_check_id(self):
        """Same check_id on different resources should produce only one risk."""
        findings = [
            _make_finding(
                "iam-user-mfa",
                ComplianceStatus.FAIL,
                soc2_controls=["CC6.1"],
            ),
            Finding(
                check_id="iam-user-mfa",
                title="MFA not enabled",
                description="Another resource",
                severity=Severity.HIGH,
                status=ComplianceStatus.FAIL,
                domain=CheckDomain.IAM,
                resource_type="AWS::IAM::User",
                resource_id="arn:aws:iam::123456789012:user/other",
                region="us-east-1",
                account_id="123456789012",
                soc2_controls=["CC6.1"],
            ),
        ]
        risks = auto_seed_from_findings(findings, "123456789012")
        assert len(risks) == 1

    def test_risk_item_fields_populated(self):
        findings = [
            _make_finding("iam-password-policy", ComplianceStatus.FAIL, ["CC6.1"]),
        ]
        risks = auto_seed_from_findings(findings, "123456789012")
        assert len(risks) == 1
        risk = risks[0]
        assert risk.risk_id == "RISK-001"
        assert risk.title == FINDING_TO_RISK["iam-password-policy"]["title"]
        assert risk.category == "technical"
        assert risk.status == "open"
        assert risk.treatment == "mitigate"
        assert "CC3.1" in risk.soc2_controls
        assert "CC6.1" in risk.soc2_controls
        assert risk.related_finding == "iam-password-policy"
        assert risk.created_date != ""
        assert risk.last_reviewed != ""

    def test_risk_score_matches_template(self):
        """Verify the seeded risk has the correct score from its template."""
        findings = [
            _make_finding("iam-password-policy", ComplianceStatus.FAIL),
        ]
        risks = auto_seed_from_findings(findings, "123456789012")
        risk = risks[0]
        # iam-password-policy template: likelihood=medium, impact=high -> 2*3=6 -> high
        assert risk.risk_score == 6
        assert risk.risk_level == "high"


class TestBuildRegister:
    """Test building a RiskRegister from risk items."""

    def _make_risk_item(
        self,
        risk_id: str,
        risk_level: str = "high",
        risk_score: int = 9,
        status: str = "open",
    ) -> RiskItem:
        return RiskItem(
            risk_id=risk_id,
            title=f"Risk {risk_id}",
            description="Test risk",
            category="technical",
            likelihood="high",
            impact="high",
            risk_score=risk_score,
            risk_level=risk_level,
            owner="test-owner",
            treatment="mitigate",
            treatment_plan="Fix it",
            status=status,
        )

    def test_correct_total_count(self):
        items = [
            self._make_risk_item("RISK-001", "high"),
            self._make_risk_item("RISK-002", "medium", 4),
            self._make_risk_item("RISK-003", "low", 1),
        ]
        register = build_register(items, "123456789012")
        assert register.total_risks == 3

    def test_correct_level_counts(self):
        items = [
            self._make_risk_item("RISK-001", "high", 9),
            self._make_risk_item("RISK-002", "high", 6),
            self._make_risk_item("RISK-003", "medium", 4),
            self._make_risk_item("RISK-004", "low", 1),
        ]
        register = build_register(items, "123456789012")
        assert register.high_risk_count == 2
        assert register.medium_risk_count == 1
        assert register.low_risk_count == 1

    def test_resolved_not_in_open_count(self):
        items = [
            self._make_risk_item("RISK-001", "high", status="open"),
            self._make_risk_item("RISK-002", "medium", 4, status="resolved"),
            self._make_risk_item("RISK-003", "low", 1, status="accepted"),
        ]
        register = build_register(items, "123456789012")
        assert register.total_risks == 3
        assert register.open_risks == 1  # only "open" status
        # resolved items don't count toward level counts (only active items do)
        assert register.high_risk_count == 1
        assert register.medium_risk_count == 0

    def test_in_progress_counted_as_active(self):
        items = [
            self._make_risk_item("RISK-001", "high", status="in_progress"),
        ]
        register = build_register(items, "123456789012")
        assert register.open_risks == 1
        assert register.high_risk_count == 1

    def test_empty_register(self):
        register = build_register([], "123456789012")
        assert register.total_risks == 0
        assert register.open_risks == 0
        assert register.high_risk_count == 0
        assert register.medium_risk_count == 0
        assert register.low_risk_count == 0

    def test_account_id_set(self):
        register = build_register([], "123456789012")
        assert register.account_id == "123456789012"

    def test_review_date_set(self):
        register = build_register([], "123456789012")
        assert register.review_date != ""

    def test_items_preserved(self):
        items = [
            self._make_risk_item("RISK-001"),
            self._make_risk_item("RISK-002"),
        ]
        register = build_register(items, "123456789012")
        assert len(register.items) == 2
