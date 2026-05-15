"""Tests for SOC 2 mapper (enrich_findings_with_controls and get_control_summary)."""

from shasta.compliance.framework import SOC2_CONTROLS
from shasta.compliance.mapper import enrich_findings_with_controls, get_control_summary
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


class TestEnrichFindingsWithControls:
    """Test enrich_findings_with_controls."""

    def test_empty_soc2_controls_get_enriched(self):
        """Finding with no soc2_controls gets them from the framework."""
        findings = [
            _make_finding("iam-password-policy", ComplianceStatus.PASS),
        ]
        assert findings[0].soc2_controls == []
        enriched = enrich_findings_with_controls(findings)
        # iam-password-policy maps to CC6.1 in the framework
        assert "CC6.1" in enriched[0].soc2_controls

    def test_existing_soc2_controls_preserved(self):
        """Finding with pre-set soc2_controls is not overwritten."""
        findings = [
            _make_finding("iam-password-policy", ComplianceStatus.PASS, ["CC9.1"]),
        ]
        enriched = enrich_findings_with_controls(findings)
        assert enriched[0].soc2_controls == ["CC9.1"]

    def test_multiple_findings_enriched(self):
        findings = [
            _make_finding("iam-password-policy", ComplianceStatus.PASS),
            _make_finding("iam-user-mfa", ComplianceStatus.PASS),
            _make_finding(
                "sg-no-unrestricted-ingress",
                ComplianceStatus.PASS,
                domain=CheckDomain.NETWORKING,
            ),
        ]
        enriched = enrich_findings_with_controls(findings)
        for f in enriched:
            assert len(f.soc2_controls) > 0

    def test_unknown_check_id_stays_empty(self):
        """A check_id not in the framework gets no controls."""
        findings = [
            _make_finding("totally-unknown-check", ComplianceStatus.PASS),
        ]
        enriched = enrich_findings_with_controls(findings)
        assert enriched[0].soc2_controls == []

    def test_mutates_in_place(self):
        """The function modifies findings in place and returns the same list."""
        findings = [
            _make_finding("iam-password-policy", ComplianceStatus.PASS),
        ]
        result = enrich_findings_with_controls(findings)
        assert result is findings

    def test_iam_password_policy_maps_to_cc61(self):
        findings = [_make_finding("iam-password-policy", ComplianceStatus.PASS)]
        enrich_findings_with_controls(findings)
        assert "CC6.1" in findings[0].soc2_controls

    def test_sg_maps_to_cc66(self):
        findings = [
            _make_finding(
                "sg-no-unrestricted-ingress",
                ComplianceStatus.PASS,
                domain=CheckDomain.NETWORKING,
            ),
        ]
        enrich_findings_with_controls(findings)
        assert "CC6.6" in findings[0].soc2_controls

    def test_cloudtrail_maps_to_cc71(self):
        findings = [
            _make_finding(
                "cloudtrail-enabled",
                ComplianceStatus.PASS,
                domain=CheckDomain.LOGGING,
            ),
        ]
        enrich_findings_with_controls(findings)
        assert "CC7.1" in findings[0].soc2_controls


class TestGetControlSummary:
    """Test get_control_summary."""

    def test_all_framework_controls_present(self):
        """Even with no findings, all SOC 2 controls appear in summary."""
        summary = get_control_summary([])
        for ctrl_id in SOC2_CONTROLS:
            assert ctrl_id in summary

    def test_no_findings_all_not_assessed(self):
        summary = get_control_summary([])
        for ctrl_id, data in summary.items():
            ctrl = SOC2_CONTROLS[ctrl_id]
            if ctrl.requires_policy and not ctrl.check_ids:
                assert data["overall_status"] == "requires_policy"
            else:
                assert data["overall_status"] == "not_assessed"

    def test_pass_finding_makes_control_pass(self):
        findings = [
            _make_finding("iam-password-policy", ComplianceStatus.PASS, ["CC6.1"]),
        ]
        summary = get_control_summary(findings)
        assert summary["CC6.1"]["pass_count"] == 1
        assert summary["CC6.1"]["overall_status"] == "pass"

    def test_fail_overrides_pass(self):
        findings = [
            _make_finding("iam-password-policy", ComplianceStatus.PASS, ["CC6.1"]),
            _make_finding("iam-user-mfa", ComplianceStatus.FAIL, ["CC6.1"]),
        ]
        summary = get_control_summary(findings)
        assert summary["CC6.1"]["pass_count"] == 1
        assert summary["CC6.1"]["fail_count"] == 1
        assert summary["CC6.1"]["overall_status"] == "fail"

    def test_partial_if_no_fail(self):
        findings = [
            _make_finding("iam-password-policy", ComplianceStatus.PASS, ["CC6.1"]),
            _make_finding("iam-user-mfa", ComplianceStatus.PARTIAL, ["CC6.1"]),
        ]
        summary = get_control_summary(findings)
        assert summary["CC6.1"]["overall_status"] == "partial"

    def test_findings_list_populated(self):
        findings = [
            _make_finding("iam-password-policy", ComplianceStatus.PASS, ["CC6.1"]),
            _make_finding("iam-user-mfa", ComplianceStatus.PASS, ["CC6.1"]),
        ]
        summary = get_control_summary(findings)
        assert len(summary["CC6.1"]["findings"]) == 2

    def test_finding_mapped_to_multiple_controls(self):
        """cloudtrail-enabled maps to CC7.1 and CC8.1."""
        findings = [
            _make_finding(
                "cloudtrail-enabled",
                ComplianceStatus.PASS,
                ["CC7.1", "CC8.1"],
                domain=CheckDomain.LOGGING,
            ),
        ]
        summary = get_control_summary(findings)
        assert summary["CC7.1"]["pass_count"] == 1
        assert summary["CC8.1"]["pass_count"] == 1

    def test_control_metadata_present(self):
        summary = get_control_summary([])
        for ctrl_id, data in summary.items():
            assert "title" in data
            assert "category" in data
            assert "guidance" in data
            assert "requires_policy" in data
            assert "has_automated_checks" in data

    def test_counts_are_integers(self):
        findings = [
            _make_finding("iam-password-policy", ComplianceStatus.FAIL, ["CC6.1"]),
        ]
        summary = get_control_summary(findings)
        assert isinstance(summary["CC6.1"]["pass_count"], int)
        assert isinstance(summary["CC6.1"]["fail_count"], int)
        assert isinstance(summary["CC6.1"]["partial_count"], int)
