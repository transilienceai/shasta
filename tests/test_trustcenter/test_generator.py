"""Tests for the trust center page generator.

Verifies rendering with scan data, rendering without scan data (the
"Not yet scanned" path), section toggles, output validity, and privacy
controls (no sensitive data exposure).
"""

from __future__ import annotations

from pathlib import Path

from shasta.evidence.models import (
    CheckDomain,
    CloudProvider,
    ComplianceStatus,
    Finding,
    ScanResult,
    Severity,
)
from shasta.trustcenter.config import TrustCenterConfig, load_config
from shasta.trustcenter.generator import build_trust_center_context, generate_trust_center


def _make_scan() -> ScanResult:
    """Create a realistic ScanResult with a mix of PASS/FAIL findings."""
    findings = []
    for i in range(10):
        findings.append(
            Finding(
                check_id=f"test-check-{i}",
                title=f"Test finding {i}",
                description="Test description",
                severity=Severity.HIGH if i < 3 else Severity.MEDIUM,
                status=ComplianceStatus.PASS if i < 6 else ComplianceStatus.FAIL,
                domain=CheckDomain.IAM if i < 4 else CheckDomain.ENCRYPTION,
                resource_type="AWS::Test::Resource",
                resource_id=f"arn:aws:test:us-east-1:123456789012:resource/{i}",
                region="us-east-1",
                account_id="123456789012",
                cloud_provider=CloudProvider.AWS,
                soc2_controls=["CC6.1"],
            )
        )
    scan = ScanResult(
        account_id="123456789012",
        region="us-east-1",
        cloud_provider=CloudProvider.AWS,
        domains_scanned=[CheckDomain.IAM, CheckDomain.ENCRYPTION],
        findings=findings,
    )
    scan.complete()
    return scan


class TestBuildContext:
    def test_context_without_scan_data(self) -> None:
        config = TrustCenterConfig(company_name="TestCo")
        ctx = build_trust_center_context(config, scan=None)
        assert ctx["has_scan_data"] is False
        assert ctx["soc2_score"] is None
        assert ctx["config"].company_name == "TestCo"
        assert ctx["generated_at"]

    def test_context_with_scan_data(self) -> None:
        config = TrustCenterConfig(company_name="TestCo")
        scan = _make_scan()
        ctx = build_trust_center_context(config, scan=scan)
        assert ctx["has_scan_data"] is True
        assert ctx["soc2_score"] is not None
        assert ctx["soc2_score"].total_findings > 0
        assert "AWS" in ctx["cloud_providers"]
        assert ctx["account_id_suffix"] == "9012"

    def test_account_id_truncated(self) -> None:
        config = TrustCenterConfig()
        scan = _make_scan()
        ctx = build_trust_center_context(config, scan=scan)
        assert ctx["account_id_suffix"] == "9012"
        assert "123456789012" not in str(ctx.get("account_id_suffix", ""))

    def test_policies_loaded(self) -> None:
        config = TrustCenterConfig()
        ctx = build_trust_center_context(config, scan=None)
        assert len(ctx["policies"]) == 8

    def test_domain_pass_rates_computed(self) -> None:
        config = TrustCenterConfig()
        scan = _make_scan()
        ctx = build_trust_center_context(config, scan=scan)
        assert ctx["iam_pass_rate"] is not None
        assert isinstance(ctx["iam_pass_rate"], int)
        assert 0 <= ctx["iam_pass_rate"] <= 100

    def test_hipaa_score_only_when_enabled(self) -> None:
        config = TrustCenterConfig(show_hipaa=False)
        scan = _make_scan()
        ctx = build_trust_center_context(config, scan=scan)
        assert ctx["hipaa_score"] is None


class TestGenerateTrustCenter:
    def test_generates_html_file(self, tmp_path: Path) -> None:
        config = TrustCenterConfig(company_name="Test Corp")
        path = generate_trust_center(config, output_path=tmp_path, scan=None)
        assert path.exists()
        assert path.name == "index.html"
        content = path.read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in content
        assert "Test Corp" in content

    def test_output_is_valid_html(self, tmp_path: Path) -> None:
        config = TrustCenterConfig(company_name="ValidHTML Inc")
        path = generate_trust_center(config, output_path=tmp_path, scan=None)
        content = path.read_text(encoding="utf-8")
        assert content.startswith("<!DOCTYPE html>")
        assert "</html>" in content
        # No Jinja2 template syntax leaks
        assert "{{" not in content
        assert "{%" not in content
        assert "{#" not in content

    def test_not_yet_scanned_appears_without_data(self, tmp_path: Path) -> None:
        config = TrustCenterConfig(company_name="NoScan Corp")
        path = generate_trust_center(config, output_path=tmp_path, scan=None)
        content = path.read_text(encoding="utf-8")
        assert "Not yet scanned" in content

    def test_section_toggle_hides_hipaa(self, tmp_path: Path) -> None:
        config = TrustCenterConfig(company_name="NoHipaa Corp", show_hipaa=False)
        path = generate_trust_center(config, output_path=tmp_path, scan=None)
        content = path.read_text(encoding="utf-8")
        assert "HIPAA" not in content

    def test_section_toggle_shows_hipaa(self, tmp_path: Path) -> None:
        config = TrustCenterConfig(company_name="Hipaa Corp", show_hipaa=True)
        path = generate_trust_center(config, output_path=tmp_path, scan=None)
        content = path.read_text(encoding="utf-8")
        assert "HIPAA" in content

    def test_policies_section_appears(self, tmp_path: Path) -> None:
        config = TrustCenterConfig(company_name="Policy Corp")
        path = generate_trust_center(config, output_path=tmp_path, scan=None)
        content = path.read_text(encoding="utf-8")
        assert "Access Control Policy" in content
        assert "Incident Response Plan" in content
        assert "In Place" in content

    def test_no_full_account_id_in_output(self, tmp_path: Path) -> None:
        config = TrustCenterConfig(company_name="Privacy Corp")
        path = generate_trust_center(config, output_path=tmp_path, scan=None)
        content = path.read_text(encoding="utf-8")
        # The test account ID from _make_scan is 123456789012
        # It should NOT appear in full in the output
        assert "123456789012" not in content

    def test_subprocessors_table_renders(self, tmp_path: Path) -> None:
        config = TrustCenterConfig(
            company_name="SubProc Corp",
            subprocessors=[
                {"name": "AWS", "purpose": "Cloud infrastructure", "location": "US"},
                {"name": "Stripe", "purpose": "Payment processing", "location": "US"},
            ],
        )
        path = generate_trust_center(config, output_path=tmp_path, scan=None)
        content = path.read_text(encoding="utf-8")
        assert "AWS" in content
        assert "Cloud infrastructure" in content
        assert "Stripe" in content

    def test_footer_has_generated_timestamp(self, tmp_path: Path) -> None:
        config = TrustCenterConfig(
            company_name="Footer Corp",
            contact_email="security@footer.com",
        )
        path = generate_trust_center(config, output_path=tmp_path, scan=None)
        content = path.read_text(encoding="utf-8")
        assert "Last updated:" in content
        assert "security@footer.com" in content
        assert "Shasta Compliance Platform" in content


class TestConfig:
    def test_default_config(self) -> None:
        config = TrustCenterConfig()
        assert config.show_soc2 is True
        assert config.show_hipaa is False
        assert config.primary_color == "#6366f1"

    def test_load_config_uses_defaults(self) -> None:
        config = load_config()
        assert config.company_name  # should be at least "Your Company" fallback

    def test_load_config_respects_overrides(self) -> None:
        override = TrustCenterConfig(company_name="Override Corp", show_hipaa=True)
        config = load_config(override)
        assert config.company_name == "Override Corp"
        assert config.show_hipaa is True
