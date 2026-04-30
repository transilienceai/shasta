"""Tests for report generation modules.

Covers provider-aware labelling, content correctness, and file I/O for:
- src/shasta/reports/generator.py (SOC 2 Markdown + HTML)
- src/shasta/reports/iso27001_report.py (ISO 27001 Markdown)
- src/shasta/reports/hipaa_report.py (HIPAA Markdown)
"""

from __future__ import annotations

from shasta.evidence.models import (
    CheckDomain,
    CloudProvider,
    ComplianceStatus,
    Finding,
    ScanResult,
    Severity,
)
from shasta.reports.generator import (
    PROVIDER_LABELS,
    _provider_labels,
    generate_html_report,
    generate_markdown_report,
    save_html_report,
    save_markdown_report,
)
from shasta.reports.iso27001_report import save_iso27001_markdown_report
from shasta.reports.hipaa_report import save_hipaa_report


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_finding(
    idx: int,
    cloud_provider: CloudProvider = CloudProvider.AWS,
    severity: Severity = Severity.MEDIUM,
    status: ComplianceStatus = ComplianceStatus.PASS,
) -> Finding:
    """Create a single Finding with deterministic fields."""
    return Finding(
        check_id=f"test-check-{idx}",
        title=f"Test Finding {idx}",
        description=f"Test description for finding {idx}",
        severity=severity,
        status=status,
        domain=CheckDomain.IAM,
        resource_type=(
            "AWS::IAM::User" if cloud_provider == CloudProvider.AWS else "Azure::IAM::User"
        ),
        resource_id=f"resource-{idx}",
        region="us-east-1",
        account_id="123456789012",
        cloud_provider=cloud_provider,
        remediation=f"Fix finding {idx} by doing the right thing.",
        soc2_controls=["CC6.1"],
        iso27001_controls=["A.8.5"],
        hipaa_controls=["164.312(a)(1)"],
    )


def _make_scan(
    cloud_provider: CloudProvider = CloudProvider.AWS,
    num_findings: int = 5,
) -> ScanResult:
    """Create a minimal completed ScanResult with sample findings.

    Includes a mix of severities and statuses so every report section has
    something to render.
    """
    findings: list[Finding] = []
    severities = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
    for i in range(num_findings):
        sev = severities[i % len(severities)]
        status = ComplianceStatus.FAIL if i < 2 else ComplianceStatus.PASS
        findings.append(
            _make_finding(i, cloud_provider=cloud_provider, severity=sev, status=status)
        )

    scan = ScanResult(
        account_id="123456789012",
        region="us-east-1",
        cloud_provider=cloud_provider,
        domains_scanned=[CheckDomain.IAM],
        findings=findings,
    )
    scan.complete()
    return scan


# ---------------------------------------------------------------------------
# _provider_labels helper
# ---------------------------------------------------------------------------


class TestProviderLabels:
    """Tests for the _provider_labels() helper."""

    def test_aws_labels(self):
        labels = _provider_labels(CloudProvider.AWS)
        assert labels["account_label"] == "AWS Account"
        assert labels["console"] == "AWS console"

    def test_azure_labels(self):
        labels = _provider_labels(CloudProvider.AZURE)
        assert labels["account_label"] == "Azure Subscription"
        assert labels["console"] == "Azure Portal"

    def test_provider_labels_dict_has_both(self):
        assert "aws" in PROVIDER_LABELS
        assert "azure" in PROVIDER_LABELS
        assert "gcp" in PROVIDER_LABELS

    def test_gcp_labels(self):
        labels = _provider_labels(CloudProvider.GCP)
        assert labels["account_label"] == "GCP Project"
        assert labels["console"] == "Google Cloud console"


# ---------------------------------------------------------------------------
# generator.py — Markdown reports
# ---------------------------------------------------------------------------


class TestMarkdownReport:
    """Tests for generate_markdown_report()."""

    def test_markdown_report_aws_provider(self):
        scan = _make_scan(cloud_provider=CloudProvider.AWS)
        report = generate_markdown_report(scan)
        assert "AWS Account:" in report
        assert "Azure Subscription:" not in report

    def test_markdown_report_azure_provider(self):
        scan = _make_scan(cloud_provider=CloudProvider.AZURE)
        report = generate_markdown_report(scan)
        assert "Azure Subscription:" in report
        assert "AWS Account:" not in report

    def test_markdown_report_gcp_provider(self):
        scan = _make_scan(cloud_provider=CloudProvider.GCP)
        scan.findings[0].cis_gcp_controls = ["1.4"]
        report = generate_markdown_report(scan)
        assert "GCP Project:" in report
        assert "AWS Account:" not in report
        assert "CIS GCP Control(s):" in report

    def test_markdown_contains_findings(self):
        scan = _make_scan()
        report = generate_markdown_report(scan)
        # At least one finding title should appear
        assert "Test Finding 0" in report

    def test_markdown_contains_compliance_score(self):
        scan = _make_scan()
        report = generate_markdown_report(scan)
        assert "Compliance Score:" in report
        assert "%" in report

    def test_markdown_contains_soc2_control_table(self):
        scan = _make_scan()
        report = generate_markdown_report(scan)
        assert "SOC 2 Control Status" in report
        assert "CC6.1" in report

    def test_markdown_contains_account_id(self):
        scan = _make_scan()
        report = generate_markdown_report(scan)
        assert "123456789012" in report

    def test_markdown_contains_remediation(self):
        scan = _make_scan()
        report = generate_markdown_report(scan)
        # Critical/high findings should have remediation
        assert "Fix finding" in report

    def test_save_markdown_creates_file(self, tmp_path):
        scan = _make_scan()
        filepath = save_markdown_report(scan, output_path=tmp_path)
        assert filepath.exists()
        assert filepath.suffix == ".md"
        content = filepath.read_text(encoding="utf-8")
        assert "SOC 2 Compliance Gap Analysis" in content

    def test_save_markdown_filename_contains_account(self, tmp_path):
        scan = _make_scan()
        filepath = save_markdown_report(scan, output_path=tmp_path)
        assert "123456789012" in filepath.name


# ---------------------------------------------------------------------------
# generator.py — HTML reports
# ---------------------------------------------------------------------------


class TestHtmlReport:
    """Tests for generate_html_report()."""

    def test_html_report_aws_provider(self):
        scan = _make_scan(cloud_provider=CloudProvider.AWS)
        report = generate_html_report(scan)
        assert "AWS Account:" in report
        assert "Azure Subscription:" not in report

    def test_html_report_azure_provider(self):
        scan = _make_scan(cloud_provider=CloudProvider.AZURE)
        report = generate_html_report(scan)
        assert "Azure Subscription:" in report
        assert "AWS Account:" not in report

    def test_html_report_gcp_provider(self):
        scan = _make_scan(cloud_provider=CloudProvider.GCP)
        scan.findings[0].cis_gcp_controls = ["1.4"]
        report = generate_html_report(scan)
        assert "GCP Project:" in report
        assert "AWS Account:" not in report
        assert "CIS GCP:" in report

    def test_html_is_valid_document(self):
        scan = _make_scan()
        report = generate_html_report(scan)
        assert report.strip().startswith("<!DOCTYPE html>")
        assert "</html>" in report

    def test_html_contains_findings(self):
        scan = _make_scan()
        report = generate_html_report(scan)
        assert "Test Finding 0" in report

    def test_html_contains_grade_box(self):
        scan = _make_scan()
        report = generate_html_report(scan)
        assert 'class="grade-box"' in report

    def test_html_contains_score_percentage(self):
        scan = _make_scan()
        report = generate_html_report(scan)
        assert "compliance score" in report

    def test_save_html_creates_file(self, tmp_path):
        scan = _make_scan()
        filepath = save_html_report(scan, output_path=tmp_path)
        assert filepath.exists()
        assert filepath.suffix == ".html"
        content = filepath.read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in content

    def test_save_html_filename_contains_account(self, tmp_path):
        scan = _make_scan()
        filepath = save_html_report(scan, output_path=tmp_path)
        assert "123456789012" in filepath.name


# ---------------------------------------------------------------------------
# iso27001_report.py
# ---------------------------------------------------------------------------


class TestISO27001Report:
    """Tests for save_iso27001_markdown_report()."""

    def test_iso27001_report_aws_label(self, tmp_path):
        scan = _make_scan(cloud_provider=CloudProvider.AWS)
        filepath = save_iso27001_markdown_report(scan, output_path=tmp_path)
        content = filepath.read_text(encoding="utf-8")
        assert "**AWS Account:**" in content
        assert "**Azure Subscription:**" not in content

    def test_iso27001_report_azure_label(self, tmp_path):
        scan = _make_scan(cloud_provider=CloudProvider.AZURE)
        filepath = save_iso27001_markdown_report(scan, output_path=tmp_path)
        content = filepath.read_text(encoding="utf-8")
        assert "**Azure Subscription:**" in content
        assert "**AWS Account:**" not in content

    def test_iso27001_report_saves_file(self, tmp_path):
        scan = _make_scan()
        filepath = save_iso27001_markdown_report(scan, output_path=tmp_path)
        assert filepath.exists()
        assert filepath.suffix == ".md"
        assert "iso27001" in filepath.name

    def test_iso27001_report_contains_title(self, tmp_path):
        scan = _make_scan()
        filepath = save_iso27001_markdown_report(scan, output_path=tmp_path)
        content = filepath.read_text(encoding="utf-8")
        assert "ISO 27001:2022 Gap Analysis Report" in content

    def test_iso27001_report_contains_score(self, tmp_path):
        scan = _make_scan()
        filepath = save_iso27001_markdown_report(scan, output_path=tmp_path)
        content = filepath.read_text(encoding="utf-8")
        assert "Compliance Score:" in content
        assert "Grade" in content

    def test_iso27001_report_contains_theme_breakdown(self, tmp_path):
        scan = _make_scan()
        filepath = save_iso27001_markdown_report(scan, output_path=tmp_path)
        content = filepath.read_text(encoding="utf-8")
        assert "By Theme" in content
        assert "Organizational (A.5)" in content

    def test_iso27001_report_contains_soc2_crossref(self, tmp_path):
        scan = _make_scan()
        filepath = save_iso27001_markdown_report(scan, output_path=tmp_path)
        content = filepath.read_text(encoding="utf-8")
        assert "SOC 2 Cross-Reference" in content


# ---------------------------------------------------------------------------
# hipaa_report.py
# ---------------------------------------------------------------------------


class TestHIPAAReport:
    """Tests for save_hipaa_report()."""

    def test_hipaa_report_saves_file(self, tmp_path):
        scan = _make_scan()
        filepath = save_hipaa_report(scan, output_path=tmp_path)
        assert filepath.exists()
        assert filepath.suffix == ".md"
        assert "hipaa" in filepath.name

    def test_hipaa_report_contains_title(self, tmp_path):
        scan = _make_scan()
        filepath = save_hipaa_report(scan, output_path=tmp_path)
        content = filepath.read_text(encoding="utf-8")
        assert "HIPAA Security Rule Gap Analysis Report" in content

    def test_hipaa_report_contains_score(self, tmp_path):
        scan = _make_scan()
        filepath = save_hipaa_report(scan, output_path=tmp_path)
        content = filepath.read_text(encoding="utf-8")
        assert "Compliance Score:" in content

    def test_hipaa_report_contains_safeguard_breakdown(self, tmp_path):
        scan = _make_scan()
        filepath = save_hipaa_report(scan, output_path=tmp_path)
        content = filepath.read_text(encoding="utf-8")
        assert "By Safeguard" in content
        assert "Administrative (164.308)" in content
        assert "Technical (164.312)" in content

    def test_hipaa_report_contains_phi_recommendations(self, tmp_path):
        scan = _make_scan()
        filepath = save_hipaa_report(scan, output_path=tmp_path)
        content = filepath.read_text(encoding="utf-8")
        assert "PHI-Specific Recommendations" in content
        assert "Data Classification" in content

    def test_hipaa_report_aws_phi_section_uses_aws_labels(self, tmp_path):
        scan = _make_scan(cloud_provider=CloudProvider.AWS)
        filepath = save_hipaa_report(scan, output_path=tmp_path)
        content = filepath.read_text(encoding="utf-8")
        # PHI recommendations should reference AWS services
        assert "CloudTrail" in content

    def test_hipaa_report_azure_phi_section_uses_azure_labels(self, tmp_path):
        scan = _make_scan(cloud_provider=CloudProvider.AZURE)
        filepath = save_hipaa_report(scan, output_path=tmp_path)
        content = filepath.read_text(encoding="utf-8")
        # PHI recommendations should reference Azure services
        assert "Activity Log" in content

    def test_hipaa_report_contains_cross_reference(self, tmp_path):
        scan = _make_scan()
        filepath = save_hipaa_report(scan, output_path=tmp_path)
        content = filepath.read_text(encoding="utf-8")
        assert "Cross-Reference: SOC 2 and ISO 27001" in content

    def test_hipaa_report_provider_aware_physical_safeguards_aws(self, tmp_path):
        scan = _make_scan(cloud_provider=CloudProvider.AWS)
        filepath = save_hipaa_report(scan, output_path=tmp_path)
        content = filepath.read_text(encoding="utf-8")
        # Physical safeguards section mentions provider name
        assert "BAA with AWS" in content or "AWS" in content

    def test_hipaa_report_provider_aware_physical_safeguards_azure(self, tmp_path):
        scan = _make_scan(cloud_provider=CloudProvider.AZURE)
        filepath = save_hipaa_report(scan, output_path=tmp_path)
        content = filepath.read_text(encoding="utf-8")
        # Physical safeguards section mentions Azure provider name
        assert "BAA with Azure" in content or "Azure" in content


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    """Edge-case and regression tests."""

    def test_empty_findings_markdown(self):
        """A scan with no findings should still produce a valid report."""
        scan = _make_scan(num_findings=0)
        report = generate_markdown_report(scan)
        assert "SOC 2 Compliance Gap Analysis" in report
        assert "No critical or high severity" in report

    def test_empty_findings_html(self):
        scan = _make_scan(num_findings=0)
        report = generate_html_report(scan)
        assert "<!DOCTYPE html>" in report
        assert "No critical or high severity" in report

    def test_single_critical_finding_in_markdown(self):
        """A single critical FAIL must appear in the Critical & High section."""
        scan = ScanResult(
            account_id="111111111111",
            region="eu-west-1",
            cloud_provider=CloudProvider.AWS,
            domains_scanned=[CheckDomain.IAM],
            findings=[
                _make_finding(
                    0,
                    severity=Severity.CRITICAL,
                    status=ComplianceStatus.FAIL,
                ),
            ],
        )
        scan.complete()
        report = generate_markdown_report(scan)
        assert "Test Finding 0" in report
        assert "CRITICAL" in report

    def test_reports_use_utc_timestamp(self):
        scan = _make_scan()
        report = generate_markdown_report(scan)
        assert "UTC" in report

    def test_save_creates_intermediate_dirs(self, tmp_path):
        """save_* functions should create parent dirs if missing."""
        nested = tmp_path / "deeply" / "nested" / "dir"
        filepath = save_markdown_report(_make_scan(), output_path=nested)
        assert filepath.exists()
