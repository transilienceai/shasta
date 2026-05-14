"""HTML report generators for ISO 27001, HIPAA, Whitney, and consolidated reports.

Produces standalone HTML files with embedded CSS (no external dependencies)
matching the visual style of the existing SOC 2 HTML report in generator.py.
"""

from __future__ import annotations

import html
from datetime import datetime, timezone
from pathlib import Path

from shasta.compliance.hipaa_mapper import get_hipaa_control_summary
from shasta.compliance.hipaa_scorer import calculate_hipaa_score
from shasta.compliance.iso27001_mapper import get_iso27001_control_summary
from shasta.compliance.iso27001_scorer import calculate_iso27001_score
from shasta.compliance.scorer import calculate_score
from shasta.evidence.models import Finding, ScanResult
from shasta.reports.generator import _render_details_html


# ---------------------------------------------------------------------------
# Shared CSS (embedded in every report)
# ---------------------------------------------------------------------------
_BASE_CSS = """
:root {
  --pass: #10b981; --fail: #ef4444; --partial: #f59e0b; --policy: #8b5cf6;
  --critical: #991b1b; --high: #dc2626; --medium: #d97706; --low: #2563eb; --info: #6b7280;
  --bg: #ffffff; --text: #1e293b; --muted: #64748b; --border: #e2e8f0; --surface: #f8fafc;
}
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  color: var(--text); line-height: 1.6; max-width: 960px; margin: 0 auto; padding: 40px 24px; }
h1 { font-size: 28px; margin-bottom: 8px; }
h2 { font-size: 22px; margin: 32px 0 16px; padding-bottom: 8px; border-bottom: 2px solid var(--border); }
h3 { font-size: 16px; margin: 20px 0 8px; }
.meta { color: var(--muted); font-size: 14px; margin-bottom: 24px; }
.grade-box { display: inline-flex; align-items: center; gap: 16px; background: var(--surface);
  border: 1px solid var(--border); border-radius: 12px; padding: 20px 28px; margin: 16px 0; }
.grade { font-size: 48px; font-weight: 700; }
.grade-f, .grade-d { color: var(--fail); }
.grade-c { color: var(--medium); }
.grade-b, .grade-a { color: var(--pass); }
.grade-details { font-size: 14px; color: var(--muted); }
.grade-details strong { color: var(--text); font-size: 20px; }
table { width: 100%; border-collapse: collapse; margin: 12px 0 24px; font-size: 14px; }
th { background: var(--surface); text-align: left; padding: 10px 12px;
  border-bottom: 2px solid var(--border); font-weight: 600; }
td { padding: 10px 12px; border-bottom: 1px solid var(--border); vertical-align: top; }
.status-pass { color: var(--pass); font-weight: 600; }
.status-fail { color: var(--fail); font-weight: 600; }
.status-partial { color: var(--partial); font-weight: 600; }
.status-requires_policy, .status-policy { color: var(--policy); font-weight: 600; }
.status-not_assessed { color: var(--muted); }
.chip { display: inline-block; font-size: 11px; font-weight: 600; padding: 2px 8px;
  border-radius: 4px; text-transform: uppercase; }
.chip-soc2 { background: #eef2ff; color: #4338ca; }
.chip-iso { background: #ecfdf5; color: #047857; }
.chip-hipaa { background: #fff1f2; color: #be123c; }
.scorecard-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; margin: 16px 0 32px; }
.scorecard { background: var(--surface); border: 1px solid var(--border); border-radius: 10px; padding: 20px; }
.scorecard h4 { font-size: 12px; text-transform: uppercase; color: var(--muted);
  letter-spacing: 0.05em; margin-bottom: 6px; }
.scorecard .pct { font-size: 32px; font-weight: 700; }
.scorecard .sub { font-size: 12px; color: var(--muted); margin-top: 4px; }
code { background: var(--surface); padding: 2px 6px; border-radius: 4px; font-size: 13px; }
.footer { margin-top: 40px; padding-top: 16px; border-top: 1px solid var(--border);
  color: var(--muted); font-size: 13px; }
.callout { background: #eff6ff; border-left: 4px solid var(--low); padding: 12px 16px;
  border-radius: 6px; margin: 16px 0; font-size: 14px; }
.callout-warn { background: #fffbeb; border-left-color: var(--medium); }
ul.remediation { padding-left: 20px; }
ul.remediation li { margin: 6px 0; }
.finding { padding: 16px; margin: 12px 0; border-radius: 8px; }
.finding-title { font-weight: 600; margin-bottom: 6px; }
.finding-meta { font-size: 13px; color: var(--muted); margin-bottom: 6px; }
.finding-desc { font-size: 14px; margin-bottom: 8px; }
.finding-remediation { font-size: 14px; background: #f0fdf4; padding: 10px 12px; border-radius: 6px; border-left: 3px solid var(--pass); }
.finding-details { font-size: 13px; margin-top: 10px; background: var(--surface); padding: 12px; border-radius: 6px; border: 1px solid var(--border); }
.finding-details .details-section { margin-bottom: 8px; }
.finding-details table { font-size: 12px; margin: 4px 0 8px; }
.finding-details ul { padding-left: 18px; margin: 4px 0; font-size: 12px; }
.sev-critical { background: #fef2f2; border-left: 4px solid var(--critical); }
.sev-high { background: #fff7ed; border-left: 4px solid var(--high); }
.sev-medium { background: #fffbeb; border-left: 4px solid var(--medium); }
.sev-low { background: #eff6ff; border-left: 4px solid var(--low); }
.sev-info { background: var(--surface); border-left: 4px solid var(--info); }
.tag { display: inline-block; font-size: 11px; font-weight: 600; padding: 2px 8px; border-radius: 4px; text-transform: uppercase; }
.tag-critical { background: #fef2f2; color: var(--critical); }
.tag-high { background: #fff7ed; color: var(--high); }
.tag-medium { background: #fffbeb; color: var(--medium); }
.tag-low { background: #eff6ff; color: var(--low); }
.tag-info { background: var(--surface); color: var(--info); }
@media print { body { max-width: none; padding: 20px; } }
"""


def _escape(value: object) -> str:
    """HTML-escape any value, handling None safely."""
    return html.escape(str(value)) if value is not None else ""


def _wrap(title: str, body: str) -> str:
    """Wrap body content in a complete HTML document."""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{_escape(title)}</title>
<style>{_BASE_CSS}</style>
</head>
<body>
{body}
<div class="footer">Report generated by Shasta — Cloud Compliance Automation &nbsp;|&nbsp; {datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}</div>
</body>
</html>
"""


def _grade_class(grade: str) -> str:
    return f"grade-{grade.lower()}"


def _status_class(status: str) -> str:
    return f"status-{status}"


# ---------------------------------------------------------------------------
# ISO 27001 HTML report
# ---------------------------------------------------------------------------
def save_iso27001_html_report(scan: ScanResult, output_path: Path | str = "data/reports") -> Path:
    """Generate an ISO 27001 gap analysis report as HTML."""
    output_dir = Path(output_path)
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    filepath = output_dir / f"iso27001-gap-analysis-{scan.account_id}-{timestamp}.html"

    score = calculate_iso27001_score(scan.findings)
    controls = get_iso27001_control_summary(scan.findings)
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    rows = []
    for ctrl_id, data in sorted(controls.items()):
        if not (data["has_automated_checks"] or data["overall_status"] != "not_assessed"):
            continue
        equiv = ", ".join(data["soc2_equivalent"]) if data["soc2_equivalent"] else "-"
        rows.append(
            f"<tr>"
            f"<td><strong>{_escape(ctrl_id)}</strong></td>"
            f"<td>{_escape(data['title'])}</td>"
            f"<td>{_escape(data['theme'])}</td>"
            f"<td class='{_status_class(data['overall_status'])}'>"
            f"{_escape(data['overall_status'].upper())}</td>"
            f"<td>{data['pass_count']}</td><td>{data['fail_count']}</td>"
            f"<td><span class='chip chip-soc2'>{_escape(equiv)}</span></td>"
            f"</tr>"
        )

    failing_details = []
    for ctrl_id, data in sorted(controls.items()):
        if data["overall_status"] != "fail":
            continue
        findings_rows = "".join(
            f"<tr><td><code>{_escape(f.resource_id[-60:])}</code></td>"
            f"<td>{_escape(f.severity.value)}</td>"
            f"<td>{_escape(f.description[:150])}</td></tr>"
            for f in data["findings"]
            if f.status.value == "fail"
        )
        failing_details.append(
            f"<h3>{_escape(ctrl_id)}: {_escape(data['title'])}</h3>"
            f"<p><strong>Theme:</strong> {_escape(data['theme'])} &nbsp;|&nbsp; "
            f"<strong>SOC 2:</strong> {_escape(', '.join(data['soc2_equivalent']) or 'None')}</p>"
            f"<p>{_escape(data['guidance'])}</p>"
            f"<table><thead><tr><th>Resource</th><th>Severity</th><th>Description</th></tr></thead>"
            f"<tbody>{findings_rows}</tbody></table>"
        )

    policy_rows = "".join(
        f"<tr><td><strong>{_escape(k)}</strong></td><td>{_escape(v['title'])}</td>"
        f"<td>{_escape(v['guidance'])}</td></tr>"
        for k, v in sorted(controls.items())
        if v["overall_status"] == "requires_policy"
    )

    body = f"""
<h1>ISO 27001:2022 Gap Analysis</h1>
<div class="meta">
  <strong>AWS Account:</strong> {_escape(scan.account_id)} &nbsp;|&nbsp;
  <strong>Region:</strong> {_escape(scan.region)} &nbsp;|&nbsp;
  <strong>Generated:</strong> {generated}
</div>

<h2>Executive Summary</h2>
<div class="grade-box">
  <div class="grade {_grade_class(score.grade)}">{score.grade}</div>
  <div class="grade-details">
    <strong>{score.score_percentage}%</strong> compliance score<br>
    {score.passing} passing · {score.failing} failing · {score.partial} partial · {score.requires_policy} policy<br>
    {score.total_controls} total controls
  </div>
</div>

<div class="scorecard-grid">
  <div class="scorecard"><h4>Organizational (A.5)</h4>
    <div class="pct status-pass">{score.organizational_pass}</div>
    <div class="sub">{score.organizational_fail} failing</div></div>
  <div class="scorecard"><h4>People (A.6)</h4>
    <div class="pct status-pass">{score.people_pass}</div>
    <div class="sub">{score.people_fail} failing</div></div>
  <div class="scorecard"><h4>Technological (A.8)</h4>
    <div class="pct status-pass">{score.technological_pass}</div>
    <div class="sub">{score.technological_fail} failing</div></div>
</div>

<h2>Control Status</h2>
<table>
  <thead><tr><th>Control</th><th>Title</th><th>Theme</th><th>Status</th><th>Pass</th><th>Fail</th><th>SOC 2</th></tr></thead>
  <tbody>{"".join(rows)}</tbody>
</table>

<h2>Failing Controls — Detail</h2>
{"".join(failing_details) if failing_details else "<p>No failing controls.</p>"}

<h2>Controls Requiring Policy Documents</h2>
{"<table><thead><tr><th>Control</th><th>Title</th><th>Guidance</th></tr></thead><tbody>" + policy_rows + "</tbody></table>" if policy_rows else "<p>None.</p>"}
"""

    filepath.write_text(
        _wrap(f"ISO 27001 Gap Analysis — {scan.account_id}", body), encoding="utf-8"
    )
    return filepath


# ---------------------------------------------------------------------------
# HIPAA HTML report
# ---------------------------------------------------------------------------
def save_hipaa_html_report(scan: ScanResult, output_path: Path | str = "data/reports") -> Path:
    """Generate a HIPAA Security Rule gap analysis report as HTML."""
    output_dir = Path(output_path)
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    filepath = output_dir / f"hipaa-gap-analysis-{scan.account_id}-{timestamp}.html"

    score = calculate_hipaa_score(scan.findings)
    controls = get_hipaa_control_summary(scan.findings)
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    def _safeguard_table(safeguard: str) -> str:
        rows = []
        for ctrl_id, data in sorted(controls.items()):
            if data["safeguard"] != safeguard:
                continue
            if not (data["has_automated_checks"] or data["overall_status"] != "not_assessed"):
                continue
            rows.append(
                f"<tr><td><strong>{_escape(ctrl_id)}</strong></td>"
                f"<td>{_escape(data['title'])}</td>"
                f"<td class='{_status_class(data['overall_status'])}'>"
                f"{_escape(data['overall_status'].upper())}</td>"
                f"<td>{data['pass_count']}</td><td>{data['fail_count']}</td></tr>"
            )
        if not rows:
            return "<p>No controls assessed for this safeguard.</p>"
        return (
            "<table><thead><tr><th>Control</th><th>Title</th><th>Status</th>"
            "<th>Pass</th><th>Fail</th></tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table>"
        )

    failing_details = []
    for ctrl_id, data in sorted(controls.items()):
        if data["overall_status"] != "fail":
            continue
        findings_rows = "".join(
            f"<tr><td><code>{_escape(f.resource_id[-60:])}</code></td>"
            f"<td>{_escape(f.severity.value)}</td>"
            f"<td>{_escape(f.description[:150])}</td></tr>"
            for f in data["findings"]
            if f.status.value == "fail"
        )
        soc2 = ", ".join(data["soc2_equivalent"]) if data["soc2_equivalent"] else "None"
        iso = ", ".join(data["iso27001_equivalent"]) if data["iso27001_equivalent"] else "None"
        failing_details.append(
            f"<h3>{_escape(ctrl_id)}: {_escape(data['title'])}</h3>"
            f"<p><strong>Safeguard:</strong> {_escape(data['safeguard'])} &nbsp;|&nbsp; "
            f"<strong>SOC 2:</strong> <span class='chip chip-soc2'>{_escape(soc2)}</span> "
            f"<strong>ISO 27001:</strong> <span class='chip chip-iso'>{_escape(iso)}</span></p>"
            f"<p>{_escape(data['guidance'])}</p>"
            f"<table><thead><tr><th>Resource</th><th>Severity</th><th>Description</th></tr></thead>"
            f"<tbody>{findings_rows}</tbody></table>"
        )

    body = f"""
<h1>HIPAA Security Rule Gap Analysis</h1>
<div class="meta">
  <strong>AWS Account:</strong> {_escape(scan.account_id)} &nbsp;|&nbsp;
  <strong>Region:</strong> {_escape(scan.region)} &nbsp;|&nbsp;
  <strong>Generated:</strong> {generated}
</div>

<h2>Executive Summary</h2>
<div class="grade-box">
  <div class="grade {_grade_class(score.grade)}">{score.grade}</div>
  <div class="grade-details">
    <strong>{score.score_percentage}%</strong> compliance score<br>
    {score.passing} passing · {score.failing} failing · {score.partial} partial · {score.requires_policy} policy<br>
    {score.total_controls} total controls
  </div>
</div>

<div class="scorecard-grid">
  <div class="scorecard"><h4>Administrative (164.308)</h4>
    <div class="pct status-pass">{score.administrative_pass}</div>
    <div class="sub">{score.administrative_fail} failing</div></div>
  <div class="scorecard"><h4>Physical (164.310)</h4>
    <div class="pct status-pass">{score.physical_pass}</div>
    <div class="sub">{score.physical_fail} failing</div></div>
  <div class="scorecard"><h4>Technical (164.312)</h4>
    <div class="pct status-pass">{score.technical_pass}</div>
    <div class="sub">{score.technical_fail} failing</div></div>
</div>

<h2>Technical Safeguards (164.312)</h2>
<p>Most relevant safeguards for cloud-native ePHI environments.</p>
{_safeguard_table("Technical")}

<h2>Administrative Safeguards (164.308)</h2>
{_safeguard_table("Administrative")}

<h2>Physical Safeguards (164.310)</h2>
<div class="callout">Physical safeguards are largely handled by your cloud provider for cloud-native organizations. Ensure your BAA is signed and reference the provider's SOC 2 Type II report.</div>
{_safeguard_table("Physical")}

<h2>Failing Controls — Detail</h2>
{"".join(failing_details) if failing_details else "<p>No failing controls.</p>"}

<h2>PHI-Specific Recommendations</h2>
<ul class="remediation">
  <li><strong>Data Classification:</strong> Tag all resources containing ePHI with <code>data-classification=phi</code></li>
  <li><strong>Minimum Necessary Standard:</strong> Restrict ePHI access to the minimum necessary per role</li>
  <li><strong>Audit Log Retention:</strong> HIPAA requires 6-year retention for security logs</li>
  <li><strong>Business Associate Agreements:</strong> Verify signed BAAs with AWS and SaaS vendors handling ePHI</li>
  <li><strong>Encryption Key Management:</strong> Use customer-managed KMS keys for ePHI workloads</li>
  <li><strong>Incident Response:</strong> 60-day breach notification timeline for breaches affecting 500+ individuals</li>
  <li><strong>Risk Analysis:</strong> Conduct formal risk analysis annually</li>
  <li><strong>Workforce Training:</strong> HIPAA-specific training must be provided annually</li>
</ul>
"""

    filepath.write_text(_wrap(f"HIPAA Gap Analysis — {scan.account_id}", body), encoding="utf-8")
    return filepath


# ---------------------------------------------------------------------------
# Whitney AI Governance HTML report
# ---------------------------------------------------------------------------
def save_whitney_html_report(
    ai_findings: list[Finding],
    account_id: str,
    output_path: Path | str = "data/reports",
) -> Path:
    """Generate a Whitney AI governance report as HTML."""
    from shasta.compliance.ai.scorer import calculate_ai_governance_score

    output_dir = Path(output_path)
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    filepath = output_dir / f"whitney-ai-governance-{account_id}-{timestamp}.html"

    score = calculate_ai_governance_score(ai_findings)
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    def _findings_rows(findings: list[Finding], statuses: tuple[str, ...]) -> str:
        rows = []
        for f in findings:
            if f.status.value not in statuses:
                continue
            rows.append(
                f"<tr><td>{_escape(f.title)}</td>"
                f"<td class='{_status_class('fail' if f.status.value == 'fail' else 'pass')}'>"
                f"{_escape(f.severity.value.upper())}</td>"
                f"<td>{_escape(f.status.value.upper())}</td>"
                f"<td><code>{_escape(f.resource_id[-60:])}</code></td></tr>"
            )
        return "".join(rows) or "<tr><td colspan='4'>None</td></tr>"

    body = f"""
<h1>Whitney AI Governance Report</h1>
<div class="meta">
  <strong>AWS Account:</strong> {_escape(account_id)} &nbsp;|&nbsp;
  <strong>Generated:</strong> {generated}
</div>

<h2>Executive Summary</h2>
<div class="grade-box">
  <div class="grade {_grade_class(score.grade)}">{score.grade}</div>
  <div class="grade-details">
    <strong>{score.score_percentage}%</strong> ISO 42001 compliance<br>
    {score.passing} passing · {score.failing} failing · {score.requires_policy} policy<br>
    {len(ai_findings)} AI service findings total
  </div>
</div>

<div class="scorecard-grid">
  <div class="scorecard"><h4>ISO 42001</h4>
    <div class="pct">{score.score_percentage}%</div>
    <div class="sub">Grade {score.grade}</div></div>
  <div class="scorecard"><h4>EU AI Act</h4>
    <div class="pct">{score.eu_score_percentage}%</div>
    <div class="sub">{score.eu_passing} passing · {score.eu_failing} failing</div></div>
  <div class="scorecard"><h4>Total Findings</h4>
    <div class="pct">{len(ai_findings)}</div>
    <div class="sub">AI service assessments</div></div>
</div>

<h2>Failing Findings</h2>
<table>
  <thead><tr><th>Finding</th><th>Severity</th><th>Status</th><th>Resource</th></tr></thead>
  <tbody>{_findings_rows(ai_findings, ("fail",))}</tbody>
</table>

<h2>Passing Findings</h2>
<table>
  <thead><tr><th>Finding</th><th>Severity</th><th>Status</th><th>Resource</th></tr></thead>
  <tbody>{_findings_rows(ai_findings, ("pass",))}</tbody>
</table>

<h2>Not Applicable (No Resources)</h2>
<table>
  <thead><tr><th>Finding</th><th>Severity</th><th>Status</th><th>Resource</th></tr></thead>
  <tbody>{_findings_rows(ai_findings, ("not_applicable",))}</tbody>
</table>

<h2>ISO 42001 & EU AI Act Remediation Priorities</h2>
<div class="callout">
  <strong>Immediate actions:</strong> Enable Bedrock model invocation logging (EU AI Act Art. 12),
  create Bedrock guardrails with content filters (ISO 42001 10.1, EU AI Act Art. 15),
  and enable CloudTrail data events for AI services.
</div>
<div class="callout callout-warn">
  <strong>Short-term:</strong> Create VPC endpoint for Bedrock, document AI system inventory
  (ISO 42001 8.4, EU AI Act Art. 11), establish AI risk assessment process.
</div>
"""

    filepath.write_text(_wrap(f"Whitney AI Governance — {account_id}", body), encoding="utf-8")
    return filepath


def _build_finding_card(f: Finding) -> str:
    """Render a single finding as an HTML card with details."""
    sev = f.severity.value
    status = f.status.value

    frameworks = []
    if f.soc2_controls:
        frameworks.append(f"SOC 2: {', '.join(f.soc2_controls)}")
    if f.cis_azure_controls:
        frameworks.append(f"CIS Azure: {', '.join(f.cis_azure_controls)}")
    if f.cis_gcp_controls:
        frameworks.append(f"CIS GCP: {', '.join(f.cis_gcp_controls)}")
    if f.mcsb_controls:
        frameworks.append(f"MCSB: {', '.join(f.mcsb_controls)}")
    iso_ctrls = f.details.get("iso27001_controls", [])
    if iso_ctrls:
        frameworks.append(f"ISO 27001: {', '.join(iso_ctrls)}")
    hipaa_ctrls = f.details.get("hipaa_controls", [])
    if hipaa_ctrls:
        frameworks.append(f"HIPAA: {', '.join(hipaa_ctrls)}")
    fw_str = " &nbsp;|&nbsp; ".join(frameworks) if frameworks else ""

    card = f"""<div class="finding sev-{_escape(sev)}">
  <div class="finding-title">
    <span class="tag tag-{_escape(sev)}">{_escape(sev)}</span>
    <span class="tag" style="background:#e2e8f0;color:var(--text)">{_escape(status.upper())}</span>
    {_escape(f.title)}
  </div>
  <div class="finding-meta">{fw_str} &nbsp;|&nbsp; <code>{_escape(f.resource_id)}</code></div>
  <div class="finding-desc">{_escape(f.description)}</div>"""

    if f.remediation:
        card += f'\n  <div class="finding-remediation"><strong>Fix:</strong> {_escape(f.remediation)}</div>'

    card += _render_details_html(f.details)
    card += "\n</div>"
    return card


def _build_findings_section(findings: list[Finding]) -> str:
    """Build the full findings section grouped by status."""
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

    failed = sorted(
        [f for f in findings if f.status.value == "fail"],
        key=lambda f: severity_order.get(f.severity.value, 5),
    )
    not_assessed = [f for f in findings if f.status.value in ("not_assessed",)]
    passing = [f for f in findings if f.status.value == "pass"]
    na = [f for f in findings if f.status.value == "not_applicable"]

    parts = ["<h2>Detailed Findings</h2>"]

    if failed:
        parts.append(f"<h3>Failing ({len(failed)})</h3>")
        for f in failed:
            parts.append(_build_finding_card(f))

    if not_assessed:
        parts.append(f"<h3>Not Assessed — Insufficient Permissions ({len(not_assessed)})</h3>")
        parts.append(
            "<p>These checks could not run due to missing permissions. "
            "Grant the cloud account's read-only security, audit log, and inventory "
            "permissions to unlock them.</p>"
        )
        for f in not_assessed:
            parts.append(_build_finding_card(f))

    if passing:
        parts.append(f"<h3>Passing ({len(passing)})</h3>")
        for f in passing:
            parts.append(_build_finding_card(f))

    if na:
        parts.append(f"<h3>Not Applicable ({len(na)})</h3>")
        for f in na:
            parts.append(_build_finding_card(f))

    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Consolidated cross-framework HTML report
# ---------------------------------------------------------------------------
def save_consolidated_html_report(
    scan: ScanResult,
    ai_findings: list[Finding] | None = None,
    output_path: Path | str = "data/reports",
) -> Path:
    """Generate a consolidated cross-framework report (SOC 2 + ISO 27001 + HIPAA + Whitney)."""
    output_dir = Path(output_path)
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    filepath = output_dir / f"consolidated-cross-framework-{scan.account_id}-{timestamp}.html"

    soc2 = calculate_score(scan.findings)
    iso = calculate_iso27001_score(scan.findings)
    hipaa = calculate_hipaa_score(scan.findings)
    hipaa_ctrls = get_hipaa_control_summary(scan.findings)
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    whitney_html = ""
    if ai_findings:
        try:
            from shasta.compliance.ai.scorer import calculate_ai_governance_score

            wh = calculate_ai_governance_score(ai_findings)
            whitney_html = f"""
  <div class="scorecard"><h4>ISO 42001 (AI)</h4>
    <div class="pct {_status_class("fail" if wh.grade == "F" else "pass")}">{wh.score_percentage}%</div>
    <div class="sub">Grade {wh.grade} · {wh.passing} pass / {wh.failing} fail</div></div>"""
        except ImportError:
            pass

    # Cross-framework mapping rows — one row per HIPAA control that has SOC2/ISO equivalents
    mapping_rows = []
    for ctrl_id, data in sorted(hipaa_ctrls.items()):
        if not (data["soc2_equivalent"] or data["iso27001_equivalent"]):
            continue
        status = data["overall_status"]
        soc2_eq = ", ".join(data["soc2_equivalent"]) if data["soc2_equivalent"] else "-"
        iso_eq = ", ".join(data["iso27001_equivalent"]) if data["iso27001_equivalent"] else "-"
        mapping_rows.append(
            f"<tr><td><span class='chip chip-hipaa'>{_escape(ctrl_id)}</span></td>"
            f"<td>{_escape(data['title'])}</td>"
            f"<td><span class='chip chip-soc2'>{_escape(soc2_eq)}</span></td>"
            f"<td><span class='chip chip-iso'>{_escape(iso_eq)}</span></td>"
            f"<td class='{_status_class(status)}'>{_escape(status.upper())}</td></tr>"
        )

    summary = scan.summary
    total_findings = summary.total_findings if summary else len(scan.findings)
    total_passed = summary.passed if summary else 0
    total_failed = summary.failed if summary else 0

    body = f"""
<h1>Consolidated Cross-Framework Compliance Report</h1>
<div class="meta">
  <strong>AWS Account:</strong> {_escape(scan.account_id)} &nbsp;|&nbsp;
  <strong>Region:</strong> {_escape(scan.region)} &nbsp;|&nbsp;
  <strong>Generated:</strong> {generated}
</div>

<h2>Executive Summary</h2>
<p>{total_findings} total findings · {total_passed} passed · {total_failed} failed</p>

<div class="scorecard-grid">
  <div class="scorecard"><h4>SOC 2 Type II</h4>
    <div class="pct {_status_class("fail" if soc2.grade == "F" else "pass")}">{soc2.score_percentage}%</div>
    <div class="sub">Grade {soc2.grade} · {soc2.passing} pass / {soc2.failing} fail</div></div>
  <div class="scorecard"><h4>ISO 27001:2022</h4>
    <div class="pct {_status_class("fail" if iso.grade == "F" else "pass")}">{iso.score_percentage}%</div>
    <div class="sub">Grade {iso.grade} · {iso.passing} pass / {iso.failing} fail</div></div>
  <div class="scorecard"><h4>HIPAA Security</h4>
    <div class="pct {_status_class("fail" if hipaa.grade == "F" else "pass")}">{hipaa.score_percentage}%</div>
    <div class="sub">Grade {hipaa.grade} · {hipaa.passing} pass / {hipaa.failing} fail</div></div>
  {whitney_html}
</div>

<h2>Cross-Framework Control Mapping</h2>
<p>Each row shows how a single HIPAA control overlaps with SOC 2 and ISO 27001 equivalents.
Fixing one addresses all.</p>
<table>
  <thead><tr><th>HIPAA</th><th>Title</th><th>SOC 2 Equivalent</th><th>ISO 27001 Equivalent</th><th>Status</th></tr></thead>
  <tbody>{"".join(mapping_rows)}</tbody>
</table>

<h2>Overlap Analysis</h2>
<div class="callout">
  <strong>~80% of remediation work is shared across all 3 frameworks.</strong>
  Addressing the top quick-win fixes (MFA, encryption, VPC flow logs, security groups,
  CloudWatch alarms, Inspector vulnerabilities) will move all 3 scores simultaneously.
</div>

<h2>HIPAA-Specific Considerations</h2>
<ul class="remediation">
  <li><strong>Business Associate Agreements:</strong> Verify BAAs with AWS and all PHI-handling subprocessors</li>
  <li><strong>Minimum Necessary Standard:</strong> Implement least-privilege IAM for PHI resources</li>
  <li><strong>6-Year Log Retention:</strong> Configure CloudWatch and S3 log retention accordingly</li>
  <li><strong>PHI Data Classification:</strong> Tag PHI resources and apply encryption specifically</li>
  <li><strong>Breach Notification:</strong> 60-day timeline for breaches affecting 500+ individuals</li>
</ul>

{_build_findings_section(scan.findings)}

<h2>Generated Artifacts</h2>
<table>
  <thead><tr><th>Artifact</th><th>Path</th></tr></thead>
  <tbody>
    <tr><td>SOC 2 Report</td><td><code>data/reports/gap-analysis-*.html</code></td></tr>
    <tr><td>ISO 27001 Report</td><td><code>data/reports/iso27001-gap-analysis-*.html</code></td></tr>
    <tr><td>HIPAA Report</td><td><code>data/reports/hipaa-gap-analysis-*.html</code></td></tr>
    <tr><td>Whitney AI Report</td><td><code>data/reports/whitney-ai-governance-*.html</code></td></tr>
    <tr><td>Terraform Remediations</td><td><code>data/remediation/remediation.tf</code></td></tr>
    <tr><td>Compliance Policies (8)</td><td><code>data/policies/*.md</code></td></tr>
  </tbody>
</table>
"""

    filepath.write_text(
        _wrap(f"Consolidated Compliance Report — {scan.account_id}", body), encoding="utf-8"
    )
    return filepath
