"""Compliance drift detection — compares current scan to previous scan.

Surfaces:
  - New findings (regressions)
  - Resolved findings (improvements)
  - Score changes over time
  - Trend direction
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from shasta.compliance.scorer import calculate_score, ComplianceScore
from shasta.evidence.models import ComplianceStatus, Finding, ScanResult


@dataclass
class DriftFinding:
    """A finding that changed between scans."""

    check_id: str
    title: str
    resource_id: str
    severity: str
    soc2_controls: list[str]
    change_type: str  # "new", "resolved", "unchanged"


@dataclass
class DriftReport:
    """Comparison between two compliance scans."""

    current_scan_id: str
    previous_scan_id: str
    current_date: str
    previous_date: str

    current_score: ComplianceScore
    previous_score: ComplianceScore
    score_delta: float  # positive = improvement

    new_findings: list[DriftFinding] = field(default_factory=list)
    resolved_findings: list[DriftFinding] = field(default_factory=list)
    unchanged_findings: int = 0

    trend: str = ""  # "improving", "degrading", "stable"


def detect_drift(current: ScanResult, previous: ScanResult) -> DriftReport:
    """Compare two scans and produce a drift report."""
    current_score = calculate_score(current.findings)
    previous_score = calculate_score(previous.findings)
    score_delta = current_score.score_percentage - previous_score.score_percentage

    # Build finding fingerprints for comparison
    # Key: (check_id, resource_id) — uniquely identifies a finding
    def _fingerprint(f: Finding) -> tuple[str, str]:
        return (f.check_id, f.resource_id)

    current_failed = {
        _fingerprint(f): f
        for f in current.findings
        if f.status in (ComplianceStatus.FAIL, ComplianceStatus.PARTIAL)
    }
    previous_failed = {
        _fingerprint(f): f
        for f in previous.findings
        if f.status in (ComplianceStatus.FAIL, ComplianceStatus.PARTIAL)
    }

    # New findings = in current but not in previous
    new_findings = []
    for fp, f in current_failed.items():
        if fp not in previous_failed:
            new_findings.append(DriftFinding(
                check_id=f.check_id,
                title=f.title,
                resource_id=f.resource_id,
                severity=f.severity.value,
                soc2_controls=f.soc2_controls,
                change_type="new",
            ))

    # Resolved findings = in previous but not in current
    resolved_findings = []
    for fp, f in previous_failed.items():
        if fp not in current_failed:
            resolved_findings.append(DriftFinding(
                check_id=f.check_id,
                title=f.title,
                resource_id=f.resource_id,
                severity=f.severity.value,
                soc2_controls=f.soc2_controls,
                change_type="resolved",
            ))

    # Unchanged
    unchanged = len(set(current_failed.keys()) & set(previous_failed.keys()))

    # Trend
    if score_delta > 2:
        trend = "improving"
    elif score_delta < -2:
        trend = "degrading"
    else:
        trend = "stable"

    return DriftReport(
        current_scan_id=current.id,
        previous_scan_id=previous.id,
        current_date=current.started_at.isoformat() if isinstance(current.started_at, datetime) else str(current.started_at),
        previous_date=previous.started_at.isoformat() if isinstance(previous.started_at, datetime) else str(previous.started_at),
        current_score=current_score,
        previous_score=previous_score,
        score_delta=round(score_delta, 1),
        new_findings=new_findings,
        resolved_findings=resolved_findings,
        unchanged_findings=unchanged,
        trend=trend,
    )


def format_drift_summary(report: DriftReport) -> str:
    """Format a drift report as a readable summary string."""
    lines = [
        "# Compliance Drift Report",
        "",
        f"**Previous scan:** {report.previous_date}",
        f"**Current scan:** {report.current_date}",
        "",
        "## Score Change",
        "",
        f"| Metric | Previous | Current | Delta |",
        f"|--------|----------|---------|-------|",
        f"| Score | {report.previous_score.score_percentage}% | {report.current_score.score_percentage}% | {'+' if report.score_delta >= 0 else ''}{report.score_delta}% |",
        f"| Grade | {report.previous_score.grade} | {report.current_score.grade} | {'improved' if report.score_delta > 0 else 'declined' if report.score_delta < 0 else 'unchanged'} |",
        f"| Failed findings | {report.previous_score.findings_failed} | {report.current_score.findings_failed} | {'+' if report.current_score.findings_failed > report.previous_score.findings_failed else ''}{report.current_score.findings_failed - report.previous_score.findings_failed} |",
        "",
        f"**Trend:** {report.trend.upper()}",
        "",
    ]

    if report.new_findings:
        lines.append(f"## New Findings ({len(report.new_findings)} regressions)")
        lines.append("")
        for f in report.new_findings:
            lines.append(f"- **{f.severity.upper()}** | {f.title} | `{f.resource_id}` | SOC2: {', '.join(f.soc2_controls)}")
        lines.append("")

    if report.resolved_findings:
        lines.append(f"## Resolved Findings ({len(report.resolved_findings)} improvements)")
        lines.append("")
        for f in report.resolved_findings:
            lines.append(f"- ~~{f.title}~~ | `{f.resource_id}`")
        lines.append("")

    lines.append(f"**Unchanged failures:** {report.unchanged_findings}")

    return "\n".join(lines)
