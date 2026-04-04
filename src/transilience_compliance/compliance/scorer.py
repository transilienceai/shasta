"""Compliance scoring engine for SOC 2 gap analysis."""

from __future__ import annotations

from dataclasses import dataclass

from transilience_compliance.compliance.mapper import get_control_summary
from transilience_compliance.evidence.models import Finding


@dataclass
class ComplianceScore:
    """Overall compliance score for a scan."""

    total_controls: int
    passing: int
    failing: int
    partial: int
    not_assessed: int
    requires_policy: int
    score_percentage: float  # 0-100, based on assessed controls only
    grade: str  # A, B, C, D, F

    total_findings: int
    findings_passed: int
    findings_failed: int
    findings_partial: int


def calculate_score(findings: list[Finding]) -> ComplianceScore:
    """Calculate an overall compliance score from findings."""
    control_summary = get_control_summary(findings)

    total = len(control_summary)
    passing = sum(1 for c in control_summary.values() if c["overall_status"] == "pass")
    failing = sum(1 for c in control_summary.values() if c["overall_status"] == "fail")
    partial = sum(1 for c in control_summary.values() if c["overall_status"] == "partial")
    not_assessed = sum(1 for c in control_summary.values() if c["overall_status"] == "not_assessed")
    requires_policy = sum(1 for c in control_summary.values() if c["overall_status"] == "requires_policy")

    # Score based on assessed controls only (partial counts as half)
    assessed = passing + failing + partial
    if assessed > 0:
        score = ((passing + partial * 0.5) / assessed) * 100
    else:
        score = 0.0

    grade = _score_to_grade(score)

    findings_passed = sum(1 for f in findings if f.status.value == "pass")
    findings_failed = sum(1 for f in findings if f.status.value == "fail")
    findings_partial = sum(1 for f in findings if f.status.value == "partial")

    return ComplianceScore(
        total_controls=total,
        passing=passing,
        failing=failing,
        partial=partial,
        not_assessed=not_assessed,
        requires_policy=requires_policy,
        score_percentage=round(score, 1),
        grade=grade,
        total_findings=len(findings),
        findings_passed=findings_passed,
        findings_failed=findings_failed,
        findings_partial=findings_partial,
    )


def _score_to_grade(score: float) -> str:
    if score >= 90:
        return "A"
    elif score >= 80:
        return "B"
    elif score >= 70:
        return "C"
    elif score >= 60:
        return "D"
    else:
        return "F"
