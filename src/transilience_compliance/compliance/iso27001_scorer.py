"""ISO 27001 compliance scoring engine."""

from __future__ import annotations

from dataclasses import dataclass

from transilience_compliance.compliance.iso27001_mapper import get_iso27001_control_summary
from transilience_compliance.evidence.models import Finding


@dataclass
class ISO27001Score:
    """Overall ISO 27001 compliance score."""

    total_controls: int
    passing: int
    failing: int
    partial: int
    not_assessed: int
    requires_policy: int
    score_percentage: float
    grade: str
    # By theme
    organizational_pass: int = 0
    organizational_fail: int = 0
    people_pass: int = 0
    people_fail: int = 0
    technological_pass: int = 0
    technological_fail: int = 0


def calculate_iso27001_score(findings: list[Finding]) -> ISO27001Score:
    """Calculate ISO 27001 compliance score from findings."""
    control_summary = get_iso27001_control_summary(findings)

    total = len(control_summary)
    passing = sum(1 for c in control_summary.values() if c["overall_status"] == "pass")
    failing = sum(1 for c in control_summary.values() if c["overall_status"] == "fail")
    partial = sum(1 for c in control_summary.values() if c["overall_status"] == "partial")
    not_assessed = sum(1 for c in control_summary.values() if c["overall_status"] == "not_assessed")
    requires_policy = sum(1 for c in control_summary.values() if c["overall_status"] == "requires_policy")

    assessed = passing + failing + partial
    score = ((passing + partial * 0.5) / assessed * 100) if assessed > 0 else 0.0
    grade = _score_to_grade(score)

    # By theme
    org_pass = sum(1 for c in control_summary.values() if c["theme"] == "Organizational" and c["overall_status"] == "pass")
    org_fail = sum(1 for c in control_summary.values() if c["theme"] == "Organizational" and c["overall_status"] == "fail")
    ppl_pass = sum(1 for c in control_summary.values() if c["theme"] == "People" and c["overall_status"] == "pass")
    ppl_fail = sum(1 for c in control_summary.values() if c["theme"] == "People" and c["overall_status"] == "fail")
    tech_pass = sum(1 for c in control_summary.values() if c["theme"] == "Technological" and c["overall_status"] == "pass")
    tech_fail = sum(1 for c in control_summary.values() if c["theme"] == "Technological" and c["overall_status"] == "fail")

    return ISO27001Score(
        total_controls=total,
        passing=passing,
        failing=failing,
        partial=partial,
        not_assessed=not_assessed,
        requires_policy=requires_policy,
        score_percentage=round(score, 1),
        grade=grade,
        organizational_pass=org_pass,
        organizational_fail=org_fail,
        people_pass=ppl_pass,
        people_fail=ppl_fail,
        technological_pass=tech_pass,
        technological_fail=tech_fail,
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
