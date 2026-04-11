"""AI governance compliance scoring engine for ISO 42001 and EU AI Act."""

from __future__ import annotations

from dataclasses import dataclass

from shasta.evidence.models import Finding
from whitney.compliance.mapper import (
    get_eu_ai_act_obligation_summary,
    get_iso42001_control_summary,
    get_mitre_atlas_summary,
    get_nist_ai_600_1_summary,
    get_nist_ai_rmf_summary,
    get_owasp_agentic_summary,
    get_owasp_llm_summary,
)


@dataclass
class AIGovernanceScore:
    """Overall AI governance compliance score."""

    # ISO 42001
    total_controls: int
    passing: int
    failing: int
    partial: int
    not_assessed: int
    requires_policy: int
    score_percentage: float  # 0-100, based on assessed controls only
    grade: str  # A, B, C, D, F

    # EU AI Act
    eu_total_obligations: int
    eu_passing: int
    eu_failing: int
    eu_partial: int
    eu_not_assessed: int
    eu_requires_policy: int
    eu_score_percentage: float
    eu_grade: str

    # OWASP LLM Top 10
    owasp_llm_total: int = 0
    owasp_llm_passing: int = 0
    owasp_llm_failing: int = 0
    owasp_llm_score: float = 0.0
    owasp_llm_grade: str = "A"

    # OWASP Agentic AI Top 10
    owasp_agentic_total: int = 0
    owasp_agentic_passing: int = 0
    owasp_agentic_failing: int = 0
    owasp_agentic_score: float = 0.0
    owasp_agentic_grade: str = "A"

    # NIST AI RMF
    nist_total: int = 0
    nist_passing: int = 0
    nist_failing: int = 0
    nist_requires_policy: int = 0
    nist_score: float = 0.0
    nist_grade: str = "A"

    # NIST AI 600-1 (GenAI Profile)
    nist_600_1_total: int = 0
    nist_600_1_passing: int = 0
    nist_600_1_failing: int = 0
    nist_600_1_requires_policy: int = 0
    nist_600_1_score: float = 0.0
    nist_600_1_grade: str = "A"

    # MITRE ATLAS
    atlas_total: int = 0
    atlas_passing: int = 0
    atlas_failing: int = 0
    atlas_score: float = 0.0
    atlas_grade: str = "A"

    # Combined
    combined_score: float = 0.0
    combined_grade: str = "A"


def calculate_ai_governance_score(findings: list[Finding]) -> AIGovernanceScore:
    """Calculate AI governance compliance score from findings.

    Scores findings against both ISO 42001 controls and EU AI Act obligations
    using the same algorithm as Shasta's SOC 2 scorer:
    (passing + partial * 0.5) / assessed * 100, with the zero-findings fix.
    """
    # ISO 42001 scoring
    iso_summary = get_iso42001_control_summary(findings)
    iso_total = len(iso_summary)
    iso_passing = sum(1 for c in iso_summary.values() if c["overall_status"] == "pass")
    iso_failing = sum(1 for c in iso_summary.values() if c["overall_status"] == "fail")
    iso_partial = sum(1 for c in iso_summary.values() if c["overall_status"] == "partial")
    iso_not_assessed = sum(1 for c in iso_summary.values() if c["overall_status"] == "not_assessed")
    iso_requires_policy = sum(
        1 for c in iso_summary.values() if c["overall_status"] == "requires_policy"
    )

    iso_assessed = iso_passing + iso_failing + iso_partial
    if iso_assessed > 0:
        iso_score = (iso_passing + iso_partial * 0.5) / iso_assessed * 100
    elif iso_not_assessed > 0 or iso_requires_policy > 0:
        iso_score = 100.0
    else:
        iso_score = 0.0
    iso_grade = _score_to_grade(iso_score)

    # EU AI Act scoring
    eu_summary = get_eu_ai_act_obligation_summary(findings)
    eu_total = len(eu_summary)
    eu_passing = sum(1 for o in eu_summary.values() if o["overall_status"] == "pass")
    eu_failing = sum(1 for o in eu_summary.values() if o["overall_status"] == "fail")
    eu_partial = sum(1 for o in eu_summary.values() if o["overall_status"] == "partial")
    eu_not_assessed = sum(1 for o in eu_summary.values() if o["overall_status"] == "not_assessed")
    eu_requires_policy = sum(
        1 for o in eu_summary.values() if o["overall_status"] == "requires_policy"
    )

    eu_assessed = eu_passing + eu_failing + eu_partial
    if eu_assessed > 0:
        eu_score = (eu_passing + eu_partial * 0.5) / eu_assessed * 100
    elif eu_not_assessed > 0 or eu_requires_policy > 0:
        eu_score = 100.0
    else:
        eu_score = 0.0
    eu_grade = _score_to_grade(eu_score)

    # OWASP LLM Top 10 scoring
    owasp_llm_summary = get_owasp_llm_summary(findings)
    owasp_llm_total = len(owasp_llm_summary)
    owasp_llm_passing = sum(1 for r in owasp_llm_summary.values() if r["overall_status"] == "pass")
    owasp_llm_failing = sum(1 for r in owasp_llm_summary.values() if r["overall_status"] == "fail")
    owasp_llm_partial = sum(
        1 for r in owasp_llm_summary.values() if r["overall_status"] == "partial"
    )
    owasp_llm_assessed = owasp_llm_passing + owasp_llm_failing + owasp_llm_partial
    owasp_llm_score = (
        (owasp_llm_passing + owasp_llm_partial * 0.5) / owasp_llm_assessed * 100
        if owasp_llm_assessed > 0
        else 100.0
    )
    owasp_llm_grade = _score_to_grade(owasp_llm_score)

    # OWASP Agentic AI Top 10 scoring
    owasp_ag_summary = get_owasp_agentic_summary(findings)
    owasp_ag_total = len(owasp_ag_summary)
    owasp_ag_passing = sum(1 for r in owasp_ag_summary.values() if r["overall_status"] == "pass")
    owasp_ag_failing = sum(1 for r in owasp_ag_summary.values() if r["overall_status"] == "fail")
    owasp_ag_partial = sum(1 for r in owasp_ag_summary.values() if r["overall_status"] == "partial")
    owasp_ag_assessed = owasp_ag_passing + owasp_ag_failing + owasp_ag_partial
    owasp_ag_score = (
        (owasp_ag_passing + owasp_ag_partial * 0.5) / owasp_ag_assessed * 100
        if owasp_ag_assessed > 0
        else 100.0
    )
    owasp_ag_grade = _score_to_grade(owasp_ag_score)

    # NIST AI RMF scoring
    nist_summary = get_nist_ai_rmf_summary(findings)
    nist_total = len(nist_summary)
    nist_passing = sum(1 for c in nist_summary.values() if c["overall_status"] == "pass")
    nist_failing = sum(1 for c in nist_summary.values() if c["overall_status"] == "fail")
    nist_partial = sum(1 for c in nist_summary.values() if c["overall_status"] == "partial")
    nist_rp = sum(1 for c in nist_summary.values() if c["overall_status"] == "requires_policy")
    nist_assessed = nist_passing + nist_failing + nist_partial
    if nist_assessed > 0:
        nist_score = (nist_passing + nist_partial * 0.5) / nist_assessed * 100
    elif nist_rp > 0:
        nist_score = 100.0
    else:
        nist_score = 0.0
    nist_grade = _score_to_grade(nist_score)

    # NIST AI 600-1 scoring
    nist_600_1_summary = get_nist_ai_600_1_summary(findings)
    nist_600_1_total = len(nist_600_1_summary)
    nist_600_1_passing = sum(
        1 for r in nist_600_1_summary.values() if r["overall_status"] == "pass"
    )
    nist_600_1_failing = sum(
        1 for r in nist_600_1_summary.values() if r["overall_status"] == "fail"
    )
    nist_600_1_partial = sum(
        1 for r in nist_600_1_summary.values() if r["overall_status"] == "partial"
    )
    nist_600_1_rp = sum(
        1 for r in nist_600_1_summary.values() if r["overall_status"] == "requires_policy"
    )
    nist_600_1_assessed = nist_600_1_passing + nist_600_1_failing + nist_600_1_partial
    if nist_600_1_assessed > 0:
        nist_600_1_score = (
            (nist_600_1_passing + nist_600_1_partial * 0.5) / nist_600_1_assessed * 100
        )
    elif nist_600_1_rp > 0:
        nist_600_1_score = 100.0
    else:
        nist_600_1_score = 0.0
    nist_600_1_grade = _score_to_grade(nist_600_1_score)

    # MITRE ATLAS scoring
    atlas_summary = get_mitre_atlas_summary(findings)
    atlas_total = len(atlas_summary)
    atlas_passing = sum(1 for t in atlas_summary.values() if t["overall_status"] == "pass")
    atlas_failing = sum(1 for t in atlas_summary.values() if t["overall_status"] == "fail")
    atlas_partial = sum(1 for t in atlas_summary.values() if t["overall_status"] == "partial")
    atlas_assessed = atlas_passing + atlas_failing + atlas_partial
    atlas_score = (
        (atlas_passing + atlas_partial * 0.5) / atlas_assessed * 100
        if atlas_assessed > 0
        else 100.0
    )
    atlas_grade = _score_to_grade(atlas_score)

    # Combined score (weighted average of all frameworks with assessed controls)
    total_assessed = (
        iso_assessed
        + eu_assessed
        + owasp_llm_assessed
        + owasp_ag_assessed
        + nist_assessed
        + nist_600_1_assessed
        + atlas_assessed
    )
    if total_assessed > 0:
        combined_passing = (
            iso_passing
            + eu_passing
            + owasp_llm_passing
            + owasp_ag_passing
            + nist_passing
            + nist_600_1_passing
            + atlas_passing
        )
        combined_partial = (
            iso_partial
            + eu_partial
            + owasp_llm_partial
            + owasp_ag_partial
            + nist_partial
            + nist_600_1_partial
            + atlas_partial
        )
        combined_score = (combined_passing + combined_partial * 0.5) / total_assessed * 100
    elif (iso_not_assessed + eu_not_assessed) > 0 or (
        iso_requires_policy + eu_requires_policy + nist_rp + nist_600_1_rp
    ) > 0:
        combined_score = 100.0
    else:
        combined_score = 0.0
    combined_grade = _score_to_grade(combined_score)

    return AIGovernanceScore(
        total_controls=iso_total,
        passing=iso_passing,
        failing=iso_failing,
        partial=iso_partial,
        not_assessed=iso_not_assessed,
        requires_policy=iso_requires_policy,
        score_percentage=round(iso_score, 1),
        grade=iso_grade,
        eu_total_obligations=eu_total,
        eu_passing=eu_passing,
        eu_failing=eu_failing,
        eu_partial=eu_partial,
        eu_not_assessed=eu_not_assessed,
        eu_requires_policy=eu_requires_policy,
        eu_score_percentage=round(eu_score, 1),
        eu_grade=eu_grade,
        owasp_llm_total=owasp_llm_total,
        owasp_llm_passing=owasp_llm_passing,
        owasp_llm_failing=owasp_llm_failing,
        owasp_llm_score=round(owasp_llm_score, 1),
        owasp_llm_grade=owasp_llm_grade,
        owasp_agentic_total=owasp_ag_total,
        owasp_agentic_passing=owasp_ag_passing,
        owasp_agentic_failing=owasp_ag_failing,
        owasp_agentic_score=round(owasp_ag_score, 1),
        owasp_agentic_grade=owasp_ag_grade,
        nist_total=nist_total,
        nist_passing=nist_passing,
        nist_failing=nist_failing,
        nist_requires_policy=nist_rp,
        nist_score=round(nist_score, 1),
        nist_grade=nist_grade,
        nist_600_1_total=nist_600_1_total,
        nist_600_1_passing=nist_600_1_passing,
        nist_600_1_failing=nist_600_1_failing,
        nist_600_1_requires_policy=nist_600_1_rp,
        nist_600_1_score=round(nist_600_1_score, 1),
        nist_600_1_grade=nist_600_1_grade,
        atlas_total=atlas_total,
        atlas_passing=atlas_passing,
        atlas_failing=atlas_failing,
        atlas_score=round(atlas_score, 1),
        atlas_grade=atlas_grade,
        combined_score=round(combined_score, 1),
        combined_grade=combined_grade,
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
