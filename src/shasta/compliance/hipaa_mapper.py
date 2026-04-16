"""Maps cloud findings to HIPAA Security Rule controls."""

from __future__ import annotations

from shasta.compliance._status import apply_control_status
from shasta.compliance.hipaa import HIPAA_CONTROLS, get_hipaa_controls_for_check
from shasta.evidence.models import Finding


def enrich_findings_with_hipaa(findings: list[Finding]) -> list[Finding]:
    """Add hipaa_controls field to findings based on check_id mapping.

    Stores the list of HIPAA control IDs in ``finding.details["hipaa_controls"]``
    so downstream consumers (scorer, report) can access the mapping without
    re-computing it.
    """
    for finding in findings:
        controls = get_hipaa_controls_for_check(finding.check_id)
        finding.hipaa_controls = [c.id for c in controls]
    return findings


def get_hipaa_control_summary(findings: list[Finding]) -> dict[str, dict]:
    """Aggregate findings by HIPAA control.

    Returns a dict keyed by control ID with per-control status, finding counts,
    and cross-reference information. Mirrors ``iso27001_mapper.get_iso27001_control_summary``.
    """
    summary: dict[str, dict] = {}

    for ctrl_id, ctrl in HIPAA_CONTROLS.items():
        summary[ctrl_id] = {
            "id": ctrl_id,
            "title": ctrl.title,
            "safeguard": ctrl.safeguard.value,
            "guidance": ctrl.guidance,
            "requires_policy": ctrl.requires_policy,
            "has_automated_checks": bool(ctrl.check_ids),
            "soc2_equivalent": ctrl.soc2_equivalent,
            "iso27001_equivalent": ctrl.iso27001_equivalent,
            "findings": [],
            "pass_count": 0,
            "fail_count": 0,
            "partial_count": 0,
            "overall_status": "not_assessed",
        }

    # Map findings to controls via check_id
    for finding in findings:
        controls = get_hipaa_controls_for_check(finding.check_id)
        for ctrl in controls:
            if ctrl.id in summary:
                summary[ctrl.id]["findings"].append(finding)
                match finding.status.value:
                    case "pass":
                        summary[ctrl.id]["pass_count"] += 1
                    case "fail":
                        summary[ctrl.id]["fail_count"] += 1
                    case "partial":
                        summary[ctrl.id]["partial_count"] += 1

    return apply_control_status(summary)
