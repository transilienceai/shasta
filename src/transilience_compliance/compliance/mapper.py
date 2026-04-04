"""Maps AWS findings to SOC 2 controls and enriches findings with control context."""

from __future__ import annotations

from transilience_compliance.compliance.framework import SOC2_CONTROLS, get_controls_for_check
from transilience_compliance.evidence.models import Finding


def enrich_findings_with_controls(findings: list[Finding]) -> list[Finding]:
    """Enrich findings that don't have SOC 2 control mappings.

    If a finding already has soc2_controls populated (set by the check
    function), this is a no-op for that finding. Otherwise, it looks up
    the mapping from the framework.
    """
    for finding in findings:
        if not finding.soc2_controls:
            controls = get_controls_for_check(finding.check_id)
            finding.soc2_controls = [c.id for c in controls]
    return findings


def get_control_summary(findings: list[Finding]) -> dict[str, dict]:
    """Aggregate findings by SOC 2 control.

    Returns a dict keyed by control ID with:
      - control metadata (title, description, guidance)
      - list of related findings
      - overall status (worst-case across findings)
      - counts of pass/fail/partial
    """
    summary: dict[str, dict] = {}

    # Initialize all known controls
    for ctrl_id, ctrl in SOC2_CONTROLS.items():
        summary[ctrl_id] = {
            "id": ctrl_id,
            "title": ctrl.title,
            "category": ctrl.category.value,
            "guidance": ctrl.guidance,
            "requires_policy": ctrl.requires_policy,
            "has_automated_checks": bool(ctrl.check_ids),
            "findings": [],
            "pass_count": 0,
            "fail_count": 0,
            "partial_count": 0,
            "overall_status": "not_assessed",
        }

    # Map findings to controls
    for finding in findings:
        for ctrl_id in finding.soc2_controls:
            if ctrl_id not in summary:
                continue
            summary[ctrl_id]["findings"].append(finding)
            match finding.status.value:
                case "pass":
                    summary[ctrl_id]["pass_count"] += 1
                case "fail":
                    summary[ctrl_id]["fail_count"] += 1
                case "partial":
                    summary[ctrl_id]["partial_count"] += 1

    # Determine overall status per control
    for ctrl_id, data in summary.items():
        if data["fail_count"] > 0:
            data["overall_status"] = "fail"
        elif data["partial_count"] > 0:
            data["overall_status"] = "partial"
        elif data["pass_count"] > 0:
            data["overall_status"] = "pass"
        elif data["requires_policy"] and not data["has_automated_checks"]:
            data["overall_status"] = "requires_policy"
        else:
            data["overall_status"] = "not_assessed"

    return summary
