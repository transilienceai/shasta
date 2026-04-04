"""Maps AWS findings to ISO 27001:2022 Annex A controls."""

from __future__ import annotations

from transilience_compliance.compliance.iso27001 import ISO27001_CONTROLS, get_iso27001_controls_for_check
from transilience_compliance.evidence.models import Finding


def enrich_findings_with_iso27001(findings: list[Finding]) -> list[Finding]:
    """Add iso27001_controls field to findings based on check_id mapping."""
    for finding in findings:
        controls = get_iso27001_controls_for_check(finding.check_id)
        # Store in details since Finding model uses soc2_controls for SOC 2
        finding.details["iso27001_controls"] = [c.id for c in controls]
    return findings


def get_iso27001_control_summary(findings: list[Finding]) -> dict[str, dict]:
    """Aggregate findings by ISO 27001 control (mirrors mapper.get_control_summary)."""
    summary: dict[str, dict] = {}

    for ctrl_id, ctrl in ISO27001_CONTROLS.items():
        summary[ctrl_id] = {
            "id": ctrl_id,
            "title": ctrl.title,
            "theme": ctrl.theme.value,
            "guidance": ctrl.guidance,
            "requires_policy": ctrl.requires_policy,
            "has_automated_checks": bool(ctrl.check_ids),
            "soc2_equivalent": ctrl.soc2_equivalent,
            "findings": [],
            "pass_count": 0,
            "fail_count": 0,
            "partial_count": 0,
            "overall_status": "not_assessed",
        }

    # Map findings to controls via check_id
    for finding in findings:
        controls = get_iso27001_controls_for_check(finding.check_id)
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

    # Determine overall status
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
