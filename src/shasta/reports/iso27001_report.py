"""ISO 27001:2022 gap analysis report generator."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from shasta.compliance.iso27001_mapper import get_iso27001_control_summary
from shasta.compliance.iso27001_scorer import calculate_iso27001_score
from shasta.evidence.models import ScanResult
from shasta.reports.generator import _provider_labels


def save_iso27001_markdown_report(
    scan: ScanResult, output_path: Path | str = "data/reports"
) -> Path:
    """Generate and save an ISO 27001 gap analysis report."""
    output_dir = Path(output_path)
    output_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    filepath = output_dir / f"iso27001-gap-analysis-{scan.account_id}-{timestamp}.md"

    score = calculate_iso27001_score(scan.findings)
    controls = get_iso27001_control_summary(scan.findings)
    labels = _provider_labels(scan.cloud_provider)

    status_icon = {
        "pass": "PASS",
        "fail": "FAIL",
        "partial": "PARTIAL",
        "requires_policy": "POLICY",
        "not_assessed": "N/A",
    }

    lines = [
        "# ISO 27001:2022 Gap Analysis Report",
        "",
        f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        f"**{labels['account_label']}:** {scan.account_id}",
        f"**Region:** {scan.region}",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        f"**Compliance Score: {score.score_percentage}% (Grade {score.grade})**",
        "",
        "| Metric | Count |",
        "|--------|-------|",
        f"| Total Controls Assessed | {score.total_controls} |",
        f"| Passing | {score.passing} |",
        f"| Failing | {score.failing} |",
        f"| Partial | {score.partial} |",
        f"| Requires Policy | {score.requires_policy} |",
        f"| Not Assessed | {score.not_assessed} |",
        "",
        "### By Theme",
        "",
        "| Theme | Passing | Failing |",
        "|-------|---------|---------|",
        f"| Organizational (A.5) | {score.organizational_pass} | {score.organizational_fail} |",
        f"| People (A.6) | {score.people_pass} | {score.people_fail} |",
        f"| Technological (A.8) | {score.technological_pass} | {score.technological_fail} |",
        "",
        "---",
        "",
        "## Control Status",
        "",
        "| Control | Title | Theme | Status | Pass | Fail | SOC 2 Equivalent |",
        "|---------|-------|-------|--------|------|------|-----------------|",
    ]

    for ctrl_id, data in sorted(controls.items()):
        if data["has_automated_checks"] or data["overall_status"] not in ("not_assessed",):
            equiv = ", ".join(data["soc2_equivalent"]) if data["soc2_equivalent"] else "-"
            lines.append(
                f"| {ctrl_id} | {data['title']} | {data['theme']} | {status_icon.get(data['overall_status'], data['overall_status'])} | {data['pass_count']} | {data['fail_count']} | {equiv} |"
            )

    lines.extend(["", "---", "", "## Failing Controls — Detail", ""])

    for ctrl_id, data in sorted(controls.items()):
        if data["overall_status"] != "fail":
            continue

        lines.extend(
            [
                f"### {ctrl_id}: {data['title']}",
                "",
                f"**Theme:** {data['theme']}",
                f"**Status:** FAIL ({data['fail_count']} failing, {data['pass_count']} passing)",
                f"**SOC 2 Equivalent:** {', '.join(data['soc2_equivalent']) or 'None'}",
                "",
                f"**Guidance:** {data['guidance']}",
                "",
                "**Findings:**",
                "",
                "| Resource | Severity | Description |",
                "|----------|----------|-------------|",
            ]
        )

        for f in data["findings"]:
            if f.status.value == "fail":
                desc = f.description[:100] + "..." if len(f.description) > 100 else f.description
                lines.append(f"| `{f.resource_id[-50:]}` | {f.severity.value} | {desc} |")

        lines.extend(["", "---", ""])

    # Policy-required controls
    policy_controls = {
        k: v for k, v in controls.items() if v["overall_status"] == "requires_policy"
    }
    if policy_controls:
        lines.extend(["", "## Controls Requiring Policy Documents", ""])
        lines.append("| Control | Title | Guidance |")
        lines.append("|---------|-------|----------|")
        for ctrl_id, data in sorted(policy_controls.items()):
            lines.append(f"| {ctrl_id} | {data['title']} | {data['guidance']} |")
        lines.extend(["", "Use `/policy-gen` to generate the required policy documents.", ""])

    # SOC 2 cross-reference
    lines.extend(
        [
            "---",
            "",
            "## SOC 2 Cross-Reference",
            "",
            "If you are also pursuing SOC 2, the following controls overlap:",
            "",
            "| ISO 27001 | SOC 2 | Status | Fixing one fixes both |",
            "|-----------|-------|--------|----------------------|",
        ]
    )

    for ctrl_id, data in sorted(controls.items()):
        if data["soc2_equivalent"] and data["overall_status"] in ("pass", "fail", "partial"):
            lines.append(
                f"| {ctrl_id} ({data['title'][:30]}) | {', '.join(data['soc2_equivalent'])} | {status_icon.get(data['overall_status'])} | Yes |"
            )

    lines.extend(
        [
            "",
            "---",
            "",
            "*Report generated by Shasta — Cloud Compliance Automation*",
        ]
    )

    filepath.write_text("\n".join(lines), encoding="utf-8")
    return filepath
