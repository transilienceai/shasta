"""HIPAA Security Rule gap analysis report generator."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from shasta.compliance.hipaa_mapper import get_hipaa_control_summary
from shasta.compliance.hipaa_scorer import calculate_hipaa_score
from shasta.evidence.models import ScanResult
from shasta.reports.generator import _provider_labels


def save_hipaa_report(scan: ScanResult, output_path: Path | str = "data/reports") -> Path:
    """Generate and save a HIPAA Security Rule gap analysis report.

    Produces a Markdown report organized by safeguard type with
    executive summary, per-safeguard breakdowns, failing control details,
    PHI-specific recommendations, and cross-references to SOC 2 and ISO 27001.
    """
    output_dir = Path(output_path)
    output_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    filepath = output_dir / f"hipaa-gap-analysis-{scan.account_id}-{timestamp}.md"

    score = calculate_hipaa_score(scan.findings)
    controls = get_hipaa_control_summary(scan.findings)
    labels = _provider_labels(scan.cloud_provider)

    status_icon = {
        "pass": "PASS",
        "fail": "FAIL",
        "partial": "PARTIAL",
        "requires_policy": "POLICY",
        "not_assessed": "N/A",
    }

    lines = [
        "# HIPAA Security Rule Gap Analysis Report",
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
        "### By Safeguard",
        "",
        "| Safeguard | Passing | Failing |",
        "|-----------|---------|---------|",
        f"| Administrative (164.308) | {score.administrative_pass} | {score.administrative_fail} |",
        f"| Physical (164.310) | {score.physical_pass} | {score.physical_fail} |",
        f"| Technical (164.312) | {score.technical_pass} | {score.technical_fail} |",
        "",
        "---",
        "",
    ]

    # ---- Technical Safeguards (most relevant for cloud) ----
    lines.extend(
        [
            "## Technical Safeguards (164.312)",
            "",
            "These are the most relevant safeguards for cloud-native ePHI environments.",
            "",
            "| Control | Title | Status | Pass | Fail |",
            "|---------|-------|--------|------|------|",
        ]
    )

    for ctrl_id, data in sorted(controls.items()):
        if data["safeguard"] == "Technical" and (
            data["has_automated_checks"] or data["overall_status"] != "not_assessed"
        ):
            lines.append(
                f"| {ctrl_id} | {data['title']} | {status_icon.get(data['overall_status'], data['overall_status'])} | {data['pass_count']} | {data['fail_count']} |"
            )

    lines.extend(["", "---", ""])

    # ---- Administrative Safeguards ----
    lines.extend(
        [
            "## Administrative Safeguards (164.308)",
            "",
            "Administrative safeguards cover security management, workforce security, and contingency planning. Many require documented policies.",
            "",
            "| Control | Title | Status | Pass | Fail | Policy Required |",
            "|---------|-------|--------|------|------|-----------------|",
        ]
    )

    for ctrl_id, data in sorted(controls.items()):
        if data["safeguard"] == "Administrative" and (
            data["has_automated_checks"] or data["overall_status"] != "not_assessed"
        ):
            policy = "Yes" if data["requires_policy"] else "No"
            lines.append(
                f"| {ctrl_id} | {data['title']} | {status_icon.get(data['overall_status'], data['overall_status'])} | {data['pass_count']} | {data['fail_count']} | {policy} |"
            )

    lines.extend(["", "---", ""])

    # ---- Physical Safeguards ----
    lines.extend(
        [
            "## Physical Safeguards (164.310)",
            "",
            f"Physical safeguards are largely handled by your cloud provider for cloud-native organizations. Ensure your BAA with {labels['account_label'].split()[0]} is signed and reference the provider's SOC 2 Type II report.",
            "",
            "| Control | Title | Status | Pass | Fail | Policy Required |",
            "|---------|-------|--------|------|------|-----------------|",
        ]
    )

    for ctrl_id, data in sorted(controls.items()):
        if data["safeguard"] == "Physical" and (
            data["has_automated_checks"] or data["overall_status"] != "not_assessed"
        ):
            policy = "Yes" if data["requires_policy"] else "No"
            lines.append(
                f"| {ctrl_id} | {data['title']} | {status_icon.get(data['overall_status'], data['overall_status'])} | {data['pass_count']} | {data['fail_count']} | {policy} |"
            )

    lines.extend(["", "---", ""])

    # ---- Failing Controls Detail ----
    lines.extend(["## Failing Controls — Detail", ""])

    for ctrl_id, data in sorted(controls.items()):
        if data["overall_status"] != "fail":
            continue

        equiv_soc2 = ", ".join(data["soc2_equivalent"]) if data["soc2_equivalent"] else "None"
        equiv_iso = (
            ", ".join(data["iso27001_equivalent"]) if data["iso27001_equivalent"] else "None"
        )

        lines.extend(
            [
                f"### {ctrl_id}: {data['title']}",
                "",
                f"**Safeguard:** {data['safeguard']}",
                f"**Status:** FAIL ({data['fail_count']} failing, {data['pass_count']} passing)",
                f"**SOC 2 Equivalent:** {equiv_soc2}",
                f"**ISO 27001 Equivalent:** {equiv_iso}",
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

    # ---- Policy-Required Controls ----
    policy_controls = {
        k: v for k, v in controls.items() if v["overall_status"] == "requires_policy"
    }
    if policy_controls:
        lines.extend(["## Controls Requiring Policy Documents", ""])
        lines.append("| Control | Title | Safeguard | Guidance |")
        lines.append("|---------|-------|-----------|----------|")
        for ctrl_id, data in sorted(policy_controls.items()):
            lines.append(
                f"| {ctrl_id} | {data['title']} | {data['safeguard']} | {data['guidance']} |"
            )
        lines.extend(["", "Use `/policy-gen` to generate the required policy documents.", ""])

    # ---- PHI-Specific Recommendations ----
    lines.extend(
        [
            "---",
            "",
            "## PHI-Specific Recommendations",
            "",
            "Beyond the technical controls above, organizations handling ePHI should implement:",
            "",
            f"1. **Data Classification**: Tag all resources containing ePHI with `data-classification=phi` or equivalent labels. Use {labels['account_label'].split()[0]} resource tags to identify PHI-bearing systems.",
            "2. **Minimum Necessary Standard**: Restrict ePHI access to the minimum necessary for each workforce member's role. Implement column-level or row-level security on databases containing PHI.",
            f"3. **Audit Log Retention**: HIPAA requires 6-year retention for security-related documentation. Configure {labels['logging_service']} retention accordingly.",
            f"4. **Business Associate Agreements**: Verify signed BAAs with {labels['account_label'].split()[0]} and all SaaS vendors that may access ePHI.",
            "5. **Encryption Key Management**: Use customer-managed KMS/Key Vault keys for ePHI workloads. Rotate keys annually and maintain key access logs.",
            "6. **Incident Response for PHI**: Your incident response plan must include PHI-specific procedures including the 60-day breach notification timeline.",
            "7. **Risk Analysis**: Conduct a formal risk analysis annually, documenting threats to ePHI confidentiality, integrity, and availability.",
            "8. **Workforce Training**: HIPAA-specific training covering PHI handling, minimum necessary, and breach reporting must be provided annually.",
            "",
        ]
    )

    # ---- Cross-Reference to SOC 2 and ISO 27001 ----
    lines.extend(
        [
            "---",
            "",
            "## Cross-Reference: SOC 2 and ISO 27001",
            "",
            "If you are also pursuing SOC 2 or ISO 27001 certification, the following controls overlap:",
            "",
            "| HIPAA | SOC 2 | ISO 27001 | Status | Fixing one helps all |",
            "|-------|-------|-----------|--------|---------------------|",
        ]
    )

    for ctrl_id, data in sorted(controls.items()):
        if (data["soc2_equivalent"] or data["iso27001_equivalent"]) and data["overall_status"] in (
            "pass",
            "fail",
            "partial",
        ):
            soc2 = ", ".join(data["soc2_equivalent"]) if data["soc2_equivalent"] else "-"
            iso = ", ".join(data["iso27001_equivalent"]) if data["iso27001_equivalent"] else "-"
            lines.append(
                f"| {ctrl_id} ({data['title'][:25]}) | {soc2} | {iso} | {status_icon.get(data['overall_status'])} | Yes |"
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
