"""Scan output summarizer — aggregates repetitive findings for readable output.

On real accounts with 150+ security groups and 95+ S3 buckets, raw scan
output can be 8,000+ lines. This module groups identical check types and
provides a compact summary while preserving full detail in the saved scan.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from transilience_compliance.evidence.models import Finding, ScanResult


def summarize_scan(scan: ScanResult, max_detail_per_check: int = 5) -> dict:
    """Produce a compact summary of scan results.

    Groups findings by check_id, shows counts, and only includes
    up to max_detail_per_check individual findings per group.
    Full detail remains in the saved scan/database.
    """
    groups: dict[str, list[Finding]] = defaultdict(list)
    for f in scan.findings:
        groups[f.check_id].append(f)

    summary_groups = []
    for check_id, findings in groups.items():
        passed = [f for f in findings if f.status.value == "pass"]
        failed = [f for f in findings if f.status.value == "fail"]
        partial = [f for f in findings if f.status.value == "partial"]

        # Pick the most representative findings to show in detail
        detail_findings = []
        # Always show failures first
        detail_findings.extend(failed[:max_detail_per_check])
        remaining = max_detail_per_check - len(detail_findings)
        if remaining > 0:
            detail_findings.extend(partial[:remaining])
        remaining = max_detail_per_check - len(detail_findings)
        if remaining > 0:
            detail_findings.extend(passed[:remaining])

        truncated = len(findings) - len(detail_findings)

        summary_groups.append({
            "check_id": check_id,
            "title": findings[0].title.split("'")[0].strip() if findings else check_id,
            "domain": findings[0].domain.value if findings else "unknown",
            "soc2_controls": findings[0].soc2_controls if findings else [],
            "total": len(findings),
            "passed": len(passed),
            "failed": len(failed),
            "partial": len(partial),
            "worst_severity": _worst_severity(findings),
            "findings": [
                {
                    "title": f.title,
                    "severity": f.severity.value,
                    "status": f.status.value,
                    "resource_id": f.resource_id,
                    "remediation": f.remediation,
                }
                for f in detail_findings
            ],
            "truncated": truncated,
        })

    # Sort: failed groups first, then by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    summary_groups.sort(key=lambda g: (
        0 if g["failed"] > 0 else 1,
        severity_order.get(g["worst_severity"], 5),
    ))

    return {
        "scan_id": scan.id,
        "account_id": scan.account_id,
        "scanned_at": scan.started_at.isoformat() if hasattr(scan.started_at, 'isoformat') else str(scan.started_at),
        "completed_at": scan.completed_at.isoformat() if scan.completed_at and hasattr(scan.completed_at, 'isoformat') else str(scan.completed_at) if scan.completed_at else None,
        "total_findings": len(scan.findings),
        "total_passed": sum(1 for f in scan.findings if f.status.value == "pass"),
        "total_failed": sum(1 for f in scan.findings if f.status.value == "fail"),
        "check_groups": len(summary_groups),
        "groups": summary_groups,
    }


def _worst_severity(findings: list[Finding]) -> str:
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    worst = "info"
    for f in findings:
        if order.get(f.severity.value, 5) < order.get(worst, 5):
            worst = f.severity.value
    return worst
