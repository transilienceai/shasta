"""Validate Whitney findings against real repos.

Loads the weekend test report and produces a validation worksheet:
for each unique (check_id, repo) pair, shows the top finding with
code snippet so a human reviewer can classify as TP/FP.

Usage:
    py -3.12 scripts/validate_findings.py                  # all repos
    py -3.12 scripts/validate_findings.py langchain         # one repo
    py -3.12 scripts/validate_findings.py --rescan mcp      # rescan + validate

Outputs a Markdown report to data/finding-validation.md
"""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
REPORT_PATH = PROJECT_ROOT / "data" / "test-weekend-report.json"

# For --rescan mode
sys.path.insert(0, str(PROJECT_ROOT / "src"))


def load_report() -> dict:
    if not REPORT_PATH.exists():
        print(f"No report found at {REPORT_PATH}")
        print("Run: py -3.12 scripts/test_weekend.py")
        sys.exit(1)
    return json.loads(REPORT_PATH.read_text(encoding="utf-8"))


def rescan_repo(keyword: str) -> dict:
    """Re-scan a single repo and return its result dict with full findings."""
    import shutil
    import tempfile
    import time

    sys.path.insert(0, str(PROJECT_ROOT / "scripts"))
    from test_weekend import REPOS, clone_repo  # noqa: E402
    from whitney.code.scanner import scan_repository
    from whitney.compliance.mapper import enrich_findings_with_ai_controls

    matches = [r for r in REPOS if keyword.lower() in r["name"].lower()]
    if not matches:
        print(f"No repo matching '{keyword}'")
        sys.exit(1)
    repo = matches[0]

    print(f"Re-scanning {repo['github']}...")
    tmpdir = Path(tempfile.mkdtemp(prefix="whitney-validate-"))
    try:
        clone_repo(repo["github"], tmpdir)
        t0 = time.monotonic()
        findings = scan_repository(tmpdir)
        enrich_findings_with_ai_controls(findings)
        duration = time.monotonic() - t0

        result = {
            "name": repo["name"],
            "github": repo["github"],
            "total_findings": len(findings),
            "scan_duration_seconds": round(duration, 1),
            "full_findings": [
                {
                    "check_id": f.check_id,
                    "title": f.title,
                    "severity": f.severity.value,
                    "file_path": f.details.get("file_path", ""),
                    "line_number": f.details.get("line_number", 0),
                    "code_snippet": f.details.get("code_snippet", ""),
                    "matched_pattern": f.details.get("matched_pattern", ""),
                    "remediation": f.remediation,
                    "frameworks": {
                        k: v
                        for k, v in f.details.items()
                        if k
                        in (
                            "iso42001_controls",
                            "eu_ai_act",
                            "owasp_llm_top10",
                            "owasp_agentic",
                            "nist_ai_rmf",
                            "nist_ai_600_1",
                            "mitre_atlas",
                        )
                    },
                }
                for f in findings
            ],
        }
        return result
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def generate_validation_report(results: list[dict], output_path: Path) -> None:
    """Generate a Markdown validation worksheet."""
    lines: list[str] = [
        "# Whitney Finding Validation Report",
        "",
        f"Generated: {datetime.now(UTC).isoformat()}",
        "",
        "## How to Review",
        "",
        "For each finding below, classify as:",
        "- **TP** (True Positive) — real security issue",
        "- **FP** (False Positive) — pattern matched but not a real issue",
        "- **EP** (Expected Pattern) — correct detection in example/test code",
        "",
        "---",
        "",
    ]

    for result in results:
        repo = result.get("github", result.get("name", "unknown"))
        total = result.get("total_findings", 0)
        lines.append(f"## {repo}")
        lines.append(f"**Total findings: {total}**")
        lines.append("")

        # Group findings by check_id
        full_findings = result.get("full_findings", [])
        if not full_findings:
            # Fall back to summary data
            by_check = result.get("findings_by_check_id", {})
            if by_check:
                lines.append("| Check ID | Count | Verdict |")
                lines.append("|----------|-------|---------|")
                for cid, count in sorted(by_check.items(), key=lambda x: -x[1]):
                    lines.append(f"| `{cid}` | {count} | _pending_ |")
                lines.append("")
            else:
                lines.append("_No findings — clean repo_")
                lines.append("")
            continue

        # Group by check_id with examples
        by_check: dict[str, list[dict]] = defaultdict(list)
        for f in full_findings:
            by_check[f["check_id"]].append(f)

        lines.append("| Check ID | Count | Severity | Verdict |")
        lines.append("|----------|-------|----------|---------|")
        for cid in sorted(by_check, key=lambda k: -len(by_check[k])):
            findings = by_check[cid]
            sev = findings[0]["severity"]
            lines.append(f"| `{cid}` | {len(findings)} | {sev} | _pending_ |")
        lines.append("")

        # Show top 3 findings per check_id for review
        for cid in sorted(by_check, key=lambda k: -len(by_check[k])):
            findings = by_check[cid]
            lines.append(f"### `{cid}` ({len(findings)} findings)")
            lines.append("")

            # Show up to 3 examples
            for i, f in enumerate(findings[:3]):
                fpath = f.get("file_path", "?")
                line = f.get("line_number", 0)
                lines.append(f"**Example {i + 1}:** `{fpath}:{line}`")
                snippet = f.get("code_snippet", "")
                if snippet:
                    lines.append("```")
                    lines.append(snippet)
                    lines.append("```")
                frameworks = f.get("frameworks", {})
                if frameworks:
                    mapped = []
                    for fw, ids in frameworks.items():
                        if ids:
                            mapped.append(f"{fw}: {', '.join(ids)}")
                    if mapped:
                        lines.append(f"Frameworks: {' | '.join(mapped)}")
                lines.append("")

            if len(findings) > 3:
                lines.append(f"_...and {len(findings) - 3} more_")
                lines.append("")

        lines.append("---")
        lines.append("")

    output_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"Validation report: {output_path}")


def main() -> None:
    keyword = None
    rescan = False

    args = sys.argv[1:]
    if "--rescan" in args:
        rescan = True
        args.remove("--rescan")
    if args:
        keyword = args[0]

    if rescan and keyword:
        # Re-scan a single repo with full finding details
        result = rescan_repo(keyword)
        results = [result]
    else:
        # Use existing report
        report = load_report()
        results = report.get("results", [])
        if keyword:
            results = [
                r
                for r in results
                if keyword.lower() in r.get("name", "").lower()
                or keyword.lower() in r.get("github", "").lower()
            ]

    output = PROJECT_ROOT / "data" / "finding-validation.md"
    generate_validation_report(results, output)

    # Print summary
    total_findings = sum(r.get("total_findings", 0) for r in results)
    print(f"\n{len(results)} repos, {total_findings} total findings")
    print(f"Review: {output}")


if __name__ == "__main__":
    main()
