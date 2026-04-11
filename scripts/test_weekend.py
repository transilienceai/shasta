"""Weekend validation: scan real GitHub repos and produce a test report.

Usage:
    py -3.12 scripts/test_weekend.py                    # scan all repos
    py -3.12 scripts/test_weekend.py langchain          # scan one by keyword
    py -3.12 scripts/test_weekend.py --self-only        # scan our own repo only

Results are saved to data/test-weekend-report.json and printed as a
summary table. Each repo is cloned to a temp directory and deleted
after scanning.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path

# Ensure the project root is importable
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from whitney.code.scanner import scan_repository  # noqa: E402
from whitney.compliance.mapper import enrich_findings_with_ai_controls  # noqa: E402
from whitney.compliance.scorer import calculate_ai_governance_score  # noqa: E402
from whitney.sbom.scanner import scan_code_for_ai_components  # noqa: E402

# ---------------------------------------------------------------------------
# Repos to scan
# ---------------------------------------------------------------------------

REPOS: list[dict[str, str]] = [
    {
        "name": "langchain",
        "github": "langchain-ai/langchain",
        "why": "Largest LLM framework — agents, tools, RAG",
        "expect": "Model versioning, agent tools, RAG patterns",
    },
    {
        "name": "llama_index",
        "github": "run-llama/llama_index",
        "why": "RAG framework — vector DB queries",
        "expect": "RAG access control, output validation",
    },
    {
        "name": "mcp-servers",
        "github": "modelcontextprotocol/servers",
        "why": "Official MCP server examples — validates MCP checks",
        "expect": "MCP auth, tool scope, input validation",
    },
    {
        "name": "a2a-samples",
        "github": "a2aproject/a2a-samples",
        "why": "Official A2A sample apps — validates A2A checks",
        "expect": "A2A delegation scope, agent auth patterns",
    },
    {
        "name": "anthropic-cookbook",
        "github": "anthropics/anthropic-cookbook",
        "why": "Well-written examples — low false-positive test",
        "expect": "Mostly clean",
    },
    {
        "name": "openai-cookbook",
        "github": "openai/openai-cookbook",
        "why": "Well-written examples — low false-positive test",
        "expect": "Mostly clean",
    },
    {
        "name": "shasta",
        "github": "transilienceai/shasta",
        "why": "Our own repo — eat our own dog food",
        "expect": "Zero AI security findings in Whitney itself",
    },
]


def clone_repo(github: str, dest: Path) -> bool:
    """Shallow-clone a repo. Returns True on success."""
    url = f"https://github.com/{github}.git"
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", "--single-branch", url, str(dest)],
            capture_output=True,
            text=True,
            timeout=120,
        )
        return dest.exists()
    except Exception as e:
        print(f"  CLONE FAILED: {e}")
        return False


def scan_one(repo: dict[str, str]) -> dict:
    """Clone, scan, and report on a single repo."""
    name = repo["name"]
    github = repo["github"]
    print(f"\n{'=' * 60}")
    print(f"  Scanning: {github}")
    print(f"  Why: {repo['why']}")
    print(f"{'=' * 60}")

    result = {
        "name": name,
        "github": github,
        "why": repo["why"],
        "expected": repo["expect"],
        "timestamp": datetime.now(UTC).isoformat(),
        "status": "pending",
        "scan_duration_seconds": 0,
        "total_findings": 0,
        "findings_by_check_id": {},
        "findings_by_severity": {},
        "sample_findings": [],
        "sbom_components": 0,
        "compliance_scores": {},
        "error": None,
    }

    tmpdir = Path(tempfile.mkdtemp(prefix=f"whitney-{name}-"))
    try:
        # Clone
        print(f"  Cloning to {tmpdir}...")
        if not clone_repo(github, tmpdir):
            result["status"] = "clone_failed"
            result["error"] = "git clone failed"
            return result

        # Code scan
        print("  Running code scan (20 checks)...")
        t0 = time.monotonic()
        findings = scan_repository(tmpdir)
        scan_time = time.monotonic() - t0
        result["scan_duration_seconds"] = round(scan_time, 1)

        # Enrich with compliance mappings
        enrich_findings_with_ai_controls(findings)

        # Compliance scoring
        score = calculate_ai_governance_score(findings)
        result["compliance_scores"] = {
            "iso42001": f"{score.score_percentage}% ({score.grade})",
            "eu_ai_act": f"{score.eu_score_percentage}% ({score.eu_grade})",
            "nist_rmf": f"{score.nist_score}% ({score.nist_grade})",
            "nist_600_1": f"{score.nist_600_1_score}% ({score.nist_600_1_grade})",
            "owasp_llm": f"{score.owasp_llm_score}% ({score.owasp_llm_grade})",
            "owasp_agentic": f"{score.owasp_agentic_score}% ({score.owasp_agentic_grade})",
            "atlas": f"{score.atlas_score}% ({score.atlas_grade})",
            "combined": f"{score.combined_score}% ({score.combined_grade})",
        }

        # SBOM
        print("  Running SBOM scan...")
        try:
            sbom_components = scan_code_for_ai_components(tmpdir)
            result["sbom_components"] = len(sbom_components)
        except Exception as e:
            result["sbom_components"] = 0
            print(f"  SBOM error (non-fatal): {e}")

        # Aggregate findings
        result["total_findings"] = len(findings)
        check_counts = Counter(f.check_id for f in findings)
        result["findings_by_check_id"] = dict(check_counts.most_common())
        severity_counts = Counter(f.severity.value for f in findings)
        result["findings_by_severity"] = dict(severity_counts)

        # Sample findings (first 5)
        for f in findings[:5]:
            result["sample_findings"].append(
                {
                    "check_id": f.check_id,
                    "title": f.title,
                    "severity": f.severity.value,
                    "file": f.details.get("file_path", ""),
                    "line": f.details.get("line_number", 0),
                }
            )

        result["status"] = "success"

        # Print summary
        print(f"\n  Results: {len(findings)} findings in {scan_time:.1f}s")
        print(f"  SBOM: {result['sbom_components']} AI components")
        print(f"  Combined score: {score.combined_score}% ({score.combined_grade})")
        if check_counts:
            print("  Top findings:")
            for cid, count in check_counts.most_common(5):
                print(f"    {cid}: {count}")
        else:
            print("  No findings (clean repo)")

    except Exception as e:
        result["status"] = "error"
        result["error"] = str(e)
        print(f"  ERROR: {e}")

    finally:
        # Cleanup
        print(f"  Cleaning up {tmpdir}...")
        shutil.rmtree(tmpdir, ignore_errors=True)

    return result


def print_summary_table(results: list[dict]) -> None:
    """Print a formatted summary table."""
    print(f"\n{'=' * 80}")
    print("  WEEKEND VALIDATION SUMMARY")
    print(f"{'=' * 80}")
    print(f"  {'Repo':<25} {'Status':<10} {'Findings':>8} {'Time':>7} {'Combined':>10}")
    print(f"  {'-' * 25} {'-' * 10} {'-' * 8} {'-' * 7} {'-' * 10}")
    for r in results:
        status = r["status"]
        findings = r["total_findings"]
        duration = f"{r['scan_duration_seconds']}s"
        combined = r.get("compliance_scores", {}).get("combined", "N/A")
        print(f"  {r['name']:<25} {status:<10} {findings:>8} {duration:>7} {combined:>10}")
    print()


def main() -> None:
    # Filter repos by command-line arg
    repos = REPOS
    if len(sys.argv) > 1:
        if sys.argv[1] == "--self-only":
            repos = [r for r in REPOS if r["name"] == "shasta"]
        else:
            keyword = sys.argv[1].lower()
            repos = [
                r for r in REPOS if keyword in r["name"].lower() or keyword in r["github"].lower()
            ]
            if not repos:
                print(f"No repos matching '{keyword}'. Available: {[r['name'] for r in REPOS]}")
                sys.exit(1)

    print(f"Whitney Weekend Validation — {len(repos)} repos")
    print(f"Started: {datetime.now(UTC).isoformat()}")

    results = []
    for repo in repos:
        result = scan_one(repo)
        results.append(result)

    print_summary_table(results)

    # Save report
    report_dir = PROJECT_ROOT / "data"
    report_dir.mkdir(exist_ok=True)
    report_path = report_dir / "test-weekend-report.json"
    report = {
        "timestamp": datetime.now(UTC).isoformat(),
        "whitney_version": "1.8.0",
        "repos_scanned": len(results),
        "results": results,
    }
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"Report saved to: {report_path}")

    # Exit code: 1 if any scan failed
    if any(r["status"] not in ("success",) for r in results):
        print("\nWARNING: Some scans failed. Review the report.")
        sys.exit(1)


if __name__ == "__main__":
    main()
