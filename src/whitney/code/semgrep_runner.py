"""Semgrep-based code scanner for Whitney.

Runs Semgrep rules against a repository and converts results to
Whitney Finding objects. Falls back gracefully if Semgrep is not
installed — the regex engine in checks.py remains the default.

Semgrep provides AST-based pattern matching (vs regex), which means:
  - No false positives in comments or docstrings
  - Structural matching (e.g., exec() inside a Tool() definition body)
  - Language-grammar-aware (handles formatting differences)
  - Still deterministic — no LLM, no probabilistic model
"""

from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path

from shasta.evidence.models import (
    CheckDomain,
    CloudProvider,
    ComplianceStatus,
    Finding,
    Severity,
)

logger = logging.getLogger(__name__)

# Directory containing Semgrep YAML rule files
RULES_DIR = Path(__file__).parent / "rules"

# Cache semgrep availability check
_SEMGREP_AVAILABLE: bool | None = None

# Map Semgrep severity to Whitney severity (overridden by metadata)
_SEMGREP_SEVERITY_MAP = {
    "ERROR": Severity.CRITICAL,
    "WARNING": Severity.HIGH,
    "INFO": Severity.LOW,
}

_WHITNEY_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


def semgrep_available() -> bool:
    """Check if Semgrep CLI is installed and accessible."""
    global _SEMGREP_AVAILABLE
    if _SEMGREP_AVAILABLE is not None:
        return _SEMGREP_AVAILABLE
    try:
        result = subprocess.run(
            ["semgrep", "--version"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=10,
        )
        _SEMGREP_AVAILABLE = result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        _SEMGREP_AVAILABLE = False
    return _SEMGREP_AVAILABLE


def run_semgrep(repo_path: str | Path) -> list[Finding]:
    """Run Semgrep rules against a repository and return Findings.

    Returns an empty list if Semgrep is not installed or if an error occurs.
    """
    if not semgrep_available():
        return []

    repo_path = Path(repo_path)
    if not RULES_DIR.is_dir():
        logger.warning("Semgrep rules directory not found: %s", RULES_DIR)
        return []

    try:
        result = subprocess.run(
            [
                "semgrep",
                "--config",
                str(RULES_DIR),
                "--json",
                "--no-git-ignore",
                "--quiet",
                str(repo_path),
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=300,
        )
    except subprocess.TimeoutExpired:
        logger.warning("Semgrep timed out after 300s")
        return []

    # Semgrep exit codes: 0 = no findings, 1 = findings found,
    # 2 = findings + rule errors (partial results), >2 = fatal error
    if result.returncode > 2:
        logger.warning("Semgrep failed (exit %d): %s", result.returncode, result.stderr[:500])
        return []

    if result.returncode == 2:
        # Partial results — some rules had parse errors but others ran fine.
        # Log the errors but still parse whatever findings were produced.
        logger.warning(
            "Semgrep had rule errors (exit 2), parsing partial results: %s",
            result.stderr[:500],
        )

    return _parse_semgrep_json(result.stdout, repo_path)


def _parse_semgrep_json(json_str: str, repo_path: Path) -> list[Finding]:
    """Convert Semgrep JSON output to Whitney Finding objects."""
    try:
        data = json.loads(json_str)
    except json.JSONDecodeError:
        logger.warning("Failed to parse Semgrep JSON output")
        return []

    findings: list[Finding] = []
    for r in data.get("results", []):
        extra = r.get("extra", {})
        meta = extra.get("metadata", {})

        # Determine severity: prefer Whitney metadata, fall back to Semgrep severity
        whitney_sev = meta.get("whitney_severity", "")
        if whitney_sev.lower() in _WHITNEY_SEVERITY_MAP:
            severity = _WHITNEY_SEVERITY_MAP[whitney_sev.lower()]
        else:
            severity = _SEMGREP_SEVERITY_MAP.get(extra.get("severity", "WARNING"), Severity.MEDIUM)

        # Extract check_id from metadata (preferred) or rule id
        check_id = meta.get("check_id", r.get("check_id", "unknown"))

        # Build file path relative to repo
        raw_path = r.get("path", "")
        try:
            rel_path = str(Path(raw_path).relative_to(repo_path))
        except ValueError:
            rel_path = raw_path

        line_number = r.get("start", {}).get("line", 0)
        code_lines = extra.get("lines", "")

        findings.append(
            Finding(
                check_id=check_id,
                title=f"{check_id.replace('code-', '').replace('-', ' ').title()} in {Path(raw_path).name}",
                description=extra.get("message", ""),
                severity=severity,
                status=ComplianceStatus.FAIL,
                domain=CheckDomain.AI_GOVERNANCE,
                cloud_provider=CloudProvider.AWS,
                resource_type="Code::Repository::File",
                resource_id=f"{repo_path.name}:{rel_path}:{line_number}",
                region="code",
                account_id="code-scan",
                remediation=meta.get("remediation", ""),
                soc2_controls=meta.get("soc2_controls", []),
                details={
                    "file_path": rel_path,
                    "line_number": line_number,
                    "matched_pattern": f"semgrep:{check_id}",
                    "code_snippet": code_lines,
                    "engine": "semgrep",
                },
            )
        )

    logger.info("Semgrep scan complete: %d finding(s)", len(findings))
    return findings
