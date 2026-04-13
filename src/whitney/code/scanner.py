"""Whitney code scanner — entry point.

This is the public interface for Whitney's code scanner. It runs
Semgrep (via :mod:`whitney.code.semgrep_runner`) and enriches the
resulting findings with compliance framework control mappings (via
:func:`whitney.compliance.mapper.enrich_findings_with_ai_controls`).

The scanner is intentionally thin — ~20 lines of orchestration logic.
All detection complexity lives in the Semgrep rule YAML files; all
compliance framework mapping lives in the compliance module. This
file's only job is to connect them.

Architecture rationale: see module docstring in
:mod:`whitney.code.__init__`.
"""
from __future__ import annotations

import logging
from pathlib import Path

from shasta.evidence.models import Finding

from whitney.code.semgrep_runner import (
    SemgrepNotInstalledError,
    run_semgrep,
)

log = logging.getLogger(__name__)

__all__ = ["scan_repository", "SemgrepNotInstalledError"]


def scan_repository(repo_path: Path | str) -> list[Finding]:
    """Scan a repository for AI security issues.

    Runs Semgrep against the given path using Whitney's bundled rules,
    then enriches the resulting findings with compliance framework
    control mappings (ISO 42001, EU AI Act, OWASP LLM Top 10, OWASP
    Agentic Top 10, NIST AI RMF, MITRE ATLAS).

    Args:
        repo_path: Directory or file to scan.

    Raises:
        SemgrepNotInstalledError: If the ``semgrep`` CLI is missing.

    Returns:
        A list of :class:`Finding` objects, one per detected issue,
        with framework mappings populated in ``Finding.details``.
    """
    repo_path = Path(repo_path)

    findings = run_semgrep(repo_path)

    # Enrich with compliance framework mappings. This populates
    # details["iso42001_controls"], details["eu_ai_act"], etc. based
    # on each finding's check_id. The compliance mapper is the single
    # source of truth for the check_id → framework mapping.
    try:
        from whitney.compliance.mapper import enrich_findings_with_ai_controls

        enrich_findings_with_ai_controls(findings)
    except ImportError as exc:
        # Compliance mapper not available — return findings without
        # framework enrichment. This lets the scanner work standalone
        # without requiring the full Whitney package.
        log.debug("Compliance mapper not available, skipping enrichment: %s", exc)

    # Phase D — LLM-as-judge triage (opt-in via WHITNEY_STRICT_JUDGE_PROMPTS).
    # When disabled (the default), this is a no-op. When enabled, findings
    # on files containing a correctly-implemented LLM-as-judge defense are
    # suppressed. See whitney.code.llm_triage for details.
    try:
        from whitney.code.llm_triage import (
            apply_llm_triage_to_findings,
            is_triage_enabled,
        )

        if is_triage_enabled():
            findings, suppressed = apply_llm_triage_to_findings(
                findings, scan_root=repo_path
            )
            if suppressed:
                log.info(
                    "LLM triage suppressed %d finding(s) on %d file(s)",
                    len(suppressed),
                    len({f.details.get("file_path") for f in suppressed}),
                )
    except ImportError as exc:
        log.debug("llm_triage module not available, skipping: %s", exc)

    return findings
