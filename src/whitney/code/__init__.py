"""Whitney code scanner — Semgrep-based AI security static analysis.

Whitney is a curated Semgrep ruleset for AI-security source code scanning,
not a custom SAST engine. The detection engine is Semgrep OSS; this module
provides:

- A thin subprocess wrapper around the Semgrep CLI (``semgrep_runner``)
- A :func:`scan_repository` entry point that runs Semgrep and enriches
  findings with compliance framework mappings (``scanner``)
- The rule YAML files under ``./rules/`` that implement detection

**Architectural principles** (locked 2026-04-13):

1. **Zero custom SAST code.** All detection is Semgrep. Pattern rules for
   presence/structure/missing-defense, taint rules for source→sink flow
   with sanitizer recognition, both for critical findings where
   belt-and-suspenders matters.

2. **Intra-file taint only.** Semgrep OSS taint mode handles intra-file
   interprocedural data flow. Cross-file is out of scope — empirically
   validated unnecessary for real-world Python AI apps (see
   ``tests/test_whitney/corpus/DIFFERENTIAL.md``).

3. **Finding contract preserved.** The :class:`Finding` model matches
   the existing Shasta contract so ``compliance/mapper.py`` and
   ``compliance/scorer.py`` continue to work unchanged.

4. **Rule files are organised by detection philosophy**, one file per
   philosophy (``prompt_injection_taint.yaml`` for flow,
   ``prompt_injection_critical_sinks.yaml`` for presence-alone-is-critical,
   ``prompt_injection_structural.yaml`` for code-shape vulnerabilities,
   ``prompt_injection_missing_defense.yaml`` for "where is the guardrail?",
   ``prompt_injection_imports.yaml`` for dependency signals).
"""
from whitney.code.scanner import scan_repository

__all__ = ["scan_repository"]
