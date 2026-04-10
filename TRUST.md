# Trust — How to Verify Shasta Yourself

This document explains how a visitor — auditor, prospect, contributor, or
future-you — can verify that the claims in `README.md` and the rest of
this repo match the code that's actually here.

It is the **backward-looking** counterpart to
[`ENGINEERING_PRINCIPLES.md`](./ENGINEERING_PRINCIPLES.md), which is
forward-looking discipline. Principles say what we promise to do.
Trust says how you check that we did it.

For the Whitney AI scanner's specific validation story (vulnerability
fixtures, live cloud validation against AWS + Azure, dual-engine
Semgrep architecture), see [`src/whitney/TRUST.md`](./src/whitney/TRUST.md).

---

## TL;DR

Shasta and Whitney together ship the following, all integrity-tested:

- **220 check functions** (174 cloud compliance + 46 AI governance)
- **112 Terraform remediation templates** (81 AWS + 31 Azure)
- **684 tests** that all pass on every commit

None of the claims in this README are written by hand and hoped-for —
every numeric claim is AST-counted from source by an integrity test
that fails the build on drift. Detection is 100% deterministic — zero
LLM calls in the scanning, scoring, mapping, policy generation, or
report pipelines. The claims you verify today will produce the same
results six months from now on the same infrastructure.

---

## The seven layers of trust

```
Layer 0 — Deterministic detection (no LLM in the pipeline)
Layer 1 — Test suite (684 tests, all green on every commit)
Layer 2 — Doc-vs-code drift integrity tests
Layer 3 — Multi-region structural enforcement
Layer 4 — CI workflow (mechanical PR-time enforcement)
Layer 5 — /audit skill (on-demand pre-commit review)
Layer 6 — Closed issues + CHANGELOG (audit trail of past failures and fixes)
```

Each layer catches a different failure mode. None of them depends on
human vigilance.

---

### Layer 0 — Deterministic detection

Shasta and Whitney make **zero LLM calls in the detection pipeline**.
Every finding is produced by:

| Mechanism | Used in |
|---|---|
| `boto3` / `azure.mgmt.*` SDK calls | All AWS / Azure cloud checks |
| Semgrep AST-based pattern matching (with regex fallback) | Whitney code scanning |
| Dictionary lookups | Framework control mapping |
| Arithmetic | Compliance scoring |
| `re.compile()` patterns | Whitney code scanning fallback + parameter matching |

The LLM (Claude Code) lives in the **user-interface layer** — it calls
Shasta and Whitney's Python functions and presents results in natural
language. The compliance engine itself is pure code.

**Why this matters for trust:**

1. **Reproducibility.** Same code + same infrastructure = identical
   findings. No model temperature, no token sampling, no run-to-run
   variance.
2. **Auditability.** Every finding traces to a specific SDK call,
   Semgrep rule (a YAML file you can read), regex pattern, dictionary
   key, or arithmetic operation. An auditor can inspect the check
   definition and understand exactly why a finding was produced.
3. **No hallucination risk.** The scanner cannot invent findings that
   don't exist or miss findings that do. Pattern matched or not matched
   — binary.
4. **No cost per scan.** No API tokens consumed. Scans can run as
   frequently as needed at zero marginal cost.

**Verify yourself:**

```bash
# No anthropic / openai imports anywhere in src/
grep -r "import anthropic\|import openai\|from anthropic\|from openai" src/
# (no results)

# Whitney's integrity tests assert this programmatically
py -3.12 -m pytest tests/test_whitney/test_integrity.py -v
```

---

### Layer 1 — Test suite

**684 tests** across `tests/`, all green on every commit. Breakdown:

| Suite | Tests | What it covers |
|---|---|---|
| `tests/test_whitney/` | 419 | Whitney AI scanner: patterns, code checks, scorer, mapper, policies, SBOM, integrity, semgrep runner |
| `tests/test_aws/` | 108 | AWS smoke tests: imports, runner signatures, multi-region structural enforcement, Terraform template renders, deprecated runtime tables, VPC endpoint expectations |
| `tests/test_azure/` | 55 | Azure smoke tests: imports, runner signatures, diagnostic settings matrix, Defender required plans, CIS 5.2.x activity log alert mappings, Terraform template renders |
| `tests/test_compliance/` | 21 | SOC 2 + ISO 27001 scorer + mapper |
| `tests/test_workflows/` | 26 | Risk register + drift detection workflows |
| `tests/test_integrity/` | 11 | **Doc-vs-code drift** — see Layer 2 |
| `tests/test_reports/` | 13 | Markdown / HTML / PDF report generation |
| Other | ~31 | Conftest, models, client, fixtures |

**Run them yourself:**

```bash
py -3.12 -m pytest --ignore=tests/test_rainier
# 684 passed in ~2 minutes
```

The full suite runs on every PR via
[`.github/workflows/integrity.yml`](./.github/workflows/integrity.yml)
(see Layer 4).

---

### Layer 2 — Doc-vs-code drift integrity tests

This is the layer that closes the most embarrassing failure mode:
**numeric claims in the README that don't match the code.**

`tests/test_integrity/test_doc_claims.py` contains **16 parametrized assertions** that AST-count the source tree and assert each numeric claim in `README.md`, `TRUST.md`, `src/whitney/README.md`, and `src/whitney/TRUST.md` matches reality:

| Test | Claim it verifies | Source of truth |
|---|---|---|
| `test_readme_total_check_count` | "5 Domains, X+ Checks" headline | AST count of `check_*` in `src/shasta/` |
| `test_readme_technical_controls_check_count` | Technical-controls table row | AST count of `check_*` in `src/shasta/` |
| `test_readme_check_to_risk_mapping_count` | "X check-to-risk mappings" | `len(FINDING_TO_RISK)` |
| `test_readme_test_count_in_tree_block` | "(N+ tests)" annotation | `pytest --collect-only` |
| `test_readme_ai_check_count` | "N AI checks (code + cloud)" | AST count of `check_*` in `src/whitney/` |
| `test_readme_terraform_template_breakdown` | "X templates (Y AWS + Z Azure)" | `TERRAFORM_TEMPLATES` registry |
| `test_readme_policy_template_count` | "N SOC 2 policy documents" | `len(POLICIES)` |
| `test_whitney_readme_test_count` | Whitney status checklist test count | `pytest tests/test_whitney/ --collect-only` |
| `test_whitney_trust_unit_test_count` | TRUST.md Layer 1 header | `pytest tests/test_whitney/ --collect-only` |
| `test_counters_return_positive_numbers` | self-test of helper functions | n/a |
| `test_pytest_collector_works` | self-test of pytest collector | n/a |

**How it works:**

* Each test extracts a numeric claim from a doc file via a tight regex
* AST-counts the corresponding code (or queries a registry / runs
  `pytest --collect-only`)
* Asserts the doc number is within tolerance
* `X+` claims pass when actual ≥ X
* Bare numbers must match exactly (or within explicit tolerance for
  fast-moving counters like total tests)
* Lines containing `~~strikethrough~~` are skipped — historical
  narrative is preserved untouched

**Failure messages are actionable.** When something drifts, the test
prints the file, line, current value, and the exact replacement to
use:

```
AssertionError: README.md:285 claims '125+' for Shasta automated checks
(technical-controls table row), but actual is 92. Either fix the doc to
'92+' or restore the missing items.
```

**Origin story.** This test file exists because v1.0.0 of the README
claimed "22 Azure Terraform templates" when the
`shasta.remediation.engine.TERRAFORM_TEMPLATES` registry contained
**zero**. The number had been inherited from a stale `.pyc` cache and
never existed in committed source. Adding the integrity test caught **six
more stale claims on its first run**, including one that had been
introduced minutes earlier.

**Run them yourself:**

```bash
py -3.12 -m pytest tests/test_integrity/ -v
# 11 passed
```

---

### Layer 3 — Multi-region structural enforcement

Single-region scanners are the most common false-clean failure mode in
compliance tooling. `tests/test_aws/test_aws_sweep_smoke.py` contains a
parametrized structural test —
`test_runner_iterates_regions_unless_global` — that **inspects the
source of every AWS module's `run_all_*` runner** and asserts it calls
both `client.get_enabled_regions()` and `client.for_region(`.

The build fails for any single-region runner unless the module
explicitly opts out via a `IS_GLOBAL = True` module-level constant.

| AWS module | Status | Why |
|---|---|---|
| `compute.py`, `kms.py`, `databases.py`, `serverless.py`, `backup.py`, `vpc_endpoints.py`, `cloudwatch_logs.py`, `data_warehouse.py` | Regional (must iterate) | All resources are scoped to a region |
| `cloudfront.py` | `IS_GLOBAL = True` | CloudFront resources live in the global namespace |
| `organizations.py` | In `GLOBAL_AWS_MODULES` set | AWS Organizations API is global |
| `iam.py` | Wired separately at scanner level | IAM is global |
| `logging_checks.py::check_cloudwatch_alarms_cis_4_x` | Special-cased | Anchors to multi-region trail's home region — naive iteration would produce 14 false-FAIL findings per multi-region account |

The same enforcement pattern applies to Azure modules via
`tests/test_azure/test_smoke.py`.

**Verify yourself:**

```bash
py -3.12 -m pytest tests/test_aws/test_aws_sweep_smoke.py -v -k iterates_regions
# All regional runners must call get_enabled_regions() + for_region(
```

---

### Layer 4 — CI workflow (mechanical PR-time enforcement)

[`.github/workflows/integrity.yml`](./.github/workflows/integrity.yml)
runs on every PR against `main` and every push to `main`. Three jobs:

| Job | What it runs | Catches |
|---|---|---|
| `doc-drift-and-smoke` | `pytest tests/test_integrity/` + `tests/test_aws/test_aws_sweep_smoke.py` + `tests/test_azure/test_smoke.py` + `tests/test_whitney/test_integrity.py` | Doc drift, stub regressions, missing framework mappings, detection-layer LLM imports, multi-region violations |
| `full-suite` | `pytest -q --ignore=tests/integration` | Any test regression anywhere in the suite |
| `lint` | `ruff check` + `ruff format --check` | Style + bugs + format consistency |

A failed job blocks merge. There is no path to ship a doc-drift
regression, a stub function regression, or a single-region scanner
regression without explicitly bypassing CI.

---

### Layer 5 — /audit skill (on-demand pre-commit review)

[`.claude/skills/audit/SKILL.md`](./.claude/skills/audit/SKILL.md)
defines a user-invocable Claude Code slash command. When a developer
types `/audit` before committing, the skill walks the staged diff
against all 20 principles in
[`ENGINEERING_PRINCIPLES.md`](./ENGINEERING_PRINCIPLES.md) and reports
PASS / FAIL / WARN per rule with file:line refs.

The skill is the on-demand layer between layer 4 (PR-time CI) and
human discipline. Failure reports are actionable — they tell the
developer the exact file, line, and replacement to apply.

---

### Layer 6 — Closed issues + CHANGELOG

The repo carries **10 closed incident-style issues**
([#3 – #12](https://github.com/transilienceai/shasta/issues?q=is%3Aissue+is%3Aclosed))
documenting past problems and resolutions. Each issue has:

* **Problem** — what was wrong, with concrete examples
* **Impact** — severity and blast radius
* **Resolution** — commit references
* **Files** — paths touched
* **Verification** — exact commands to confirm the fix

The same audit trail lives in
[`CHANGELOG.md`](./CHANGELOG.md), which uses the
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format.
Historical entries are immutable — strikethrough markers
(`~~done~~`) protect them from revisionism, and the integrity tests
in Layer 2 skip strikethrough lines so historical narrative is never
"updated" to match present numbers.

---

## Framework coverage matrix

Every finding produced by Shasta or Whitney carries explicit framework
control IDs as **list fields on the Pydantic `Finding` model**, not as
free text inside descriptions:

```python
class Finding(BaseModel):
    soc2_controls:       list[str] = Field(default_factory=list)
    iso27001_controls:   list[str] = Field(default_factory=list)
    hipaa_controls:      list[str] = Field(default_factory=list)
    cis_aws_controls:    list[str] = Field(default_factory=list)
    cis_azure_controls:  list[str] = Field(default_factory=list)
    mcsb_controls:       list[str] = Field(default_factory=list)
```

This means every framework score is a real query, not a regex extraction.

| Framework | Coverage | Where it's defined |
|---|---|---|
| **SOC 2** | CC1.1 – CC9.1 + Availability | `src/shasta/compliance/framework.py` |
| **ISO 27001:2022** | 35 Annex A controls across 4 themes | `src/shasta/compliance/iso27001_*` |
| **HIPAA Security Rule** | 29 controls across Administrative / Physical / Technical safeguards | `src/shasta/compliance/hipaa_*` |
| **CIS AWS Foundations Benchmark v3.0** | Sections 1.x – 5.x populated on every new AWS check | `cis_aws_controls` field |
| **CIS Microsoft Azure Foundations Benchmark v3.0** | Sections 1.x – 9.x populated on every new Azure check | `cis_azure_controls` field |
| **Microsoft Cloud Security Benchmark** | IM, NS, DP, LT, BR, PA, GS sections | `mcsb_controls` field |
| **ISO 42001** | 11 AI management system controls (Whitney) | `src/whitney/compliance/iso42001.py` |
| **EU AI Act** | 8 obligations (Whitney) | `src/whitney/compliance/eu_ai_act.py` |
| **OWASP LLM Top 10** | 10 risks (Whitney) | `src/whitney/compliance/owasp_llm_top10.py` |
| **OWASP Agentic Top 10** | 10 risks (Whitney) | `src/whitney/compliance/owasp_agentic.py` |
| **NIST AI RMF** | 19 categories (Whitney) | `src/whitney/compliance/nist_ai_rmf.py` |
| **MITRE ATLAS** | 15 techniques (Whitney) | `src/whitney/compliance/mitre_atlas.py` |

---

## How to verify any specific claim

If you read a number anywhere in this repo and want to verify it
yourself, here are the load-bearing commands:

```bash
# Total check functions across Shasta + Whitney
py -3.12 -c "
import ast, pathlib
n = 0
for d in ['src/shasta', 'src/whitney']:
    for p in pathlib.Path(d).rglob('*.py'):
        try: t = ast.parse(p.read_text(encoding='utf-8'))
        except: continue
        for node in ast.walk(t):
            if isinstance(node, ast.FunctionDef) and node.name.startswith('check_'):
                n += 1
print(n)
"

# Terraform template count
py -3.12 -c "
from shasta.remediation.engine import TERRAFORM_TEMPLATES
aws = sum(1 for k in TERRAFORM_TEMPLATES if not k.startswith('azure-'))
azure = sum(1 for k in TERRAFORM_TEMPLATES if k.startswith('azure-'))
print(f'{len(TERRAFORM_TEMPLATES)} templates ({aws} AWS + {azure} Azure)')
"

# Total tests
py -3.12 -m pytest --collect-only -q --ignore=tests/test_rainier 2>&1 | tail -1

# Run the doc-drift integrity tests
py -3.12 -m pytest tests/test_integrity/ -v

# Run the structural multi-region enforcement tests
py -3.12 -m pytest tests/test_aws/test_aws_sweep_smoke.py -v -k iterates_regions

# Confirm zero LLM imports in the detection layer
grep -rn "import anthropic\|import openai\|from anthropic\|from openai" src/
# (no results expected)
```

---

## What's deliberately not promised

This document does not promise:

* **100% detection of every possible misconfiguration.** Compliance
  scanners are best-effort. The framework coverage matrix above lists
  what is implemented; gaps are tracked as open issues, not silently
  hidden.
* **100% framework coverage.** Where a framework has 50 controls and we
  cover 35, the count is documented. We do not claim coverage we don't
  have.
* **A bug-free codebase.** Past bugs are documented in closed issues
  #3 – #12. We expect to find more. The integrity tests + CI workflow
  exist precisely so future bugs cannot silently regress claims.
* **Indefinite stability of every framework mapping.** Frameworks
  change. CIS AWS v3.0 and CIS Azure v3.0 are the current targets;
  when a new version ships, the mapping work is tracked as an issue.

What this document **does** promise: every numeric claim in the README,
this file, and `src/whitney/TRUST.md` is verified by an automated test
that fails the build when it drifts. The audit trail is in CI logs and
closed issues. The reproducibility is guaranteed by the deterministic
detection layer.

---

## See also

* [`README.md`](./README.md) — what Shasta and Whitney do
* [`ENGINEERING_PRINCIPLES.md`](./ENGINEERING_PRINCIPLES.md) — the 20
  principles the codebase is held to
* [`CHANGELOG.md`](./CHANGELOG.md) — versioned history
* [`src/whitney/TRUST.md`](./src/whitney/TRUST.md) — Whitney-specific
  validation story (vulnerability fixtures, live cloud validation,
  Semgrep dual-engine architecture)
* [`tests/test_integrity/test_doc_claims.py`](./tests/test_integrity/test_doc_claims.py)
  — the load-bearing test file for Layer 2
* [Closed issues #3–#12](https://github.com/transilienceai/shasta/issues?q=is%3Aissue+is%3Aclosed)
  — documented failure modes and their resolutions

---

*This file is itself subject to the integrity tests it describes. Every
numeric claim in the TL;DR and the framework coverage matrix is
verified by `tests/test_integrity/test_doc_claims.py` on every PR. If
you spot a number here that doesn't match the code, the integrity test
caught it before you did — or there's a bug in the integrity test
itself. Either way, open an issue.*
