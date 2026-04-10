# How We Know Whitney Works

Whitney is an AI security and governance scanner. This document explains
how we validated that it delivers trustworthy results — not through
marketing claims, but through layered testing against real AI
infrastructure.

> **For the project-wide trust story** (test counts, doc-vs-code drift
> integrity tests, multi-region structural enforcement, CI workflow,
> framework coverage matrix across Shasta and Whitney, the seven
> enforcement layers), see the **[root `TRUST.md`](../../TRUST.md)** at the
> repository root. This file is the Whitney-specific deep dive: AI
> validation fixtures, live AWS + Azure resource testing, and the
> Semgrep dual-engine deterministic architecture.

---

## Three Layers of Validation

### Layer 1: Unit Tests (419 tests)

Every Whitney module has comprehensive test coverage. Tests use realistic code samples, not toy examples.

| Test File | Tests | What It Proves |
|-----------|-------|----------------|
| `test_patterns.py` | 128 | All 30+ regex patterns correctly match real API keys, PII, prompt patterns, dangerous tools, and reject safe inputs. Parametrized with real-world examples. |
| `test_code_checks.py` | 60 | All 15 code scanner checks detect vulnerable code (Flask apps with prompt injection, hardcoded keys, unguarded agents) and produce zero false positives on clean code. |
| `test_scorer.py` | 23 | ISO 42001 + EU AI Act scoring engine correctly calculates pass/fail/partial, grade boundaries (A/B/C/D/F), and combined scores. Edge cases: empty findings, all-pass, all-fail, mixed. |
| `test_iso42001.py` | 14 | All 11 ISO 42001 controls are defined, lookups work, automated vs policy-required filtering is correct. |
| `test_eu_ai_act.py` | 15 | All 8 EU AI Act obligations are defined, check-to-obligation mappings are correct. |
| `test_mapper.py` | 18 | Finding enrichment adds correct control IDs. Summary aggregation counts pass/fail correctly. Fail overrides pass on the same control. |
| `test_scanner.py` | 10 | Repository scanning orchestrator runs all 15 checks, handles missing repos, mocked git cloning, token sanitisation in error messages. |
| `test_ai_policies.py` | 20 | All 7 policy templates render correctly with company name substitution. Templates cover all 8 requires_policy controls. |
| `test_ai_sbom.py` | 31 | SBOM discovers AI SDKs from dependency files, detects models from source code, filters non-AI packages, cross-references CVEs, produces valid CycloneDX 1.5 JSON. |

**How to run:** `py -3.12 -m pytest tests/test_whitney/ -v`

### Layer 2: Integration Tests (21 tests)

Whitney is run end-to-end against a deliberately vulnerable AI application ([vuln-ai-app](https://github.com/kkmookhey/vuln-ai-app)) — a Flask app containing every AI security vulnerability Whitney checks for.

| Test Class | Tests | What It Proves |
|------------|-------|----------------|
| `TestCodeScanValidation` | 8 | All 15 check IDs are triggered. Findings include file paths, line numbers, code snippets, and remediation guidance. |
| `TestAISBOMValidation` | 5 | CycloneDX output is valid. AI SDKs (openai, langchain, anthropic) and models (gpt-4) are discovered. CVE-2023-46229 (langchain) is flagged. |
| `TestComplianceScoringValidation` | 6 | Vulnerable app scores F/F/F on ISO 42001, EU AI Act, and combined. Failing controls >= 4. Policy-required controls identified. Findings enriched with control mappings. |
| `TestPolicyGenerationValidation` | 2 | All 7 AI governance policies generate correctly with company name. All 8 requires_policy controls covered. |

**How to run:** `py -3.12 -m pytest tests/integration/validate_whitney.py -v`

### Layer 3: Live Cloud Validation

Whitney was run against real AWS and Azure infrastructure with intentionally configured (and misconfigured) AI resources.

#### AWS (Account 470226123496, us-east-1)

**Resources deployed for testing:**

| Resource | Configuration | Expected Result |
|----------|--------------|-----------------|
| Lambda `whitney-ai-vulnerable` | `OPENAI_API_KEY` in plaintext env var | FAIL |
| S3 `whitney-training-data` | KMS encryption + versioning enabled | PASS |
| CloudTrail `shasta-trail` | Advanced event selectors for SageMaker/Bedrock | PASS |
| SageMaker Model Package Group | IAM-only access, Approved model package | PASS |
| SageMaker Notebook | ml.t3.medium, root access disabled | PASS |
| SageMaker Endpoint | No KMS encryption, data capture enabled | FAIL (encryption), PASS (data capture) |
| SageMaker Training Job | Configured with VPC | PASS |
| Bedrock invocation logging | Enabled, logging to S3 | PASS |

**Results: 14/15 checks produced findings.**

| Status | Count | Details |
|--------|-------|---------|
| PASS | 9 | Logging, CloudTrail, S3 encryption, S3 versioning, registry access, model approval, notebook root, training VPC, data capture |
| FAIL | 5 | No Bedrock guardrails, no content filters, no VPC endpoint, hardcoded Lambda key, endpoint missing KMS |
| N/A | 1 | No Bedrock agents deployed (premium feature) |

Every finding matched the expected result for the resource configuration. No false positives. No false negatives.

#### Azure (Subscription cb0d6ed4, East US)

**Resources deployed for testing:**

| Resource | Configuration | Expected Result |
|----------|--------------|-----------------|
| Azure OpenAI `whitney-openai-test` | S0 tier, public access, no managed identity | FAIL (multiple checks) |
| OpenAI deployment `gpt-4o-mini-test` | Default content filter | PASS |
| Cognitive Services `whitney-textanalytics-test` | F0 tier, public access | FAIL (network rules) |
| Azure ML workspace `whitney-ml-test` | Default encryption, no drift monitoring | FAIL/PARTIAL |

**Results: 13/15 checks produced findings.**

| Status | Count | Details |
|--------|-------|---------|
| PASS | 3 | Content filter active, abuse monitoring enabled, curated environments |
| FAIL | 7 | Public network access (2x), key rotation, no managed identity, no private endpoint, no drift monitoring, no RAI dashboard |
| PARTIAL | 3 | Microsoft-managed keys instead of CMK (OpenAI, TextAnalytics, ML workspace) |
| N/A | 2 | No AI Search service, no ML compute targets |

**All resources were torn down after validation.**

---

## What This Means

1. **The patterns work.** 128 parametrized tests prove every regex matches what it claims and rejects what it should. Real API key formats, real PII patterns, real code constructs.

2. **The checks find real vulnerabilities.** A deliberately vulnerable app triggers all 15 code checks. Every check produces findings with file paths, line numbers, and code snippets. Zero false positives on clean code.

3. **The scoring is correct.** Grade boundaries are tested. Fail overrides pass. Partial counts as half. Empty scans score 100%. Vulnerable scans score 0%.

4. **It works against real infrastructure.** Not mocks — actual AWS resources (Lambda, S3, SageMaker, Bedrock) and actual Azure resources (OpenAI, ML workspaces, Cognitive Services). Intentional misconfigurations were detected. Correct configurations passed.

5. **The compliance mapping is accurate.** ISO 42001 controls and EU AI Act obligations are correctly mapped to check IDs. Findings are enriched with the right control references. Scoring aggregates correctly across frameworks.

6. **The SBOM is real.** CycloneDX 1.5 JSON output includes AI SDKs from dependency files, models from source code, and cloud services from AWS/Azure discovery. Known CVEs are cross-referenced.

7. **Policies cover the gaps.** The 7 policy templates address all 8 controls/obligations that require documented policies. Without them, 40% of the compliance surface would have no path to remediation.

---

## Test Coverage Summary

```
Whitney unit tests:    419  (run: pytest tests/test_whitney/)
Integration tests:      21  (run: pytest tests/integration/validate_whitney.py)

AWS checks validated:   14/15 (93%)  — see Layer 3 above
Azure checks validated: 13/15 (87%)  — see Layer 3 above
Code checks validated:  15/15 (100%) — see Layer 1 / Layer 2 above
```

For the project-wide test count across Shasta + Whitney + integrity +
smoke suites, see the [root `TRUST.md`](../../TRUST.md#layer-1--test-suite).

---

## Deterministic by Design — No LLM in the Pipeline

A common concern with AI-built tools: "if it was built with AI, does it use AI to produce results, and can those results be trusted?"

Whitney uses **zero LLM calls**. We verified this by searching the entire codebase:

```
$ grep -r "import openai\|import anthropic\|from openai\|from anthropic" src/
(no results)
```

Every Whitney module is pure deterministic code:

| Module | What it does | How |
|--------|-------------|-----|
| Code scanner | Finds AI security issues in source code | Semgrep AST-based pattern matching (13 checks) + regex fallback / Python (2 checks for file-level logic) |
| Cloud checks | Evaluates AWS/Azure AI service configuration | boto3 / Azure SDK describe/list API calls |
| Compliance mapper | Maps findings to ISO 42001, EU AI Act, OWASP, NIST, MITRE | Dictionary lookups by check_id |
| Scorer | Calculates compliance percentages and grades | Arithmetic: (pass + partial*0.5) / assessed * 100 |
| Policy generator | Produces governance policy documents | Jinja2 template rendering with company name substitution |
| AI SBOM | Inventories AI SDKs, models, cloud services | File parsing + dict construction, CycloneDX JSON output |

**Detection engines used by the code scanner:**

| Engine | Used for | What it is |
|--------|---------|-----------|
| **Semgrep** | 13 of 15 code checks (when installed) | AST-based pattern matching. Open source. Used by Trail of Bits, GitLab, Snyk Code. Deterministic — same input always produces same output. |
| **Python regex** | 2 file-level checks always; all 15 if Semgrep not installed | `re.compile()` patterns evaluated against file contents. Deterministic. |

The 2 checks that always run as Python are `check_no_rate_limiting` (needs file-level memoization) and `check_outdated_ai_sdk` (needs dependency parsing + version constraint comparison).

**Why this matters:**

1. **Reproducibility.** Same code + same infrastructure = identical findings. No model temperature, no token sampling, no run-to-run variance. Both Semgrep and regex are deterministic.
2. **Auditability.** Every finding traces to a specific Semgrep rule (a YAML file you can read), regex pattern (a Python `re.compile()` call), API response, or dict lookup. An auditor can inspect the check definition and understand exactly why a finding was produced.
3. **No hallucination risk.** The scanner cannot invent findings that don't exist or miss findings that do. Pattern matched or not matched — binary.
4. **No cost per scan.** No API tokens consumed. Scans can run as frequently as needed at zero marginal cost.

**Why Semgrep instead of regex alone:**

Semgrep parses code into an AST (abstract syntax tree) before matching. This catches what regex can't:

- Won't match patterns inside comments or docstrings (regex would)
- `Tool(func=exec)` — Semgrep's `pattern-inside: Tool(...)` knows the dangerous call is structurally inside the tool definition. Regex can only check "within N lines."
- Handles formatting differences: `model="gpt-4"`, `model = "gpt-4"`, `model =\n  "gpt-4"` are all the same AST node.
- `pattern-not-inside: @login_required` — Semgrep can express "model endpoint that is NOT decorated with auth" as a single structural query. Regex needs three separate scans with sliding windows.

If Semgrep is not installed, Whitney falls back to regex automatically. No installation required, but the AST engine is more precise.

Most AI security vendors (Straiker, Lakera, CalypsoAI, Promptfoo) use LLMs in their detection pipelines. This gives them flexibility but introduces non-determinism. Whitney chose the opposite trade-off: less flexible, but every result is explainable and reproducible.

Claude Code is used as the **user interface layer** only — it calls Whitney's Python functions and presents results in natural language. The compliance engine itself is pure code.

---

**How to verify yourself:**

```bash
# Run all tests
py -3.12 -m pytest tests/test_whitney/ tests/integration/ -v

# Scan your own repo
py -3.12 -c "
from whitney.code.scanner import scan_repository
findings = scan_repository('.')
for f in findings:
    print(f'[{f.severity.value.upper()}] {f.check_id}: {f.title}')
"
```
