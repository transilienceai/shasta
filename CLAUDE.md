# Shasta — Multi-Cloud Compliance Automation

## What is this?
Shasta is a Claude Code-native SOC 2 and ISO 27001 compliance platform. It scans AWS and Azure environments, maps findings to compliance controls, generates remediation guidance (with Terraform), and produces compliance policies and reports.

## Tech stack
- Python 3.11+, boto3, azure-identity, azure-mgmt-*, msgraph-sdk, rich, pydantic, jinja2, weasyprint
- SQLite for local data storage
- Claude Code skills for user interface

## Project layout
- `src/shasta/` — cloud compliance library (SOC 2, ISO 27001)
- `src/shasta/aws/` — AWS check modules (boto3)
- `src/shasta/azure/` — Azure check modules (azure-mgmt-*, msgraph-sdk)
- `src/shasta/compliance/ai/` — AI governance frameworks (ISO 42001, EU AI Act, NIST AI RMF)
- `src/shasta/aws/ai_checks.py` — AWS AI service checks (Bedrock, SageMaker)
- `src/shasta/azure/ai_checks.py` — Azure AI service checks (Azure OpenAI, Azure ML)
- `.claude/skills/` — Claude Code skill definitions
- `tests/` — pytest test suite (uses moto for AWS mocking, unittest.mock for Azure)
- `data/` — runtime data (gitignored)

## Commands
- Install: `pip install -e ".[dev]"` (core) or `pip install -e ".[dev,azure]"` (with Azure)
- Test: `pytest`
- Lint: `ruff check src/ tests/`
- Format: `ruff format src/ tests/`

## Conventions
- Use pydantic models for all data structures
- All AWS calls go through `src/shasta/aws/client.py` session management
- All Azure calls go through `src/shasta/azure/client.py` session management
- Every check function returns a list of `Finding` objects
- Use `rich` for terminal output formatting
- Keep functions focused — one check per function
- Type hints on all function signatures

## Engineering principles (load-bearing — apply on every change)

The full set is in [`ENGINEERING_PRINCIPLES.md`](./ENGINEERING_PRINCIPLES.md) — read it
once before your first PR. The 8 most load-bearing rules are inlined here so
they are in context at every conversation start:

1. **Numbers in docs are tests waiting to be written.** Every "X checks" /
   "Y templates" / "N tests" claim in `README.md`, `CHANGELOG.md`, or
   `TRUST.md` must be backed by a test in
   `tests/test_integrity/test_doc_claims.py` that AST-counts the source.
   Bumping a count in code without updating the doc (or vice versa) must
   fail the build. Lines with `~~strikethrough~~` are skipped — historical
   narrative is preserved.

2. **No stub functions.** A `check_*` / `run_*` / `generate_*` function
   whose body is `pass`, `return []`, `return None`, or docstring-only is a
   build break. Either implement it or delete it. The integrity tests in
   `tests/test_whitney/test_integrity.py` enforce this for Whitney; extend
   the same pattern when adding new modules.

3. **Default to multi-region / multi-subscription.** New AWS check modules
   must iterate `client.get_enabled_regions()` via `client.for_region(r)`.
   New Azure check modules must call sites via `AzureClient.for_subscription(sid)`
   when scanning multiple subscriptions. Single-region/single-subscription is
   the explicit override, never the default.

4. **Frameworks belong on the `Finding` model.** Populate
   `soc2_controls`, `cis_aws_controls`, `cis_azure_controls`, `mcsb_controls`,
   `iso27001_controls`, `hipaa_controls` as appropriate. Never embed a control
   ID in a free-text description string — it can't be aggregated, scored, or
   exported that way.

5. **Detection layer is deterministic. Zero LLM calls** in scanning, scoring,
   mapping, policy generation, or report pipelines. SDK calls, AST matching,
   dictionary lookups, arithmetic only. The LLM lives in the user-interface
   layer (Claude Code skills) translating findings into natural language —
   not finding them. This is enforced by `tests/test_whitney/test_integrity.py`.

6. **Treat empty results different from errors.** Use `NOT_ASSESSED` when an
   API call failed or permission was denied; `NOT_APPLICABLE` when the
   account legitimately has no resources of that type; `FAIL` only for
   actual non-compliance. Conflating them produces false-clean reports —
   the worst possible failure mode for a compliance tool.

7. **Cross-cutting walkers beat per-service code.** When you find yourself
   about to write the same gap N times across different services
   (`check_X_has_private_endpoint`, `check_Y_has_private_endpoint`, ...),
   stop and write a walker — see `src/shasta/azure/private_endpoints.py`,
   `src/shasta/aws/vpc_endpoints.py`, `src/shasta/azure/diagnostic_settings.py`
   for the pattern. One walker beats N near-duplicate functions.

8. **Lease-protected force pushes only.** When pushing to a shared branch
   with divergent history, use `git push --force-with-lease=<ref>:<sha>` so
   the push fails safely if anyone else pushed in the interval. Never use
   raw `--force` on `main` or `release/*` branches.

## When in doubt
- Default to fail-closed. A check that errors out reports `NOT_ASSESSED`, not `PASS`.
- Default to citing the rule. Every check should reference the framework section it implements.
- Default to deletion over deprecation. Unused code rots — delete it, don't leave a stub.
- Default to honesty. If something isn't done, say so. Trust outweighs marketing benefit.

## Required tests on every PR
- `pytest tests/test_integrity/` — doc-vs-code drift integrity tests
- `pytest tests/test_aws/test_aws_sweep_smoke.py` — AWS module structural smoke tests
- `pytest tests/test_azure/test_smoke.py` — Azure module structural smoke tests

These are mechanically enforced by `.github/workflows/integrity.yml` on every PR.
A drift in any tracked numeric claim (or a stub-shaped function, or a missing
template) fails the build until either the code is restored or the doc is updated.

## Slash commands
- `/audit` — walks staged changes against the engineering principles checklist
  and reports pass/fail per principle. Run before any non-trivial commit.
