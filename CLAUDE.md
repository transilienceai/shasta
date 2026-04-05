# Shasta — Multi-Cloud Compliance Automation

## What is this?
Shasta is a Claude Code-native SOC 2 and ISO 27001 compliance platform. It scans AWS and Azure environments, maps findings to compliance controls, generates remediation guidance (with Terraform), and produces compliance policies and reports.

## Tech stack
- Python 3.11+, boto3, azure-identity, azure-mgmt-*, msgraph-sdk, rich, pydantic, jinja2, weasyprint
- SQLite for local data storage
- Claude Code skills for user interface

## Project layout
- `src/shasta/` — core Python library
- `src/shasta/aws/` — AWS check modules (boto3)
- `src/shasta/azure/` — Azure check modules (azure-mgmt-*, msgraph-sdk)
- `.claude/skills/` — Claude Code skill definitions
- `tests/` — pytest test suite (uses moto for AWS mocking)
- `data/` — runtime data (gitignored)

## Commands
- Install: `pip install -e ".[dev]"`
- Test: `pytest`
- Lint: `ruff check src/ tests/`
- Format: `ruff format src/ tests/`

## Conventions
- Use pydantic models for all data structures
- All AWS calls go through `src/shasta/aws/client.py` session management
- Every check function returns a list of `Finding` objects
- Use `rich` for terminal output formatting
- Keep functions focused — one check per function
- Type hints on all function signatures
