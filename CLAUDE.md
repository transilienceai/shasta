# Shasta — AWS Compliance Automation

## What is this?
Shasta is a Claude Code-native SOC 2 compliance platform. It scans AWS environments, maps findings to SOC 2 controls, generates remediation guidance (with Terraform), and produces compliance policies and reports.

## Tech stack
- Python 3.11+, boto3, rich, pydantic, jinja2, weasyprint
- SQLite for local data storage
- Claude Code skills for user interface

## Project layout
- `src/shasta/` — core Python library
- `skills/` — Claude Code skill definitions
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
