# Contributing to Transilience Community Compliance

Thanks for contributing. This repository is intended to be a commodity-quality open-source compliance toolkit, so changes should improve clarity, reproducibility, and operator trust.

## Before you start

1. Open or link an issue describing the change.
2. Confirm the scope is AWS-first unless the issue explicitly expands it.
3. Avoid features that auto-modify customer infrastructure.

## Development workflow

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
ruff check .
pytest
python -m build
```

## Pull requests

- Use small, reviewable PRs.
- Use conventional commit subjects when possible.
- Update docs and examples for user-facing behavior changes.
- Add tests for CLI, config, report, or scan behavior changes.
- Do not include secrets, customer identifiers, or real cloud evidence in commits.

## Design guidelines

- Keep the CLI stable and explicit.
- Prefer readable artifacts over deeply nested schemas.
- Treat reports, evidence, and remediation output as user-facing interfaces.
- Preserve provenance and attribution for the derivative work.

