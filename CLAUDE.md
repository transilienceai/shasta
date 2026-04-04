# Transilience Community Compliance

## Working assumptions

- Keep the project AWS-first unless a task explicitly introduces another provider.
- Prefer additive changes over broad rewrites; preserve the current scanning/reporting behavior unless the task requires a change.
- Remediation output must remain review-first. Do not introduce automatic mutation of customer AWS environments.

## Code layout

- `src/transilience_compliance/cli.py` contains the public CLI surface.
- `src/transilience_compliance/aws/` contains AWS discovery and checks.
- `src/transilience_compliance/compliance/` contains framework mappings and scoring.
- `src/transilience_compliance/reports/` contains report generation.
- `src/transilience_compliance/remediation/` contains Terraform guidance.
- `src/transilience_compliance/workflows/` contains review/evidence-oriented workflows.

## Quality bar

- Keep config and artifact formats stable.
- Add or update tests with behavior changes.
- Prefer readable, auditable output over clever abstractions.

