# Architecture

The project keeps a straightforward pipeline:

1. `AWSClient` validates credentials and discovers account context.
2. Domain scanners evaluate AWS resources and emit `Finding` objects.
3. Framework mappers enrich findings with SOC 2 and ISO 27001 context.
4. Reports, remediation bundles, evidence, and workflow artifacts are generated from the stored scan data.

## Core modules

- `aws/`: AWS service checks and account discovery
- `compliance/`: framework catalogs, scoring, and control mapping
- `reports/`: Markdown, HTML, PDF, and ISO 27001 outputs
- `remediation/`: Terraform remediation generation
- `workflows/`: access reviews and risk register helpers
- `sbom/` and `threat_intel/`: supply-chain and advisory workflows
- `db/`: local SQLite persistence
- `cli.py`: public command surface

## Persistence

- Stored scan history: `data/transilience-compliance.db`
- Raw scan JSON: `data/scans/`
- Reports: `data/reports/`
- Evidence: `data/evidence/`
- SBOM and advisory artifacts: `data/sbom/`, `data/advisories/`

