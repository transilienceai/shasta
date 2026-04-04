# Transilience Community Compliance

<div align="center">

[![MIT License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![CI](https://img.shields.io/github/actions/workflow/status/transilienceai/transilience-communitytools-compliance/ci.yml?branch=main&label=CI)](../../actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/Python-3.11%2B-blue.svg)](pyproject.toml)

AWS-first open-source compliance automation for teams that want reproducible SOC 2 and ISO 27001 evidence, reports, and remediation guidance without a SaaS control plane.

[Quick Start](#quick-start) | [CLI](#cli) | [Architecture](docs/architecture.md) | [Contributing](CONTRIBUTING.md) | [Security](SECURITY.md)

</div>

---

## Overview

Transilience Community Compliance is a terminal-first compliance toolkit for AWS environments. It validates access, scans cloud configuration, maps findings to SOC 2 and ISO 27001 controls, generates auditor-friendly reports, produces Terraform remediation bundles, and collects evidence snapshots you can keep in version control.

This repository is derived from `shasta` and published with permission from KK. Provenance is documented in [NOTICE](NOTICE).

### What it includes

- AWS security and compliance scanning across IAM, networking, storage, encryption, monitoring, and Inspector-backed vulnerability checks
- Control mapping for SOC 2 and ISO 27001
- Markdown, HTML, and PDF compliance reporting
- Terraform-oriented remediation guidance
- Policy document generation for the controls automation cannot satisfy on its own
- Evidence collection, IAM access review, SBOM generation, and threat advisory workflows

### What it does not do

- It does not auto-remediate your AWS account
- It does not replace auditor judgment or company-owned policies/processes
- It does not promise multi-cloud support in v1

## Quick Start

### 1. Clone and install

```bash
git clone git@github.com:transilienceai/transilience-communitytools-compliance.git
cd transilience-communitytools-compliance
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### 2. Configure AWS credentials

Use a normal AWS profile or environment variables.

```bash
aws configure --profile compliance
```

For a tightly scoped read-only policy, start from [infra/transilience-compliance-scanning-policy.json](infra/transilience-compliance-scanning-policy.json) and the detailed notes in [docs/aws-permissions.md](docs/aws-permissions.md).

### 3. Save local config

```bash
cp examples/config.example.toml config.toml
transilience-compliance connect-aws --profile compliance --company-name "Example Co"
```

### 4. Run a scan and generate reports

```bash
transilience-compliance scan --framework both
transilience-compliance report --framework soc2 --format all
transilience-compliance report --framework iso27001
transilience-compliance remediate
```

## CLI

### Core commands

```bash
transilience-compliance connect-aws
transilience-compliance scan
transilience-compliance report
transilience-compliance remediate
transilience-compliance policy-gen
transilience-compliance review-access
transilience-compliance evidence
transilience-compliance sbom
transilience-compliance threat-advisory
```

### Common examples

```bash
# Validate AWS access and store config.toml
transilience-compliance connect-aws --profile compliance --region us-east-1

# Run a focused IAM/storage scan
transilience-compliance scan --framework both --domain iam --domain storage

# Generate HTML/PDF SOC 2 reporting from the latest stored scan
transilience-compliance report --framework soc2 --format all

# Generate policy docs for audit prep
transilience-compliance policy-gen --company-name "Example Co"

# Collect evidence snapshots tied to the latest scan
transilience-compliance evidence
```

## Repository Layout

```text
transilience-communitytools-compliance/
├── docs/                         # Architecture, permissions, framework notes
├── examples/                     # Sample config and usage artifacts
├── infra/                        # Read-only IAM policy and test environment
├── src/transilience_compliance/  # Python package and CLI
└── tests/                        # Unit and smoke tests
```

## Development

```bash
pip install -e ".[dev]"
ruff check .
pytest
python -m build
```

Contribution and workflow details live in [CONTRIBUTING.md](CONTRIBUTING.md).

## Responsible Use

Use this project only on systems and accounts you own or are explicitly authorized to assess. The tooling is designed to help security and compliance programs, not to bypass access controls or perform unauthorized testing.

## License

MIT. See [LICENSE](LICENSE).

