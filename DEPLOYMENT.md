# Deployment Guide

This project is designed to run locally or in a trusted automation environment with AWS credentials and Python 3.11+ available.

## Local setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
cp examples/config.example.toml config.toml
transilience-compliance connect-aws --profile compliance
```

## CI or scheduled execution

- Provide AWS credentials via your runner's secret store or workload identity.
- Mount or generate `config.toml` at runtime.
- Persist the `data/` directory if you want scan history, evidence history, and generated reports to survive between runs.
- Keep the AWS role read-only. Remediation output is generated as reviewable Terraform, not applied automatically.

## Recommended automation flow

```bash
transilience-compliance scan --framework both
transilience-compliance report --framework soc2 --format all
transilience-compliance evidence
transilience-compliance threat-advisory --lookback-days 1
```

For least-privilege IAM guidance, see [docs/aws-permissions.md](docs/aws-permissions.md).

