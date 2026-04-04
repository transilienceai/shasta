"""Command-line interface for Transilience Community Compliance."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Iterable

from transilience_compliance.aws.client import AWSClient, AWSClientError
from transilience_compliance.config import CONFIG_FILENAME, load_config, save_config
from transilience_compliance.db.schema import ComplianceDB
from transilience_compliance.evidence.collector import collect_all_evidence
from transilience_compliance.evidence.models import CheckDomain, ScanResult
from transilience_compliance.policies.generator import POLICIES, generate_all_policies, generate_policy
from transilience_compliance.remediation.engine import (
    generate_all_remediations,
    save_terraform_bundle,
)
from transilience_compliance.reports.generator import (
    save_html_report,
    save_markdown_report,
)
from transilience_compliance.reports.iso27001_report import save_iso27001_markdown_report
from transilience_compliance.reports.pdf import save_pdf_report
from transilience_compliance.sbom.discovery import discover_sbom, save_sbom
from transilience_compliance.sbom.vuln_scanner import (
    save_vuln_report,
    scan_sbom_vulnerabilities,
)
from transilience_compliance.scanner import run_full_scan
from transilience_compliance.threat_intel.advisory import (
    save_advisory_report,
    generate_daily_advisory,
)
from transilience_compliance.workflows.access_review import run_access_review, save_access_review


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="transilience-compliance",
        description="AWS-first compliance automation toolkit for SOC 2 and ISO 27001 workflows.",
    )
    parser.add_argument(
        "--config",
        help=f"Path to a config file. Defaults to the nearest {CONFIG_FILENAME}.",
    )

    subparsers = parser.add_subparsers(dest="command")

    connect = subparsers.add_parser("connect-aws", help="Validate AWS access and save local config.")
    connect.add_argument("--profile", help="AWS profile name to use.")
    connect.add_argument("--region", default="us-east-1", help="AWS region to use.")
    connect.add_argument("--company-name", help="Company name for generated artifacts.")
    connect.add_argument(
        "--github-repo",
        action="append",
        dest="github_repos",
        default=None,
        help="GitHub repo to include in configuration. Repeat for multiple repos.",
    )
    connect.set_defaults(func=cmd_connect_aws)

    scan = subparsers.add_parser("scan", help="Run an AWS compliance scan and persist the result.")
    _add_aws_args(scan)
    scan.add_argument(
        "--framework",
        choices=("soc2", "iso27001", "both"),
        default="both",
        help="Compliance mapping to attach to findings.",
    )
    scan.add_argument(
        "--domain",
        action="append",
        choices=[domain.value for domain in CheckDomain if domain not in {CheckDomain.LOGGING, CheckDomain.COMPUTE}],
        default=None,
        help="Limit the scan to a specific domain. Repeat for multiple domains.",
    )
    scan.add_argument(
        "--include-github",
        action="store_true",
        help="Include GitHub branch protection checks using configured repositories.",
    )
    scan.add_argument("--output-dir", help="Artifact directory. Defaults to config output_dir.")
    scan.set_defaults(func=cmd_scan)

    report = subparsers.add_parser("report", help="Generate reports from the latest or a specific stored scan.")
    report.add_argument("--scan-id", help="Stored scan ID. Defaults to the latest scan.")
    report.add_argument("--account-id", help="Load the latest scan for a specific AWS account.")
    report.add_argument("--output-dir", help="Report directory. Defaults to config output_dir/reports.")
    report.add_argument(
        "--framework",
        choices=("soc2", "iso27001"),
        default="soc2",
        help="Report framework to generate.",
    )
    report.add_argument(
        "--format",
        choices=("md", "html", "pdf", "all"),
        default="all",
        help="Output format for SOC 2 reports.",
    )
    report.set_defaults(func=cmd_report)

    remediate = subparsers.add_parser("remediate", help="Generate Terraform remediation bundles from a stored scan.")
    remediate.add_argument("--scan-id", help="Stored scan ID. Defaults to the latest scan.")
    remediate.add_argument("--account-id", help="Load the latest scan for a specific AWS account.")
    remediate.add_argument("--output-dir", help="Output directory. Defaults to config output_dir/remediation.")
    remediate.set_defaults(func=cmd_remediate)

    policy = subparsers.add_parser("policy-gen", help="Generate policy documents.")
    policy.add_argument("--company-name", help="Company name to render into policies.")
    policy.add_argument("--effective-date", help="Effective date to embed in generated policies.")
    policy.add_argument("--output-dir", help="Output directory. Defaults to config output_dir/policies.")
    policy.add_argument(
        "--policy",
        action="append",
        choices=sorted(POLICIES.keys()),
        default=None,
        help="Generate specific policy IDs instead of the full set. Repeat for multiple policies.",
    )
    policy.set_defaults(func=cmd_policy_gen)

    access_review = subparsers.add_parser("review-access", help="Generate an IAM access review report.")
    _add_aws_args(access_review)
    access_review.add_argument("--output-dir", help="Output directory. Defaults to config output_dir/reviews.")
    access_review.set_defaults(func=cmd_review_access)

    evidence = subparsers.add_parser("evidence", help="Collect point-in-time evidence snapshots.")
    _add_aws_args(evidence)
    evidence.add_argument("--scan-id", help="Existing scan ID to associate with evidence.")
    evidence.add_argument("--output-dir", help="Output directory. Defaults to config output_dir/evidence.")
    evidence.set_defaults(func=cmd_evidence)

    sbom = subparsers.add_parser("sbom", help="Generate an SBOM and optional vulnerability report.")
    _add_aws_args(sbom)
    sbom.add_argument("--output-dir", help="Output directory. Defaults to config output_dir/sbom.")
    sbom.add_argument(
        "--skip-vuln-scan",
        action="store_true",
        help="Skip the live OSV/CISA vulnerability lookup.",
    )
    sbom.set_defaults(func=cmd_sbom)

    advisory = subparsers.add_parser("threat-advisory", help="Generate a threat advisory from the live SBOM.")
    _add_aws_args(advisory)
    advisory.add_argument("--lookback-days", type=int, default=1, help="Recent threat window in days.")
    advisory.add_argument("--output-dir", help="Output directory. Defaults to config output_dir/advisories.")
    advisory.set_defaults(func=cmd_threat_advisory)

    return parser


def _add_aws_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--profile", help="AWS profile name to use.")
    parser.add_argument("--region", help="AWS region to use.")


def _load_runtime_config(args: argparse.Namespace) -> dict:
    config = load_config(getattr(args, "config", None))
    if getattr(args, "profile", None):
        config["aws_profile"] = args.profile
    if getattr(args, "region", None):
        config["aws_region"] = args.region
    return config


def _output_root(config: dict, explicit: str | None) -> Path:
    if explicit:
        return Path(explicit)
    return Path(config.get("output_dir", "data"))


def _artifact_dir(config: dict, explicit: str | None, leaf: str) -> Path:
    if explicit:
        return Path(explicit)
    return Path(config.get("output_dir", "data")) / leaf


def _build_client(config: dict) -> AWSClient:
    profile = config.get("aws_profile") or None
    region = config.get("aws_region") or "us-east-1"
    return AWSClient(profile_name=profile, region=region)


def _serialize_scan(scan: ScanResult, output_dir: Path) -> Path:
    scans_dir = output_dir / "scans"
    scans_dir.mkdir(parents=True, exist_ok=True)
    path = scans_dir / f"scan-{scan.account_id}-{scan.id}.json"
    path.write_text(scan.model_dump_json(indent=2), encoding="utf-8")
    return path


def _load_scan(args: argparse.Namespace, config: dict) -> ScanResult:
    db = ComplianceDB(_output_root(config, None) / "transilience-compliance.db")
    db.initialize()
    scan = db.get_scan(args.scan_id) if getattr(args, "scan_id", None) else db.get_latest_scan(getattr(args, "account_id", None))
    db.close()
    if not scan:
        raise ValueError("No stored scan found. Run `transilience-compliance scan` first.")
    return scan


def _print_paths(label: str, paths: Iterable[Path]) -> None:
    for path in paths:
        print(f"{label}: {path}")


def cmd_connect_aws(args: argparse.Namespace) -> int:
    config = _load_runtime_config(args)
    if args.company_name:
        config["company_name"] = args.company_name
    if args.github_repos is not None:
        config["github_repos"] = args.github_repos

    client = _build_client(config)
    info = client.validate_credentials()
    services = client.discover_services()

    config_path = save_config(config, args.config)
    print(f"Saved config: {config_path}")
    print(json.dumps(
        {
            "account_id": info.account_id,
            "region": info.region,
            "user_arn": info.user_arn,
            "services_in_use": services,
        },
        indent=2,
    ))
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    config = _load_runtime_config(args)
    output_root = _output_root(config, args.output_dir)
    client = _build_client(config)
    client.validate_credentials()
    client.discover_services()

    domains = [CheckDomain(value) for value in args.domain] if args.domain else None
    github_repos = config.get("github_repos", [])
    scan = run_full_scan(
        client,
        domains=domains,
        framework=args.framework,
        include_github=args.include_github,
        github_token=None,
        github_repos=github_repos,
    )

    db = ComplianceDB(output_root / "transilience-compliance.db")
    db.initialize()
    db.save_scan(scan)
    db.close()

    serialized_path = _serialize_scan(scan, output_root)
    print(f"Saved scan: {serialized_path}")
    if scan.summary:
        print(
            json.dumps(
                {
                    "scan_id": scan.id,
                    "account_id": scan.account_id,
                    "framework": args.framework,
                    "total_findings": scan.summary.total_findings,
                    "passed": scan.summary.passed,
                    "failed": scan.summary.failed,
                    "partial": scan.summary.partial,
                },
                indent=2,
            )
        )
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    scan = _load_scan(args, config)
    output_dir = _artifact_dir(config, args.output_dir, "reports")
    paths: list[Path] = []

    if args.framework == "iso27001":
        paths.append(save_iso27001_markdown_report(scan, output_dir))
    else:
        if args.format in ("md", "all"):
            paths.append(save_markdown_report(scan, output_dir))
        if args.format in ("html", "all"):
            paths.append(save_html_report(scan, output_dir))
        if args.format in ("pdf", "all"):
            paths.append(save_pdf_report(scan, output_dir))

    _print_paths("Generated report", paths)
    return 0


def cmd_remediate(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    scan = _load_scan(args, config)
    remediations = generate_all_remediations(scan.findings)
    output_dir = _artifact_dir(config, args.output_dir, "remediation")
    bundle = save_terraform_bundle(remediations, output_dir)
    print(f"Generated remediation bundle: {bundle}")
    print(f"Included remediations: {len(remediations)}")
    return 0


def cmd_policy_gen(args: argparse.Namespace) -> int:
    config = load_config(args.config)
    company_name = args.company_name or config.get("company_name") or "Acme Corp"
    output_dir = _artifact_dir(config, args.output_dir, "policies")

    if args.policy:
        generated: list[Path] = []
        output_dir.mkdir(parents=True, exist_ok=True)
        for policy_id in args.policy:
            content = generate_policy(
                policy_id,
                company_name=company_name,
                effective_date=args.effective_date,
            )
            path = output_dir / POLICIES[policy_id]["filename"]
            path.write_text(content, encoding="utf-8")
            generated.append(path)
    else:
        generated = generate_all_policies(
            company_name=company_name,
            output_path=output_dir,
            effective_date=args.effective_date,
        )

    _print_paths("Generated policy", generated)
    return 0


def cmd_review_access(args: argparse.Namespace) -> int:
    config = _load_runtime_config(args)
    client = _build_client(config)
    client.validate_credentials()
    report = run_access_review(client)
    output_dir = _artifact_dir(config, args.output_dir, "reviews")
    path = save_access_review(report, output_dir)
    print(f"Generated access review: {path}")
    return 0


def cmd_evidence(args: argparse.Namespace) -> int:
    config = _load_runtime_config(args)
    client = _build_client(config)
    client.validate_credentials()

    if args.scan_id:
        scan_id = args.scan_id
    else:
        db = ComplianceDB(_output_root(config, None) / "transilience-compliance.db")
        db.initialize()
        latest = db.get_latest_scan()
        db.close()
        scan_id = latest.id if latest else "manual-evidence-run"

    output_dir = _artifact_dir(config, args.output_dir, "evidence")
    paths = collect_all_evidence(client, scan_id=scan_id, output_path=output_dir)
    _print_paths("Collected evidence", paths)
    return 0


def cmd_sbom(args: argparse.Namespace) -> int:
    config = _load_runtime_config(args)
    client = _build_client(config)
    client.validate_credentials()
    report = discover_sbom(client)
    output_dir = _artifact_dir(config, args.output_dir, "sbom")

    generated = [save_sbom(report, output_dir)]
    if not args.skip_vuln_scan:
        generated.append(save_vuln_report(scan_sbom_vulnerabilities(report), output_dir))

    _print_paths("Generated artifact", generated)
    return 0


def cmd_threat_advisory(args: argparse.Namespace) -> int:
    config = _load_runtime_config(args)
    client = _build_client(config)
    client.validate_credentials()

    sbom = discover_sbom(client)
    report = generate_daily_advisory(sbom, lookback_days=args.lookback_days)
    output_dir = _artifact_dir(config, args.output_dir, "advisories")
    path = save_advisory_report(report, output_dir)
    print(f"Generated threat advisory: {path}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 0

    try:
        return args.func(args)
    except (AWSClientError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
