"""Trust center page generator.

Mirrors the pattern in src/shasta/reports/generator.py:
build context dict from data sources → render Jinja2 template → write file.

Engineering Principle #1: all numbers from live data, never hardcoded.
Engineering Principle #5: missing scan data → "Not yet scanned".
Engineering Principle #11: pure Jinja2, zero LLM calls.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from jinja2 import BaseLoader, Environment

from shasta.trustcenter.config import TrustCenterConfig, load_config
from shasta.trustcenter.template import HTML_TEMPLATE

# Sentinel value to distinguish "caller didn't pass scan" from "caller passed None"
_SENTINEL = object()


def _domain_pass_rate(domain_breakdown: dict, domain: str) -> int | None:
    """Calculate pass rate for a specific domain. Returns 0-100 or None if no data."""
    counts = domain_breakdown.get(domain)
    if not counts:
        return None
    total = counts.get("pass", 0) + counts.get("fail", 0) + counts.get("partial", 0)
    if total == 0:
        return None
    return round(counts.get("pass", 0) / total * 100)


def build_trust_center_context(
    config: TrustCenterConfig,
    scan: Any | None = None,
) -> dict:
    """Build Jinja2 template context from scan data and config.

    If scan is None, all numeric sections show "Not yet scanned".
    All numbers are derived from live scorer outputs.
    """
    context: dict[str, Any] = {
        "config": config,
        "generated_at": datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
        "has_scan_data": False,
        "soc2_score": None,
        "iso_score": None,
        "hipaa_score": None,
        "domain_breakdown": {},
        "policies": [],
        "cloud_providers": [],
        "domains_scanned": [],
        "scan_date": None,
        "account_id_suffix": "****",
        "encryption_pass_rate": None,
        "iam_pass_rate": None,
        "monitoring_pass_rate": None,
    }

    # Load policies (always available, regardless of scan state)
    try:
        from shasta.policies.generator import list_policies

        context["policies"] = list_policies()
    except Exception:
        pass

    if scan is None:
        return context

    # We have scan data — populate everything from it
    context["has_scan_data"] = True
    findings = scan.findings

    # Compliance scores
    if config.show_soc2:
        try:
            from shasta.compliance.scorer import calculate_score

            context["soc2_score"] = calculate_score(findings)
        except Exception:
            pass

    if config.show_iso27001:
        try:
            from shasta.compliance.iso27001_scorer import calculate_iso27001_score

            context["iso_score"] = calculate_iso27001_score(findings)
        except Exception:
            pass

    if config.show_hipaa:
        try:
            from shasta.compliance.hipaa_scorer import calculate_hipaa_score

            context["hipaa_score"] = calculate_hipaa_score(findings)
        except Exception:
            pass

    # Domain breakdown from scan summary
    if scan.summary and scan.summary.by_domain:
        context["domain_breakdown"] = scan.summary.by_domain

    # Data protection pass rates
    context["encryption_pass_rate"] = _domain_pass_rate(context["domain_breakdown"], "encryption")
    context["iam_pass_rate"] = _domain_pass_rate(context["domain_breakdown"], "iam")
    context["monitoring_pass_rate"] = _domain_pass_rate(context["domain_breakdown"], "monitoring")

    # Infrastructure info
    cloud_providers = set()
    for f in findings:
        cp = getattr(f, "cloud_provider", None)
        if cp:
            cloud_providers.add(cp.value.upper() if hasattr(cp, "value") else str(cp).upper())
    context["cloud_providers"] = sorted(cloud_providers)

    context["domains_scanned"] = (
        [d.value for d in scan.domains_scanned] if scan.domains_scanned else []
    )
    context["scan_date"] = (
        scan.completed_at.strftime("%Y-%m-%d") if scan.completed_at else "In progress"
    )

    # Privacy: truncate account ID to last 4 characters
    account_id = scan.account_id or ""
    context["account_id_suffix"] = account_id[-4:] if len(account_id) >= 4 else account_id

    return context


def generate_trust_center(
    config: TrustCenterConfig | None = None,
    output_path: Path | str = "data/trust-center",
    scan: Any | None = _SENTINEL,
) -> Path:
    """Generate a trust center page and return the path to index.html.

    1. Load config (defaults → shasta.config.json → trust-center.config.json)
    2. Load latest scan from ShastaDB (if available), or use the provided scan
    3. Build context from scan data + config
    4. Render Jinja2 template
    5. Write output_path/index.html

    Pass ``scan=None`` explicitly to force the "Not yet scanned" path
    (useful in tests). Omit ``scan`` entirely to auto-load from the DB.
    """
    cfg = load_config(config)

    # Try to load the latest scan from the database, unless caller provided one
    if scan is _SENTINEL:
        scan = None
        try:
            from shasta.db.schema import ShastaDB

            db = ShastaDB()
            db.initialize()
            scan = db.get_latest_scan()
        except Exception:
            pass

    context = build_trust_center_context(cfg, scan)

    # Render template
    env = Environment(loader=BaseLoader(), autoescape=True)
    template = env.from_string(HTML_TEMPLATE)
    html = template.render(**context)

    # Write output
    out_dir = Path(output_path)
    out_dir.mkdir(parents=True, exist_ok=True)
    filepath = out_dir / "index.html"
    filepath.write_text(html, encoding="utf-8")

    return filepath
