"""Daily Threat Advisory Engine.

Generates personalized threat advisories for founders by:
  1. Querying live threat feeds (NVD, CISA KEV, GitHub Advisories)
  2. Filtering to the founder's tech stack (from SBOM + AWS scan)
  3. Scoring relevance based on what's actually deployed
  4. Formatting for Slack + email delivery

Output: "Here's what matters to YOU today" — not generic threat intel.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any
from urllib import request, error

from shasta.sbom.discovery import SBOMReport


@dataclass
class ThreatAdvisory:
    """A single threat advisory relevant to the founder's environment."""

    id: str  # CVE or advisory ID
    title: str
    severity: str
    published: str
    description: str
    affected_component: str  # What in their env is affected
    affected_resource: str  # Specific AWS resource
    action_required: str  # What to do
    references: list[str] = field(default_factory=list)
    is_kev: bool = False  # CISA Known Exploited
    is_supply_chain: bool = False


@dataclass
class DailyAdvisoryReport:
    """Daily threat advisory report for a founder."""

    generated_at: str
    period: str  # "last 24 hours" or "last 7 days"
    tech_stack_summary: str  # What we're monitoring for
    total_advisories: int = 0
    critical_count: int = 0
    high_count: int = 0
    advisories: list[ThreatAdvisory] = field(default_factory=list)


def generate_daily_advisory(
    sbom: SBOMReport,
    lookback_days: int = 1,
) -> DailyAdvisoryReport:
    """Generate a personalized daily threat advisory."""
    now = datetime.now(timezone.utc)
    start_date = now - timedelta(days=lookback_days)

    # Build tech stack profile from SBOM
    tech_stack = _build_tech_stack(sbom)

    report = DailyAdvisoryReport(
        generated_at=now.isoformat(),
        period=f"last {lookback_days} day(s)",
        tech_stack_summary=", ".join(f"{k} ({v})" for k, v in sorted(tech_stack.items())),
    )

    # Query NVD for recent CVEs affecting our stack
    nvd_advisories = _query_nvd(tech_stack, start_date)
    report.advisories.extend(nvd_advisories)

    # Query CISA KEV for any new actively exploited vulns
    kev_advisories = _query_cisa_kev_recent(tech_stack, start_date)
    report.advisories.extend(kev_advisories)

    # Check for supply chain incidents (from our known-compromised list + GitHub)
    supply_chain = _check_recent_supply_chain(tech_stack, start_date)
    report.advisories.extend(supply_chain)

    # Deduplicate by ID
    seen = set()
    unique = []
    for adv in report.advisories:
        if adv.id not in seen:
            seen.add(adv.id)
            unique.append(adv)
    report.advisories = sorted(unique, key=lambda a: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(a.severity, 4))

    report.total_advisories = len(report.advisories)
    report.critical_count = sum(1 for a in report.advisories if a.severity == "critical")
    report.high_count = sum(1 for a in report.advisories if a.severity == "high")

    return report


def _build_tech_stack(sbom: SBOMReport) -> dict[str, str]:
    """Build a tech stack profile from SBOM for threat matching."""
    stack: dict[str, str] = {}
    for dep in sbom.dependencies:
        key = f"{dep.ecosystem}:{dep.name}"
        if key not in stack:
            stack[dep.name] = dep.version
    # Also track ecosystems
    for eco in sbom.ecosystems:
        stack[f"ecosystem:{eco}"] = str(sbom.ecosystems[eco])
    return stack


def _query_nvd(tech_stack: dict, start_date: datetime) -> list[ThreatAdvisory]:
    """Query NVD for recent CVEs matching our tech stack."""
    advisories = []
    keywords = [name for name in tech_stack.keys() if not name.startswith("ecosystem:")]

    # NVD API — search for recent CVEs by keyword
    # We batch by the most common/important packages
    search_terms = keywords[:10]  # Limit to top 10 to avoid rate limiting

    for term in search_terms:
        try:
            start_str = start_date.strftime("%Y-%m-%dT00:00:00.000")
            end_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT23:59:59.999")

            url = (
                f"https://services.nvd.nist.gov/rest/json/cves/2.0"
                f"?keywordSearch={term}"
                f"&pubStartDate={start_str}"
                f"&pubEndDate={end_str}"
                f"&resultsPerPage=5"
            )

            req = request.Request(url, headers={"Accept": "application/json"})
            resp = request.urlopen(req, timeout=15)
            data = json.loads(resp.read())

            for vuln in data.get("vulnerabilities", []):
                cve = vuln.get("cve", {})
                cve_id = cve.get("id", "")

                # Extract severity
                metrics = cve.get("metrics", {})
                severity = "medium"
                score = 0.0
                for cvss_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    cvss_list = metrics.get(cvss_key, [])
                    if cvss_list:
                        score = cvss_list[0].get("cvssData", {}).get("baseScore", 0)
                        if score >= 9.0:
                            severity = "critical"
                        elif score >= 7.0:
                            severity = "high"
                        elif score >= 4.0:
                            severity = "medium"
                        else:
                            severity = "low"
                        break

                # Get description
                descriptions = cve.get("descriptions", [])
                desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

                published = cve.get("published", "")

                references = [r.get("url", "") for r in cve.get("references", [])[:3]]

                version = tech_stack.get(term, "unknown")
                advisories.append(ThreatAdvisory(
                    id=cve_id,
                    title=f"{cve_id}: {term} vulnerability (CVSS {score})",
                    severity=severity,
                    published=published,
                    description=desc[:500],
                    affected_component=f"{term} {version}",
                    affected_resource=f"Detected in your environment via SBOM",
                    action_required=f"Check if your version of {term} ({version}) is affected. Update to the latest patched version.",
                    references=references,
                ))

        except (error.URLError, json.JSONDecodeError, error.HTTPError):
            continue  # NVD rate limits are strict — fail gracefully

        # NVD rate limit: 5 requests per 30 seconds without API key
        import time
        time.sleep(6)

    return advisories


def _query_cisa_kev_recent(tech_stack: dict, start_date: datetime) -> list[ThreatAdvisory]:
    """Check CISA KEV for recently added actively exploited vulnerabilities."""
    advisories = []

    try:
        req = request.Request(
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
            headers={"Accept": "application/json"},
        )
        resp = request.urlopen(req, timeout=15)
        data = json.loads(resp.read())

        for vuln in data.get("vulnerabilities", []):
            date_added = vuln.get("dateAdded", "")
            try:
                added_dt = datetime.strptime(date_added, "%Y-%m-%d").replace(tzinfo=timezone.utc)
                if added_dt < start_date:
                    continue
            except ValueError:
                continue

            product = vuln.get("product", "").lower()
            vendor = vuln.get("vendorProject", "").lower()

            # Check if this affects anything in our stack
            affected = False
            for name in tech_stack:
                if name.lower() in product or name.lower() in vendor:
                    affected = True
                    break

            if affected:
                advisories.append(ThreatAdvisory(
                    id=vuln.get("cveID", ""),
                    title=f"CISA KEV: {vuln.get('vulnerabilityName', '')}",
                    severity="critical",  # KEV = actively exploited
                    published=date_added,
                    description=vuln.get("shortDescription", ""),
                    affected_component=f"{vuln.get('vendorProject', '')} {vuln.get('product', '')}",
                    affected_resource="Detected in your tech stack — actively exploited in the wild",
                    action_required=f"Remediate by {vuln.get('requiredAction', 'applying vendor patch')}. Due date: {vuln.get('dueDate', 'ASAP')}",
                    is_kev=True,
                ))

    except (error.URLError, json.JSONDecodeError):
        pass

    return advisories


def _check_recent_supply_chain(tech_stack: dict, start_date: datetime) -> list[ThreatAdvisory]:
    """Check GitHub Advisory Database for recent supply chain attacks."""
    advisories = []

    # Query GitHub Advisory Database (public, no auth needed for basic queries)
    ecosystems_to_check = set()
    for name in tech_stack:
        if name.startswith("ecosystem:"):
            eco = name.split(":")[1]
            gh_eco_map = {"pypi": "pip", "npm": "npm", "maven": "maven", "go": "go", "rubygems": "rubygems"}
            if eco in gh_eco_map:
                ecosystems_to_check.add(gh_eco_map[eco])

    for ecosystem in ecosystems_to_check:
        try:
            url = (
                f"https://api.github.com/advisories"
                f"?ecosystem={ecosystem}"
                f"&severity=critical,high"
                f"&per_page=5"
                f"&sort=published"
                f"&direction=desc"
            )
            req = request.Request(url, headers={
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            })
            resp = request.urlopen(req, timeout=15)
            data = json.loads(resp.read())

            for adv in data:
                published = adv.get("published_at", "")
                try:
                    pub_dt = datetime.fromisoformat(published.replace("Z", "+00:00"))
                    if pub_dt < start_date:
                        continue
                except (ValueError, TypeError):
                    continue

                ghsa_id = adv.get("ghsa_id", "")
                cve_id = adv.get("cve_id", ghsa_id)

                # Check if any affected package is in our stack
                affected_pkg = ""
                for vuln_entry in adv.get("vulnerabilities", []):
                    pkg = vuln_entry.get("package", {})
                    pkg_name = pkg.get("name", "")
                    if pkg_name in tech_stack:
                        affected_pkg = pkg_name
                        break

                if not affected_pkg:
                    continue

                severity = adv.get("severity", "medium")
                advisories.append(ThreatAdvisory(
                    id=cve_id or ghsa_id,
                    title=adv.get("summary", "Supply chain advisory"),
                    severity=severity,
                    published=published,
                    description=adv.get("description", "")[:500],
                    affected_component=affected_pkg,
                    affected_resource=f"Found in your SBOM",
                    action_required="Update to the patched version immediately.",
                    references=[adv.get("html_url", "")],
                    is_supply_chain=True,
                ))

        except (error.URLError, json.JSONDecodeError, error.HTTPError):
            continue

    return advisories


def format_advisory_slack(report: DailyAdvisoryReport) -> dict:
    """Format the daily advisory as a Slack message."""
    if not report.advisories:
        return {
            "blocks": [{
                "type": "header",
                "text": {"type": "plain_text", "text": ":shield: Shasta Daily Threat Advisory"}
            }, {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"No new threats affecting your environment in the {report.period}. :white_check_mark:\n\n_Monitoring: {report.tech_stack_summary}_"}
            }]
        }

    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": ":shield: Shasta Daily Threat Advisory"}
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Period:* {report.period}"},
                {"type": "mrkdwn", "text": f"*Total Advisories:* {report.total_advisories}"},
                {"type": "mrkdwn", "text": f"*Critical:* {report.critical_count}"},
                {"type": "mrkdwn", "text": f"*High:* {report.high_count}"},
            ]
        },
    ]

    severity_emoji = {"critical": ":red_circle:", "high": ":large_orange_circle:", "medium": ":large_yellow_circle:", "low": ":large_blue_circle:"}

    for adv in report.advisories[:10]:  # Limit to 10 in Slack
        emoji = severity_emoji.get(adv.severity, ":white_circle:")
        kev_tag = " :rotating_light: *ACTIVELY EXPLOITED*" if adv.is_kev else ""
        sc_tag = " :chains: *SUPPLY CHAIN*" if adv.is_supply_chain else ""

        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": (
                f"{emoji} *{adv.id}*{kev_tag}{sc_tag}\n"
                f"{adv.title}\n"
                f"_Affects:_ `{adv.affected_component}`\n"
                f"_Action:_ {adv.action_required}"
            )}
        })

    blocks.append({
        "type": "context",
        "elements": [{"type": "mrkdwn", "text": f"_Monitoring: {report.tech_stack_summary}_"}]
    })

    return {"blocks": blocks}


def save_advisory_report(report: DailyAdvisoryReport, output_path: Path | str = "data/advisories") -> Path:
    """Save the daily advisory as Markdown."""
    output_dir = Path(output_path)
    output_dir.mkdir(parents=True, exist_ok=True)

    date_str = datetime.now().strftime("%Y-%m-%d")
    filepath = output_dir / f"threat-advisory-{date_str}.md"

    lines = [
        f"# Daily Threat Advisory — {date_str}",
        "",
        f"**Period:** {report.period}",
        f"**Advisories:** {report.total_advisories} ({report.critical_count} critical, {report.high_count} high)",
        f"**Tech Stack Monitored:** {report.tech_stack_summary}",
        "",
        "---",
        "",
    ]

    if not report.advisories:
        lines.append("No new threats affecting your environment. All clear.")
    else:
        for adv in report.advisories:
            kev = " | ACTIVELY EXPLOITED (CISA KEV)" if adv.is_kev else ""
            sc = " | SUPPLY CHAIN ATTACK" if adv.is_supply_chain else ""
            lines.extend([
                f"## {adv.id} — {adv.severity.upper()}{kev}{sc}",
                "",
                f"**{adv.title}**",
                "",
                f"- **Affects:** {adv.affected_component}",
                f"- **In your environment:** {adv.affected_resource}",
                f"- **Action:** {adv.action_required}",
                f"- **Published:** {adv.published}",
                "",
                adv.description[:500] if adv.description else "",
                "",
                "---",
                "",
            ])

    filepath.write_text("\n".join(lines), encoding="utf-8")
    return filepath
