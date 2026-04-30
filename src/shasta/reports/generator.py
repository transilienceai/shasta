"""Report generation for Shasta compliance scans.

Generates Markdown and HTML reports from scan results, suitable for
sharing with auditors, investors, or internal stakeholders.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, BaseLoader

import html as html_mod

from shasta.compliance.mapper import get_control_summary
from shasta.compliance.scorer import calculate_score
from shasta.evidence.models import CloudProvider, ScanResult

# Provider-aware labels for reports and templates
PROVIDER_LABELS: dict[str, dict[str, str]] = {
    "aws": {
        "account_label": "AWS Account",
        "console": "AWS console",
        "config_service": "AWS Config",
        "logging_service": "CloudTrail",
        "threat_service": "Amazon GuardDuty",
        "inspector_service": "AWS Inspector",
        "product_tagline": "Cloud Compliance Automation",
    },
    "azure": {
        "account_label": "Azure Subscription",
        "console": "Azure Portal",
        "config_service": "Azure Policy",
        "logging_service": "Activity Log",
        "threat_service": "Microsoft Defender for Cloud",
        "inspector_service": "Defender for Cloud",
        "product_tagline": "Cloud Compliance Automation",
    },
    "gcp": {
        "account_label": "GCP Project",
        "console": "Google Cloud console",
        "config_service": "Security Command Center",
        "logging_service": "Cloud Audit Logs",
        "threat_service": "Security Command Center",
        "inspector_service": "Security Command Center",
        "product_tagline": "Cloud Compliance Automation",
    },
}


def _provider_labels(provider: CloudProvider) -> dict[str, str]:
    """Return display labels for the given cloud provider."""
    return PROVIDER_LABELS.get(provider.value, PROVIDER_LABELS["aws"])


# Keys in Finding.details that are framework mappings (already shown elsewhere)
_FRAMEWORK_KEYS = frozenset(
    {
        "iso27001_controls",
        "hipaa_controls",
        "soc2_controls",
        "cis_azure_controls",
        "mcsb_controls",
        "cis_aws_controls",
        "cis_gcp_controls",
    }
)


def _render_details_html(details: dict) -> str:
    """Render a Finding.details dict as an HTML snippet with tables/lists."""
    if not details:
        return ""
    # Filter out framework mapping keys
    items = {k: v for k, v in details.items() if k not in _FRAMEWORK_KEYS and v}
    if not items:
        return ""

    parts = []
    for key, value in items.items():
        label = key.replace("_", " ").title()
        esc = html_mod.escape

        if isinstance(value, list) and value:
            if isinstance(value[0], dict):
                # List of dicts → table
                headers = list(value[0].keys())
                header_row = "".join(
                    f"<th>{esc(h.replace('_', ' ').title())}</th>" for h in headers
                )
                body_rows = []
                for row in value:
                    cells = "".join(
                        f"<td><code>{esc(str(row.get(h, '')))}</code></td>"
                        if h in ("app_id", "principal_id", "scope", "expired")
                        else f"<td>{esc(str(row.get(h, '')))}</td>"
                        for h in headers
                    )
                    body_rows.append(f"<tr>{cells}</tr>")
                parts.append(
                    f"<div class='details-section'><strong>{esc(label)}</strong> ({len(value)} items)"
                    f"<table><thead><tr>{header_row}</tr></thead>"
                    f"<tbody>{''.join(body_rows)}</tbody></table></div>"
                )
            else:
                # List of scalars → bullet list
                items_html = "".join(f"<li><code>{esc(str(v))}</code></li>" for v in value)
                parts.append(
                    f"<div class='details-section'><strong>{esc(label)}</strong> ({len(value)} items)"
                    f"<ul>{items_html}</ul></div>"
                )
        elif isinstance(value, dict):
            # Dict → key-value table
            rows = "".join(
                f"<tr><td>{esc(str(k))}</td><td><strong>{esc(str(v))}</strong></td></tr>"
                for k, v in value.items()
            )
            parts.append(
                f"<div class='details-section'><strong>{esc(label)}</strong>"
                f"<table><tbody>{rows}</tbody></table></div>"
            )
        else:
            # Scalar
            parts.append(
                f"<div class='details-section'><strong>{esc(label)}:</strong> "
                f"<code>{esc(str(value))}</code></div>"
            )

    if not parts:
        return ""
    return f"<div class='finding-details'>{''.join(parts)}</div>"


MARKDOWN_TEMPLATE = """\
# SOC 2 Compliance Gap Analysis Report

**Generated:** {{ generated_at }}
**{{ account_label }}:** {{ account_id }}
**Region:** {{ region }}
**Domains Scanned:** {{ domains }}

---

## Executive Summary

**Compliance Score: {{ score.score_percentage }}% (Grade {{ score.grade }})**

| Metric | Count |
|--------|-------|
| Total Findings | {{ score.total_findings }} |
| Passed | {{ score.findings_passed }} |
| Failed | {{ score.findings_failed }} |
| Partial | {{ score.findings_partial }} |

| Controls | Count |
|----------|-------|
| Passing | {{ score.passing }} |
| Failing | {{ score.failing }} |
| Partial | {{ score.partial }} |
| Requires Policy | {{ score.requires_policy }} |

{% if score.grade in ['D', 'F'] -%}
> **Your account has significant compliance gaps.** The findings below provide a
> clear roadmap to SOC 2 readiness. Focus on critical and high severity items first
> — most can be resolved in a few hours with the remediation guidance provided.
{% elif score.grade == 'C' -%}
> **You're making progress but have notable gaps.** Address the high-severity findings
> below to move toward SOC 2 readiness.
{% elif score.grade in ['A', 'B'] -%}
> **Your technical controls are in good shape.** Address any remaining findings and
> ensure your policy documents are in place to complete SOC 2 readiness.
{% endif %}

---

## SOC 2 Control Status

| Control | Title | Status | Passed | Failed |
|---------|-------|--------|--------|--------|
{% for ctrl_id, ctrl in controls.items() -%}
| {{ ctrl_id }} | {{ ctrl.title }} | {{ status_icon(ctrl.overall_status) }} {{ ctrl.overall_status | upper }} | {{ ctrl.pass_count }} | {{ ctrl.fail_count }} |
{% endfor %}

---

## Critical & High Severity Findings

{% for f in critical_high -%}
### {{ severity_icon(f.severity.value) }} {{ f.title }}

- **Severity:** {{ f.severity.value | upper }}
- **SOC 2 Control(s):** {{ f.soc2_controls | join(', ') }}
{% if f.cis_gcp_controls -%}
- **CIS GCP Control(s):** {{ f.cis_gcp_controls | join(', ') }}
{% endif -%}
- **Resource:** `{{ f.resource_id }}`
- **Description:** {{ f.description }}
{% if f.remediation -%}
- **Remediation:** {{ f.remediation }}
{% endif %}

{% endfor %}

{% if not critical_high -%}
No critical or high severity findings. Well done!
{% endif %}

---

## Medium Severity Findings

{% for f in medium -%}
### {{ f.title }}

- **SOC 2 Control(s):** {{ f.soc2_controls | join(', ') }}
{% if f.cis_gcp_controls -%}
- **CIS GCP Control(s):** {{ f.cis_gcp_controls | join(', ') }}
{% endif -%}
- **Resource:** `{{ f.resource_id }}`
- **Description:** {{ f.description }}
{% if f.remediation -%}
- **Remediation:** {{ f.remediation }}
{% endif %}

{% endfor %}

{% if not medium -%}
No medium severity findings.
{% endif %}

---

## Low & Informational

{% if low_info -%}
| Check | Resource | Status |
|-------|----------|--------|
{% for f in low_info -%}
| {{ f.title }} | `{{ f.resource_id | truncate(60) }}` | {{ status_icon(f.status.value) }} {{ f.status.value | upper }} |
{% endfor %}
{% else -%}
No low or informational findings.
{% endif %}

---

## Controls Requiring Policy Documents

The following SOC 2 controls cannot be satisfied by cloud configuration alone —
they require documented policies and processes. Use Shasta's `/policy-gen` skill
to generate these.

{% for ctrl_id, ctrl in policy_controls.items() -%}
- **{{ ctrl_id }} — {{ ctrl.title }}:** {{ ctrl.guidance }}
{% endfor %}

---

## Prioritized Remediation Roadmap

{% for i, item in enumerate(remediation_priorities, 1) -%}
{{ i }}. **{{ item.title }}** ({{ item.severity.value | upper }}) — {{ item.remediation }}
{% endfor %}

---

*Report generated by Shasta — Cloud Compliance Automation*
"""

HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SOC 2 Gap Analysis — {{ account_id }}</title>
<style>
  :root {
    --pass: #10b981; --fail: #ef4444; --partial: #f59e0b;
    --critical: #991b1b; --high: #dc2626; --medium: #d97706; --low: #2563eb; --info: #6b7280;
    --bg: #ffffff; --text: #1e293b; --muted: #64748b; --border: #e2e8f0; --surface: #f8fafc;
  }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; color: var(--text); line-height: 1.6; max-width: 900px; margin: 0 auto; padding: 40px 24px; }
  h1 { font-size: 28px; margin-bottom: 8px; }
  h2 { font-size: 22px; margin: 32px 0 16px; padding-bottom: 8px; border-bottom: 2px solid var(--border); }
  h3 { font-size: 16px; margin: 20px 0 8px; }
  .meta { color: var(--muted); font-size: 14px; margin-bottom: 24px; }
  .grade-box { display: inline-flex; align-items: center; gap: 16px; background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 20px 28px; margin: 16px 0; }
  .grade { font-size: 48px; font-weight: 700; }
  .grade-f { color: var(--fail); } .grade-d { color: var(--fail); }
  .grade-c { color: var(--medium); } .grade-b { color: var(--pass); } .grade-a { color: var(--pass); }
  .grade-details { font-size: 14px; color: var(--muted); }
  .grade-details strong { color: var(--text); font-size: 20px; }
  table { width: 100%; border-collapse: collapse; margin: 12px 0 24px; font-size: 14px; }
  th { background: var(--surface); text-align: left; padding: 10px 12px; border-bottom: 2px solid var(--border); font-weight: 600; }
  td { padding: 10px 12px; border-bottom: 1px solid var(--border); }
  .status-pass { color: var(--pass); font-weight: 600; }
  .status-fail { color: var(--fail); font-weight: 600; }
  .status-partial { color: var(--partial); font-weight: 600; }
  .status-policy { color: var(--medium); font-weight: 600; }
  .sev-critical { background: #fef2f2; border-left: 4px solid var(--critical); }
  .sev-high { background: #fff7ed; border-left: 4px solid var(--high); }
  .sev-medium { background: #fffbeb; border-left: 4px solid var(--medium); }
  .finding { padding: 16px; margin: 12px 0; border-radius: 8px; }
  .finding-title { font-weight: 600; margin-bottom: 6px; }
  .finding-meta { font-size: 13px; color: var(--muted); margin-bottom: 6px; }
  .finding-desc { font-size: 14px; margin-bottom: 8px; }
  .finding-remediation { font-size: 14px; background: #f0fdf4; padding: 10px 12px; border-radius: 6px; border-left: 3px solid var(--pass); }
  .finding-details { font-size: 13px; margin-top: 10px; background: var(--surface); padding: 12px; border-radius: 6px; border: 1px solid var(--border); }
  .finding-details .details-section { margin-bottom: 8px; }
  .finding-details table { font-size: 12px; margin: 4px 0 8px; }
  .finding-details ul { padding-left: 18px; margin: 4px 0; font-size: 12px; }
  .tag { display: inline-block; font-size: 11px; font-weight: 600; padding: 2px 8px; border-radius: 4px; text-transform: uppercase; }
  .tag-critical { background: #fef2f2; color: var(--critical); }
  .tag-high { background: #fff7ed; color: var(--high); }
  .tag-medium { background: #fffbeb; color: var(--medium); }
  .tag-low { background: #eff6ff; color: var(--low); }
  code { background: var(--surface); padding: 2px 6px; border-radius: 4px; font-size: 13px; }
  .roadmap li { margin: 8px 0; }
  .footer { margin-top: 40px; padding-top: 16px; border-top: 1px solid var(--border); color: var(--muted); font-size: 13px; }
  @media print { body { max-width: none; padding: 20px; } }
</style>
</head>
<body>

<h1>SOC 2 Compliance Gap Analysis</h1>
<div class="meta">
  <strong>{{ account_label }}:</strong> {{ account_id }} &nbsp;|&nbsp;
  <strong>Region:</strong> {{ region }} &nbsp;|&nbsp;
  <strong>Generated:</strong> {{ generated_at }} &nbsp;|&nbsp;
  <strong>Domains:</strong> {{ domains }}
</div>

<h2>Executive Summary</h2>
<div class="grade-box">
  <div class="grade grade-{{ score.grade | lower }}">{{ score.grade }}</div>
  <div class="grade-details">
    <strong>{{ score.score_percentage }}%</strong> compliance score<br>
    {{ score.total_findings }} findings: {{ score.findings_passed }} passed, {{ score.findings_failed }} failed<br>
    {{ score.passing }} of {{ score.passing + score.failing + score.partial }} assessed controls passing
  </div>
</div>

<h2>SOC 2 Control Status</h2>
<table>
  <thead><tr><th>Control</th><th>Title</th><th>Status</th><th>Pass</th><th>Fail</th></tr></thead>
  <tbody>
  {% for ctrl_id, ctrl in controls.items() %}
  <tr>
    <td><strong>{{ ctrl_id }}</strong></td>
    <td>{{ ctrl.title }}</td>
    <td class="status-{{ 'pass' if ctrl.overall_status == 'pass' else 'fail' if ctrl.overall_status == 'fail' else 'partial' if ctrl.overall_status == 'partial' else 'policy' }}">
      {{ ctrl.overall_status | upper }}
    </td>
    <td>{{ ctrl.pass_count }}</td>
    <td>{{ ctrl.fail_count }}</td>
  </tr>
  {% endfor %}
  </tbody>
</table>

<h2>Critical & High Severity Findings</h2>
{% for f in critical_high %}
<div class="finding sev-{{ f.severity.value }}">
  <div class="finding-title">
    <span class="tag tag-{{ f.severity.value }}">{{ f.severity.value }}</span>
    {{ f.title }}
  </div>
  <div class="finding-meta">SOC 2: {{ f.soc2_controls | join(', ') }}{% if f.cis_gcp_controls %} &nbsp;|&nbsp; CIS GCP: {{ f.cis_gcp_controls | join(', ') }}{% endif %} &nbsp;|&nbsp; Resource: <code>{{ f.resource_id }}</code></div>
  <div class="finding-desc">{{ f.description }}</div>
  {% if f.remediation %}
  <div class="finding-remediation"><strong>Fix:</strong> {{ f.remediation }}</div>
  {% endif %}
  {{ render_details(f.details) }}
</div>
{% endfor %}
{% if not critical_high %}
<p>No critical or high severity findings.</p>
{% endif %}

<h2>Medium Severity Findings</h2>
{% for f in medium %}
<div class="finding sev-medium">
  <div class="finding-title">
    <span class="tag tag-medium">medium</span>
    {{ f.title }}
  </div>
  <div class="finding-meta">SOC 2: {{ f.soc2_controls | join(', ') }}{% if f.cis_gcp_controls %} &nbsp;|&nbsp; CIS GCP: {{ f.cis_gcp_controls | join(', ') }}{% endif %} &nbsp;|&nbsp; Resource: <code>{{ f.resource_id }}</code></div>
  <div class="finding-desc">{{ f.description }}</div>
  {% if f.remediation %}
  <div class="finding-remediation"><strong>Fix:</strong> {{ f.remediation }}</div>
  {% endif %}
  {{ render_details(f.details) }}
</div>
{% endfor %}
{% if not medium %}
<p>No medium severity findings.</p>
{% endif %}

<h2>Passing Controls</h2>
<table>
  <thead><tr><th>Finding</th><th>Resource</th><th>Domain</th></tr></thead>
  <tbody>
  {% for f in passing %}
  <tr>
    <td>{{ f.title }}</td>
    <td><code>{{ f.resource_id[-50:] }}</code></td>
    <td>{{ f.domain.value }}</td>
  </tr>
  {% endfor %}
  </tbody>
</table>

<h2>Controls Requiring Policy Documents</h2>
<p>These SOC 2 controls require documented policies — not just cloud configuration. Use <code>/policy-gen</code> to generate them.</p>
<table>
  <thead><tr><th>Control</th><th>Title</th><th>What's Needed</th></tr></thead>
  <tbody>
  {% for ctrl_id, ctrl in policy_controls.items() %}
  <tr>
    <td><strong>{{ ctrl_id }}</strong></td>
    <td>{{ ctrl.title }}</td>
    <td>{{ ctrl.guidance }}</td>
  </tr>
  {% endfor %}
  </tbody>
</table>

<h2>Prioritized Remediation Roadmap</h2>
<ol class="roadmap">
{% for item in remediation_priorities %}
  <li><strong>{{ item.title }}</strong> <span class="tag tag-{{ item.severity.value }}">{{ item.severity.value }}</span><br>{{ item.remediation }}</li>
{% endfor %}
</ol>

<div class="footer">
  Report generated by Shasta — Cloud Compliance Automation &nbsp;|&nbsp; {{ generated_at }}
</div>

</body>
</html>
"""


def _build_context(scan: ScanResult) -> dict:
    """Build the template context from a scan result."""
    score = calculate_score(scan.findings)
    control_summary = get_control_summary(scan.findings)

    # Split controls
    assessed_controls = {
        k: v for k, v in control_summary.items() if v["overall_status"] not in ("not_assessed",)
    }
    policy_controls = {
        k: v for k, v in control_summary.items() if v["overall_status"] == "requires_policy"
    }

    # Split findings by severity
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    failed = [f for f in scan.findings if f.status.value == "fail"]
    failed.sort(key=lambda f: severity_order.get(f.severity.value, 5))

    critical_high = [f for f in failed if f.severity.value in ("critical", "high")]
    medium = [f for f in failed if f.severity.value == "medium"]
    low_info = [f for f in scan.findings if f.severity.value in ("low", "info")]
    passing = [f for f in scan.findings if f.status.value == "pass"]

    labels = _provider_labels(scan.cloud_provider)

    return {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "account_id": scan.account_id,
        "account_label": labels["account_label"],
        "region": scan.region,
        "domains": ", ".join(d.value for d in scan.domains_scanned),
        "score": score,
        "controls": assessed_controls,
        "policy_controls": policy_controls,
        "critical_high": critical_high,
        "medium": medium,
        "low_info": low_info,
        "passing": passing,
        "remediation_priorities": failed,  # already sorted by severity
        "enumerate": enumerate,
    }


def _make_jinja_env() -> Environment:
    env = Environment(loader=BaseLoader(), autoescape=False)
    env.globals["status_icon"] = lambda s: {
        "pass": "✅",
        "fail": "❌",
        "partial": "⚠️",
        "requires_policy": "📋",
        "not_assessed": "—",
    }.get(s, "—")
    env.globals["severity_icon"] = lambda s: {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🔵",
        "info": "ℹ️",
    }.get(s, "")
    env.filters["truncate"] = lambda s, length=60: s[:length] + "..." if len(s) > length else s
    env.globals["render_details"] = _render_details_html
    return env


def generate_markdown_report(scan: ScanResult) -> str:
    """Generate a Markdown compliance report."""
    env = _make_jinja_env()
    template = env.from_string(MARKDOWN_TEMPLATE)
    return template.render(**_build_context(scan))


def generate_html_report(scan: ScanResult) -> str:
    """Generate an HTML compliance report."""
    env = _make_jinja_env()
    env.autoescape = True
    template = env.from_string(HTML_TEMPLATE)
    return template.render(**_build_context(scan))


def save_markdown_report(scan: ScanResult, output_path: Path | str = "data/reports") -> Path:
    """Generate and save a Markdown report."""
    output_dir = Path(output_path)
    output_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    filepath = output_dir / f"gap-analysis-{scan.account_id}-{timestamp}.md"

    content = generate_markdown_report(scan)
    filepath.write_text(content, encoding="utf-8")
    return filepath


def save_html_report(scan: ScanResult, output_path: Path | str = "data/reports") -> Path:
    """Generate and save an HTML report."""
    output_dir = Path(output_path)
    output_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    filepath = output_dir / f"gap-analysis-{scan.account_id}-{timestamp}.html"

    content = generate_html_report(scan)
    filepath.write_text(content, encoding="utf-8")
    return filepath
