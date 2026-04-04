"""Slack integration for compliance alerts.

Sends compliance alerts, scan summaries, and daily digests to Slack
via incoming webhooks. No external dependencies — uses urllib.
"""

from __future__ import annotations

import json
from typing import Any
from urllib import request, error

from transilience_compliance.compliance.scorer import ComplianceScore
from transilience_compliance.evidence.models import Finding, ScanResult


class SlackClient:
    """Slack integration using incoming webhooks."""

    def __init__(self, webhook_url: str):
        self._webhook_url = webhook_url

    def send(self, payload: dict) -> bool:
        """Send a payload to the Slack webhook."""
        try:
            req = request.Request(
                self._webhook_url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
            )
            request.urlopen(req, timeout=10)
            return True
        except error.URLError as e:
            print(f"Slack send failed: {e}")
            return False

    def send_scan_summary(self, scan: ScanResult, score: ComplianceScore) -> bool:
        """Send a scan summary to Slack."""
        grade_emoji = {"A": ":white_check_mark:", "B": ":large_green_circle:", "C": ":large_yellow_circle:", "D": ":large_orange_circle:", "F": ":red_circle:"}.get(score.grade, ":question:")

        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": "Transilience Compliance Scan Complete"}
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Grade:*\n{grade_emoji} {score.grade} ({score.score_percentage}%)"},
                    {"type": "mrkdwn", "text": f"*Account:*\n{scan.account_id}"},
                    {"type": "mrkdwn", "text": f"*Findings:*\n{score.findings_passed} passed, {score.findings_failed} failed"},
                    {"type": "mrkdwn", "text": f"*Controls:*\n{score.passing} passing, {score.failing} failing"},
                ]
            },
        ]

        # Add critical/high findings
        critical_high = [f for f in scan.findings if f.status.value == "fail" and f.severity.value in ("critical", "high")]
        if critical_high:
            finding_text = "\n".join(
                f":rotating_light: *{f.severity.value.upper()}* — {f.title}"
                for f in critical_high[:10]
            )
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Critical/High Findings:*\n{finding_text}"}
            })

        blocks.append({
            "type": "context",
            "elements": [{"type": "mrkdwn", "text": f"Scanned domains: {', '.join(d.value for d in scan.domains_scanned)}"}]
        })

        return self.send({"blocks": blocks})

    def send_finding_alert(self, finding: Finding) -> bool:
        """Send an alert for a single critical finding."""
        severity_colors = {"critical": "#991b1b", "high": "#dc2626", "medium": "#d97706"}
        color = severity_colors.get(finding.severity.value, "#6b7280")

        payload = {
            "attachments": [{
                "color": color,
                "blocks": [
                    {
                        "type": "header",
                        "text": {"type": "plain_text", "text": f"Compliance Alert: {finding.title}"}
                    },
                    {
                        "type": "section",
                        "fields": [
                            {"type": "mrkdwn", "text": f"*Severity:*\n{finding.severity.value.upper()}"},
                            {"type": "mrkdwn", "text": f"*SOC 2:*\n{', '.join(finding.soc2_controls)}"},
                            {"type": "mrkdwn", "text": f"*Resource:*\n`{finding.resource_id}`"},
                            {"type": "mrkdwn", "text": f"*Domain:*\n{finding.domain.value}"},
                        ]
                    },
                    {
                        "type": "section",
                        "text": {"type": "mrkdwn", "text": finding.description[:2000]}
                    },
                ]
            }]
        }

        if finding.remediation:
            payload["attachments"][0]["blocks"].append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": f":wrench: *Fix:* {finding.remediation[:1000]}"}
            })

        return self.send(payload)

    def send_drift_alert(self, new_findings: int, resolved: int, score_delta: float, trend: str) -> bool:
        """Send a drift detection summary."""
        trend_emoji = {"improving": ":chart_with_upwards_trend:", "degrading": ":chart_with_downwards_trend:", "stable": ":left_right_arrow:"}.get(trend, ":question:")

        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": "Transilience Compliance Drift Report"}
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Trend:*\n{trend_emoji} {trend.upper()}"},
                    {"type": "mrkdwn", "text": f"*Score Change:*\n{'+' if score_delta >= 0 else ''}{score_delta}%"},
                    {"type": "mrkdwn", "text": f"*New Issues:*\n{new_findings}"},
                    {"type": "mrkdwn", "text": f"*Resolved:*\n{resolved}"},
                ]
            },
        ]

        if new_findings > 0:
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": ":warning: New compliance issues detected. Run `/scan` for details."}
            })

        return self.send({"blocks": blocks})
