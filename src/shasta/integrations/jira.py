"""Jira integration for Shasta compliance ticket management.

Creates and tracks Jira tickets for compliance findings:
  - Critical/high findings → auto-create tickets
  - Track remediation status
  - Link findings to Jira issues
"""

from __future__ import annotations

import json
from base64 import b64encode
from dataclasses import dataclass
from typing import Any
from urllib import request, error

from shasta.evidence.models import Finding


@dataclass
class JiraTicket:
    """A created Jira ticket."""

    key: str  # e.g., "COMP-123"
    url: str
    summary: str
    finding_id: str


class JiraClient:
    """Jira Cloud integration via REST API v3."""

    def __init__(self, base_url: str, email: str, api_token: str, project_key: str):
        self._base_url = base_url.rstrip("/")
        self._auth = b64encode(f"{email}:{api_token}".encode()).decode()
        self._project_key = project_key

    def _request(self, method: str, path: str, data: dict | None = None) -> dict:
        url = f"{self._base_url}/rest/api/3{path}"
        body = json.dumps(data).encode("utf-8") if data else None
        req = request.Request(
            url,
            data=body,
            method=method,
            headers={
                "Authorization": f"Basic {self._auth}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )
        resp = request.urlopen(req, timeout=15)
        return json.loads(resp.read()) if resp.read() else {}

    def create_finding_ticket(self, finding: Finding) -> JiraTicket:
        """Create a Jira ticket for a compliance finding."""
        severity_priority = {
            "critical": "Highest",
            "high": "High",
            "medium": "Medium",
            "low": "Low",
            "info": "Lowest",
        }

        description = {
            "type": "doc",
            "version": 1,
            "content": [
                {
                    "type": "heading",
                    "attrs": {"level": 2},
                    "content": [{"type": "text", "text": "Compliance Finding"}]
                },
                {
                    "type": "table",
                    "attrs": {"isNumberColumnEnabled": False, "layout": "default"},
                    "content": [
                        _table_row("Severity", finding.severity.value.upper()),
                        _table_row("SOC 2 Controls", ", ".join(finding.soc2_controls)),
                        _table_row("Domain", finding.domain.value),
                        _table_row("Resource", finding.resource_id),
                        _table_row("Check ID", finding.check_id),
                    ]
                },
                {
                    "type": "heading",
                    "attrs": {"level": 3},
                    "content": [{"type": "text", "text": "Description"}]
                },
                {
                    "type": "paragraph",
                    "content": [{"type": "text", "text": finding.description}]
                },
            ]
        }

        if finding.remediation:
            description["content"].extend([
                {
                    "type": "heading",
                    "attrs": {"level": 3},
                    "content": [{"type": "text", "text": "Remediation"}]
                },
                {
                    "type": "paragraph",
                    "content": [{"type": "text", "text": finding.remediation}]
                },
            ])

        payload = {
            "fields": {
                "project": {"key": self._project_key},
                "summary": f"[SOC2] {finding.title}",
                "description": description,
                "issuetype": {"name": "Bug"},
                "labels": ["shasta", "compliance", "soc2", finding.severity.value, finding.domain.value],
            }
        }

        result = self._request("POST", "/issue", payload)
        ticket_key = result.get("key", "UNKNOWN")

        return JiraTicket(
            key=ticket_key,
            url=f"{self._base_url}/browse/{ticket_key}",
            summary=f"[SOC2] {finding.title}",
            finding_id=finding.id,
        )

    def create_finding_tickets(self, findings: list[Finding], min_severity: str = "high") -> list[JiraTicket]:
        """Create Jira tickets for all findings at or above min_severity."""
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        threshold = severity_order.get(min_severity, 1)

        tickets = []
        for f in findings:
            if f.status.value == "fail" and severity_order.get(f.severity.value, 5) <= threshold:
                try:
                    ticket = self.create_finding_ticket(f)
                    tickets.append(ticket)
                except error.URLError as e:
                    print(f"Failed to create ticket for {f.check_id}: {e}")

        return tickets

    def search_existing_tickets(self, label: str = "shasta") -> list[dict]:
        """Search for existing Shasta tickets."""
        jql = f'project = {self._project_key} AND labels = {label} AND status != Done'
        result = self._request("GET", f"/search?jql={jql}&maxResults=50")
        return result.get("issues", [])


def _table_row(key: str, value: str) -> dict:
    """Build an ADF table row."""
    return {
        "type": "tableRow",
        "content": [
            {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": key, "marks": [{"type": "strong"}]}]}]},
            {"type": "tableCell", "content": [{"type": "paragraph", "content": [{"type": "text", "text": value}]}]},
        ]
    }
