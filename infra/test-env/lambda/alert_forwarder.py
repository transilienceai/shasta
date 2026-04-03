"""Shasta Alert Forwarder Lambda.

Receives SNS messages from EventBridge/Config compliance events
and forwards them to Slack and Jira.

Environment variables:
  SLACK_WEBHOOK_URL — Slack incoming webhook URL
  JIRA_BASE_URL     — Jira base URL (e.g., https://company.atlassian.net)
  JIRA_EMAIL        — Jira account email
  JIRA_API_TOKEN    — Jira API token
  JIRA_PROJECT_KEY  — Jira project key for tickets
"""

import json
import os
import logging
from base64 import b64encode
from urllib import request, error

logger = logging.getLogger()
logger.setLevel(logging.INFO)

SEVERITY_COLORS = {
    "critical": "#991b1b",
    "high": "#dc2626",
    "medium": "#d97706",
    "low": "#2563eb",
    "info": "#6b7280",
}

SEVERITY_EMOJI = {
    "critical": ":red_circle:",
    "high": ":large_orange_circle:",
    "medium": ":large_yellow_circle:",
    "low": ":large_blue_circle:",
    "info": ":white_circle:",
}


def lambda_handler(event, context):
    """Process SNS message and forward to Slack + Jira."""
    logger.info(f"Received event: {json.dumps(event)}")

    for record in event.get("Records", []):
        try:
            sns_message = record.get("Sns", {}).get("Message", "{}")
            message = json.loads(sns_message) if isinstance(sns_message, str) else sns_message

            alert = parse_alert(message)
            if alert:
                send_to_slack(alert)
                if alert.get("severity") in ("critical", "high"):
                    create_jira_ticket(alert)
        except Exception as e:
            logger.error(f"Error processing record: {e}")

    return {"statusCode": 200}


def parse_alert(message):
    """Parse various AWS event types into a normalized alert."""
    # Config Rules compliance change
    if message.get("messageType") == "ComplianceChangeNotification":
        return {
            "source": "AWS Config",
            "title": f"Config Rule Non-Compliant: {message.get('configRuleName', 'unknown')}",
            "description": f"Resource `{message.get('resourceId', 'unknown')}` ({message.get('resourceType', '')}) is now NON_COMPLIANT for rule `{message.get('configRuleName', '')}`.",
            "severity": "high",
            "resource": message.get("resourceId", "unknown"),
            "rule": message.get("configRuleName", "unknown"),
        }

    # EventBridge / CloudTrail events
    detail = message.get("detail", {})
    detail_type = message.get("detail-type", "")

    if "GuardDuty Finding" in detail_type:
        severity_val = detail.get("severity", 0)
        if severity_val >= 7:
            sev = "critical"
        elif severity_val >= 4:
            sev = "high"
        else:
            sev = "medium"
        return {
            "source": "GuardDuty",
            "title": f"GuardDuty: {detail.get('title', detail.get('type', 'Finding'))}",
            "description": detail.get("description", "A new GuardDuty finding was detected."),
            "severity": sev,
            "resource": detail.get("resource", {}).get("resourceType", "unknown"),
            "rule": detail.get("type", ""),
        }

    if detail.get("userIdentity", {}).get("type") == "Root":
        return {
            "source": "CloudTrail",
            "title": f"Root Account Activity: {detail.get('eventName', 'unknown')}",
            "description": f"The root account performed `{detail.get('eventName', 'unknown')}` from IP `{detail.get('sourceIPAddress', 'unknown')}`. Root account usage should be extremely rare.",
            "severity": "critical",
            "resource": "root-account",
            "rule": "root-account-usage",
        }

    event_name = detail.get("eventName", "")
    event_source = detail.get("eventSource", "")

    if event_source == "ec2.amazonaws.com" and "SecurityGroup" in event_name:
        return {
            "source": "CloudTrail",
            "title": f"Security Group Change: {event_name}",
            "description": f"User `{detail.get('userIdentity', {}).get('arn', 'unknown')}` performed `{event_name}`. Review the change for SOC 2 CC6.6 compliance.",
            "severity": "medium",
            "resource": json.dumps(detail.get("requestParameters", {}))[:200],
            "rule": "sg-change-detection",
        }

    if event_source == "iam.amazonaws.com":
        return {
            "source": "CloudTrail",
            "title": f"IAM Change: {event_name}",
            "description": f"User `{detail.get('userIdentity', {}).get('arn', 'unknown')}` performed `{event_name}`. Review for SOC 2 CC6.1/CC6.2 compliance.",
            "severity": "high" if "Admin" in str(detail.get("requestParameters", {})) else "medium",
            "resource": json.dumps(detail.get("requestParameters", {}))[:200],
            "rule": "iam-change-detection",
        }

    if event_source == "s3.amazonaws.com":
        return {
            "source": "CloudTrail",
            "title": f"S3 Policy Change: {event_name}",
            "description": f"User `{detail.get('userIdentity', {}).get('arn', 'unknown')}` performed `{event_name}`. Review for SOC 2 CC6.7 compliance.",
            "severity": "high" if "Delete" in event_name else "medium",
            "resource": detail.get("requestParameters", {}).get("bucketName", "unknown"),
            "rule": "s3-change-detection",
        }

    # Fallback
    return {
        "source": message.get("source", "AWS"),
        "title": detail_type or "Compliance Event",
        "description": json.dumps(message)[:500],
        "severity": "medium",
        "resource": "unknown",
        "rule": "generic",
    }


def send_to_slack(alert):
    """Send an alert to Slack via incoming webhook."""
    webhook_url = os.environ.get("SLACK_WEBHOOK_URL", "")
    if not webhook_url:
        logger.info("No Slack webhook configured, skipping")
        return

    severity = alert.get("severity", "medium")
    color = SEVERITY_COLORS.get(severity, "#6b7280")
    emoji = SEVERITY_EMOJI.get(severity, ":white_circle:")

    payload = {
        "attachments": [{
            "color": color,
            "blocks": [
                {
                    "type": "header",
                    "text": {
                        "type": "plain_text",
                        "text": f"{emoji} Shasta: {alert['title']}",
                    }
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Source:*\n{alert['source']}"},
                        {"type": "mrkdwn", "text": f"*Severity:*\n{severity.upper()}"},
                    ]
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": alert["description"][:2000],
                    }
                },
            ]
        }]
    }

    try:
        req = request.Request(
            webhook_url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        request.urlopen(req, timeout=10)
        logger.info(f"Slack alert sent: {alert['title']}")
    except error.URLError as e:
        logger.error(f"Slack webhook failed: {e}")


def create_jira_ticket(alert):
    """Create a Jira ticket for critical/high alerts."""
    base_url = os.environ.get("JIRA_BASE_URL", "")
    email = os.environ.get("JIRA_EMAIL", "")
    token = os.environ.get("JIRA_API_TOKEN", "")
    project_key = os.environ.get("JIRA_PROJECT_KEY", "")

    if not all([base_url, email, token, project_key]):
        logger.info("Jira not fully configured, skipping ticket creation")
        return

    severity = alert.get("severity", "medium")
    priority_map = {"critical": "Highest", "high": "High", "medium": "Medium", "low": "Low"}

    payload = {
        "fields": {
            "project": {"key": project_key},
            "summary": f"[Shasta] {alert['title']}",
            "description": {
                "type": "doc",
                "version": 1,
                "content": [{
                    "type": "paragraph",
                    "content": [{"type": "text", "text": alert["description"]}]
                }, {
                    "type": "paragraph",
                    "content": [{"type": "text", "text": f"Source: {alert['source']} | Severity: {severity.upper()} | Resource: {alert.get('resource', 'N/A')}"}]
                }]
            },
            "issuetype": {"name": "Bug"},
            "labels": ["shasta", "compliance", f"soc2", severity],
        }
    }

    try:
        auth = b64encode(f"{email}:{token}".encode()).decode()
        req = request.Request(
            f"{base_url}/rest/api/3/issue",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Basic {auth}",
            },
        )
        resp = request.urlopen(req, timeout=15)
        result = json.loads(resp.read())
        logger.info(f"Jira ticket created: {result.get('key', 'unknown')}")
    except error.URLError as e:
        logger.error(f"Jira ticket creation failed: {e}")
