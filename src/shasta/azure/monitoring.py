"""Azure monitoring and logging checks for SOC 2 and ISO 27001.

Checks Activity Log diagnostic settings, Microsoft Defender for Cloud,
Azure Policy compliance, and Monitor alerts for CC7.1, CC7.2, CC8.1.
"""

from __future__ import annotations

from shasta.azure.client import AzureClient
from shasta.evidence.models import (
    CheckDomain,
    CloudProvider,
    ComplianceStatus,
    Finding,
    Severity,
)


def run_all_azure_monitoring_checks(client: AzureClient) -> list[Finding]:
    """Run all Azure monitoring and logging compliance checks."""
    findings: list[Finding] = []
    sub_id = client.account_info.subscription_id if client.account_info else "unknown"
    region = client.account_info.region if client.account_info else "unknown"

    findings.extend(check_activity_log(client, sub_id, region))
    findings.extend(check_defender_enabled(client, sub_id, region))
    findings.extend(check_policy_compliance(client, sub_id, region))
    findings.extend(check_monitor_alerts(client, sub_id, region))

    return findings


def check_activity_log(client: AzureClient, subscription_id: str, region: str) -> list[Finding]:
    """[CC7.1, CC8.1] Check that Activity Log has diagnostic settings configured."""
    try:
        from azure.mgmt.monitor import MonitorManagementClient

        monitor = client.mgmt_client(MonitorManagementClient)

        # Activity Log diagnostic settings are at the subscription level
        resource_id = f"/subscriptions/{subscription_id}"
        settings = list(monitor.diagnostic_settings.list(resource_id))

        active_settings = []
        for s in settings:
            # Check if any log categories are enabled
            has_logs = False
            for log in s.logs or []:
                if log.enabled:
                    has_logs = True
                    break
            if has_logs:
                destinations = []
                if s.workspace_id:
                    destinations.append("Log Analytics")
                if s.storage_account_id:
                    destinations.append("Storage Account")
                if s.event_hub_authorization_rule_id:
                    destinations.append("Event Hub")
                active_settings.append(
                    {
                        "name": s.name,
                        "destinations": destinations,
                    }
                )

        if active_settings:
            return [
                Finding(
                    check_id="azure-activity-log",
                    title="Activity Log diagnostic settings configured",
                    description=f"{len(active_settings)} diagnostic setting(s) export Activity Log data: "
                    f"{', '.join(s['name'] for s in active_settings)}",
                    severity=Severity.INFO,
                    status=ComplianceStatus.PASS,
                    domain=CheckDomain.MONITORING,
                    resource_type="Azure::Monitor::DiagnosticSetting",
                    resource_id=resource_id,
                    region=region,
                    account_id=subscription_id,
                    cloud_provider=CloudProvider.AZURE,
                    soc2_controls=["CC7.1", "CC8.1"],
                    details={"settings": active_settings},
                )
            ]
        else:
            return [
                Finding(
                    check_id="azure-activity-log",
                    title="Activity Log not exported",
                    description="No diagnostic settings configured to export Activity Log. "
                    "Without log export, audit trail data may be lost after the 90-day retention period.",
                    severity=Severity.HIGH,
                    status=ComplianceStatus.FAIL,
                    domain=CheckDomain.MONITORING,
                    resource_type="Azure::Monitor::DiagnosticSetting",
                    resource_id=resource_id,
                    region=region,
                    account_id=subscription_id,
                    cloud_provider=CloudProvider.AZURE,
                    remediation="Configure diagnostic settings to export Activity Log to Log Analytics or Storage. "
                    "Monitor > Activity log > Diagnostic settings > Add diagnostic setting.",
                    soc2_controls=["CC7.1", "CC8.1"],
                )
            ]

    except Exception as e:
        return [
            Finding(
                check_id="azure-activity-log",
                title="Activity Log check failed",
                description=f"Could not check Activity Log diagnostic settings: {e}",
                severity=Severity.MEDIUM,
                status=ComplianceStatus.NOT_ASSESSED,
                domain=CheckDomain.MONITORING,
                resource_type="Azure::Monitor::DiagnosticSetting",
                resource_id=f"/subscriptions/{subscription_id}",
                region=region,
                account_id=subscription_id,
                cloud_provider=CloudProvider.AZURE,
                soc2_controls=["CC7.1", "CC8.1"],
            )
        ]


def check_defender_enabled(client: AzureClient, subscription_id: str, region: str) -> list[Finding]:
    """[CC7.1, CC7.2] Check if Microsoft Defender for Cloud is enabled."""
    try:
        from azure.mgmt.security import SecurityCenter

        security = client.mgmt_client(SecurityCenter, asc_location="centralus")

        pricings = list(security.pricings.list().value or [])

        enabled_plans = []
        disabled_plans = []

        for pricing in pricings:
            plan_name = pricing.name or "unknown"
            tier = pricing.pricing_tier or "Free"
            if tier.lower() == "standard":
                enabled_plans.append(plan_name)
            else:
                disabled_plans.append(plan_name)

        if enabled_plans:
            all_enabled = len(disabled_plans) == 0
            return [
                Finding(
                    check_id="azure-defender-enabled",
                    title=f"Microsoft Defender enabled ({len(enabled_plans)} plans)",
                    description=f"Defender for Cloud has {len(enabled_plans)} plan(s) enabled: "
                    f"{', '.join(enabled_plans[:10])}"
                    + ("" if all_enabled else f". {len(disabled_plans)} plan(s) on Free tier."),
                    severity=Severity.INFO if all_enabled else Severity.LOW,
                    status=ComplianceStatus.PASS if all_enabled else ComplianceStatus.PARTIAL,
                    domain=CheckDomain.MONITORING,
                    resource_type="Azure::Security::Pricing",
                    resource_id=f"/subscriptions/{subscription_id}/defender",
                    region=region,
                    account_id=subscription_id,
                    cloud_provider=CloudProvider.AZURE,
                    soc2_controls=["CC7.1", "CC7.2"],
                    details={"enabled_plans": enabled_plans, "disabled_plans": disabled_plans},
                )
            ]
        else:
            return [
                Finding(
                    check_id="azure-defender-enabled",
                    title="Microsoft Defender for Cloud not enabled",
                    description="No Defender for Cloud plans are on the Standard tier. "
                    "Without Defender, you have no threat detection or security recommendations.",
                    severity=Severity.HIGH,
                    status=ComplianceStatus.FAIL,
                    domain=CheckDomain.MONITORING,
                    resource_type="Azure::Security::Pricing",
                    resource_id=f"/subscriptions/{subscription_id}/defender",
                    region=region,
                    account_id=subscription_id,
                    cloud_provider=CloudProvider.AZURE,
                    remediation="Enable Microsoft Defender for Cloud plans. "
                    "Defender for Cloud > Environment settings > Enable Standard tier on key resource types.",
                    soc2_controls=["CC7.1", "CC7.2"],
                    details={"disabled_plans": disabled_plans},
                )
            ]

    except Exception as e:
        return [
            Finding(
                check_id="azure-defender-enabled",
                title="Defender check failed",
                description=f"Could not check Microsoft Defender for Cloud: {e}",
                severity=Severity.MEDIUM,
                status=ComplianceStatus.NOT_ASSESSED,
                domain=CheckDomain.MONITORING,
                resource_type="Azure::Security::Pricing",
                resource_id=f"/subscriptions/{subscription_id}/defender",
                region=region,
                account_id=subscription_id,
                cloud_provider=CloudProvider.AZURE,
                soc2_controls=["CC7.1", "CC7.2"],
            )
        ]


def check_policy_compliance(
    client: AzureClient, subscription_id: str, region: str
) -> list[Finding]:
    """[CC7.1, CC8.1] Check Azure Policy compliance state."""
    try:
        from azure.mgmt.resource import PolicyClient

        policy_client = client.mgmt_client(PolicyClient)

        # Get policy assignments at subscription scope
        assignments = list(policy_client.policy_assignments.list())

        if assignments:
            return [
                Finding(
                    check_id="azure-policy-compliance",
                    title=f"Azure Policy active ({len(assignments)} assignments)",
                    description=f"{len(assignments)} policy assignment(s) found at the subscription level. "
                    "Azure Policy provides continuous compliance monitoring.",
                    severity=Severity.INFO,
                    status=ComplianceStatus.PASS,
                    domain=CheckDomain.MONITORING,
                    resource_type="Azure::Policy::Assignment",
                    resource_id=f"/subscriptions/{subscription_id}/policyAssignments",
                    region=region,
                    account_id=subscription_id,
                    cloud_provider=CloudProvider.AZURE,
                    soc2_controls=["CC7.1", "CC8.1"],
                    details={
                        "assignment_count": len(assignments),
                        "assignments": [a.display_name for a in assignments[:10]],
                    },
                )
            ]
        else:
            return [
                Finding(
                    check_id="azure-policy-compliance",
                    title="No Azure Policy assignments found",
                    description="No policy assignments at the subscription level. "
                    "Azure Policy enables continuous compliance monitoring and enforcement.",
                    severity=Severity.MEDIUM,
                    status=ComplianceStatus.FAIL,
                    domain=CheckDomain.MONITORING,
                    resource_type="Azure::Policy::Assignment",
                    resource_id=f"/subscriptions/{subscription_id}/policyAssignments",
                    region=region,
                    account_id=subscription_id,
                    cloud_provider=CloudProvider.AZURE,
                    remediation="Assign Azure Policy initiatives for security baseline. "
                    "Policy > Assignments > Assign policy > Select 'Azure Security Benchmark'.",
                    soc2_controls=["CC7.1", "CC8.1"],
                )
            ]

    except Exception as e:
        return [
            Finding(
                check_id="azure-policy-compliance",
                title="Policy compliance check failed",
                description=f"Could not check Azure Policy assignments: {e}",
                severity=Severity.MEDIUM,
                status=ComplianceStatus.NOT_ASSESSED,
                domain=CheckDomain.MONITORING,
                resource_type="Azure::Policy::Assignment",
                resource_id=f"/subscriptions/{subscription_id}/policyAssignments",
                region=region,
                account_id=subscription_id,
                cloud_provider=CloudProvider.AZURE,
                soc2_controls=["CC7.1", "CC8.1"],
            )
        ]


def check_monitor_alerts(client: AzureClient, subscription_id: str, region: str) -> list[Finding]:
    """[CC7.2] Check if Azure Monitor alert rules are configured."""
    try:
        from azure.mgmt.monitor import MonitorManagementClient

        monitor = client.mgmt_client(MonitorManagementClient)

        alerts = list(monitor.alert_rules.list_by_subscription())

        # Also check metric alerts (more common in modern setups)
        metric_alerts = list(monitor.metric_alerts.list_by_subscription())
        total_alerts = len(alerts) + len(metric_alerts)

        if total_alerts > 0:
            return [
                Finding(
                    check_id="azure-monitor-alerts",
                    title=f"Azure Monitor alerts configured ({total_alerts} rules)",
                    description=f"{total_alerts} alert rule(s) configured "
                    f"({len(alerts)} classic, {len(metric_alerts)} metric-based).",
                    severity=Severity.INFO,
                    status=ComplianceStatus.PASS,
                    domain=CheckDomain.MONITORING,
                    resource_type="Azure::Monitor::AlertRule",
                    resource_id=f"/subscriptions/{subscription_id}/alertRules",
                    region=region,
                    account_id=subscription_id,
                    cloud_provider=CloudProvider.AZURE,
                    soc2_controls=["CC7.2"],
                    details={"classic_alerts": len(alerts), "metric_alerts": len(metric_alerts)},
                )
            ]
        else:
            return [
                Finding(
                    check_id="azure-monitor-alerts",
                    title="No Azure Monitor alert rules configured",
                    description="No alert rules found in the subscription. "
                    "Without alerts, anomalies and incidents may go undetected.",
                    severity=Severity.MEDIUM,
                    status=ComplianceStatus.FAIL,
                    domain=CheckDomain.MONITORING,
                    resource_type="Azure::Monitor::AlertRule",
                    resource_id=f"/subscriptions/{subscription_id}/alertRules",
                    region=region,
                    account_id=subscription_id,
                    cloud_provider=CloudProvider.AZURE,
                    remediation="Create alert rules for critical metrics and activity log events. "
                    "Monitor > Alerts > Create > Alert rule.",
                    soc2_controls=["CC7.2"],
                )
            ]

    except Exception as e:
        return [
            Finding(
                check_id="azure-monitor-alerts",
                title="Monitor alerts check failed",
                description=f"Could not check Azure Monitor alerts: {e}",
                severity=Severity.MEDIUM,
                status=ComplianceStatus.NOT_ASSESSED,
                domain=CheckDomain.MONITORING,
                resource_type="Azure::Monitor::AlertRule",
                resource_id=f"/subscriptions/{subscription_id}/alertRules",
                region=region,
                account_id=subscription_id,
                cloud_provider=CloudProvider.AZURE,
                soc2_controls=["CC7.2"],
            )
        ]
