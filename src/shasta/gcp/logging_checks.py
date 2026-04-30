"""GCP Cloud Logging and audit configuration checks for SOC 2 and CIS GCP Benchmark v2.0.

Covers:
  CC7.1 — Detection and monitoring (audit logs, log-based metrics)
  CC7.2 — Anomaly monitoring (alerts on security-relevant events)

CIS GCP v2.0 Section 2 (Logging and Monitoring).
"""

from __future__ import annotations

from typing import Any

from shasta.gcp.client import GCPClient
from shasta.evidence.models import (
    CheckDomain,
    CloudProvider,
    ComplianceStatus,
    Finding,
    Severity,
)

IS_GLOBAL = True  # Audit log configuration is project-wide

# CIS 2.x log-based metric filters (log filter, description, cis_id)
# Each tuple: (filter_fragment, human_description, cis_id)
_CIS_LOG_METRICS: list[tuple[str, str, str]] = [
    ("protoPayload.methodName:SetIamPolicy", "IAM policy changes", "2.2"),
    ("resource.type=audited_resource AND protoPayload.serviceName=cloudresourcemanager", "project ownership changes", "2.4"),
    ("resource.type=gce_firewall_rule", "VPC firewall rule changes", "2.10"),
    ("resource.type=gce_network", "VPC network changes", "2.9"),
    ("resource.type=gce_route", "VPC route changes", "2.8"),
    ("resource.type=iam_role AND protoPayload.methodName:(roles.create OR roles.update OR roles.delete)", "custom IAM role changes", "2.3"),
    ("protoPayload.methodName=google.logging.v2.ConfigServiceV2.UpdateSink", "audit logging sink changes", "2.5"),
    ("resource.type=bigquery_dataset", "BigQuery IAM changes", "2.13"),
]


def run_all_gcp_logging_checks(client: GCPClient) -> list[Finding]:
    """Run all GCP Cloud Logging and monitoring compliance checks."""
    project_id = client.project_id if client.account_info else (client._project_id or "unknown")

    findings: list[Finding] = []
    findings.extend(check_audit_config_data_access(client, project_id))
    findings.extend(check_log_sink_configured(client, project_id))
    findings.extend(check_log_metrics_and_alerts(client, project_id))
    findings.extend(check_log_retention_period(client, project_id))
    findings.extend(check_log_metric_vpc_network_changes(client, project_id))
    findings.extend(check_log_metric_firewall_changes(client, project_id))
    findings.extend(check_log_metric_custom_role_changes(client, project_id))
    findings.extend(check_log_metric_project_ownership(client, project_id))

    return findings


def check_audit_config_data_access(
    client: GCPClient, project_id: str
) -> list[Finding]:
    """[CIS 2.1] Data Access audit logs should be configured for all services.

    By default, GCP only writes Admin Activity logs. Data Access logs (DATA_READ,
    DATA_WRITE) must be explicitly enabled per service. Without them you cannot
    audit who read or wrote data in Cloud Storage, BigQuery, Cloud SQL, etc.
    """
    region = "global"
    try:
        crm = client.service("cloudresourcemanager", "v1")
        policy = crm.projects().getIamPolicy(resource=project_id, body={}).execute()
        audit_configs = policy.get("auditConfigs", [])
    except Exception as e:
        return [
            Finding.not_assessed(
                check_id="gcp-audit-data-access",
                title="Unable to read project IAM policy for audit config",
                description=f"API call failed: {e}",
                domain=CheckDomain.MONITORING,
                resource_type="GCP::IAM::AuditConfig",
                account_id=project_id,
                region=region,
                cloud_provider=CloudProvider.GCP,
            )
        ]

    # Check whether allServices has DATA_READ and DATA_WRITE enabled
    all_services_config: dict[str, set[str]] = {}
    for config in audit_configs:
        service = config.get("service", "")
        for log_config in config.get("auditLogConfigs", []):
            log_type = log_config.get("logType", "")
            if service not in all_services_config:
                all_services_config[service] = set()
            all_services_config[service].add(log_type)

    required_log_types = {"DATA_READ", "DATA_WRITE"}
    all_services_types = all_services_config.get("allServices", set())
    missing_types = required_log_types - all_services_types

    if not missing_types:
        return [
            Finding(
                check_id="gcp-audit-data-access",
                title="Data Access audit logs (DATA_READ + DATA_WRITE) enabled for allServices",
                description=(
                    "The project audit config enables DATA_READ and DATA_WRITE logs for "
                    "allServices. All API data access operations are captured in Cloud Audit Logs."
                ),
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.MONITORING,
                resource_type="GCP::IAM::AuditConfig",
                resource_id=f"projects/{project_id}",
                region=region,
                account_id=project_id,
                cloud_provider=CloudProvider.GCP,
                soc2_controls=["CC7.1", "CC8.1"],
                cis_gcp_controls=["2.1"],
            )
        ]

    return [
        Finding(
            check_id="gcp-audit-data-access",
            title=f"Data Access audit logs missing for allServices: {', '.join(sorted(missing_types))}",
            description=(
                f"The project audit config does not enable {', '.join(sorted(missing_types))} "
                "for allServices. Without these log types, read and write operations to GCP "
                "data services (Cloud Storage, BigQuery, Cloud SQL, etc.) are not captured "
                "in Cloud Audit Logs, leaving a blind spot in your audit trail."
            ),
            severity=Severity.HIGH,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.MONITORING,
            resource_type="GCP::IAM::AuditConfig",
            resource_id=f"projects/{project_id}",
            region=region,
            account_id=project_id,
            cloud_provider=CloudProvider.GCP,
            remediation=(
                "Enable Data Access logs in the GCP Console: IAM & Admin > Audit Logs, "
                "select 'All Google Cloud Services', and check DATA_READ and DATA_WRITE. "
                "Note: Data Access logs significantly increase logging volume — budget accordingly."
            ),
            soc2_controls=["CC7.1", "CC8.1"],
            cis_gcp_controls=["2.1"],
            iso27001_controls=["A.8.15"],
            hipaa_controls=["164.312(b)"],
            details={"missing_log_types": sorted(missing_types), "current_audit_configs": list(all_services_types)},
        )
    ]


def check_log_sink_configured(
    client: GCPClient, project_id: str
) -> list[Finding]:
    """[CIS 2.2] At least one log sink should export project logs to an external destination.

    Log sinks export Cloud Logging entries to Cloud Storage, BigQuery, or Pub/Sub.
    Without a sink, logs are only retained in Cloud Logging for 30 days (Admin Activity)
    or 30 days (Data Access by default). A sink provides long-term retention and
    immutable audit trail outside of Cloud Logging.
    """
    region = "global"
    try:
        logging = client.service("logging", "v2")
        response = logging.projects().sinks().list(parent=f"projects/{project_id}").execute()
        sinks = response.get("sinks", [])
    except Exception as e:
        return [
            Finding.not_assessed(
                check_id="gcp-log-sink",
                title="Unable to list log sinks",
                description=f"API call failed: {e}",
                domain=CheckDomain.MONITORING,
                resource_type="GCP::Logging::LogSink",
                account_id=project_id,
                region=region,
                cloud_provider=CloudProvider.GCP,
            )
        ]

    # Filter to non-_Default sinks that have a real destination
    active_export_sinks = [
        s for s in sinks
        if s.get("name", "").split("/")[-1] not in ("_Default", "_Required")
        and s.get("destination")
    ]

    if active_export_sinks:
        return [
            Finding(
                check_id="gcp-log-sink",
                title=f"{len(active_export_sinks)} log export sink(s) configured",
                description=(
                    f"{len(active_export_sinks)} log sink(s) export logs to external "
                    "destinations: "
                    + ", ".join(s.get("destination", "")[:40] for s in active_export_sinks[:3])
                    + "."
                ),
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.MONITORING,
                resource_type="GCP::Logging::LogSink",
                resource_id=f"projects/{project_id}/sinks",
                region=region,
                account_id=project_id,
                cloud_provider=CloudProvider.GCP,
                soc2_controls=["CC7.1"],
                cis_gcp_controls=["2.2"],
            )
        ]

    return [
        Finding(
            check_id="gcp-log-sink",
            title="No log export sinks configured — logs retained only in Cloud Logging",
            description=(
                "No log sinks export project logs to an external destination (Cloud Storage, "
                "BigQuery, or Pub/Sub). Logs retained only in Cloud Logging may be deleted "
                "within 30-365 days and are not immutably archived."
            ),
            severity=Severity.MEDIUM,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.MONITORING,
            resource_type="GCP::Logging::LogSink",
            resource_id=f"projects/{project_id}/sinks",
            region=region,
            account_id=project_id,
            cloud_provider=CloudProvider.GCP,
            remediation=(
                "Create an export sink: `gcloud logging sinks create audit-export-sink "
                "storage.googleapis.com/BUCKET_NAME --log-filter='logName:cloudaudit.googleapis.com' "
                f"--project={project_id}`. Then grant the sink's service account "
                "`storage.objectCreator` on the destination bucket."
            ),
            soc2_controls=["CC7.1"],
            cis_gcp_controls=["2.2"],
            iso27001_controls=["A.8.15"],
        )
    ]


def check_log_metrics_and_alerts(
    client: GCPClient, project_id: str
) -> list[Finding]:
    """[CIS 2.2–2.13] Log-based metrics and alert policies should exist for key audit events.

    CIS GCP requires log-based metrics + Alerting policies for IAM changes, custom role
    changes, project ownership changes, VPC network changes, firewall changes, etc.
    This check reports which events are covered and which are missing.
    """
    region = "global"
    try:
        logging = client.service("logging", "v2")
        monitoring = client.service("monitoring", "v3")

        metrics_resp = (
            logging.projects()
            .metrics()
            .list(parent=f"projects/{project_id}")
            .execute()
        )
        metrics = metrics_resp.get("metrics", [])

        policies_resp = (
            monitoring.projects()
            .alertPolicies()
            .list(name=f"projects/{project_id}")
            .execute()
        )
        policies = policies_resp.get("alertPolicies", [])
    except Exception as e:
        return [
            Finding.not_assessed(
                check_id="gcp-log-metric-alerts",
                title="Unable to list log metrics or alert policies",
                description=f"API call failed: {e}",
                domain=CheckDomain.MONITORING,
                resource_type="GCP::Logging::LogMetric",
                account_id=project_id,
                region=region,
                cloud_provider=CloudProvider.GCP,
            )
        ]

    # Build set of filter fragments seen in existing metrics
    existing_filters = {m.get("filter", "") for m in metrics}
    # Build set of metric names referenced in alert policies
    alerted_metrics: set[str] = set()
    for policy in policies:
        for condition in policy.get("conditions", []):
            threshold = condition.get("conditionThreshold", {})
            for agg in threshold.get("aggregations", []):
                pass
            # Check the filter/metric for the condition
            filter_str = threshold.get("filter", "")
            if "logging.googleapis.com/user/" in filter_str:
                metric_name = filter_str.split("logging.googleapis.com/user/")[-1].split('"')[0]
                alerted_metrics.add(metric_name)

    covered: list[str] = []
    missing: list[dict[str, str]] = []

    for filter_frag, description, cis_id in _CIS_LOG_METRICS:
        has_metric = any(filter_frag in f for f in existing_filters)
        if has_metric:
            covered.append(f"CIS {cis_id}: {description}")
        else:
            missing.append({"cis_id": cis_id, "description": description})

    if not missing:
        return [
            Finding(
                check_id="gcp-log-metric-alerts",
                title=f"All {len(covered)} required CIS log-based metrics are configured",
                description="Log-based metrics exist for all required CIS 2.x audit events.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.MONITORING,
                resource_type="GCP::Logging::LogMetric",
                resource_id=f"projects/{project_id}/metrics",
                region=region,
                account_id=project_id,
                cloud_provider=CloudProvider.GCP,
                soc2_controls=["CC7.1", "CC7.2"],
                cis_gcp_controls=["2.2", "2.3", "2.4", "2.5", "2.8", "2.9", "2.10", "2.13"],
            )
        ]

    return [
        Finding(
            check_id="gcp-log-metric-alerts",
            title=f"{len(missing)} required CIS log-based metric(s) are missing",
            description=(
                f"{len(missing)} CIS-required log-based metrics do not exist. Missing: "
                + "; ".join(f"CIS {m['cis_id']} ({m['description']})" for m in missing[:5])
                + (f" and {len(missing)-5} more" if len(missing) > 5 else "")
                + ". Without these metrics, security events like IAM changes and firewall "
                "modifications go undetected in real time."
            ),
            severity=Severity.MEDIUM,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.MONITORING,
            resource_type="GCP::Logging::LogMetric",
            resource_id=f"projects/{project_id}/metrics",
            region=region,
            account_id=project_id,
            cloud_provider=CloudProvider.GCP,
            remediation=(
                "Create log-based metrics via the Console (Logging > Log-based Metrics) "
                "and pair each with an Alerting policy. The CIS GCP benchmark v2.0 Section 2 "
                "provides the exact filter strings for each required metric."
            ),
            soc2_controls=["CC7.1", "CC7.2"],
            cis_gcp_controls=["2.2", "2.3", "2.4", "2.5", "2.8", "2.9", "2.10", "2.13"],
            iso27001_controls=["A.8.15", "A.8.16"],
            details={"missing_metrics": missing, "covered_metrics": covered},
        )
    ]


def check_log_retention_period(
    client: GCPClient, project_id: str
) -> list[Finding]:
    """Log buckets should retain logs for at least 365 days.

    Cloud Logging default retention is 30 days for most log types. For SOC 2 and
    HIPAA compliance, 1 year of log retention is standard. This check verifies the
    _Default and _Required log buckets have sufficient retention configured.
    """
    region = "global"
    MIN_RETENTION_DAYS = 365

    try:
        logging = client.service("logging", "v2")
        response = (
            logging.projects()
            .locations()
            .buckets()
            .list(parent=f"projects/{project_id}/locations/-")
            .execute()
        )
        buckets = response.get("buckets", [])
    except Exception as e:
        return [
            Finding.not_assessed(
                check_id="gcp-log-retention",
                title="Unable to list Cloud Logging buckets",
                description=f"API call failed: {e}",
                domain=CheckDomain.MONITORING,
                resource_type="GCP::Logging::LogBucket",
                account_id=project_id,
                region=region,
                cloud_provider=CloudProvider.GCP,
            )
        ]

    if not buckets:
        return []

    insufficient: list[dict[str, Any]] = []
    for bucket in buckets:
        bucket_name = bucket.get("name", "").split("/")[-1]
        retention_days = bucket.get("retentionDays", 30)
        if retention_days < MIN_RETENTION_DAYS:
            insufficient.append(
                {
                    "bucket": bucket_name,
                    "retention_days": retention_days,
                    "required_days": MIN_RETENTION_DAYS,
                }
            )

    if not insufficient:
        return [
            Finding(
                check_id="gcp-log-retention",
                title=f"All Cloud Logging buckets retain logs ≥{MIN_RETENTION_DAYS} days",
                description=f"All Cloud Logging buckets have retention ≥{MIN_RETENTION_DAYS} days configured.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.MONITORING,
                resource_type="GCP::Logging::LogBucket",
                resource_id=f"projects/{project_id}/locations/-/buckets",
                region=region,
                account_id=project_id,
                cloud_provider=CloudProvider.GCP,
                soc2_controls=["CC7.1"],
                cis_gcp_controls=["2.1"],
            )
        ]

    return [
        Finding(
            check_id="gcp-log-retention",
            title=f"{len(insufficient)} Cloud Logging bucket(s) retain logs <{MIN_RETENTION_DAYS} days",
            description=(
                f"{len(insufficient)} logging bucket(s) have retention below {MIN_RETENTION_DAYS} "
                "days. SOC 2 and HIPAA require at least 1 year of audit log retention."
            ),
            severity=Severity.MEDIUM,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.MONITORING,
            resource_type="GCP::Logging::LogBucket",
            resource_id=f"projects/{project_id}/locations/-/buckets",
            region=region,
            account_id=project_id,
            cloud_provider=CloudProvider.GCP,
            remediation=(
                "Update retention: `gcloud logging buckets update BUCKET_NAME "
                f"--location=LOCATION --retention-days={MIN_RETENTION_DAYS} "
                f"--project={project_id}`."
            ),
            soc2_controls=["CC7.1"],
            cis_gcp_controls=["2.1"],
            iso27001_controls=["A.8.15"],
            hipaa_controls=["164.312(b)"],
            details={"buckets_with_short_retention": insufficient},
        )
    ]


def check_log_metric_vpc_network_changes(
    client: GCPClient, project_id: str
) -> list[Finding]:
    """[CIS 2.9] A log-based metric should exist for VPC network configuration changes.

    VPC network changes (creating/deleting networks, routes, peering) are significant
    security events that should trigger real-time alerts.
    """
    return _check_single_log_metric(
        client=client,
        project_id=project_id,
        check_id="gcp-log-metric-vpc-changes",
        filter_fragment="resource.type=gce_network",
        description="VPC network configuration changes",
        cis_id="2.9",
    )


def check_log_metric_firewall_changes(
    client: GCPClient, project_id: str
) -> list[Finding]:
    """[CIS 2.10] A log-based metric should exist for VPC firewall rule changes.

    Unauthorized firewall changes can open the network perimeter. Real-time
    alerting on firewall mutations is essential for detecting privilege escalation.
    """
    return _check_single_log_metric(
        client=client,
        project_id=project_id,
        check_id="gcp-log-metric-firewall-changes",
        filter_fragment="resource.type=gce_firewall_rule",
        description="VPC firewall rule changes",
        cis_id="2.10",
    )


def check_log_metric_custom_role_changes(
    client: GCPClient, project_id: str
) -> list[Finding]:
    """[CIS 2.3] A log-based metric should exist for custom IAM role changes.

    Custom role mutations (adding permissions, creating new roles) are a common
    privilege escalation technique that should trigger immediate alerts.
    """
    return _check_single_log_metric(
        client=client,
        project_id=project_id,
        check_id="gcp-log-metric-custom-role-changes",
        filter_fragment="resource.type=iam_role",
        description="custom IAM role changes",
        cis_id="2.3",
    )


def check_log_metric_project_ownership(
    client: GCPClient, project_id: str
) -> list[Finding]:
    """[CIS 2.4] A log-based metric should exist for project ownership (IAM policy) changes.

    Changes to project-level IAM policy are the most impactful security events —
    any escalation to Owner gives full project control. These must be alerted on immediately.
    """
    return _check_single_log_metric(
        client=client,
        project_id=project_id,
        check_id="gcp-log-metric-project-ownership",
        filter_fragment="protoPayload.methodName:SetIamPolicy",
        description="project IAM policy (ownership) changes",
        cis_id="2.4",
    )


def _check_single_log_metric(
    client: GCPClient,
    project_id: str,
    check_id: str,
    filter_fragment: str,
    description: str,
    cis_id: str,
) -> list[Finding]:
    """Shared implementation for single-metric CIS log checks."""
    region = "global"
    try:
        logging = client.service("logging", "v2")
        response = (
            logging.projects()
            .metrics()
            .list(parent=f"projects/{project_id}")
            .execute()
        )
        metrics = response.get("metrics", [])
    except Exception as e:
        return [
            Finding.not_assessed(
                check_id=check_id,
                title=f"Unable to list log metrics for CIS {cis_id} check",
                description=f"API call failed: {e}",
                domain=CheckDomain.MONITORING,
                resource_type="GCP::Logging::LogMetric",
                account_id=project_id,
                region=region,
                cloud_provider=CloudProvider.GCP,
            )
        ]

    existing_filters = {m.get("filter", "") for m in metrics}
    has_metric = any(filter_fragment in f for f in existing_filters)

    if has_metric:
        return [
            Finding(
                check_id=check_id,
                title=f"Log-based metric for {description} exists [CIS {cis_id}]",
                description=f"A log-based metric covering {description} is configured.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.MONITORING,
                resource_type="GCP::Logging::LogMetric",
                resource_id=f"projects/{project_id}/metrics",
                region=region,
                account_id=project_id,
                cloud_provider=CloudProvider.GCP,
                soc2_controls=["CC7.1", "CC7.2"],
                cis_gcp_controls=[cis_id],
            )
        ]

    return [
        Finding(
            check_id=check_id,
            title=f"No log-based metric for {description} [CIS {cis_id}]",
            description=(
                f"No log-based metric covering {description} was found. "
                f"CIS GCP {cis_id} requires a metric+alert for this event type to "
                "detect unauthorized changes in real time."
            ),
            severity=Severity.MEDIUM,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.MONITORING,
            resource_type="GCP::Logging::LogMetric",
            resource_id=f"projects/{project_id}/metrics",
            region=region,
            account_id=project_id,
            cloud_provider=CloudProvider.GCP,
            remediation=(
                f"Create a log-based metric with filter containing `{filter_fragment}` "
                "and pair it with an Alerting policy notification channel. "
                "See Cloud Logging > Log-based Metrics in the Console."
            ),
            soc2_controls=["CC7.1", "CC7.2"],
            cis_gcp_controls=[cis_id],
            iso27001_controls=["A.8.15", "A.8.16"],
        )
    ]
