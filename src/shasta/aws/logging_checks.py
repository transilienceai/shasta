"""Logging and monitoring checks for SOC 2 compliance.

Covers:
  CC7.1 — Detection and Monitoring (CloudTrail, AWS Config)
  CC7.2 — Anomaly Monitoring (GuardDuty)
  CC8.1 — Change Management (CloudTrail, AWS Config)
"""

from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from shasta.aws.client import AWSClient
from shasta.evidence.models import CheckDomain, ComplianceStatus, Finding, Severity


def _guardduty_severity(severity_counts: dict[str, Any]) -> Severity:
    """Determine finding severity from GuardDuty severity counts.

    GuardDuty COUNT_BY_SEVERITY returns keys as numeric strings (e.g., "8.0")
    representing severity ranges: 7.0-8.9 = High, 4.0-6.9 = Medium, 1.0-3.9 = Low.
    """
    for key, count in severity_counts.items():
        if int(count) == 0:
            continue
        try:
            val = float(key)
            if val >= 7.0:
                return Severity.HIGH
        except (ValueError, TypeError):
            # Key might be a string like "HIGH" in some API versions
            if str(key).upper() in ("HIGH", "CRITICAL"):
                return Severity.HIGH
    return Severity.MEDIUM


# Finding type prefixes that should always be treated as critical regardless of
# GuardDuty's numeric severity. These represent active compromise / data
# exfiltration / cryptomining and warrant immediate response.
_GUARDDUTY_CRITICAL_TYPE_PREFIXES = (
    "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration",
    "UnauthorizedAccess:IAMUser/AnomalousBehavior",
    "UnauthorizedAccess:EC2/MaliciousIPCaller",
    "CryptoCurrency:EC2/BitcoinTool",
    "CryptoCurrency:Lambda/BitcoinTool",
    "Trojan:EC2/",
    "Backdoor:EC2/",
    "Impact:",
    "Exfiltration:",
)


def _is_critical_guardduty_type(finding_type: str) -> bool:
    return any(finding_type.startswith(p) for p in _GUARDDUTY_CRITICAL_TYPE_PREFIXES)


def _list_top_guardduty_findings(
    gd: Any, detector_id: str, limit: int = 10
) -> list[dict[str, Any]]:
    """Return the most severe + recent active GuardDuty findings.

    Sorted by severity descending so the most dangerous types appear first.
    Only fetches non-archived findings.
    """
    try:
        listed = gd.list_findings(
            DetectorId=detector_id,
            FindingCriteria={
                "Criterion": {
                    "service.archived": {"Eq": ["false"]},
                }
            },
            SortCriteria={"AttributeName": "severity", "OrderBy": "DESC"},
            MaxResults=limit,
        )
        finding_ids = listed.get("FindingIds", [])
    except ClientError:
        return []

    if not finding_ids:
        return []

    try:
        resp = gd.get_findings(DetectorId=detector_id, FindingIds=finding_ids)
    except ClientError:
        return []

    out = []
    for f in resp.get("Findings", []):
        out.append(
            {
                "id": f.get("Id"),
                "type": f.get("Type", ""),
                "title": f.get("Title", ""),
                "severity": f.get("Severity", 0),
                "resource": (f.get("Resource") or {}).get("ResourceType", ""),
                "region": f.get("Region", ""),
                "updated_at": f.get("UpdatedAt", ""),
                "count": (f.get("Service") or {}).get("Count", 1),
            }
        )
    return out


def run_all_logging_checks(client: AWSClient) -> list[Finding]:
    """Run all logging and monitoring compliance checks."""
    findings: list[Finding] = []
    account_id = client.account_info.account_id if client.account_info else "unknown"
    region = client.account_info.region if client.account_info else "us-east-1"

    findings.extend(check_cloudtrail(client, account_id, region))
    findings.extend(check_guardduty(client, account_id, region))
    findings.extend(check_aws_config(client, account_id, region))

    return findings


def check_cloudtrail(client: AWSClient, account_id: str, region: str) -> list[Finding]:
    """CC7.1/CC8.1 — Check that CloudTrail is enabled and properly configured."""
    findings = []
    ct = client.client("cloudtrail")

    try:
        trails = ct.describe_trails()["trailList"]
    except ClientError:
        return [
            Finding(
                check_id="cloudtrail-enabled",
                title="Unable to check CloudTrail status",
                description="Could not query CloudTrail. Ensure the scanning role has cloudtrail:DescribeTrails permission.",
                severity=Severity.MEDIUM,
                status=ComplianceStatus.NOT_ASSESSED,
                domain=CheckDomain.MONITORING,
                resource_type="AWS::CloudTrail::Trail",
                resource_id=f"arn:aws:cloudtrail:{region}:{account_id}",
                region=region,
                account_id=account_id,
                soc2_controls=["CC7.1", "CC8.1"],
            )
        ]

    if not trails:
        return [
            Finding(
                check_id="cloudtrail-enabled",
                title="No CloudTrail trails configured",
                description="No CloudTrail trails exist in this account. CloudTrail is essential for logging all API activity — without it, you have no audit trail of who did what in your AWS account.",
                severity=Severity.CRITICAL,
                status=ComplianceStatus.FAIL,
                domain=CheckDomain.MONITORING,
                resource_type="AWS::CloudTrail::Trail",
                resource_id=f"arn:aws:cloudtrail:{region}:{account_id}",
                region=region,
                account_id=account_id,
                remediation="Create a CloudTrail trail that logs management events across all regions. Enable log file validation and send logs to a dedicated S3 bucket.",
                soc2_controls=["CC7.1", "CC8.1"],
            )
        ]

    for trail in trails:
        trail_name = trail.get("Name", "unknown")
        trail_arn = trail.get("TrailARN", "")
        issues = []

        # Check multi-region
        if not trail.get("IsMultiRegionTrail", False):
            issues.append("Not multi-region (only logs events in its home region)")

        # Check log file validation
        if not trail.get("LogFileValidationEnabled", False):
            issues.append("Log file validation disabled (can't verify log integrity)")

        # Check if logging is active
        try:
            status = ct.get_trail_status(Name=trail_arn)
            if not status.get("IsLogging", False):
                issues.append("Logging is currently STOPPED")
        except ClientError:
            issues.append("Could not verify logging status")

        # Check global service events
        if not trail.get("IncludeGlobalServiceEvents", False):
            issues.append("Not logging global service events (IAM, STS, etc.)")

        if issues:
            findings.append(
                Finding(
                    check_id="cloudtrail-enabled",
                    title=f"CloudTrail '{trail_name}' has configuration issues",
                    description=f"Trail '{trail_name}' exists but has issues: {'; '.join(issues)}",
                    severity=Severity.HIGH if "STOPPED" in str(issues) else Severity.MEDIUM,
                    status=ComplianceStatus.PARTIAL,
                    domain=CheckDomain.MONITORING,
                    resource_type="AWS::CloudTrail::Trail",
                    resource_id=trail_arn,
                    region=region,
                    account_id=account_id,
                    remediation=f"Fix CloudTrail '{trail_name}': " + "; ".join(issues),
                    soc2_controls=["CC7.1", "CC8.1"],
                    details={
                        "trail_name": trail_name,
                        "issues": issues,
                        "trail_config": {
                            k: v for k, v in trail.items() if isinstance(v, (str, bool))
                        },
                    },
                )
            )
        else:
            findings.append(
                Finding(
                    check_id="cloudtrail-enabled",
                    title=f"CloudTrail '{trail_name}' is properly configured",
                    description=f"Trail '{trail_name}' is multi-region, has log file validation, is actively logging, and includes global events.",
                    severity=Severity.INFO,
                    status=ComplianceStatus.PASS,
                    domain=CheckDomain.MONITORING,
                    resource_type="AWS::CloudTrail::Trail",
                    resource_id=trail_arn,
                    region=region,
                    account_id=account_id,
                    soc2_controls=["CC7.1", "CC8.1"],
                    details={
                        "trail_name": trail_name,
                        "trail_config": {
                            k: v for k, v in trail.items() if isinstance(v, (str, bool))
                        },
                    },
                )
            )

    return findings


def check_guardduty(client: AWSClient, account_id: str, region: str) -> list[Finding]:
    """CC7.1/CC7.2 — Check that GuardDuty is enabled across all enabled regions.

    Probes every region returned by ec2:DescribeRegions. Reports PASS if at
    least one region has an ENABLED detector, and surfaces uncovered regions
    in the finding details. Per-region active findings are emitted separately.
    """
    findings: list[Finding] = []

    try:
        regions = client.get_enabled_regions()
    except ClientError:
        regions = [region]

    # region -> {"status": ENABLED|DISABLED, "detector_id": str, "severity_counts": dict}
    per_region: dict[str, dict[str, Any]] = {}
    probe_errors = 0

    for r in regions:
        try:
            gd = client.for_region(r).client("guardduty")
            detector_ids = gd.list_detectors().get("DetectorIds", [])
        except ClientError:
            probe_errors += 1
            continue

        if not detector_ids:
            continue

        detector_id = detector_ids[0]
        try:
            detector = gd.get_detector(DetectorId=detector_id)
            status = detector.get("Status", "DISABLED")
            severity_counts: dict[str, Any] = {}
            top_findings: list[dict[str, Any]] = []
            if status == "ENABLED":
                stats = gd.get_findings_statistics(
                    DetectorId=detector_id,
                    FindingStatisticTypes=["COUNT_BY_SEVERITY"],
                )
                severity_counts = stats.get("FindingStatistics", {}).get("CountBySeverity", {})
                # Pull the actual top findings (highest severity first, most recent)
                top_findings = _list_top_guardduty_findings(gd, detector_id, limit=10)
            per_region[r] = {
                "status": status,
                "detector_id": detector_id,
                "severity_counts": severity_counts,
                "top_findings": top_findings,
            }
        except ClientError:
            probe_errors += 1
            continue

    # If we couldn't query anywhere, return NOT_ASSESSED
    if not per_region and probe_errors == len(regions):
        return [
            Finding(
                check_id="guardduty-enabled",
                title="Unable to check GuardDuty status",
                description="Could not query GuardDuty in any region. Ensure the scanning role has guardduty:ListDetectors permission.",
                severity=Severity.MEDIUM,
                status=ComplianceStatus.NOT_ASSESSED,
                domain=CheckDomain.MONITORING,
                resource_type="AWS::GuardDuty::Detector",
                resource_id=f"arn:aws:guardduty:{region}:{account_id}",
                region=region,
                account_id=account_id,
                soc2_controls=["CC7.1", "CC7.2"],
            )
        ]

    enabled_regions = sorted(r for r, d in per_region.items() if d["status"] == "ENABLED")
    disabled_regions = sorted(r for r, d in per_region.items() if d["status"] != "ENABLED")
    uncovered_regions = sorted(set(regions) - set(per_region.keys()))

    if not per_region:
        # No detectors anywhere — true fail
        return [
            Finding(
                check_id="guardduty-enabled",
                title="GuardDuty is NOT enabled in any region",
                description=f"Amazon GuardDuty has no detectors in any of the {len(regions)} enabled region(s). GuardDuty uses machine learning to detect threats, compromised instances, and anomalous behavior — it's a critical layer of automated threat detection.",
                severity=Severity.HIGH,
                status=ComplianceStatus.FAIL,
                domain=CheckDomain.MONITORING,
                resource_type="AWS::GuardDuty::Detector",
                resource_id=f"arn:aws:guardduty:{region}:{account_id}",
                region=region,
                account_id=account_id,
                remediation="Enable GuardDuty in your primary operating region(s). It starts analyzing immediately with no configuration needed.",
                soc2_controls=["CC7.1", "CC7.2"],
                details={"regions_checked": regions},
            )
        ]

    if enabled_regions:
        primary = enabled_regions[0]
        primary_detector = per_region[primary]["detector_id"]
        total_active_findings = sum(
            int(v)
            for r in enabled_regions
            for v in per_region[r]["severity_counts"].values()
        )
        findings.append(
            Finding(
                check_id="guardduty-enabled",
                title=f"GuardDuty is enabled in {len(enabled_regions)} region(s): {', '.join(enabled_regions)}",
                description=(
                    f"GuardDuty is actively monitoring in: {', '.join(enabled_regions)}. "
                    + (
                        f"There are {total_active_findings} active finding(s) across enabled regions."
                        if total_active_findings > 0
                        else "No active findings."
                    )
                ),
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.MONITORING,
                resource_type="AWS::GuardDuty::Detector",
                resource_id=f"arn:aws:guardduty:{primary}:{account_id}:detector/{primary_detector}",
                region=primary,
                account_id=account_id,
                soc2_controls=["CC7.1", "CC7.2"],
                details={
                    "enabled_regions": enabled_regions,
                    "disabled_regions": disabled_regions,
                    "uncovered_regions": uncovered_regions,
                    "active_findings": total_active_findings,
                },
            )
        )

        # Per-region active findings — surface actual finding types so users
        # can see WHAT is happening, not just a count.
        for r in enabled_regions:
            severity_counts = per_region[r]["severity_counts"]
            total = sum(int(v) for v in severity_counts.values())
            top_findings = per_region[r].get("top_findings", [])
            if total > 0:
                detector_id = per_region[r]["detector_id"]

                # Determine severity: bump to CRITICAL if any top finding has a
                # critical-class type, regardless of GuardDuty's numeric scale.
                has_critical_type = any(
                    _is_critical_guardduty_type(tf.get("type", "")) for tf in top_findings
                )
                has_high_numeric = any(
                    float(tf.get("severity") or 0) >= 7.0 for tf in top_findings
                )
                if has_critical_type:
                    severity = Severity.CRITICAL
                elif has_high_numeric:
                    severity = Severity.HIGH
                else:
                    severity = _guardduty_severity(severity_counts)

                # Build a description listing the actual finding types
                if top_findings:
                    type_summary = "; ".join(
                        f"{tf['type']} (sev={tf['severity']}, x{tf.get('count', 1)})"
                        for tf in top_findings[:5]
                    )
                    description = (
                        f"GuardDuty has detected {total} active threat(s) in {r}. "
                        f"Top finding types: {type_summary}"
                    )
                else:
                    description = (
                        f"GuardDuty has detected {total} active threat(s) in {r}. "
                        "Active findings require investigation and response."
                    )

                findings.append(
                    Finding(
                        check_id="guardduty-no-active-findings",
                        title=f"GuardDuty has {total} active finding(s) in {r}",
                        description=description,
                        severity=severity,
                        status=ComplianceStatus.FAIL,
                        domain=CheckDomain.MONITORING,
                        resource_type="AWS::GuardDuty::Detector",
                        resource_id=f"arn:aws:guardduty:{r}:{account_id}:detector/{detector_id}",
                        region=r,
                        account_id=account_id,
                        remediation="Review and address all GuardDuty findings in the AWS Console (GuardDuty > Findings). Archive resolved findings after investigation.",
                        soc2_controls=["CC7.2"],
                        details={
                            "total_findings": total,
                            "severity_counts": severity_counts,
                            "top_findings": top_findings,
                        },
                    )
                )
    else:
        # Detectors exist but all are disabled
        findings.append(
            Finding(
                check_id="guardduty-enabled",
                title=f"GuardDuty detectors exist but are DISABLED in {len(disabled_regions)} region(s)",
                description=f"GuardDuty detectors are present in {', '.join(disabled_regions)} but none are enabled. They are not actively monitoring for threats.",
                severity=Severity.HIGH,
                status=ComplianceStatus.FAIL,
                domain=CheckDomain.MONITORING,
                resource_type="AWS::GuardDuty::Detector",
                resource_id=f"arn:aws:guardduty:{disabled_regions[0]}:{account_id}",
                region=disabled_regions[0],
                account_id=account_id,
                remediation="Re-enable the GuardDuty detector(s).",
                soc2_controls=["CC7.1", "CC7.2"],
                details={"disabled_regions": disabled_regions},
            )
        )

    return findings


def check_aws_config(client: AWSClient, account_id: str, region: str) -> list[Finding]:
    """CC7.1/CC8.1 — Check AWS Config is enabled and recording across all enabled regions.

    Probes every region returned by ec2:DescribeRegions. Reports PASS if at
    least one region has an actively recording recorder, and surfaces uncovered
    regions in the finding details. Per-region recorder issues are emitted as
    PARTIAL findings tagged with the region.
    """
    findings: list[Finding] = []

    try:
        regions = client.get_enabled_regions()
    except ClientError:
        regions = [region]

    # region -> list of {"name", "recording", "all_supported", "include_global", "issues"}
    per_region: dict[str, list[dict[str, Any]]] = {}
    probe_errors = 0

    for r in regions:
        try:
            cfg = client.for_region(r).client("config")
            recorders = cfg.describe_configuration_recorders().get("ConfigurationRecorders", [])
        except ClientError:
            probe_errors += 1
            continue

        if not recorders:
            continue

        try:
            statuses = cfg.describe_configuration_recorder_status().get(
                "ConfigurationRecordersStatus", []
            )
        except ClientError:
            statuses = []

        recorder_infos: list[dict[str, Any]] = []
        for recorder in recorders:
            recorder_name = recorder.get("name", "default")
            recording_group = recorder.get("recordingGroup", {})
            all_supported = recording_group.get("allSupported", False)
            include_global = recording_group.get("includeGlobalResourceTypes", False)
            status_entry = next((s for s in statuses if s.get("name") == recorder_name), {})
            is_recording = status_entry.get("recording", False)

            issues = []
            if not is_recording:
                issues.append("Recording is currently STOPPED")
            if not all_supported:
                issues.append("Not recording all supported resource types")
            if not include_global:
                issues.append("Not recording global resources (IAM, etc.)")

            recorder_infos.append(
                {
                    "name": recorder_name,
                    "recording": is_recording,
                    "all_supported": all_supported,
                    "include_global": include_global,
                    "issues": issues,
                }
            )
        per_region[r] = recorder_infos

    if not per_region and probe_errors == len(regions):
        return [
            Finding(
                check_id="config-enabled",
                title="Unable to check AWS Config status",
                description="Could not query AWS Config in any region. Ensure the scanning role has config:DescribeConfigurationRecorders permission.",
                severity=Severity.MEDIUM,
                status=ComplianceStatus.NOT_ASSESSED,
                domain=CheckDomain.MONITORING,
                resource_type="AWS::Config::ConfigurationRecorder",
                resource_id=f"arn:aws:config:{region}:{account_id}",
                region=region,
                account_id=account_id,
                soc2_controls=["CC7.1", "CC8.1"],
            )
        ]

    if not per_region:
        return [
            Finding(
                check_id="config-enabled",
                title="AWS Config is NOT enabled in any region",
                description=f"AWS Config has no recorders in any of the {len(regions)} enabled region(s). Config continuously records resource configurations and changes — essential for change management auditing and drift detection.",
                severity=Severity.HIGH,
                status=ComplianceStatus.FAIL,
                domain=CheckDomain.MONITORING,
                resource_type="AWS::Config::ConfigurationRecorder",
                resource_id=f"arn:aws:config:{region}:{account_id}",
                region=region,
                account_id=account_id,
                remediation="Enable AWS Config in your primary operating region(s) with a recorder that captures all resource types, including global resources.",
                soc2_controls=["CC7.1", "CC8.1"],
                details={"regions_checked": regions},
            )
        ]

    healthy_regions = sorted(
        r for r, infos in per_region.items() if any(not i["issues"] for i in infos)
    )
    uncovered_regions = sorted(set(regions) - set(per_region.keys()))

    if healthy_regions:
        primary = healthy_regions[0]
        primary_recorder = next(i for i in per_region[primary] if not i["issues"])["name"]
        findings.append(
            Finding(
                check_id="config-enabled",
                title=f"AWS Config is enabled and recording in {len(healthy_regions)} region(s): {', '.join(healthy_regions)}",
                description=f"AWS Config recorders are actively recording all resource types (including global resources) in: {', '.join(healthy_regions)}.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.MONITORING,
                resource_type="AWS::Config::ConfigurationRecorder",
                resource_id=f"arn:aws:config:{primary}:{account_id}:config-recorder/{primary_recorder}",
                region=primary,
                account_id=account_id,
                soc2_controls=["CC7.1", "CC8.1"],
                details={
                    "healthy_regions": healthy_regions,
                    "uncovered_regions": uncovered_regions,
                },
            )
        )

    # Per-region issues (PARTIAL findings) — only for recorders that have problems
    for r, infos in sorted(per_region.items()):
        for info in infos:
            if not info["issues"]:
                continue
            # Skip "STOPPED" issues if a healthy recorder exists in the same region
            findings.append(
                Finding(
                    check_id="config-enabled",
                    title=f"AWS Config recorder '{info['name']}' in {r} has issues",
                    description=f"Config recorder '{info['name']}' in {r} has issues: {'; '.join(info['issues'])}",
                    severity=Severity.HIGH if "STOPPED" in str(info["issues"]) else Severity.MEDIUM,
                    status=ComplianceStatus.PARTIAL,
                    domain=CheckDomain.MONITORING,
                    resource_type="AWS::Config::ConfigurationRecorder",
                    resource_id=f"arn:aws:config:{r}:{account_id}:config-recorder/{info['name']}",
                    region=r,
                    account_id=account_id,
                    remediation="Fix Config recorder: " + "; ".join(info["issues"]),
                    soc2_controls=["CC7.1", "CC8.1"],
                    details={
                        "recorder_name": info["name"],
                        "issues": info["issues"],
                        "recording": info["recording"],
                        "all_supported": info["all_supported"],
                        "include_global": info["include_global"],
                    },
                )
            )

    # If no healthy region at all, add a FAIL rollup
    if not healthy_regions:
        findings.insert(
            0,
            Finding(
                check_id="config-enabled",
                title="AWS Config is enabled but no recorder is healthy",
                description=f"Config recorders exist in {', '.join(sorted(per_region.keys()))} but all have issues (stopped, partial coverage, or missing global resources).",
                severity=Severity.HIGH,
                status=ComplianceStatus.FAIL,
                domain=CheckDomain.MONITORING,
                resource_type="AWS::Config::ConfigurationRecorder",
                resource_id=f"arn:aws:config:{sorted(per_region.keys())[0]}:{account_id}",
                region=sorted(per_region.keys())[0],
                account_id=account_id,
                remediation="Resolve recorder issues so at least one region has a fully healthy recorder.",
                soc2_controls=["CC7.1", "CC8.1"],
                details={"regions_with_issues": sorted(per_region.keys())},
            ),
        )

    return findings
