"""Logging and monitoring checks for SOC 2 compliance.

Covers:
  CC7.1 — Detection and Monitoring (CloudTrail, AWS Config)
  CC7.2 — Anomaly Monitoring (GuardDuty)
  CC8.1 — Change Management (CloudTrail, AWS Config)
"""

from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from transilience_compliance.aws.client import AWSClient
from transilience_compliance.evidence.models import CheckDomain, ComplianceStatus, Finding, Severity


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
                    details={"trail_name": trail_name, "issues": issues, "trail_config": {k: v for k, v in trail.items() if isinstance(v, (str, bool))}},
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
                    details={"trail_name": trail_name, "trail_config": {k: v for k, v in trail.items() if isinstance(v, (str, bool))}},
                )
            )

    return findings


def check_guardduty(client: AWSClient, account_id: str, region: str) -> list[Finding]:
    """CC7.1/CC7.2 — Check that GuardDuty is enabled."""
    findings = []
    gd = client.client("guardduty")

    try:
        detectors = gd.list_detectors()["DetectorIds"]
    except ClientError:
        return [
            Finding(
                check_id="guardduty-enabled",
                title="Unable to check GuardDuty status",
                description="Could not query GuardDuty. Ensure the scanning role has guardduty:ListDetectors permission.",
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

    if not detectors:
        return [
            Finding(
                check_id="guardduty-enabled",
                title="GuardDuty is NOT enabled",
                description="Amazon GuardDuty is not enabled in this account/region. GuardDuty uses machine learning to detect threats, compromised instances, and anomalous behavior — it's a critical layer of automated threat detection.",
                severity=Severity.HIGH,
                status=ComplianceStatus.FAIL,
                domain=CheckDomain.MONITORING,
                resource_type="AWS::GuardDuty::Detector",
                resource_id=f"arn:aws:guardduty:{region}:{account_id}",
                region=region,
                account_id=account_id,
                remediation="Enable GuardDuty in this region. It starts analyzing immediately with no configuration needed.",
                soc2_controls=["CC7.1", "CC7.2"],
            )
        ]

    # Check first detector's details
    detector_id = detectors[0]
    try:
        detector = gd.get_detector(DetectorId=detector_id)
        detector_status = detector.get("Status", "DISABLED")

        if detector_status == "ENABLED":
            # Check for active findings
            finding_stats = gd.get_findings_statistics(
                DetectorId=detector_id,
                FindingStatisticTypes=["COUNT_BY_SEVERITY"],
            )
            severity_counts = finding_stats.get("FindingStatistics", {}).get("CountBySeverity", {})
            total_findings = sum(int(v) for v in severity_counts.values())

            findings.append(
                Finding(
                    check_id="guardduty-enabled",
                    title="GuardDuty is enabled and active",
                    description=f"GuardDuty is enabled (detector {detector_id}). " +
                        (f"There are {total_findings} active finding(s) that should be reviewed." if total_findings > 0 else "No active findings."),
                    severity=Severity.INFO,
                    status=ComplianceStatus.PASS,
                    domain=CheckDomain.MONITORING,
                    resource_type="AWS::GuardDuty::Detector",
                    resource_id=f"arn:aws:guardduty:{region}:{account_id}:detector/{detector_id}",
                    region=region,
                    account_id=account_id,
                    soc2_controls=["CC7.1", "CC7.2"],
                    details={"detector_id": detector_id, "status": detector_status, "active_findings": total_findings, "severity_counts": severity_counts},
                )
            )

            # If there are active findings, flag them
            if total_findings > 0:
                findings.append(
                    Finding(
                        check_id="guardduty-no-active-findings",
                        title=f"GuardDuty has {total_findings} active finding(s)",
                        description=f"GuardDuty has detected {total_findings} potential threat(s). Active findings require investigation and response.",
                        severity=Severity.HIGH if any(float(k) >= 7.0 for k in severity_counts.keys()) else Severity.MEDIUM,
                        status=ComplianceStatus.FAIL,
                        domain=CheckDomain.MONITORING,
                        resource_type="AWS::GuardDuty::Detector",
                        resource_id=f"arn:aws:guardduty:{region}:{account_id}:detector/{detector_id}",
                        region=region,
                        account_id=account_id,
                        remediation="Review and address all GuardDuty findings. Archive resolved findings after investigation.",
                        soc2_controls=["CC7.2"],
                        details={"total_findings": total_findings, "severity_counts": severity_counts},
                    )
                )
        else:
            findings.append(
                Finding(
                    check_id="guardduty-enabled",
                    title="GuardDuty detector exists but is DISABLED",
                    description=f"GuardDuty detector {detector_id} exists but is disabled. It is not actively monitoring for threats.",
                    severity=Severity.HIGH,
                    status=ComplianceStatus.FAIL,
                    domain=CheckDomain.MONITORING,
                    resource_type="AWS::GuardDuty::Detector",
                    resource_id=f"arn:aws:guardduty:{region}:{account_id}:detector/{detector_id}",
                    region=region,
                    account_id=account_id,
                    remediation="Re-enable the GuardDuty detector.",
                    soc2_controls=["CC7.1", "CC7.2"],
                    details={"detector_id": detector_id, "status": detector_status},
                )
            )

    except ClientError:
        pass

    return findings


def check_aws_config(client: AWSClient, account_id: str, region: str) -> list[Finding]:
    """CC7.1/CC8.1 — Check that AWS Config is enabled and recording."""
    findings = []
    config = client.client("config")

    try:
        recorders = config.describe_configuration_recorders()["ConfigurationRecorders"]
    except ClientError:
        return [
            Finding(
                check_id="config-enabled",
                title="Unable to check AWS Config status",
                description="Could not query AWS Config. Ensure the scanning role has config:DescribeConfigurationRecorders permission.",
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

    if not recorders:
        return [
            Finding(
                check_id="config-enabled",
                title="AWS Config is NOT enabled",
                description="AWS Config is not set up in this account/region. Config continuously records resource configurations and changes — essential for change management auditing and drift detection.",
                severity=Severity.HIGH,
                status=ComplianceStatus.FAIL,
                domain=CheckDomain.MONITORING,
                resource_type="AWS::Config::ConfigurationRecorder",
                resource_id=f"arn:aws:config:{region}:{account_id}",
                region=region,
                account_id=account_id,
                remediation="Enable AWS Config with a recorder that captures all resource types, including global resources.",
                soc2_controls=["CC7.1", "CC8.1"],
            )
        ]

    for recorder in recorders:
        recorder_name = recorder.get("name", "default")
        recording_group = recorder.get("recordingGroup", {})
        all_supported = recording_group.get("allSupported", False)
        include_global = recording_group.get("includeGlobalResourceTypes", False)

        # Check if recording is active
        try:
            statuses = config.describe_configuration_recorder_status()["ConfigurationRecordersStatus"]
            recorder_status = next((s for s in statuses if s.get("name") == recorder_name), {})
            is_recording = recorder_status.get("recording", False)
        except ClientError:
            is_recording = False

        issues = []
        if not is_recording:
            issues.append("Recording is currently STOPPED")
        if not all_supported:
            issues.append("Not recording all supported resource types")
        if not include_global:
            issues.append("Not recording global resources (IAM, etc.)")

        if issues:
            findings.append(
                Finding(
                    check_id="config-enabled",
                    title=f"AWS Config recorder '{recorder_name}' has issues",
                    description=f"Config recorder '{recorder_name}' has issues: {'; '.join(issues)}",
                    severity=Severity.HIGH if "STOPPED" in str(issues) else Severity.MEDIUM,
                    status=ComplianceStatus.PARTIAL,
                    domain=CheckDomain.MONITORING,
                    resource_type="AWS::Config::ConfigurationRecorder",
                    resource_id=f"arn:aws:config:{region}:{account_id}:config-recorder/{recorder_name}",
                    region=region,
                    account_id=account_id,
                    remediation=f"Fix Config recorder: " + "; ".join(issues),
                    soc2_controls=["CC7.1", "CC8.1"],
                    details={"recorder_name": recorder_name, "issues": issues, "recording": is_recording, "all_supported": all_supported, "include_global": include_global},
                )
            )
        else:
            findings.append(
                Finding(
                    check_id="config-enabled",
                    title=f"AWS Config is enabled and recording all resources",
                    description=f"Config recorder '{recorder_name}' is active, recording all resource types including global resources.",
                    severity=Severity.INFO,
                    status=ComplianceStatus.PASS,
                    domain=CheckDomain.MONITORING,
                    resource_type="AWS::Config::ConfigurationRecorder",
                    resource_id=f"arn:aws:config:{region}:{account_id}:config-recorder/{recorder_name}",
                    region=region,
                    account_id=account_id,
                    soc2_controls=["CC7.1", "CC8.1"],
                    details={"recorder_name": recorder_name, "recording": True, "all_supported": True, "include_global": True},
                )
            )

    return findings
