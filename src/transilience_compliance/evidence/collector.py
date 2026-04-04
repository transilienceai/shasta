"""Evidence collector — snapshots AWS state for audit trail.

Captures point-in-time evidence that an auditor can review:
  - IAM configuration snapshots
  - S3 bucket policies and encryption settings
  - Security group rules
  - CloudTrail/GuardDuty/Config status
  - Credential report

Each evidence artifact is timestamped and stored in the database + as JSON files.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from transilience_compliance.aws.client import AWSClient
from transilience_compliance.db.schema import ComplianceDB
from transilience_compliance.evidence.models import Evidence


def collect_all_evidence(
    client: AWSClient,
    scan_id: str,
    output_path: Path | str = "data/evidence",
) -> list[Path]:
    """Collect all evidence artifacts and save to disk + database."""
    output_dir = Path(output_path)
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    scan_dir = output_dir / f"scan-{scan_id}-{timestamp}"
    scan_dir.mkdir(parents=True, exist_ok=True)

    db = ComplianceDB()
    db.initialize()

    account_id = client.account_info.account_id if client.account_info else "unknown"
    saved_files = []

    collectors = [
        ("iam-password-policy", "IAM password policy configuration", _collect_password_policy),
        ("iam-credential-report", "IAM credential report (all users)", _collect_credential_report),
        ("iam-users-and-policies", "IAM users with their policies and groups", _collect_iam_users),
        ("s3-bucket-configs", "S3 bucket encryption, versioning, and access settings", _collect_s3_configs),
        ("security-groups", "VPC security group rules", _collect_security_groups),
        ("vpc-flow-log-status", "VPC flow log configurations", _collect_vpc_flow_logs),
        ("cloudtrail-status", "CloudTrail trail configurations and status", _collect_cloudtrail),
        ("guardduty-status", "GuardDuty detector status and findings summary", _collect_guardduty),
        ("config-recorder-status", "AWS Config recorder status", _collect_config_status),
    ]

    for evidence_id, description, collector_fn in collectors:
        try:
            data = collector_fn(client)
            evidence = Evidence(
                scan_id=scan_id,
                finding_id=evidence_id,
                evidence_type="config_snapshot",
                description=description,
                data=data,
            )
            db.save_evidence(evidence)

            filepath = scan_dir / f"{evidence_id}.json"
            filepath.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
            saved_files.append(filepath)
        except Exception as e:
            # Log but don't fail — collect what we can
            error_path = scan_dir / f"{evidence_id}-error.txt"
            error_path.write_text(f"Collection failed: {e}", encoding="utf-8")
            saved_files.append(error_path)

    # Write manifest
    manifest = {
        "scan_id": scan_id,
        "account_id": account_id,
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "artifacts": [str(f.name) for f in saved_files],
    }
    manifest_path = scan_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    saved_files.append(manifest_path)

    db.close()
    return saved_files


def _collect_password_policy(client: AWSClient) -> dict:
    iam = client.client("iam")
    try:
        return iam.get_account_password_policy()["PasswordPolicy"]
    except Exception:
        return {"status": "no_policy_configured"}


def _collect_credential_report(client: AWSClient) -> dict:
    import csv
    import io
    import time

    iam = client.client("iam")
    for _ in range(10):
        resp = iam.generate_credential_report()
        if resp["State"] == "COMPLETE":
            break
        time.sleep(1)

    raw = iam.get_credential_report()["Content"].decode("utf-8")
    users = list(csv.DictReader(io.StringIO(raw)))
    return {"users": users, "total_users": len(users)}


def _collect_iam_users(client: AWSClient) -> dict:
    iam = client.client("iam")
    users_data = []

    paginator = iam.get_paginator("list_users")
    for page in paginator.paginate():
        for user in page["Users"]:
            username = user["UserName"]
            attached = iam.list_attached_user_policies(UserName=username)["AttachedPolicies"]
            inline = iam.list_user_policies(UserName=username)["PolicyNames"]
            groups = [g["GroupName"] for g in iam.list_groups_for_user(UserName=username)["Groups"]]
            mfa = iam.list_mfa_devices(UserName=username)["MFADevices"]
            keys = iam.list_access_keys(UserName=username)["AccessKeyMetadata"]

            users_data.append({
                "username": username,
                "arn": user["Arn"],
                "created": user["CreateDate"].isoformat(),
                "attached_policies": [p["PolicyName"] for p in attached],
                "inline_policies": list(inline),
                "groups": groups,
                "mfa_devices": len(mfa),
                "access_keys": [
                    {"key_id": k["AccessKeyId"], "status": k["Status"], "created": k["CreateDate"].isoformat()}
                    for k in keys
                ],
            })

    return {"users": users_data, "total": len(users_data)}


def _collect_s3_configs(client: AWSClient) -> dict:
    s3 = client.client("s3")
    buckets_data = []

    for bucket in s3.list_buckets().get("Buckets", []):
        name = bucket["Name"]
        config: dict[str, Any] = {"name": name}

        try:
            enc = s3.get_bucket_encryption(Bucket=name)
            config["encryption"] = enc.get("ServerSideEncryptionConfiguration", {})
        except Exception:
            config["encryption"] = None

        try:
            ver = s3.get_bucket_versioning(Bucket=name)
            config["versioning"] = ver.get("Status", "Disabled")
        except Exception:
            config["versioning"] = "unknown"

        try:
            pab = s3.get_public_access_block(Bucket=name)
            config["public_access_block"] = pab.get("PublicAccessBlockConfiguration", {})
        except Exception:
            config["public_access_block"] = None

        try:
            pol = s3.get_bucket_policy(Bucket=name)
            config["policy"] = json.loads(pol["Policy"])
        except Exception:
            config["policy"] = None

        buckets_data.append(config)

    return {"buckets": buckets_data, "total": len(buckets_data)}


def _collect_security_groups(client: AWSClient) -> dict:
    ec2 = client.client("ec2")
    sgs = []
    paginator = ec2.get_paginator("describe_security_groups")
    for page in paginator.paginate():
        for sg in page["SecurityGroups"]:
            sgs.append({
                "group_id": sg["GroupId"],
                "group_name": sg.get("GroupName", ""),
                "vpc_id": sg.get("VpcId", ""),
                "description": sg.get("Description", ""),
                "ingress_rules": sg.get("IpPermissions", []),
                "egress_rules": sg.get("IpPermissionsEgress", []),
            })
    return {"security_groups": sgs, "total": len(sgs)}


def _collect_vpc_flow_logs(client: AWSClient) -> dict:
    ec2 = client.client("ec2")
    vpcs = ec2.describe_vpcs()["Vpcs"]
    flow_logs = ec2.describe_flow_logs()["FlowLogs"]

    return {
        "vpcs": [{"vpc_id": v["VpcId"], "tags": v.get("Tags", [])} for v in vpcs],
        "flow_logs": [
            {"flow_log_id": fl["FlowLogId"], "resource_id": fl["ResourceId"], "status": fl["FlowLogStatus"]}
            for fl in flow_logs
        ],
    }


def _collect_cloudtrail(client: AWSClient) -> dict:
    ct = client.client("cloudtrail")
    trails = ct.describe_trails()["trailList"]
    trail_data = []

    for trail in trails:
        trail_info = {k: v for k, v in trail.items() if isinstance(v, (str, bool))}
        try:
            status = ct.get_trail_status(Name=trail["TrailARN"])
            trail_info["is_logging"] = status.get("IsLogging", False)
        except Exception:
            trail_info["is_logging"] = "unknown"
        trail_data.append(trail_info)

    return {"trails": trail_data, "total": len(trail_data)}


def _collect_guardduty(client: AWSClient) -> dict:
    gd = client.client("guardduty")
    detectors = gd.list_detectors()["DetectorIds"]

    if not detectors:
        return {"enabled": False, "detectors": []}

    detector_id = detectors[0]
    detector = gd.get_detector(DetectorId=detector_id)

    try:
        stats = gd.get_findings_statistics(
            DetectorId=detector_id,
            FindingStatisticTypes=["COUNT_BY_SEVERITY"],
        )
        finding_counts = stats.get("FindingStatistics", {}).get("CountBySeverity", {})
    except Exception:
        finding_counts = {}

    return {
        "enabled": True,
        "detector_id": detector_id,
        "status": detector.get("Status", "UNKNOWN"),
        "finding_counts": finding_counts,
    }


def _collect_config_status(client: AWSClient) -> dict:
    config = client.client("config")

    try:
        recorders = config.describe_configuration_recorders()["ConfigurationRecorders"]
        statuses = config.describe_configuration_recorder_status()["ConfigurationRecordersStatus"]
    except Exception:
        return {"enabled": False}

    return {
        "enabled": bool(recorders),
        "recorders": [
            {
                "name": r.get("name"),
                "all_supported": r.get("recordingGroup", {}).get("allSupported", False),
                "include_global": r.get("recordingGroup", {}).get("includeGlobalResourceTypes", False),
            }
            for r in recorders
        ],
        "status": [
            {"name": s.get("name"), "recording": s.get("recording", False)}
            for s in statuses
        ],
    }
