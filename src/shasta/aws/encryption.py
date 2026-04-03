"""Encryption checks for SOC 2 compliance.

Covers:
  CC6.7 — Data protection at rest (EBS volumes, RDS instances)
  A1.2  — Recovery / backups (RDS automated backups, multi-AZ)
"""

from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from shasta.aws.client import AWSClient
from shasta.evidence.models import CheckDomain, ComplianceStatus, Finding, Severity


def run_all_encryption_checks(client: AWSClient) -> list[Finding]:
    """Run all EBS and RDS encryption checks."""
    findings: list[Finding] = []
    account_id = client.account_info.account_id if client.account_info else "unknown"
    region = client.account_info.region if client.account_info else "us-east-1"

    findings.extend(check_ebs_encryption_default(client, account_id, region))
    findings.extend(check_ebs_volumes(client, account_id, region))
    findings.extend(check_rds_encryption(client, account_id, region))
    findings.extend(check_rds_public_access(client, account_id, region))
    findings.extend(check_rds_backups(client, account_id, region))

    return findings


def check_ebs_encryption_default(client: AWSClient, account_id: str, region: str) -> list[Finding]:
    """CC6.7 — Check that EBS encryption by default is enabled."""
    ec2 = client.client("ec2")

    try:
        response = ec2.get_ebs_encryption_by_default()
        enabled = response.get("EbsEncryptionByDefault", False)

        if enabled:
            return [
                Finding(
                    check_id="ebs-encryption-by-default",
                    title="EBS encryption by default is enabled",
                    description="EBS encryption by default is enabled in this region. All new EBS volumes will be automatically encrypted.",
                    severity=Severity.INFO,
                    status=ComplianceStatus.PASS,
                    domain=CheckDomain.ENCRYPTION,
                    resource_type="AWS::EC2::EBSEncryption",
                    resource_id=f"arn:aws:ec2:{region}:{account_id}:ebs-default-encryption",
                    region=region,
                    account_id=account_id,
                    soc2_controls=["CC6.7"],
                    details={"enabled": True},
                )
            ]
        else:
            return [
                Finding(
                    check_id="ebs-encryption-by-default",
                    title="EBS encryption by default is NOT enabled",
                    description="EBS encryption by default is disabled in this region. New EBS volumes will be created unencrypted unless explicitly specified. This means an engineer could accidentally create an unencrypted volume.",
                    severity=Severity.HIGH,
                    status=ComplianceStatus.FAIL,
                    domain=CheckDomain.ENCRYPTION,
                    resource_type="AWS::EC2::EBSEncryption",
                    resource_id=f"arn:aws:ec2:{region}:{account_id}:ebs-default-encryption",
                    region=region,
                    account_id=account_id,
                    remediation="Enable EBS encryption by default: AWS Console > EC2 > Settings > EBS encryption > Enable. Or via CLI: aws ec2 enable-ebs-encryption-by-default",
                    soc2_controls=["CC6.7"],
                    details={"enabled": False},
                )
            ]
    except ClientError:
        return []


def check_ebs_volumes(client: AWSClient, account_id: str, region: str) -> list[Finding]:
    """CC6.7 — Check that all existing EBS volumes are encrypted."""
    findings = []
    ec2 = client.client("ec2")

    try:
        paginator = ec2.get_paginator("describe_volumes")
        unencrypted = []
        encrypted_count = 0
        total = 0

        for page in paginator.paginate():
            for vol in page["Volumes"]:
                total += 1
                vol_id = vol["VolumeId"]
                is_encrypted = vol.get("Encrypted", False)

                if not is_encrypted:
                    # Get name tag
                    name = ""
                    for tag in vol.get("Tags", []):
                        if tag["Key"] == "Name":
                            name = tag["Value"]

                    attachments = vol.get("Attachments", [])
                    attached_to = attachments[0].get("InstanceId", "unattached") if attachments else "unattached"

                    unencrypted.append({
                        "volume_id": vol_id,
                        "name": name,
                        "size_gb": vol.get("Size", 0),
                        "state": vol.get("State", ""),
                        "attached_to": attached_to,
                    })
                else:
                    encrypted_count += 1

        if total == 0:
            return []  # No volumes, nothing to check

        if unencrypted:
            for vol in unencrypted:
                findings.append(
                    Finding(
                        check_id="ebs-volume-encrypted",
                        title=f"EBS volume {vol['volume_id']} is NOT encrypted",
                        description=f"EBS volume {vol['volume_id']}" + (f" ({vol['name']})" if vol['name'] else "") + f" ({vol['size_gb']} GB, attached to {vol['attached_to']}) is not encrypted. Data at rest on this volume is not protected.",
                        severity=Severity.HIGH,
                        status=ComplianceStatus.FAIL,
                        domain=CheckDomain.ENCRYPTION,
                        resource_type="AWS::EC2::Volume",
                        resource_id=vol["volume_id"],
                        region=region,
                        account_id=account_id,
                        remediation=f"EBS volumes cannot be encrypted in-place. Create an encrypted snapshot, then create a new encrypted volume from it, and swap. Enable EBS encryption by default to prevent future unencrypted volumes.",
                        soc2_controls=["CC6.7"],
                        details=vol,
                    )
                )
        else:
            findings.append(
                Finding(
                    check_id="ebs-volume-encrypted",
                    title=f"All {total} EBS volumes are encrypted",
                    description=f"All {total} EBS volume(s) in this region are encrypted at rest.",
                    severity=Severity.INFO,
                    status=ComplianceStatus.PASS,
                    domain=CheckDomain.ENCRYPTION,
                    resource_type="AWS::EC2::Volume",
                    resource_id=f"arn:aws:ec2:{region}:{account_id}:volumes",
                    region=region,
                    account_id=account_id,
                    soc2_controls=["CC6.7"],
                    details={"total": total, "encrypted": encrypted_count},
                )
            )

    except ClientError:
        pass

    return findings


def check_rds_encryption(client: AWSClient, account_id: str, region: str) -> list[Finding]:
    """CC6.7 — Check that all RDS instances have encryption at rest enabled."""
    findings = []
    rds = client.client("rds")

    try:
        paginator = rds.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            for db in page["DBInstances"]:
                db_id = db["DBInstanceIdentifier"]
                db_arn = db["DBInstanceArn"]
                encrypted = db.get("StorageEncrypted", False)
                engine = db.get("Engine", "unknown")
                instance_class = db.get("DBInstanceClass", "unknown")

                if encrypted:
                    kms_key = db.get("KmsKeyId", "default")
                    findings.append(
                        Finding(
                            check_id="rds-encryption-at-rest",
                            title=f"RDS instance '{db_id}' is encrypted",
                            description=f"RDS instance '{db_id}' ({engine}, {instance_class}) has storage encryption enabled.",
                            severity=Severity.INFO,
                            status=ComplianceStatus.PASS,
                            domain=CheckDomain.ENCRYPTION,
                            resource_type="AWS::RDS::DBInstance",
                            resource_id=db_arn,
                            region=region,
                            account_id=account_id,
                            soc2_controls=["CC6.7"],
                            details={"db_id": db_id, "engine": engine, "encrypted": True, "kms_key": kms_key},
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            check_id="rds-encryption-at-rest",
                            title=f"RDS instance '{db_id}' is NOT encrypted",
                            description=f"RDS instance '{db_id}' ({engine}, {instance_class}) does not have storage encryption enabled. Database data at rest is not protected.",
                            severity=Severity.HIGH,
                            status=ComplianceStatus.FAIL,
                            domain=CheckDomain.ENCRYPTION,
                            resource_type="AWS::RDS::DBInstance",
                            resource_id=db_arn,
                            region=region,
                            account_id=account_id,
                            remediation=f"RDS encryption cannot be enabled on an existing unencrypted instance. Create an encrypted snapshot, restore to a new encrypted instance, then switch over. Enable encryption for all new instances.",
                            soc2_controls=["CC6.7"],
                            details={"db_id": db_id, "engine": engine, "encrypted": False},
                        )
                    )
    except ClientError:
        pass

    return findings


def check_rds_public_access(client: AWSClient, account_id: str, region: str) -> list[Finding]:
    """CC6.6 — Check that RDS instances are not publicly accessible."""
    findings = []
    rds = client.client("rds")

    try:
        paginator = rds.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            for db in page["DBInstances"]:
                db_id = db["DBInstanceIdentifier"]
                db_arn = db["DBInstanceArn"]
                publicly_accessible = db.get("PubliclyAccessible", False)

                if publicly_accessible:
                    endpoint = db.get("Endpoint", {}).get("Address", "unknown")
                    findings.append(
                        Finding(
                            check_id="rds-no-public-access",
                            title=f"RDS instance '{db_id}' is publicly accessible",
                            description=f"RDS instance '{db_id}' (endpoint: {endpoint}) is configured as publicly accessible. Databases should never be directly reachable from the internet.",
                            severity=Severity.CRITICAL,
                            status=ComplianceStatus.FAIL,
                            domain=CheckDomain.ENCRYPTION,
                            resource_type="AWS::RDS::DBInstance",
                            resource_id=db_arn,
                            region=region,
                            account_id=account_id,
                            remediation=f"Modify RDS instance '{db_id}' to set PubliclyAccessible = false. Access should be through private subnets or VPN only.",
                            soc2_controls=["CC6.6", "CC6.7"],
                            details={"db_id": db_id, "publicly_accessible": True, "endpoint": endpoint},
                        )
                    )
    except ClientError:
        pass

    return findings


def check_rds_backups(client: AWSClient, account_id: str, region: str) -> list[Finding]:
    """A1.2 — Check that RDS instances have automated backups enabled."""
    findings = []
    rds = client.client("rds")

    try:
        paginator = rds.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            for db in page["DBInstances"]:
                db_id = db["DBInstanceIdentifier"]
                db_arn = db["DBInstanceArn"]
                retention = db.get("BackupRetentionPeriod", 0)
                multi_az = db.get("MultiAZ", False)

                issues = []
                if retention == 0:
                    issues.append("Automated backups disabled (retention = 0)")
                elif retention < 7:
                    issues.append(f"Backup retention only {retention} days (recommend 7+)")

                if not multi_az:
                    issues.append("Not Multi-AZ (single point of failure)")

                if issues:
                    findings.append(
                        Finding(
                            check_id="rds-backup-enabled",
                            title=f"RDS instance '{db_id}' has backup/availability issues",
                            description=f"RDS instance '{db_id}': {'; '.join(issues)}",
                            severity=Severity.HIGH if retention == 0 else Severity.MEDIUM,
                            status=ComplianceStatus.FAIL,
                            domain=CheckDomain.ENCRYPTION,
                            resource_type="AWS::RDS::DBInstance",
                            resource_id=db_arn,
                            region=region,
                            account_id=account_id,
                            remediation=f"Enable automated backups with 7+ day retention for '{db_id}'. Consider enabling Multi-AZ for production databases.",
                            soc2_controls=["CC6.7"],
                            details={"db_id": db_id, "retention_days": retention, "multi_az": multi_az},
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            check_id="rds-backup-enabled",
                            title=f"RDS instance '{db_id}' has backups and Multi-AZ enabled",
                            description=f"RDS instance '{db_id}' has {retention}-day backup retention and Multi-AZ enabled.",
                            severity=Severity.INFO,
                            status=ComplianceStatus.PASS,
                            domain=CheckDomain.ENCRYPTION,
                            resource_type="AWS::RDS::DBInstance",
                            resource_id=db_arn,
                            region=region,
                            account_id=account_id,
                            soc2_controls=["CC6.7"],
                            details={"db_id": db_id, "retention_days": retention, "multi_az": multi_az},
                        )
                    )
    except ClientError:
        pass

    return findings
