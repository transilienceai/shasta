"""GCP encryption security checks for SOC 2 and CIS GCP Benchmark v2.0.

Covers:
  CC6.7 — Data protection at rest and in transit

CIS GCP v2.0 Sections 1 (KMS), 6 (Cloud SQL), 7 (BigQuery).
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

IS_GLOBAL = True  # Uses global/project-wide listing endpoints for KMS, SQL, BigQuery

# KMS key rotation period must be ≤ this many seconds (90 days)
_MAX_ROTATION_PERIOD_SECONDS = 90 * 24 * 3600


def run_all_gcp_encryption_checks(client: GCPClient) -> list[Finding]:
    """Run all GCP encryption compliance checks."""
    project_id = client.project_id if client.account_info else (client._project_id or "unknown")

    findings: list[Finding] = []
    findings.extend(check_kms_key_rotation_period(client, project_id))
    findings.extend(check_sql_require_ssl(client, project_id))
    findings.extend(check_sql_no_public_ip(client, project_id))
    findings.extend(check_sql_data_backup_enabled(client, project_id))
    findings.extend(check_bigquery_no_public_access(client, project_id))
    findings.extend(check_bigquery_cmek_configured(client, project_id))

    return findings


def check_kms_key_rotation_period(
    client: GCPClient, project_id: str
) -> list[Finding]:
    """[CIS 1.10] Cloud KMS key rotation period should be ≤90 days.

    Key rotation limits the amount of data encrypted under a single key version
    and the window of exposure if a key is compromised. The CIS benchmark requires
    an automatic rotation period of 90 days or less.
    """
    region = "global"
    try:
        kms = client.service("cloudkms", "v1")
        # List all key rings across all locations via the aggregated endpoint
        parent = f"projects/{project_id}/locations/-"
        key_rings_resp = kms.projects().locations().keyRings().list(parent=parent).execute()
        key_rings = key_rings_resp.get("keyRings", [])
    except Exception as e:
        return [
            Finding.not_assessed(
                check_id="gcp-kms-key-rotation",
                title="Unable to list KMS key rings",
                description=f"API call failed: {e}",
                domain=CheckDomain.ENCRYPTION,
                resource_type="GCP::KMS::CryptoKey",
                account_id=project_id,
                region=region,
                cloud_provider=CloudProvider.GCP,
            )
        ]

    if not key_rings:
        return [
            Finding(
                check_id="gcp-kms-key-rotation",
                title="No Cloud KMS key rings found in project",
                description="No KMS key rings exist — rotation check not applicable.",
                severity=Severity.INFO,
                status=ComplianceStatus.NOT_APPLICABLE,
                domain=CheckDomain.ENCRYPTION,
                resource_type="GCP::KMS::CryptoKey",
                resource_id=f"projects/{project_id}/locations/-/keyRings",
                region=region,
                account_id=project_id,
                cloud_provider=CloudProvider.GCP,
                soc2_controls=["CC6.7"],
                cis_gcp_controls=["1.10"],
            )
        ]

    offenders: list[dict[str, Any]] = []
    for ring in key_rings:
        ring_name = ring.get("name", "")
        try:
            keys_resp = (
                kms.projects()
                .locations()
                .keyRings()
                .cryptoKeys()
                .list(parent=ring_name)
                .execute()
            )
            keys = keys_resp.get("cryptoKeys", [])
        except Exception:
            continue

        for key in keys:
            purpose = key.get("purpose", "")
            if purpose != "ENCRYPT_DECRYPT":
                continue  # Only symmetric encryption keys can be rotated
            rotation_period = key.get("rotationPeriod")
            next_rotation = key.get("nextRotationTime")

            if not rotation_period:
                offenders.append(
                    {
                        "key": key.get("name", ""),
                        "issue": "no rotation period set",
                    }
                )
            else:
                # rotationPeriod is like "7776000s" (90 days in seconds)
                try:
                    period_secs = int(rotation_period.rstrip("s"))
                    if period_secs > _MAX_ROTATION_PERIOD_SECONDS:
                        offenders.append(
                            {
                                "key": key.get("name", ""),
                                "issue": f"rotation period {period_secs // 86400} days (>{_MAX_ROTATION_PERIOD_SECONDS // 86400} day limit)",
                            }
                        )
                except (ValueError, AttributeError):
                    pass

    if not offenders:
        return [
            Finding(
                check_id="gcp-kms-key-rotation",
                title="All KMS ENCRYPT_DECRYPT keys have rotation ≤90 days",
                description="All Cloud KMS symmetric keys are configured to rotate within 90 days.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.ENCRYPTION,
                resource_type="GCP::KMS::CryptoKey",
                resource_id=f"projects/{project_id}/locations/-/keyRings/-/cryptoKeys",
                region=region,
                account_id=project_id,
                cloud_provider=CloudProvider.GCP,
                soc2_controls=["CC6.7"],
                cis_gcp_controls=["1.10"],
            )
        ]

    return [
        Finding(
            check_id="gcp-kms-key-rotation",
            title=f"{len(offenders)} KMS key(s) have insufficient rotation configuration",
            description=(
                f"{len(offenders)} Cloud KMS symmetric key(s) either have no automatic rotation "
                "period or a period exceeding 90 days. Long-lived keys expand the breach window."
            ),
            severity=Severity.MEDIUM,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.ENCRYPTION,
            resource_type="GCP::KMS::CryptoKey",
            resource_id=f"projects/{project_id}/locations/-/keyRings/-/cryptoKeys",
            region=region,
            account_id=project_id,
            cloud_provider=CloudProvider.GCP,
            remediation=(
                "Set automatic rotation via the Console or: "
                "`gcloud kms keys update KEY_NAME --keyring=KEYRING --location=LOCATION "
                "--rotation-period=7776000s --next-rotation-time=TOMORROW_ISO8601`. "
                "For new keys, always set --rotation-period at creation time."
            ),
            soc2_controls=["CC6.7"],
            cis_gcp_controls=["1.10"],
            iso27001_controls=["A.8.24"],
            details={"keys_with_issues": offenders[:20]},
        )
    ]


def check_sql_require_ssl(
    client: GCPClient, project_id: str
) -> list[Finding]:
    """[CIS 6.3] Cloud SQL instances should require SSL for all connections.

    Without enforced SSL, database clients can connect over unencrypted channels,
    exposing credentials and data in transit to network eavesdropping.
    """
    region = "global"
    try:
        sqladmin = client.service("sqladmin", "v1beta4")
        response = sqladmin.instances().list(project=project_id).execute()
        instances = response.get("items", [])
    except Exception as e:
        return [
            Finding.not_assessed(
                check_id="gcp-sql-require-ssl",
                title="Unable to list Cloud SQL instances",
                description=f"API call failed: {e}",
                domain=CheckDomain.ENCRYPTION,
                resource_type="GCP::SQL::Instance",
                account_id=project_id,
                region=region,
                cloud_provider=CloudProvider.GCP,
            )
        ]

    if not instances:
        return [
            Finding(
                check_id="gcp-sql-require-ssl",
                title="No Cloud SQL instances found",
                description="No Cloud SQL instances exist — SSL check not applicable.",
                severity=Severity.INFO,
                status=ComplianceStatus.NOT_APPLICABLE,
                domain=CheckDomain.ENCRYPTION,
                resource_type="GCP::SQL::Instance",
                resource_id=f"projects/{project_id}/instances",
                region=region,
                account_id=project_id,
                cloud_provider=CloudProvider.GCP,
                soc2_controls=["CC6.7"],
                cis_gcp_controls=["6.3"],
            )
        ]

    offenders: list[dict[str, str]] = []
    for inst in instances:
        settings = inst.get("settings", {})
        ip_config = settings.get("ipConfiguration", {})
        if not ip_config.get("requireSsl", False):
            offenders.append(
                {
                    "instance": inst.get("name", ""),
                    "region": inst.get("region", ""),
                    "database_version": inst.get("databaseVersion", ""),
                }
            )

    if not offenders:
        return [
            Finding(
                check_id="gcp-sql-require-ssl",
                title=f"All {len(instances)} Cloud SQL instance(s) require SSL",
                description="SSL is enforced on all Cloud SQL instances.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.ENCRYPTION,
                resource_type="GCP::SQL::Instance",
                resource_id=f"projects/{project_id}/instances",
                region=region,
                account_id=project_id,
                cloud_provider=CloudProvider.GCP,
                soc2_controls=["CC6.7"],
                cis_gcp_controls=["6.3"],
            )
        ]

    return [
        Finding(
            check_id="gcp-sql-require-ssl",
            title=f"{len(offenders)} Cloud SQL instance(s) do not require SSL",
            description=(
                f"{len(offenders)} Cloud SQL instance(s) allow non-SSL connections: "
                + ", ".join(o["instance"] for o in offenders[:5])
                + (f" and {len(offenders) - 5} more" if len(offenders) > 5 else "")
                + ". This allows database credentials and query results to be captured in transit."
            ),
            severity=Severity.HIGH,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.ENCRYPTION,
            resource_type="GCP::SQL::Instance",
            resource_id=f"projects/{project_id}/instances",
            region=region,
            account_id=project_id,
            cloud_provider=CloudProvider.GCP,
            remediation=(
                "Enable SSL requirement: `gcloud sql instances patch INSTANCE_NAME "
                "--require-ssl --project=PROJECT_ID`. "
                "Also create client SSL certificates and update application connection strings."
            ),
            soc2_controls=["CC6.7"],
            cis_gcp_controls=["6.3"],
            iso27001_controls=["A.8.24"],
            hipaa_controls=["164.312(e)(1)"],
            details={"instances_without_ssl": offenders[:20]},
        )
    ]


def check_sql_no_public_ip(
    client: GCPClient, project_id: str
) -> list[Finding]:
    """[CIS 6.2] Cloud SQL instances should not have a public IP address.

    A public IP makes the database endpoint directly reachable from the internet.
    Use Private IP with VPC Service Controls or Cloud SQL Auth Proxy instead.
    """
    region = "global"
    try:
        sqladmin = client.service("sqladmin", "v1beta4")
        response = sqladmin.instances().list(project=project_id).execute()
        instances = response.get("items", [])
    except Exception as e:
        return [
            Finding.not_assessed(
                check_id="gcp-sql-no-public-ip",
                title="Unable to list Cloud SQL instances for public IP check",
                description=f"API call failed: {e}",
                domain=CheckDomain.ENCRYPTION,
                resource_type="GCP::SQL::Instance",
                account_id=project_id,
                region=region,
                cloud_provider=CloudProvider.GCP,
            )
        ]

    if not instances:
        return []

    offenders: list[dict[str, str]] = []
    for inst in instances:
        ip_addresses = inst.get("ipAddresses", [])
        public_ips = [ip for ip in ip_addresses if ip.get("type") == "PRIMARY"]
        if public_ips:
            offenders.append(
                {
                    "instance": inst.get("name", ""),
                    "public_ip": public_ips[0].get("ipAddress", ""),
                    "region": inst.get("region", ""),
                }
            )

    if not offenders:
        return [
            Finding(
                check_id="gcp-sql-no-public-ip",
                title=f"All {len(instances)} Cloud SQL instance(s) use private IP only",
                description="No Cloud SQL instances have a public IP address.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.ENCRYPTION,
                resource_type="GCP::SQL::Instance",
                resource_id=f"projects/{project_id}/instances",
                region=region,
                account_id=project_id,
                cloud_provider=CloudProvider.GCP,
                soc2_controls=["CC6.6"],
                cis_gcp_controls=["6.2"],
            )
        ]

    return [
        Finding(
            check_id="gcp-sql-no-public-ip",
            title=f"{len(offenders)} Cloud SQL instance(s) have a public IP",
            description=(
                f"{len(offenders)} Cloud SQL instance(s) have a public IP address: "
                + ", ".join(o["instance"] for o in offenders[:5])
                + ". Public IPs make the database endpoint reachable from the internet."
            ),
            severity=Severity.HIGH,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.ENCRYPTION,
            resource_type="GCP::SQL::Instance",
            resource_id=f"projects/{project_id}/instances",
            region=region,
            account_id=project_id,
            cloud_provider=CloudProvider.GCP,
            remediation=(
                "Migrate to Private IP: `gcloud sql instances patch INSTANCE_NAME "
                "--no-assign-ip --network=VPC_NETWORK --project=PROJECT_ID`. "
                "Use Cloud SQL Auth Proxy for secure connections from application code."
            ),
            soc2_controls=["CC6.6"],
            cis_gcp_controls=["6.2"],
            iso27001_controls=["A.8.20"],
            details={"instances_with_public_ip": offenders[:20]},
        )
    ]


def check_sql_data_backup_enabled(
    client: GCPClient, project_id: str
) -> list[Finding]:
    """[CIS 6.7] Cloud SQL instances should have automated backups enabled.

    Automated backups are a last resort recovery mechanism. Without them, data
    loss from accidental deletion, corruption, or a ransom attack is unrecoverable.
    """
    region = "global"
    try:
        sqladmin = client.service("sqladmin", "v1beta4")
        response = sqladmin.instances().list(project=project_id).execute()
        instances = response.get("items", [])
    except Exception as e:
        return [
            Finding.not_assessed(
                check_id="gcp-sql-backups",
                title="Unable to list Cloud SQL instances for backup check",
                description=f"API call failed: {e}",
                domain=CheckDomain.ENCRYPTION,
                resource_type="GCP::SQL::Instance",
                account_id=project_id,
                region=region,
                cloud_provider=CloudProvider.GCP,
            )
        ]

    if not instances:
        return []

    missing: list[dict[str, str]] = []
    for inst in instances:
        settings = inst.get("settings", {})
        backup_config = settings.get("backupConfiguration", {})
        if not backup_config.get("enabled", False):
            missing.append(
                {
                    "instance": inst.get("name", ""),
                    "region": inst.get("region", ""),
                }
            )

    if not missing:
        return [
            Finding(
                check_id="gcp-sql-backups",
                title=f"All {len(instances)} Cloud SQL instance(s) have automated backups",
                description="Automated backups are enabled on all Cloud SQL instances.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.ENCRYPTION,
                resource_type="GCP::SQL::Instance",
                resource_id=f"projects/{project_id}/instances",
                region=region,
                account_id=project_id,
                cloud_provider=CloudProvider.GCP,
                soc2_controls=["CC6.7"],
                cis_gcp_controls=["6.7"],
            )
        ]

    return [
        Finding(
            check_id="gcp-sql-backups",
            title=f"{len(missing)} Cloud SQL instance(s) have automated backups disabled",
            description=(
                f"{len(missing)} Cloud SQL instance(s) do not have automated backups: "
                + ", ".join(m["instance"] for m in missing[:5])
                + ". Without backups, data loss from corruption or accidental deletion is permanent."
            ),
            severity=Severity.HIGH,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.ENCRYPTION,
            resource_type="GCP::SQL::Instance",
            resource_id=f"projects/{project_id}/instances",
            region=region,
            account_id=project_id,
            cloud_provider=CloudProvider.GCP,
            remediation=(
                "Enable backups: `gcloud sql instances patch INSTANCE_NAME "
                "--backup-start-time=HH:MM --project=PROJECT_ID`. "
                "Also enable point-in-time recovery for MySQL/PostgreSQL instances."
            ),
            soc2_controls=["CC6.7"],
            cis_gcp_controls=["6.7"],
            hipaa_controls=["164.308(a)(7)"],
            details={"instances_without_backups": missing[:20]},
        )
    ]


def check_bigquery_no_public_access(
    client: GCPClient, project_id: str
) -> list[Finding]:
    """[CIS 7.1] BigQuery datasets should not be publicly accessible.

    Public datasets expose all tables within them to the internet, bypassing
    any row-level security or table-level IAM policies.
    """
    region = "global"
    try:
        bq = client.service("bigquery", "v2")
        response = bq.datasets().list(projectId=project_id, all=False).execute()
        datasets = response.get("datasets", [])
    except Exception as e:
        return [
            Finding.not_assessed(
                check_id="gcp-bigquery-public-access",
                title="Unable to list BigQuery datasets",
                description=f"API call failed: {e}",
                domain=CheckDomain.ENCRYPTION,
                resource_type="GCP::BigQuery::Dataset",
                account_id=project_id,
                region=region,
                cloud_provider=CloudProvider.GCP,
            )
        ]

    if not datasets:
        return [
            Finding(
                check_id="gcp-bigquery-public-access",
                title="No BigQuery datasets found in project",
                description="No BigQuery datasets exist — public access check not applicable.",
                severity=Severity.INFO,
                status=ComplianceStatus.NOT_APPLICABLE,
                domain=CheckDomain.ENCRYPTION,
                resource_type="GCP::BigQuery::Dataset",
                resource_id=f"projects/{project_id}/datasets",
                region=region,
                account_id=project_id,
                cloud_provider=CloudProvider.GCP,
                soc2_controls=["CC6.7"],
                cis_gcp_controls=["7.1"],
            )
        ]

    public_datasets: list[dict[str, str]] = []
    for ds_ref in datasets:
        dataset_id = ds_ref.get("datasetReference", {}).get("datasetId", "")
        try:
            dataset = (
                bq.datasets()
                .get(projectId=project_id, datasetId=dataset_id)
                .execute()
            )
            for entry in dataset.get("access", []):
                special = entry.get("specialGroup", "")
                if special in ("allUsers", "allAuthenticatedUsers"):
                    public_datasets.append(
                        {"dataset": dataset_id, "special_group": special}
                    )
                    break
        except Exception:
            continue

    if not public_datasets:
        return [
            Finding(
                check_id="gcp-bigquery-public-access",
                title=f"All {len(datasets)} BigQuery dataset(s) are not publicly accessible",
                description="No BigQuery datasets grant access to allUsers or allAuthenticatedUsers.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.ENCRYPTION,
                resource_type="GCP::BigQuery::Dataset",
                resource_id=f"projects/{project_id}/datasets",
                region=region,
                account_id=project_id,
                cloud_provider=CloudProvider.GCP,
                soc2_controls=["CC6.7"],
                cis_gcp_controls=["7.1"],
            )
        ]

    return [
        Finding(
            check_id="gcp-bigquery-public-access",
            title=f"{len(public_datasets)} BigQuery dataset(s) are publicly accessible",
            description=(
                f"{len(public_datasets)} BigQuery dataset(s) grant access to allUsers or "
                "allAuthenticatedUsers, exposing all tables within those datasets to the internet."
            ),
            severity=Severity.CRITICAL,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.ENCRYPTION,
            resource_type="GCP::BigQuery::Dataset",
            resource_id=f"projects/{project_id}/datasets",
            region=region,
            account_id=project_id,
            cloud_provider=CloudProvider.GCP,
            remediation=(
                "Remove public access via Console (BigQuery > dataset > Sharing > Permissions) "
                "or: `bq update --dataset PROJECT_ID:DATASET_ID` after patching the JSON policy "
                "to remove allUsers/allAuthenticatedUsers entries."
            ),
            soc2_controls=["CC6.7"],
            cis_gcp_controls=["7.1"],
            iso27001_controls=["A.8.3"],
            details={"public_datasets": public_datasets},
        )
    ]


def check_bigquery_cmek_configured(
    client: GCPClient, project_id: str
) -> list[Finding]:
    """[CIS 7.2] BigQuery datasets with sensitive data should use Customer-Managed Encryption Keys.

    By default BigQuery uses Google-managed keys. CMEK gives you control over key
    lifecycle, rotation, and the ability to disable access to all data in the dataset
    by disabling/destroying the KMS key.
    """
    region = "global"
    try:
        bq = client.service("bigquery", "v2")
        response = bq.datasets().list(projectId=project_id, all=False).execute()
        datasets = response.get("datasets", [])
    except Exception as e:
        return [
            Finding.not_assessed(
                check_id="gcp-bigquery-cmek",
                title="Unable to list BigQuery datasets for CMEK check",
                description=f"API call failed: {e}",
                domain=CheckDomain.ENCRYPTION,
                resource_type="GCP::BigQuery::Dataset",
                account_id=project_id,
                region=region,
                cloud_provider=CloudProvider.GCP,
            )
        ]

    if not datasets:
        return []

    missing_cmek: list[str] = []
    for ds_ref in datasets:
        dataset_id = ds_ref.get("datasetReference", {}).get("datasetId", "")
        try:
            dataset = (
                bq.datasets()
                .get(projectId=project_id, datasetId=dataset_id)
                .execute()
            )
            # defaultEncryptionConfiguration is only set when CMEK is configured
            if not dataset.get("defaultEncryptionConfiguration", {}).get("kmsKeyName"):
                missing_cmek.append(dataset_id)
        except Exception:
            continue

    if not missing_cmek:
        return [
            Finding(
                check_id="gcp-bigquery-cmek",
                title=f"All {len(datasets)} BigQuery dataset(s) use CMEK",
                description="Customer-managed encryption keys are configured on all BigQuery datasets.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.ENCRYPTION,
                resource_type="GCP::BigQuery::Dataset",
                resource_id=f"projects/{project_id}/datasets",
                region=region,
                account_id=project_id,
                cloud_provider=CloudProvider.GCP,
                soc2_controls=["CC6.7"],
                cis_gcp_controls=["7.2"],
            )
        ]

    return [
        Finding(
            check_id="gcp-bigquery-cmek",
            title=f"{len(missing_cmek)} BigQuery dataset(s) use Google-managed encryption (not CMEK)",
            description=(
                f"{len(missing_cmek)} BigQuery dataset(s) do not use Customer-Managed Encryption "
                "Keys. For datasets containing sensitive or regulated data, CMEK gives you "
                "direct control over key lifecycle and cryptographic access."
            ),
            severity=Severity.LOW,
            status=ComplianceStatus.PARTIAL,
            domain=CheckDomain.ENCRYPTION,
            resource_type="GCP::BigQuery::Dataset",
            resource_id=f"projects/{project_id}/datasets",
            region=region,
            account_id=project_id,
            cloud_provider=CloudProvider.GCP,
            remediation=(
                "New datasets can be configured with CMEK at creation time. For existing datasets, "
                "create a new dataset with CMEK configured, copy data with `bq cp`, and delete the "
                "old dataset. The KMS key must be in the same region as the dataset."
            ),
            soc2_controls=["CC6.7"],
            cis_gcp_controls=["7.2"],
            iso27001_controls=["A.8.24"],
            details={"datasets_without_cmek": missing_cmek[:20]},
        )
    ]
