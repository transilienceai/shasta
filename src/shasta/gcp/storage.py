"""GCP Cloud Storage (GCS) security checks for SOC 2 and CIS GCP Benchmark v2.0.

Covers:
  CC6.7 — Data protection at rest and in transit (bucket access, encryption)

CIS GCP v2.0 Section 5 (Cloud Storage).
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

IS_GLOBAL = True  # GCS buckets are listed project-wide (not per-region)


def run_all_gcp_storage_checks(client: GCPClient) -> list[Finding]:
    """Run all GCP Cloud Storage compliance checks."""
    project_id = client.project_id if client.account_info else (client._project_id or "unknown")

    findings: list[Finding] = []
    findings.extend(check_bucket_no_public_access(client, project_id))
    findings.extend(check_bucket_uniform_access_enabled(client, project_id))
    findings.extend(check_bucket_versioning_enabled(client, project_id))
    findings.extend(check_bucket_access_logging_enabled(client, project_id))
    findings.extend(check_bucket_retention_policy(client, project_id))

    return findings


def _list_buckets(client: GCPClient, project_id: str) -> list[Any]:
    """Return all GCS buckets in the project, or raise on error."""
    storage = client.storage_client()
    return list(storage.list_buckets(project=project_id))


def check_bucket_no_public_access(client: GCPClient, project_id: str) -> list[Finding]:
    """[CIS 5.1] GCS buckets should not allow allUsers or allAuthenticatedUsers.

    Public buckets expose all objects to the internet. Even buckets without sensitive
    data should not be public unless you are explicitly serving public content from them,
    because they become attack vectors for storing malicious content.
    """
    region = "global"
    try:
        buckets = _list_buckets(client, project_id)
    except Exception as e:
        return [
            Finding.not_assessed(
                check_id="gcp-storage-bucket-public-access",
                title="Unable to list GCS buckets",
                description=f"API call failed: {e}",
                domain=CheckDomain.STORAGE,
                resource_type="GCP::Storage::Bucket",
                account_id=project_id,
                region=region,
                cloud_provider=CloudProvider.GCP,
            )
        ]

    if not buckets:
        return [
            Finding(
                check_id="gcp-storage-bucket-public-access",
                title="No GCS buckets found in project",
                description="No Cloud Storage buckets found — check not applicable.",
                severity=Severity.INFO,
                status=ComplianceStatus.NOT_APPLICABLE,
                domain=CheckDomain.STORAGE,
                resource_type="GCP::Storage::Bucket",
                resource_id=f"projects/{project_id}",
                region=region,
                account_id=project_id,
                cloud_provider=CloudProvider.GCP,
                soc2_controls=["CC6.7"],
                cis_gcp_controls=["5.1"],
            )
        ]

    public_buckets: list[dict[str, str]] = []
    access_errors: list[dict[str, str]] = []
    for bucket in buckets:
        try:
            policy = bucket.get_iam_policy(requested_policy_version=3)
            for binding in policy.bindings:
                members = list(binding.get("members", []))
                if "allUsers" in members or "allAuthenticatedUsers" in members:
                    public_buckets.append({"bucket": bucket.name, "role": binding.get("role", "")})
                    break
        except Exception as e:
            access_errors.append({"bucket": getattr(bucket, "name", "unknown"), "error": str(e)})
            continue

    if not public_buckets and not access_errors:
        return [
            Finding(
                check_id="gcp-storage-bucket-public-access",
                title=f"All {len(buckets)} GCS bucket(s) are not publicly accessible",
                description="No GCS buckets grant access to allUsers or allAuthenticatedUsers.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.STORAGE,
                resource_type="GCP::Storage::Bucket",
                resource_id=f"projects/{project_id}",
                region=region,
                account_id=project_id,
                cloud_provider=CloudProvider.GCP,
                soc2_controls=["CC6.7"],
                cis_gcp_controls=["5.1"],
            )
        ]

    findings: list[Finding] = []
    if public_buckets:
        findings.append(
            Finding(
                check_id="gcp-storage-bucket-public-access",
                title=f"{len(public_buckets)} GCS bucket(s) are publicly accessible",
                description=(
                    f"{len(public_buckets)} bucket(s) grant access to allUsers or "
                    "allAuthenticatedUsers. These buckets are readable from the internet."
                ),
                severity=Severity.CRITICAL,
                status=ComplianceStatus.FAIL,
                domain=CheckDomain.STORAGE,
                resource_type="GCP::Storage::Bucket",
                resource_id=f"projects/{project_id}",
                region=region,
                account_id=project_id,
                cloud_provider=CloudProvider.GCP,
                remediation=(
                    "Remove public access: `gcloud storage buckets remove-iam-policy-binding "
                    "gs://BUCKET_NAME --member=allUsers --role=ROLE`. "
                    "Enable 'Public Access Prevention' at the org or project level to block "
                    "future public grants: `gcloud resource-manager org-policies enable-enforce "
                    "constraints/storage.publicAccessPrevention --project=PROJECT_ID`."
                ),
                soc2_controls=["CC6.7"],
                cis_gcp_controls=["5.1"],
                iso27001_controls=["A.8.3"],
                hipaa_controls=["164.312(c)(1)"],
                details={"public_buckets": public_buckets[:20]},
            )
        )
    if access_errors:
        finding = Finding.not_assessed(
            check_id="gcp-storage-bucket-public-access",
            title="Some GCS bucket IAM policies could not be assessed",
            description=(
                f"Unable to read IAM policy for {len(access_errors)} bucket(s). "
                "The scan cannot prove every bucket is non-public."
            ),
            domain=CheckDomain.STORAGE,
            resource_type="GCP::Storage::Bucket",
            account_id=project_id,
            region=region,
            cloud_provider=CloudProvider.GCP,
        )
        finding.details["access_errors"] = access_errors[:20]
        findings.append(finding)
    return findings


def check_bucket_uniform_access_enabled(client: GCPClient, project_id: str) -> list[Finding]:
    """[CIS 5.2] Uniform bucket-level access should be enabled on all GCS buckets.

    When uniform access is disabled, individual objects can have ACLs that override
    the bucket-level IAM policy. This creates a complex permission model that is
    difficult to audit and easy to misconfigure, leaving objects publicly readable
    without the bucket policy showing it.
    """
    region = "global"
    try:
        buckets = _list_buckets(client, project_id)
    except Exception as e:
        return [
            Finding.not_assessed(
                check_id="gcp-storage-uniform-access",
                title="Unable to list GCS buckets for uniform access check",
                description=f"API call failed: {e}",
                domain=CheckDomain.STORAGE,
                resource_type="GCP::Storage::Bucket",
                account_id=project_id,
                region=region,
                cloud_provider=CloudProvider.GCP,
            )
        ]

    if not buckets:
        return []

    missing: list[str] = []
    access_errors: list[dict[str, str]] = []
    for bucket in buckets:
        try:
            iam_config = bucket.iam_configuration
            if not getattr(iam_config, "uniform_bucket_level_access_enabled", False):
                missing.append(bucket.name)
        except Exception as e:
            access_errors.append({"bucket": getattr(bucket, "name", "unknown"), "error": str(e)})
            continue

    if not missing and not access_errors:
        return [
            Finding(
                check_id="gcp-storage-uniform-access",
                title=f"All {len(buckets)} GCS bucket(s) have uniform bucket-level access",
                description="Uniform bucket-level access is enabled on all GCS buckets.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.STORAGE,
                resource_type="GCP::Storage::Bucket",
                resource_id=f"projects/{project_id}",
                region=region,
                account_id=project_id,
                cloud_provider=CloudProvider.GCP,
                soc2_controls=["CC6.7"],
                cis_gcp_controls=["5.2"],
            )
        ]

    findings: list[Finding] = []
    if missing:
        findings.append(
            Finding(
                check_id="gcp-storage-uniform-access",
                title=f"{len(missing)} GCS bucket(s) have ACL-based (non-uniform) access",
                description=(
                    f"{len(missing)} bucket(s) do not have uniform bucket-level access enabled: "
                    f"{', '.join(missing[:10])}{'...' if len(missing) > 10 else ''}. "
                    "Object-level ACLs can bypass bucket IAM policies, making access control "
                    "hard to audit."
                ),
                severity=Severity.MEDIUM,
                status=ComplianceStatus.FAIL,
                domain=CheckDomain.STORAGE,
                resource_type="GCP::Storage::Bucket",
                resource_id=f"projects/{project_id}",
                region=region,
                account_id=project_id,
                cloud_provider=CloudProvider.GCP,
                remediation=(
                    "Enable uniform access: `gcloud storage buckets update gs://BUCKET_NAME "
                    "--uniform-bucket-level-access`. Note: once enabled for 90+ days, this "
                    "cannot be reverted."
                ),
                soc2_controls=["CC6.7"],
                cis_gcp_controls=["5.2"],
                details={"buckets_without_uniform_access": missing},
            )
        )
    if access_errors:
        finding = Finding.not_assessed(
            check_id="gcp-storage-uniform-access",
            title="Some GCS bucket access modes could not be assessed",
            description=(
                f"Unable to read uniform bucket-level access settings for "
                f"{len(access_errors)} bucket(s)."
            ),
            domain=CheckDomain.STORAGE,
            resource_type="GCP::Storage::Bucket",
            account_id=project_id,
            region=region,
            cloud_provider=CloudProvider.GCP,
        )
        finding.details["access_errors"] = access_errors[:20]
        findings.append(finding)
    return findings


def check_bucket_versioning_enabled(client: GCPClient, project_id: str) -> list[Finding]:
    """GCS buckets storing important data should have versioning enabled.

    Versioning protects against accidental or malicious deletion and overwrites.
    Without versioning, a ransomware attack or accidental `gsutil rm` can destroy
    data permanently.
    """
    region = "global"
    try:
        buckets = _list_buckets(client, project_id)
    except Exception as e:
        return [
            Finding.not_assessed(
                check_id="gcp-storage-versioning",
                title="Unable to list GCS buckets for versioning check",
                description=f"API call failed: {e}",
                domain=CheckDomain.STORAGE,
                resource_type="GCP::Storage::Bucket",
                account_id=project_id,
                region=region,
                cloud_provider=CloudProvider.GCP,
            )
        ]

    if not buckets:
        return []

    missing: list[str] = []
    access_errors: list[dict[str, str]] = []
    for bucket in buckets:
        try:
            if not bucket.versioning_enabled:
                missing.append(bucket.name)
        except Exception as e:
            access_errors.append({"bucket": getattr(bucket, "name", "unknown"), "error": str(e)})
            continue

    if not missing and not access_errors:
        return [
            Finding(
                check_id="gcp-storage-versioning",
                title=f"All {len(buckets)} GCS bucket(s) have versioning enabled",
                description="Object versioning is enabled on all GCS buckets.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.STORAGE,
                resource_type="GCP::Storage::Bucket",
                resource_id=f"projects/{project_id}",
                region=region,
                account_id=project_id,
                cloud_provider=CloudProvider.GCP,
                soc2_controls=["CC6.7"],
                cis_gcp_controls=["5.3"],
            )
        ]

    findings: list[Finding] = []
    if missing:
        findings.append(
            Finding(
                check_id="gcp-storage-versioning",
                title=f"{len(missing)} GCS bucket(s) do not have versioning enabled",
                description=(
                    f"{len(missing)} bucket(s) do not have object versioning: "
                    f"{', '.join(missing[:10])}{'...' if len(missing) > 10 else ''}. "
                    "Without versioning, deleted or overwritten objects cannot be recovered."
                ),
                severity=Severity.MEDIUM,
                status=ComplianceStatus.FAIL,
                domain=CheckDomain.STORAGE,
                resource_type="GCP::Storage::Bucket",
                resource_id=f"projects/{project_id}",
                region=region,
                account_id=project_id,
                cloud_provider=CloudProvider.GCP,
                remediation=(
                    "Enable versioning: `gcloud storage buckets update gs://BUCKET_NAME "
                    "--versioning`. Add a lifecycle rule to expire old versions after N days "
                    "to control storage costs."
                ),
                soc2_controls=["CC6.7"],
                cis_gcp_controls=["5.3"],
                details={"buckets_without_versioning": missing},
            )
        )
    if access_errors:
        finding = Finding.not_assessed(
            check_id="gcp-storage-versioning",
            title="Some GCS bucket versioning settings could not be assessed",
            description=f"Unable to read versioning settings for {len(access_errors)} bucket(s).",
            domain=CheckDomain.STORAGE,
            resource_type="GCP::Storage::Bucket",
            account_id=project_id,
            region=region,
            cloud_provider=CloudProvider.GCP,
        )
        finding.details["access_errors"] = access_errors[:20]
        findings.append(finding)
    return findings


def check_bucket_access_logging_enabled(client: GCPClient, project_id: str) -> list[Finding]:
    """GCS buckets should have access logging enabled.

    Access logs record every GET/PUT/DELETE against the bucket, providing an
    audit trail required for SOC 2 CC7.1 and ISO 27001 A.8.15 (logging of events).
    """
    region = "global"
    try:
        buckets = _list_buckets(client, project_id)
    except Exception as e:
        return [
            Finding.not_assessed(
                check_id="gcp-storage-access-logging",
                title="Unable to list GCS buckets for access logging check",
                description=f"API call failed: {e}",
                domain=CheckDomain.STORAGE,
                resource_type="GCP::Storage::Bucket",
                account_id=project_id,
                region=region,
                cloud_provider=CloudProvider.GCP,
            )
        ]

    if not buckets:
        return []

    missing: list[str] = []
    access_errors: list[dict[str, str]] = []
    for bucket in buckets:
        try:
            logging_cfg = (
                bucket.get_logging_config()
                if callable(getattr(bucket, "get_logging_config", None))
                else None
            )
            if not logging_cfg:
                # Fallback: check via reload
                bucket.reload()
                logging_cfg = bucket._properties.get("logging")  # type: ignore[attr-defined]
            if not logging_cfg:
                missing.append(bucket.name)
        except Exception as e:
            access_errors.append({"bucket": getattr(bucket, "name", "unknown"), "error": str(e)})

    if not missing and not access_errors:
        return [
            Finding(
                check_id="gcp-storage-access-logging",
                title=f"All {len(buckets)} GCS bucket(s) have access logging configured",
                description="Access logging is configured on all GCS buckets.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.STORAGE,
                resource_type="GCP::Storage::Bucket",
                resource_id=f"projects/{project_id}",
                region=region,
                account_id=project_id,
                cloud_provider=CloudProvider.GCP,
                soc2_controls=["CC7.1"],
                cis_gcp_controls=["5.4"],
            )
        ]

    findings: list[Finding] = []
    if missing:
        findings.append(
            Finding(
                check_id="gcp-storage-access-logging",
                title=f"{len(missing)} GCS bucket(s) lack access logging",
                description=(
                    f"{len(missing)} bucket(s) do not have access logging enabled: "
                    f"{', '.join(missing[:10])}{'...' if len(missing) > 10 else ''}. "
                    "Without access logs, you cannot audit who accessed, modified, or deleted objects."
                ),
                severity=Severity.MEDIUM,
                status=ComplianceStatus.FAIL,
                domain=CheckDomain.STORAGE,
                resource_type="GCP::Storage::Bucket",
                resource_id=f"projects/{project_id}",
                region=region,
                account_id=project_id,
                cloud_provider=CloudProvider.GCP,
                remediation=(
                    "Enable access logging by pointing the bucket at a dedicated log bucket: "
                    "`gcloud storage buckets update gs://BUCKET_NAME "
                    "--log-bucket=LOG_BUCKET_NAME --log-object-prefix=PREFIX`."
                ),
                soc2_controls=["CC7.1"],
                cis_gcp_controls=["5.4"],
                iso27001_controls=["A.8.15"],
                details={"buckets_without_access_logging": missing},
            )
        )
    if access_errors:
        finding = Finding.not_assessed(
            check_id="gcp-storage-access-logging",
            title="Some GCS bucket access logging settings could not be assessed",
            description=f"Unable to read access logging settings for {len(access_errors)} bucket(s).",
            domain=CheckDomain.STORAGE,
            resource_type="GCP::Storage::Bucket",
            account_id=project_id,
            region=region,
            cloud_provider=CloudProvider.GCP,
        )
        finding.details["access_errors"] = access_errors[:20]
        findings.append(finding)
    return findings


def check_bucket_retention_policy(client: GCPClient, project_id: str) -> list[Finding]:
    """GCS buckets that store audit logs or compliance data should have a retention policy.

    A retention policy prevents objects from being deleted or overwritten before a
    minimum retention period expires. A locked retention policy makes this immutable —
    not even a storage admin can delete objects before the policy expires.
    """
    region = "global"
    try:
        buckets = _list_buckets(client, project_id)
    except Exception as e:
        return [
            Finding.not_assessed(
                check_id="gcp-storage-retention-policy",
                title="Unable to list GCS buckets for retention policy check",
                description=f"API call failed: {e}",
                domain=CheckDomain.STORAGE,
                resource_type="GCP::Storage::Bucket",
                account_id=project_id,
                region=region,
                cloud_provider=CloudProvider.GCP,
            )
        ]

    if not buckets:
        return []

    missing: list[str] = []
    access_errors: list[dict[str, str]] = []
    for bucket in buckets:
        try:
            retention = bucket.retention_policy
            if not retention or not getattr(retention, "retention_period", None):
                missing.append(bucket.name)
        except Exception as e:
            access_errors.append({"bucket": getattr(bucket, "name", "unknown"), "error": str(e)})

    if not missing and not access_errors:
        return [
            Finding(
                check_id="gcp-storage-retention-policy",
                title=f"All {len(buckets)} GCS bucket(s) have a retention policy set",
                description="Retention policies are configured on all GCS buckets.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.STORAGE,
                resource_type="GCP::Storage::Bucket",
                resource_id=f"projects/{project_id}",
                region=region,
                account_id=project_id,
                cloud_provider=CloudProvider.GCP,
                soc2_controls=["CC6.7", "CC7.1"],
                cis_gcp_controls=["5.5"],
            )
        ]

    findings: list[Finding] = []
    if missing:
        findings.append(
            Finding(
                check_id="gcp-storage-retention-policy",
                title=f"{len(missing)} GCS bucket(s) have no retention policy",
                description=(
                    f"{len(missing)} bucket(s) lack a retention policy: "
                    f"{', '.join(missing[:10])}{'...' if len(missing) > 10 else ''}. "
                    "Buckets storing audit logs or compliance artifacts should have a minimum "
                    "retention period to prevent premature deletion."
                ),
                severity=Severity.LOW,
                status=ComplianceStatus.PARTIAL,
                domain=CheckDomain.STORAGE,
                resource_type="GCP::Storage::Bucket",
                resource_id=f"projects/{project_id}",
                region=region,
                account_id=project_id,
                cloud_provider=CloudProvider.GCP,
                remediation=(
                    "Set a retention policy: `gcloud storage buckets update gs://BUCKET_NAME "
                    "--retention-period=2678400s` (31 days). For audit log buckets, use a "
                    "longer period (e.g., 365 days) and consider locking the policy."
                ),
                soc2_controls=["CC6.7", "CC7.1"],
                cis_gcp_controls=["5.5"],
                details={"buckets_without_retention": missing},
            )
        )
    if access_errors:
        finding = Finding.not_assessed(
            check_id="gcp-storage-retention-policy",
            title="Some GCS bucket retention policies could not be assessed",
            description=f"Unable to read retention policy settings for {len(access_errors)} bucket(s).",
            domain=CheckDomain.STORAGE,
            resource_type="GCP::Storage::Bucket",
            account_id=project_id,
            region=region,
            cloud_provider=CloudProvider.GCP,
        )
        finding.details["access_errors"] = access_errors[:20]
        findings.append(finding)
    return findings
