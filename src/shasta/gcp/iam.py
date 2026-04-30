"""GCP IAM security checks for SOC 2 and CIS GCP Benchmark v2.0.

Covers:
  CC6.1 — Logical access security (MFA, admin privileges, service accounts)
  CC6.2 — Access provisioning (least privilege, primitive roles)
  CC6.3 — Access removal (stale SA keys, unused accounts)

CIS GCP v2.0 Section 1 (Identity and Access Management).
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta
from typing import Any

from shasta.gcp.client import GCPClient
from shasta.evidence.models import (
    CheckDomain,
    CloudProvider,
    ComplianceStatus,
    Finding,
    Severity,
)

IS_GLOBAL = True  # IAM is project-level — no per-region iteration

SA_KEY_MAX_AGE_DAYS = 90

# Primitive roles that should never be assigned at the project level for users
PRIMITIVE_ROLES = {"roles/owner", "roles/editor"}

# Roles that should not be granted to service accounts at project level
SA_ADMIN_ROLES = {"roles/owner", "roles/editor", "roles/iam.serviceAccountAdmin"}


def run_all_gcp_iam_checks(client: GCPClient) -> list[Finding]:
    """Run all GCP IAM compliance checks and return findings."""
    project_id = client.project_id if client.account_info else (client._project_id or "unknown")
    region = client.account_info.region if client.account_info else _DEFAULT_REGION

    findings: list[Finding] = []
    findings.extend(check_service_account_key_rotation(client, project_id, region))
    findings.extend(check_service_account_not_admin(client, project_id, region))
    findings.extend(check_primitive_roles_not_used(client, project_id, region))
    findings.extend(check_iam_no_allusers_access(client, project_id, region))
    findings.extend(check_iam_service_account_token_creator(client, project_id, region))
    findings.extend(check_iam_workload_identity_preferred(client, project_id, region))

    return findings


_DEFAULT_REGION = "global"


def check_service_account_key_rotation(
    client: GCPClient, project_id: str, region: str
) -> list[Finding]:
    """[CIS 1.4] User-managed service account keys should not be older than 90 days.

    Keys that are never rotated become long-lived credentials — if leaked they
    remain valid indefinitely. Enforcing rotation bounds the window of exposure.
    """
    try:
        iam = client.service("iam", "v1")
        sa_response = (
            iam.projects()
            .serviceAccounts()
            .list(name=f"projects/{project_id}")
            .execute()
        )
        accounts = sa_response.get("accounts", [])
    except Exception as e:
        return [
            Finding.not_assessed(
                check_id="gcp-iam-sa-key-rotation",
                title="Unable to list service accounts",
                description=f"API call failed: {e}",
                domain=CheckDomain.IAM,
                resource_type="GCP::IAM::ServiceAccount",
                account_id=project_id,
                region=region,
                cloud_provider=CloudProvider.GCP,
            )
        ]

    if not accounts:
        return [
            Finding(
                check_id="gcp-iam-sa-key-rotation",
                title="No service accounts found in project",
                description="No service accounts exist — no key rotation check required.",
                severity=Severity.INFO,
                status=ComplianceStatus.NOT_APPLICABLE,
                domain=CheckDomain.IAM,
                resource_type="GCP::IAM::ServiceAccount",
                resource_id=f"projects/{project_id}/serviceAccounts",
                region=region,
                account_id=project_id,
                cloud_provider=CloudProvider.GCP,
                soc2_controls=["CC6.3"],
                cis_gcp_controls=["1.4"],
            )
        ]

    now = datetime.now(timezone.utc)
    threshold = now - timedelta(days=SA_KEY_MAX_AGE_DAYS)
    stale: list[dict[str, Any]] = []
    findings: list[Finding] = []

    for sa in accounts:
        sa_email = sa.get("email", "")
        sa_name = sa.get("name", "")
        # Skip Google-managed service accounts (default SAs)
        if sa_email.endswith(".gserviceaccount.com") and "iam.gserviceaccount.com" not in sa_email:
            continue

        try:
            keys_resp = (
                iam.projects()
                .serviceAccounts()
                .keys()
                .list(name=sa_name, keyTypes=["USER_MANAGED"])
                .execute()
            )
            keys = keys_resp.get("keys", [])
        except Exception:
            continue

        for key in keys:
            created_str = key.get("validAfterTime", "")
            if not created_str:
                continue
            try:
                created = datetime.fromisoformat(created_str.replace("Z", "+00:00"))
            except (ValueError, TypeError):
                continue

            age_days = (now - created).days
            if created < threshold:
                stale.append(
                    {
                        "sa_email": sa_email,
                        "key_name": key.get("name", ""),
                        "age_days": age_days,
                        "created": created_str,
                    }
                )

    if not stale:
        return [
            Finding(
                check_id="gcp-iam-sa-key-rotation",
                title=f"All user-managed SA keys are ≤{SA_KEY_MAX_AGE_DAYS} days old",
                description=f"No stale user-managed service account keys found across {len(accounts)} accounts.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.IAM,
                resource_type="GCP::IAM::ServiceAccountKey",
                resource_id=f"projects/{project_id}/serviceAccounts",
                region=region,
                account_id=project_id,
                cloud_provider=CloudProvider.GCP,
                soc2_controls=["CC6.3"],
                cis_gcp_controls=["1.4"],
            )
        ]

    return [
        Finding(
            check_id="gcp-iam-sa-key-rotation",
            title=f"{len(stale)} user-managed SA key(s) are >{SA_KEY_MAX_AGE_DAYS} days old",
            description=(
                f"{len(stale)} user-managed service account key(s) have not been rotated within "
                f"{SA_KEY_MAX_AGE_DAYS} days. Long-lived keys expand the breach window if stolen. "
                "Prefer Workload Identity Federation over SA keys for GCE/GKE workloads."
            ),
            severity=Severity.HIGH,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.IAM,
            resource_type="GCP::IAM::ServiceAccountKey",
            resource_id=f"projects/{project_id}/serviceAccounts",
            region=region,
            account_id=project_id,
            cloud_provider=CloudProvider.GCP,
            remediation=(
                "Rotate or delete stale keys: "
                "`gcloud iam service-accounts keys delete KEY_ID --iam-account=SA_EMAIL`. "
                "For GCE/GKE workloads, migrate to Workload Identity Federation to eliminate "
                "key management entirely."
            ),
            soc2_controls=["CC6.3"],
            cis_gcp_controls=["1.4"],
            iso27001_controls=["A.8.3"],
            details={"stale_keys": stale[:20]},
        )
    ]


def check_service_account_not_admin(
    client: GCPClient, project_id: str, region: str
) -> list[Finding]:
    """[CIS 1.5] Service accounts should not have admin-level roles at project scope.

    Assigning Owner, Editor, or ServiceAccountAdmin to a service account
    creates an escalation path: any compromised workload using that SA
    can pivot to full project control.
    """
    try:
        crm = client.service("cloudresourcemanager", "v1")
        policy = crm.projects().getIamPolicy(resource=project_id, body={}).execute()
        bindings = policy.get("bindings", [])
    except Exception as e:
        return [
            Finding.not_assessed(
                check_id="gcp-iam-sa-not-admin",
                title="Unable to read project IAM policy",
                description=f"API call failed: {e}",
                domain=CheckDomain.IAM,
                resource_type="GCP::IAM::Policy",
                account_id=project_id,
                region=region,
                cloud_provider=CloudProvider.GCP,
            )
        ]

    offenders: list[dict[str, str]] = []
    for binding in bindings:
        role = binding.get("role", "")
        if role not in SA_ADMIN_ROLES:
            continue
        for member in binding.get("members", []):
            if member.startswith("serviceAccount:"):
                offenders.append({"member": member, "role": role})

    if not offenders:
        return [
            Finding(
                check_id="gcp-iam-sa-not-admin",
                title="No service accounts with admin roles at project scope",
                description="No service accounts hold Owner, Editor, or ServiceAccountAdmin at the project level.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.IAM,
                resource_type="GCP::IAM::Policy",
                resource_id=f"projects/{project_id}",
                region=region,
                account_id=project_id,
                cloud_provider=CloudProvider.GCP,
                soc2_controls=["CC6.1", "CC6.2"],
                cis_gcp_controls=["1.5"],
            )
        ]

    return [
        Finding(
            check_id="gcp-iam-sa-not-admin",
            title=f"{len(offenders)} service account(s) hold admin roles at project scope",
            description=(
                f"{len(offenders)} service account binding(s) grant Owner, Editor, or "
                "ServiceAccountAdmin at the project level. If any workload using these SAs is "
                "compromised, an attacker gains full project control."
            ),
            severity=Severity.HIGH,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.IAM,
            resource_type="GCP::IAM::Policy",
            resource_id=f"projects/{project_id}",
            region=region,
            account_id=project_id,
            cloud_provider=CloudProvider.GCP,
            remediation=(
                "Replace broad roles with purpose-built predefined roles "
                "(e.g., `roles/storage.objectCreator` instead of `roles/editor`). "
                "Use `gcloud projects remove-iam-policy-binding PROJECT_ID "
                "--member=serviceAccount:SA_EMAIL --role=roles/editor`."
            ),
            soc2_controls=["CC6.1", "CC6.2"],
            cis_gcp_controls=["1.5"],
            iso27001_controls=["A.5.15", "A.8.2"],
            details={"offenders": offenders[:20]},
        )
    ]


def check_primitive_roles_not_used(
    client: GCPClient, project_id: str, region: str
) -> list[Finding]:
    """[CIS 1.1] Primitive roles (owner/editor/viewer) should not be used for users.

    Primitive roles pre-date IAM and grant permissions across ALL GCP services.
    They violate least privilege and make access reviews nearly impossible because
    the exact permissions implied by 'Editor' span thousands of API methods.
    """
    try:
        crm = client.service("cloudresourcemanager", "v1")
        policy = crm.projects().getIamPolicy(resource=project_id, body={}).execute()
        bindings = policy.get("bindings", [])
    except Exception as e:
        return [
            Finding.not_assessed(
                check_id="gcp-iam-primitive-roles",
                title="Unable to read project IAM policy",
                description=f"API call failed: {e}",
                domain=CheckDomain.IAM,
                resource_type="GCP::IAM::Policy",
                account_id=project_id,
                region=region,
                cloud_provider=CloudProvider.GCP,
            )
        ]

    offenders: list[dict[str, str]] = []
    for binding in bindings:
        role = binding.get("role", "")
        if role not in PRIMITIVE_ROLES:
            continue
        for member in binding.get("members", []):
            # Exclude service accounts and groups — focus on human users and allUsers
            if member.startswith(("user:", "allUsers", "allAuthenticatedUsers")):
                offenders.append({"member": member, "role": role})

    if not offenders:
        return [
            Finding(
                check_id="gcp-iam-primitive-roles",
                title="No users have primitive Owner/Editor roles at project scope",
                description="Human user accounts do not hold primitive Owner or Editor roles at the project level.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.IAM,
                resource_type="GCP::IAM::Policy",
                resource_id=f"projects/{project_id}",
                region=region,
                account_id=project_id,
                cloud_provider=CloudProvider.GCP,
                soc2_controls=["CC6.1", "CC6.2"],
                cis_gcp_controls=["1.1"],
            )
        ]

    return [
        Finding(
            check_id="gcp-iam-primitive-roles",
            title=f"{len(offenders)} user(s) hold primitive Owner/Editor roles",
            description=(
                f"{len(offenders)} user binding(s) use primitive Owner or Editor roles. "
                "Primitive roles grant permissions across ALL GCP services, violating the "
                "principle of least privilege. Use purpose-specific predefined or custom roles."
            ),
            severity=Severity.HIGH,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.IAM,
            resource_type="GCP::IAM::Policy",
            resource_id=f"projects/{project_id}",
            region=region,
            account_id=project_id,
            cloud_provider=CloudProvider.GCP,
            remediation=(
                "Replace primitive roles with predefined roles scoped to the services each user "
                "actually needs. Use `gcloud projects get-iam-policy PROJECT_ID` to audit, then "
                "`gcloud projects remove-iam-policy-binding` to remove and add scoped replacements."
            ),
            soc2_controls=["CC6.1", "CC6.2"],
            cis_gcp_controls=["1.1"],
            iso27001_controls=["A.5.15"],
            details={"offenders": offenders[:20]},
        )
    ]


def check_iam_no_allusers_access(
    client: GCPClient, project_id: str, region: str
) -> list[Finding]:
    """[CIS 1.2] allUsers and allAuthenticatedUsers should not appear in IAM policies.

    These special members grant access to the public internet. A project-level
    binding to allUsers is almost never intentional and exposes all resources
    in the project to unauthenticated traffic.
    """
    try:
        crm = client.service("cloudresourcemanager", "v1")
        policy = crm.projects().getIamPolicy(resource=project_id, body={}).execute()
        bindings = policy.get("bindings", [])
    except Exception as e:
        return [
            Finding.not_assessed(
                check_id="gcp-iam-no-allusers",
                title="Unable to read project IAM policy",
                description=f"API call failed: {e}",
                domain=CheckDomain.IAM,
                resource_type="GCP::IAM::Policy",
                account_id=project_id,
                region=region,
                cloud_provider=CloudProvider.GCP,
            )
        ]

    public_bindings: list[dict[str, str]] = []
    for binding in bindings:
        role = binding.get("role", "")
        for member in binding.get("members", []):
            if member in ("allUsers", "allAuthenticatedUsers"):
                public_bindings.append({"member": member, "role": role})

    if not public_bindings:
        return [
            Finding(
                check_id="gcp-iam-no-allusers",
                title="No public (allUsers/allAuthenticatedUsers) IAM bindings at project level",
                description="The project IAM policy does not grant access to allUsers or allAuthenticatedUsers.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.IAM,
                resource_type="GCP::IAM::Policy",
                resource_id=f"projects/{project_id}",
                region=region,
                account_id=project_id,
                cloud_provider=CloudProvider.GCP,
                soc2_controls=["CC6.1"],
                cis_gcp_controls=["1.2"],
            )
        ]

    return [
        Finding(
            check_id="gcp-iam-no-allusers",
            title=f"{len(public_bindings)} public IAM binding(s) found at project level",
            description=(
                f"{len(public_bindings)} IAM binding(s) grant access to allUsers or "
                "allAuthenticatedUsers at the project level. This exposes all resources in the "
                "project to unauthenticated or any-authenticated traffic on the internet."
            ),
            severity=Severity.CRITICAL,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.IAM,
            resource_type="GCP::IAM::Policy",
            resource_id=f"projects/{project_id}",
            region=region,
            account_id=project_id,
            cloud_provider=CloudProvider.GCP,
            remediation=(
                "Remove public bindings immediately: "
                "`gcloud projects remove-iam-policy-binding PROJECT_ID "
                "--member=allUsers --role=ROLE`. Audit whether any individual resource "
                "(GCS bucket, Cloud Run service) legitimately needs public access and scope "
                "the permission there instead of at the project level."
            ),
            soc2_controls=["CC6.1", "CC6.6"],
            cis_gcp_controls=["1.2"],
            iso27001_controls=["A.5.15", "A.8.3"],
            details={"public_bindings": public_bindings},
        )
    ]


def check_iam_service_account_token_creator(
    client: GCPClient, project_id: str, region: str
) -> list[Finding]:
    """[CIS 1.6] Service Account Token Creator / Account User roles create impersonation chains.

    Granting roles/iam.serviceAccountTokenCreator to a broad principal lets that
    principal impersonate any service account in the project, effectively granting
    the combined permissions of all SAs. The role should exist only in tightly
    scoped resource-level bindings, not at the project level.
    """
    IMPERSONATION_ROLES = {
        "roles/iam.serviceAccountTokenCreator",
        "roles/iam.serviceAccountUser",
    }

    try:
        crm = client.service("cloudresourcemanager", "v1")
        policy = crm.projects().getIamPolicy(resource=project_id, body={}).execute()
        bindings = policy.get("bindings", [])
    except Exception as e:
        return [
            Finding.not_assessed(
                check_id="gcp-iam-sa-token-creator",
                title="Unable to read project IAM policy",
                description=f"API call failed: {e}",
                domain=CheckDomain.IAM,
                resource_type="GCP::IAM::Policy",
                account_id=project_id,
                region=region,
                cloud_provider=CloudProvider.GCP,
            )
        ]

    offenders: list[dict[str, Any]] = []
    for binding in bindings:
        role = binding.get("role", "")
        if role not in IMPERSONATION_ROLES:
            continue
        members = binding.get("members", [])
        non_sa = [m for m in members if not m.startswith("serviceAccount:")]
        if non_sa:
            offenders.append({"role": role, "members": non_sa})

    if not offenders:
        return [
            Finding(
                check_id="gcp-iam-sa-token-creator",
                title="ServiceAccountTokenCreator/User not assigned to non-SA principals",
                description=(
                    "No user or group accounts hold ServiceAccountTokenCreator or "
                    "ServiceAccountUser at the project level."
                ),
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.IAM,
                resource_type="GCP::IAM::Policy",
                resource_id=f"projects/{project_id}",
                region=region,
                account_id=project_id,
                cloud_provider=CloudProvider.GCP,
                soc2_controls=["CC6.1", "CC6.2"],
                cis_gcp_controls=["1.6"],
            )
        ]

    return [
        Finding(
            check_id="gcp-iam-sa-token-creator",
            title=f"{len(offenders)} broad ServiceAccountTokenCreator/User binding(s) at project level",
            description=(
                f"{len(offenders)} binding(s) grant ServiceAccountTokenCreator or "
                "ServiceAccountUser to non-SA principals at the project level. Any of these "
                "principals can generate tokens for — and impersonate — any service account "
                "in the project."
            ),
            severity=Severity.HIGH,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.IAM,
            resource_type="GCP::IAM::Policy",
            resource_id=f"projects/{project_id}",
            region=region,
            account_id=project_id,
            cloud_provider=CloudProvider.GCP,
            remediation=(
                "Remove project-level TokenCreator/User bindings and re-create them as "
                "resource-level bindings on the specific service accounts that need to be "
                "impersonated. This limits the blast radius to a single SA rather than all "
                "SAs in the project."
            ),
            soc2_controls=["CC6.1", "CC6.2"],
            cis_gcp_controls=["1.6"],
            iso27001_controls=["A.5.15"],
            details={"impersonation_bindings": offenders},
        )
    ]


def check_iam_workload_identity_preferred(
    client: GCPClient, project_id: str, region: str
) -> list[Finding]:
    """[CIS 1.4] Prefer Workload Identity over user-managed service account keys.

    User-managed keys require manual rotation and are a persistent credential that
    can be leaked. Workload Identity Federation eliminates keys entirely for
    workloads running on GCE, GKE, Cloud Run, and external OIDC providers.
    This check is advisory — it flags projects with many user-managed keys as
    candidates for Workload Identity migration.
    """
    try:
        iam = client.service("iam", "v1")
        sa_response = (
            iam.projects()
            .serviceAccounts()
            .list(name=f"projects/{project_id}")
            .execute()
        )
        accounts = sa_response.get("accounts", [])
    except Exception as e:
        return [
            Finding.not_assessed(
                check_id="gcp-iam-workload-identity",
                title="Unable to list service accounts for Workload Identity check",
                description=f"API call failed: {e}",
                domain=CheckDomain.IAM,
                resource_type="GCP::IAM::ServiceAccount",
                account_id=project_id,
                region=region,
                cloud_provider=CloudProvider.GCP,
            )
        ]

    total_user_keys = 0
    sa_with_keys: list[str] = []
    for sa in accounts:
        sa_name = sa.get("name", "")
        try:
            keys_resp = (
                iam.projects()
                .serviceAccounts()
                .keys()
                .list(name=sa_name, keyTypes=["USER_MANAGED"])
                .execute()
            )
            count = len(keys_resp.get("keys", []))
            if count > 0:
                total_user_keys += count
                sa_with_keys.append(sa.get("email", sa_name))
        except Exception:
            continue

    if total_user_keys == 0:
        return [
            Finding(
                check_id="gcp-iam-workload-identity",
                title="No user-managed SA keys found — Workload Identity likely in use",
                description=(
                    "No user-managed service account keys found in the project. "
                    "This is the desired state — workloads should use Workload Identity "
                    "Federation instead of static keys."
                ),
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.IAM,
                resource_type="GCP::IAM::ServiceAccount",
                resource_id=f"projects/{project_id}/serviceAccounts",
                region=region,
                account_id=project_id,
                cloud_provider=CloudProvider.GCP,
                soc2_controls=["CC6.3"],
                cis_gcp_controls=["1.4"],
            )
        ]

    return [
        Finding(
            check_id="gcp-iam-workload-identity",
            title=f"{total_user_keys} user-managed SA key(s) across {len(sa_with_keys)} account(s)",
            description=(
                f"{total_user_keys} user-managed key(s) exist across {len(sa_with_keys)} "
                "service account(s). Each key is a long-lived credential that requires manual "
                "rotation. Consider migrating these workloads to Workload Identity Federation."
            ),
            severity=Severity.MEDIUM,
            status=ComplianceStatus.PARTIAL,
            domain=CheckDomain.IAM,
            resource_type="GCP::IAM::ServiceAccount",
            resource_id=f"projects/{project_id}/serviceAccounts",
            region=region,
            account_id=project_id,
            cloud_provider=CloudProvider.GCP,
            remediation=(
                "For GCE instances: enable the Metadata Service identity (no key needed). "
                "For GKE: enable Workload Identity on the cluster and node pool. "
                "For external workloads: configure Workload Identity Federation with your "
                "identity provider. Then delete user-managed keys."
            ),
            soc2_controls=["CC6.3"],
            cis_gcp_controls=["1.4"],
            iso27001_controls=["A.8.3"],
            details={
                "total_user_managed_keys": total_user_keys,
                "service_accounts_with_keys": sa_with_keys[:20],
            },
        )
    ]
