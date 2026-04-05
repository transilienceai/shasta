"""Azure Identity & Access checks for SOC 2 and ISO 27001.

Checks Entra ID (Azure AD) authentication policies and Azure RBAC
role assignments for compliance with CC6.1, CC6.2, CC6.3.

Requires Microsoft Graph API permissions:
- User.Read.All, Policy.Read.All, RoleManagement.Read.Directory
And Azure RBAC Reader on the subscription.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from shasta.azure.client import AzureClient
from shasta.evidence.models import (
    CheckDomain,
    CloudProvider,
    ComplianceStatus,
    Finding,
    Severity,
)

# Privileged Entra ID directory roles that should have minimal assignments
PRIVILEGED_ROLES = {
    "Global Administrator",
    "Privileged Role Administrator",
    "Privileged Authentication Administrator",
    "Security Administrator",
    "Exchange Administrator",
    "SharePoint Administrator",
    "User Administrator",
}

# Azure RBAC roles that are overprivileged at subscription scope
OVERPRIVILEGED_RBAC_ROLES = {
    "Owner",
    "Contributor",
    "User Access Administrator",
}

INACTIVE_DAYS_THRESHOLD = 90


def run_all_azure_iam_checks(client: AzureClient) -> list[Finding]:
    """Run all Azure identity and access compliance checks."""
    findings: list[Finding] = []
    sub_id = client.account_info.subscription_id if client.account_info else "unknown"
    region = client.account_info.region if client.account_info else "unknown"

    findings.extend(check_conditional_access_mfa(client, sub_id, region))
    findings.extend(check_privileged_roles(client, sub_id, region))
    findings.extend(check_rbac_least_privilege(client, sub_id, region))
    findings.extend(check_inactive_users(client, sub_id, region))
    findings.extend(check_guest_access(client, sub_id, region))
    findings.extend(check_service_principal_hygiene(client, sub_id, region))

    return findings


def check_conditional_access_mfa(
    client: AzureClient, subscription_id: str, region: str
) -> list[Finding]:
    """[CC6.1] Check if Conditional Access policies enforce MFA for all users."""
    try:
        graph = client.graph_client()
        policies = list(client.graph_call(graph.identity.conditional_access.policies.get()).value or [])

        mfa_enforced = False
        mfa_policy_names = []

        for policy in policies:
            if policy.state != "enabled":
                continue
            # Check if grant controls include MFA
            grant = policy.grant_controls
            if grant and grant.built_in_controls:
                if "mfa" in [c.lower() for c in grant.built_in_controls]:
                    # Check if policy targets all users
                    conditions = policy.conditions
                    if conditions and conditions.users:
                        include_all = (
                            conditions.users.include_users
                            and "All" in conditions.users.include_users
                        )
                        include_groups = bool(conditions.users.include_groups)
                        if include_all or include_groups:
                            mfa_enforced = True
                            mfa_policy_names.append(policy.display_name)

        if mfa_enforced:
            return [
                Finding(
                    check_id="azure-conditional-access-mfa",
                    title="Conditional Access enforces MFA",
                    description=f"MFA is enforced via Conditional Access policies: {', '.join(mfa_policy_names)}",
                    severity=Severity.INFO,
                    status=ComplianceStatus.PASS,
                    domain=CheckDomain.IAM,
                    resource_type="Azure::EntraID::ConditionalAccessPolicy",
                    resource_id=f"/tenants/{subscription_id}/conditionalAccess",
                    region=region,
                    account_id=subscription_id,
                    cloud_provider=CloudProvider.AZURE,
                    remediation="",
                    soc2_controls=["CC6.1"],
                    details={"policies": mfa_policy_names},
                )
            ]
        else:
            return [
                Finding(
                    check_id="azure-conditional-access-mfa",
                    title="MFA not enforced via Conditional Access",
                    description="No enabled Conditional Access policy requires MFA for all users. "
                    "Without MFA, compromised passwords give direct account access.",
                    severity=Severity.HIGH,
                    status=ComplianceStatus.FAIL,
                    domain=CheckDomain.IAM,
                    resource_type="Azure::EntraID::ConditionalAccessPolicy",
                    resource_id=f"/tenants/{subscription_id}/conditionalAccess",
                    region=region,
                    account_id=subscription_id,
                    cloud_provider=CloudProvider.AZURE,
                    remediation="Create a Conditional Access policy requiring MFA for all users. "
                    "Entra ID > Security > Conditional Access > New policy > Grant: Require MFA.",
                    soc2_controls=["CC6.1"],
                    details={"total_policies": len(policies)},
                )
            ]

    except Exception as e:
        error_msg = str(e)
        # Handle missing permissions gracefully
        if (
            "Authorization" in error_msg
            or "Forbidden" in error_msg
            or "insufficient" in error_msg.lower()
        ):
            return [
                Finding(
                    check_id="azure-conditional-access-mfa",
                    title="Cannot check Conditional Access (insufficient permissions)",
                    description="Graph API permissions Policy.Read.All required to check Conditional Access policies. "
                    "This may also require an Entra ID P1/P2 license.",
                    severity=Severity.MEDIUM,
                    status=ComplianceStatus.NOT_ASSESSED,
                    domain=CheckDomain.IAM,
                    resource_type="Azure::EntraID::ConditionalAccessPolicy",
                    resource_id=f"/tenants/{subscription_id}/conditionalAccess",
                    region=region,
                    account_id=subscription_id,
                    cloud_provider=CloudProvider.AZURE,
                    remediation="Grant Policy.Read.All permission to the scanning identity.",
                    soc2_controls=["CC6.1"],
                )
            ]
        raise


def check_privileged_roles(client: AzureClient, subscription_id: str, region: str) -> list[Finding]:
    """[CC6.1, CC6.2] Check for excessive privileged directory role assignments."""
    findings: list[Finding] = []

    try:
        graph = client.graph_client()
        role_assignments = list(client.graph_call(graph.role_management.directory.role_assignments.get()).value or [])
        role_definitions = list(client.graph_call(graph.role_management.directory.role_definitions.get()).value or [])

        # Map role definition IDs to names
        role_map = {rd.id: rd.display_name for rd in role_definitions}

        # Count assignments per privileged role
        privileged_counts: dict[str, list[str]] = {}
        for assignment in role_assignments:
            role_name = role_map.get(assignment.role_definition_id, "Unknown")
            if role_name in PRIVILEGED_ROLES:
                if role_name not in privileged_counts:
                    privileged_counts[role_name] = []
                privileged_counts[role_name].append(assignment.principal_id)

        global_admins = privileged_counts.get("Global Administrator", [])
        if len(global_admins) > 3:
            findings.append(
                Finding(
                    check_id="azure-privileged-roles",
                    title=f"Excessive Global Administrator assignments ({len(global_admins)})",
                    description=f"{len(global_admins)} principals have Global Administrator role. "
                    "Best practice is 2-3 break-glass accounts maximum.",
                    severity=Severity.HIGH,
                    status=ComplianceStatus.FAIL,
                    domain=CheckDomain.IAM,
                    resource_type="Azure::EntraID::RoleAssignment",
                    resource_id=f"/tenants/{subscription_id}/globalAdmins",
                    region=region,
                    account_id=subscription_id,
                    cloud_provider=CloudProvider.AZURE,
                    remediation="Reduce Global Administrator assignments to 2-3 break-glass accounts. "
                    "Use least-privilege roles (e.g., Application Administrator) for daily operations.",
                    soc2_controls=["CC6.1", "CC6.2"],
                    details={
                        "global_admin_count": len(global_admins),
                        "privileged_roles": {k: len(v) for k, v in privileged_counts.items()},
                    },
                )
            )
        else:
            findings.append(
                Finding(
                    check_id="azure-privileged-roles",
                    title=f"Global Administrator assignments within limits ({len(global_admins)})",
                    description=f"{len(global_admins)} principals have Global Administrator role.",
                    severity=Severity.INFO,
                    status=ComplianceStatus.PASS,
                    domain=CheckDomain.IAM,
                    resource_type="Azure::EntraID::RoleAssignment",
                    resource_id=f"/tenants/{subscription_id}/globalAdmins",
                    region=region,
                    account_id=subscription_id,
                    cloud_provider=CloudProvider.AZURE,
                    soc2_controls=["CC6.1", "CC6.2"],
                    details={
                        "global_admin_count": len(global_admins),
                        "privileged_roles": {k: len(v) for k, v in privileged_counts.items()},
                    },
                )
            )

    except Exception as e:
        if "Authorization" in str(e) or "Forbidden" in str(e):
            findings.append(
                Finding(
                    check_id="azure-privileged-roles",
                    title="Cannot check privileged roles (insufficient permissions)",
                    description="Graph API permissions RoleManagement.Read.Directory required.",
                    severity=Severity.MEDIUM,
                    status=ComplianceStatus.NOT_ASSESSED,
                    domain=CheckDomain.IAM,
                    resource_type="Azure::EntraID::RoleAssignment",
                    resource_id=f"/tenants/{subscription_id}/roles",
                    region=region,
                    account_id=subscription_id,
                    cloud_provider=CloudProvider.AZURE,
                    soc2_controls=["CC6.1", "CC6.2"],
                )
            )
        else:
            raise

    return findings


def check_rbac_least_privilege(
    client: AzureClient, subscription_id: str, region: str
) -> list[Finding]:
    """[CC6.2] Check for overprivileged RBAC role assignments at subscription scope."""
    findings: list[Finding] = []

    try:
        from azure.mgmt.authorization import AuthorizationManagementClient

        auth_client = client.mgmt_client(AuthorizationManagementClient)

        # List role assignments at subscription scope
        assignments = list(auth_client.role_assignments.list_for_subscription())
        role_defs: dict[str, str] = {}

        overprivileged = []
        for assignment in assignments:
            # Only check subscription-scope assignments
            scope = assignment.scope or ""
            if scope != f"/subscriptions/{subscription_id}":
                continue

            # Get role name
            role_def_id = assignment.role_definition_id or ""
            if role_def_id not in role_defs:
                try:
                    rd = auth_client.role_definitions.get_by_id(role_def_id)
                    role_defs[role_def_id] = rd.role_name or "Unknown"
                except Exception:
                    role_defs[role_def_id] = "Unknown"

            role_name = role_defs[role_def_id]
            if role_name in OVERPRIVILEGED_RBAC_ROLES:
                overprivileged.append(
                    {
                        "principal_id": assignment.principal_id,
                        "principal_type": assignment.principal_type,
                        "role": role_name,
                        "scope": scope,
                    }
                )

        if overprivileged:
            findings.append(
                Finding(
                    check_id="azure-rbac-least-privilege",
                    title=f"Overprivileged RBAC assignments at subscription scope ({len(overprivileged)})",
                    description=f"{len(overprivileged)} principals have {', '.join(OVERPRIVILEGED_RBAC_ROLES)} "
                    f"roles at subscription scope. Prefer scoped assignments at resource group level.",
                    severity=Severity.MEDIUM,
                    status=ComplianceStatus.FAIL,
                    domain=CheckDomain.IAM,
                    resource_type="Azure::Authorization::RoleAssignment",
                    resource_id=f"/subscriptions/{subscription_id}/rbac",
                    region=region,
                    account_id=subscription_id,
                    cloud_provider=CloudProvider.AZURE,
                    remediation="Review and reduce subscription-scope Owner/Contributor assignments. "
                    "Assign roles at resource group scope instead of subscription scope.",
                    soc2_controls=["CC6.2"],
                    details={"overprivileged_assignments": overprivileged},
                )
            )
        else:
            findings.append(
                Finding(
                    check_id="azure-rbac-least-privilege",
                    title="No overprivileged subscription-scope RBAC assignments",
                    description="No Owner/Contributor/User Access Administrator roles assigned at subscription scope.",
                    severity=Severity.INFO,
                    status=ComplianceStatus.PASS,
                    domain=CheckDomain.IAM,
                    resource_type="Azure::Authorization::RoleAssignment",
                    resource_id=f"/subscriptions/{subscription_id}/rbac",
                    region=region,
                    account_id=subscription_id,
                    cloud_provider=CloudProvider.AZURE,
                    soc2_controls=["CC6.2"],
                )
            )

    except Exception as e:
        findings.append(
            Finding(
                check_id="azure-rbac-least-privilege",
                title="RBAC check failed",
                description=f"Could not check RBAC assignments: {e}",
                severity=Severity.MEDIUM,
                status=ComplianceStatus.NOT_ASSESSED,
                domain=CheckDomain.IAM,
                resource_type="Azure::Authorization::RoleAssignment",
                resource_id=f"/subscriptions/{subscription_id}/rbac",
                region=region,
                account_id=subscription_id,
                cloud_provider=CloudProvider.AZURE,
                soc2_controls=["CC6.2"],
            )
        )

    return findings


def check_inactive_users(client: AzureClient, subscription_id: str, region: str) -> list[Finding]:
    """[CC6.3] Check for users with no sign-in activity in 90+ days."""
    findings: list[Finding] = []

    try:
        graph = client.graph_client()
        users = list(client.graph_call(graph.users.get()).value or [])

        cutoff = datetime.now(UTC) - timedelta(days=INACTIVE_DAYS_THRESHOLD)
        inactive_users = []
        active_users = 0

        for user in users:
            if not user.account_enabled:
                continue

            last_sign_in = None
            if hasattr(user, "sign_in_activity") and user.sign_in_activity:
                last_sign_in = user.sign_in_activity.last_sign_in_date_time

            if last_sign_in is None or last_sign_in < cutoff:
                inactive_users.append(
                    {
                        "user_principal_name": user.user_principal_name,
                        "display_name": user.display_name,
                        "last_sign_in": last_sign_in.isoformat() if last_sign_in else "never",
                    }
                )
            else:
                active_users += 1

        if inactive_users:
            findings.append(
                Finding(
                    check_id="azure-inactive-users",
                    title=f"Inactive users found ({len(inactive_users)} users, {INACTIVE_DAYS_THRESHOLD}+ days)",
                    description=f"{len(inactive_users)} enabled users have not signed in for {INACTIVE_DAYS_THRESHOLD}+ days. "
                    "Stale accounts increase the attack surface.",
                    severity=Severity.MEDIUM,
                    status=ComplianceStatus.FAIL,
                    domain=CheckDomain.IAM,
                    resource_type="Azure::EntraID::User",
                    resource_id=f"/tenants/{subscription_id}/inactiveUsers",
                    region=region,
                    account_id=subscription_id,
                    cloud_provider=CloudProvider.AZURE,
                    remediation="Review inactive accounts and disable or delete those no longer needed. "
                    "Entra ID > Users > filter by last sign-in > Disable account.",
                    soc2_controls=["CC6.3"],
                    details={
                        "inactive_users": inactive_users[:20],
                        "total_inactive": len(inactive_users),
                    },
                )
            )
        else:
            findings.append(
                Finding(
                    check_id="azure-inactive-users",
                    title="No inactive users found",
                    description=f"All {active_users} enabled users have signed in within {INACTIVE_DAYS_THRESHOLD} days.",
                    severity=Severity.INFO,
                    status=ComplianceStatus.PASS,
                    domain=CheckDomain.IAM,
                    resource_type="Azure::EntraID::User",
                    resource_id=f"/tenants/{subscription_id}/users",
                    region=region,
                    account_id=subscription_id,
                    cloud_provider=CloudProvider.AZURE,
                    soc2_controls=["CC6.3"],
                )
            )

    except Exception as e:
        if "Authorization" in str(e) or "Forbidden" in str(e):
            findings.append(
                Finding(
                    check_id="azure-inactive-users",
                    title="Cannot check user activity (insufficient permissions)",
                    description="Graph API permissions User.Read.All and AuditLog.Read.All required.",
                    severity=Severity.MEDIUM,
                    status=ComplianceStatus.NOT_ASSESSED,
                    domain=CheckDomain.IAM,
                    resource_type="Azure::EntraID::User",
                    resource_id=f"/tenants/{subscription_id}/users",
                    region=region,
                    account_id=subscription_id,
                    cloud_provider=CloudProvider.AZURE,
                    soc2_controls=["CC6.3"],
                )
            )
        else:
            raise

    return findings


def check_guest_access(client: AzureClient, subscription_id: str, region: str) -> list[Finding]:
    """[CC6.3] Review external/guest user accounts in the tenant."""
    findings: list[Finding] = []

    try:
        graph = client.graph_client()
        users = list(client.graph_call(graph.users.get()).value or [])

        guests = []
        for user in users:
            if user.user_type and user.user_type.lower() == "guest":
                guests.append(
                    {
                        "user_principal_name": user.user_principal_name,
                        "display_name": user.display_name,
                        "account_enabled": user.account_enabled,
                    }
                )

        if guests:
            enabled_guests = [g for g in guests if g.get("account_enabled")]
            findings.append(
                Finding(
                    check_id="azure-guest-access",
                    title=f"Guest users found ({len(guests)} total, {len(enabled_guests)} enabled)",
                    description=f"{len(enabled_guests)} enabled guest users in the tenant. "
                    "Guest accounts should be reviewed periodically and removed when no longer needed.",
                    severity=Severity.MEDIUM if len(enabled_guests) > 5 else Severity.LOW,
                    status=ComplianceStatus.PARTIAL if enabled_guests else ComplianceStatus.PASS,
                    domain=CheckDomain.IAM,
                    resource_type="Azure::EntraID::User",
                    resource_id=f"/tenants/{subscription_id}/guestUsers",
                    region=region,
                    account_id=subscription_id,
                    cloud_provider=CloudProvider.AZURE,
                    remediation="Review guest users quarterly. Remove guests who no longer need access. "
                    "Entra ID > Users > filter User type = Guest.",
                    soc2_controls=["CC6.3"],
                    details={
                        "guest_users": guests[:20],
                        "total_guests": len(guests),
                        "enabled_guests": len(enabled_guests),
                    },
                )
            )
        else:
            findings.append(
                Finding(
                    check_id="azure-guest-access",
                    title="No guest users found",
                    description="No external/guest user accounts in the tenant.",
                    severity=Severity.INFO,
                    status=ComplianceStatus.PASS,
                    domain=CheckDomain.IAM,
                    resource_type="Azure::EntraID::User",
                    resource_id=f"/tenants/{subscription_id}/guestUsers",
                    region=region,
                    account_id=subscription_id,
                    cloud_provider=CloudProvider.AZURE,
                    soc2_controls=["CC6.3"],
                )
            )

    except Exception as e:
        if "Authorization" in str(e) or "Forbidden" in str(e):
            findings.append(
                Finding(
                    check_id="azure-guest-access",
                    title="Cannot check guest users (insufficient permissions)",
                    description="Graph API permissions User.Read.All required.",
                    severity=Severity.MEDIUM,
                    status=ComplianceStatus.NOT_ASSESSED,
                    domain=CheckDomain.IAM,
                    resource_type="Azure::EntraID::User",
                    resource_id=f"/tenants/{subscription_id}/guestUsers",
                    region=region,
                    account_id=subscription_id,
                    cloud_provider=CloudProvider.AZURE,
                    soc2_controls=["CC6.3"],
                )
            )
        else:
            raise

    return findings


def check_service_principal_hygiene(
    client: AzureClient, subscription_id: str, region: str
) -> list[Finding]:
    """[CC6.2, CC6.3] Check for service principals with stale credentials."""
    findings: list[Finding] = []

    try:
        graph = client.graph_client()
        apps = list(client.graph_call(graph.applications.get()).value or [])

        stale_apps = []
        now = datetime.now(UTC)

        for app in apps:
            # Check password credentials
            for cred in app.password_credentials or []:
                if cred.end_date_time and cred.end_date_time < now:
                    stale_apps.append(
                        {
                            "app_name": app.display_name,
                            "app_id": app.app_id,
                            "credential_type": "password",
                            "expired": cred.end_date_time.isoformat(),
                        }
                    )
                    break

            # Check certificate credentials
            for cred in app.key_credentials or []:
                if cred.end_date_time and cred.end_date_time < now:
                    stale_apps.append(
                        {
                            "app_name": app.display_name,
                            "app_id": app.app_id,
                            "credential_type": "certificate",
                            "expired": cred.end_date_time.isoformat(),
                        }
                    )
                    break

        if stale_apps:
            findings.append(
                Finding(
                    check_id="azure-service-principal-hygiene",
                    title=f"App registrations with expired credentials ({len(stale_apps)})",
                    description=f"{len(stale_apps)} app registrations have expired password or certificate credentials. "
                    "Expired credentials should be rotated or the app registration removed.",
                    severity=Severity.HIGH,
                    status=ComplianceStatus.FAIL,
                    domain=CheckDomain.IAM,
                    resource_type="Azure::EntraID::Application",
                    resource_id=f"/tenants/{subscription_id}/applications",
                    region=region,
                    account_id=subscription_id,
                    cloud_provider=CloudProvider.AZURE,
                    remediation="Rotate expired credentials or remove unused app registrations. "
                    "Entra ID > App registrations > Certificates & secrets.",
                    soc2_controls=["CC6.2", "CC6.3"],
                    details={"stale_apps": stale_apps[:20], "total_stale": len(stale_apps)},
                )
            )
        else:
            findings.append(
                Finding(
                    check_id="azure-service-principal-hygiene",
                    title="All app registration credentials are current",
                    description=f"Checked {len(apps)} app registrations — no expired credentials found.",
                    severity=Severity.INFO,
                    status=ComplianceStatus.PASS,
                    domain=CheckDomain.IAM,
                    resource_type="Azure::EntraID::Application",
                    resource_id=f"/tenants/{subscription_id}/applications",
                    region=region,
                    account_id=subscription_id,
                    cloud_provider=CloudProvider.AZURE,
                    soc2_controls=["CC6.2", "CC6.3"],
                )
            )

    except Exception as e:
        if "Authorization" in str(e) or "Forbidden" in str(e):
            findings.append(
                Finding(
                    check_id="azure-service-principal-hygiene",
                    title="Cannot check app registrations (insufficient permissions)",
                    description="Graph API permissions Application.Read.All required.",
                    severity=Severity.MEDIUM,
                    status=ComplianceStatus.NOT_ASSESSED,
                    domain=CheckDomain.IAM,
                    resource_type="Azure::EntraID::Application",
                    resource_id=f"/tenants/{subscription_id}/applications",
                    region=region,
                    account_id=subscription_id,
                    cloud_provider=CloudProvider.AZURE,
                    soc2_controls=["CC6.2", "CC6.3"],
                )
            )
        else:
            raise

    return findings
