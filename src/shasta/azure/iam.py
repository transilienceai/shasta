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

# Microsoft Azure Management cloud app ID — covers Portal, ARM, CLI, PowerShell, REST APIs.
AZURE_MGMT_APP_ID = "797f4846-ba00-4fd7-ba43-dac1f8f63013"


def run_all_azure_iam_checks(client: AzureClient) -> list[Finding]:
    """Run all Azure identity and access compliance checks."""
    findings: list[Finding] = []
    sub_id = client.account_info.subscription_id if client.account_info else "unknown"
    region = client.account_info.region if client.account_info else "unknown"

    findings.extend(check_conditional_access_mfa(client, sub_id, region))
    findings.extend(check_legacy_auth_blocked(client, sub_id, region))
    findings.extend(check_mfa_for_azure_management(client, sub_id, region))
    findings.extend(check_privileged_roles(client, sub_id, region))
    findings.extend(check_pim_eligibility(client, sub_id, region))
    findings.extend(check_rbac_least_privilege(client, sub_id, region))
    findings.extend(check_custom_role_wildcards(client, sub_id, region))
    findings.extend(check_classic_administrators(client, sub_id, region))
    findings.extend(check_guest_invitation_restrictions(client, sub_id, region))
    findings.extend(check_inactive_users(client, sub_id, region))
    findings.extend(check_guest_access(client, sub_id, region))
    findings.extend(check_service_principal_hygiene(client, sub_id, region))

    return findings


def _ca_policies(client: AzureClient) -> list:
    """Fetch all Conditional Access policies, returning [] on permission errors."""
    try:
        graph = client.graph_client()
        return list(client.graph_call(graph.identity.conditional_access.policies.get()).value or [])
    except Exception:
        return []


def _no_permission_finding(
    check_id: str,
    title: str,
    description: str,
    subscription_id: str,
    region: str,
    resource_type: str,
    resource_id: str,
    soc2: list[str],
    cis: list[str] | None = None,
) -> Finding:
    return Finding(
        check_id=check_id,
        title=title,
        description=description,
        severity=Severity.MEDIUM,
        status=ComplianceStatus.NOT_ASSESSED,
        domain=CheckDomain.IAM,
        resource_type=resource_type,
        resource_id=resource_id,
        region=region,
        account_id=subscription_id,
        cloud_provider=CloudProvider.AZURE,
        soc2_controls=soc2,
        cis_azure_controls=cis or [],
    )


def check_conditional_access_mfa(
    client: AzureClient, subscription_id: str, region: str
) -> list[Finding]:
    """[CC6.1] Check if Conditional Access policies enforce MFA for all users."""
    try:
        graph = client.graph_client()
        policies = list(
            client.graph_call(graph.identity.conditional_access.policies.get()).value or []
        )

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
            or "AccessDenied" in error_msg
            or "403" in error_msg
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
        role_assignments = list(
            client.graph_call(graph.role_management.directory.role_assignments.get()).value or []
        )
        role_definitions = list(
            client.graph_call(graph.role_management.directory.role_definitions.get()).value or []
        )

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
        if any(k in str(e) for k in ("Authorization", "Forbidden", "AccessDenied", "403")):
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
        if any(k in str(e) for k in ("Authorization", "Forbidden", "AccessDenied", "403")):
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
        if any(k in str(e) for k in ("Authorization", "Forbidden", "AccessDenied", "403")):
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
        if any(k in str(e) for k in ("Authorization", "Forbidden", "AccessDenied", "403")):
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


# ---------------------------------------------------------------------------
# CIS Azure v3.0 Identity checks (Stage 1 additions)
# ---------------------------------------------------------------------------


def check_legacy_auth_blocked(
    client: AzureClient, subscription_id: str, region: str
) -> list[Finding]:
    """[CIS 1.1.x] Check that a Conditional Access policy blocks legacy authentication.

    Legacy auth (Exchange ActiveSync, IMAP, POP, SMTP, Other Clients) bypasses
    MFA and is the #1 password-spray attack vector. Best practice is a CA
    policy targeting clientAppTypes = ['exchangeActiveSync','other'] with
    grant control = block.
    """
    policies = _ca_policies(client)
    if not policies:
        return [
            _no_permission_finding(
                "azure-legacy-auth-blocked",
                "Cannot check legacy authentication block (Conditional Access unavailable)",
                "Could not enumerate Conditional Access policies. Requires Policy.Read.All on Graph and Entra ID P1+.",
                subscription_id,
                region,
                "Azure::EntraID::ConditionalAccessPolicy",
                f"/tenants/{subscription_id}/conditionalAccess",
                ["CC6.1"],
                ["1.1.1"],
            )
        ]

    blocking_policies: list[str] = []
    for p in policies:
        if getattr(p, "state", None) != "enabled":
            continue
        cond = getattr(p, "conditions", None)
        client_apps = getattr(cond, "client_app_types", None) if cond else None
        if not client_apps:
            continue
        normalized = {str(a).lower() for a in client_apps}
        # Targets legacy clients (anything other than 'browser'/'mobileAppsAndDesktopClients')
        if normalized & {"exchangeactivesync", "other", "exchangeActiveSync".lower()}:
            grant = getattr(p, "grant_controls", None)
            built_in = [c.lower() for c in (getattr(grant, "built_in_controls", None) or [])]
            if "block" in built_in:
                blocking_policies.append(p.display_name or "unnamed")

    if blocking_policies:
        return [
            Finding(
                check_id="azure-legacy-auth-blocked",
                title="Legacy authentication is blocked by Conditional Access",
                description=(
                    f"{len(blocking_policies)} CA policy(ies) block legacy authentication: "
                    f"{', '.join(blocking_policies)}. This stops password-spray attacks against "
                    "Exchange ActiveSync, IMAP, POP, and SMTP."
                ),
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.IAM,
                resource_type="Azure::EntraID::ConditionalAccessPolicy",
                resource_id=f"/tenants/{subscription_id}/conditionalAccess/legacyAuth",
                region=region,
                account_id=subscription_id,
                cloud_provider=CloudProvider.AZURE,
                soc2_controls=["CC6.1"],
                cis_azure_controls=["1.1.1"],
                mcsb_controls=["IM-6"],
                details={"policies": blocking_policies},
            )
        ]
    return [
        Finding(
            check_id="azure-legacy-auth-blocked",
            title="Legacy authentication is NOT blocked",
            description=(
                "No enabled Conditional Access policy blocks legacy authentication clients. "
                "Legacy protocols (ActiveSync, IMAP, POP, SMTP) bypass MFA and account for the "
                "vast majority of credential-based attacks against Entra ID."
            ),
            severity=Severity.HIGH,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.IAM,
            resource_type="Azure::EntraID::ConditionalAccessPolicy",
            resource_id=f"/tenants/{subscription_id}/conditionalAccess/legacyAuth",
            region=region,
            account_id=subscription_id,
            cloud_provider=CloudProvider.AZURE,
            remediation=(
                "Create a CA policy: Users=All, Cloud apps=All, Conditions > Client apps > "
                "select Exchange ActiveSync clients + Other clients, Grant > Block access. "
                "Test in report-only mode first."
            ),
            soc2_controls=["CC6.1"],
            cis_azure_controls=["1.1.1"],
            mcsb_controls=["IM-6"],
            details={"total_policies": len(policies)},
        )
    ]


def check_mfa_for_azure_management(
    client: AzureClient, subscription_id: str, region: str
) -> list[Finding]:
    """[CIS 1.1.4] Check that a CA policy enforces MFA for the Microsoft Azure Management cloud app.

    The Azure Management app ID is 797f4846-ba00-4fd7-ba43-dac1f8f63013 and
    covers Azure Portal, ARM, CLI, PowerShell, REST APIs.
    """
    policies = _ca_policies(client)
    if not policies:
        return [
            _no_permission_finding(
                "azure-mfa-azure-management",
                "Cannot check MFA-for-Azure-Management policy",
                "Could not enumerate Conditional Access policies. Requires Policy.Read.All.",
                subscription_id,
                region,
                "Azure::EntraID::ConditionalAccessPolicy",
                f"/tenants/{subscription_id}/conditionalAccess",
                ["CC6.1"],
                ["1.1.4"],
            )
        ]

    matched: list[str] = []
    for p in policies:
        if getattr(p, "state", None) != "enabled":
            continue
        cond = getattr(p, "conditions", None)
        apps = getattr(cond, "applications", None) if cond else None
        include_apps = getattr(apps, "include_applications", None) if apps else None
        if not include_apps:
            continue
        if AZURE_MGMT_APP_ID not in include_apps and "All" not in include_apps:
            continue
        grant = getattr(p, "grant_controls", None)
        built_in = [c.lower() for c in (getattr(grant, "built_in_controls", None) or [])]
        if "mfa" in built_in:
            matched.append(p.display_name or "unnamed")

    if matched:
        return [
            Finding(
                check_id="azure-mfa-azure-management",
                title="MFA enforced for Azure Management",
                description=(
                    f"{len(matched)} CA policy(ies) enforce MFA on the Microsoft Azure Management "
                    f"cloud app: {', '.join(matched)}."
                ),
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.IAM,
                resource_type="Azure::EntraID::ConditionalAccessPolicy",
                resource_id=f"/tenants/{subscription_id}/conditionalAccess/azureMgmt",
                region=region,
                account_id=subscription_id,
                cloud_provider=CloudProvider.AZURE,
                soc2_controls=["CC6.1"],
                cis_azure_controls=["1.1.4"],
                mcsb_controls=["IM-6"],
                details={"policies": matched},
            )
        ]
    return [
        Finding(
            check_id="azure-mfa-azure-management",
            title="MFA is NOT enforced for Azure Management",
            description=(
                "No enabled Conditional Access policy targets the Microsoft Azure Management cloud "
                "app (Azure Portal, ARM, CLI, PowerShell) with MFA. A leaked admin password gives "
                "direct subscription access without a second factor."
            ),
            severity=Severity.HIGH,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.IAM,
            resource_type="Azure::EntraID::ConditionalAccessPolicy",
            resource_id=f"/tenants/{subscription_id}/conditionalAccess/azureMgmt",
            region=region,
            account_id=subscription_id,
            cloud_provider=CloudProvider.AZURE,
            remediation=(
                "Create a CA policy: Users=All (exclude break-glass), Cloud apps=Microsoft Azure "
                "Management, Grant=Require MFA. Verify break-glass exclusions before enforcing."
            ),
            soc2_controls=["CC6.1"],
            cis_azure_controls=["1.1.4"],
            mcsb_controls=["IM-6"],
        )
    ]


def check_pim_eligibility(client: AzureClient, subscription_id: str, region: str) -> list[Finding]:
    """[CIS 1.23] Check that privileged directory roles use PIM eligibility, not permanent assignments.

    Privileged Identity Management (PIM) lets admins activate roles JIT with
    MFA and approval rather than holding the role permanently.
    """
    try:
        graph = client.graph_client()
        # active assignments
        active = list(
            client.graph_call(
                graph.role_management.directory.role_assignment_schedule_instances.get()
            ).value
            or []
        )
        # eligible (PIM) assignments
        eligible = list(
            client.graph_call(
                graph.role_management.directory.role_eligibility_schedule_instances.get()
            ).value
            or []
        )
        role_defs = list(
            client.graph_call(graph.role_management.directory.role_definitions.get()).value or []
        )
    except Exception:
        return [
            _no_permission_finding(
                "azure-pim-eligibility",
                "Cannot check PIM eligibility (insufficient permissions or no Entra ID P2)",
                "PIM checks require RoleManagement.Read.Directory and Entra ID P2 license.",
                subscription_id,
                region,
                "Azure::EntraID::PIM",
                f"/tenants/{subscription_id}/pim",
                ["CC6.1", "CC6.2"],
                ["1.23"],
            )
        ]

    role_map = {rd.id: rd.display_name for rd in role_defs}
    permanent_privileged: dict[str, int] = {}
    for a in active:
        role_name = role_map.get(getattr(a, "role_definition_id", None), "Unknown")
        if role_name not in PRIVILEGED_ROLES:
            continue
        # Permanent assignments have no end date
        end_date = getattr(getattr(a, "end_date_time", None), "isoformat", lambda: None)()
        if end_date is None:
            permanent_privileged[role_name] = permanent_privileged.get(role_name, 0) + 1

    eligible_count = sum(
        1
        for e in eligible
        if role_map.get(getattr(e, "role_definition_id", None), "") in PRIVILEGED_ROLES
    )

    if not permanent_privileged:
        return [
            Finding(
                check_id="azure-pim-eligibility",
                title="Privileged roles use PIM eligibility (no permanent assignments)",
                description=(
                    f"All privileged role assignments are time-bound or PIM-eligible "
                    f"({eligible_count} eligible). No permanent privileged assignments found."
                ),
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.IAM,
                resource_type="Azure::EntraID::PIM",
                resource_id=f"/tenants/{subscription_id}/pim",
                region=region,
                account_id=subscription_id,
                cloud_provider=CloudProvider.AZURE,
                soc2_controls=["CC6.1", "CC6.2"],
                cis_azure_controls=["1.23"],
                mcsb_controls=["PA-2"],
                details={"eligible_assignments": eligible_count},
            )
        ]

    total_perm = sum(permanent_privileged.values())
    return [
        Finding(
            check_id="azure-pim-eligibility",
            title=f"{total_perm} permanent privileged role assignment(s) found",
            description=(
                f"Privileged roles with permanent (non-PIM) assignments: "
                f"{', '.join(f'{r}={c}' for r, c in permanent_privileged.items())}. "
                "Permanent privileged access violates least-privilege; eligible PIM assignments "
                "force JIT activation with MFA and audit trail."
            ),
            severity=Severity.HIGH,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.IAM,
            resource_type="Azure::EntraID::PIM",
            resource_id=f"/tenants/{subscription_id}/pim",
            region=region,
            account_id=subscription_id,
            cloud_provider=CloudProvider.AZURE,
            remediation=(
                "Convert permanent privileged role assignments to PIM eligible. "
                "Entra ID > Privileged Identity Management > Azure AD roles > Roles > "
                "select role > Add assignments > Eligible. Configure activation max 8h, "
                "require MFA, require justification."
            ),
            soc2_controls=["CC6.1", "CC6.2"],
            cis_azure_controls=["1.23"],
            mcsb_controls=["PA-2"],
            details={
                "permanent_by_role": permanent_privileged,
                "eligible_assignments": eligible_count,
            },
        )
    ]


def check_classic_administrators(
    client: AzureClient, subscription_id: str, region: str
) -> list[Finding]:
    """[CIS 1.22] Check for legacy Service Administrator / Co-Administrator role assignments.

    Classic admins predate RBAC and grant full subscription access without
    audit granularity. They should be removed entirely.
    """
    try:
        from azure.mgmt.authorization import AuthorizationManagementClient

        auth = client.mgmt_client(AuthorizationManagementClient)
        classic = list(auth.classic_administrators.list())
    except Exception as e:
        if any(k in str(e) for k in ("Authorization", "Forbidden", "AccessDenied", "403")):
            return [
                _no_permission_finding(
                    "azure-classic-admins",
                    "Cannot check classic administrators (insufficient permissions)",
                    "Requires Microsoft.Authorization/classicAdministrators/read.",
                    subscription_id,
                    region,
                    "Azure::Authorization::ClassicAdmin",
                    f"/subscriptions/{subscription_id}/providers/Microsoft.Authorization/classicAdministrators",
                    ["CC6.1", "CC6.2"],
                    ["1.22"],
                )
            ]
        return [Finding.not_assessed(
            check_id="azure-classic-admins",
            title="Unable to check classic administrators",
            description=f"API call failed: {e}",
            domain=CheckDomain.IAM,
            resource_type="Azure::Authorization::ClassicAdmin",
            account_id=subscription_id,
            region=region,
            cloud_provider=CloudProvider.AZURE,
        )]

    if not classic:
        return [
            Finding(
                check_id="azure-classic-admins",
                title="No classic administrators present",
                description="The subscription has no Service Administrator or Co-Administrator legacy role assignments.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.IAM,
                resource_type="Azure::Authorization::ClassicAdmin",
                resource_id=f"/subscriptions/{subscription_id}/providers/Microsoft.Authorization/classicAdministrators",
                region=region,
                account_id=subscription_id,
                cloud_provider=CloudProvider.AZURE,
                soc2_controls=["CC6.1", "CC6.2"],
                cis_azure_controls=["1.22"],
            )
        ]

    admins = [
        {
            "email": getattr(c, "email_address", ""),
            "role": getattr(c, "role", ""),
        }
        for c in classic
    ]
    return [
        Finding(
            check_id="azure-classic-admins",
            title=f"{len(classic)} classic administrator(s) still assigned",
            description=(
                f"{len(classic)} legacy classic admin assignment(s) detected: "
                f"{', '.join(a['email'] for a in admins[:5])}. "
                "Classic admins predate RBAC, grant full subscription control, and have no "
                "fine-grained audit. Migrate to Owner/Contributor RBAC and remove."
            ),
            severity=Severity.HIGH,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.IAM,
            resource_type="Azure::Authorization::ClassicAdmin",
            resource_id=f"/subscriptions/{subscription_id}/providers/Microsoft.Authorization/classicAdministrators",
            region=region,
            account_id=subscription_id,
            cloud_provider=CloudProvider.AZURE,
            remediation=(
                "Re-create equivalent access using RBAC role assignments (Owner/Contributor at "
                "the smallest necessary scope). Then remove classic assignments via "
                "Subscription > Access control (IAM) > Classic administrators."
            ),
            soc2_controls=["CC6.1", "CC6.2"],
            cis_azure_controls=["1.22"],
            details={"admins": admins[:20]},
        )
    ]


def check_custom_role_wildcards(
    client: AzureClient, subscription_id: str, region: str
) -> list[Finding]:
    """[CIS 1.21] Check for custom RBAC roles with wildcard Actions at subscription scope.

    Custom roles with Actions: ["*"] are equivalent to Owner but easier to
    miss in access reviews. The CIS benchmark explicitly forbids them.
    """
    try:
        from azure.mgmt.authorization import AuthorizationManagementClient

        auth = client.mgmt_client(AuthorizationManagementClient)
        scope = f"/subscriptions/{subscription_id}"
        defs = list(auth.role_definitions.list(scope))
    except Exception:
        return [
            _no_permission_finding(
                "azure-custom-role-wildcards",
                "Cannot enumerate custom RBAC roles",
                "Requires Microsoft.Authorization/roleDefinitions/read.",
                subscription_id,
                region,
                "Azure::Authorization::RoleDefinition",
                f"/subscriptions/{subscription_id}/providers/Microsoft.Authorization/roleDefinitions",
                ["CC6.1", "CC6.2"],
                ["1.21"],
            )
        ]

    offenders: list[dict] = []
    for d in defs:
        if getattr(d, "role_type", "") != "CustomRole":
            continue
        for perm in getattr(d, "permissions", []) or []:
            actions = list(getattr(perm, "actions", []) or [])
            data_actions = list(getattr(perm, "data_actions", []) or [])
            if "*" in actions or "*" in data_actions:
                offenders.append(
                    {
                        "name": getattr(d, "role_name", "unknown"),
                        "id": getattr(d, "id", ""),
                        "actions": actions,
                        "data_actions": data_actions,
                    }
                )
                break

    if not offenders:
        return [
            Finding(
                check_id="azure-custom-role-wildcards",
                title="No custom RBAC roles with wildcard Actions",
                description=f"Reviewed {len(defs)} role definitions; no custom role grants Actions=['*'].",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.IAM,
                resource_type="Azure::Authorization::RoleDefinition",
                resource_id=f"/subscriptions/{subscription_id}/providers/Microsoft.Authorization/roleDefinitions",
                region=region,
                account_id=subscription_id,
                cloud_provider=CloudProvider.AZURE,
                soc2_controls=["CC6.1", "CC6.2"],
                cis_azure_controls=["1.21"],
            )
        ]
    return [
        Finding(
            check_id="azure-custom-role-wildcards",
            title=f"{len(offenders)} custom RBAC role(s) grant wildcard Actions",
            description=(
                f"Custom roles with Actions=['*'] effectively grant Owner without the Owner "
                f"role name: {', '.join(o['name'] for o in offenders)}. These bypass "
                "least-privilege reviews."
            ),
            severity=Severity.HIGH,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.IAM,
            resource_type="Azure::Authorization::RoleDefinition",
            resource_id=f"/subscriptions/{subscription_id}/providers/Microsoft.Authorization/roleDefinitions",
            region=region,
            account_id=subscription_id,
            cloud_provider=CloudProvider.AZURE,
            remediation=(
                "Review each custom role and replace wildcard Actions with the specific "
                "operations needed. If the role truly needs full control, use the built-in "
                "Owner role instead so it's caught by access reviews."
            ),
            soc2_controls=["CC6.1", "CC6.2"],
            cis_azure_controls=["1.21"],
            details={"offending_roles": offenders[:10]},
        )
    ]


def check_guest_invitation_restrictions(
    client: AzureClient, subscription_id: str, region: str
) -> list[Finding]:
    """[CIS 1.3] Check that guest invitations are restricted to admins / specific roles.

    Reads the authorizationPolicy for allowInvitesFrom. Allowed values:
    none / adminsAndGuestInviters / adminsGuestInvitersAndAllMembers / everyone.
    Anything but the first two is a finding.
    """
    try:
        graph = client.graph_client()
        policy = client.graph_call(graph.policies.authorization_policy.get())
    except Exception:
        return [
            _no_permission_finding(
                "azure-guest-invitations",
                "Cannot read authorization policy",
                "Requires Policy.Read.All on Microsoft Graph.",
                subscription_id,
                region,
                "Azure::EntraID::AuthorizationPolicy",
                f"/tenants/{subscription_id}/policies/authorizationPolicy",
                ["CC6.1", "CC6.3"],
                ["1.3"],
            )
        ]

    allow_invites = getattr(policy, "allow_invites_from", None) or "unknown"
    restricted_values = {"none", "adminsAndGuestInviters"}

    if allow_invites in restricted_values:
        return [
            Finding(
                check_id="azure-guest-invitations",
                title=f"Guest invitations restricted (allowInvitesFrom={allow_invites})",
                description="Guest invitations are limited to admins and designated guest inviters only.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.IAM,
                resource_type="Azure::EntraID::AuthorizationPolicy",
                resource_id=f"/tenants/{subscription_id}/policies/authorizationPolicy",
                region=region,
                account_id=subscription_id,
                cloud_provider=CloudProvider.AZURE,
                soc2_controls=["CC6.1", "CC6.3"],
                cis_azure_controls=["1.3"],
                details={"allow_invites_from": allow_invites},
            )
        ]
    return [
        Finding(
            check_id="azure-guest-invitations",
            title=f"Guest invitations are too permissive (allowInvitesFrom={allow_invites})",
            description=(
                f"The authorization policy allows '{allow_invites}' to invite guest users. "
                "Any internal user (or worse, any guest) can invite arbitrary external accounts "
                "into the tenant, which then receive the default user role."
            ),
            severity=Severity.MEDIUM,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.IAM,
            resource_type="Azure::EntraID::AuthorizationPolicy",
            resource_id=f"/tenants/{subscription_id}/policies/authorizationPolicy",
            region=region,
            account_id=subscription_id,
            cloud_provider=CloudProvider.AZURE,
            remediation=(
                "Restrict guest invitations to admins. Entra ID > External Identities > "
                "External collaboration settings > Guest invite settings > 'Only users assigned "
                "to specific admin roles can invite guest users'."
            ),
            soc2_controls=["CC6.1", "CC6.3"],
            cis_azure_controls=["1.3"],
            details={"allow_invites_from": allow_invites},
        )
    ]
