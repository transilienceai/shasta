"""Azure Entra ID hardening checks for CIS Azure, CIS M365, and MCSB.

Covers Identity Protection risk policies, password & authentication settings,
application consent controls, directory settings, privileged access hygiene,
and cross-tenant access configuration.

Complements ``iam.py`` (which covers RBAC + core Conditional Access + PIM).

Requires Microsoft Graph API permissions:
- Policy.Read.All  (CA policies, auth policy, consent policy, cross-tenant)
- Directory.Read.All  (directory settings, group settings)
- IdentityProtection.Read.All  (risk policy evaluation via CA conditions)
"""

from __future__ import annotations

from typing import Any

from shasta.azure.client import AzureClient
from shasta.evidence.models import (
    CheckDomain,
    CloudProvider,
    ComplianceStatus,
    Finding,
    Severity,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Guest user role IDs on the authorization policy (guestUserRoleId).
GUEST_ROLE_RESTRICTED = "2af84b1e-32c8-42b7-82bc-daa82404023b"  # own properties only
GUEST_ROLE_LIMITED = "10dae51f-b6af-4016-8d66-8c2a99b929b3"  # limited access
GUEST_ROLE_SAME_AS_MEMBERS = "a0b1b346-4d3e-4e8b-98f8-753987be4970"  # too permissive

# Heuristic display-name fragments for break-glass / emergency accounts.
BREAK_GLASS_HINTS = {"break glass", "breakglass", "emergency", "bg-", "break-glass"}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


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
    mcsb: list[str] | None = None,
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
        mcsb_controls=mcsb or [],
    )


# ---------------------------------------------------------------------------
# Shared data-fetcher functions (minimise Graph round-trips)
# ---------------------------------------------------------------------------


def _fetch_ca_policies(client: AzureClient) -> list[Any] | None:
    """Return CA policies or *None* on permission/API errors."""
    try:
        graph = client.graph_client()
        return list(client.graph_call(graph.identity.conditional_access.policies.get()).value or [])
    except Exception:
        return None


def _fetch_authorization_policy(client: AzureClient) -> Any | None:
    """Return the tenant authorization policy or *None* on error."""
    try:
        graph = client.graph_client()
        return client.graph_call(graph.policies.authorization_policy.get())
    except Exception:
        return None


def _fetch_directory_settings(client: AzureClient) -> list[Any] | None:
    """Return directory settings (group settings) or *None* on error."""
    try:
        graph = client.graph_client()
        return list(client.graph_call(graph.group_settings.get()).value or [])
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


def run_all_azure_entra_checks(client: AzureClient) -> list[Finding]:
    """Run all Entra ID hardening checks (CIS / MCSB gaps beyond iam.py)."""
    findings: list[Finding] = []
    sub_id = client.account_info.subscription_id if client.account_info else "unknown"
    region = client.account_info.region if client.account_info else "unknown"

    # Pre-fetch shared data (3 calls serve 11 of 16 checks)
    ca_policies = _fetch_ca_policies(client)
    auth_policy = _fetch_authorization_policy(client)
    dir_settings = _fetch_directory_settings(client)

    # Group A: Identity Protection
    findings.extend(check_sign_in_risk_policy(client, sub_id, region, ca_policies=ca_policies))
    findings.extend(check_user_risk_policy(client, sub_id, region, ca_policies=ca_policies))

    # Group B: Password & Authentication
    findings.extend(
        check_banned_password_protection(client, sub_id, region, dir_settings=dir_settings)
    )
    findings.extend(check_sspr_notifications(client, sub_id, region))
    findings.extend(check_authentication_methods(client, sub_id, region))
    findings.extend(check_security_defaults(client, sub_id, region, ca_policies=ca_policies))

    # Group C: Application & Consent
    findings.extend(check_user_consent_restricted(client, sub_id, region, auth_policy=auth_policy))
    findings.extend(
        check_app_registration_restricted(client, sub_id, region, auth_policy=auth_policy)
    )
    findings.extend(check_admin_consent_workflow(client, sub_id, region))

    # Group D: Directory Settings
    findings.extend(check_admin_portal_restricted(client, sub_id, region, auth_policy=auth_policy))
    findings.extend(
        check_security_group_creation_restricted(client, sub_id, region, auth_policy=auth_policy)
    )
    findings.extend(
        check_m365_group_creation_restricted(client, sub_id, region, dir_settings=dir_settings)
    )
    findings.extend(
        check_guest_user_access_restricted(client, sub_id, region, auth_policy=auth_policy)
    )

    # Group E: Privileged Access
    findings.extend(check_break_glass_accounts(client, sub_id, region, ca_policies=ca_policies))
    findings.extend(check_named_locations(client, sub_id, region))

    # Group F: Cross-Tenant
    findings.extend(check_cross_tenant_access_default(client, sub_id, region))

    return findings


# ===================================================================
# Group A — Identity Protection
# ===================================================================


def check_sign_in_risk_policy(
    client: AzureClient,
    subscription_id: str,
    region: str,
    *,
    ca_policies: list[Any] | None = None,
) -> list[Finding]:
    """[CIS M365 1.4 / MCSB IM-7] CA policy enforces MFA or block on risky sign-ins."""
    policies = ca_policies if ca_policies is not None else _fetch_ca_policies(client)
    rid = f"/tenants/{subscription_id}/conditionalAccess/signInRisk"

    if policies is None:
        return [
            _no_permission_finding(
                "azure-sign-in-risk-policy",
                "Cannot check sign-in risk policy (insufficient permissions)",
                "Conditional Access policies could not be enumerated. "
                "Requires Policy.Read.All and Entra ID P2.",
                subscription_id,
                region,
                "Azure::EntraID::ConditionalAccessPolicy",
                rid,
                ["CC6.1"],
                ["1.2.6"],
                ["IM-7"],
            )
        ]

    matching: list[str] = []
    for p in policies:
        if getattr(p, "state", None) != "enabled":
            continue
        cond = getattr(p, "conditions", None)
        risk_levels = getattr(cond, "sign_in_risk_levels", None) if cond else None
        if not risk_levels:
            continue
        normalized = {str(r).lower() for r in risk_levels}
        if "high" not in normalized:
            continue
        grant = getattr(p, "grant_controls", None)
        built_in = [c.lower() for c in (getattr(grant, "built_in_controls", None) or [])]
        if "mfa" in built_in or "block" in built_in:
            matching.append(getattr(p, "display_name", None) or "unnamed")

    if matching:
        return [
            Finding(
                check_id="azure-sign-in-risk-policy",
                title="Sign-in risk policy enforced via Conditional Access",
                description=(
                    f"{len(matching)} CA policy(ies) enforce MFA or block on high-risk "
                    f"sign-ins: {', '.join(matching)}."
                ),
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.IAM,
                resource_type="Azure::EntraID::ConditionalAccessPolicy",
                resource_id=rid,
                region=region,
                account_id=subscription_id,
                cloud_provider=CloudProvider.AZURE,
                soc2_controls=["CC6.1"],
                cis_azure_controls=["1.2.6"],
                mcsb_controls=["IM-7"],
                details={"policies": matching},
            )
        ]

    return [
        Finding(
            check_id="azure-sign-in-risk-policy",
            title="No sign-in risk Conditional Access policy",
            description=(
                "No enabled Conditional Access policy enforces MFA or block for high-risk "
                "sign-ins. Identity Protection sign-in risk policies detect compromised "
                "credentials, anonymous IPs, and atypical travel in real time."
            ),
            severity=Severity.HIGH,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.IAM,
            resource_type="Azure::EntraID::ConditionalAccessPolicy",
            resource_id=rid,
            region=region,
            account_id=subscription_id,
            cloud_provider=CloudProvider.AZURE,
            remediation=(
                "Create a Conditional Access policy: Users = All users, "
                "Conditions > Sign-in risk = High (and Medium), "
                "Grant = Require MFA. Requires Entra ID P2 license."
            ),
            soc2_controls=["CC6.1"],
            cis_azure_controls=["1.2.6"],
            mcsb_controls=["IM-7"],
            details={"total_ca_policies": len(policies)},
        )
    ]


def check_user_risk_policy(
    client: AzureClient,
    subscription_id: str,
    region: str,
    *,
    ca_policies: list[Any] | None = None,
) -> list[Finding]:
    """[MCSB IM-7] CA policy enforces block or password change on risky users."""
    policies = ca_policies if ca_policies is not None else _fetch_ca_policies(client)
    rid = f"/tenants/{subscription_id}/conditionalAccess/userRisk"

    if policies is None:
        return [
            _no_permission_finding(
                "azure-user-risk-policy",
                "Cannot check user risk policy (insufficient permissions)",
                "Conditional Access policies could not be enumerated. "
                "Requires Policy.Read.All and Entra ID P2.",
                subscription_id,
                region,
                "Azure::EntraID::ConditionalAccessPolicy",
                rid,
                ["CC6.1"],
                None,
                ["IM-7"],
            )
        ]

    matching: list[str] = []
    for p in policies:
        if getattr(p, "state", None) != "enabled":
            continue
        cond = getattr(p, "conditions", None)
        risk_levels = getattr(cond, "user_risk_levels", None) if cond else None
        if not risk_levels:
            continue
        normalized = {str(r).lower() for r in risk_levels}
        if "high" not in normalized:
            continue
        # Accept block OR password-change as valid remediation
        grant = getattr(p, "grant_controls", None)
        built_in = [c.lower() for c in (getattr(grant, "built_in_controls", None) or [])]
        if "block" in built_in or "passwordchange" in built_in:
            matching.append(getattr(p, "display_name", None) or "unnamed")

    if matching:
        return [
            Finding(
                check_id="azure-user-risk-policy",
                title="User risk policy enforced via Conditional Access",
                description=(
                    f"{len(matching)} CA policy(ies) enforce block or password change "
                    f"for high-risk users: {', '.join(matching)}."
                ),
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.IAM,
                resource_type="Azure::EntraID::ConditionalAccessPolicy",
                resource_id=rid,
                region=region,
                account_id=subscription_id,
                cloud_provider=CloudProvider.AZURE,
                soc2_controls=["CC6.1"],
                mcsb_controls=["IM-7"],
                details={"policies": matching},
            )
        ]

    return [
        Finding(
            check_id="azure-user-risk-policy",
            title="No user risk Conditional Access policy",
            description=(
                "No enabled Conditional Access policy blocks or forces password change "
                "for high-risk users. Identity Protection user risk detects leaked "
                "credentials and anomalous user behaviour."
            ),
            severity=Severity.HIGH,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.IAM,
            resource_type="Azure::EntraID::ConditionalAccessPolicy",
            resource_id=rid,
            region=region,
            account_id=subscription_id,
            cloud_provider=CloudProvider.AZURE,
            remediation=(
                "Create a Conditional Access policy: Users = All users, "
                "Conditions > User risk = High, "
                "Grant = Block access (or Require password change + MFA). "
                "Requires Entra ID P2 license."
            ),
            soc2_controls=["CC6.1"],
            mcsb_controls=["IM-7"],
            details={"total_ca_policies": len(policies)},
        )
    ]


# ===================================================================
# Group B — Password & Authentication
# ===================================================================


def check_banned_password_protection(
    client: AzureClient,
    subscription_id: str,
    region: str,
    *,
    dir_settings: list[Any] | None = None,
) -> list[Finding]:
    """[MCSB IM-8] Custom banned password list is enabled and enforced."""
    settings = dir_settings if dir_settings is not None else _fetch_directory_settings(client)
    rid = f"/tenants/{subscription_id}/passwordProtection"

    if settings is None:
        return [
            _no_permission_finding(
                "azure-banned-password-protection",
                "Cannot check banned password protection (insufficient permissions)",
                "Directory settings could not be enumerated. Requires Directory.Read.All.",
                subscription_id,
                region,
                "Azure::EntraID::PasswordProtection",
                rid,
                ["CC6.1"],
                None,
                ["IM-8"],
            )
        ]

    # Look for the "Password Rule Settings" template in directory settings.
    custom_enabled = None
    mode = None
    for s in settings:
        template_id = getattr(s, "template_id", None) or ""
        display_name = getattr(s, "display_name", None) or ""
        if "password" not in template_id.lower() and "password" not in display_name.lower():
            continue
        values = getattr(s, "values", None) or []
        for v in values:
            name = getattr(v, "name", None) or ""
            value = getattr(v, "value", None)
            if name.lower() == "bannedpasswordcheckonpremisesmode":
                mode = value
            if name.lower() == "enablebannedpasswordcheck":
                custom_enabled = str(value).lower() == "true"

    if custom_enabled is None:
        # No password rule settings found — may not be configured
        return [
            Finding(
                check_id="azure-banned-password-protection",
                title="Banned password protection settings not found",
                description=(
                    "No Password Rule Settings found in directory settings. "
                    "Custom banned password list may not be configured."
                ),
                severity=Severity.MEDIUM,
                status=ComplianceStatus.FAIL,
                domain=CheckDomain.IAM,
                resource_type="Azure::EntraID::PasswordProtection",
                resource_id=rid,
                region=region,
                account_id=subscription_id,
                cloud_provider=CloudProvider.AZURE,
                remediation=(
                    "Enable custom banned passwords: Entra ID > Security > "
                    "Authentication methods > Password protection > "
                    "Enable custom banned password list = Yes, Mode = Enforce."
                ),
                soc2_controls=["CC6.1"],
                mcsb_controls=["IM-8"],
                details={},
            )
        ]

    if custom_enabled and mode and str(mode).lower() == "enforce":
        return [
            Finding(
                check_id="azure-banned-password-protection",
                title="Custom banned password list is enabled and enforced",
                description=(
                    "Password protection is configured with a custom "
                    "banned password list in Enforce mode."
                ),
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.IAM,
                resource_type="Azure::EntraID::PasswordProtection",
                resource_id=rid,
                region=region,
                account_id=subscription_id,
                cloud_provider=CloudProvider.AZURE,
                soc2_controls=["CC6.1"],
                mcsb_controls=["IM-8"],
                details={"custom_enabled": custom_enabled, "mode": mode},
            )
        ]

    return [
        Finding(
            check_id="azure-banned-password-protection",
            title="Banned password protection is not fully enforced",
            description=(
                f"Custom banned password list enabled={custom_enabled}, mode={mode}. "
                "For full protection, enable the custom list and set mode to Enforce."
            ),
            severity=Severity.MEDIUM,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.IAM,
            resource_type="Azure::EntraID::PasswordProtection",
            resource_id=rid,
            region=region,
            account_id=subscription_id,
            cloud_provider=CloudProvider.AZURE,
            remediation=(
                "Entra ID > Security > Authentication methods > Password protection > "
                "Enable custom banned password list = Yes, Mode = Enforce."
            ),
            soc2_controls=["CC6.1"],
            mcsb_controls=["IM-8"],
            details={"custom_enabled": custom_enabled, "mode": mode},
        )
    ]


def check_sspr_notifications(
    client: AzureClient,
    subscription_id: str,
    region: str,
) -> list[Finding]:
    """[CIS 1.6-1.8] SSPR notifications: notify users on reset and all admins on admin resets."""
    rid = f"/tenants/{subscription_id}/sspr"

    try:
        graph = client.graph_client()
        # The v1.0 passwordResetPolicies aren't directly on the Graph SDK surface.
        # Use the directory settings that expose SSPR configuration.
        settings = client.graph_call(graph.group_settings.get()).value or []
    except Exception:
        return [
            _no_permission_finding(
                "azure-sspr-notifications",
                "Cannot check SSPR notification settings (insufficient permissions)",
                "Directory settings could not be enumerated. Requires Directory.Read.All.",
                subscription_id,
                region,
                "Azure::EntraID::SSPR",
                rid,
                ["CC6.1"],
                ["1.6"],
                None,
            )
        ]

    notify_users = None
    notify_admins = None
    for s in settings:
        values = getattr(s, "values", None) or []
        for v in values:
            name = (getattr(v, "name", None) or "").lower()
            value = getattr(v, "value", None)
            if "notifyusersonpasswordreset" in name:
                notify_users = str(value).lower() == "true"
            if "notifyadminsonpasswordreset" in name or "notifyonadminreset" in name:
                notify_admins = str(value).lower() == "true"

    if notify_users is None and notify_admins is None:
        return [
            Finding(
                check_id="azure-sspr-notifications",
                title="SSPR notification settings not found in directory settings",
                description=(
                    "Self-service password reset notification configuration was not found. "
                    "SSPR may not be enabled or may require Microsoft Graph beta API."
                ),
                severity=Severity.MEDIUM,
                status=ComplianceStatus.NOT_ASSESSED,
                domain=CheckDomain.IAM,
                resource_type="Azure::EntraID::SSPR",
                resource_id=rid,
                region=region,
                account_id=subscription_id,
                cloud_provider=CloudProvider.AZURE,
                remediation=(
                    "Enable SSPR and configure notifications: Entra ID > Password reset > "
                    "Notifications > Notify users = Yes, Notify admins = Yes."
                ),
                soc2_controls=["CC6.1"],
                cis_azure_controls=["1.6"],
                details={},
            )
        ]

    both_ok = notify_users is True and notify_admins is True
    return [
        Finding(
            check_id="azure-sspr-notifications",
            title="SSPR notifications configured correctly"
            if both_ok
            else "SSPR notifications incomplete",
            description=(
                "Users are notified on password reset and all admins are notified when "
                "another admin resets their password."
                if both_ok
                else (
                    f"SSPR notifications: notify users={notify_users}, "
                    f"notify admins on admin reset={notify_admins}. "
                    "Both should be enabled."
                )
            ),
            severity=Severity.INFO if both_ok else Severity.MEDIUM,
            status=ComplianceStatus.PASS if both_ok else ComplianceStatus.FAIL,
            domain=CheckDomain.IAM,
            resource_type="Azure::EntraID::SSPR",
            resource_id=rid,
            region=region,
            account_id=subscription_id,
            cloud_provider=CloudProvider.AZURE,
            remediation=""
            if both_ok
            else (
                "Entra ID > Password reset > Notifications > "
                "Notify users on password resets = Yes, "
                "Notify all admins when other admins reset their password = Yes."
            ),
            soc2_controls=["CC6.1"],
            cis_azure_controls=["1.6"],
            details={"notify_users": notify_users, "notify_admins": notify_admins},
        )
    ]


def check_authentication_methods(
    client: AzureClient,
    subscription_id: str,
    region: str,
) -> list[Finding]:
    """[MCSB IM-6] Strong authentication methods (FIDO2 / passwordless) are enabled."""
    rid = f"/tenants/{subscription_id}/authenticationMethods"

    try:
        graph = client.graph_client()
        policy = client.graph_call(graph.policies.authentication_methods_policy.get())
    except Exception:
        return [
            _no_permission_finding(
                "azure-authentication-methods",
                "Cannot check authentication methods policy (insufficient permissions)",
                "Requires Policy.Read.All to read authentication methods policy.",
                subscription_id,
                region,
                "Azure::EntraID::AuthenticationMethodsPolicy",
                rid,
                ["CC6.1"],
                None,
                ["IM-6"],
            )
        ]

    configs = getattr(policy, "authentication_method_configurations", None) or []
    strong_methods: list[str] = []
    for cfg in configs:
        method_id = (getattr(cfg, "id", None) or "").lower()
        state = (getattr(cfg, "state", None) or "").lower()
        if state != "enabled":
            continue
        if method_id in ("fido2", "microsoftauthenticator", "windowshelloforbusiness"):
            strong_methods.append(method_id)

    if strong_methods:
        return [
            Finding(
                check_id="azure-authentication-methods",
                title="Strong authentication methods enabled",
                description=(
                    f"Passwordless / phishing-resistant methods enabled: "
                    f"{', '.join(strong_methods)}."
                ),
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.IAM,
                resource_type="Azure::EntraID::AuthenticationMethodsPolicy",
                resource_id=rid,
                region=region,
                account_id=subscription_id,
                cloud_provider=CloudProvider.AZURE,
                soc2_controls=["CC6.1"],
                mcsb_controls=["IM-6"],
                details={"strong_methods": strong_methods},
            )
        ]

    return [
        Finding(
            check_id="azure-authentication-methods",
            title="No strong authentication methods enabled",
            description=(
                "Neither FIDO2, Microsoft Authenticator (passwordless), nor "
                "Windows Hello for Business is enabled. These methods provide "
                "phishing-resistant authentication."
            ),
            severity=Severity.MEDIUM,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.IAM,
            resource_type="Azure::EntraID::AuthenticationMethodsPolicy",
            resource_id=rid,
            region=region,
            account_id=subscription_id,
            cloud_provider=CloudProvider.AZURE,
            remediation=(
                "Enable FIDO2 or Microsoft Authenticator passwordless: "
                "Entra ID > Security > Authentication methods > Policies > "
                "FIDO2 security key = Enabled (target all users or a pilot group)."
            ),
            soc2_controls=["CC6.1"],
            mcsb_controls=["IM-6"],
            details={"strong_methods": []},
        )
    ]


def check_security_defaults(
    client: AzureClient,
    subscription_id: str,
    region: str,
    *,
    ca_policies: list[Any] | None = None,
) -> list[Finding]:
    """[CIS 2.1] Security defaults are enabled, or Conditional Access is used instead."""
    rid = f"/tenants/{subscription_id}/securityDefaults"

    try:
        graph = client.graph_client()
        sd_policy = client.graph_call(
            graph.policies.identity_security_defaults_enforcement_policy.get()
        )
    except Exception:
        return [
            _no_permission_finding(
                "azure-security-defaults",
                "Cannot check security defaults (insufficient permissions)",
                "Requires Policy.Read.All.",
                subscription_id,
                region,
                "Azure::EntraID::SecurityDefaults",
                rid,
                ["CC6.1"],
                ["2.1.1"],
                None,
            )
        ]

    is_enabled = getattr(sd_policy, "is_enabled", False)

    # If CA policies are active, security defaults being OFF is expected.
    policies = ca_policies if ca_policies is not None else _fetch_ca_policies(client)
    has_ca = bool(policies and any(getattr(p, "state", None) == "enabled" for p in policies))

    if is_enabled:
        return [
            Finding(
                check_id="azure-security-defaults",
                title="Security defaults are enabled",
                description=(
                    "Security defaults enforce baseline MFA and block "
                    "legacy authentication for all users."
                ),
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.IAM,
                resource_type="Azure::EntraID::SecurityDefaults",
                resource_id=rid,
                region=region,
                account_id=subscription_id,
                cloud_provider=CloudProvider.AZURE,
                soc2_controls=["CC6.1"],
                cis_azure_controls=["2.1.1"],
                details={"is_enabled": True, "has_ca_policies": has_ca},
            )
        ]

    if has_ca:
        return [
            Finding(
                check_id="azure-security-defaults",
                title="Security defaults disabled (Conditional Access in use)",
                description=(
                    "Security defaults are disabled but Conditional Access policies are "
                    "active. CA provides equivalent or stronger protection."
                ),
                severity=Severity.INFO,
                status=ComplianceStatus.NOT_APPLICABLE,
                domain=CheckDomain.IAM,
                resource_type="Azure::EntraID::SecurityDefaults",
                resource_id=rid,
                region=region,
                account_id=subscription_id,
                cloud_provider=CloudProvider.AZURE,
                soc2_controls=["CC6.1"],
                cis_azure_controls=["2.1.1"],
                details={"is_enabled": False, "has_ca_policies": True},
            )
        ]

    return [
        Finding(
            check_id="azure-security-defaults",
            title="Security defaults are disabled with no Conditional Access",
            description=(
                "Security defaults are disabled and no Conditional Access policies are "
                "active. The tenant has no baseline MFA or legacy auth blocking."
            ),
            severity=Severity.CRITICAL,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.IAM,
            resource_type="Azure::EntraID::SecurityDefaults",
            resource_id=rid,
            region=region,
            account_id=subscription_id,
            cloud_provider=CloudProvider.AZURE,
            remediation=(
                "Enable security defaults: Entra ID > Properties > Manage security defaults > "
                "Enable security defaults = Yes. Or deploy Conditional Access policies for "
                "MFA and legacy auth blocking."
            ),
            soc2_controls=["CC6.1"],
            cis_azure_controls=["2.1.1"],
            details={"is_enabled": False, "has_ca_policies": False},
        )
    ]


# ===================================================================
# Group C — Application & Consent
# ===================================================================


def check_user_consent_restricted(
    client: AzureClient,
    subscription_id: str,
    region: str,
    *,
    auth_policy: Any | None = None,
) -> list[Finding]:
    """[CIS 1.9 / MCSB IM-8] Users cannot consent to apps accessing company data."""
    policy = auth_policy if auth_policy is not None else _fetch_authorization_policy(client)
    rid = f"/tenants/{subscription_id}/userConsent"

    if policy is None:
        return [
            _no_permission_finding(
                "azure-user-consent-apps",
                "Cannot check user consent settings (insufficient permissions)",
                "Authorization policy could not be read. Requires Policy.Read.All.",
                subscription_id,
                region,
                "Azure::EntraID::AuthorizationPolicy",
                rid,
                ["CC6.1"],
                ["1.11"],
                ["IM-8"],
            )
        ]

    default_perms = getattr(policy, "default_user_role_permissions", None)
    consent_allowed = (
        getattr(default_perms, "permission_grant_policies_assigned", None)
        if default_perms
        else None
    )

    # Restrictive: empty list or only the "low-risk" policy
    if consent_allowed is not None:
        normalized = [str(p).lower() for p in consent_allowed]
        permissive_legacy = any("legacy" in p for p in normalized)
        # "ManagePermissionGrantsForSelf.microsoft-user-default-legacy" is the permissive default
        if not consent_allowed or (
            len(consent_allowed) == 1 and "low" in normalized[0] and not permissive_legacy
        ):
            return [
                Finding(
                    check_id="azure-user-consent-apps",
                    title="User consent to applications is restricted",
                    description=(
                        "Users cannot consent to applications accessing company data, or "
                        "consent is limited to low-risk permissions from verified publishers."
                    ),
                    severity=Severity.INFO,
                    status=ComplianceStatus.PASS,
                    domain=CheckDomain.IAM,
                    resource_type="Azure::EntraID::AuthorizationPolicy",
                    resource_id=rid,
                    region=region,
                    account_id=subscription_id,
                    cloud_provider=CloudProvider.AZURE,
                    soc2_controls=["CC6.1"],
                    cis_azure_controls=["1.11"],
                    mcsb_controls=["IM-8"],
                    details={"permission_grant_policies": consent_allowed},
                )
            ]

    return [
        Finding(
            check_id="azure-user-consent-apps",
            title="Users can consent to applications accessing company data",
            description=(
                "The authorization policy allows users to consent to applications. "
                "Malicious or over-privileged apps can exfiltrate data via OAuth consent "
                "phishing attacks."
            ),
            severity=Severity.HIGH,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.IAM,
            resource_type="Azure::EntraID::AuthorizationPolicy",
            resource_id=rid,
            region=region,
            account_id=subscription_id,
            cloud_provider=CloudProvider.AZURE,
            remediation=(
                "Restrict user consent: Entra ID > Enterprise applications > "
                "Consent and permissions > User consent settings > "
                "Do not allow user consent (or Allow for verified publishers, low-risk only)."
            ),
            soc2_controls=["CC6.1"],
            cis_azure_controls=["1.11"],
            mcsb_controls=["IM-8"],
            details={"permission_grant_policies": consent_allowed},
        )
    ]


def check_app_registration_restricted(
    client: AzureClient,
    subscription_id: str,
    region: str,
    *,
    auth_policy: Any | None = None,
) -> list[Finding]:
    """[CIS 1.11] Users cannot register applications."""
    policy = auth_policy if auth_policy is not None else _fetch_authorization_policy(client)
    rid = f"/tenants/{subscription_id}/appRegistration"

    if policy is None:
        return [
            _no_permission_finding(
                "azure-app-registration-restricted",
                "Cannot check app registration settings (insufficient permissions)",
                "Authorization policy could not be read. Requires Policy.Read.All.",
                subscription_id,
                region,
                "Azure::EntraID::AuthorizationPolicy",
                rid,
                ["CC6.1"],
                ["1.12"],
                None,
            )
        ]

    default_perms = getattr(policy, "default_user_role_permissions", None)
    allowed = getattr(default_perms, "allowed_to_create_apps", None) if default_perms else None

    if allowed is False:
        return [
            Finding(
                check_id="azure-app-registration-restricted",
                title="Users cannot register applications",
                description="Application registration is restricted to admins.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.IAM,
                resource_type="Azure::EntraID::AuthorizationPolicy",
                resource_id=rid,
                region=region,
                account_id=subscription_id,
                cloud_provider=CloudProvider.AZURE,
                soc2_controls=["CC6.1"],
                cis_azure_controls=["1.12"],
                details={"allowed_to_create_apps": False},
            )
        ]

    return [
        Finding(
            check_id="azure-app-registration-restricted",
            title="Users can register applications",
            description=(
                "Any user can register applications in Entra ID. Unrestricted app "
                "registration can lead to excessive app sprawl and shadow IT."
            ),
            severity=Severity.MEDIUM,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.IAM,
            resource_type="Azure::EntraID::AuthorizationPolicy",
            resource_id=rid,
            region=region,
            account_id=subscription_id,
            cloud_provider=CloudProvider.AZURE,
            remediation=(
                "Restrict app registration: Entra ID > User settings > "
                "App registrations > Users can register applications = No."
            ),
            soc2_controls=["CC6.1"],
            cis_azure_controls=["1.12"],
            details={"allowed_to_create_apps": allowed},
        )
    ]


def check_admin_consent_workflow(
    client: AzureClient,
    subscription_id: str,
    region: str,
) -> list[Finding]:
    """[MCSB IM-8] Admin consent workflow is enabled."""
    rid = f"/tenants/{subscription_id}/adminConsent"

    try:
        graph = client.graph_client()
        policy = client.graph_call(graph.policies.admin_consent_request_policy.get())
    except Exception:
        return [
            _no_permission_finding(
                "azure-admin-consent-workflow",
                "Cannot check admin consent workflow (insufficient permissions)",
                "Requires Policy.Read.All to read admin consent request policy.",
                subscription_id,
                region,
                "Azure::EntraID::AdminConsentPolicy",
                rid,
                ["CC6.1"],
                None,
                ["IM-8"],
            )
        ]

    is_enabled = getattr(policy, "is_enabled", False)

    if is_enabled:
        return [
            Finding(
                check_id="azure-admin-consent-workflow",
                title="Admin consent workflow is enabled",
                description=(
                    "Users can request admin consent for apps they cannot consent to, "
                    "providing a governed alternative to shadow consent."
                ),
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.IAM,
                resource_type="Azure::EntraID::AdminConsentPolicy",
                resource_id=rid,
                region=region,
                account_id=subscription_id,
                cloud_provider=CloudProvider.AZURE,
                soc2_controls=["CC6.1"],
                mcsb_controls=["IM-8"],
                details={"is_enabled": True},
            )
        ]

    return [
        Finding(
            check_id="azure-admin-consent-workflow",
            title="Admin consent workflow is disabled",
            description=(
                "Users have no governed way to request admin consent for apps. "
                "Without a workflow, users may seek workarounds or shadow IT solutions."
            ),
            severity=Severity.MEDIUM,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.IAM,
            resource_type="Azure::EntraID::AdminConsentPolicy",
            resource_id=rid,
            region=region,
            account_id=subscription_id,
            cloud_provider=CloudProvider.AZURE,
            remediation=(
                "Enable admin consent workflow: Entra ID > Enterprise applications > "
                "Admin consent settings > Users can request admin consent = Yes, "
                "then configure reviewers."
            ),
            soc2_controls=["CC6.1"],
            mcsb_controls=["IM-8"],
            details={"is_enabled": False},
        )
    ]


# ===================================================================
# Group D — Directory Settings
# ===================================================================


def check_admin_portal_restricted(
    client: AzureClient,
    subscription_id: str,
    region: str,
    *,
    auth_policy: Any | None = None,
) -> list[Finding]:
    """[CIS 1.15] Non-admin access to Entra admin portal is restricted."""
    policy = auth_policy if auth_policy is not None else _fetch_authorization_policy(client)
    rid = f"/tenants/{subscription_id}/adminPortal"

    if policy is None:
        return [
            _no_permission_finding(
                "azure-admin-portal-restricted",
                "Cannot check admin portal restriction (insufficient permissions)",
                "Authorization policy could not be read. Requires Policy.Read.All.",
                subscription_id,
                region,
                "Azure::EntraID::AuthorizationPolicy",
                rid,
                ["CC6.1"],
                ["1.15"],
                None,
            )
        ]

    default_perms = getattr(policy, "default_user_role_permissions", None)
    # allowedToReadOtherUsers is the closest v1.0 proxy; the actual setting
    # is the Entra portal "Restrict access to Azure AD administration portal".
    allowed_to_read = (
        getattr(default_perms, "allowed_to_read_other_users", None) if default_perms else None
    )

    if allowed_to_read is False:
        return [
            Finding(
                check_id="azure-admin-portal-restricted",
                title="Entra admin portal access is restricted to admins",
                description="Non-admin users cannot access the Entra ID administration portal.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.IAM,
                resource_type="Azure::EntraID::AuthorizationPolicy",
                resource_id=rid,
                region=region,
                account_id=subscription_id,
                cloud_provider=CloudProvider.AZURE,
                soc2_controls=["CC6.1"],
                cis_azure_controls=["1.15"],
                details={"allowed_to_read_other_users": False},
            )
        ]

    return [
        Finding(
            check_id="azure-admin-portal-restricted",
            title="Entra admin portal is accessible to non-admin users",
            description=(
                "Non-admin users can access the Entra ID administration portal and "
                "enumerate directory objects. This provides reconnaissance data to "
                "compromised non-admin accounts."
            ),
            severity=Severity.MEDIUM,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.IAM,
            resource_type="Azure::EntraID::AuthorizationPolicy",
            resource_id=rid,
            region=region,
            account_id=subscription_id,
            cloud_provider=CloudProvider.AZURE,
            remediation=(
                "Restrict portal access: Entra ID > User settings > Administration portal > "
                "Restrict access to Microsoft Entra admin center = Yes."
            ),
            soc2_controls=["CC6.1"],
            cis_azure_controls=["1.15"],
            details={"allowed_to_read_other_users": allowed_to_read},
        )
    ]


def check_security_group_creation_restricted(
    client: AzureClient,
    subscription_id: str,
    region: str,
    *,
    auth_policy: Any | None = None,
) -> list[Finding]:
    """[CIS 1.17] Users cannot create security groups."""
    policy = auth_policy if auth_policy is not None else _fetch_authorization_policy(client)
    rid = f"/tenants/{subscription_id}/securityGroupCreation"

    if policy is None:
        return [
            _no_permission_finding(
                "azure-security-group-creation",
                "Cannot check security group creation settings (insufficient permissions)",
                "Authorization policy could not be read. Requires Policy.Read.All.",
                subscription_id,
                region,
                "Azure::EntraID::AuthorizationPolicy",
                rid,
                ["CC6.1"],
                ["1.18"],
                None,
            )
        ]

    default_perms = getattr(policy, "default_user_role_permissions", None)
    allowed = (
        getattr(default_perms, "allowed_to_create_security_groups", None) if default_perms else None
    )

    if allowed is False:
        return [
            Finding(
                check_id="azure-security-group-creation",
                title="Users cannot create security groups",
                description="Security group creation is restricted to admins.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.IAM,
                resource_type="Azure::EntraID::AuthorizationPolicy",
                resource_id=rid,
                region=region,
                account_id=subscription_id,
                cloud_provider=CloudProvider.AZURE,
                soc2_controls=["CC6.1"],
                cis_azure_controls=["1.18"],
                details={"allowed_to_create_security_groups": False},
            )
        ]

    return [
        Finding(
            check_id="azure-security-group-creation",
            title="Users can create security groups",
            description=(
                "Any user can create security groups, which can be used to grant access "
                "to resources. Unrestricted group creation leads to access sprawl."
            ),
            severity=Severity.LOW,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.IAM,
            resource_type="Azure::EntraID::AuthorizationPolicy",
            resource_id=rid,
            region=region,
            account_id=subscription_id,
            cloud_provider=CloudProvider.AZURE,
            remediation=(
                "Restrict group creation: Entra ID > Groups > General > "
                "Users can create security groups in Azure portals, API or PowerShell = No."
            ),
            soc2_controls=["CC6.1"],
            cis_azure_controls=["1.18"],
            details={"allowed_to_create_security_groups": allowed},
        )
    ]


def check_m365_group_creation_restricted(
    client: AzureClient,
    subscription_id: str,
    region: str,
    *,
    dir_settings: list[Any] | None = None,
) -> list[Finding]:
    """[CIS 1.19] Users cannot create Microsoft 365 groups."""
    settings = dir_settings if dir_settings is not None else _fetch_directory_settings(client)
    rid = f"/tenants/{subscription_id}/m365GroupCreation"

    if settings is None:
        return [
            _no_permission_finding(
                "azure-m365-group-creation",
                "Cannot check M365 group creation settings (insufficient permissions)",
                "Directory settings could not be enumerated. Requires Directory.Read.All.",
                subscription_id,
                region,
                "Azure::EntraID::DirectorySettings",
                rid,
                ["CC6.1"],
                ["1.20"],
                None,
            )
        ]

    enable_group_creation = None
    for s in settings:
        display_name = getattr(s, "display_name", None) or ""
        template_id = getattr(s, "template_id", None) or ""
        # Group.Unified template controls M365 group creation
        if (
            "group.unified" not in display_name.lower()
            and "group.unified" not in template_id.lower()
        ):
            continue
        values = getattr(s, "values", None) or []
        for v in values:
            name = (getattr(v, "name", None) or "").lower()
            if name == "enablegroupcreation":
                enable_group_creation = str(getattr(v, "value", "")).lower() == "true"

    if enable_group_creation is None:
        # No Group.Unified setting found — default allows creation
        return [
            Finding(
                check_id="azure-m365-group-creation",
                title="M365 group creation settings not configured",
                description=(
                    "No Group.Unified directory setting found. By default, all users "
                    "can create Microsoft 365 groups."
                ),
                severity=Severity.LOW,
                status=ComplianceStatus.FAIL,
                domain=CheckDomain.IAM,
                resource_type="Azure::EntraID::DirectorySettings",
                resource_id=rid,
                region=region,
                account_id=subscription_id,
                cloud_provider=CloudProvider.AZURE,
                remediation=(
                    "Configure Group.Unified settings via PowerShell or Graph API: "
                    "Set EnableGroupCreation = false and optionally "
                    "GroupCreationAllowedGroupId to a specific group of allowed creators."
                ),
                soc2_controls=["CC6.1"],
                cis_azure_controls=["1.20"],
                details={},
            )
        ]

    if not enable_group_creation:
        return [
            Finding(
                check_id="azure-m365-group-creation",
                title="M365 group creation is restricted",
                description="Only designated users/groups can create Microsoft 365 groups.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.IAM,
                resource_type="Azure::EntraID::DirectorySettings",
                resource_id=rid,
                region=region,
                account_id=subscription_id,
                cloud_provider=CloudProvider.AZURE,
                soc2_controls=["CC6.1"],
                cis_azure_controls=["1.20"],
                details={"enable_group_creation": False},
            )
        ]

    return [
        Finding(
            check_id="azure-m365-group-creation",
            title="All users can create Microsoft 365 groups",
            description=(
                "EnableGroupCreation is true in Group.Unified settings. Any user can "
                "create M365 groups (Teams, SharePoint sites), leading to data sprawl."
            ),
            severity=Severity.LOW,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.IAM,
            resource_type="Azure::EntraID::DirectorySettings",
            resource_id=rid,
            region=region,
            account_id=subscription_id,
            cloud_provider=CloudProvider.AZURE,
            remediation=(
                "Restrict M365 group creation: Set EnableGroupCreation = false in "
                "Group.Unified directory settings. Use GroupCreationAllowedGroupId "
                "to allow a specific security group to create M365 groups."
            ),
            soc2_controls=["CC6.1"],
            cis_azure_controls=["1.20"],
            details={"enable_group_creation": True},
        )
    ]


def check_guest_user_access_restricted(
    client: AzureClient,
    subscription_id: str,
    region: str,
    *,
    auth_policy: Any | None = None,
) -> list[Finding]:
    """[CIS 1.12] Guest user permissions are limited to their own directory objects."""
    policy = auth_policy if auth_policy is not None else _fetch_authorization_policy(client)
    rid = f"/tenants/{subscription_id}/guestAccess"

    if policy is None:
        return [
            _no_permission_finding(
                "azure-guest-access-restrictions",
                "Cannot check guest access restrictions (insufficient permissions)",
                "Authorization policy could not be read. Requires Policy.Read.All.",
                subscription_id,
                region,
                "Azure::EntraID::AuthorizationPolicy",
                rid,
                ["CC6.1", "CC6.3"],
                ["1.5"],
                None,
            )
        ]

    guest_role = str(getattr(policy, "guest_user_role_id", "") or "").lower()

    if guest_role == GUEST_ROLE_RESTRICTED.lower():
        return [
            Finding(
                check_id="azure-guest-access-restrictions",
                title="Guest users restricted to own directory objects",
                description=(
                    "Guest user role is set to the most restrictive level: guests can "
                    "only see their own profile properties."
                ),
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.IAM,
                resource_type="Azure::EntraID::AuthorizationPolicy",
                resource_id=rid,
                region=region,
                account_id=subscription_id,
                cloud_provider=CloudProvider.AZURE,
                soc2_controls=["CC6.1", "CC6.3"],
                cis_azure_controls=["1.5"],
                details={"guest_user_role_id": guest_role},
            )
        ]

    if guest_role == GUEST_ROLE_LIMITED.lower():
        return [
            Finding(
                check_id="azure-guest-access-restrictions",
                title="Guest users have limited access (not most restrictive)",
                description=(
                    "Guest user role is set to limited access. Guests can see membership "
                    "of non-hidden groups. Consider restricting to own properties only."
                ),
                severity=Severity.LOW,
                status=ComplianceStatus.PARTIAL,
                domain=CheckDomain.IAM,
                resource_type="Azure::EntraID::AuthorizationPolicy",
                resource_id=rid,
                region=region,
                account_id=subscription_id,
                cloud_provider=CloudProvider.AZURE,
                remediation=(
                    "Restrict guest access further: Entra ID > External Identities > "
                    "External collaboration settings > Guest user access > "
                    "Guest users have limited access to properties and memberships "
                    "of directory objects (most restrictive)."
                ),
                soc2_controls=["CC6.1", "CC6.3"],
                cis_azure_controls=["1.5"],
                details={"guest_user_role_id": guest_role},
            )
        ]

    return [
        Finding(
            check_id="azure-guest-access-restrictions",
            title="Guest users have same access as members",
            description=(
                "Guest user role is set to the same permissions as member users. "
                "External guests can enumerate all users, groups, and other directory "
                "objects, which is a significant information disclosure risk."
            ),
            severity=Severity.HIGH,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.IAM,
            resource_type="Azure::EntraID::AuthorizationPolicy",
            resource_id=rid,
            region=region,
            account_id=subscription_id,
            cloud_provider=CloudProvider.AZURE,
            remediation=(
                "Restrict guest permissions: Entra ID > External Identities > "
                "External collaboration settings > Guest user access > "
                "Guest users have limited access to properties and memberships "
                "of directory objects."
            ),
            soc2_controls=["CC6.1", "CC6.3"],
            cis_azure_controls=["1.5"],
            details={"guest_user_role_id": guest_role},
        )
    ]


# ===================================================================
# Group E — Privileged Access
# ===================================================================


def check_break_glass_accounts(
    client: AzureClient,
    subscription_id: str,
    region: str,
    *,
    ca_policies: list[Any] | None = None,
) -> list[Finding]:
    """[MCSB PA-5] At least 2 emergency / break-glass Global Admin accounts exist."""
    rid = f"/tenants/{subscription_id}/breakGlass"

    # Step 1: get Global Admin role assignments
    try:
        graph = client.graph_client()
        role_defs = list(
            client.graph_call(graph.role_management.directory.role_definitions.get()).value or []
        )
        role_assignments = list(
            client.graph_call(graph.role_management.directory.role_assignments.get()).value or []
        )
    except Exception:
        return [
            _no_permission_finding(
                "azure-break-glass-accounts",
                "Cannot check break-glass accounts (insufficient permissions)",
                "Requires RoleManagement.Read.Directory and User.Read.All.",
                subscription_id,
                region,
                "Azure::EntraID::BreakGlassAccount",
                rid,
                ["CC6.1"],
                None,
                ["PA-5"],
            )
        ]

    # Find Global Administrator role definition ID
    ga_role_id = None
    for rd in role_defs:
        if getattr(rd, "display_name", None) == "Global Administrator":
            ga_role_id = getattr(rd, "id", None)
            break

    if ga_role_id is None:
        return [
            Finding(
                check_id="azure-break-glass-accounts",
                title="Global Administrator role not found",
                description="Could not locate the Global Administrator role definition.",
                severity=Severity.MEDIUM,
                status=ComplianceStatus.NOT_ASSESSED,
                domain=CheckDomain.IAM,
                resource_type="Azure::EntraID::BreakGlassAccount",
                resource_id=rid,
                region=region,
                account_id=subscription_id,
                cloud_provider=CloudProvider.AZURE,
                soc2_controls=["CC6.1"],
                mcsb_controls=["PA-5"],
                details={},
            )
        ]

    # Collect principal IDs with Global Admin
    ga_principal_ids = [
        getattr(a, "principal_id", None)
        for a in role_assignments
        if getattr(a, "role_definition_id", None) == ga_role_id
    ]

    # Step 2: check which ones look like break-glass accounts
    try:
        users = list(client.graph_call(graph.users.get()).value or [])
    except Exception:
        users = []

    user_map = {getattr(u, "id", None): u for u in users}
    candidates: list[dict[str, Any]] = []
    for pid in ga_principal_ids:
        user = user_map.get(pid)
        if user is None:
            continue
        display_name = (getattr(user, "display_name", None) or "").lower()
        upn = (getattr(user, "user_principal_name", None) or "").lower()
        on_prem_synced = bool(getattr(user, "on_premises_sync_enabled", False))
        # Heuristic: cloud-only + name matches break-glass pattern
        is_candidate = not on_prem_synced and any(
            hint in display_name or hint in upn for hint in BREAK_GLASS_HINTS
        )
        if is_candidate:
            candidates.append(
                {
                    "user_id": pid,
                    "display_name": getattr(user, "display_name", None),
                    "upn": getattr(user, "user_principal_name", None),
                    "cloud_only": not on_prem_synced,
                }
            )

    # Step 3: verify CA policy exclusions for candidates
    policies = ca_policies if ca_policies is not None else _fetch_ca_policies(client)
    excluded_from_ca: list[str] = []
    if policies:
        for c in candidates:
            uid = c["user_id"]
            for p in policies:
                if getattr(p, "state", None) != "enabled":
                    continue
                cond = getattr(p, "conditions", None)
                users_cond = getattr(cond, "users", None) if cond else None
                excludes = getattr(users_cond, "exclude_users", None) if users_cond else None
                if excludes and uid in excludes:
                    excluded_from_ca.append(c["display_name"] or uid)
                    break

    if len(candidates) >= 2:
        return [
            Finding(
                check_id="azure-break-glass-accounts",
                title=f"Break-glass accounts detected ({len(candidates)} found)",
                description=(
                    f"{len(candidates)} cloud-only Global Admin accounts matching "
                    f"break-glass naming conventions found. "
                    f"{len(excluded_from_ca)} are excluded from at least one CA policy."
                ),
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.IAM,
                resource_type="Azure::EntraID::BreakGlassAccount",
                resource_id=rid,
                region=region,
                account_id=subscription_id,
                cloud_provider=CloudProvider.AZURE,
                soc2_controls=["CC6.1"],
                mcsb_controls=["PA-5"],
                details={
                    "candidates": candidates,
                    "excluded_from_ca": excluded_from_ca,
                    "total_global_admins": len(ga_principal_ids),
                },
            )
        ]

    return [
        Finding(
            check_id="azure-break-glass-accounts",
            title=(f"Insufficient break-glass accounts ({len(candidates)} found, need >= 2)"),
            description=(
                f"Only {len(candidates)} cloud-only Global Admin account(s) matching "
                "break-glass naming conventions detected. Microsoft recommends at least "
                "2 emergency access accounts excluded from Conditional Access policies "
                "to prevent tenant lockout."
            ),
            severity=Severity.HIGH,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.IAM,
            resource_type="Azure::EntraID::BreakGlassAccount",
            resource_id=rid,
            region=region,
            account_id=subscription_id,
            cloud_provider=CloudProvider.AZURE,
            remediation=(
                "Create at least 2 cloud-only break-glass accounts with Global Admin role. "
                "Use strong, unique passwords stored securely offline. Exclude from all CA "
                "policies. Name them clearly (e.g., 'Break Glass 1'). "
                "See: https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access"
            ),
            soc2_controls=["CC6.1"],
            mcsb_controls=["PA-5"],
            details={
                "candidates": candidates,
                "total_global_admins": len(ga_principal_ids),
            },
        )
    ]


def check_named_locations(
    client: AzureClient,
    subscription_id: str,
    region: str,
) -> list[Finding]:
    """[MCSB IM-7] Named locations (IP ranges / countries) defined for CA policies."""
    rid = f"/tenants/{subscription_id}/namedLocations"

    try:
        graph = client.graph_client()
        locations = list(
            client.graph_call(graph.identity.conditional_access.named_locations.get()).value or []
        )
    except Exception:
        return [
            _no_permission_finding(
                "azure-named-locations",
                "Cannot check named locations (insufficient permissions)",
                "Requires Policy.Read.All to enumerate named locations.",
                subscription_id,
                region,
                "Azure::EntraID::NamedLocation",
                rid,
                ["CC6.1"],
                None,
                ["IM-7"],
            )
        ]

    if locations:
        names = [getattr(loc, "display_name", None) or "unnamed" for loc in locations]
        return [
            Finding(
                check_id="azure-named-locations",
                title=f"Named locations configured ({len(locations)})",
                description=(
                    f"{len(locations)} named location(s) defined for Conditional Access: "
                    f"{', '.join(names[:10])}{'...' if len(names) > 10 else ''}."
                ),
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.IAM,
                resource_type="Azure::EntraID::NamedLocation",
                resource_id=rid,
                region=region,
                account_id=subscription_id,
                cloud_provider=CloudProvider.AZURE,
                soc2_controls=["CC6.1"],
                mcsb_controls=["IM-7"],
                details={"locations": names},
            )
        ]

    return [
        Finding(
            check_id="azure-named-locations",
            title="No named locations configured",
            description=(
                "No named locations (trusted IP ranges or countries) are defined. "
                "Named locations are required for location-based Conditional Access "
                "policies (e.g., block sign-ins from unexpected countries)."
            ),
            severity=Severity.MEDIUM,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.IAM,
            resource_type="Azure::EntraID::NamedLocation",
            resource_id=rid,
            region=region,
            account_id=subscription_id,
            cloud_provider=CloudProvider.AZURE,
            remediation=(
                "Define named locations: Entra ID > Security > Conditional Access > "
                "Named locations > New location. Add your corporate IP ranges and/or "
                "trusted countries."
            ),
            soc2_controls=["CC6.1"],
            mcsb_controls=["IM-7"],
            details={},
        )
    ]


# ===================================================================
# Group F — Cross-Tenant
# ===================================================================


def check_cross_tenant_access_default(
    client: AzureClient,
    subscription_id: str,
    region: str,
) -> list[Finding]:
    """[MCSB IM-7] Default cross-tenant access is not open to all users and apps."""
    rid = f"/tenants/{subscription_id}/crossTenantAccess"

    try:
        graph = client.graph_client()
        default_policy = client.graph_call(graph.policies.cross_tenant_access_policy.default.get())
    except Exception:
        return [
            _no_permission_finding(
                "azure-cross-tenant-access",
                "Cannot check cross-tenant access policy (insufficient permissions)",
                "Requires Policy.Read.All to read cross-tenant access settings.",
                subscription_id,
                region,
                "Azure::EntraID::CrossTenantAccessPolicy",
                rid,
                ["CC6.1", "CC6.3"],
                None,
                ["IM-7"],
            )
        ]

    # Check inbound B2B collaboration defaults
    inbound = getattr(default_policy, "b2b_collaboration_inbound", None)
    inbound_apps = getattr(inbound, "applications", None) if inbound else None
    inbound_users = getattr(inbound, "users_and_groups", None) if inbound else None

    inbound_apps_type = getattr(inbound_apps, "access_type", None) if inbound_apps else None
    inbound_users_type = getattr(inbound_users, "access_type", None) if inbound_users else None

    # "allowed" with no specific targets means all apps/users from any tenant
    is_open = (
        str(inbound_apps_type).lower() == "allowed" and str(inbound_users_type).lower() == "allowed"
    )

    if not is_open:
        return [
            Finding(
                check_id="azure-cross-tenant-access",
                title="Cross-tenant inbound access is restricted",
                description=(
                    "Default cross-tenant B2B collaboration inbound policy is not open "
                    "to all external users and applications."
                ),
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.IAM,
                resource_type="Azure::EntraID::CrossTenantAccessPolicy",
                resource_id=rid,
                region=region,
                account_id=subscription_id,
                cloud_provider=CloudProvider.AZURE,
                soc2_controls=["CC6.1", "CC6.3"],
                mcsb_controls=["IM-7"],
                details={
                    "inbound_apps_access_type": str(inbound_apps_type),
                    "inbound_users_access_type": str(inbound_users_type),
                },
            )
        ]

    return [
        Finding(
            check_id="azure-cross-tenant-access",
            title="Cross-tenant inbound access is open to all",
            description=(
                "Default cross-tenant B2B collaboration allows all external users and "
                "all applications from any Azure AD tenant. This can lead to "
                "unauthorized external access."
            ),
            severity=Severity.MEDIUM,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.IAM,
            resource_type="Azure::EntraID::CrossTenantAccessPolicy",
            resource_id=rid,
            region=region,
            account_id=subscription_id,
            cloud_provider=CloudProvider.AZURE,
            remediation=(
                "Restrict cross-tenant access: Entra ID > External Identities > "
                "Cross-tenant access settings > Default settings > Edit inbound defaults > "
                "Block by default, then add organisation-specific allow rules."
            ),
            soc2_controls=["CC6.1", "CC6.3"],
            mcsb_controls=["IM-7"],
            details={
                "inbound_apps_access_type": str(inbound_apps_type),
                "inbound_users_access_type": str(inbound_users_type),
            },
        )
    ]
