"""IAM security checks for SOC 2 compliance.

Covers:
  CC6.1 — Logical access security (MFA, password policy, root account)
  CC6.2 — Access provisioning (least privilege, group membership, user inventory)
  CC6.3 — Access removal (stale keys, inactive users, unused credentials)
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta
from typing import Any

from shasta.aws.client import AWSClient
from shasta.evidence.models import CheckDomain, ComplianceStatus, Finding, Severity

# Thresholds
ACCESS_KEY_MAX_AGE_DAYS = 90
INACTIVE_USER_DAYS = 90
OVERPRIVILEGED_POLICIES = {
    "arn:aws:iam::aws:policy/AdministratorAccess",
    "arn:aws:iam::aws:policy/IAMFullAccess",
    "arn:aws:iam::aws:policy/PowerUserAccess",
}


def run_all_iam_checks(client: AWSClient) -> list[Finding]:
    """Run all IAM compliance checks and return findings."""
    findings: list[Finding] = []
    account_id = client.account_info.account_id if client.account_info else "unknown"
    region = client.account_info.region if client.account_info else "us-east-1"

    iam = client.client("iam")

    findings.extend(check_password_policy(iam, account_id, region))
    findings.extend(check_root_account(iam, account_id, region))
    findings.extend(check_root_account_activity(iam, account_id, region))
    findings.extend(check_user_mfa(iam, account_id, region))
    findings.extend(check_access_key_rotation(iam, account_id, region))
    findings.extend(check_inactive_users(iam, account_id, region))
    findings.extend(check_user_direct_policies(iam, account_id, region))
    findings.extend(check_overprivileged_users(iam, account_id, region))
    findings.extend(check_iam_policy_wildcards(iam, account_id, region))
    findings.extend(check_iam_role_trust_external_account(iam, account_id, region))
    findings.extend(check_iam_unused_roles(iam, account_id, region))

    return findings


# IAM is a global service — these new checks below do NOT iterate regions.
# The existing run_all_iam_checks() above is called once with the original
# client (the scanner.py wiring already treats IAM as a global domain).

UNUSED_ROLE_DAYS_THRESHOLD = 90


def check_password_policy(iam: Any, account_id: str, region: str) -> list[Finding]:
    """CC6.1 — Check that the account password policy meets minimum standards."""
    try:
        policy = iam.get_account_password_policy()["PasswordPolicy"]
    except iam.exceptions.NoSuchEntityException:
        return [
            Finding(
                check_id="iam-password-policy",
                title="No IAM password policy configured",
                description="The AWS account has no custom password policy. The default policy is weak and does not meet SOC 2 requirements.",
                severity=Severity.HIGH,
                status=ComplianceStatus.FAIL,
                domain=CheckDomain.IAM,
                resource_type="AWS::IAM::AccountPasswordPolicy",
                resource_id=f"arn:aws:iam::{account_id}:account-password-policy",
                region=region,
                account_id=account_id,
                remediation="Set a password policy requiring minimum 14 characters, uppercase, lowercase, numbers, symbols, and 90-day rotation.",
                soc2_controls=["CC6.1"],
                details={"policy_exists": False},
            )
        ]

    issues = []
    if policy.get("MinimumPasswordLength", 0) < 14:
        issues.append(f"Minimum length is {policy.get('MinimumPasswordLength', 0)}, should be 14+")
    if not policy.get("RequireUppercaseCharacters", False):
        issues.append("Uppercase characters not required")
    if not policy.get("RequireLowercaseCharacters", False):
        issues.append("Lowercase characters not required")
    if not policy.get("RequireNumbers", False):
        issues.append("Numbers not required")
    if not policy.get("RequireSymbols", False):
        issues.append("Symbols not required")
    if policy.get("MaxPasswordAge", 0) == 0:
        issues.append("Password expiration not enforced")
    if policy.get("PasswordReusePrevention", 0) < 12:
        issues.append(
            f"Password reuse prevention is {policy.get('PasswordReusePrevention', 0)}, should be 12+"
        )

    if issues:
        status = ComplianceStatus.FAIL if len(issues) >= 3 else ComplianceStatus.PARTIAL
        return [
            Finding(
                check_id="iam-password-policy",
                title="IAM password policy does not meet SOC 2 standards",
                description=f"Password policy has {len(issues)} issue(s): {'; '.join(issues)}",
                severity=Severity.HIGH,
                status=status,
                domain=CheckDomain.IAM,
                resource_type="AWS::IAM::AccountPasswordPolicy",
                resource_id=f"arn:aws:iam::{account_id}:account-password-policy",
                region=region,
                account_id=account_id,
                remediation="Update the password policy to require minimum 14 characters, all character types, 90-day expiration, and 12-password reuse prevention.",
                soc2_controls=["CC6.1"],
                details={"policy": policy, "issues": issues},
            )
        ]

    return [
        Finding(
            check_id="iam-password-policy",
            title="IAM password policy meets SOC 2 standards",
            description="The account password policy meets all minimum requirements for SOC 2 compliance.",
            severity=Severity.INFO,
            status=ComplianceStatus.PASS,
            domain=CheckDomain.IAM,
            resource_type="AWS::IAM::AccountPasswordPolicy",
            resource_id=f"arn:aws:iam::{account_id}:account-password-policy",
            region=region,
            account_id=account_id,
            soc2_controls=["CC6.1"],
            details={"policy": policy},
        )
    ]


def check_root_account(iam: Any, account_id: str, region: str) -> list[Finding]:
    """CC6.1 — Check root account security (MFA, access keys)."""
    findings = []
    summary = iam.get_account_summary()["SummaryMap"]

    # Root MFA
    root_mfa = summary.get("AccountMFAEnabled", 0) == 1
    findings.append(
        Finding(
            check_id="iam-root-mfa",
            title="Root account MFA is enabled" if root_mfa else "Root account MFA is NOT enabled",
            description=(
                "The root account has MFA enabled."
                if root_mfa
                else "The root account does not have MFA enabled. This is a critical security risk — the root account has unrestricted access to all AWS resources."
            ),
            severity=Severity.INFO if root_mfa else Severity.CRITICAL,
            status=ComplianceStatus.PASS if root_mfa else ComplianceStatus.FAIL,
            domain=CheckDomain.IAM,
            resource_type="AWS::IAM::RootAccount",
            resource_id=f"arn:aws:iam::{account_id}:root",
            region=region,
            account_id=account_id,
            remediation=""
            if root_mfa
            else "Enable MFA on the root account immediately. Use a hardware MFA device for maximum security.",
            soc2_controls=["CC6.1"],
            details={"mfa_enabled": root_mfa},
        )
    )

    # Root access keys
    # We check via credential report for root access keys
    try:
        _generate_credential_report(iam)
        report = _parse_credential_report(iam)
        root_entry = next((u for u in report if u["user"] == "<root_account>"), None)
        if root_entry:
            has_keys = (
                root_entry.get("access_key_1_active", "false") == "true"
                or root_entry.get("access_key_2_active", "false") == "true"
            )
            if has_keys:
                findings.append(
                    Finding(
                        check_id="iam-root-access-keys",
                        title="Root account has active access keys",
                        description="The root account has active access keys. Root access keys should be deleted — use IAM users or roles instead.",
                        severity=Severity.CRITICAL,
                        status=ComplianceStatus.FAIL,
                        domain=CheckDomain.IAM,
                        resource_type="AWS::IAM::RootAccount",
                        resource_id=f"arn:aws:iam::{account_id}:root",
                        region=region,
                        account_id=account_id,
                        remediation="Delete root account access keys. Create IAM users or roles for programmatic access.",
                        soc2_controls=["CC6.1"],
                        details={
                            "access_key_1_active": root_entry.get("access_key_1_active"),
                            "access_key_2_active": root_entry.get("access_key_2_active"),
                        },
                    )
                )
    except Exception:
        pass  # Credential report may not be available

    return findings


# Threshold for flagging recent root account usage
ROOT_RECENT_USE_DAYS = 90


def check_root_account_activity(iam: Any, account_id: str, region: str) -> list[Finding]:
    """CC6.1/CC6.3 — Check whether the root account has been used recently.

    Reads password_last_used and access_key_last_used_date from the credential
    report's <root_account> entry. Any usage in the last 90 days is flagged
    HIGH because root should be used only for break-glass / billing tasks.
    """
    findings: list[Finding] = []
    try:
        _generate_credential_report(iam)
        report = _parse_credential_report(iam)
    except Exception:
        return findings

    root_entry = next((u for u in report if u["user"] == "<root_account>"), None)
    if not root_entry:
        return findings

    now = datetime.now(timezone.utc)
    threshold = now - timedelta(days=ROOT_RECENT_USE_DAYS)

    last_activity: datetime | None = None
    activity_sources: list[str] = []

    pwd_last_used = root_entry.get("password_last_used", "N/A")
    if pwd_last_used not in ("N/A", "no_information", "not_supported", ""):
        try:
            pwd_date = datetime.fromisoformat(pwd_last_used.replace("Z", "+00:00"))
            if last_activity is None or pwd_date > last_activity:
                last_activity = pwd_date
            activity_sources.append(f"console login on {pwd_date.date().isoformat()}")
        except (ValueError, TypeError):
            pass

    for key_num in ("1", "2"):
        key_active = root_entry.get(f"access_key_{key_num}_active", "false")
        key_last_used = root_entry.get(f"access_key_{key_num}_last_used_date", "N/A")
        if key_active == "true" and key_last_used not in ("N/A", "no_information", ""):
            try:
                key_date = datetime.fromisoformat(key_last_used.replace("Z", "+00:00"))
                if last_activity is None or key_date > last_activity:
                    last_activity = key_date
                activity_sources.append(f"access key {key_num} on {key_date.date().isoformat()}")
            except (ValueError, TypeError):
                pass

    if last_activity is None:
        findings.append(
            Finding(
                check_id="iam-root-not-used",
                title="Root account has no recorded recent usage",
                description="The root account has no record of recent console logins or access key usage. This is the desired state — root should be used only for break-glass scenarios.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.IAM,
                resource_type="AWS::IAM::RootAccount",
                resource_id=f"arn:aws:iam::{account_id}:root",
                region=region,
                account_id=account_id,
                soc2_controls=["CC6.1", "CC6.3"],
                details={"sources_checked": ["password_last_used", "access_key_last_used_date"]},
            )
        )
        return findings

    days_ago = (now - last_activity).days
    is_recent = last_activity >= threshold

    if is_recent:
        findings.append(
            Finding(
                check_id="iam-root-not-used",
                title=f"Root account was used {days_ago} day(s) ago",
                description=(
                    f"The root account has been used recently ({'; '.join(activity_sources)}). "
                    "Root should be reserved for break-glass / billing tasks only — day-to-day "
                    "operations should use IAM users or roles. SOC 2 CC6.1/CC6.3 expects root usage "
                    "to be rare, audited, and alerted on."
                ),
                severity=Severity.HIGH,
                status=ComplianceStatus.FAIL,
                domain=CheckDomain.IAM,
                resource_type="AWS::IAM::RootAccount",
                resource_id=f"arn:aws:iam::{account_id}:root",
                region=region,
                account_id=account_id,
                remediation=(
                    "Audit recent root activity in CloudTrail (filter userIdentity.type=Root). "
                    "Move whatever the root account was doing to an IAM user or role with scoped "
                    "permissions. Set up a CloudWatch alarm on RootAccountUsage metric and "
                    "ensure root credentials are stored in a vault with break-glass procedures."
                ),
                soc2_controls=["CC6.1", "CC6.3"],
                details={
                    "days_since_last_use": days_ago,
                    "last_activity_iso": last_activity.isoformat(),
                    "activity_sources": activity_sources,
                    "threshold_days": ROOT_RECENT_USE_DAYS,
                },
            )
        )
    else:
        findings.append(
            Finding(
                check_id="iam-root-not-used",
                title=f"Root account last used {days_ago} day(s) ago (outside threshold)",
                description=f"Root was last used {days_ago} days ago — outside the {ROOT_RECENT_USE_DAYS}-day recency window.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.IAM,
                resource_type="AWS::IAM::RootAccount",
                resource_id=f"arn:aws:iam::{account_id}:root",
                region=region,
                account_id=account_id,
                soc2_controls=["CC6.1", "CC6.3"],
                details={
                    "days_since_last_use": days_ago,
                    "last_activity_iso": last_activity.isoformat(),
                    "threshold_days": ROOT_RECENT_USE_DAYS,
                },
            )
        )

    return findings


def check_user_mfa(iam: Any, account_id: str, region: str) -> list[Finding]:
    """CC6.1 — Check that all IAM users with console access have MFA enabled."""
    findings = []
    users = _get_all_users(iam)

    for user in users:
        username = user["UserName"]

        # Check if user has console access (login profile)
        has_console = False
        try:
            iam.get_login_profile(UserName=username)
            has_console = True
        except iam.exceptions.NoSuchEntityException:
            pass

        if not has_console:
            continue

        # Check MFA devices
        mfa_devices = iam.list_mfa_devices(UserName=username)["MFADevices"]
        has_mfa = len(mfa_devices) > 0

        findings.append(
            Finding(
                check_id="iam-user-mfa",
                title=f"MFA {'enabled' if has_mfa else 'NOT enabled'} for user '{username}'",
                description=(
                    f"IAM user '{username}' has console access and MFA is {'enabled' if has_mfa else 'not enabled'}."
                    + (
                        ""
                        if has_mfa
                        else " Users with console access must have MFA to meet SOC 2 requirements."
                    )
                ),
                severity=Severity.INFO if has_mfa else Severity.HIGH,
                status=ComplianceStatus.PASS if has_mfa else ComplianceStatus.FAIL,
                domain=CheckDomain.IAM,
                resource_type="AWS::IAM::User",
                resource_id=user["Arn"],
                region=region,
                account_id=account_id,
                remediation=""
                if has_mfa
                else f"Enable MFA for user '{username}'. Virtual MFA (authenticator app) or hardware MFA are both acceptable.",
                soc2_controls=["CC6.1"],
                details={
                    "username": username,
                    "has_console_access": True,
                    "mfa_enabled": has_mfa,
                    "mfa_device_count": len(mfa_devices),
                },
            )
        )

    return findings


def check_access_key_rotation(iam: Any, account_id: str, region: str) -> list[Finding]:
    """CC6.3 — Check that access keys are rotated within the threshold."""
    findings = []
    users = _get_all_users(iam)
    now = datetime.now(timezone.utc)

    for user in users:
        username = user["UserName"]
        keys = iam.list_access_keys(UserName=username)["AccessKeyMetadata"]

        for key in keys:
            if key["Status"] != "Active":
                continue

            key_age = now - key["CreateDate"]
            age_days = key_age.days
            key_id = key["AccessKeyId"]

            if age_days > ACCESS_KEY_MAX_AGE_DAYS:
                findings.append(
                    Finding(
                        check_id="iam-access-key-rotation",
                        title=f"Access key for '{username}' is {age_days} days old",
                        description=f"Access key {key_id} for user '{username}' was created {age_days} days ago and has not been rotated. Keys should be rotated every {ACCESS_KEY_MAX_AGE_DAYS} days.",
                        severity=Severity.HIGH if age_days > 180 else Severity.MEDIUM,
                        status=ComplianceStatus.FAIL,
                        domain=CheckDomain.IAM,
                        resource_type="AWS::IAM::AccessKey",
                        resource_id=f"arn:aws:iam::{account_id}:user/{username}/accesskey/{key_id}",
                        region=region,
                        account_id=account_id,
                        remediation=f"Rotate access key {key_id} for user '{username}'. Create a new key, update applications, then deactivate and delete the old key.",
                        soc2_controls=["CC6.3"],
                        details={
                            "username": username,
                            "access_key_id": key_id,
                            "age_days": age_days,
                            "created": key["CreateDate"].isoformat(),
                        },
                    )
                )
            else:
                findings.append(
                    Finding(
                        check_id="iam-access-key-rotation",
                        title=f"Access key for '{username}' is within rotation policy ({age_days} days)",
                        description=f"Access key {key_id} for user '{username}' is {age_days} days old, within the {ACCESS_KEY_MAX_AGE_DAYS}-day rotation policy.",
                        severity=Severity.INFO,
                        status=ComplianceStatus.PASS,
                        domain=CheckDomain.IAM,
                        resource_type="AWS::IAM::AccessKey",
                        resource_id=f"arn:aws:iam::{account_id}:user/{username}/accesskey/{key_id}",
                        region=region,
                        account_id=account_id,
                        soc2_controls=["CC6.3"],
                        details={
                            "username": username,
                            "access_key_id": key_id,
                            "age_days": age_days,
                            "created": key["CreateDate"].isoformat(),
                        },
                    )
                )

    return findings


def check_inactive_users(iam: Any, account_id: str, region: str) -> list[Finding]:
    """CC6.3 — Check for users who haven't been active recently."""
    findings = []
    now = datetime.now(timezone.utc)
    threshold = now - timedelta(days=INACTIVE_USER_DAYS)

    try:
        _generate_credential_report(iam)
        report = _parse_credential_report(iam)
    except Exception as e:
        return [Finding.not_assessed(
            check_id="iam-inactive-user",
            title="Unable to check inactive users",
            description=f"API call failed: {e}",
            domain=CheckDomain.IAM,
            resource_type="AWS::IAM::User",
            account_id=account_id,
            region=region,
        )]

    for entry in report:
        if entry["user"] == "<root_account>":
            continue

        username = entry["user"]
        arn = entry.get("arn", f"arn:aws:iam::{account_id}:user/{username}")

        # Determine last activity
        last_activity = None
        activity_source = "never"

        password_last_used = entry.get("password_last_used", "N/A")
        if password_last_used not in ("N/A", "no_information", "not_supported"):
            try:
                pwd_date = datetime.fromisoformat(password_last_used.replace("Z", "+00:00"))
                if last_activity is None or pwd_date > last_activity:
                    last_activity = pwd_date
                    activity_source = "console login"
            except (ValueError, TypeError):
                pass

        for key_num in ("1", "2"):
            key_active = entry.get(f"access_key_{key_num}_active", "false")
            key_last_used = entry.get(f"access_key_{key_num}_last_used_date", "N/A")
            if key_active == "true" and key_last_used not in ("N/A", "no_information"):
                try:
                    key_date = datetime.fromisoformat(key_last_used.replace("Z", "+00:00"))
                    if last_activity is None or key_date > last_activity:
                        last_activity = key_date
                        activity_source = f"access key {key_num}"
                except (ValueError, TypeError):
                    pass

        if last_activity is None:
            # User was created but never used — check creation date
            user_creation = entry.get("user_creation_time", "")
            try:
                created = datetime.fromisoformat(user_creation.replace("Z", "+00:00"))
                if created < threshold:
                    findings.append(
                        Finding(
                            check_id="iam-inactive-user",
                            title=f"User '{username}' has never been active",
                            description=f"IAM user '{username}' was created but has never logged in or used access keys. Unused accounts should be removed.",
                            severity=Severity.MEDIUM,
                            status=ComplianceStatus.FAIL,
                            domain=CheckDomain.IAM,
                            resource_type="AWS::IAM::User",
                            resource_id=arn,
                            region=region,
                            account_id=account_id,
                            remediation=f"Review whether user '{username}' is still needed. If not, disable or delete the account.",
                            soc2_controls=["CC6.3"],
                            details={
                                "username": username,
                                "last_activity": None,
                                "created": user_creation,
                            },
                        )
                    )
            except (ValueError, TypeError):
                pass
        elif last_activity < threshold:
            days_inactive = (now - last_activity).days
            findings.append(
                Finding(
                    check_id="iam-inactive-user",
                    title=f"User '{username}' has been inactive for {days_inactive} days",
                    description=f"IAM user '{username}' was last active {days_inactive} days ago (via {activity_source}). Inactive accounts should be reviewed and removed.",
                    severity=Severity.MEDIUM,
                    status=ComplianceStatus.FAIL,
                    domain=CheckDomain.IAM,
                    resource_type="AWS::IAM::User",
                    resource_id=arn,
                    region=region,
                    account_id=account_id,
                    remediation=f"Review whether user '{username}' still needs access. If not, disable credentials and delete the account.",
                    soc2_controls=["CC6.3"],
                    details={
                        "username": username,
                        "last_activity": last_activity.isoformat(),
                        "activity_source": activity_source,
                        "days_inactive": days_inactive,
                    },
                )
            )

    return findings


def check_user_direct_policies(iam: Any, account_id: str, region: str) -> list[Finding]:
    """CC6.2 — Check that users don't have policies attached directly (should use groups/roles)."""
    findings = []
    users = _get_all_users(iam)

    for user in users:
        username = user["UserName"]
        arn = user["Arn"]

        attached = iam.list_attached_user_policies(UserName=username)["AttachedPolicies"]
        inline = iam.list_user_policies(UserName=username)["PolicyNames"]

        direct_policies = [p["PolicyName"] for p in attached] + list(inline)

        if direct_policies:
            findings.append(
                Finding(
                    check_id="iam-no-direct-policies",
                    title=f"User '{username}' has {len(direct_policies)} direct policy attachment(s)",
                    description=f"IAM user '{username}' has policies attached directly: {', '.join(direct_policies)}. Best practice is to assign permissions through groups or roles for easier management and auditing.",
                    severity=Severity.MEDIUM,
                    status=ComplianceStatus.FAIL,
                    domain=CheckDomain.IAM,
                    resource_type="AWS::IAM::User",
                    resource_id=arn,
                    region=region,
                    account_id=account_id,
                    remediation=f"Move direct policies for '{username}' to an IAM group. Add the user to the group instead of attaching policies directly.",
                    soc2_controls=["CC6.2"],
                    details={
                        "username": username,
                        "attached_policies": [p["PolicyName"] for p in attached],
                        "inline_policies": list(inline),
                    },
                )
            )

    return findings


def check_overprivileged_users(iam: Any, account_id: str, region: str) -> list[Finding]:
    """CC6.2 — Check for users with overly broad permissions (admin-level policies)."""
    findings = []
    users = _get_all_users(iam)

    for user in users:
        username = user["UserName"]
        arn = user["Arn"]

        # Check directly attached policies
        attached = iam.list_attached_user_policies(UserName=username)["AttachedPolicies"]
        dangerous_direct = [
            p["PolicyName"] for p in attached if p["PolicyArn"] in OVERPRIVILEGED_POLICIES
        ]

        # Check group policies
        groups = iam.list_groups_for_user(UserName=username)["Groups"]
        dangerous_group = []
        for group in groups:
            group_policies = iam.list_attached_group_policies(GroupName=group["GroupName"])[
                "AttachedPolicies"
            ]
            dangerous_group.extend(
                f"{p['PolicyName']} (via group '{group['GroupName']}')"
                for p in group_policies
                if p["PolicyArn"] in OVERPRIVILEGED_POLICIES
            )

        all_dangerous = dangerous_direct + dangerous_group
        if all_dangerous:
            findings.append(
                Finding(
                    check_id="iam-overprivileged-user",
                    title=f"User '{username}' has overly broad permissions",
                    description=f"IAM user '{username}' has admin-level policies: {', '.join(all_dangerous)}. This violates the principle of least privilege.",
                    severity=Severity.HIGH,
                    status=ComplianceStatus.FAIL,
                    domain=CheckDomain.IAM,
                    resource_type="AWS::IAM::User",
                    resource_id=arn,
                    region=region,
                    account_id=account_id,
                    remediation=f"Replace admin-level policies for '{username}' with scoped policies that grant only the permissions needed for their role.",
                    soc2_controls=["CC6.2"],
                    details={"username": username, "dangerous_policies": all_dangerous},
                )
            )

    return findings


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_all_users(iam: Any) -> list[dict]:
    """Get all IAM users, handling pagination."""
    users = []
    paginator = iam.get_paginator("list_users")
    for page in paginator.paginate():
        users.extend(page["Users"])
    return users


def _generate_credential_report(iam: Any) -> None:
    """Generate a credential report, waiting until complete."""
    import time

    for _ in range(10):
        response = iam.generate_credential_report()
        if response["State"] == "COMPLETE":
            return
        time.sleep(1)


def _parse_credential_report(iam: Any) -> list[dict]:
    """Parse the IAM credential report CSV into a list of dicts."""
    import csv
    import io

    response = iam.get_credential_report()
    content = response["Content"].decode("utf-8")
    reader = csv.DictReader(io.StringIO(content))
    return list(reader)


# ---------------------------------------------------------------------------
# CIS AWS v3.0 IAM checks (Stage 1 of the AWS parity sweep)
# ---------------------------------------------------------------------------


def check_iam_policy_wildcards(
    iam: Any, account_id: str, region: str
) -> list[Finding]:
    """[CIS AWS 1.16] Customer-managed IAM policies should not grant Action='*' on Resource='*'.

    Mirrors Azure's check_custom_role_wildcards. A customer-managed policy
    that allows Action='*' on Resource='*' is functionally equivalent to
    AdministratorAccess but easier to miss in access reviews because it
    doesn't carry the well-known name.
    """
    import json as _json

    try:
        paginator = iam.get_paginator("list_policies")
        custom_policies = []
        for page in paginator.paginate(Scope="Local", OnlyAttached=False):
            custom_policies.extend(page.get("Policies", []))
    except Exception as e:
        return [Finding.not_assessed(
            check_id="iam-policy-wildcards",
            title="Unable to check IAM policy wildcards",
            description=f"API call failed: {e}",
            domain=CheckDomain.IAM,
            resource_type="AWS::IAM::ManagedPolicy",
            account_id=account_id,
            region=region,
        )]

    if not custom_policies:
        return []

    offenders: list[dict] = []
    reviewed = 0
    for policy in custom_policies:
        arn = policy.get("Arn")
        version_id = policy.get("DefaultVersionId")
        if not arn or not version_id:
            continue
        try:
            version = iam.get_policy_version(PolicyArn=arn, VersionId=version_id)
            doc = version.get("PolicyVersion", {}).get("Document")
        except Exception:
            continue
        if isinstance(doc, str):
            try:
                doc = _json.loads(doc)
            except _json.JSONDecodeError:
                continue
        if not isinstance(doc, dict):
            continue
        reviewed += 1

        statements = doc.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        for stmt in statements:
            if stmt.get("Effect") != "Allow":
                continue
            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            resources = stmt.get("Resource", [])
            if isinstance(resources, str):
                resources = [resources]
            if "*" in actions and ("*" in resources or not resources):
                offenders.append(
                    {
                        "policy_name": policy.get("PolicyName"),
                        "arn": arn,
                        "attachment_count": policy.get("AttachmentCount", 0),
                    }
                )
                break

    if not offenders:
        return [
            Finding(
                check_id="iam-policy-wildcards",
                title=f"All {reviewed} customer-managed IAM policies are scoped",
                description="No customer-managed policy grants Action='*' on Resource='*'.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.IAM,
                resource_type="AWS::IAM::ManagedPolicy",
                resource_id=f"arn:aws:iam::{account_id}:policy/*",
                region=region,
                account_id=account_id,
                soc2_controls=["CC6.1", "CC6.2"],
                cis_aws_controls=["1.16"],
            )
        ]
    return [
        Finding(
            check_id="iam-policy-wildcards",
            title=f"{len(offenders)} customer-managed IAM policy(ies) grant wildcard Action+Resource",
            description=(
                f"{len(offenders)} customer-managed policy(ies) allow Action='*' on Resource='*'. "
                "These are functionally equivalent to AdministratorAccess but bypass access "
                "reviews that filter on the well-known admin policy name. Identify which "
                "principals these policies are attached to (the attachment_count field shows "
                "how many users/roles/groups have them) and replace with scoped policies that "
                "list only the actions actually used."
            ),
            severity=Severity.HIGH,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.IAM,
            resource_type="AWS::IAM::ManagedPolicy",
            resource_id=f"arn:aws:iam::{account_id}:policy/*",
            region=region,
            account_id=account_id,
            remediation=(
                "For each policy: review where it's attached, generate a scoped replacement "
                "from CloudTrail data via IAM Access Analyzer policy generation, then detach "
                "the wildcard policy. If the role genuinely needs full admin, use the built-in "
                "AdministratorAccess policy so access reviews can spot it."
            ),
            soc2_controls=["CC6.1", "CC6.2"],
            cis_aws_controls=["1.16"],
            details={"wildcard_policies": offenders[:20]},
        )
    ]


def check_iam_role_trust_external_account(
    iam: Any, account_id: str, region: str
) -> list[Finding]:
    """IAM roles trusting external AWS accounts should require an ExternalId condition.

    The "confused deputy" attack: a third-party SaaS holds an IAM role that
    can assume your role. If the SaaS is compromised, the attacker can pivot
    into your account. The fix is to require an ExternalId condition that the
    SaaS must include in their AssumeRole call - guessing the ExternalId is
    cryptographically infeasible.
    """
    import json as _json

    try:
        paginator = iam.get_paginator("list_roles")
        roles = []
        for page in paginator.paginate():
            roles.extend(page.get("Roles", []))
    except Exception as e:
        return [Finding.not_assessed(
            check_id="iam-role-trust-external",
            title="Unable to check IAM role trust policies",
            description=f"API call failed: {e}",
            domain=CheckDomain.IAM,
            resource_type="AWS::IAM::Role",
            account_id=account_id,
            region=region,
        )]

    if not roles:
        return []

    offenders: list[dict] = []
    own_account_principal = f"arn:aws:iam::{account_id}:"
    for role in roles:
        path = role.get("Path", "/")
        if path.startswith("/aws-service-role/") or path.startswith("/service-role/"):
            continue
        doc = role.get("AssumeRolePolicyDocument")
        if isinstance(doc, str):
            try:
                doc = _json.loads(doc)
            except _json.JSONDecodeError:
                continue
        if not isinstance(doc, dict):
            continue

        for stmt in doc.get("Statement", []):
            if stmt.get("Effect") != "Allow":
                continue
            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            if not any(a in ("sts:AssumeRole", "sts:*") for a in actions):
                continue
            principal = stmt.get("Principal", {})
            aws_principals = principal.get("AWS", []) if isinstance(principal, dict) else []
            if isinstance(aws_principals, str):
                aws_principals = [aws_principals]
            external = [
                p
                for p in aws_principals
                if isinstance(p, str) and not p.startswith(own_account_principal) and p != "*"
            ]
            if not external:
                continue
            cond = stmt.get("Condition", {}) or {}
            has_external_id = (
                "StringEquals" in cond
                and "sts:ExternalId" in cond.get("StringEquals", {})
            ) or (
                "StringLike" in cond
                and "sts:ExternalId" in cond.get("StringLike", {})
            )
            if not has_external_id:
                offenders.append(
                    {
                        "role_name": role.get("RoleName"),
                        "arn": role.get("Arn"),
                        "external_principals": external,
                    }
                )
                break

    if not offenders:
        return [
            Finding(
                check_id="iam-role-trust-external",
                title="All cross-account IAM roles use ExternalId conditions",
                description="Every role trusting an external AWS account carries an sts:ExternalId condition.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.IAM,
                resource_type="AWS::IAM::Role",
                resource_id=f"arn:aws:iam::{account_id}:role/*",
                region=region,
                account_id=account_id,
                soc2_controls=["CC6.1", "CC6.2"],
                cis_aws_controls=["1.x"],
            )
        ]
    return [
        Finding(
            check_id="iam-role-trust-external",
            title=f"{len(offenders)} IAM role(s) trust external accounts without ExternalId",
            description=(
                f"{len(offenders)} role(s) allow sts:AssumeRole from a foreign AWS account "
                "without an sts:ExternalId condition. This is the 'confused deputy' attack "
                "vector - if the foreign account is ever compromised, the attacker can assume "
                "your role with no second factor. The ExternalId is a shared secret that the "
                "foreign caller must include in every AssumeRole call."
            ),
            severity=Severity.HIGH,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.IAM,
            resource_type="AWS::IAM::Role",
            resource_id=f"arn:aws:iam::{account_id}:role/*",
            region=region,
            account_id=account_id,
            remediation=(
                "For each role, generate a random ExternalId (UUID is fine), share it with "
                "the third party out-of-band, and update the trust policy with: "
                'Condition: {StringEquals: {sts:ExternalId: "your-external-id"}}. '
                "The third party must then include ExternalId in every AssumeRole call."
            ),
            soc2_controls=["CC6.1", "CC6.2"],
            cis_aws_controls=["1.x"],
            details={"roles_without_external_id": offenders[:20]},
        )
    ]


# Threshold for flagging unused IAM roles (matches inactive user threshold)
UNUSED_ROLE_DAYS_THRESHOLD = 90


def check_iam_unused_roles(
    iam: Any, account_id: str, region: str
) -> list[Finding]:
    """IAM roles with no LastUsedDate (or LastUsedDate >90 days) are stale.

    Mirrors check_inactive_users but for roles. Stale roles accumulate
    permissions and become forgotten attack surface. AWS surfaces
    LastUsedDate via get_role for every role.
    """
    try:
        paginator = iam.get_paginator("list_roles")
        roles = []
        for page in paginator.paginate():
            roles.extend(page.get("Roles", []))
    except Exception as e:
        return [Finding.not_assessed(
            check_id="iam-unused-roles",
            title="Unable to check unused IAM roles",
            description=f"API call failed: {e}",
            domain=CheckDomain.IAM,
            resource_type="AWS::IAM::Role",
            account_id=account_id,
            region=region,
        )]

    if not roles:
        return []

    threshold = datetime.now(timezone.utc) - timedelta(days=UNUSED_ROLE_DAYS_THRESHOLD)
    stale: list[dict] = []
    for role in roles:
        path = role.get("Path", "/")
        if path.startswith("/aws-service-role/") or path.startswith("/service-role/"):
            continue
        try:
            detail = iam.get_role(RoleName=role.get("RoleName")).get("Role", {})
        except Exception:
            continue
        last_used_info = detail.get("RoleLastUsed", {}) or {}
        last_used = last_used_info.get("LastUsedDate")
        created = role.get("CreateDate")
        if created and (datetime.now(timezone.utc) - created).days < UNUSED_ROLE_DAYS_THRESHOLD:
            continue
        if last_used is None:
            stale.append(
                {
                    "role_name": role.get("RoleName"),
                    "arn": role.get("Arn"),
                    "created": str(created),
                    "last_used": "never",
                }
            )
        elif last_used < threshold:
            days_ago = (datetime.now(timezone.utc) - last_used).days
            stale.append(
                {
                    "role_name": role.get("RoleName"),
                    "arn": role.get("Arn"),
                    "last_used": str(last_used),
                    "days_since_use": days_ago,
                }
            )

    if not stale:
        return [
            Finding(
                check_id="iam-unused-roles",
                title=f"No stale IAM roles (all used within {UNUSED_ROLE_DAYS_THRESHOLD} days)",
                description=f"All {len(roles)} customer-managed roles have been used recently.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.IAM,
                resource_type="AWS::IAM::Role",
                resource_id=f"arn:aws:iam::{account_id}:role/*",
                region=region,
                account_id=account_id,
                soc2_controls=["CC6.2", "CC6.3"],
                cis_aws_controls=["1.x"],
            )
        ]
    return [
        Finding(
            check_id="iam-unused-roles",
            title=f"{len(stale)} IAM role(s) unused for >{UNUSED_ROLE_DAYS_THRESHOLD} days",
            description=(
                f"{len(stale)} role(s) have either never been used or were last used more than "
                f"{UNUSED_ROLE_DAYS_THRESHOLD} days ago. Stale roles accumulate permissions, "
                "become forgotten attack surface, and complicate access reviews. The right "
                "lifecycle is: create role > use it > if it stops being used, delete it."
            ),
            severity=Severity.MEDIUM,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.IAM,
            resource_type="AWS::IAM::Role",
            resource_id=f"arn:aws:iam::{account_id}:role/*",
            region=region,
            account_id=account_id,
            remediation=(
                "Review each stale role: confirm it's truly unused (search CloudTrail for "
                "AssumeRole events), then run `aws iam delete-role --role-name <name>` after "
                "detaching its policies. For roles used by automation but rarely, document "
                "the expected cadence so they don't get flagged again."
            ),
            soc2_controls=["CC6.2", "CC6.3"],
            cis_aws_controls=["1.x"],
            details={"stale_roles": stale[:20]},
        )
    ]
