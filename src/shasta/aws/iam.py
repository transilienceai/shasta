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
    findings.extend(check_user_mfa(iam, account_id, region))
    findings.extend(check_access_key_rotation(iam, account_id, region))
    findings.extend(check_inactive_users(iam, account_id, region))
    findings.extend(check_user_direct_policies(iam, account_id, region))
    findings.extend(check_overprivileged_users(iam, account_id, region))

    return findings


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
        issues.append(f"Password reuse prevention is {policy.get('PasswordReusePrevention', 0)}, should be 12+")

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
            remediation="" if root_mfa else "Enable MFA on the root account immediately. Use a hardware MFA device for maximum security.",
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
            has_keys = root_entry.get("access_key_1_active", "false") == "true" or root_entry.get(
                "access_key_2_active", "false"
            ) == "true"
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
                        details={"access_key_1_active": root_entry.get("access_key_1_active"), "access_key_2_active": root_entry.get("access_key_2_active")},
                    )
                )
    except Exception:
        pass  # Credential report may not be available

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
                    + ("" if has_mfa else " Users with console access must have MFA to meet SOC 2 requirements.")
                ),
                severity=Severity.INFO if has_mfa else Severity.HIGH,
                status=ComplianceStatus.PASS if has_mfa else ComplianceStatus.FAIL,
                domain=CheckDomain.IAM,
                resource_type="AWS::IAM::User",
                resource_id=user["Arn"],
                region=region,
                account_id=account_id,
                remediation="" if has_mfa else f"Enable MFA for user '{username}'. Virtual MFA (authenticator app) or hardware MFA are both acceptable.",
                soc2_controls=["CC6.1"],
                details={"username": username, "has_console_access": True, "mfa_enabled": has_mfa, "mfa_device_count": len(mfa_devices)},
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
                        details={"username": username, "access_key_id": key_id, "age_days": age_days, "created": key["CreateDate"].isoformat()},
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
                        details={"username": username, "access_key_id": key_id, "age_days": age_days, "created": key["CreateDate"].isoformat()},
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
    except Exception:
        return []

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
                            details={"username": username, "last_activity": None, "created": user_creation},
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
                    details={"username": username, "last_activity": last_activity.isoformat(), "activity_source": activity_source, "days_inactive": days_inactive},
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
                    details={"username": username, "attached_policies": [p["PolicyName"] for p in attached], "inline_policies": list(inline)},
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
        dangerous_direct = [p["PolicyName"] for p in attached if p["PolicyArn"] in OVERPRIVILEGED_POLICIES]

        # Check group policies
        groups = iam.list_groups_for_user(UserName=username)["Groups"]
        dangerous_group = []
        for group in groups:
            group_policies = iam.list_attached_group_policies(GroupName=group["GroupName"])["AttachedPolicies"]
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
