"""Periodic access review workflow for SOC 2 CC6.2/CC6.3 compliance.

Generates a structured access review report that lists every IAM user,
their permissions, last activity, and flags issues for human review.
An auditor expects to see these conducted quarterly.
"""

from __future__ import annotations

import csv
import io
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any

from shasta.aws.client import AWSClient


@dataclass
class UserAccessRecord:
    """A single user's access profile for review."""

    username: str
    arn: str
    created: str
    has_console: bool
    has_mfa: bool
    access_keys: list[dict] = field(default_factory=list)
    groups: list[str] = field(default_factory=list)
    attached_policies: list[str] = field(default_factory=list)
    inline_policies: list[str] = field(default_factory=list)
    last_console_login: str | None = None
    last_key_used: str | None = None
    days_inactive: int | None = None
    flags: list[str] = field(default_factory=list)


@dataclass
class AccessReviewReport:
    """Complete access review report."""

    account_id: str
    review_date: str
    total_users: int
    users_with_console: int
    users_with_mfa: int
    users_with_keys: int
    users_flagged: int
    records: list[UserAccessRecord] = field(default_factory=list)


def run_access_review(client: AWSClient) -> AccessReviewReport:
    """Run a comprehensive IAM access review."""
    iam = client.client("iam")
    account_id = client.account_info.account_id if client.account_info else "unknown"
    now = datetime.now(timezone.utc)

    # Generate credential report
    for _ in range(10):
        resp = iam.generate_credential_report()
        if resp["State"] == "COMPLETE":
            break
        time.sleep(1)

    cred_report = {}
    try:
        raw = iam.get_credential_report()["Content"].decode("utf-8")
        for row in csv.DictReader(io.StringIO(raw)):
            cred_report[row["user"]] = row
    except Exception:
        pass

    # Enumerate all users
    records = []
    paginator = iam.get_paginator("list_users")
    for page in paginator.paginate():
        for user in page["Users"]:
            record = _build_user_record(iam, user, cred_report, now)
            records.append(record)

    # Build summary
    report = AccessReviewReport(
        account_id=account_id,
        review_date=now.strftime("%Y-%m-%d"),
        total_users=len(records),
        users_with_console=sum(1 for r in records if r.has_console),
        users_with_mfa=sum(1 for r in records if r.has_mfa),
        users_with_keys=sum(1 for r in records if r.access_keys),
        users_flagged=sum(1 for r in records if r.flags),
        records=records,
    )

    return report


def _build_user_record(
    iam: Any, user: dict, cred_report: dict, now: datetime
) -> UserAccessRecord:
    """Build a detailed access record for a single user."""
    username = user["UserName"]
    arn = user["Arn"]
    created = user["CreateDate"].isoformat()

    # Console access
    has_console = False
    try:
        iam.get_login_profile(UserName=username)
        has_console = True
    except iam.exceptions.NoSuchEntityException:
        pass

    # MFA
    mfa_devices = iam.list_mfa_devices(UserName=username)["MFADevices"]
    has_mfa = len(mfa_devices) > 0

    # Access keys
    keys = []
    for key in iam.list_access_keys(UserName=username)["AccessKeyMetadata"]:
        age_days = (now - key["CreateDate"]).days
        keys.append({
            "key_id": key["AccessKeyId"],
            "status": key["Status"],
            "created": key["CreateDate"].isoformat(),
            "age_days": age_days,
        })

    # Groups
    groups = [g["GroupName"] for g in iam.list_groups_for_user(UserName=username)["Groups"]]

    # Direct policies
    attached = [p["PolicyName"] for p in iam.list_attached_user_policies(UserName=username)["AttachedPolicies"]]
    inline = iam.list_user_policies(UserName=username)["PolicyNames"]

    # Last activity from credential report
    cred = cred_report.get(username, {})
    last_console = cred.get("password_last_used", "N/A")
    if last_console in ("N/A", "no_information", "not_supported"):
        last_console = None

    last_key = None
    for kn in ("1", "2"):
        klu = cred.get(f"access_key_{kn}_last_used_date", "N/A")
        if klu not in ("N/A", "no_information"):
            if last_key is None or klu > last_key:
                last_key = klu

    # Calculate inactivity
    last_activity_date = None
    for date_str in (last_console, last_key):
        if date_str:
            try:
                d = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
                if last_activity_date is None or d > last_activity_date:
                    last_activity_date = d
            except (ValueError, TypeError):
                pass

    days_inactive = None
    if last_activity_date:
        days_inactive = (now - last_activity_date).days
    elif user["CreateDate"] < now - timedelta(days=30):
        days_inactive = (now - user["CreateDate"]).days

    # Flags
    flags = []
    if has_console and not has_mfa:
        flags.append("CONSOLE_NO_MFA")
    if days_inactive is not None and days_inactive > 90:
        flags.append(f"INACTIVE_{days_inactive}d")
    for k in keys:
        if k["status"] == "Active" and k["age_days"] > 90:
            flags.append(f"KEY_STALE_{k['age_days']}d")
    if attached:
        flags.append("DIRECT_POLICIES")
    admin_policies = {"AdministratorAccess", "IAMFullAccess", "PowerUserAccess"}
    all_policy_names = set(attached) | set(inline)
    for g in groups:
        try:
            gp = iam.list_attached_group_policies(GroupName=g)["AttachedPolicies"]
            all_policy_names.update(p["PolicyName"] for p in gp)
        except Exception:
            pass
    if all_policy_names & admin_policies:
        flags.append("OVERPRIVILEGED")

    return UserAccessRecord(
        username=username,
        arn=arn,
        created=created,
        has_console=has_console,
        has_mfa=has_mfa,
        access_keys=keys,
        groups=groups,
        attached_policies=attached,
        inline_policies=list(inline),
        last_console_login=last_console,
        last_key_used=last_key,
        days_inactive=days_inactive,
        flags=flags,
    )


def save_access_review(report: AccessReviewReport, output_path: Path | str = "data/reviews") -> Path:
    """Save the access review as a Markdown report."""
    output_dir = Path(output_path)
    output_dir.mkdir(parents=True, exist_ok=True)
    filepath = output_dir / f"access-review-{report.account_id}-{report.review_date}.md"

    lines = [
        f"# IAM Access Review — {report.review_date}",
        "",
        f"**Account:** {report.account_id}",
        f"**Date:** {report.review_date}",
        f"**Total Users:** {report.total_users}",
        f"**Users with Console Access:** {report.users_with_console}",
        f"**Users with MFA:** {report.users_with_mfa}",
        f"**Users with Access Keys:** {report.users_with_keys}",
        f"**Users Flagged for Review:** {report.users_flagged}",
        "",
        "---",
        "",
    ]

    # Flagged users first
    flagged = [r for r in report.records if r.flags]
    if flagged:
        lines.append("## Flagged Users (Require Action)")
        lines.append("")
        for r in flagged:
            lines.append(f"### {r.username}")
            lines.append(f"- **Flags:** {', '.join(r.flags)}")
            lines.append(f"- **Console:** {'Yes' if r.has_console else 'No'} | **MFA:** {'Yes' if r.has_mfa else 'No'}")
            lines.append(f"- **Groups:** {', '.join(r.groups) or 'None'}")
            lines.append(f"- **Direct Policies:** {', '.join(r.attached_policies) or 'None'}")
            lines.append(f"- **Access Keys:** {len(r.access_keys)}")
            lines.append(f"- **Last Console Login:** {r.last_console_login or 'Never'}")
            lines.append(f"- **Last Key Used:** {r.last_key_used or 'Never'}")
            lines.append(f"- **Days Inactive:** {r.days_inactive or 'N/A'}")
            lines.append("")

    # All users table
    lines.append("## All Users Summary")
    lines.append("")
    lines.append("| User | Console | MFA | Keys | Groups | Direct Policies | Inactive Days | Flags |")
    lines.append("|------|---------|-----|------|--------|-----------------|---------------|-------|")
    for r in report.records:
        flags_str = ", ".join(r.flags) if r.flags else "-"
        lines.append(
            f"| {r.username} | {'Y' if r.has_console else 'N'} | {'Y' if r.has_mfa else 'N'} "
            f"| {len(r.access_keys)} | {', '.join(r.groups) or '-'} "
            f"| {', '.join(r.attached_policies) or '-'} "
            f"| {r.days_inactive or '-'} | {flags_str} |"
        )

    lines.extend([
        "",
        "---",
        "",
        "## Reviewer Sign-off",
        "",
        "| Field | Value |",
        "|-------|-------|",
        "| Reviewed by | ___________________ |",
        "| Date | ___________________ |",
        "| Actions taken | ___________________ |",
        "",
        "*This review satisfies SOC 2 CC6.2 (Access Provisioning) and CC6.3 (Access Removal) requirements.*",
    ])

    filepath.write_text("\n".join(lines), encoding="utf-8")
    return filepath
