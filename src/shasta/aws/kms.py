"""AWS KMS security checks: rotation, key policy, scheduled deletion, principal scope.

KMS is the foundation of every other encryption check in Shasta — EBS, RDS,
S3, EFS, CloudWatch Logs, Secrets Manager all sit on top of customer-managed
KMS keys. A weak KMS posture undermines all of those.

Every check in this module is regional. KMS keys are scoped to a region;
multi-region keys (CIS AWS doesn't currently mandate them) are noted in the
finding details.
"""

from __future__ import annotations

import json
from typing import Any

from botocore.exceptions import ClientError

from shasta.aws.client import AWSClient
from shasta.evidence.models import (
    CheckDomain,
    ComplianceStatus,
    Finding,
    Severity,
)


# This module iterates regions per Engineering Principle #3.
IS_GLOBAL = False


def run_all_aws_kms_checks(client: AWSClient) -> list[Finding]:
    """Run all KMS checks across every enabled region."""
    findings: list[Finding] = []
    account_id = client.account_info.account_id if client.account_info else "unknown"
    region = client.account_info.region if client.account_info else "us-east-1"

    try:
        regions = client.get_enabled_regions()
    except ClientError:
        regions = [region]

    for r in regions:
        try:
            rc = client.for_region(r)
            findings.extend(check_kms_key_rotation(rc, account_id, r))
            findings.extend(check_kms_key_policy_wildcards(rc, account_id, r))
            findings.extend(check_kms_scheduled_deletion(rc, account_id, r))
            findings.extend(check_kms_no_unrestricted_principal(rc, account_id, r))
        except ClientError:
            continue

    return findings


def _list_customer_keys(client: AWSClient) -> list[dict]:
    """Return customer-managed CMKs (excludes AWS-managed and AWS-owned keys)."""
    try:
        kms = client.client("kms")
    except ClientError:
        return []

    out: list[dict] = []
    try:
        paginator = kms.get_paginator("list_keys")
        for page in paginator.paginate():
            for entry in page.get("Keys", []):
                key_id = entry.get("KeyId")
                if not key_id:
                    continue
                try:
                    md = kms.describe_key(KeyId=key_id).get("KeyMetadata", {})
                except ClientError:
                    continue
                # Skip AWS-managed and AWS-owned keys; only customer-managed are
                # in scope for these checks.
                if md.get("KeyManager") != "CUSTOMER":
                    continue
                out.append(md)
    except ClientError:
        pass
    return out


def check_kms_key_rotation(
    client: AWSClient, account_id: str, region: str
) -> list[Finding]:
    """[CIS AWS 3.8] Customer-managed KMS keys should have annual rotation enabled.

    Without rotation, the same key material protects data forever. NIST SP
    800-57 recommends annual rotation for symmetric keys protecting bulk data.
    AWS KMS auto-rotation is one boolean — there's no excuse to leave it off.
    """
    findings: list[Finding] = []
    try:
        kms = client.client("kms")
    except ClientError as e:
        return [Finding.not_assessed(
            check_id="kms-key-rotation",
            title="Unable to check KMS key rotation",
            description=f"API call failed: {e}",
            domain=CheckDomain.ENCRYPTION,
            resource_type="AWS::KMS::Key",
            account_id=account_id,
            region=region,
        )]

    keys = _list_customer_keys(client)
    if not keys:
        return []

    rotation_off: list[dict] = []
    rotation_on = 0
    for key in keys:
        key_id = key.get("KeyId")
        # Asymmetric and HMAC keys don't support rotation — skip them
        if key.get("KeySpec", "SYMMETRIC_DEFAULT") != "SYMMETRIC_DEFAULT":
            continue
        # Pending-deletion keys can't be rotated
        if key.get("KeyState") in ("PendingDeletion", "PendingReplicaDeletion"):
            continue
        try:
            status = kms.get_key_rotation_status(KeyId=key_id)
            if status.get("KeyRotationEnabled"):
                rotation_on += 1
            else:
                rotation_off.append(
                    {
                        "key_id": key_id,
                        "arn": key.get("Arn"),
                        "description": key.get("Description", ""),
                    }
                )
        except ClientError:
            continue

    if not rotation_off:
        return [
            Finding(
                check_id="kms-key-rotation",
                title=f"All {rotation_on} customer-managed CMK(s) have rotation enabled",
                description="Every symmetric customer-managed key has automatic annual rotation.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.ENCRYPTION,
                resource_type="AWS::KMS::Key",
                resource_id=f"arn:aws:kms:{region}:{account_id}:key/*",
                region=region,
                account_id=account_id,
                soc2_controls=["CC6.7"],
                cis_aws_controls=["3.8"],
            )
        ]
    return [
        Finding(
            check_id="kms-key-rotation",
            title=f"{len(rotation_off)} customer-managed CMK(s) without rotation",
            description=(
                f"{len(rotation_off)} of {len(rotation_off) + rotation_on} symmetric customer-managed "
                "key(s) have automatic rotation disabled. Without rotation, the same key material "
                "protects data forever, expanding the blast radius of any future key compromise."
            ),
            severity=Severity.MEDIUM,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.ENCRYPTION,
            resource_type="AWS::KMS::Key",
            resource_id=f"arn:aws:kms:{region}:{account_id}:key/*",
            region=region,
            account_id=account_id,
            remediation=(
                "For each key: aws kms enable-key-rotation --key-id <key-id>. "
                "Annual rotation is the default rotation period; AWS handles the rotation "
                "transparently and old key material remains available for decryption of "
                "previously-encrypted data."
            ),
            soc2_controls=["CC6.7"],
            cis_aws_controls=["3.8"],
            details={"keys_without_rotation": rotation_off[:20]},
        )
    ]


def _decode_key_policy(client: AWSClient, key_id: str) -> dict | None:
    try:
        kms = client.client("kms")
        policy_str = kms.get_key_policy(KeyId=key_id, PolicyName="default").get("Policy", "")
        return json.loads(policy_str) if policy_str else None
    except (ClientError, json.JSONDecodeError):
        return None


def check_kms_key_policy_wildcards(
    client: AWSClient, account_id: str, region: str
) -> list[Finding]:
    """KMS key policies should not grant ``Action: "kms:*"`` to ``Principal: "*"``.

    A wildcard principal + wildcard action on a KMS key is the encryption-key
    equivalent of a public S3 bucket: anyone in any AWS account can encrypt,
    decrypt, schedule deletion, or take ownership of the key.
    """
    findings: list[Finding] = []
    keys = _list_customer_keys(client)
    if not keys:
        return []

    offenders: list[dict] = []
    reviewed = 0
    for key in keys:
        key_id = key.get("KeyId")
        policy = _decode_key_policy(client, key_id)
        if not policy:
            continue
        reviewed += 1
        for stmt in policy.get("Statement", []):
            if stmt.get("Effect") != "Allow":
                continue
            principal = stmt.get("Principal", {})
            # Principal can be "*" or {"AWS": "*"}
            principal_wildcard = (
                principal == "*"
                or (isinstance(principal, dict) and principal.get("AWS") == "*")
                or (
                    isinstance(principal, dict)
                    and isinstance(principal.get("AWS"), list)
                    and "*" in principal.get("AWS", [])
                )
            )
            if not principal_wildcard:
                continue
            # Only flag if there's no Condition narrowing the principal
            if stmt.get("Condition"):
                continue
            actions = stmt.get("Action", [])
            if isinstance(actions, str):
                actions = [actions]
            if any(a == "kms:*" or a == "*" for a in actions):
                offenders.append(
                    {
                        "key_id": key_id,
                        "arn": key.get("Arn"),
                        "actions": actions,
                    }
                )
                break

    if not offenders:
        return [
            Finding(
                check_id="kms-key-policy-wildcards",
                title=f"All {reviewed} CMK(s) have non-wildcard key policies",
                description="No customer-managed key grants wildcard Action to wildcard Principal without a Condition.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.ENCRYPTION,
                resource_type="AWS::KMS::Key",
                resource_id=f"arn:aws:kms:{region}:{account_id}:key/*",
                region=region,
                account_id=account_id,
                soc2_controls=["CC6.1", "CC6.7"],
                cis_aws_controls=["3.x"],
            )
        ]
    return [
        Finding(
            check_id="kms-key-policy-wildcards",
            title=f"{len(offenders)} CMK(s) with wildcard Principal+Action key policies",
            description=(
                "These keys grant `kms:*` (or `*`) to `Principal: \"*\"` with no Condition. "
                "Anyone in any AWS account can encrypt, decrypt, take ownership, or schedule "
                "deletion. This is the KMS equivalent of a public S3 bucket — and unlike S3 "
                "Public Access Block, there's no account-wide guardrail that prevents it."
            ),
            severity=Severity.HIGH,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.ENCRYPTION,
            resource_type="AWS::KMS::Key",
            resource_id=f"arn:aws:kms:{region}:{account_id}:key/*",
            region=region,
            account_id=account_id,
            remediation=(
                "Rewrite the key policy to scope Principal to specific account or role ARNs. "
                "If cross-account access is required, use a specific account principal "
                "(arn:aws:iam::ACCOUNT_ID:root) plus a Condition narrowing the source. "
                "Run `aws kms put-key-policy --key-id <id> --policy file://policy.json`."
            ),
            soc2_controls=["CC6.1", "CC6.7"],
            cis_aws_controls=["3.x"],
            details={"wildcard_keys": offenders[:20]},
        )
    ]


def check_kms_scheduled_deletion(
    client: AWSClient, account_id: str, region: str
) -> list[Finding]:
    """KMS keys in PendingDeletion state should be flagged immediately.

    A key in PendingDeletion will be permanently destroyed in 7-30 days,
    making any data encrypted with it permanently unrecoverable. This often
    indicates either a mistake (cancel deletion) or a malicious action
    (alert SecOps).
    """
    keys = _list_customer_keys(client)
    if not keys:
        return []

    pending: list[dict] = []
    for key in keys:
        if key.get("KeyState") == "PendingDeletion":
            pending.append(
                {
                    "key_id": key.get("KeyId"),
                    "arn": key.get("Arn"),
                    "deletion_date": str(key.get("DeletionDate", "")),
                    "description": key.get("Description", ""),
                }
            )

    if not pending:
        return [
            Finding(
                check_id="kms-scheduled-deletion",
                title=f"No CMKs in PendingDeletion state in {region}",
                description="No customer-managed key is scheduled for deletion.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.ENCRYPTION,
                resource_type="AWS::KMS::Key",
                resource_id=f"arn:aws:kms:{region}:{account_id}:key/*",
                region=region,
                account_id=account_id,
                soc2_controls=["A1.2"],
                cis_aws_controls=["3.x"],
            )
        ]
    return [
        Finding(
            check_id="kms-scheduled-deletion",
            title=f"{len(pending)} CMK(s) in PendingDeletion state",
            description=(
                f"{len(pending)} customer-managed key(s) are scheduled for permanent destruction. "
                "Any data encrypted with these keys becomes unrecoverable when the deletion "
                "completes (7-30 days from when the deletion was scheduled). Investigate immediately: "
                "either this is a mistake (run cancel-key-deletion) or it's malicious (alert SecOps "
                "and review CloudTrail for the ScheduleKeyDeletion event)."
            ),
            severity=Severity.CRITICAL,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.ENCRYPTION,
            resource_type="AWS::KMS::Key",
            resource_id=f"arn:aws:kms:{region}:{account_id}:key/*",
            region=region,
            account_id=account_id,
            remediation=(
                "If the deletion is a mistake: aws kms cancel-key-deletion --key-id <id> "
                "(this also disables the key — re-enable with aws kms enable-key). "
                "If the deletion was unauthorized: search CloudTrail for "
                "eventName=ScheduleKeyDeletion in the relevant time window and identify the "
                "principal. Add an SCP denying kms:ScheduleKeyDeletion except via a break-glass role."
            ),
            soc2_controls=["A1.2"],
            cis_aws_controls=["3.x"],
            details={"keys_pending_deletion": pending},
        )
    ]


def check_kms_no_unrestricted_principal(
    client: AWSClient, account_id: str, region: str
) -> list[Finding]:
    """KMS key policies should not grant access to broad cross-account principals.

    Subset of the wildcard check: also flags `Principal: {"AWS": "arn:aws:iam::123456789012:root"}`
    grants without a Condition narrowing the source. Cross-account access is
    legitimate but should always carry a SourceArn / SourceAccount condition.
    """
    findings: list[Finding] = []
    keys = _list_customer_keys(client)
    if not keys:
        return []

    own_account_root = f"arn:aws:iam::{account_id}:root"
    cross_account: list[dict] = []
    for key in keys:
        key_id = key.get("KeyId")
        policy = _decode_key_policy(client, key_id)
        if not policy:
            continue
        for stmt in policy.get("Statement", []):
            if stmt.get("Effect") != "Allow":
                continue
            principal = stmt.get("Principal", {})
            if not isinstance(principal, dict):
                continue
            aws_principals = principal.get("AWS", [])
            if isinstance(aws_principals, str):
                aws_principals = [aws_principals]
            cross_acct_principals = [
                p
                for p in aws_principals
                if isinstance(p, str)
                and p != own_account_root
                and p != "*"
                and ":root" in p
            ]
            if cross_acct_principals and not stmt.get("Condition"):
                cross_account.append(
                    {
                        "key_id": key_id,
                        "principals": cross_acct_principals,
                        "actions": stmt.get("Action", []),
                    }
                )
                break

    if not cross_account:
        return [
            Finding(
                check_id="kms-no-unrestricted-principal",
                title=f"No CMKs grant cross-account access without Conditions in {region}",
                description="All cross-account grants on customer-managed keys carry a Condition.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.ENCRYPTION,
                resource_type="AWS::KMS::Key",
                resource_id=f"arn:aws:kms:{region}:{account_id}:key/*",
                region=region,
                account_id=account_id,
                soc2_controls=["CC6.1", "CC6.7"],
                cis_aws_controls=["3.x"],
            )
        ]
    return [
        Finding(
            check_id="kms-no-unrestricted-principal",
            title=f"{len(cross_account)} CMK(s) grant cross-account access without Conditions",
            description=(
                "These keys allow another AWS account to use them with no SourceArn or "
                "SourceAccount condition narrowing the access. If the foreign account is "
                "ever compromised, the attacker inherits full use of these keys."
            ),
            severity=Severity.MEDIUM,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.ENCRYPTION,
            resource_type="AWS::KMS::Key",
            resource_id=f"arn:aws:kms:{region}:{account_id}:key/*",
            region=region,
            account_id=account_id,
            remediation=(
                "Add a Condition block to each cross-account grant: "
                '"Condition": {"StringEquals": {"aws:SourceAccount": "<foreign-account-id>"}} '
                "or restrict by aws:PrincipalArn / kms:CallerAccount."
            ),
            soc2_controls=["CC6.1", "CC6.7"],
            cis_aws_controls=["3.x"],
            details={"cross_account_grants": cross_account[:20]},
        )
    ]
