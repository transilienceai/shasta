"""AWS Backup security checks: vault lock, cross-account, encryption.

Mirrors what the Azure Recovery Services Vault module covers — vault
existence, encryption, immutability/lock, recovery point retention.
"""

from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from shasta.aws.client import AWSClient
from shasta.evidence.models import (
    CheckDomain,
    ComplianceStatus,
    Finding,
    Severity,
)


def run_all_aws_backup_checks(client: AWSClient) -> list[Finding]:
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
            findings.extend(check_backup_vault_exists(rc, account_id, r))
            findings.extend(check_backup_vault_lock(rc, account_id, r))
            findings.extend(check_backup_vault_encryption(rc, account_id, r))
            findings.extend(check_backup_plans(rc, account_id, r))
            findings.extend(check_backup_cross_region_copy(rc, account_id, r))
            findings.extend(check_backup_vault_access_policy(rc, account_id, r))
        except ClientError:
            continue

    return findings


# ---------------------------------------------------------------------------
# Stage 2 of parity sweep: cross-region copy + access policy (mirrors Azure RSV)
# ---------------------------------------------------------------------------


def check_backup_cross_region_copy(
    client: AWSClient, account_id: str, region: str
) -> list[Finding]:
    """At least one Backup plan should have a cross-region copy action.

    Mirrors Azure's check_rsv_cross_region_restore. Without cross-region
    copies, a single-region disaster destroys the backups along with the
    primary data. AWS Backup supports copy actions in backup plans that
    replicate recovery points to a destination vault in another region.
    """
    try:
        bk = client.client("backup")
        plans_list = bk.list_backup_plans().get("BackupPlansList", [])
    except ClientError as e:
        return [Finding.not_assessed(
            check_id="aws-backup-cross-region-copy",
            title="Unable to check Backup cross-region copy",
            description=f"API call failed: {e}",
            domain=CheckDomain.LOGGING,
            resource_type="AWS::Backup::BackupPlan",
            account_id=account_id,
            region=region,
        )]
    if not plans_list:
        return []

    plans_with_copy: list[str] = []
    plans_without_copy: list[str] = []
    for entry in plans_list:
        plan_id = entry.get("BackupPlanId")
        plan_name = entry.get("BackupPlanName", "unknown")
        if not plan_id:
            continue
        try:
            plan = bk.get_backup_plan(BackupPlanId=plan_id).get("BackupPlan", {})
        except ClientError:
            continue
        rules = plan.get("Rules", []) or []
        has_copy = False
        for rule in rules:
            copy_actions = rule.get("CopyActions", []) or []
            for action in copy_actions:
                dest = action.get("DestinationBackupVaultArn", "")
                # Cross-region copy = destination ARN is in a different region
                # ARN format: arn:aws:backup:REGION:ACCOUNT:backup-vault:NAME
                parts = dest.split(":")
                if len(parts) >= 4 and parts[3] != region:
                    has_copy = True
                    break
            if has_copy:
                break
        if has_copy:
            plans_with_copy.append(plan_name)
        else:
            plans_without_copy.append(plan_name)

    if not plans_without_copy:
        return [
            Finding(
                check_id="aws-backup-cross-region-copy",
                title=f"All {len(plans_with_copy)} Backup plan(s) have cross-region copy",
                description="Every backup plan ships at least one rule's recovery points to a vault in a different region.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.LOGGING,
                resource_type="AWS::Backup::BackupPlan",
                resource_id=f"arn:aws:backup:{region}:{account_id}:backup-plan:*",
                region=region,
                account_id=account_id,
                soc2_controls=["A1.1", "A1.2"],
                cis_aws_controls=["2.x"],
            )
        ]
    return [
        Finding(
            check_id="aws-backup-cross-region-copy",
            title=f"{len(plans_without_copy)} Backup plan(s) lack cross-region copy",
            description=(
                "Without cross-region copy actions, a single-region disaster (control plane "
                "outage, account compromise, ransomware) destroys both your primary data and "
                "your backups simultaneously. AWS Backup supports copy actions in plan rules "
                "that replicate recovery points to a destination vault in another region."
            ),
            severity=Severity.MEDIUM,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.LOGGING,
            resource_type="AWS::Backup::BackupPlan",
            resource_id=f"arn:aws:backup:{region}:{account_id}:backup-plan:*",
            region=region,
            account_id=account_id,
            remediation=(
                "Edit each backup plan to add a copy action to every rule: "
                "CopyActions=[{DestinationBackupVaultArn=arn:aws:backup:<dest-region>:"
                "<acct>:backup-vault:<vault>,Lifecycle={DeleteAfterDays=30}}]"
            ),
            soc2_controls=["A1.1", "A1.2"],
            cis_aws_controls=["2.x"],
            details={"plans_without_copy": plans_without_copy[:20]},
        )
    ]


def check_backup_vault_access_policy(
    client: AWSClient, account_id: str, region: str
) -> list[Finding]:
    """Backup vaults should have an access policy that denies risky operations.

    Mirrors Azure's check_rsv_mua. AWS Backup supports vault access policies
    (resource-based policies) that can deny DeleteBackupVault, DeleteRecoveryPoint,
    and StartCopyJob to all principals except a designated break-glass role.
    Combined with Vault Lock, this is the AWS analog of Multi-User Authorization.
    """
    findings: list[Finding] = []
    try:
        bk = client.client("backup")
    except ClientError as e:
        return [Finding.not_assessed(
            check_id="aws-backup-vault-access-policy",
            title="Unable to check Backup vault access policies",
            description=f"API call failed: {e}",
            domain=CheckDomain.LOGGING,
            resource_type="AWS::Backup::BackupVault",
            account_id=account_id,
            region=region,
        )]
    for v in _list_vaults(client):
        name = v.get("BackupVaultName", "unknown")
        arn = v.get("BackupVaultArn", "")
        try:
            policy_resp = bk.get_backup_vault_access_policy(BackupVaultName=name)
            policy_doc = policy_resp.get("Policy", "")
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code == "ResourceNotFoundException":
                policy_doc = ""
            else:
                continue

        has_deny_policy = bool(policy_doc) and '"Effect":"Deny"' in policy_doc.replace(" ", "")
        if has_deny_policy:
            findings.append(
                Finding(
                    check_id="aws-backup-vault-access-policy",
                    title=f"Backup vault '{name}' has a deny-style access policy",
                    description="Vault has a resource-based policy with a Deny statement.",
                    severity=Severity.INFO,
                    status=ComplianceStatus.PASS,
                    domain=CheckDomain.LOGGING,
                    resource_type="AWS::Backup::BackupVault",
                    resource_id=arn,
                    region=region,
                    account_id=account_id,
                    soc2_controls=["A1.1", "A1.2"],
                    cis_aws_controls=["2.x"],
                )
            )
        else:
            findings.append(
                Finding(
                    check_id="aws-backup-vault-access-policy",
                    title=f"Backup vault '{name}' has no deny-style access policy",
                    description=(
                        "Without a resource-based policy denying DeleteBackupVault, "
                        "DeleteRecoveryPoint, and StartCopyJob to non-break-glass principals, "
                        "a compromised admin can wipe backups even with Vault Lock in "
                        "GOVERNANCE mode. This is the AWS analog of Azure RSV's "
                        "Multi-User Authorization."
                    ),
                    severity=Severity.MEDIUM,
                    status=ComplianceStatus.FAIL,
                    domain=CheckDomain.LOGGING,
                    resource_type="AWS::Backup::BackupVault",
                    resource_id=arn,
                    region=region,
                    account_id=account_id,
                    remediation=(
                        f"aws backup put-backup-vault-access-policy --backup-vault-name {name} "
                        '--policy file://deny-policy.json. The policy should Deny '
                        'backup:DeleteBackupVault, backup:DeleteRecoveryPoint, and '
                        'backup:StartCopyJob with a NotPrincipal of your break-glass role ARN.'
                    ),
                    soc2_controls=["A1.1", "A1.2"],
                    cis_aws_controls=["2.x"],
                )
            )
    return findings


def _list_vaults(client: AWSClient) -> list[dict]:
    try:
        bk = client.client("backup")
        paginator = bk.get_paginator("list_backup_vaults")
        out: list[dict] = []
        for page in paginator.paginate():
            out.extend(page.get("BackupVaultList", []))
        return out
    except ClientError:
        return []


def check_backup_vault_exists(client: AWSClient, account_id: str, region: str) -> list[Finding]:
    """[CIS AWS] At least one AWS Backup vault should exist per region with workloads."""
    vaults = _list_vaults(client)
    if vaults:
        return [
            Finding(
                check_id="aws-backup-vault-exists",
                title=f"{len(vaults)} AWS Backup vault(s) present",
                description="Region has Backup vaults provisioned for centralized backups.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.LOGGING,
                resource_type="AWS::Backup::BackupVault",
                resource_id=f"arn:aws:backup:{region}:{account_id}:backup-vault:*",
                region=region,
                account_id=account_id,
                soc2_controls=["A1.1", "A1.2"],
                cis_aws_controls=["2.x"],
                details={"vault_count": len(vaults)},
            )
        ]
    # Only fail if there are RDS / EFS / EBS workloads worth backing up
    return []


def check_backup_vault_lock(client: AWSClient, account_id: str, region: str) -> list[Finding]:
    """[CIS AWS] AWS Backup vaults should have Vault Lock in COMPLIANCE mode."""
    findings: list[Finding] = []
    try:
        bk = client.client("backup")
    except ClientError as e:
        return [Finding.not_assessed(
            check_id="aws-backup-vault-lock",
            title="Unable to check Backup vault lock status",
            description=f"API call failed: {e}",
            domain=CheckDomain.LOGGING,
            resource_type="AWS::Backup::BackupVault",
            account_id=account_id,
            region=region,
        )]
    for v in _list_vaults(client):
        name = v.get("BackupVaultName", "unknown")
        arn = v.get("BackupVaultArn", "")
        try:
            details = bk.describe_backup_vault(BackupVaultName=name)
        except ClientError:
            continue

        locked = bool(details.get("Locked", False))
        lock_date = details.get("LockDate")
        min_retain = details.get("MinRetentionDays")
        compliance_mode = locked and bool(lock_date)

        if compliance_mode:
            findings.append(
                Finding(
                    check_id="aws-backup-vault-lock",
                    title=f"Backup vault '{name}' is in COMPLIANCE mode",
                    description=(
                        f"Vault is locked (immutable). Min retention: {min_retain} days. "
                        "Recovery points cannot be deleted before retention expires."
                    ),
                    severity=Severity.INFO,
                    status=ComplianceStatus.PASS,
                    domain=CheckDomain.LOGGING,
                    resource_type="AWS::Backup::BackupVault",
                    resource_id=arn,
                    region=region,
                    account_id=account_id,
                    soc2_controls=["A1.1", "A1.2"],
                    cis_aws_controls=["2.x"],
                    details={"vault": name, "min_retain": min_retain},
                )
            )
        elif locked:
            findings.append(
                Finding(
                    check_id="aws-backup-vault-lock",
                    title=f"Backup vault '{name}' is in GOVERNANCE mode",
                    description=(
                        "Vault is locked but in governance mode — IAM users with "
                        "backup:DeleteRecoveryPoint can still delete recovery points before "
                        "retention expires. COMPLIANCE mode is required to defeat ransomware."
                    ),
                    severity=Severity.MEDIUM,
                    status=ComplianceStatus.PARTIAL,
                    domain=CheckDomain.LOGGING,
                    resource_type="AWS::Backup::BackupVault",
                    resource_id=arn,
                    region=region,
                    account_id=account_id,
                    remediation=(
                        f"aws backup put-backup-vault-lock-configuration --backup-vault-name {name} "
                        "--changeable-for-days 3 --min-retention-days 30 --max-retention-days 365"
                    ),
                    soc2_controls=["A1.1", "A1.2"],
                    cis_aws_controls=["2.x"],
                    details={"vault": name},
                )
            )
        else:
            findings.append(
                Finding(
                    check_id="aws-backup-vault-lock",
                    title=f"Backup vault '{name}' has no Vault Lock",
                    description=(
                        "An attacker (or compromised admin) with backup:DeleteRecoveryPoint can "
                        "wipe every backup in this vault. Vault Lock in COMPLIANCE mode is the "
                        "only AWS-side control that defeats this."
                    ),
                    severity=Severity.HIGH,
                    status=ComplianceStatus.FAIL,
                    domain=CheckDomain.LOGGING,
                    resource_type="AWS::Backup::BackupVault",
                    resource_id=arn,
                    region=region,
                    account_id=account_id,
                    remediation=(
                        f"aws backup put-backup-vault-lock-configuration --backup-vault-name {name} "
                        "--changeable-for-days 3 --min-retention-days 30 --max-retention-days 365"
                    ),
                    soc2_controls=["A1.1", "A1.2"],
                    cis_aws_controls=["2.x"],
                    details={"vault": name},
                )
            )

    return findings


def check_backup_vault_encryption(client: AWSClient, account_id: str, region: str) -> list[Finding]:
    """Backup vaults should be encrypted with customer-managed KMS."""
    findings: list[Finding] = []
    for v in _list_vaults(client):
        name = v.get("BackupVaultName", "unknown")
        arn = v.get("BackupVaultArn", "")
        kms = v.get("EncryptionKeyArn")
        if kms and "alias/aws/backup" not in kms:
            findings.append(
                Finding(
                    check_id="aws-backup-vault-cmk",
                    title=f"Backup vault '{name}' uses customer-managed KMS",
                    description=f"Encryption key: {kms}",
                    severity=Severity.INFO,
                    status=ComplianceStatus.PASS,
                    domain=CheckDomain.ENCRYPTION,
                    resource_type="AWS::Backup::BackupVault",
                    resource_id=arn,
                    region=region,
                    account_id=account_id,
                    soc2_controls=["CC6.7"],
                    cis_aws_controls=["2.x"],
                )
            )
        else:
            findings.append(
                Finding(
                    check_id="aws-backup-vault-cmk",
                    title=f"Backup vault '{name}' uses AWS-managed key",
                    description="No customer-managed KMS key — you can't revoke decryption independently.",
                    severity=Severity.LOW,
                    status=ComplianceStatus.PARTIAL,
                    domain=CheckDomain.ENCRYPTION,
                    resource_type="AWS::Backup::BackupVault",
                    resource_id=arn,
                    region=region,
                    account_id=account_id,
                    remediation="Recreate the vault with --encryption-key-arn pointing to a customer-managed KMS key.",
                    soc2_controls=["CC6.7"],
                    cis_aws_controls=["2.x"],
                )
            )
    return findings


def check_backup_plans(client: AWSClient, account_id: str, region: str) -> list[Finding]:
    """[CIS AWS] At least one Backup plan should exist."""
    try:
        bk = client.client("backup")
        plans = bk.list_backup_plans().get("BackupPlansList", [])
    except ClientError as e:
        return [Finding.not_assessed(
            check_id="aws-backup-plans",
            title="Unable to check Backup plans",
            description=f"API call failed: {e}",
            domain=CheckDomain.LOGGING,
            resource_type="AWS::Backup::BackupPlan",
            account_id=account_id,
            region=region,
        )]

    if plans:
        return [
            Finding(
                check_id="aws-backup-plans",
                title=f"{len(plans)} AWS Backup plan(s) configured",
                description="Backup plans exist to schedule recovery point creation.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.LOGGING,
                resource_type="AWS::Backup::BackupPlan",
                resource_id=f"arn:aws:backup:{region}:{account_id}:backup-plan:*",
                region=region,
                account_id=account_id,
                soc2_controls=["A1.2"],
                cis_aws_controls=["2.x"],
                details={"plan_count": len(plans)},
            )
        ]
    return [
        Finding(
            check_id="aws-backup-plans",
            title="No AWS Backup plans configured",
            description=(
                "Backup vaults exist but no backup plans schedule recovery points. Without "
                "a plan, nothing is being backed up automatically."
            ),
            severity=Severity.MEDIUM,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.LOGGING,
            resource_type="AWS::Backup::BackupPlan",
            resource_id=f"arn:aws:backup:{region}:{account_id}:backup-plan:*",
            region=region,
            account_id=account_id,
            remediation=(
                "Create a backup plan via the Backup console or "
                "`aws backup create-backup-plan`. Use AWS-managed plans (Daily-35day, "
                "Monthly-1year) as a starting point."
            ),
            soc2_controls=["A1.2"],
            cis_aws_controls=["2.x"],
        )
    ]
