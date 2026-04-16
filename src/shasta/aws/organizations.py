"""AWS Organizations governance auditor.

Mirrors the Azure governance.py module — checks the org-level structure
that holds account-level controls together: Organizations enabled,
SCPs in use, AI services opt-out, tag policies, backup policies.
"""

from __future__ import annotations

from botocore.exceptions import ClientError

from shasta.aws.client import AWSClient
from shasta.evidence.models import (
    CheckDomain,
    ComplianceStatus,
    Finding,
    Severity,
)


def run_all_aws_organizations_checks(client: AWSClient) -> list[Finding]:
    findings: list[Finding] = []
    account_id = client.account_info.account_id if client.account_info else "unknown"
    region = client.account_info.region if client.account_info else "us-east-1"

    findings.extend(check_organizations_enabled(client, account_id, region))
    findings.extend(check_scps_in_use(client, account_id, region))
    findings.extend(check_tag_policy(client, account_id, region))
    findings.extend(check_backup_policy(client, account_id, region))
    findings.extend(check_delegated_admin(client, account_id, region))

    return findings


def _org_client(client: AWSClient):
    try:
        return client.client("organizations")
    except ClientError:
        return None


def check_organizations_enabled(client: AWSClient, account_id: str, region: str) -> list[Finding]:
    """[CIS AWS 1.x] AWS Organizations should be enabled with the account in an OU hierarchy."""
    org = _org_client(client)
    if not org:
        return []
    try:
        info = org.describe_organization().get("Organization", {})
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code in ("AWSOrganizationsNotInUseException", "AccessDeniedException"):
            return [
                Finding(
                    check_id="aws-org-enabled",
                    title="AWS Organizations is NOT in use",
                    description=(
                        "Account is not part of any AWS Organization. Without Organizations "
                        "you cannot apply Service Control Policies, enforce centralized "
                        "logging, share resources via RAM, or use the Backup / Tag policy "
                        "features that need org-level scope."
                    ),
                    severity=Severity.MEDIUM,
                    status=ComplianceStatus.FAIL,
                    domain=CheckDomain.IAM,
                    resource_type="AWS::Organizations::Organization",
                    resource_id="organizations:none",
                    region=region,
                    account_id=account_id,
                    remediation=(
                        "Create an Organization from a dedicated management account, then "
                        "invite this account into it."
                    ),
                    soc2_controls=["CC1.3"],
                    cis_aws_controls=["1.x"],
                )
            ]
        return []

    feature_set = info.get("FeatureSet", "CONSOLIDATED_BILLING")
    if feature_set == "ALL":
        return [
            Finding(
                check_id="aws-org-enabled",
                title="AWS Organizations enabled with ALL features",
                description=(
                    f"Org ID: {info.get('Id')}. Master account: {info.get('MasterAccountId')}. "
                    "ALL-features mode allows SCPs and other governance policies."
                ),
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.IAM,
                resource_type="AWS::Organizations::Organization",
                resource_id=info.get("Arn", ""),
                region=region,
                account_id=account_id,
                soc2_controls=["CC1.3"],
                cis_aws_controls=["1.x"],
                details={"org_id": info.get("Id"), "feature_set": feature_set},
            )
        ]
    return [
        Finding(
            check_id="aws-org-enabled",
            title="Organizations is in CONSOLIDATED_BILLING mode only",
            description=(
                "Org exists but is in consolidated-billing-only mode. SCPs, tag policies, "
                "and backup policies require ALL-features mode."
            ),
            severity=Severity.MEDIUM,
            status=ComplianceStatus.PARTIAL,
            domain=CheckDomain.IAM,
            resource_type="AWS::Organizations::Organization",
            resource_id=info.get("Arn", ""),
            region=region,
            account_id=account_id,
            remediation="Upgrade the Organization to ALL features via the management account.",
            soc2_controls=["CC1.3"],
            cis_aws_controls=["1.x"],
        )
    ]


def check_scps_in_use(client: AWSClient, account_id: str, region: str) -> list[Finding]:
    """[CIS AWS] At least one Service Control Policy should be attached beyond the default FullAWSAccess."""
    org = _org_client(client)
    if not org:
        return []
    try:
        policies = org.list_policies(Filter="SERVICE_CONTROL_POLICY").get("Policies", [])
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code in (
            "AWSOrganizationsNotInUseException",
            "AccessDeniedException",
            "PolicyTypeNotEnabledException",
        ):
            return []
        return []

    custom = [p for p in policies if not p.get("AwsManaged")]
    if custom:
        return [
            Finding(
                check_id="aws-org-scps",
                title=f"{len(custom)} custom Service Control Policy(ies) defined",
                description=(
                    f"Custom SCPs found: {', '.join(p.get('Name', '') for p in custom[:5])}. "
                    "SCPs enforce guardrails across all accounts in the OU."
                ),
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.IAM,
                resource_type="AWS::Organizations::Policy",
                resource_id=f"arn:aws:organizations::{account_id}:policy/*",
                region=region,
                account_id=account_id,
                soc2_controls=["CC6.1", "CC6.2"],
                cis_aws_controls=["1.x"],
                details={"custom_scp_count": len(custom)},
            )
        ]
    return [
        Finding(
            check_id="aws-org-scps",
            title="No custom Service Control Policies defined",
            description=(
                "Only the default FullAWSAccess SCP is in place. Without custom SCPs you "
                "have no org-wide guardrails — child accounts can disable CloudTrail, leave "
                "regions unrestricted, or assume any role."
            ),
            severity=Severity.MEDIUM,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.IAM,
            resource_type="AWS::Organizations::Policy",
            resource_id=f"arn:aws:organizations::{account_id}:policy/*",
            region=region,
            account_id=account_id,
            remediation=(
                "Author SCPs that deny: CloudTrail disable/delete, root account use, "
                "creation of resources outside approved regions, and risky IAM changes. "
                "Apply at the OU level."
            ),
            soc2_controls=["CC6.1", "CC6.2"],
            cis_aws_controls=["1.x"],
        )
    ]


def check_tag_policy(client: AWSClient, account_id: str, region: str) -> list[Finding]:
    """Tag policies should enforce required tags org-wide."""
    org = _org_client(client)
    if not org:
        return []
    try:
        policies = org.list_policies(Filter="TAG_POLICY").get("Policies", [])
    except ClientError as e:
        return [Finding.not_assessed(
            check_id="aws-tag-policy",
            title="Unable to check tag policies",
            description=f"API call failed: {e}",
            domain=CheckDomain.MONITORING,
            resource_type="AWS::Organizations::Policy",
            account_id=account_id,
            region=region,
        )]

    if policies:
        return [
            Finding(
                check_id="aws-tag-policy",
                title=f"{len(policies)} tag policy(ies) defined",
                description="Tag policies enforce required tag keys/values across the org.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.MONITORING,
                resource_type="AWS::Organizations::Policy",
                resource_id=f"arn:aws:organizations::{account_id}:policy/*",
                region=region,
                account_id=account_id,
                soc2_controls=["CC2.1"],
                cis_aws_controls=["1.x"],
            )
        ]
    return [
        Finding(
            check_id="aws-tag-policy",
            title="No org-level tag policies defined",
            description=(
                "Without tag policies, resources are tagged inconsistently — making cost "
                "allocation, ownership tracking, and policy-based access control unreliable."
            ),
            severity=Severity.LOW,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.MONITORING,
            resource_type="AWS::Organizations::Policy",
            resource_id=f"arn:aws:organizations::{account_id}:policy/*",
            region=region,
            account_id=account_id,
            remediation=(
                "Define a tag policy enforcing 'owner' and 'environment' keys at the org "
                "root, then attach it to OUs."
            ),
            soc2_controls=["CC2.1"],
            cis_aws_controls=["1.x"],
        )
    ]


def check_backup_policy(client: AWSClient, account_id: str, region: str) -> list[Finding]:
    """[CIS AWS] Org-level Backup policy should enforce backup plans across accounts."""
    org = _org_client(client)
    if not org:
        return []
    try:
        policies = org.list_policies(Filter="BACKUP_POLICY").get("Policies", [])
    except ClientError as e:
        return [Finding.not_assessed(
            check_id="aws-backup-policy",
            title="Unable to check org-level backup policies",
            description=f"API call failed: {e}",
            domain=CheckDomain.LOGGING,
            resource_type="AWS::Organizations::Policy",
            account_id=account_id,
            region=region,
        )]

    if policies:
        return [
            Finding(
                check_id="aws-backup-policy",
                title=f"{len(policies)} org-level Backup policy(ies) defined",
                description="Backup plans are enforced via Organizations.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.LOGGING,
                resource_type="AWS::Organizations::Policy",
                resource_id=f"arn:aws:organizations::{account_id}:policy/*",
                region=region,
                account_id=account_id,
                soc2_controls=["A1.1", "A1.2"],
                cis_aws_controls=["1.x"],
            )
        ]
    return [
        Finding(
            check_id="aws-backup-policy",
            title="No org-level Backup policies",
            description=(
                "Backup plans need to be defined per account. With an org-level Backup policy "
                "you can enforce a baseline (daily-35day, monthly-1year) across every member "
                "account automatically."
            ),
            severity=Severity.LOW,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.LOGGING,
            resource_type="AWS::Organizations::Policy",
            resource_id=f"arn:aws:organizations::{account_id}:policy/*",
            region=region,
            account_id=account_id,
            remediation=(
                "Create an org-level Backup policy via "
                "`aws organizations create-policy --type BACKUP_POLICY ...` and attach to OUs."
            ),
            soc2_controls=["A1.1", "A1.2"],
            cis_aws_controls=["1.x"],
        )
    ]


def check_delegated_admin(client: AWSClient, account_id: str, region: str) -> list[Finding]:
    """Delegated administrators for Security Hub / GuardDuty / Config should not be the management account."""
    org = _org_client(client)
    if not org:
        return []
    try:
        delegated = org.list_delegated_administrators().get("DelegatedAdministrators", [])
    except ClientError as e:
        return [Finding.not_assessed(
            check_id="aws-delegated-admin",
            title="Unable to check delegated administrators",
            description=f"API call failed: {e}",
            domain=CheckDomain.IAM,
            resource_type="AWS::Organizations::DelegatedAdministrator",
            account_id=account_id,
            region=region,
        )]

    if delegated:
        return [
            Finding(
                check_id="aws-delegated-admin",
                title=f"{len(delegated)} delegated administrator(s) configured",
                description=(
                    "Security services are delegated to non-management accounts, which is the "
                    "recommended pattern (keeps management account locked down)."
                ),
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.IAM,
                resource_type="AWS::Organizations::DelegatedAdministrator",
                resource_id=f"arn:aws:organizations::{account_id}:account/*",
                region=region,
                account_id=account_id,
                soc2_controls=["CC1.3", "CC6.1"],
                cis_aws_controls=["1.x"],
                details={"delegated_count": len(delegated)},
            )
        ]
    return [
        Finding(
            check_id="aws-delegated-admin",
            title="No delegated administrators configured",
            description=(
                "Security services (Security Hub, GuardDuty, Config, Backup) should be "
                "delegated to a dedicated security account so the management account stays "
                "minimal-privilege and rarely accessed."
            ),
            severity=Severity.LOW,
            status=ComplianceStatus.PARTIAL,
            domain=CheckDomain.IAM,
            resource_type="AWS::Organizations::DelegatedAdministrator",
            resource_id=f"arn:aws:organizations::{account_id}:account/*",
            region=region,
            account_id=account_id,
            remediation=(
                "Create a dedicated security/audit account, then run "
                "`aws organizations register-delegated-administrator` for securityhub, "
                "guardduty, config, backup, and access-analyzer."
            ),
            soc2_controls=["CC1.3", "CC6.1"],
            cis_aws_controls=["1.x"],
        )
    ]
