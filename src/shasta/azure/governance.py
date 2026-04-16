"""Azure governance checks: management groups, policy initiatives, locks, tags.

Maps to CIS Azure section 1 (subscription/MG hierarchy), section 2 (policy
initiatives), and CIS 5.x / MCSB GS-1 governance controls.
"""

from __future__ import annotations

from shasta.azure.client import AzureClient
from shasta.evidence.models import (
    CheckDomain,
    CloudProvider,
    ComplianceStatus,
    Finding,
    Severity,
)

# Built-in initiatives every CSPM should look for
EXPECTED_INITIATIVE_NAMES = {
    "Microsoft cloud security benchmark",
    "Azure Security Benchmark",
    "CIS Microsoft Azure Foundations Benchmark v2.0.0",
    "CIS Microsoft Azure Foundations Benchmark v1.4.0",
    "ISO 27001:2013",
    "NIST SP 800-53 Rev. 5",
    "PCI DSS v4",
    "SOC 2 Type 2",
}


def run_all_azure_governance_checks(client: AzureClient) -> list[Finding]:
    """Run all Azure governance checks."""
    findings: list[Finding] = []
    sub_id = client.account_info.subscription_id if client.account_info else "unknown"
    region = client.account_info.region if client.account_info else "unknown"

    findings.extend(check_management_group_hierarchy(client, sub_id, region))
    findings.extend(check_security_initiative_assigned(client, sub_id, region))
    findings.extend(check_critical_resource_locks(client, sub_id, region))
    findings.extend(check_required_tags(client, sub_id, region))

    return findings


def check_management_group_hierarchy(
    client: AzureClient, subscription_id: str, region: str
) -> list[Finding]:
    """[MCSB GS-1] Subscriptions should live under a management group hierarchy, not Tenant Root only."""
    try:
        from azure.mgmt.managementgroups import ManagementGroupsAPI

        mgmt = ManagementGroupsAPI(client.credential)
        groups = list(mgmt.management_groups.list())
    except Exception as e:
        if "AuthorizationFailed" in str(e) or "Forbidden" in str(e):
            return [
                Finding(
                    check_id="azure-management-group-hierarchy",
                    title="Cannot read management groups (insufficient permission)",
                    description="Requires Reader on the management group hierarchy.",
                    severity=Severity.MEDIUM,
                    status=ComplianceStatus.NOT_ASSESSED,
                    domain=CheckDomain.MONITORING,
                    resource_type="Azure::Management::Group",
                    resource_id="/providers/Microsoft.Management/managementGroups",
                    region=region,
                    account_id=subscription_id,
                    cloud_provider=CloudProvider.AZURE,
                    soc2_controls=["CC1.3"],
                    mcsb_controls=["GS-1"],
                )
            ]
        return [Finding.not_assessed(
            check_id="azure-management-group-hierarchy",
            title="Unable to check management group hierarchy",
            description=f"API call failed: {e}",
            domain=CheckDomain.MONITORING,
            resource_type="Azure::Management::Group",
            account_id=subscription_id,
            region=region,
            cloud_provider=CloudProvider.AZURE,
        )]

    # Tenant Root group is always present; we want at least one child group too
    non_root = [g for g in groups if (g.name or "") != (g.tenant_id or "")]
    if non_root:
        return [
            Finding(
                check_id="azure-management-group-hierarchy",
                title=f"{len(non_root)} management group(s) under tenant root",
                description=(
                    f"Hierarchy is in use ({len(non_root)} management group(s) plus the tenant "
                    "root). Policies and RBAC can be inherited at MG scope."
                ),
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.MONITORING,
                resource_type="Azure::Management::Group",
                resource_id="/providers/Microsoft.Management/managementGroups",
                region=region,
                account_id=subscription_id,
                cloud_provider=CloudProvider.AZURE,
                soc2_controls=["CC1.3"],
                mcsb_controls=["GS-1"],
                details={"group_count": len(non_root)},
            )
        ]
    return [
        Finding(
            check_id="azure-management-group-hierarchy",
            title="Subscriptions sit directly under tenant root",
            description=(
                "No management groups exist beneath the tenant root. Without a hierarchy, "
                "policy assignments and RBAC must be applied per subscription, which scales "
                "poorly and creates drift across environments."
            ),
            severity=Severity.LOW,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.MONITORING,
            resource_type="Azure::Management::Group",
            resource_id="/providers/Microsoft.Management/managementGroups",
            region=region,
            account_id=subscription_id,
            cloud_provider=CloudProvider.AZURE,
            remediation=(
                "Build a management group hierarchy: e.g. tenant root > Platform / Sandbox / "
                "Production / NonProd, then move subscriptions into the appropriate group."
            ),
            soc2_controls=["CC1.3"],
            mcsb_controls=["GS-1"],
        )
    ]


def check_security_initiative_assigned(
    client: AzureClient, subscription_id: str, region: str
) -> list[Finding]:
    """[CIS 2.x] At least one recognized security initiative should be assigned at sub or MG scope."""
    try:
        from azure.mgmt.resource import PolicyClient

        policy = client.mgmt_client(PolicyClient)
        assignments = list(policy.policy_assignments.list())
    except Exception as e:
        return [Finding.not_assessed(
            check_id="azure-security-initiative",
            title="Unable to check security initiative assignments",
            description=f"API call failed: {e}",
            domain=CheckDomain.MONITORING,
            resource_type="Azure::Policy::Assignment",
            account_id=subscription_id,
            region=region,
            cloud_provider=CloudProvider.AZURE,
        )]

    initiative_names = [a.display_name or "" for a in assignments]
    matched = [n for n in initiative_names if any(e in n for e in EXPECTED_INITIATIVE_NAMES)]

    if matched:
        return [
            Finding(
                check_id="azure-security-initiative",
                title=f"{len(matched)} security initiative(s) assigned",
                description=(
                    f"Recognized initiative(s) found: {', '.join(matched[:5])}. Continuous "
                    "compliance evaluation is in place."
                ),
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.MONITORING,
                resource_type="Azure::Policy::Assignment",
                resource_id=f"/subscriptions/{subscription_id}/policyAssignments",
                region=region,
                account_id=subscription_id,
                cloud_provider=CloudProvider.AZURE,
                soc2_controls=["CC2.1", "CC4.1"],
                cis_azure_controls=["2.x"],
                mcsb_controls=["GS-1"],
                details={"initiatives": matched},
            )
        ]
    return [
        Finding(
            check_id="azure-security-initiative",
            title="No recognized security initiative assigned",
            description=(
                "None of the standard security initiatives are assigned at this scope. "
                f"Looked for: {', '.join(sorted(EXPECTED_INITIATIVE_NAMES))}. Without one, "
                "Defender for Cloud's regulatory compliance dashboard will be empty and you "
                "have no continuous benchmark scoring."
            ),
            severity=Severity.MEDIUM,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.MONITORING,
            resource_type="Azure::Policy::Assignment",
            resource_id=f"/subscriptions/{subscription_id}/policyAssignments",
            region=region,
            account_id=subscription_id,
            cloud_provider=CloudProvider.AZURE,
            remediation=(
                "Assign 'Microsoft cloud security benchmark' (built-in) at the tenant root "
                "management group, then add CIS Azure Foundations and any regulatory "
                "initiatives needed."
            ),
            soc2_controls=["CC2.1", "CC4.1"],
            cis_azure_controls=["2.x"],
            mcsb_controls=["GS-1"],
            details={"all_assignments": initiative_names[:20]},
        )
    ]


def check_critical_resource_locks(
    client: AzureClient, subscription_id: str, region: str
) -> list[Finding]:
    """[MCSB GS-1] Critical resource groups (KV, RSV, log Storage) should have CanNotDelete locks."""
    try:
        from azure.mgmt.resource import ResourceManagementClient
        from azure.mgmt.resource.locks import ManagementLockClient
    except ImportError:
        return [Finding.not_assessed(
            check_id="azure-resource-locks",
            title="Unable to check resource locks (SDK not installed)",
            description="azure-mgmt-resource package not installed.",
            domain=CheckDomain.MONITORING,
            resource_type="Azure::Authorization::Lock",
            account_id=subscription_id,
            region=region,
            cloud_provider=CloudProvider.AZURE,
        )]

    rm = client.mgmt_client(ResourceManagementClient)
    locks_client = client.mgmt_client(ManagementLockClient)

    # Identify resource groups holding sensitive resources
    sensitive_types = (
        "Microsoft.KeyVault/vaults",
        "Microsoft.RecoveryServices/vaults",
        "Microsoft.OperationalInsights/workspaces",
    )
    sensitive_rgs: set[str] = set()
    try:
        for r in rm.resources.list():
            if (getattr(r, "type", "") or "") in sensitive_types:
                sensitive_rgs.add(_rg_from_id(r.id or ""))
    except Exception:
        pass

    if not sensitive_rgs:
        return []

    findings: list[Finding] = []
    for rg in sorted(sensitive_rgs):
        try:
            locks = list(locks_client.management_locks.list_at_resource_group_level(rg))
        except Exception:
            locks = []
        has_delete_lock = any(
            (getattr(lk, "level", "") or "").lower() == "cannotdelete" for lk in locks
        )
        rid = f"/subscriptions/{subscription_id}/resourceGroups/{rg}"
        if has_delete_lock:
            findings.append(
                Finding(
                    check_id="azure-resource-locks",
                    title=f"Resource group '{rg}' has a CanNotDelete lock",
                    description="Sensitive resource group is protected from accidental deletion.",
                    severity=Severity.INFO,
                    status=ComplianceStatus.PASS,
                    domain=CheckDomain.MONITORING,
                    resource_type="Azure::Authorization::Lock",
                    resource_id=rid,
                    region=region,
                    account_id=subscription_id,
                    cloud_provider=CloudProvider.AZURE,
                    soc2_controls=["A1.2"],
                    mcsb_controls=["GS-1"],
                    details={"resource_group": rg, "lock_count": len(locks)},
                )
            )
        else:
            findings.append(
                Finding(
                    check_id="azure-resource-locks",
                    title=f"Resource group '{rg}' has no delete lock",
                    description=(
                        f"Resource group '{rg}' contains sensitive resources (Key Vault, "
                        "Recovery Services Vault, or Log Analytics workspace) but has no "
                        "CanNotDelete lock. A misclick or compromised admin can wipe the "
                        "entire group."
                    ),
                    severity=Severity.MEDIUM,
                    status=ComplianceStatus.FAIL,
                    domain=CheckDomain.MONITORING,
                    resource_type="Azure::Authorization::Lock",
                    resource_id=rid,
                    region=region,
                    account_id=subscription_id,
                    cloud_provider=CloudProvider.AZURE,
                    remediation=(
                        f"az lock create --name 'protect-{rg}' --lock-type CanNotDelete "
                        f"--resource-group {rg}"
                    ),
                    soc2_controls=["A1.2"],
                    mcsb_controls=["GS-1"],
                    details={"resource_group": rg},
                )
            )
    return findings


def _rg_from_id(rid: str) -> str:
    return rid.split("/resourceGroups/")[1].split("/")[0] if "/resourceGroups/" in rid else ""


def check_required_tags(client: AzureClient, subscription_id: str, region: str) -> list[Finding]:
    """Resource groups should carry owner / environment tags."""
    try:
        from azure.mgmt.resource import ResourceManagementClient

        rm = client.mgmt_client(ResourceManagementClient)
        groups = list(rm.resource_groups.list())
    except Exception as e:
        return [Finding.not_assessed(
            check_id="azure-required-tags",
            title="Unable to check resource group tags",
            description=f"API call failed: {e}",
            domain=CheckDomain.MONITORING,
            resource_type="Azure::Resources::ResourceGroup",
            account_id=subscription_id,
            region=region,
            cloud_provider=CloudProvider.AZURE,
        )]

    required = {"owner", "environment"}
    untagged: list[str] = []
    for g in groups:
        tags = {k.lower() for k in (g.tags or {}).keys()}
        if not required.issubset(tags):
            untagged.append(g.name or "unknown")

    if not untagged:
        return [
            Finding(
                check_id="azure-required-tags",
                title=f"All {len(groups)} resource group(s) carry required tags",
                description="Every resource group has owner and environment tags.",
                severity=Severity.INFO,
                status=ComplianceStatus.PASS,
                domain=CheckDomain.MONITORING,
                resource_type="Azure::Resources::ResourceGroup",
                resource_id=f"/subscriptions/{subscription_id}/resourceGroups",
                region=region,
                account_id=subscription_id,
                cloud_provider=CloudProvider.AZURE,
                soc2_controls=["CC2.1"],
                mcsb_controls=["AM-1"],
            )
        ]
    return [
        Finding(
            check_id="azure-required-tags",
            title=f"{len(untagged)} resource group(s) missing required tags",
            description=(
                f"{len(untagged)} resource group(s) lack 'owner' and/or 'environment' tags. "
                "Without ownership and environment metadata, incident response, cost "
                "allocation, and access reviews are guesswork."
            ),
            severity=Severity.LOW,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.MONITORING,
            resource_type="Azure::Resources::ResourceGroup",
            resource_id=f"/subscriptions/{subscription_id}/resourceGroups",
            region=region,
            account_id=subscription_id,
            cloud_provider=CloudProvider.AZURE,
            remediation=(
                "Use Azure Policy 'Require a tag on resource groups' (built-in, deny effect) "
                "for owner and environment, then backfill missing tags."
            ),
            soc2_controls=["CC2.1"],
            mcsb_controls=["AM-1"],
            details={"untagged_groups": untagged[:20], "total_untagged": len(untagged)},
        )
    ]
