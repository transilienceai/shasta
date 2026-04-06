"""SOC 2 Trust Service Criteria framework definitions.

Defines the SOC 2 controls, their descriptions, and which automated
checks map to each control.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class ControlCategory(str, Enum):
    """SOC 2 Trust Service Categories."""

    SECURITY = "Security"
    AVAILABILITY = "Availability"
    PROCESSING_INTEGRITY = "Processing Integrity"
    CONFIDENTIALITY = "Confidentiality"
    PRIVACY = "Privacy"


@dataclass
class SOC2Control:
    """A single SOC 2 control point."""

    id: str  # e.g., "CC6.1"
    title: str
    description: str
    category: ControlCategory
    check_ids: list[str] = field(default_factory=list)  # Automated checks that map here
    requires_policy: bool = False  # Needs a policy document (not just AWS checks)
    guidance: str = ""  # Plain-English guidance for the founder


# ---------------------------------------------------------------------------
# SOC 2 Security Controls (CC1–CC9) — Phase 1 focuses on CC6, CC7, CC8
# ---------------------------------------------------------------------------

SOC2_CONTROLS: dict[str, SOC2Control] = {
    # CC6 — Logical and Physical Access Controls
    "CC6.1": SOC2Control(
        id="CC6.1",
        title="Logical Access Security",
        description="The entity implements logical access security software, infrastructure, and architectures over protected information assets to protect them from security events.",
        category=ControlCategory.SECURITY,
        check_ids=[
            "iam-password-policy",
            "iam-root-mfa",
            "iam-root-access-keys",
            "iam-user-mfa",
            # Azure
            "azure-conditional-access-mfa",
            "azure-privileged-roles",
        ],
        guidance="This control requires strong authentication: MFA for all users, a robust password policy, and protected root/admin account credentials.",
    ),
    "CC6.2": SOC2Control(
        id="CC6.2",
        title="Access Provisioning",
        description="Prior to issuing system credentials and granting system access, the entity registers and authorizes new internal and external users.",
        category=ControlCategory.SECURITY,
        check_ids=[
            "iam-no-direct-policies",
            "iam-overprivileged-user",
            "iam-role-trust-overpermissive",
            # Azure
            "azure-rbac-least-privilege",
            "azure-service-principal-hygiene",
            "azure-pim-enabled",
        ],
        guidance="This control requires least-privilege access: users get only the permissions they need, managed through groups/roles, not direct policy attachments.",
    ),
    "CC6.3": SOC2Control(
        id="CC6.3",
        title="Access Removal",
        description="The entity removes access to protected information assets when appropriate, based on termination or changes in job function.",
        category=ControlCategory.SECURITY,
        check_ids=[
            "iam-access-key-rotation",
            "iam-inactive-user",
            # Azure
            "azure-inactive-users",
            "azure-guest-access",
        ],
        guidance="This control requires timely removal of access: rotate credentials regularly, disable inactive accounts, and have a process for offboarding.",
    ),
    "CC6.6": SOC2Control(
        id="CC6.6",
        title="System Boundaries",
        description="The entity implements logical access security measures to protect against threats from sources outside its system boundaries.",
        category=ControlCategory.SECURITY,
        check_ids=[
            "sg-no-unrestricted-ingress",
            "vpc-flow-logs-enabled",
            "ec2-imdsv1-enabled",
            # Azure
            "azure-nsg-unrestricted-ingress",
            "azure-nsg-default-restricted",
            "azure-vnet-flow-logs",
            "azure-public-ip-exposure",
            "azure-sql-public-access",
            "azure-app-service-https",
            "azure-bastion-deployed",
            "azure-aks-rbac",
        ],
        guidance="This control requires network segmentation: restrict inbound traffic, use private subnets/VNets, and enable flow logs for monitoring.",
    ),
    "CC6.7": SOC2Control(
        id="CC6.7",
        title="Data Protection in Transit and at Rest",
        description="The entity restricts the transmission, movement, and removal of information to authorized internal and external users and processes.",
        category=ControlCategory.SECURITY,
        check_ids=[
            "s3-encryption-at-rest",
            "s3-ssl-only",
            "s3-versioning",
            "s3-public-access-block",
            "s3-acl-not-public",
            "ebs-snapshot-public",
            "rds-snapshot-public",
            "kms-key-rotation",
            # Azure
            "azure-storage-encryption",
            "azure-storage-https-only",
            "azure-blob-public-access",
            "azure-storage-soft-delete",
            "azure-disk-encryption",
            "azure-sql-tde",
            "azure-keyvault-config",
        ],
        guidance="This control requires encryption everywhere: data at rest (S3/Storage/Disks), data in transit (TLS/SSL), and access controls on storage.",
    ),
    # CC7 — System Operations / Monitoring
    "CC7.1": SOC2Control(
        id="CC7.1",
        title="Detection and Monitoring",
        description="To meet its objectives, the entity uses detection and monitoring procedures to identify changes to configurations that result in the introduction of new vulnerabilities.",
        category=ControlCategory.SECURITY,
        check_ids=[
            "cloudtrail-enabled",
            "guardduty-enabled",
            "config-enabled",
            # Azure
            "azure-activity-log",
            "azure-defender-enabled",
            "azure-policy-compliance",
        ],
        guidance="This control requires comprehensive logging: CloudTrail/Activity Log for API activity, GuardDuty/Defender for threat detection, and Config/Policy for configuration tracking.",
    ),
    "CC7.2": SOC2Control(
        id="CC7.2",
        title="Anomaly Monitoring",
        description="The entity monitors system components and the operation of those components for anomalies that are indicative of malicious acts.",
        category=ControlCategory.SECURITY,
        check_ids=[
            "guardduty-enabled",
            "guardduty-no-active-findings",
            # Azure
            "azure-defender-enabled",
            "azure-monitor-alerts",
        ],
        guidance="This control requires active threat monitoring: GuardDuty/Defender for anomaly detection, and a process to review and respond to findings.",
    ),
    # CC8 — Change Management
    "CC8.1": SOC2Control(
        id="CC8.1",
        title="Change Management",
        description="The entity authorizes, designs, develops, configures, documents, tests, approves, and implements changes to infrastructure, data, software, and procedures.",
        category=ControlCategory.SECURITY,
        check_ids=[
            "cloudtrail-enabled",
            "config-enabled",
            # Azure
            "azure-activity-log",
            "azure-policy-compliance",
        ],
        requires_policy=True,
        guidance="This control requires change tracking: CloudTrail/Activity Log logs all API changes, Config/Policy records configuration history, and you need a documented change management policy.",
    ),
    # Non-automated controls (require policies/processes)
    "CC1.1": SOC2Control(
        id="CC1.1",
        title="Control Environment",
        description="The entity demonstrates a commitment to integrity and ethical values.",
        category=ControlCategory.SECURITY,
        requires_policy=True,
        guidance="This requires a code of conduct, defined security responsibilities, and board/management oversight of the control environment.",
    ),
    "CC2.1": SOC2Control(
        id="CC2.1",
        title="Information and Communication",
        description="The entity obtains or generates and uses relevant, quality information to support the functioning of internal control.",
        category=ControlCategory.SECURITY,
        requires_policy=True,
        guidance="This requires security awareness training, an incident communication plan, and processes for sharing security-relevant information.",
    ),
    "CC3.1": SOC2Control(
        id="CC3.1",
        title="Risk Assessment",
        description="The entity specifies objectives with sufficient clarity to enable the identification and assessment of risks.",
        category=ControlCategory.SECURITY,
        requires_policy=True,
        guidance="This requires a risk register, annual risk assessment process, and documented risk treatment decisions.",
    ),
    "CC5.1": SOC2Control(
        id="CC5.1",
        title="Control Activities",
        description="The entity selects and develops control activities that contribute to the mitigation of risks to the achievement of objectives.",
        category=ControlCategory.SECURITY,
        requires_policy=True,
        guidance="This requires IT general controls, segregation of duties, and documented control procedures.",
    ),
    "CC9.1": SOC2Control(
        id="CC9.1",
        title="Risk Mitigation",
        description="The entity identifies, selects, and develops risk mitigation activities for risks arising from potential business disruptions.",
        category=ControlCategory.SECURITY,
        check_ids=[
            "vendor-dns-spf",
            "vendor-dns-dmarc",
            "vendor-ssl-validity",
            "vendor-ssl-version",
            "vendor-http-hsts",
            "vendor-http-https-redirect",
            "vendor-breach-history",
            "vendor-trust-certifications",
            "vendor-ports-summary",
        ],
        requires_policy=True,
        guidance="This requires vendor management (use /vendor-risk to assess vendors), business continuity planning, disaster recovery procedures, and appropriate insurance.",
    ),
}


def get_control(control_id: str) -> SOC2Control | None:
    """Look up a SOC 2 control by ID."""
    return SOC2_CONTROLS.get(control_id)


def get_controls_for_check(check_id: str) -> list[SOC2Control]:
    """Find all SOC 2 controls that a given check maps to."""
    return [ctrl for ctrl in SOC2_CONTROLS.values() if check_id in ctrl.check_ids]


def get_automated_controls() -> list[SOC2Control]:
    """Get all controls that have automated checks."""
    return [ctrl for ctrl in SOC2_CONTROLS.values() if ctrl.check_ids]


def get_policy_required_controls() -> list[SOC2Control]:
    """Get all controls that require policy documents."""
    return [ctrl for ctrl in SOC2_CONTROLS.values() if ctrl.requires_policy]
