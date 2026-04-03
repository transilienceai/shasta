"""ISO 27001:2022 Annex A control framework definitions.

Maps existing Shasta AWS checks to ISO 27001:2022 Annex A controls.
Same scanner, same findings — different compliance framework view.

ISO 27001:2022 has 93 controls organized into 4 themes:
  - Organizational (A.5): 37 controls
  - People (A.6): 8 controls
  - Physical (A.7): 14 controls
  - Technological (A.8): 34 controls

For cloud-native startups, A.5 and A.8 are the focus. A.6 (people)
is handled by HR/training, A.7 (physical) is N/A.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class ISO27001Theme(str, Enum):
    """ISO 27001:2022 control themes."""

    ORGANIZATIONAL = "Organizational"
    PEOPLE = "People"
    PHYSICAL = "Physical"
    TECHNOLOGICAL = "Technological"


@dataclass
class ISO27001Control:
    """A single ISO 27001:2022 Annex A control."""

    id: str  # e.g., "A.5.15"
    title: str
    description: str
    theme: ISO27001Theme
    check_ids: list[str] = field(default_factory=list)
    requires_policy: bool = False
    guidance: str = ""
    soc2_equivalent: list[str] = field(default_factory=list)  # Cross-reference to SOC 2


ISO27001_CONTROLS: dict[str, ISO27001Control] = {
    # =========================================================================
    # A.5 — Organizational Controls
    # =========================================================================
    "A.5.1": ISO27001Control(
        id="A.5.1",
        title="Policies for information security",
        description="A set of policies for information security shall be defined, approved by management, published, communicated, and reviewed.",
        theme=ISO27001Theme.ORGANIZATIONAL,
        requires_policy=True,
        guidance="Requires a documented information security policy approved by leadership. Use /policy-gen to generate the foundation.",
        soc2_equivalent=["CC1.1", "CC5.1"],
    ),
    "A.5.2": ISO27001Control(
        id="A.5.2",
        title="Information security roles and responsibilities",
        description="Information security roles and responsibilities shall be defined and allocated.",
        theme=ISO27001Theme.ORGANIZATIONAL,
        requires_policy=True,
        guidance="Define who is responsible for security: CISO/security lead, system owners, data custodians. For small teams, one person may hold multiple roles.",
        soc2_equivalent=["CC1.1"],
    ),
    "A.5.8": ISO27001Control(
        id="A.5.8",
        title="Information security in project management",
        description="Information security shall be integrated into project management.",
        theme=ISO27001Theme.ORGANIZATIONAL,
        requires_policy=True,
        guidance="Security reviews should be part of the development lifecycle. GitHub branch protection and PR reviews satisfy this.",
        check_ids=["github-branch-protection", "github-pr-reviews"],
        soc2_equivalent=["CC8.1"],
    ),
    "A.5.10": ISO27001Control(
        id="A.5.10",
        title="Acceptable use of information and assets",
        description="Rules for the acceptable use of information and assets shall be identified, documented, and implemented.",
        theme=ISO27001Theme.ORGANIZATIONAL,
        requires_policy=True,
        guidance="Your Acceptable Use Policy covers this. Ensure all employees acknowledge it.",
        soc2_equivalent=["CC1.1", "CC2.1"],
    ),
    "A.5.12": ISO27001Control(
        id="A.5.12",
        title="Classification of information",
        description="Information shall be classified according to information security needs of the organization.",
        theme=ISO27001Theme.ORGANIZATIONAL,
        requires_policy=True,
        guidance="Your Data Classification Policy defines Confidential/Internal/Public levels.",
        soc2_equivalent=["CC6.7"],
    ),
    "A.5.15": ISO27001Control(
        id="A.5.15",
        title="Access control",
        description="Rules to control physical and logical access to information and other associated assets shall be established and implemented.",
        theme=ISO27001Theme.ORGANIZATIONAL,
        check_ids=["iam-password-policy", "iam-user-mfa", "iam-root-mfa"],
        guidance="Enforce strong authentication: MFA for all users, robust password policy, secured root account.",
        soc2_equivalent=["CC6.1"],
    ),
    "A.5.16": ISO27001Control(
        id="A.5.16",
        title="Identity management",
        description="The full lifecycle of identities shall be managed.",
        theme=ISO27001Theme.ORGANIZATIONAL,
        check_ids=["iam-no-direct-policies", "iam-overprivileged-user"],
        guidance="Manage IAM identities through groups/roles with least privilege. No direct policy attachments.",
        soc2_equivalent=["CC6.2"],
    ),
    "A.5.17": ISO27001Control(
        id="A.5.17",
        title="Authentication information",
        description="Allocation and management of authentication information shall be controlled.",
        theme=ISO27001Theme.ORGANIZATIONAL,
        check_ids=["iam-password-policy", "iam-access-key-rotation"],
        guidance="Password policy meets complexity standards, access keys are rotated within 90 days.",
        soc2_equivalent=["CC6.1", "CC6.3"],
    ),
    "A.5.18": ISO27001Control(
        id="A.5.18",
        title="Access rights",
        description="Access rights to information and assets shall be provisioned, reviewed, modified, and removed in accordance with the organization's access control policy.",
        theme=ISO27001Theme.ORGANIZATIONAL,
        check_ids=["iam-inactive-user", "iam-access-key-rotation"],
        guidance="Review access quarterly, remove inactive users, rotate keys. Use /review-access for formal reviews.",
        soc2_equivalent=["CC6.3"],
    ),
    "A.5.19": ISO27001Control(
        id="A.5.19",
        title="Information security in supplier relationships",
        description="Processes and procedures shall be defined to manage security risks associated with the use of supplier's products or services.",
        theme=ISO27001Theme.ORGANIZATIONAL,
        requires_policy=True,
        guidance="Your Vendor Management Policy covers supplier security. Maintain an active vendor inventory.",
        soc2_equivalent=["CC9.1"],
    ),
    "A.5.23": ISO27001Control(
        id="A.5.23",
        title="Information security for use of cloud services",
        description="Processes for acquisition, use, management, and exit from cloud services shall be established.",
        theme=ISO27001Theme.ORGANIZATIONAL,
        check_ids=[
            "cloudtrail-enabled", "guardduty-enabled", "config-enabled",
            "iam-password-policy", "iam-user-mfa",
            "s3-encryption-at-rest", "sg-no-unrestricted-ingress",
        ],
        guidance="This is the catch-all cloud security control. Your full Shasta scan covers this comprehensively.",
        soc2_equivalent=["CC6.1", "CC6.6", "CC6.7", "CC7.1"],
    ),
    "A.5.24": ISO27001Control(
        id="A.5.24",
        title="Information security incident management planning and preparation",
        description="The organization shall plan and prepare for managing information security incidents.",
        theme=ISO27001Theme.ORGANIZATIONAL,
        requires_policy=True,
        check_ids=["guardduty-enabled"],
        guidance="Your Incident Response Plan + GuardDuty for automated detection. Test the plan annually.",
        soc2_equivalent=["CC7.1", "CC7.2"],
    ),
    "A.5.29": ISO27001Control(
        id="A.5.29",
        title="Information security during disruption",
        description="The organization shall plan how to maintain information security at an appropriate level during disruption.",
        theme=ISO27001Theme.ORGANIZATIONAL,
        check_ids=["rds-backup-enabled"],
        requires_policy=True,
        guidance="Your BCP/DR Plan + automated backups (RDS, S3 versioning). Test recovery annually.",
        soc2_equivalent=["CC9.1"],
    ),
    "A.5.30": ISO27001Control(
        id="A.5.30",
        title="ICT readiness for business continuity",
        description="ICT readiness shall be planned, implemented, maintained, and tested based on business continuity objectives.",
        theme=ISO27001Theme.ORGANIZATIONAL,
        check_ids=["rds-backup-enabled", "s3-versioning"],
        guidance="Verify backup retention, test restoration, document RTO/RPO in BCP.",
        soc2_equivalent=["CC9.1"],
    ),

    # =========================================================================
    # A.6 — People Controls (mostly policy/process)
    # =========================================================================
    "A.6.1": ISO27001Control(
        id="A.6.1",
        title="Screening",
        description="Background verification checks on candidates shall be carried out prior to joining.",
        theme=ISO27001Theme.PEOPLE,
        requires_policy=True,
        guidance="Background checks before hiring. Document the process in HR procedures.",
    ),
    "A.6.3": ISO27001Control(
        id="A.6.3",
        title="Information security awareness, education and training",
        description="Personnel shall receive appropriate security awareness education and training.",
        theme=ISO27001Theme.PEOPLE,
        requires_policy=True,
        guidance="Security awareness training at onboarding + annual refresher. Use your e-learning portal.",
        soc2_equivalent=["CC2.1"],
    ),
    "A.6.5": ISO27001Control(
        id="A.6.5",
        title="Responsibilities after termination or change of employment",
        description="Information security responsibilities that remain valid after termination or change shall be defined, enforced, and communicated.",
        theme=ISO27001Theme.PEOPLE,
        check_ids=["iam-inactive-user"],
        guidance="Revoke access within 24 hours of termination. Access review catches lingering accounts.",
        soc2_equivalent=["CC6.3"],
    ),

    # =========================================================================
    # A.8 — Technological Controls
    # =========================================================================
    "A.8.1": ISO27001Control(
        id="A.8.1",
        title="User endpoint devices",
        description="Information stored on, processed by, or accessible via user endpoint devices shall be protected.",
        theme=ISO27001Theme.TECHNOLOGICAL,
        requires_policy=True,
        guidance="Require disk encryption, screen locks, and endpoint protection on all company devices. MDM integration recommended.",
    ),
    "A.8.3": ISO27001Control(
        id="A.8.3",
        title="Information access restriction",
        description="Access to information and application functions shall be restricted in accordance with the access control policy.",
        theme=ISO27001Theme.TECHNOLOGICAL,
        check_ids=["iam-overprivileged-user", "s3-public-access-block"],
        guidance="Least privilege enforced through IAM. S3 public access blocked. No admin policies on regular users.",
        soc2_equivalent=["CC6.2", "CC6.7"],
    ),
    "A.8.5": ISO27001Control(
        id="A.8.5",
        title="Secure authentication",
        description="Secure authentication technologies and procedures shall be established and implemented.",
        theme=ISO27001Theme.TECHNOLOGICAL,
        check_ids=["iam-root-mfa", "iam-user-mfa", "iam-password-policy"],
        guidance="MFA on all accounts, strong password policy, no shared credentials.",
        soc2_equivalent=["CC6.1"],
    ),
    "A.8.9": ISO27001Control(
        id="A.8.9",
        title="Configuration management",
        description="Configurations, including security configurations, of hardware, software, services, and networks shall be established, documented, maintained, and reviewed.",
        theme=ISO27001Theme.TECHNOLOGICAL,
        check_ids=["config-enabled", "cloudtrail-enabled"],
        guidance="AWS Config records all resource configurations. CloudTrail logs all changes.",
        soc2_equivalent=["CC7.1", "CC8.1"],
    ),
    "A.8.12": ISO27001Control(
        id="A.8.12",
        title="Data leakage prevention",
        description="Data leakage prevention measures shall be applied to systems, networks, and any other devices that process, store, or transmit sensitive information.",
        theme=ISO27001Theme.TECHNOLOGICAL,
        check_ids=["s3-public-access-block", "s3-ssl-only", "rds-no-public-access"],
        guidance="Block public S3 access, enforce SSL, keep databases private.",
        soc2_equivalent=["CC6.6", "CC6.7"],
    ),
    "A.8.15": ISO27001Control(
        id="A.8.15",
        title="Logging",
        description="Logs that record activities, exceptions, faults, and other relevant events shall be produced, stored, protected, and analysed.",
        theme=ISO27001Theme.TECHNOLOGICAL,
        check_ids=["cloudtrail-enabled", "vpc-flow-logs-enabled"],
        guidance="CloudTrail for API activity, VPC flow logs for network traffic. Minimum 1 year retention.",
        soc2_equivalent=["CC7.1"],
    ),
    "A.8.16": ISO27001Control(
        id="A.8.16",
        title="Monitoring activities",
        description="Networks, systems, and applications shall be monitored for anomalous behaviour and appropriate actions taken.",
        theme=ISO27001Theme.TECHNOLOGICAL,
        check_ids=["guardduty-enabled", "guardduty-no-active-findings"],
        guidance="GuardDuty for ML-based threat detection. Review and respond to all findings.",
        soc2_equivalent=["CC7.2"],
    ),
    "A.8.20": ISO27001Control(
        id="A.8.20",
        title="Networks security",
        description="Networks and network devices shall be secured, managed, and controlled to protect information in systems and applications.",
        theme=ISO27001Theme.TECHNOLOGICAL,
        check_ids=["sg-no-unrestricted-ingress", "vpc-flow-logs-enabled", "sg-default-restricted"],
        guidance="Restrict security groups, enable flow logs, lock down default SGs.",
        soc2_equivalent=["CC6.6"],
    ),
    "A.8.21": ISO27001Control(
        id="A.8.21",
        title="Security of network services",
        description="Security mechanisms, service levels, and service requirements of network services shall be identified, implemented, and monitored.",
        theme=ISO27001Theme.TECHNOLOGICAL,
        check_ids=["s3-ssl-only", "sg-no-unrestricted-ingress"],
        guidance="Enforce TLS everywhere. Restrict network service access to known sources.",
        soc2_equivalent=["CC6.6", "CC6.7"],
    ),
    "A.8.24": ISO27001Control(
        id="A.8.24",
        title="Use of cryptography",
        description="Rules for the effective use of cryptography, including management of cryptographic keys, shall be defined and implemented.",
        theme=ISO27001Theme.TECHNOLOGICAL,
        check_ids=[
            "s3-encryption-at-rest", "ebs-encryption-by-default",
            "ebs-volume-encrypted", "rds-encryption-at-rest",
        ],
        guidance="Encrypt everything at rest (S3, EBS, RDS) using KMS. Encrypt in transit with TLS.",
        soc2_equivalent=["CC6.7"],
    ),
    "A.8.25": ISO27001Control(
        id="A.8.25",
        title="Secure development lifecycle",
        description="Rules for the secure development of software and systems shall be established and applied.",
        theme=ISO27001Theme.TECHNOLOGICAL,
        check_ids=["github-branch-protection", "github-pr-reviews", "github-status-checks"],
        guidance="Branch protection, mandatory code review, CI/CD checks before merge.",
        soc2_equivalent=["CC8.1"],
    ),
    "A.8.26": ISO27001Control(
        id="A.8.26",
        title="Application security requirements",
        description="Information security requirements shall be identified, specified, and approved when developing or acquiring applications.",
        theme=ISO27001Theme.TECHNOLOGICAL,
        check_ids=["inspector-enabled", "inspector-critical-findings"],
        guidance="AWS Inspector scans for vulnerabilities. SBOM tracks dependencies.",
        soc2_equivalent=["CC7.1"],
    ),
    "A.8.28": ISO27001Control(
        id="A.8.28",
        title="Secure coding",
        description="Secure coding principles shall be applied to software development.",
        theme=ISO27001Theme.TECHNOLOGICAL,
        check_ids=["github-pr-reviews", "github-status-checks"],
        guidance="Code reviews catch security issues. Automated tests verify security properties.",
        soc2_equivalent=["CC8.1"],
    ),
    "A.8.32": ISO27001Control(
        id="A.8.32",
        title="Change management",
        description="Changes to information processing facilities and information systems shall be subject to change management procedures.",
        theme=ISO27001Theme.TECHNOLOGICAL,
        check_ids=["cloudtrail-enabled", "config-enabled"],
        guidance="CloudTrail logs all API changes. AWS Config tracks configuration drift. Your Change Management Policy documents the process.",
        soc2_equivalent=["CC8.1"],
    ),
}


# ---------------------------------------------------------------------------
# Helper functions (mirror framework.py pattern)
# ---------------------------------------------------------------------------

def get_iso27001_control(control_id: str) -> ISO27001Control | None:
    return ISO27001_CONTROLS.get(control_id)


def get_iso27001_controls_for_check(check_id: str) -> list[ISO27001Control]:
    return [ctrl for ctrl in ISO27001_CONTROLS.values() if check_id in ctrl.check_ids]


def get_automated_iso27001_controls() -> list[ISO27001Control]:
    return [ctrl for ctrl in ISO27001_CONTROLS.values() if ctrl.check_ids]


def get_policy_required_iso27001_controls() -> list[ISO27001Control]:
    return [ctrl for ctrl in ISO27001_CONTROLS.values() if ctrl.requires_policy]
