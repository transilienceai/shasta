"""HIPAA Security Rule framework definitions.

Maps Shasta cloud checks (AWS + Azure) to HIPAA Security Rule safeguards.
Same scanner, same findings — different compliance framework view.

The HIPAA Security Rule (45 CFR Part 164) has safeguards organized into:
  - Administrative Safeguards (164.308): policies, procedures, workforce security
  - Physical Safeguards (164.310): facility access, workstation, device controls
  - Technical Safeguards (164.312): access control, audit, integrity, transmission
  - Breach Notification (164.400-series): incident notification requirements

For cloud-native organizations handling ePHI, Technical Safeguards (164.312)
are the primary focus. Administrative Safeguards require documented policies.
Physical Safeguards are largely N/A when infrastructure is fully in AWS/Azure.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class HIPAASafeguard(str, Enum):
    """HIPAA Security Rule safeguard categories."""

    ADMINISTRATIVE = "Administrative"
    PHYSICAL = "Physical"
    TECHNICAL = "Technical"


@dataclass
class HIPAAControl:
    """A single HIPAA Security Rule control."""

    id: str  # e.g., "164.308(a)(1)"
    title: str
    description: str
    safeguard: HIPAASafeguard
    check_ids: list[str] = field(default_factory=list)
    requires_policy: bool = False
    guidance: str = ""
    soc2_equivalent: list[str] = field(default_factory=list)
    iso27001_equivalent: list[str] = field(default_factory=list)


HIPAA_CONTROLS: dict[str, HIPAAControl] = {
    # =========================================================================
    # Administrative Safeguards — 164.308
    # =========================================================================
    "164.308(a)(1)": HIPAAControl(
        id="164.308(a)(1)",
        title="Security Management Process",
        description="Implement policies and procedures to prevent, detect, contain, and correct security violations.",
        safeguard=HIPAASafeguard.ADMINISTRATIVE,
        check_ids=[
            "guardduty-enabled",
            "azure-defender-enabled",
        ],
        requires_policy=True,
        guidance="Requires a documented security management process including risk analysis, risk management, sanction policy, and information system activity review. GuardDuty/Defender provides automated threat detection.",
        soc2_equivalent=["CC3.1", "CC7.1"],
        iso27001_equivalent=["A.5.1", "A.5.24"],
    ),
    "164.308(a)(2)": HIPAAControl(
        id="164.308(a)(2)",
        title="Assigned Security Responsibility",
        description="Identify the security official responsible for developing and implementing security policies and procedures.",
        safeguard=HIPAASafeguard.ADMINISTRATIVE,
        requires_policy=True,
        guidance="Designate a HIPAA Security Officer responsible for ePHI protection. For startups, the CTO or security lead typically holds this role.",
        soc2_equivalent=["CC1.1"],
        iso27001_equivalent=["A.5.2"],
    ),
    "164.308(a)(3)": HIPAAControl(
        id="164.308(a)(3)",
        title="Workforce Security",
        description="Implement policies and procedures to ensure all members of the workforce have appropriate access to ePHI and to prevent unauthorized access.",
        safeguard=HIPAASafeguard.ADMINISTRATIVE,
        check_ids=[
            "iam-inactive-user",
            "azure-inactive-users",
            "iam-overprivileged-user",
            "azure-rbac-least-privilege",
        ],
        guidance="Ensure workforce members have appropriate ePHI access. Remove access for terminated employees within 24 hours. Review access quarterly.",
        soc2_equivalent=["CC6.2", "CC6.3"],
        iso27001_equivalent=["A.5.16", "A.5.18", "A.6.5"],
    ),
    "164.308(a)(4)": HIPAAControl(
        id="164.308(a)(4)",
        title="Information Access Management",
        description="Implement policies and procedures for authorizing access to ePHI consistent with the minimum necessary standard.",
        safeguard=HIPAASafeguard.ADMINISTRATIVE,
        check_ids=[
            "iam-no-direct-policies",
            "iam-overprivileged-user",
            "azure-rbac-least-privilege",
            "iam-role-trust-overpermissive",
        ],
        guidance="Enforce least-privilege access to ePHI. Use role-based access through groups, not direct policy attachments. Document access authorization procedures.",
        soc2_equivalent=["CC6.1", "CC6.2"],
        iso27001_equivalent=["A.5.15", "A.5.16", "A.8.3"],
    ),
    "164.308(a)(5)": HIPAAControl(
        id="164.308(a)(5)",
        title="Security Awareness and Training",
        description="Implement a security awareness and training program for all workforce members including management.",
        safeguard=HIPAASafeguard.ADMINISTRATIVE,
        requires_policy=True,
        guidance="Provide HIPAA security training at onboarding and annually. Cover password management, phishing awareness, incident reporting, and ePHI handling procedures.",
        soc2_equivalent=["CC2.1"],
        iso27001_equivalent=["A.6.3"],
    ),
    "164.308(a)(6)": HIPAAControl(
        id="164.308(a)(6)",
        title="Security Incident Procedures",
        description="Implement policies and procedures to address security incidents.",
        safeguard=HIPAASafeguard.ADMINISTRATIVE,
        check_ids=[
            "guardduty-enabled",
            "azure-defender-enabled",
        ],
        requires_policy=True,
        guidance="Document incident response procedures specific to ePHI breaches. GuardDuty/Defender provides automated detection. Maintain incident logs and conduct post-incident analysis.",
        soc2_equivalent=["CC7.1", "CC7.2"],
        iso27001_equivalent=["A.5.24"],
    ),
    "164.308(a)(7)": HIPAAControl(
        id="164.308(a)(7)",
        title="Contingency Plan",
        description="Establish policies and procedures for responding to an emergency or other occurrence that damages systems containing ePHI.",
        safeguard=HIPAASafeguard.ADMINISTRATIVE,
        check_ids=[
            "rds-backup-enabled",
            "s3-versioning",
            "azure-storage-soft-delete",
        ],
        requires_policy=True,
        guidance="Maintain a contingency plan with data backup, disaster recovery, and emergency mode operation procedures. Test the plan annually. Automated backups satisfy the data backup requirement.",
        soc2_equivalent=["CC9.1"],
        iso27001_equivalent=["A.5.29", "A.5.30"],
    ),
    "164.308(a)(8)": HIPAAControl(
        id="164.308(a)(8)",
        title="Evaluation",
        description="Perform a periodic technical and nontechnical evaluation to establish the extent to which security policies and procedures meet the requirements of the Security Rule.",
        safeguard=HIPAASafeguard.ADMINISTRATIVE,
        requires_policy=True,
        guidance="Conduct an annual security evaluation (this scan counts as the technical component). Document the evaluation process, findings, and remediation timeline.",
        soc2_equivalent=["CC3.1"],
        iso27001_equivalent=["A.5.1"],
    ),
    "164.308(b)(1)": HIPAAControl(
        id="164.308(b)(1)",
        title="Business Associate Agreements",
        description="A covered entity must obtain satisfactory assurances from business associates that they will appropriately safeguard ePHI.",
        safeguard=HIPAASafeguard.ADMINISTRATIVE,
        requires_policy=True,
        guidance="Maintain signed BAAs with all vendors that access, store, or transmit ePHI. Your cloud provider offers a BAA — ensure yours is signed. Track BAA status in your vendor inventory.",
        soc2_equivalent=["CC9.1"],
        iso27001_equivalent=["A.5.19"],
    ),
    # =========================================================================
    # Physical Safeguards — 164.310
    # =========================================================================
    "164.310(a)(1)": HIPAAControl(
        id="164.310(a)(1)",
        title="Facility Access Controls",
        description="Implement policies and procedures to limit physical access to electronic information systems and the facilities in which they are housed.",
        safeguard=HIPAASafeguard.PHYSICAL,
        requires_policy=True,
        guidance="For cloud-native organizations, cloud provider data centers handle physical facility security. Document that your infrastructure is cloud-hosted and reference the provider's SOC 2 report for physical controls.",
        soc2_equivalent=["CC6.1"],
        iso27001_equivalent=["A.5.15"],
    ),
    "164.310(b)": HIPAAControl(
        id="164.310(b)",
        title="Workstation Use",
        description="Implement policies and procedures that specify the proper functions to be performed and the manner in which those functions are to be performed on workstations that access ePHI.",
        safeguard=HIPAASafeguard.PHYSICAL,
        requires_policy=True,
        guidance="Document acceptable workstation use policies for ePHI access. Require screen locks, disk encryption, and VPN for remote access to ePHI systems.",
        soc2_equivalent=["CC6.1"],
        iso27001_equivalent=["A.8.1"],
    ),
    "164.310(c)": HIPAAControl(
        id="164.310(c)",
        title="Workstation Security",
        description="Implement physical safeguards for all workstations that access ePHI to restrict access to authorized users.",
        safeguard=HIPAASafeguard.PHYSICAL,
        requires_policy=True,
        guidance="Enforce endpoint protection: full-disk encryption, automatic screen lock, endpoint detection and response (EDR) software. MDM for company-owned devices.",
        soc2_equivalent=["CC6.1"],
        iso27001_equivalent=["A.8.1"],
    ),
    "164.310(d)(1)": HIPAAControl(
        id="164.310(d)(1)",
        title="Device and Media Controls",
        description="Implement policies and procedures that govern the receipt and removal of hardware and electronic media containing ePHI.",
        safeguard=HIPAASafeguard.PHYSICAL,
        check_ids=[
            "ebs-encryption-by-default",
            "azure-disk-encryption",
        ],
        requires_policy=True,
        guidance="Encrypt all storage volumes containing ePHI. Document media disposal procedures. For cloud, encryption at rest ensures disposed disks are unreadable.",
        soc2_equivalent=["CC6.7"],
        iso27001_equivalent=["A.8.24"],
    ),
    # =========================================================================
    # Technical Safeguards — 164.312
    # =========================================================================
    "164.312(a)(1)": HIPAAControl(
        id="164.312(a)(1)",
        title="Access Control",
        description="Implement technical policies and procedures for electronic information systems that maintain ePHI to allow access only to authorized persons or software programs.",
        safeguard=HIPAASafeguard.TECHNICAL,
        check_ids=[
            "iam-password-policy",
            "iam-user-mfa",
            "iam-root-mfa",
            "azure-conditional-access-mfa",
            "azure-privileged-roles",
            "azure-pim-enabled",
        ],
        guidance="Enforce multi-factor authentication for all users accessing ePHI systems. Use strong password policies and privileged identity management.",
        soc2_equivalent=["CC6.1"],
        iso27001_equivalent=["A.5.15", "A.8.5"],
    ),
    "164.312(a)(2)(i)": HIPAAControl(
        id="164.312(a)(2)(i)",
        title="Unique User Identification",
        description="Assign a unique name and/or number for identifying and tracking user identity.",
        safeguard=HIPAASafeguard.TECHNICAL,
        check_ids=[
            "iam-user-mfa",
            "azure-conditional-access-mfa",
        ],
        guidance="Every user must have a unique identifier — no shared accounts. MFA enforcement verifies that each login is the actual account owner.",
        soc2_equivalent=["CC6.1"],
        iso27001_equivalent=["A.5.16", "A.8.5"],
    ),
    "164.312(a)(2)(ii)": HIPAAControl(
        id="164.312(a)(2)(ii)",
        title="Emergency Access Procedure",
        description="Establish procedures for obtaining necessary ePHI during an emergency.",
        safeguard=HIPAASafeguard.TECHNICAL,
        requires_policy=True,
        guidance="Document break-glass procedures for emergency ePHI access. Include a sealed emergency admin account with MFA, and log all emergency access for post-incident review.",
        soc2_equivalent=["CC9.1"],
        iso27001_equivalent=["A.5.29"],
    ),
    "164.312(a)(2)(iii)": HIPAAControl(
        id="164.312(a)(2)(iii)",
        title="Automatic Logoff",
        description="Implement electronic procedures that terminate an electronic session after a predetermined time of inactivity.",
        safeguard=HIPAASafeguard.TECHNICAL,
        requires_policy=True,
        guidance="Configure session timeouts for all systems accessing ePHI. Cloud console sessions should timeout after 1 hour max. Application sessions should timeout after 15 minutes of inactivity.",
        soc2_equivalent=["CC6.1"],
        iso27001_equivalent=["A.8.5"],
    ),
    "164.312(a)(2)(iv)": HIPAAControl(
        id="164.312(a)(2)(iv)",
        title="Encryption and Decryption",
        description="Implement a mechanism to encrypt and decrypt ePHI.",
        safeguard=HIPAASafeguard.TECHNICAL,
        check_ids=[
            "s3-encryption-at-rest",
            "ebs-encryption-by-default",
            "ebs-volume-encrypted",
            "rds-encryption-at-rest",
            "azure-disk-encryption",
            "azure-sql-tde",
            "azure-keyvault-config",
            "azure-storage-encryption",
        ],
        guidance="Encrypt all ePHI at rest using AES-256 via KMS/Key Vault. Covers S3/Storage, EBS/Disks, RDS/SQL databases. Use customer-managed keys for sensitive workloads.",
        soc2_equivalent=["CC6.7"],
        iso27001_equivalent=["A.8.24"],
    ),
    "164.312(b)": HIPAAControl(
        id="164.312(b)",
        title="Audit Controls",
        description="Implement hardware, software, and/or procedural mechanisms that record and examine activity in information systems that contain or use ePHI.",
        safeguard=HIPAASafeguard.TECHNICAL,
        check_ids=[
            "cloudtrail-enabled",
            "vpc-flow-logs-enabled",
            "config-enabled",
            "azure-activity-log",
            "azure-vnet-flow-logs",
            "azure-policy-compliance",
        ],
        guidance="Enable comprehensive audit logging: CloudTrail/Activity Log for API calls, VPC/VNet flow logs for network activity, Config/Policy for configuration changes. Retain logs for minimum 6 years per HIPAA.",
        soc2_equivalent=["CC7.1"],
        iso27001_equivalent=["A.8.15", "A.8.9"],
    ),
    "164.312(c)(1)": HIPAAControl(
        id="164.312(c)(1)",
        title="Integrity Controls",
        description="Implement policies and procedures to protect ePHI from improper alteration or destruction.",
        safeguard=HIPAASafeguard.TECHNICAL,
        check_ids=[
            "config-enabled",
            "s3-versioning",
            "azure-storage-soft-delete",
            "azure-policy-compliance",
        ],
        guidance="Enable versioning on storage containing ePHI to prevent data loss. Config/Policy detects unauthorized configuration changes. Use object lock for immutable ePHI records.",
        soc2_equivalent=["CC6.7", "CC7.1"],
        iso27001_equivalent=["A.8.9", "A.8.24"],
    ),
    "164.312(c)(2)": HIPAAControl(
        id="164.312(c)(2)",
        title="Mechanism to Authenticate ePHI",
        description="Implement electronic mechanisms to corroborate that ePHI has not been altered or destroyed in an unauthorized manner.",
        safeguard=HIPAASafeguard.TECHNICAL,
        check_ids=[
            "s3-versioning",
            "azure-storage-soft-delete",
        ],
        guidance="S3 versioning and Azure soft delete provide tamper-evident storage. Use checksums/hashes for ePHI integrity verification.",
        soc2_equivalent=["CC6.7"],
        iso27001_equivalent=["A.8.24"],
    ),
    "164.312(d)": HIPAAControl(
        id="164.312(d)",
        title="Person or Entity Authentication",
        description="Implement procedures to verify that a person or entity seeking access to ePHI is the one claimed.",
        safeguard=HIPAASafeguard.TECHNICAL,
        check_ids=[
            "iam-user-mfa",
            "iam-root-mfa",
            "iam-password-policy",
            "azure-conditional-access-mfa",
            "azure-pim-enabled",
        ],
        guidance="Multi-factor authentication verifies identity before ePHI access. Password policy ensures credential strength. PIM provides just-in-time privileged access.",
        soc2_equivalent=["CC6.1"],
        iso27001_equivalent=["A.5.15", "A.8.5"],
    ),
    "164.312(e)(1)": HIPAAControl(
        id="164.312(e)(1)",
        title="Transmission Security",
        description="Implement technical security measures to guard against unauthorized access to ePHI being transmitted over an electronic communications network.",
        safeguard=HIPAASafeguard.TECHNICAL,
        check_ids=[
            "s3-ssl-only",
            "azure-storage-https-only",
            "azure-app-service-https",
            "sg-no-unrestricted-ingress",
            "azure-nsg-unrestricted-ingress",
        ],
        guidance="Enforce TLS/SSL for all ePHI in transit. Restrict network access to known sources. Block unencrypted protocols on storage endpoints.",
        soc2_equivalent=["CC6.6", "CC6.7"],
        iso27001_equivalent=["A.8.20", "A.8.21", "A.8.24"],
    ),
    "164.312(e)(2)(i)": HIPAAControl(
        id="164.312(e)(2)(i)",
        title="Integrity Controls for Transmission",
        description="Implement security measures to ensure that electronically transmitted ePHI is not improperly modified without detection.",
        safeguard=HIPAASafeguard.TECHNICAL,
        check_ids=[
            "s3-ssl-only",
            "azure-storage-https-only",
        ],
        guidance="TLS provides integrity protection for data in transit. Enforce HTTPS-only on all storage endpoints handling ePHI.",
        soc2_equivalent=["CC6.7"],
        iso27001_equivalent=["A.8.21", "A.8.24"],
    ),
    "164.312(e)(2)(ii)": HIPAAControl(
        id="164.312(e)(2)(ii)",
        title="Encryption for Transmission",
        description="Implement a mechanism to encrypt ePHI whenever deemed appropriate.",
        safeguard=HIPAASafeguard.TECHNICAL,
        check_ids=[
            "s3-ssl-only",
            "azure-storage-https-only",
            "azure-app-service-https",
        ],
        guidance="Encrypt all ePHI in transit using TLS 1.2+. Enforce HTTPS on all storage, application, and API endpoints.",
        soc2_equivalent=["CC6.7"],
        iso27001_equivalent=["A.8.21", "A.8.24"],
    ),
    # =========================================================================
    # Breach Notification Rule — 164.400-series (policy only)
    # =========================================================================
    "164.402": HIPAAControl(
        id="164.402",
        title="Breach Definition",
        description="Define what constitutes a breach of unsecured ePHI for notification purposes.",
        safeguard=HIPAASafeguard.ADMINISTRATIVE,
        requires_policy=True,
        guidance="Document the breach definition per HIPAA: unauthorized acquisition, access, use, or disclosure of ePHI that compromises its security or privacy. Include the risk assessment methodology for determining breach severity.",
        soc2_equivalent=["CC7.1"],
        iso27001_equivalent=["A.5.24"],
    ),
    "164.404": HIPAAControl(
        id="164.404",
        title="Individual Notification",
        description="Notify affected individuals without unreasonable delay and no later than 60 days after discovery of a breach.",
        safeguard=HIPAASafeguard.ADMINISTRATIVE,
        requires_policy=True,
        guidance="Document the individual notification procedure: written notice within 60 days of breach discovery, content requirements (description, types of information, steps to protect, what entity is doing, contact procedures).",
        soc2_equivalent=["CC7.2"],
        iso27001_equivalent=["A.5.24"],
    ),
    "164.406": HIPAAControl(
        id="164.406",
        title="Media Notification",
        description="Provide notice to prominent media outlets for breaches affecting more than 500 residents of a state or jurisdiction.",
        safeguard=HIPAASafeguard.ADMINISTRATIVE,
        requires_policy=True,
        guidance="Document the media notification procedure for large-scale breaches (500+ individuals in a state). Include PR team contact, template press release, and escalation criteria.",
        soc2_equivalent=["CC7.2"],
        iso27001_equivalent=["A.5.24"],
    ),
    "164.408": HIPAAControl(
        id="164.408",
        title="HHS Notification",
        description="Notify the Secretary of HHS of breaches of unsecured ePHI.",
        safeguard=HIPAASafeguard.ADMINISTRATIVE,
        requires_policy=True,
        guidance="Document the HHS notification procedure: breaches of 500+ individuals reported within 60 days via HHS breach portal; smaller breaches reported annually. Maintain a breach log for annual reporting.",
        soc2_equivalent=["CC7.2"],
        iso27001_equivalent=["A.5.24"],
    ),
}


# ---------------------------------------------------------------------------
# Helper functions (mirror iso27001.py / framework.py pattern)
# ---------------------------------------------------------------------------


def get_hipaa_control(control_id: str) -> HIPAAControl | None:
    """Look up a HIPAA control by ID."""
    return HIPAA_CONTROLS.get(control_id)


def get_hipaa_controls_for_check(check_id: str) -> list[HIPAAControl]:
    """Find all HIPAA controls that a given check maps to."""
    return [ctrl for ctrl in HIPAA_CONTROLS.values() if check_id in ctrl.check_ids]


def get_automated_hipaa_controls() -> list[HIPAAControl]:
    """Get all HIPAA controls that have automated checks."""
    return [ctrl for ctrl in HIPAA_CONTROLS.values() if ctrl.check_ids]


def get_policy_required_hipaa_controls() -> list[HIPAAControl]:
    """Get all HIPAA controls that require policy documents."""
    return [ctrl for ctrl in HIPAA_CONTROLS.values() if ctrl.requires_policy]
