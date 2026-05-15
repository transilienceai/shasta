"""Risk register workflow for SOC 2 CC3.1 compliance.

A living risk register that:
  1. Auto-seeds from scan findings (misconfigurations → risks)
  2. Supports manual risk additions (business/operational risks)
  3. Tracks risk treatment, ownership, and review cadence
  4. Produces auditor-grade Markdown reports with risk matrix
  5. Persists to SQLite for history tracking
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from shasta.evidence.models import ComplianceStatus, Finding

LIKELIHOOD_VALUES = {"low": 1, "medium": 2, "high": 3}
IMPACT_VALUES = {"low": 1, "medium": 2, "high": 3}


@dataclass
class RiskItem:
    """A single risk in the register."""

    risk_id: str
    title: str
    description: str
    category: str  # technical, operational, compliance, vendor, personnel
    likelihood: str  # low, medium, high
    impact: str  # low, medium, high
    risk_score: int  # 1-9
    risk_level: str  # low (1-2), medium (3-4), high (6-9)
    owner: str
    treatment: str  # mitigate, accept, transfer, avoid
    treatment_plan: str
    status: str  # open, in_progress, accepted, resolved
    soc2_controls: list[str] = field(default_factory=lambda: ["CC3.1"])
    related_finding: str = ""
    created_date: str = ""
    last_reviewed: str = ""
    review_notes: str = ""


@dataclass
class RiskRegister:
    """Complete risk register for an account."""

    account_id: str
    review_date: str
    total_risks: int = 0
    open_risks: int = 0
    high_risk_count: int = 0
    medium_risk_count: int = 0
    low_risk_count: int = 0
    items: list[RiskItem] = field(default_factory=list)


def calculate_risk(likelihood: str, impact: str) -> tuple[int, str]:
    """Calculate risk score and level from likelihood × impact."""
    score = LIKELIHOOD_VALUES.get(likelihood, 1) * IMPACT_VALUES.get(impact, 1)
    if score >= 6:
        level = "high"
    elif score >= 3:
        level = "medium"
    else:
        level = "low"
    return score, level


# ---------------------------------------------------------------------------
# Auto-seeding: convert scan findings into risk items
# ---------------------------------------------------------------------------

# Maps check_id to risk template (title, description, category, likelihood, impact)
FINDING_TO_RISK: dict[str, dict[str, str]] = {
    "iam-password-policy": {
        "title": "Weak authentication controls",
        "description": "Password policy does not meet minimum security standards, increasing the risk of credential compromise through brute force or dictionary attacks.",
        "category": "technical",
        "likelihood": "medium",
        "impact": "high",
        "treatment": "mitigate",
        "treatment_plan": "Strengthen IAM password policy to require 14+ characters, complexity, rotation, and reuse prevention.",
    },
    "iam-root-mfa": {
        "title": "Root account compromise",
        "description": "Root account lacks MFA. If root credentials are compromised, attacker gains unrestricted access to all AWS resources, data, and billing.",
        "category": "technical",
        "likelihood": "low",
        "impact": "high",
        "treatment": "mitigate",
        "treatment_plan": "Enable hardware MFA on root account. Delete root access keys. Store root credentials in secure vault.",
    },
    "iam-user-mfa": {
        "title": "Unauthorized access via compromised password",
        "description": "IAM users with console access lack MFA. A single leaked or guessed password grants full console access without a second factor.",
        "category": "technical",
        "likelihood": "medium",
        "impact": "high",
        "treatment": "mitigate",
        "treatment_plan": "Enable MFA for all IAM users with console access. Enforce via IAM policy.",
    },
    "iam-overprivileged-user": {
        "title": "Excessive privilege escalation risk",
        "description": "Users with admin-level access can modify any resource. If compromised, the blast radius is the entire AWS account.",
        "category": "technical",
        "likelihood": "medium",
        "impact": "high",
        "treatment": "mitigate",
        "treatment_plan": "Replace admin policies with scoped, role-based permissions. Implement least privilege.",
    },
    "iam-access-key-rotation": {
        "title": "Stale credentials in circulation",
        "description": "Long-lived access keys may have been exposed in logs, code repos, or shared communications. The longer a key exists, the higher the exposure risk.",
        "category": "technical",
        "likelihood": "medium",
        "impact": "medium",
        "treatment": "mitigate",
        "treatment_plan": "Implement 90-day key rotation policy. Use IAM roles instead of long-lived keys where possible.",
    },
    "sg-no-unrestricted-ingress": {
        "title": "Network intrusion via exposed management ports",
        "description": "Security groups allow inbound access from the entire internet. Exposed SSH, RDP, or database ports are actively scanned and attacked.",
        "category": "technical",
        "likelihood": "high",
        "impact": "high",
        "treatment": "mitigate",
        "treatment_plan": "Restrict security group ingress to specific IP ranges. Use VPN or Session Manager for management access.",
    },
    "vpc-flow-logs-enabled": {
        "title": "Unable to investigate security incidents",
        "description": "Without VPC flow logs, there is no record of network traffic. If a breach occurs, incident response cannot determine what data was accessed or exfiltrated.",
        "category": "technical",
        "likelihood": "medium",
        "impact": "medium",
        "treatment": "mitigate",
        "treatment_plan": "Enable VPC flow logs on all VPCs. Send to CloudWatch Logs with 90-day retention.",
    },
    "s3-encryption-at-rest": {
        "title": "Data exposure from unencrypted storage",
        "description": "Data stored without encryption at rest could be read by anyone with physical access to the underlying storage or through certain access misconfigurations.",
        "category": "technical",
        "likelihood": "low",
        "impact": "high",
        "treatment": "mitigate",
        "treatment_plan": "Enable SSE-KMS encryption on all S3 buckets. Enable EBS encryption by default.",
    },
    "s3-public-access-block": {
        "title": "Accidental public data exposure",
        "description": "Without public access blocks, a misconfigured bucket policy or ACL could expose sensitive data to the internet.",
        "category": "technical",
        "likelihood": "medium",
        "impact": "high",
        "treatment": "mitigate",
        "treatment_plan": "Enable all four S3 public access block settings on every bucket.",
    },
    "cloudtrail-enabled": {
        "title": "No audit trail for AWS API activity",
        "description": "Without CloudTrail, there is no record of who did what in the AWS account. Impossible to detect unauthorized changes or investigate incidents.",
        "category": "technical",
        "likelihood": "medium",
        "impact": "high",
        "treatment": "mitigate",
        "treatment_plan": "Enable multi-region CloudTrail with log file validation. Store in encrypted S3 bucket.",
    },
    "guardduty-enabled": {
        "title": "No automated threat detection",
        "description": "Without GuardDuty, there is no ML-based monitoring for account compromise, unusual API activity, or malicious network behavior.",
        "category": "technical",
        "likelihood": "medium",
        "impact": "medium",
        "treatment": "mitigate",
        "treatment_plan": "Enable GuardDuty in all regions. Set up alerting for high-severity findings.",
    },
    "ebs-encryption-by-default": {
        "title": "Unencrypted compute storage",
        "description": "Without EBS encryption by default, new volumes may be created unencrypted, storing sensitive data without at-rest protection.",
        "category": "technical",
        "likelihood": "medium",
        "impact": "medium",
        "treatment": "mitigate",
        "treatment_plan": "Enable EBS encryption by default in all regions.",
    },
    "rds-no-public-access": {
        "title": "Database directly exposed to internet",
        "description": "Publicly accessible databases can be reached by anyone. Combined with weak credentials, this leads to data breaches.",
        "category": "technical",
        "likelihood": "high",
        "impact": "high",
        "treatment": "mitigate",
        "treatment_plan": "Set PubliclyAccessible=false. Access databases through private subnets or VPN only.",
    },
    # -----------------------------------------------------------------------
    # Azure checks
    # -----------------------------------------------------------------------
    "azure-conditional-access-mfa": {
        "title": "Azure users lack MFA enforcement",
        "description": "No Conditional Access policy enforces MFA. A compromised password grants full account access without a second factor.",
        "category": "technical",
        "likelihood": "medium",
        "impact": "high",
        "treatment": "mitigate",
        "treatment_plan": "Create a Conditional Access policy requiring MFA for all users. Entra ID > Security > Conditional Access.",
    },
    "azure-privileged-roles": {
        "title": "Excessive Global Administrator assignments",
        "description": "Too many principals have the Global Administrator role. If any one is compromised, the entire tenant is at risk.",
        "category": "technical",
        "likelihood": "low",
        "impact": "high",
        "treatment": "mitigate",
        "treatment_plan": "Reduce Global Admins to 2-3 break-glass accounts. Use scoped roles for daily operations.",
    },
    "azure-rbac-least-privilege": {
        "title": "Overprivileged Azure RBAC assignments",
        "description": "Owner or Contributor roles assigned at subscription scope give broad write access to all resources.",
        "category": "technical",
        "likelihood": "medium",
        "impact": "high",
        "treatment": "mitigate",
        "treatment_plan": "Assign roles at resource group scope instead of subscription scope. Use custom roles with minimal permissions.",
    },
    "azure-inactive-users": {
        "title": "Stale Azure user accounts",
        "description": "Inactive users that haven't signed in for 90+ days increase the attack surface — dormant accounts are prime targets for credential stuffing.",
        "category": "technical",
        "likelihood": "medium",
        "impact": "medium",
        "treatment": "mitigate",
        "treatment_plan": "Disable or delete accounts inactive for 90+ days. Entra ID > Users > filter by last sign-in.",
    },
    "azure-guest-access": {
        "title": "Unreviewed guest/external users in tenant",
        "description": "Guest users have access to tenant resources. Without periodic review, former partners or contractors retain access.",
        "category": "technical",
        "likelihood": "medium",
        "impact": "medium",
        "treatment": "mitigate",
        "treatment_plan": "Review guest users quarterly. Remove guests who no longer need access.",
    },
    "azure-service-principal-hygiene": {
        "title": "App registrations with expired credentials",
        "description": "Service principals with expired credentials may indicate abandoned applications or failed rotation processes.",
        "category": "technical",
        "likelihood": "medium",
        "impact": "medium",
        "treatment": "mitigate",
        "treatment_plan": "Rotate expired credentials or remove unused app registrations. Entra ID > App registrations.",
    },
    "azure-nsg-unrestricted-ingress": {
        "title": "Azure NSG allows unrestricted internet ingress",
        "description": "Network Security Groups allow inbound traffic from the internet on dangerous ports. Exposed SSH, RDP, or database ports are actively scanned.",
        "category": "technical",
        "likelihood": "high",
        "impact": "high",
        "treatment": "mitigate",
        "treatment_plan": "Restrict NSG inbound rules to specific source IPs. Use Azure Bastion for management access.",
    },
    "azure-vnet-flow-logs": {
        "title": "No NSG flow logs for network forensics",
        "description": "Without NSG flow logs, there is no record of network traffic for incident investigation or anomaly detection.",
        "category": "technical",
        "likelihood": "medium",
        "impact": "medium",
        "treatment": "mitigate",
        "treatment_plan": "Enable NSG flow logs via Network Watcher. Send to Log Analytics with 90-day retention.",
    },
    "azure-public-ip-exposure": {
        "title": "Resources exposed via public IP addresses",
        "description": "Public IPs attached to resources create internet exposure. Each public IP is a potential entry point for attackers.",
        "category": "technical",
        "likelihood": "medium",
        "impact": "medium",
        "treatment": "mitigate",
        "treatment_plan": "Replace public IPs with Private Endpoints or Azure Bastion where possible.",
    },
    "azure-storage-encryption": {
        "title": "Azure storage allows outdated TLS",
        "description": "Storage accounts allowing TLS 1.0 or 1.1 are vulnerable to known cryptographic attacks against data in transit.",
        "category": "technical",
        "likelihood": "low",
        "impact": "high",
        "treatment": "mitigate",
        "treatment_plan": "Set minimum TLS version to 1.2 on all storage accounts.",
    },
    "azure-storage-https-only": {
        "title": "Azure storage allows unencrypted HTTP traffic",
        "description": "Storage accounts not enforcing HTTPS allow data to be intercepted in transit over plaintext HTTP connections.",
        "category": "technical",
        "likelihood": "low",
        "impact": "high",
        "treatment": "mitigate",
        "treatment_plan": "Enable HTTPS-only traffic on all storage accounts.",
    },
    "azure-blob-public-access": {
        "title": "Azure blob containers allow public access",
        "description": "Storage accounts that permit public blob access risk accidental data exposure if a container is misconfigured.",
        "category": "technical",
        "likelihood": "medium",
        "impact": "high",
        "treatment": "mitigate",
        "treatment_plan": "Disable public blob access at the storage account level.",
    },
    "azure-storage-soft-delete": {
        "title": "Azure storage lacks data recovery protection",
        "description": "Without soft delete and versioning, deleted or overwritten data cannot be recovered — ransomware or accidental deletion is permanent.",
        "category": "technical",
        "likelihood": "low",
        "impact": "high",
        "treatment": "mitigate",
        "treatment_plan": "Enable blob soft delete (90-day retention) and versioning on all storage accounts.",
    },
    "azure-disk-encryption": {
        "title": "Unencrypted Azure managed disks",
        "description": "Managed disks without encryption at rest expose data if physical media is compromised or through certain access misconfigurations.",
        "category": "technical",
        "likelihood": "low",
        "impact": "high",
        "treatment": "mitigate",
        "treatment_plan": "Enable Server-Side Encryption on all managed disks. Use customer-managed keys via Key Vault for enhanced control.",
    },
    "azure-sql-tde": {
        "title": "Azure SQL database lacks encryption at rest",
        "description": "SQL databases without Transparent Data Encryption store data in plaintext on disk.",
        "category": "technical",
        "likelihood": "low",
        "impact": "high",
        "treatment": "mitigate",
        "treatment_plan": "Enable TDE on all SQL databases. Azure SQL enables TDE by default — verify it hasn't been disabled.",
    },
    "azure-keyvault-config": {
        "title": "Key Vault missing purge protection",
        "description": "Without purge protection, deleted keys, secrets, and certificates can be permanently lost — no recovery possible.",
        "category": "technical",
        "likelihood": "low",
        "impact": "high",
        "treatment": "mitigate",
        "treatment_plan": "Enable purge protection on all Key Vaults. Note: this cannot be reversed once enabled.",
    },
    "azure-sql-public-access": {
        "title": "Azure SQL Server exposed to public internet",
        "description": "SQL Servers with public network access enabled can be reached from the internet. Combined with weak credentials, this leads to data breaches.",
        "category": "technical",
        "likelihood": "high",
        "impact": "high",
        "treatment": "mitigate",
        "treatment_plan": "Disable public network access on SQL Servers. Use Private Endpoints for connectivity.",
    },
    "azure-activity-log": {
        "title": "Azure Activity Log not exported for retention",
        "description": "Without diagnostic settings exporting Activity Log, audit trail data is lost after the 90-day default retention.",
        "category": "technical",
        "likelihood": "medium",
        "impact": "high",
        "treatment": "mitigate",
        "treatment_plan": "Configure diagnostic settings to export Activity Log to Log Analytics or Storage Account.",
    },
    "azure-defender-enabled": {
        "title": "Microsoft Defender for Cloud not enabled",
        "description": "Without Defender, there is no automated threat detection, security recommendations, or vulnerability assessment for Azure resources.",
        "category": "technical",
        "likelihood": "medium",
        "impact": "medium",
        "treatment": "mitigate",
        "treatment_plan": "Enable Defender for Cloud Standard tier on key resource types (Servers, Storage, SQL, Key Vault).",
    },
    "azure-policy-compliance": {
        "title": "No Azure Policy assignments for compliance enforcement",
        "description": "Without Azure Policy, there is no automated enforcement of security baselines or continuous compliance monitoring.",
        "category": "technical",
        "likelihood": "medium",
        "impact": "medium",
        "treatment": "mitigate",
        "treatment_plan": "Assign the Azure Security Benchmark initiative at subscription scope.",
    },
    "azure-monitor-alerts": {
        "title": "No Azure Monitor alert rules configured",
        "description": "Without alert rules, security-relevant events and anomalies go undetected until manual review.",
        "category": "technical",
        "likelihood": "medium",
        "impact": "medium",
        "treatment": "mitigate",
        "treatment_plan": "Create alert rules for critical metrics: failed sign-ins, resource deletions, role changes, budget thresholds.",
    },
}


def auto_seed_from_findings(findings: list[Finding], account_id: str) -> list[RiskItem]:
    """Convert failing scan findings into risk register items."""
    now = datetime.now(UTC).strftime("%Y-%m-%d")
    risks = []
    seen_checks = set()
    counter = 1

    for finding in findings:
        if finding.status not in (ComplianceStatus.FAIL, ComplianceStatus.PARTIAL):
            continue
        if finding.check_id in seen_checks:
            continue  # One risk per check type, not per resource

        template = FINDING_TO_RISK.get(finding.check_id)
        if not template:
            continue

        seen_checks.add(finding.check_id)
        score, level = calculate_risk(template["likelihood"], template["impact"])

        risks.append(
            RiskItem(
                risk_id=f"RISK-{counter:03d}",
                title=template["title"],
                description=template["description"],
                category=template["category"],
                likelihood=template["likelihood"],
                impact=template["impact"],
                risk_score=score,
                risk_level=level,
                owner="[Assign owner]",
                treatment=template["treatment"],
                treatment_plan=template["treatment_plan"],
                status="open",
                soc2_controls=["CC3.1"] + finding.soc2_controls,
                related_finding=finding.check_id,
                created_date=now,
                last_reviewed=now,
                review_notes="Auto-generated from Shasta compliance scan.",
            )
        )
        counter += 1

    return risks


def build_register(items: list[RiskItem], account_id: str) -> RiskRegister:
    """Build a RiskRegister summary from a list of items."""
    now = datetime.now(UTC).strftime("%Y-%m-%d")
    active = [r for r in items if r.status in ("open", "in_progress")]

    return RiskRegister(
        account_id=account_id,
        review_date=now,
        total_risks=len(items),
        open_risks=len(active),
        high_risk_count=sum(1 for r in active if r.risk_level == "high"),
        medium_risk_count=sum(1 for r in active if r.risk_level == "medium"),
        low_risk_count=sum(1 for r in active if r.risk_level == "low"),
        items=items,
    )


def save_risk_register_report(
    register: RiskRegister, output_path: Path | str = "data/risk-register"
) -> Path:
    """Save the risk register as an auditor-grade Markdown report."""
    output_dir = Path(output_path)
    output_dir.mkdir(parents=True, exist_ok=True)
    filepath = output_dir / f"risk-register-{register.account_id}-{register.review_date}.md"

    lines = [
        "# Risk Register",
        "",
        f"**Account:** {register.account_id}",
        f"**Review Date:** {register.review_date}",
        f"**Total Risks:** {register.total_risks}",
        f"**Open Risks:** {register.open_risks} ({register.high_risk_count} high, {register.medium_risk_count} medium, {register.low_risk_count} low)",
        "",
        "---",
        "",
        "## Risk Matrix",
        "",
        "| | **Low Impact** | **Medium Impact** | **High Impact** |",
        "|---|---|---|---|",
    ]

    # Build risk matrix
    matrix: dict[tuple[str, str], list[str]] = {}
    for item in register.items:
        if item.status in ("open", "in_progress"):
            key = (item.likelihood, item.impact)
            matrix.setdefault(key, []).append(item.risk_id)

    for likelihood in ("high", "medium", "low"):
        cells = []
        for impact in ("low", "medium", "high"):
            ids = matrix.get((likelihood, impact), [])
            cells.append(", ".join(ids) if ids else "-")
        lines.append(
            f"| **{likelihood.title()} Likelihood** | {cells[0]} | {cells[1]} | {cells[2]} |"
        )

    lines.extend(["", "---", "", "## Risk Details", ""])

    # Sort: high first, then medium, then low
    level_order = {"high": 0, "medium": 1, "low": 2}
    sorted_items = sorted(
        register.items, key=lambda r: (level_order.get(r.risk_level, 3), -r.risk_score)
    )

    for item in sorted_items:
        level_badge = {"high": "HIGH", "medium": "MEDIUM", "low": "LOW"}.get(
            item.risk_level, item.risk_level
        )
        status_badge = item.status.upper().replace("_", " ")

        lines.extend(
            [
                f"### {item.risk_id}: {item.title} [{level_badge}]",
                "",
                f"- **Category:** {item.category}",
                f"- **Likelihood:** {item.likelihood} | **Impact:** {item.impact} | **Score:** {item.risk_score}/9",
                f"- **Status:** {status_badge}",
                f"- **Owner:** {item.owner}",
                f"- **Treatment:** {item.treatment}",
                f"- **Treatment Plan:** {item.treatment_plan}",
                f"- **SOC 2 Controls:** {', '.join(item.soc2_controls)}",
                f"- **Created:** {item.created_date} | **Last Reviewed:** {item.last_reviewed}",
            ]
        )
        if item.related_finding:
            lines.append(f"- **Source:** Auto-seeded from scan finding `{item.related_finding}`")
        if item.review_notes:
            lines.append(f"- **Notes:** {item.review_notes}")
        lines.extend(["", "---", ""])

    lines.extend(
        [
            "## Treatment Summary",
            "",
            "| Treatment | Count |",
            "|-----------|-------|",
            f"| Mitigate | {sum(1 for r in register.items if r.treatment == 'mitigate')} |",
            f"| Accept | {sum(1 for r in register.items if r.treatment == 'accept')} |",
            f"| Transfer | {sum(1 for r in register.items if r.treatment == 'transfer')} |",
            f"| Avoid | {sum(1 for r in register.items if r.treatment == 'avoid')} |",
            "",
            "## Reviewer Sign-off",
            "",
            "| Field | Value |",
            "|-------|-------|",
            "| Reviewed by | ___________________ |",
            "| Date | ___________________ |",
            "| Next review due | ___________________ |",
            "",
            "*This risk register satisfies SOC 2 CC3.1 (Risk Assessment) and ISO 27001 A.8.8 (Management of technical vulnerabilities) requirements.*",
        ]
    )

    filepath.write_text("\n".join(lines), encoding="utf-8")
    return filepath
