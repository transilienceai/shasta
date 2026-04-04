"""Policy document generator for SOC 2 compliance.

Generates Markdown policy documents from templates, tailored to the
company's context. These are the non-technical controls that SOC 2
requires but can't be automated through AWS checks.

SOC 2 mapping:
  CC1.1 — Control Environment → Code of Conduct, Security Roles
  CC2.1 — Communication → Security Awareness, Incident Comms
  CC3.1 — Risk Assessment → Risk Assessment Policy
  CC5.1 — Control Activities → Access Control, Change Management
  CC9.1 — Risk Mitigation → Vendor Management, BCP/DR, Data Classification
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from jinja2 import Environment, BaseLoader

# ---------------------------------------------------------------------------
# Policy Templates
# ---------------------------------------------------------------------------

POLICIES: dict[str, dict] = {
    "access_control": {
        "title": "Access Control Policy",
        "soc2_controls": ["CC6.1", "CC6.2", "CC6.3", "CC5.1"],
        "filename": "access-control-policy.md",
        "template": """\
# Access Control Policy

**Version:** 1.0
**Effective Date:** {{ effective_date }}
**Owner:** {{ company_name }} Security Team
**SOC 2 Controls:** CC6.1, CC6.2, CC6.3, CC5.1

## 1. Purpose

This policy establishes requirements for controlling access to {{ company_name }}'s information systems, applications, and data to protect against unauthorized access.

## 2. Scope

This policy applies to all employees, contractors, and third parties with access to {{ company_name }}'s systems and data.

## 3. Access Management

### 3.1 Principle of Least Privilege
- All access is granted based on the principle of least privilege
- Users receive only the minimum permissions necessary to perform their job duties
- Administrative/privileged access requires additional approval and justification

### 3.2 Access Provisioning
- Access requests must be submitted through the designated process and approved by the user's manager
- Access is provisioned based on role-based access control (RBAC) using IAM groups and roles
- Direct policy attachments to individual users are prohibited — use groups or roles
- All new access is reviewed within 5 business days of provisioning

### 3.3 Authentication
- Multi-factor authentication (MFA) is required for:
  - All AWS console access
  - All production system access
  - VPN and remote access
  - All administrative/privileged accounts
- Password requirements:
  - Minimum 14 characters
  - Must include uppercase, lowercase, numbers, and symbols
  - Passwords expire every 90 days
  - Last 12 passwords cannot be reused
- The root AWS account must have MFA enabled and access keys deleted
- Root account credentials are stored securely and used only for account recovery

### 3.4 Access Reviews
- All user access is reviewed quarterly by system owners
- Privileged access is reviewed monthly
- Access reviews are documented and retained for audit

### 3.5 Access Removal
- Access is revoked within 24 hours of employee termination
- Access is modified within 5 business days of role change
- Inactive accounts (no login for 90 days) are automatically flagged for review
- Access keys must be rotated every 90 days

## 4. Network Access
- Production network access is restricted by security groups and NACLs
- No security group may allow unrestricted inbound access (0.0.0.0/0) except for public-facing load balancers on ports 80/443
- SSH, RDP, and database ports must never be open to the internet
- VPC flow logs must be enabled on all VPCs

## 5. Violations
Violations of this policy may result in disciplinary action, up to and including termination.

## 6. Review
This policy is reviewed annually or when significant changes occur.
""",
    },
    "change_management": {
        "title": "Change Management Policy",
        "soc2_controls": ["CC8.1", "CC5.1"],
        "filename": "change-management-policy.md",
        "template": """\
# Change Management Policy

**Version:** 1.0
**Effective Date:** {{ effective_date }}
**Owner:** {{ company_name }} Engineering Team
**SOC 2 Controls:** CC8.1, CC5.1

## 1. Purpose

This policy ensures that all changes to {{ company_name }}'s production systems are authorized, tested, documented, and tracked to maintain system integrity and availability.

## 2. Scope

This policy covers all changes to production infrastructure, application code, databases, and configurations.

## 3. Change Categories

| Category | Description | Approval | Examples |
|----------|-------------|----------|----------|
| Standard | Pre-approved, low-risk changes | No additional approval | Dependency updates, config tweaks |
| Normal | Moderate risk, planned changes | Peer review + team lead | New features, architecture changes |
| Emergency | Urgent fixes for incidents | Post-change review within 48hrs | Security patches, outage fixes |

## 4. Change Process

### 4.1 Request
- All changes are tracked in the version control system (Git)
- Each change requires a pull request with description, testing plan, and rollback plan

### 4.2 Review
- All code changes require at least one peer review before merge
- Infrastructure changes require review by a team member with infrastructure expertise
- Security-sensitive changes require security team review

### 4.3 Testing
- All changes must pass automated tests before deployment
- Changes to critical systems require manual testing in a staging environment

### 4.4 Deployment
- Deployments follow the documented deployment procedure
- All deployments are logged in CloudTrail and AWS Config
- Rollback procedures must be tested and documented

### 4.5 Post-Deployment
- Monitor for errors and performance degradation after deployment
- Emergency changes receive a post-change review within 48 hours

## 5. Audit Trail
- AWS CloudTrail is enabled across all regions for API activity logging
- AWS Config records all resource configuration changes
- Git history provides full change attribution and history
- Logs are retained for a minimum of 1 year

## 6. Review
This policy is reviewed annually or when significant changes occur.
""",
    },
    "incident_response": {
        "title": "Incident Response Plan",
        "soc2_controls": ["CC7.1", "CC7.2", "CC2.1"],
        "filename": "incident-response-plan.md",
        "template": """\
# Incident Response Plan

**Version:** 1.0
**Effective Date:** {{ effective_date }}
**Owner:** {{ company_name }} Security Team
**SOC 2 Controls:** CC7.1, CC7.2, CC2.1

## 1. Purpose

This plan establishes procedures for detecting, responding to, and recovering from security incidents at {{ company_name }}.

## 2. Incident Classification

| Severity | Description | Response Time | Examples |
|----------|-------------|---------------|----------|
| Critical (P1) | Active data breach, system compromise | 15 minutes | Data exfiltration, ransomware, root account compromise |
| High (P2) | Potential breach, vulnerability exploited | 1 hour | GuardDuty high-severity finding, unauthorized access attempt |
| Medium (P3) | Security policy violation, suspicious activity | 4 hours | Unusual API activity, failed login spikes |
| Low (P4) | Minor policy deviation | Next business day | Expired certificates, non-critical misconfig |

## 3. Detection

- **Amazon GuardDuty** monitors for threats continuously
- **AWS CloudTrail** logs all API activity for investigation
- **AWS Config** tracks configuration changes
- **CloudWatch Alarms** alert on key metrics
- Team members can report incidents to: {{ incident_email | default('security@' + company_name.lower().replace(' ', '') + '.com') }}

## 4. Response Process

### Phase 1: Identification (0-15 min)
- Confirm the incident is real (not a false positive)
- Classify severity level
- Notify the incident commander

### Phase 2: Containment (15 min - 2 hrs)
- Isolate affected systems (revoke credentials, restrict network access)
- Preserve evidence (snapshot instances, export logs)
- Prevent further damage

### Phase 3: Eradication (2-24 hrs)
- Identify root cause
- Remove the threat (patch vulnerability, remove malware, rotate credentials)
- Verify the threat is eliminated

### Phase 4: Recovery (24-72 hrs)
- Restore systems from known-good backups
- Monitor for recurrence
- Gradually restore normal operations

### Phase 5: Post-Incident (Within 1 week)
- Conduct post-mortem / blameless retrospective
- Document lessons learned
- Update this plan and controls as needed
- Notify affected parties if required

## 5. Communication

- Internal: Slack channel #incidents (or equivalent)
- External (customers): Only after legal review
- Regulatory: As required by applicable regulations
- Law enforcement: If criminal activity is suspected

## 6. Testing
- This plan is tested at least annually through a tabletop exercise
- GuardDuty findings are reviewed weekly

## 7. Review
This plan is reviewed annually or after any significant incident.
""",
    },
    "risk_assessment": {
        "title": "Risk Assessment Policy",
        "soc2_controls": ["CC3.1"],
        "filename": "risk-assessment-policy.md",
        "template": """\
# Risk Assessment Policy

**Version:** 1.0
**Effective Date:** {{ effective_date }}
**Owner:** {{ company_name }} Leadership Team
**SOC 2 Controls:** CC3.1

## 1. Purpose

This policy establishes the process for identifying, assessing, and managing risks to {{ company_name }}'s information systems and data.

## 2. Risk Assessment Process

### 2.1 Frequency
- A comprehensive risk assessment is performed annually
- Targeted assessments are performed when significant changes occur (new services, acquisitions, major incidents)

### 2.2 Scope
The assessment covers:
- Infrastructure and cloud services (AWS)
- Application security
- Data protection
- Third-party/vendor risks
- Business continuity threats
- Regulatory and compliance risks

### 2.3 Methodology
1. **Identify assets**: List critical systems, data stores, and services
2. **Identify threats**: For each asset, identify potential threats (unauthorized access, data loss, service disruption, etc.)
3. **Assess likelihood**: Rate likelihood as Low / Medium / High
4. **Assess impact**: Rate business impact as Low / Medium / High
5. **Calculate risk**: Risk = Likelihood x Impact
6. **Prioritize**: Address High risks first, then Medium, then Low
7. **Treat**: For each risk, choose: Mitigate, Accept, Transfer, or Avoid

### 2.4 Risk Register
- All identified risks are documented in a risk register
- Each risk includes: description, owner, likelihood, impact, treatment plan, and status
- The risk register is reviewed quarterly

## 3. Risk Treatment

| Treatment | When to Use | Example |
|-----------|-------------|---------|
| Mitigate | Risk can be reduced by controls | Enable MFA, encrypt data |
| Accept | Risk is low and cost of mitigation exceeds benefit | Documented acceptance by leadership |
| Transfer | Risk can be shared with a third party | Cyber insurance, outsourced SOC |
| Avoid | Risk is too high and the activity is not essential | Discontinue a risky feature |

## 4. Roles
- **Risk Owner**: The individual accountable for managing a specific risk
- **Security Team**: Conducts assessments and recommends treatments
- **Leadership**: Reviews and approves risk acceptance decisions

## 5. Review
This policy is reviewed annually.
""",
    },
    "vendor_management": {
        "title": "Vendor Management Policy",
        "soc2_controls": ["CC9.1"],
        "filename": "vendor-management-policy.md",
        "template": """\
# Vendor Management Policy

**Version:** 1.0
**Effective Date:** {{ effective_date }}
**Owner:** {{ company_name }} Operations Team
**SOC 2 Controls:** CC9.1

## 1. Purpose

This policy establishes requirements for evaluating, selecting, and monitoring third-party vendors who access, process, or store {{ company_name }}'s data.

## 2. Vendor Classification

| Tier | Criteria | Review Frequency | Examples |
|------|----------|-----------------|----------|
| Critical | Processes customer data, provides core infrastructure | Annual review + continuous monitoring | AWS, primary database provider |
| Standard | Has access to internal data or systems | Annual review | SaaS tools, analytics providers |
| Low | No data access, non-essential services | At onboarding + renewal | Office supplies, marketing tools |

## 3. Vendor Assessment

### 3.1 Pre-Engagement
Before engaging a new Critical or Standard vendor:
- Request and review SOC 2 Type II report (or equivalent)
- Evaluate security practices, data handling, and incident response
- Review data processing agreement / DPA
- Assess business continuity capabilities
- Document risk assessment results

### 3.2 Ongoing Monitoring
- Request updated SOC 2 reports annually
- Monitor for security incidents or breaches reported by the vendor
- Review vendor access permissions quarterly
- Maintain an up-to-date vendor inventory

## 4. Vendor Inventory
A current inventory of all vendors is maintained, including:
- Vendor name and primary contact
- Services provided and data accessed
- Tier classification
- Contract expiration date
- Last security review date
- SOC 2 report status

## 5. Vendor Offboarding
When terminating a vendor relationship:
- Revoke all access credentials within 24 hours
- Confirm data deletion or return per contract terms
- Update vendor inventory

## 6. Review
This policy is reviewed annually.
""",
    },
    "data_classification": {
        "title": "Data Classification Policy",
        "soc2_controls": ["CC6.7", "CC9.1"],
        "filename": "data-classification-policy.md",
        "template": """\
# Data Classification Policy

**Version:** 1.0
**Effective Date:** {{ effective_date }}
**Owner:** {{ company_name }} Security Team
**SOC 2 Controls:** CC6.7, CC9.1

## 1. Purpose

This policy defines how {{ company_name }} classifies, handles, and protects data based on its sensitivity.

## 2. Classification Levels

| Level | Description | Examples | Handling |
|-------|-------------|----------|----------|
| **Confidential** | Highly sensitive, breach would cause significant harm | Customer PII, credentials, financial data, encryption keys | Encrypted at rest + in transit, access logged, need-to-know only |
| **Internal** | For internal use, not for public | Internal docs, architecture diagrams, employee info | Encrypted in transit, access controlled |
| **Public** | Intended for public access | Marketing site, public docs, open-source code | No special handling required |

## 3. Data Handling Requirements

### 3.1 Storage
- Confidential data must be encrypted at rest (AES-256 or KMS)
- S3 buckets containing Confidential data must have versioning and public access blocks enabled
- Database backups containing Confidential data must be encrypted

### 3.2 Transmission
- All data in transit must use TLS 1.2 or higher
- S3 buckets must enforce SSL-only access via bucket policy
- API endpoints must use HTTPS only

### 3.3 Access
- Access to Confidential data follows the principle of least privilege
- All access to Confidential data is logged via CloudTrail
- Access reviews are conducted quarterly

### 3.4 Retention & Disposal
- Data is retained only as long as required by business or legal requirements
- Confidential data is securely deleted when no longer needed
- S3 object lifecycle policies are used for automated data lifecycle management

## 4. Review
This policy is reviewed annually or when data handling practices change.
""",
    },
    "acceptable_use": {
        "title": "Acceptable Use Policy",
        "soc2_controls": ["CC1.1", "CC2.1"],
        "filename": "acceptable-use-policy.md",
        "template": """\
# Acceptable Use Policy

**Version:** 1.0
**Effective Date:** {{ effective_date }}
**Owner:** {{ company_name }} Leadership
**SOC 2 Controls:** CC1.1, CC2.1

## 1. Purpose

This policy defines acceptable use of {{ company_name }}'s information systems, ensuring all users understand their responsibilities for protecting company and customer data.

## 2. Scope

This policy applies to all employees, contractors, and third parties with access to {{ company_name }}'s systems.

## 3. General Principles

- Use company systems and data for authorized business purposes
- Protect credentials — never share passwords or access keys
- Report security incidents or suspicious activity immediately
- Follow the principle of least privilege — don't request more access than you need
- Lock your workstation when unattended

## 4. Prohibited Activities

- Sharing AWS credentials, access keys, or MFA devices
- Storing credentials in code, wikis, or unencrypted files
- Bypassing security controls or access restrictions
- Installing unauthorized software on production systems
- Accessing data or systems beyond your authorization
- Using company systems for illegal activities

## 5. AWS-Specific Requirements

- Never use the root account for daily operations
- Always use MFA for AWS console access
- Never commit AWS access keys to source code repositories
- Use IAM roles for service-to-service authentication (not access keys)
- Follow the change management policy for all infrastructure changes

## 6. Security Awareness

- All employees complete security awareness training at onboarding
- Annual refresher training is required
- Phishing simulation exercises are conducted quarterly

## 7. Violations

Violations of this policy may result in disciplinary action, up to and including termination. Illegal activities will be reported to law enforcement.

## 8. Review
This policy is reviewed annually.
""",
    },
    "business_continuity": {
        "title": "Business Continuity & Disaster Recovery Plan",
        "soc2_controls": ["CC9.1"],
        "filename": "business-continuity-plan.md",
        "template": """\
# Business Continuity & Disaster Recovery Plan

**Version:** 1.0
**Effective Date:** {{ effective_date }}
**Owner:** {{ company_name }} Engineering & Operations
**SOC 2 Controls:** CC9.1

## 1. Purpose

This plan ensures {{ company_name }} can continue critical business operations and recover from disruptions, including infrastructure failures, data loss, and security incidents.

## 2. Recovery Objectives

| Metric | Target | Description |
|--------|--------|-------------|
| RTO (Recovery Time Objective) | 4 hours | Maximum acceptable downtime |
| RPO (Recovery Point Objective) | 1 hour | Maximum acceptable data loss |

## 3. Critical Systems

| System | Tier | Backup Method | Recovery Method |
|--------|------|---------------|-----------------|
| Production Database | Tier 1 | Automated daily snapshots, continuous replication | Restore from snapshot, failover to replica |
| Application Servers | Tier 1 | Infrastructure as Code (Terraform) | Redeploy from IaC |
| S3 Data Stores | Tier 1 | Versioning + cross-region replication | Restore from versions or replica |
| CloudTrail Logs | Tier 2 | S3 with versioning | Restore from S3 |

## 4. Backup Strategy

- **Databases**: Automated daily snapshots retained for 30 days; point-in-time recovery enabled
- **Infrastructure**: All infrastructure defined in Terraform — can be rebuilt from code
- **Application Code**: Stored in Git with multiple remotes
- **S3 Buckets**: Versioning enabled on all buckets containing business data
- **Encryption Keys**: KMS keys with rotation enabled; key policies documented

## 5. Disaster Recovery Procedures

### 5.1 Infrastructure Failure
1. Assess scope of failure (single AZ, region, service)
2. If single AZ: failover to multi-AZ replicas
3. If region: deploy to backup region from Terraform
4. Verify data integrity after recovery
5. Update DNS if needed

### 5.2 Data Loss / Corruption
1. Identify scope and cause of data loss
2. Restore from most recent clean backup/snapshot
3. Apply transaction logs to minimize data loss
4. Verify data integrity
5. Conduct root cause analysis

### 5.3 Security Incident
1. Follow the Incident Response Plan
2. Isolate affected systems
3. Restore from known-good backups after threat elimination
4. Rotate all potentially compromised credentials

## 6. Testing
- DR procedures are tested at least annually
- Backup restoration is tested quarterly
- Results are documented and gaps are addressed

## 7. Review
This plan is reviewed annually or after any significant incident or infrastructure change.
""",
    },
}


def generate_policy(
    policy_id: str,
    company_name: str = "Acme Corp",
    effective_date: str | None = None,
    **kwargs,
) -> str:
    """Generate a single policy document from a template."""
    if policy_id not in POLICIES:
        raise ValueError(f"Unknown policy: {policy_id}. Available: {list(POLICIES.keys())}")

    policy = POLICIES[policy_id]
    env = Environment(loader=BaseLoader())
    template = env.from_string(policy["template"])

    if effective_date is None:
        effective_date = datetime.now().strftime("%Y-%m-%d")

    return template.render(
        company_name=company_name,
        effective_date=effective_date,
        **kwargs,
    )


def generate_all_policies(
    company_name: str = "Acme Corp",
    output_path: Path | str = "data/policies",
    **kwargs,
) -> list[Path]:
    """Generate all policy documents and save to disk."""
    output_dir = Path(output_path)
    output_dir.mkdir(parents=True, exist_ok=True)

    paths = []
    for policy_id, policy in POLICIES.items():
        content = generate_policy(policy_id, company_name=company_name, **kwargs)
        filepath = output_dir / policy["filename"]
        filepath.write_text(content, encoding="utf-8")
        paths.append(filepath)

    return paths


def list_policies() -> list[dict]:
    """List all available policy templates."""
    return [
        {
            "id": pid,
            "title": p["title"],
            "soc2_controls": p["soc2_controls"],
            "filename": p["filename"],
        }
        for pid, p in POLICIES.items()
    ]
