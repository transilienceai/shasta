"""Remediation engine — generates prioritized fix recommendations and Terraform code.

For each failing finding, produces:
  1. Plain-English explanation of what's wrong and why it matters
  2. Step-by-step remediation instructions
  3. Terraform code to fix the issue (where applicable)
  4. Priority score for ordering the remediation roadmap
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from transilience_compliance.evidence.models import ComplianceStatus, Finding, Severity

SEVERITY_PRIORITY = {
    Severity.CRITICAL: 1,
    Severity.HIGH: 2,
    Severity.MEDIUM: 3,
    Severity.LOW: 4,
    Severity.INFO: 5,
}


@dataclass
class Remediation:
    """A remediation recommendation for a finding."""

    finding: Finding
    priority: int
    explanation: str  # Why this matters (founder-friendly)
    steps: list[str]  # Step-by-step instructions
    terraform: str = ""  # Terraform code to fix, if applicable
    effort: str = ""  # "quick" (<30min), "moderate" (1-4hrs), "significant" (>4hrs)
    category: str = ""  # "iam", "networking", "storage", "monitoring"


# ---------------------------------------------------------------------------
# Terraform template registry — maps check_id to a Terraform generator
# ---------------------------------------------------------------------------

TERRAFORM_TEMPLATES: dict[str, callable] = {}


def _tf(check_id: str):
    """Decorator to register a Terraform template generator."""
    def decorator(fn):
        TERRAFORM_TEMPLATES[check_id] = fn
        return fn
    return decorator


@_tf("iam-password-policy")
def _tf_password_policy(f: Finding) -> str:
    return '''\
resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length        = 14
  require_lowercase_characters   = true
  require_uppercase_characters   = true
  require_numbers                = true
  require_symbols                = true
  allow_users_to_change_password = true
  max_password_age               = 90
  password_reuse_prevention      = 12
  hard_expiry                    = false
}'''


@_tf("iam-user-mfa")
def _tf_user_mfa(f: Finding) -> str:
    username = f.details.get("username", "USERNAME")
    return f'''\
# MFA must be enabled manually or via CLI — Terraform cannot create virtual MFA devices.
# Run the following AWS CLI commands:

# 1. Create a virtual MFA device:
#    aws iam create-virtual-mfa-device --virtual-mfa-device-name {username}-mfa \\
#        --outfile /tmp/{username}-qr.png --bootstrap-method QRCodePNG

# 2. Scan the QR code with an authenticator app (Google Authenticator, Authy, etc.)

# 3. Enable MFA for the user (replace CODE1 and CODE2 with two consecutive codes):
#    aws iam enable-mfa-device --user-name {username} \\
#        --serial-number arn:aws:iam::ACCOUNT_ID:mfa/{username}-mfa \\
#        --authentication-code1 CODE1 --authentication-code2 CODE2'''


@_tf("iam-no-direct-policies")
def _tf_no_direct_policies(f: Finding) -> str:
    username = f.details.get("username", "USERNAME")
    attached = f.details.get("attached_policies", [])
    policies_block = "\n".join(f'  # - {p}' for p in attached)
    return f'''\
# Move direct policies from user '{username}' to a group.
# Currently attached directly:
{policies_block}

resource "aws_iam_group" "{username}_group" {{
  name = "{username}-role-group"
}}

resource "aws_iam_group_membership" "{username}_membership" {{
  name  = "{username}-membership"
  users = ["{username}"]
  group = aws_iam_group.{username}_group.name
}}

# Attach the policies to the group instead of the user.
# Then remove direct user policy attachments.'''


@_tf("iam-overprivileged-user")
def _tf_overprivileged(f: Finding) -> str:
    username = f.details.get("username", "USERNAME")
    return f'''\
# Replace AdministratorAccess for user '{username}' with scoped policies.
# Step 1: Identify what the user actually needs access to.
# Step 2: Create a custom policy with minimum required permissions.
# Step 3: Remove the admin policy and attach the scoped one.

# Example: If the user only needs S3 and EC2 read access:
resource "aws_iam_policy" "{username}_scoped" {{
  name        = "{username}-scoped-access"
  description = "Scoped permissions for {username} — replaces AdministratorAccess"

  policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [
      {{
        Effect   = "Allow"
        Action   = [
          "s3:Get*",
          "s3:List*",
          "ec2:Describe*",
        ]
        Resource = "*"
      }}
    ]
  }})
}}

# IMPORTANT: Customize the actions and resources above based on
# what '{username}' actually needs to do.'''


@_tf("sg-no-unrestricted-ingress")
def _tf_restrict_sg(f: Finding) -> str:
    sg_name = f.details.get("sg_name", "SECURITY_GROUP")
    sg_id = f.resource_id
    rules = f.details.get("unrestricted_rules", [])

    rules_desc = []
    for r in rules:
        if r.get("protocol") == "-1":
            rules_desc.append("all traffic")
        else:
            rules_desc.append(f"port {r.get('from_port')}-{r.get('to_port')}")

    return f'''\
# Security group '{sg_name}' ({sg_id}) currently allows unrestricted
# ingress for: {", ".join(rules_desc)}
#
# Replace 0.0.0.0/0 with your specific IP ranges:

# Option 1: Restrict to your office/VPN IP
# Find your IP: curl -s ifconfig.me
resource "aws_vpc_security_group_ingress_rule" "{sg_name}_restricted" {{
  security_group_id = "{sg_id}"
  from_port         = 443  # Adjust port as needed
  to_port           = 443
  ip_protocol       = "tcp"
  cidr_ipv4         = "YOUR_OFFICE_IP/32"  # Replace with your actual IP
  description       = "HTTPS from office"
}}

# Option 2: If this SG is no longer needed, delete it:
# aws ec2 delete-security-group --group-id {sg_id}
#
# First check nothing is using it:
# aws ec2 describe-network-interfaces --filters Name=group-id,Values={sg_id}'''


@_tf("vpc-flow-logs-enabled")
def _tf_vpc_flow_logs(f: Finding) -> str:
    vpc_id = f.resource_id
    vpc_name = f.details.get("vpc_name", "")
    safe_name = (vpc_name or vpc_id).replace("-", "_").replace(" ", "_")
    return f'''\
resource "aws_flow_log" "{safe_name}_flow_log" {{
  vpc_id          = "{vpc_id}"
  traffic_type    = "ALL"
  log_destination = aws_cloudwatch_log_group.{safe_name}_flow.arn
  iam_role_arn    = aws_iam_role.flow_log_role.arn
}}

resource "aws_cloudwatch_log_group" "{safe_name}_flow" {{
  name              = "/aws/vpc/flow-logs/{vpc_id}"
  retention_in_days = 90
}}

resource "aws_iam_role" "flow_log_role" {{
  name = "vpc-flow-log-role"
  assume_role_policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [{{
      Effect    = "Allow"
      Principal = {{ Service = "vpc-flow-logs.amazonaws.com" }}
      Action    = "sts:AssumeRole"
    }}]
  }})
}}

resource "aws_iam_role_policy" "flow_log_policy" {{
  name = "vpc-flow-log-policy"
  role = aws_iam_role.flow_log_role.id
  policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [{{
      Effect = "Allow"
      Action = [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams"
      ]
      Resource = "*"
    }}]
  }})
}}'''


@_tf("s3-versioning")
def _tf_s3_versioning(f: Finding) -> str:
    bucket = f.details.get("bucket", "BUCKET_NAME")
    return f'''\
resource "aws_s3_bucket_versioning" "{bucket.replace("-", "_")}" {{
  bucket = "{bucket}"
  versioning_configuration {{
    status = "Enabled"
  }}
}}'''


@_tf("s3-ssl-only")
def _tf_s3_ssl(f: Finding) -> str:
    bucket = f.details.get("bucket", "BUCKET_NAME")
    safe = bucket.replace("-", "_")
    return f'''\
resource "aws_s3_bucket_policy" "{safe}_ssl_only" {{
  bucket = "{bucket}"
  policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [{{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [
        "arn:aws:s3:::{bucket}",
        "arn:aws:s3:::{bucket}/*"
      ]
      Condition = {{
        Bool = {{ "aws:SecureTransport" = "false" }}
      }}
    }}]
  }})
}}'''


@_tf("s3-public-access-block")
def _tf_s3_public_block(f: Finding) -> str:
    bucket = f.details.get("bucket", "BUCKET_NAME")
    safe = bucket.replace("-", "_")
    return f'''\
resource "aws_s3_bucket_public_access_block" "{safe}" {{
  bucket                  = "{bucket}"
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}}'''


@_tf("s3-encryption-at-rest")
def _tf_s3_encryption(f: Finding) -> str:
    bucket = f.details.get("bucket", "BUCKET_NAME")
    safe = bucket.replace("-", "_")
    return f'''\
resource "aws_s3_bucket_server_side_encryption_configuration" "{safe}" {{
  bucket = "{bucket}"
  rule {{
    apply_server_side_encryption_by_default {{
      sse_algorithm = "aws:kms"
    }}
    bucket_key_enabled = true
  }}
}}'''


# ---------------------------------------------------------------------------
# Explanation and steps registry
# ---------------------------------------------------------------------------

EXPLANATIONS: dict[str, dict] = {
    "iam-password-policy": {
        "explanation": "Your AWS password policy is like the rules for building keys to your office. Right now, the rules are too lax — allowing short, simple passwords that are easy to guess. An attacker who cracks one password gets into your AWS console.",
        "steps": [
            "Go to IAM > Account settings > Password policy in the AWS Console",
            "Set minimum length to 14 characters",
            "Require uppercase, lowercase, numbers, AND symbols",
            "Set password expiration to 90 days",
            "Set password reuse prevention to 12",
            "Or apply the Terraform template below",
        ],
        "effort": "quick",
    },
    "iam-user-mfa": {
        "explanation": "Multi-factor authentication (MFA) is a second lock on the door. Even if someone steals a password, they can't get in without the second factor (usually a phone app). Without MFA, a single leaked password means full account access.",
        "steps": [
            "Log into the AWS Console as the user (or an admin)",
            "Go to IAM > Users > select the user > Security credentials",
            "Click 'Assign MFA device'",
            "Choose 'Authenticator app' and scan the QR code",
            "Enter two consecutive codes to activate",
        ],
        "effort": "quick",
    },
    "iam-root-mfa": {
        "explanation": "The root account is the master key to your entire AWS account. If compromised without MFA, an attacker has unrestricted access to everything — they could delete all your data, spin up expensive resources, or lock you out entirely.",
        "steps": [
            "Sign in as root (email + password) at https://console.aws.amazon.com/",
            "Go to Security credentials in the top-right dropdown",
            "Assign an MFA device — hardware key is ideal, authenticator app is acceptable",
            "Store backup codes securely",
        ],
        "effort": "quick",
    },
    "iam-no-direct-policies": {
        "explanation": "Attaching policies directly to users is like giving each employee a unique set of keys instead of a role-based keycard. It becomes unmanageable — when someone changes roles, you have to update each user individually. Groups make access easy to audit and update.",
        "steps": [
            "Create an IAM group for the user's role (e.g., 'developers', 'ops')",
            "Attach the necessary policies to the group",
            "Add the user to the group",
            "Remove the direct policy attachments from the user",
        ],
        "effort": "quick",
    },
    "iam-overprivileged-user": {
        "explanation": "Giving a user AdministratorAccess is like giving an intern the CEO's master key. If their credentials are compromised, the attacker gets unlimited access. The principle of least privilege means each person gets only the access they actually need.",
        "steps": [
            "Identify what the user actually needs to do (which services, which actions)",
            "Create a scoped IAM policy with only those permissions",
            "Attach the scoped policy to a group",
            "Remove AdministratorAccess",
            "Test that the user can still do their work",
        ],
        "effort": "moderate",
    },
    "sg-no-unrestricted-ingress": {
        "explanation": "A security group open to 0.0.0.0/0 means anyone on the internet can reach that port. For SSH or RDP, this means anyone can try to brute-force their way in. For databases, it means your data could be directly exposed.",
        "steps": [
            "Identify who actually needs access to this resource",
            "Find your office/VPN IP address (curl ifconfig.me)",
            "Update the security group to only allow that IP range",
            "If the SG is unused, check for attached resources and delete it",
        ],
        "effort": "quick",
    },
    "vpc-flow-logs-enabled": {
        "explanation": "VPC flow logs are like security cameras for your network. Without them, if someone breaks in, you have no way to see what traffic came and went. They're essential for incident investigation and audit trail.",
        "steps": [
            "Go to VPC > Your VPCs in the AWS Console",
            "Select the VPC and click 'Flow logs' tab",
            "Create flow log: ALL traffic, send to CloudWatch Logs",
            "Set retention to 90 days minimum",
            "Or apply the Terraform template below",
        ],
        "effort": "quick",
    },
    "s3-versioning": {
        "explanation": "Without versioning, if someone accidentally deletes a file or overwrites it with bad data, it's gone forever. Versioning keeps a history of every change, letting you recover from accidents or ransomware.",
        "steps": [
            "Go to S3 > select the bucket > Properties tab",
            "Under Bucket Versioning, click Edit and enable it",
            "Consider adding a lifecycle rule to expire old versions after 90 days to control costs",
        ],
        "effort": "quick",
    },
    "s3-ssl-only": {
        "explanation": "Without an SSL-only policy, data can be sent to or from your S3 bucket over unencrypted HTTP. This means anyone monitoring the network could read your data in transit — like sending a postcard instead of a sealed envelope.",
        "steps": [
            "Go to S3 > select the bucket > Permissions > Bucket policy",
            "Add a policy that denies all requests where aws:SecureTransport is false",
            "Or apply the Terraform template below",
        ],
        "effort": "quick",
    },
    "s3-encryption-at-rest": {
        "explanation": "Encryption at rest means your data is scrambled on disk. If someone steals the physical drive or gets unauthorized access to the storage layer, they can't read anything without the encryption key.",
        "steps": [
            "Go to S3 > select the bucket > Properties tab",
            "Under Default encryption, enable SSE-KMS (preferred) or SSE-S3",
            "This only affects new objects — existing objects keep their current encryption",
        ],
        "effort": "quick",
    },
    "s3-public-access-block": {
        "explanation": "The public access block is a safety net that prevents anyone from accidentally making your bucket or objects public. Without it, a single misconfigured policy or ACL could expose your data to the entire internet.",
        "steps": [
            "Go to S3 > select the bucket > Permissions",
            "Under 'Block public access', click Edit",
            "Enable all four settings",
            "Click Save changes",
        ],
        "effort": "quick",
    },
    "sg-default-restricted": {
        "explanation": "Default security groups often have permissive rules left over from initial setup. Any resource that doesn't explicitly specify a security group will use the default — meaning those leftover rules apply unexpectedly.",
        "steps": [
            "Go to VPC > Security Groups in the AWS Console",
            "Find the default security group for each VPC",
            "Remove all inbound rules (leave outbound as-is if needed)",
            "Ensure all resources use custom security groups instead",
        ],
        "effort": "quick",
    },
    "iam-access-key-rotation": {
        "explanation": "Access keys are like passwords for programmatic access. The longer they exist, the more likely they've been accidentally committed to a repo, shared in a message, or logged somewhere insecure. Regular rotation limits the damage window.",
        "steps": [
            "Create a new access key for the user",
            "Update all applications using the old key",
            "Verify everything works with the new key",
            "Deactivate the old key, wait a few days, then delete it",
        ],
        "effort": "moderate",
    },
    "iam-inactive-user": {
        "explanation": "Unused accounts are a risk because they can be compromised without anyone noticing. If an ex-employee's credentials are leaked or brute-forced, there's no active user to notice the suspicious activity.",
        "steps": [
            "Review whether the user still needs access",
            "If not: disable their console password and deactivate access keys",
            "After confirming no automated processes depend on the user, delete the account",
        ],
        "effort": "quick",
    },
    "guardduty-no-active-findings": {
        "explanation": "GuardDuty has found potential security threats in your environment. These could range from unusual API calls to possible credential compromise. Each finding needs to be investigated — some may be false positives, but some could be real attacks.",
        "steps": [
            "Go to GuardDuty > Findings in the AWS Console",
            "Review each active finding",
            "For each: determine if it's a real threat or expected behavior",
            "Archive false positives, remediate real threats",
            "Set up SNS notifications for future findings",
        ],
        "effort": "moderate",
    },
}


def generate_remediation(finding: Finding) -> Remediation:
    """Generate a full remediation recommendation for a finding."""
    check_id = finding.check_id
    info = EXPLANATIONS.get(check_id, {})

    # Generate Terraform if available
    tf_generator = TERRAFORM_TEMPLATES.get(check_id)
    terraform = tf_generator(finding) if tf_generator else ""

    return Remediation(
        finding=finding,
        priority=SEVERITY_PRIORITY.get(finding.severity, 5),
        explanation=info.get("explanation", finding.description),
        steps=info.get("steps", [finding.remediation] if finding.remediation else []),
        terraform=terraform,
        effort=info.get("effort", "moderate"),
        category=finding.domain.value,
    )


def generate_all_remediations(findings: list[Finding]) -> list[Remediation]:
    """Generate remediations for all failing findings, sorted by priority."""
    failing = [f for f in findings if f.status in (ComplianceStatus.FAIL, ComplianceStatus.PARTIAL)]
    remediations = [generate_remediation(f) for f in failing]
    remediations.sort(key=lambda r: (r.priority, r.category))
    return remediations


def save_terraform_bundle(
    remediations: list[Remediation],
    output_path: Path | str = "data/remediation",
) -> Path:
    """Save all Terraform remediations as a single .tf file."""
    output_dir = Path(output_path)
    output_dir.mkdir(parents=True, exist_ok=True)
    filepath = output_dir / "remediation.tf"

    blocks = []
    blocks.append("# Transilience Community Compliance remediation bundle")
    blocks.append("# Review each resource before applying!\n")

    seen_check_ids = set()
    for r in remediations:
        if r.terraform and r.finding.check_id not in seen_check_ids:
            blocks.append(f"# --- {r.finding.title} ---")
            blocks.append(f"# SOC 2: {', '.join(r.finding.soc2_controls)}")
            blocks.append(f"# Severity: {r.finding.severity.value}")
            blocks.append(r.terraform)
            blocks.append("")
            seen_check_ids.add(r.finding.check_id)

    filepath.write_text("\n".join(blocks), encoding="utf-8")
    return filepath
