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

from shasta.evidence.models import ComplianceStatus, Finding, Severity

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
    return """\
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
}"""


@_tf("iam-user-mfa")
def _tf_user_mfa(f: Finding) -> str:
    username = f.details.get("username", "USERNAME")
    return f"""\
# MFA must be enabled manually or via CLI — Terraform cannot create virtual MFA devices.
# Run the following AWS CLI commands:

# 1. Create a virtual MFA device:
#    aws iam create-virtual-mfa-device --virtual-mfa-device-name {username}-mfa \\
#        --outfile /tmp/{username}-qr.png --bootstrap-method QRCodePNG

# 2. Scan the QR code with an authenticator app (Google Authenticator, Authy, etc.)

# 3. Enable MFA for the user (replace CODE1 and CODE2 with two consecutive codes):
#    aws iam enable-mfa-device --user-name {username} \\
#        --serial-number arn:aws:iam::ACCOUNT_ID:mfa/{username}-mfa \\
#        --authentication-code1 CODE1 --authentication-code2 CODE2"""


@_tf("iam-no-direct-policies")
def _tf_no_direct_policies(f: Finding) -> str:
    username = f.details.get("username", "USERNAME")
    attached = f.details.get("attached_policies", [])
    policies_block = "\n".join(f"  # - {p}" for p in attached)
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
# AWS — Stage 1/2/3 CIS AWS v3.0 sweep templates
# ---------------------------------------------------------------------------


def _aws_safe(name: str) -> str:
    """Sanitize an AWS resource name for use as a Terraform identifier."""
    return (name or "RESOURCE").replace("-", "_").replace(".", "_").replace("/", "_")


# ----- CloudTrail -----


@_tf("cloudtrail-kms-encryption")
def _tf_aws_ct_kms(f: Finding) -> str:
    name = f.details.get("trail", "main")
    return f'''\
resource "aws_kms_key" "cloudtrail" {{
  description             = "CloudTrail log encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [
      {{
        Sid    = "AllowCloudTrail"
        Effect = "Allow"
        Principal = {{ Service = "cloudtrail.amazonaws.com" }}
        Action = ["kms:GenerateDataKey*", "kms:Decrypt"]
        Resource = "*"
      }},
      {{
        Sid    = "AllowAccountFullAccess"
        Effect = "Allow"
        Principal = {{ AWS = "arn:aws:iam::ACCOUNT_ID:root" }}
        Action = "kms:*"
        Resource = "*"
      }}
    ]
  }})
}}

resource "aws_cloudtrail" "{_aws_safe(name)}" {{
  name           = "{name}"
  # ... existing config ...
  kms_key_id     = aws_kms_key.cloudtrail.arn
}}'''


@_tf("cloudtrail-log-validation")
def _tf_aws_ct_validation(f: Finding) -> str:
    name = f.details.get("trail", "main")
    return f'''\
resource "aws_cloudtrail" "{_aws_safe(name)}" {{
  name = "{name}"
  # ... existing config ...

  enable_log_file_validation = true  # CIS AWS 3.2
}}'''


@_tf("cloudtrail-s3-object-lock")
def _tf_aws_ct_object_lock(f: Finding) -> str:
    bucket = f.details.get("bucket", "cloudtrail-logs")
    safe = _aws_safe(bucket)
    return f'''\
# Object Lock can only be enabled at bucket creation. Migrate logs to a new
# bucket created with object_lock_enabled = true, then update the trail.

resource "aws_s3_bucket" "{safe}_v2" {{
  bucket              = "{bucket}-v2"
  object_lock_enabled = true
}}

resource "aws_s3_bucket_object_lock_configuration" "{safe}_v2" {{
  bucket = aws_s3_bucket.{safe}_v2.id

  rule {{
    default_retention {{
      mode = "COMPLIANCE"
      days = 365
    }}
  }}
}}

resource "aws_s3_bucket_versioning" "{safe}_v2" {{
  bucket = aws_s3_bucket.{safe}_v2.id
  versioning_configuration {{
    status = "Enabled"
  }}
}}'''


@_tf("security-hub-enabled")
def _tf_aws_security_hub(f: Finding) -> str:
    return '''\
resource "aws_securityhub_account" "main" {
  enable_default_standards = true
}

resource "aws_securityhub_standards_subscription" "cis_aws" {
  standards_arn = "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/3.0.0"
  depends_on    = [aws_securityhub_account.main]
}

resource "aws_securityhub_standards_subscription" "fsbp" {
  standards_arn = "arn:aws:securityhub:::standards/aws-foundational-security-best-practices/v/1.0.0"
  depends_on    = [aws_securityhub_account.main]
}'''


@_tf("iam-access-analyzer")
def _tf_aws_access_analyzer(f: Finding) -> str:
    return '''\
resource "aws_accessanalyzer_analyzer" "default" {
  analyzer_name = "default"
  type          = "ACCOUNT"  # Use ORGANIZATION if AWS Organizations is in use
}'''


# ----- Encryption: EFS / SNS / SQS / Secrets Manager / ACM -----


@_tf("efs-encryption")
def _tf_aws_efs_encryption(f: Finding) -> str:
    fs_id = f.details.get("file_system_id", "fs")
    return f'''\
# EFS encryption can only be enabled at creation. Recreate the file system:
resource "aws_efs_file_system" "{_aws_safe(fs_id)}_encrypted" {{
  creation_token = "{fs_id}-encrypted"
  encrypted      = true
  kms_key_id     = aws_kms_key.efs.arn
}}

resource "aws_kms_key" "efs" {{
  description         = "EFS encryption key"
  enable_key_rotation = true
}}'''


@_tf("sns-encryption")
def _tf_aws_sns_encryption(f: Finding) -> str:
    return '''\
resource "aws_sns_topic" "encrypted_topic" {
  name              = "TOPIC_NAME"
  kms_master_key_id = "alias/aws/sns"  # or a customer-managed key alias
}'''


@_tf("sqs-encryption")
def _tf_aws_sqs_encryption(f: Finding) -> str:
    return '''\
resource "aws_sqs_queue" "encrypted_queue" {
  name                              = "QUEUE_NAME"
  sqs_managed_sse_enabled           = true  # SQS-managed SSE (no KMS cost)
  # OR for KMS:
  # kms_master_key_id                 = "alias/aws/sqs"
  # kms_data_key_reuse_period_seconds = 300
}'''


@_tf("secrets-manager-rotation")
def _tf_aws_sm_rotation(f: Finding) -> str:
    return '''\
resource "aws_secretsmanager_secret" "db_password" {
  name = "db_password"
}

resource "aws_secretsmanager_secret_rotation" "db_password" {
  secret_id           = aws_secretsmanager_secret.db_password.id
  rotation_lambda_arn = aws_lambda_function.rotator.arn

  rotation_rules {
    automatically_after_days = 30
  }
}'''


@_tf("acm-expiring-certs")
def _tf_aws_acm_renewal(f: Finding) -> str:
    return '''\
# Use DNS validation so ACM auto-renews ~60 days before expiry.
# For email-validated or imported certs, switch to DNS-validated:
resource "aws_acm_certificate" "main" {
  domain_name       = "example.com"
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_route53_record" "cert_validation" {
  for_each = {
    for d in aws_acm_certificate.main.domain_validation_options : d.domain_name => {
      name   = d.resource_record_name
      record = d.resource_record_value
      type   = d.resource_record_type
    }
  }
  zone_id = "ZONE_ID"
  name    = each.value.name
  records = [each.value.record]
  type    = each.value.type
  ttl     = 60
}'''


# ----- Networking: ELB v2 -----


@_tf("elb-listener-tls")
def _tf_aws_elb_tls(f: Finding) -> str:
    return '''\
# Use a modern TLS policy and redirect HTTP -> HTTPS
resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.main.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"  # CIS AWS
  certificate_arn   = aws_acm_certificate.main.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app.arn
  }
}

resource "aws_lb_listener" "http_redirect" {
  load_balancer_arn = aws_lb.main.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}'''


@_tf("elb-access-logs")
def _tf_aws_elb_access_logs(f: Finding) -> str:
    return '''\
resource "aws_lb" "main" {
  name = "main"
  # ... existing config ...

  access_logs {
    bucket  = aws_s3_bucket.elb_logs.id
    prefix  = "alb-logs"
    enabled = true
  }
}'''


@_tf("elb-drop-invalid-headers")
def _tf_aws_elb_drop_headers(f: Finding) -> str:
    return '''\
resource "aws_lb" "main" {
  name = "main"
  # ... existing config ...

  drop_invalid_header_fields = true  # CIS AWS
}'''


# ----- Stage 2: Databases -----


@_tf("rds-iam-auth")
def _tf_aws_rds_iam_auth(f: Finding) -> str:
    db_id = f.details.get("db", "main")
    return f'''\
resource "aws_db_instance" "{_aws_safe(db_id)}" {{
  identifier = "{db_id}"
  # ... existing config ...

  iam_database_authentication_enabled = true  # CIS AWS 2.3.x
}}'''


@_tf("rds-deletion-protection")
def _tf_aws_rds_deletion_protect(f: Finding) -> str:
    db_id = f.details.get("db", "main")
    return f'''\
resource "aws_db_instance" "{_aws_safe(db_id)}" {{
  identifier          = "{db_id}"
  # ... existing config ...
  deletion_protection = true
}}'''


@_tf("rds-pi-kms")
def _tf_aws_rds_pi(f: Finding) -> str:
    db_id = f.details.get("db", "main")
    return f'''\
resource "aws_db_instance" "{_aws_safe(db_id)}" {{
  identifier = "{db_id}"
  # ... existing config ...

  performance_insights_enabled    = true
  performance_insights_kms_key_id = aws_kms_key.rds_pi.arn
}}

resource "aws_kms_key" "rds_pi" {{
  description         = "RDS Performance Insights"
  enable_key_rotation = true
}}'''


@_tf("rds-auto-minor-upgrade")
def _tf_aws_rds_minor(f: Finding) -> str:
    db_id = f.details.get("db", "main")
    return f'''\
resource "aws_db_instance" "{_aws_safe(db_id)}" {{
  identifier                  = "{db_id}"
  # ... existing config ...
  auto_minor_version_upgrade  = true
}}'''


@_tf("dynamodb-pitr")
def _tf_aws_ddb_pitr(f: Finding) -> str:
    return '''\
resource "aws_dynamodb_table" "main" {
  name = "TABLE_NAME"
  # ... existing config ...

  point_in_time_recovery {
    enabled = true
  }
}'''


@_tf("dynamodb-kms")
def _tf_aws_ddb_kms(f: Finding) -> str:
    return '''\
resource "aws_dynamodb_table" "main" {
  name = "TABLE_NAME"
  # ... existing config ...

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.dynamodb.arn  # Customer-managed
  }
}

resource "aws_kms_key" "dynamodb" {
  description         = "DynamoDB CMK"
  enable_key_rotation = true
}'''


# ----- Stage 2: Serverless -----


@_tf("lambda-runtime-eol")
def _tf_aws_lambda_runtime(f: Finding) -> str:
    deprecated = f.details.get("deprecated", [])
    examples = ", ".join(d.get("name", "") if isinstance(d, dict) else str(d) for d in deprecated[:3])
    return f'''\
# Bump deprecated Lambda runtimes ({examples}) to a current version.
resource "aws_lambda_function" "example" {{
  function_name = "FUNCTION_NAME"
  runtime       = "python3.12"  # or nodejs20.x / java21 / dotnet8
  # ... existing config ...
}}'''


@_tf("lambda-env-kms")
def _tf_aws_lambda_env_kms(f: Finding) -> str:
    return '''\
resource "aws_kms_key" "lambda_env" {
  description         = "Lambda environment variable encryption"
  enable_key_rotation = true
}

resource "aws_lambda_function" "example" {
  function_name = "FUNCTION_NAME"
  kms_key_arn   = aws_kms_key.lambda_env.arn
  # ... existing config ...
}'''


@_tf("lambda-dlq")
def _tf_aws_lambda_dlq(f: Finding) -> str:
    return '''\
resource "aws_sqs_queue" "lambda_dlq" {
  name                       = "lambda-dlq"
  message_retention_seconds  = 1209600  # 14 days
}

resource "aws_lambda_function" "example" {
  function_name = "FUNCTION_NAME"
  # ... existing config ...

  dead_letter_config {
    target_arn = aws_sqs_queue.lambda_dlq.arn
  }
}'''


@_tf("apigw-logging")
def _tf_aws_apigw_logging(f: Finding) -> str:
    return '''\
resource "aws_api_gateway_method_settings" "all" {
  rest_api_id = aws_api_gateway_rest_api.main.id
  stage_name  = aws_api_gateway_stage.prod.stage_name
  method_path = "*/*"

  settings {
    metrics_enabled = true
    logging_level   = "INFO"
  }
}'''


@_tf("apigw-waf")
def _tf_aws_apigw_waf(f: Finding) -> str:
    return '''\
resource "aws_wafv2_web_acl" "apigw" {
  name        = "apigw-waf"
  scope       = "REGIONAL"
  default_action { allow {} }

  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 1
    override_action { none {} }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "common"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "apigw-waf"
    sampled_requests_enabled   = true
  }
}

resource "aws_wafv2_web_acl_association" "apigw" {
  resource_arn = aws_api_gateway_stage.prod.arn
  web_acl_arn  = aws_wafv2_web_acl.apigw.arn
}'''


@_tf("sfn-logging")
def _tf_aws_sfn_logging(f: Finding) -> str:
    return '''\
resource "aws_cloudwatch_log_group" "sfn" {
  name              = "/aws/states/STATE_MACHINE_NAME"
  retention_in_days = 90
}

resource "aws_sfn_state_machine" "main" {
  name     = "STATE_MACHINE_NAME"
  # ... existing config ...

  logging_configuration {
    log_destination        = "${aws_cloudwatch_log_group.sfn.arn}:*"
    include_execution_data = true
    level                  = "ALL"
  }
}'''


# ----- Stage 2: Backup -----


@_tf("aws-backup-vault-lock")
def _tf_aws_backup_vault_lock(f: Finding) -> str:
    name = f.details.get("vault", "primary")
    return f'''\
resource "aws_backup_vault" "{_aws_safe(name)}" {{
  name        = "{name}"
  kms_key_arn = aws_kms_key.backup.arn
}}

resource "aws_backup_vault_lock_configuration" "{_aws_safe(name)}" {{
  backup_vault_name   = aws_backup_vault.{_aws_safe(name)}.name
  changeable_for_days = 3       # Compliance mode after 3 days
  min_retention_days  = 30
  max_retention_days  = 365
}}

resource "aws_kms_key" "backup" {{
  description         = "AWS Backup vault encryption"
  enable_key_rotation = true
}}'''


@_tf("aws-backup-plans")
def _tf_aws_backup_plans(f: Finding) -> str:
    return '''\
resource "aws_backup_plan" "daily_35day" {
  name = "daily-35day"

  rule {
    rule_name         = "daily"
    target_vault_name = aws_backup_vault.primary.name
    schedule          = "cron(0 5 ? * * *)"

    lifecycle {
      delete_after = 35
    }
  }
}

resource "aws_backup_selection" "all_resources" {
  iam_role_arn = aws_iam_role.backup.arn
  name         = "all-resources"
  plan_id      = aws_backup_plan.daily_35day.id

  selection_tag {
    type  = "STRINGEQUALS"
    key   = "backup"
    value = "true"
  }
}'''


# ----- Stage 3: Cross-cutting -----


@_tf("aws-vpc-endpoints")
def _tf_aws_vpc_endpoints(f: Finding) -> str:
    return '''\
# Gateway endpoints (free)
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = aws_route_table.private[*].id
}

resource "aws_vpc_endpoint" "dynamodb" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.region}.dynamodb"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = aws_route_table.private[*].id
}

# Interface endpoints (priced per AZ + per GB)
locals {
  interface_endpoints = [
    "kms", "secretsmanager", "ssm", "ssmmessages", "ec2messages",
    "ecr.api", "ecr.dkr", "logs", "sts"
  ]
}

resource "aws_vpc_endpoint" "interface" {
  for_each            = toset(local.interface_endpoints)
  vpc_id              = aws_vpc.main.id
  service_name        = "com.amazonaws.${var.region}.${each.key}"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  security_group_ids  = [aws_security_group.endpoints.id]
  private_dns_enabled = true
}'''


@_tf("cwl-kms-encryption")
def _tf_aws_cwl_kms(f: Finding) -> str:
    return '''\
resource "aws_kms_key" "logs" {
  description         = "CloudWatch Logs encryption"
  enable_key_rotation = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "AllowLogs"
      Effect = "Allow"
      Principal = { Service = "logs.${var.region}.amazonaws.com" }
      Action = ["kms:Encrypt*", "kms:Decrypt*", "kms:ReEncrypt*",
                "kms:GenerateDataKey*", "kms:Describe*"]
      Resource = "*"
    }]
  })
}

resource "aws_cloudwatch_log_group" "app" {
  name              = "/app/main"
  retention_in_days = 90
  kms_key_id        = aws_kms_key.logs.arn
}'''


@_tf("cwl-retention")
def _tf_aws_cwl_retention(f: Finding) -> str:
    return '''\
# Apply a retention policy to existing log groups via for_each
data "aws_cloudwatch_log_groups" "all" {}

resource "aws_cloudwatch_log_group" "retention_patch" {
  for_each          = toset(data.aws_cloudwatch_log_groups.all.log_group_names)
  name              = each.value
  retention_in_days = 90  # or 180/365 for compliance-critical
}'''


@_tf("aws-org-scps")
def _tf_aws_scps(f: Finding) -> str:
    return '''\
# Deny CloudTrail disable / delete across all member accounts
resource "aws_organizations_policy" "deny_cloudtrail_disable" {
  name = "deny-cloudtrail-disable"
  type = "SERVICE_CONTROL_POLICY"

  content = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "DenyCloudTrailDisable"
      Effect = "Deny"
      Action = [
        "cloudtrail:StopLogging",
        "cloudtrail:DeleteTrail",
        "cloudtrail:UpdateTrail",
        "cloudtrail:PutEventSelectors",
      ]
      Resource = "*"
    }]
  })
}

resource "aws_organizations_policy_attachment" "deny_ct" {
  policy_id = aws_organizations_policy.deny_cloudtrail_disable.id
  target_id = "ou-XXXX-XXXXXXXX"  # OU or account ID
}'''


@_tf("aws-tag-policy")
def _tf_aws_tag_policy(f: Finding) -> str:
    return '''\
resource "aws_organizations_policy" "require_owner_tag" {
  name = "require-owner-tag"
  type = "TAG_POLICY"

  content = jsonencode({
    tags = {
      owner = {
        tag_key = { "@@assign" = "owner" }
        enforced_for = { "@@assign" = ["ec2:instance", "rds:db", "s3:bucket"] }
      }
      environment = {
        tag_key = { "@@assign" = "environment" }
        tag_value = { "@@assign" = ["production", "staging", "dev"] }
        enforced_for = { "@@assign" = ["ec2:instance", "rds:db", "s3:bucket"] }
      }
    }
  })
}'''


# ---------------------------------------------------------------------------
# AWS Stage 1 (parity sweep): EC2/EKS/ECS, KMS, IAM, CloudWatch CIS 4.x
# ---------------------------------------------------------------------------


@_tf("ec2-imdsv2-enforced")
def _tf_aws_imdsv2(f: Finding) -> str:
    return '''\
# Enforce IMDSv2 on every existing instance
resource "aws_ec2_instance_metadata_defaults" "account_default" {
  http_tokens                 = "required"
  http_endpoint               = "enabled"
  http_put_response_hop_limit = 1
}

# For new instances launched via Terraform, set on each aws_instance resource:
# resource "aws_instance" "example" {
#   metadata_options {
#     http_tokens                 = "required"
#     http_endpoint               = "enabled"
#     http_put_response_hop_limit = 1
#   }
# }

# To remediate existing instances via CLI:
#   aws ec2 modify-instance-metadata-options --instance-id i-xxx \\
#       --http-tokens required --http-endpoint enabled --http-put-response-hop-limit 1'''


@_tf("ec2-instance-profile")
def _tf_aws_ec2_instance_profile(f: Finding) -> str:
    return '''\
# Minimal IAM role for an EC2 instance with no AWS access (extend as needed)
resource "aws_iam_role" "ec2_baseline" {
  name = "ec2-baseline"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action = "sts:AssumeRole"
    }]
  })
}

# Attach SSM managed instance core for Session Manager (no SSH needed)
resource "aws_iam_role_policy_attachment" "ssm" {
  role       = aws_iam_role.ec2_baseline.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "ec2_baseline" {
  name = "ec2-baseline"
  role = aws_iam_role.ec2_baseline.name
}

# Then attach to existing instances:
#   aws ec2 associate-iam-instance-profile --instance-id i-xxx \\
#       --iam-instance-profile Name=ec2-baseline'''


@_tf("eks-private-endpoint")
def _tf_aws_eks_private(f: Finding) -> str:
    cluster = f.details.get("cluster", "main")
    return f'''\
resource "aws_eks_cluster" "{_aws_safe(cluster)}" {{
  name     = "{cluster}"
  role_arn = aws_iam_role.eks_cluster.arn

  vpc_config {{
    subnet_ids              = aws_subnet.private[*].id
    endpoint_public_access  = false  # CIS 5.4.x
    endpoint_private_access = true
    security_group_ids      = [aws_security_group.eks_control_plane.id]
  }}

  # ... existing config ...
}}'''


@_tf("eks-audit-logging")
def _tf_aws_eks_audit(f: Finding) -> str:
    cluster = f.details.get("cluster", "main")
    return f'''\
resource "aws_eks_cluster" "{_aws_safe(cluster)}" {{
  name = "{cluster}"
  # ... existing config ...

  enabled_cluster_log_types = [
    "api",
    "audit",
    "authenticator",
    "controllerManager",
    "scheduler",
  ]
}}

resource "aws_cloudwatch_log_group" "{_aws_safe(cluster)}_eks" {{
  name              = "/aws/eks/{cluster}/cluster"
  retention_in_days = 90
  kms_key_id        = aws_kms_key.logs.arn
}}'''


@_tf("eks-secrets-encryption")
def _tf_aws_eks_secrets(f: Finding) -> str:
    cluster = f.details.get("cluster", "main")
    return f'''\
resource "aws_kms_key" "eks_secrets" {{
  description             = "EKS envelope encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}}

resource "aws_eks_cluster" "{_aws_safe(cluster)}" {{
  name = "{cluster}"
  # ... existing config ...

  encryption_config {{
    resources = ["secrets"]
    provider {{
      key_arn = aws_kms_key.eks_secrets.arn
    }}
  }}
}}'''


@_tf("ecs-task-privileged")
def _tf_aws_ecs_no_privileged(f: Finding) -> str:
    return '''\
resource "aws_ecs_task_definition" "app" {
  family = "app"
  # ... existing config ...

  container_definitions = jsonencode([{
    name       = "app"
    image      = "..."
    privileged = false  # Never true unless absolutely necessary
    user       = "1000"  # Non-root
    readonlyRootFilesystem = true
    # ... rest of definition ...
  }])
}'''


@_tf("ecs-task-root-user")
def _tf_aws_ecs_no_root(f: Finding) -> str:
    return '''\
# In the Dockerfile of the container image:
#   FROM python:3.12-slim
#   RUN useradd -u 1000 -m app
#   USER 1000
#
# In the task definition, mirror the same user:
resource "aws_ecs_task_definition" "app" {
  family = "app"
  # ... existing config ...

  container_definitions = jsonencode([{
    name  = "app"
    image = "..."
    user  = "1000"  # Non-root uid matching the Dockerfile
    # ... rest of definition ...
  }])
}'''


@_tf("kms-key-rotation")
def _tf_aws_kms_rotation(f: Finding) -> str:
    return '''\
# Enable rotation on every existing customer-managed CMK:
#
# for key_id in $(aws kms list-keys --query "Keys[].KeyId" --output text); do
#   meta=$(aws kms describe-key --key-id "$key_id" --query "KeyMetadata.KeyManager" --output text)
#   spec=$(aws kms describe-key --key-id "$key_id" --query "KeyMetadata.KeySpec" --output text)
#   if [ "$meta" = "CUSTOMER" ] && [ "$spec" = "SYMMETRIC_DEFAULT" ]; then
#     aws kms enable-key-rotation --key-id "$key_id"
#   fi
# done

# For new keys via Terraform, always include enable_key_rotation = true:
resource "aws_kms_key" "example" {
  description             = "..."
  enable_key_rotation     = true
  deletion_window_in_days = 30
}'''


@_tf("kms-key-policy-wildcards")
def _tf_aws_kms_policy(f: Finding) -> str:
    return '''\
# Replace wildcard key policies with scoped principals
resource "aws_kms_key" "example" {
  description             = "..."
  enable_key_rotation     = true
  deletion_window_in_days = 30

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowAccountRoot"
        Effect = "Allow"
        Principal = { AWS = "arn:aws:iam::ACCOUNT_ID:root" }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowSpecificService"
        Effect = "Allow"
        Principal = { Service = "logs.us-east-1.amazonaws.com" }
        Action = ["kms:Encrypt*", "kms:Decrypt*", "kms:ReEncrypt*",
                  "kms:GenerateDataKey*", "kms:Describe*"]
        Resource = "*"
      }
    ]
  })
}'''


@_tf("iam-policy-wildcards")
def _tf_aws_iam_no_wildcards(f: Finding) -> str:
    policies = f.details.get("wildcard_policies", [])
    names = ", ".join(p.get("policy_name", "") for p in policies[:3]) or "<policy-name>"
    return f'''\
# Replace wildcard policies ({names}) with scoped equivalents.
# Use IAM Access Analyzer policy generation to derive a policy from
# CloudTrail data:
#
#   aws accessanalyzer start-policy-generation \\
#     --policy-generation-details principalArn=arn:aws:iam::ACCOUNT_ID:role/MyRole \\
#     --cloud-trail-details accessRole=arn:aws:iam::ACCOUNT_ID:role/AccessAnalyzerRole,trails=[{{cloudTrailArn=arn:aws:cloudtrail:us-east-1:ACCOUNT_ID:trail/management}}],startTime=2026-01-01T00:00:00Z

# Or define a scoped policy explicitly via Terraform:
resource "aws_iam_policy" "scoped_replacement" {{
  name        = "scoped-replacement"
  description = "Scoped replacement for a wildcard policy"

  policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [{{
      Effect = "Allow"
      Action = [
        "s3:GetObject",
        "s3:PutObject",
      ]
      Resource = "arn:aws:s3:::specific-bucket/specific-prefix/*"
    }}]
  }})
}}'''


@_tf("iam-role-trust-external")
def _tf_aws_iam_external_id(f: Finding) -> str:
    return '''\
# Add an ExternalId condition to every cross-account role trust policy
resource "aws_iam_role" "third_party_integration" {
  name = "third-party-integration"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = { AWS = "arn:aws:iam::THIRD_PARTY_ACCOUNT_ID:root" }
      Action   = "sts:AssumeRole"
      Condition = {
        StringEquals = {
          # Generate a UUID and share out-of-band with the third party
          "sts:ExternalId" = "00000000-0000-0000-0000-000000000000"
        }
      }
    }]
  })
}'''


@_tf("cloudwatch-alarms-cis-4")
def _tf_aws_cwl_cis_4(f: Finding) -> str:
    return '''\
# CloudTrail metric filters + alarms for CIS AWS 4.1-4.15
# This is a representative sample — the full set is 15 filter+alarm pairs.
# Run them in the home region of the multi-region trail.

resource "aws_sns_topic" "secops_alerts" {
  name = "secops-cis-4-x-alerts"
}

# CIS 4.5 — CloudTrail config changes
resource "aws_cloudwatch_log_metric_filter" "cis_4_5" {
  name           = "cis-4-5-cloudtrail-changes"
  log_group_name = "CloudTrail/management-events"
  pattern = <<-EOT
    { ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) ||
      ($.eventName = DeleteTrail) || ($.eventName = StartLogging) ||
      ($.eventName = StopLogging) }
  EOT

  metric_transformation {
    name      = "CIS-4-5-CloudTrailChanges"
    namespace = "CISBenchmark"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "cis_4_5" {
  alarm_name          = "cis-4-5-cloudtrail-changes"
  metric_name         = "CIS-4-5-CloudTrailChanges"
  namespace           = "CISBenchmark"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_actions       = [aws_sns_topic.secops_alerts.arn]
}

# Repeat the metric_filter + metric_alarm pair for each of CIS 4.1-4.15.
# CIS Foundations Benchmark v3.0 spec lists the exact filter pattern for each.'''


@_tf("aws-config-conformance-packs")
def _tf_aws_conformance_pack(f: Finding) -> str:
    return '''\
# Deploy the CIS AWS Foundations Benchmark v3.0 conformance pack
resource "aws_config_conformance_pack" "cis_aws_v3" {
  name = "cis-aws-foundations-v3"

  template_s3_uri = "s3://aws-managed-config-conformance-packs/Operational-Best-Practices-for-CIS-AWS-v3.0.yaml"
}

# Or use AWS-managed conformance pack templates directly via the console:
# Config > Conformance packs > Deploy conformance pack > Use sample template
# > select "Operational Best Practices for CIS AWS v3.0".'''


# ---------------------------------------------------------------------------
# AWS Stage 2 (parity sweep): CloudFront, Redshift, ElastiCache, Lambda
# Function URLs, API Gateway hardening, S3 hardening, AWS Backup
# ---------------------------------------------------------------------------


@_tf("cloudfront-https-only")
def _tf_aws_cf_https(f: Finding) -> str:
    return '''\
resource "aws_cloudfront_distribution" "main" {
  # ... existing config ...

  default_cache_behavior {
    viewer_protocol_policy = "redirect-to-https"
    # ... existing behavior config ...
  }

  # Repeat on every additional cache behavior:
  ordered_cache_behavior {
    path_pattern           = "*"
    viewer_protocol_policy = "redirect-to-https"
    # ... rest of behavior ...
  }
}'''


@_tf("cloudfront-min-tls")
def _tf_aws_cf_tls(f: Finding) -> str:
    return '''\
resource "aws_cloudfront_distribution" "main" {
  # ... existing config ...

  viewer_certificate {
    acm_certificate_arn      = aws_acm_certificate.main.arn
    ssl_support_method       = "sni-only"
    minimum_protocol_version = "TLSv1.2_2021"
  }
}

# ACM certificate for CloudFront must live in us-east-1
resource "aws_acm_certificate" "main" {
  provider          = aws.us_east_1
  domain_name       = "example.com"
  validation_method = "DNS"
}'''


@_tf("cloudfront-waf")
def _tf_aws_cf_waf(f: Finding) -> str:
    return '''\
# Web ACL must be in us-east-1 for CloudFront
resource "aws_wafv2_web_acl" "cloudfront" {
  provider = aws.us_east_1
  name     = "cloudfront-waf"
  scope    = "CLOUDFRONT"
  default_action { allow {} }

  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 1
    override_action { none {} }
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "common"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "cloudfront-waf"
    sampled_requests_enabled   = true
  }
}

resource "aws_cloudfront_distribution" "main" {
  web_acl_id = aws_wafv2_web_acl.cloudfront.arn
  # ... existing config ...
}'''


@_tf("cloudfront-oac")
def _tf_aws_cf_oac(f: Finding) -> str:
    return '''\
resource "aws_cloudfront_origin_access_control" "s3" {
  name                              = "s3-oac"
  description                       = "OAC for S3 origin"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

resource "aws_cloudfront_distribution" "main" {
  origin {
    domain_name              = aws_s3_bucket.content.bucket_regional_domain_name
    origin_access_control_id = aws_cloudfront_origin_access_control.s3.id
    origin_id                = "s3-content"
  }
  # ... existing config ...
}

# Restrict S3 bucket policy to allow only the CloudFront distribution
resource "aws_s3_bucket_policy" "content" {
  bucket = aws_s3_bucket.content.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "cloudfront.amazonaws.com" }
      Action    = "s3:GetObject"
      Resource  = "${aws_s3_bucket.content.arn}/*"
      Condition = {
        StringEquals = {
          "AWS:SourceArn" = aws_cloudfront_distribution.main.arn
        }
      }
    }]
  })
}'''


@_tf("redshift-encryption")
def _tf_aws_redshift_encrypt(f: Finding) -> str:
    return '''\
resource "aws_kms_key" "redshift" {
  description             = "Redshift cluster encryption"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

resource "aws_redshift_cluster" "main" {
  cluster_identifier = "main"
  encrypted          = true
  kms_key_id         = aws_kms_key.redshift.arn
  # ... existing config ...
}'''


@_tf("redshift-public-access")
def _tf_aws_redshift_private(f: Finding) -> str:
    return '''\
resource "aws_redshift_cluster" "main" {
  cluster_identifier  = "main"
  publicly_accessible = false
  # Place in a private subnet group
  cluster_subnet_group_name = aws_redshift_subnet_group.private.name
  vpc_security_group_ids    = [aws_security_group.redshift.id]
  # ... existing config ...
}'''


@_tf("redshift-audit-logging")
def _tf_aws_redshift_logging(f: Finding) -> str:
    return '''\
resource "aws_s3_bucket" "redshift_logs" {
  bucket = "company-redshift-audit-logs"
}

resource "aws_redshift_cluster" "main" {
  cluster_identifier = "main"
  # ... existing config ...

  logging {
    enable        = true
    bucket_name   = aws_s3_bucket.redshift_logs.id
    s3_key_prefix = "redshift-audit/"
  }
}'''


@_tf("redshift-require-ssl")
def _tf_aws_redshift_ssl(f: Finding) -> str:
    return '''\
resource "aws_redshift_parameter_group" "secure" {
  family = "redshift-1.0"
  name   = "redshift-secure"

  parameter {
    name  = "require_ssl"
    value = "true"
  }
}

resource "aws_redshift_cluster" "main" {
  cluster_identifier        = "main"
  cluster_parameter_group_name = aws_redshift_parameter_group.secure.name
  # ... existing config ...
}'''


@_tf("elasticache-transit-encryption")
def _tf_aws_ec_transit(f: Finding) -> str:
    return '''\
resource "aws_elasticache_replication_group" "main" {
  replication_group_id       = "main"
  description                = "Redis with TLS"
  transit_encryption_enabled = true
  at_rest_encryption_enabled = true
  auth_token                 = "REDIS_AUTH_TOKEN"
  # ... existing config ...
}'''


@_tf("elasticache-at-rest-encryption")
def _tf_aws_ec_at_rest(f: Finding) -> str:
    return '''\
resource "aws_kms_key" "elasticache" {
  description         = "ElastiCache encryption"
  enable_key_rotation = true
}

resource "aws_elasticache_replication_group" "main" {
  replication_group_id       = "main"
  description                = "Redis with at-rest encryption"
  at_rest_encryption_enabled = true
  kms_key_id                 = aws_kms_key.elasticache.arn
  # ... existing config ...
}'''


@_tf("elasticache-auth-token")
def _tf_aws_ec_auth(f: Finding) -> str:
    return '''\
resource "aws_elasticache_replication_group" "main" {
  replication_group_id       = "main"
  description                = "Redis with AUTH"
  transit_encryption_enabled = true
  auth_token                 = data.aws_secretsmanager_secret_version.redis_auth.secret_string
  # ... existing config ...
}

# Store the auth token in Secrets Manager
data "aws_secretsmanager_secret_version" "redis_auth" {
  secret_id = "redis-auth-token"
}'''


@_tf("neptune-encryption")
def _tf_aws_neptune_encrypt(f: Finding) -> str:
    return '''\
resource "aws_kms_key" "neptune" {
  description         = "Neptune cluster encryption"
  enable_key_rotation = true
}

resource "aws_neptune_cluster" "main" {
  cluster_identifier  = "main"
  storage_encrypted   = true
  kms_key_arn         = aws_kms_key.neptune.arn
  # ... existing config ...
}'''


@_tf("rds-force-ssl")
def _tf_aws_rds_force_ssl(f: Finding) -> str:
    engine = f.details.get("engine", "postgres")
    if "mysql" in engine or "mariadb" in engine:
        param_name = "require_secure_transport"
        value = "ON"
    else:
        param_name = "rds.force_ssl"
        value = "1"
    return f'''\
resource "aws_db_parameter_group" "secure" {{
  name   = "rds-secure"
  family = "{engine}15"  # adjust to match engine version

  parameter {{
    name         = "{param_name}"
    value        = "{value}"
    apply_method = "pending-reboot"
  }}
}}

resource "aws_db_instance" "main" {{
  parameter_group_name = aws_db_parameter_group.secure.name
  # ... existing config ...
}}'''


@_tf("rds-postgres-log-settings")
def _tf_aws_rds_pg_logs(f: Finding) -> str:
    return '''\
resource "aws_db_parameter_group" "postgres_audit" {
  name   = "postgres-audit"
  family = "postgres15"  # adjust to your version

  parameter {
    name  = "log_connections"
    value = "1"
  }
  parameter {
    name  = "log_disconnections"
    value = "1"
  }
  parameter {
    name  = "log_checkpoints"
    value = "1"
  }
  parameter {
    name  = "log_statement"
    value = "ddl"  # log all DDL changes
  }
}

resource "aws_db_instance" "main" {
  parameter_group_name = aws_db_parameter_group.postgres_audit.name
  enabled_cloudwatch_logs_exports = ["postgresql"]
  # ... existing config ...
}'''


@_tf("rds-min-tls")
def _tf_aws_rds_min_tls(f: Finding) -> str:
    return '''\
# SQL Server RDS only
resource "aws_db_parameter_group" "sqlserver_tls" {
  name   = "sqlserver-tls"
  family = "sqlserver-se-15.0"  # adjust to engine version

  parameter {
    name         = "rds.tls_version"
    value        = "1.2"
    apply_method = "pending-reboot"
  }
}'''


@_tf("lambda-function-url-auth")
def _tf_aws_lambda_url_auth(f: Finding) -> str:
    return '''\
resource "aws_lambda_function_url" "secured" {
  function_name      = aws_lambda_function.example.function_name
  authorization_type = "AWS_IAM"  # never NONE for production endpoints
}'''


@_tf("lambda-layer-origin")
def _tf_aws_lambda_layer(f: Finding) -> str:
    return '''\
# Re-publish foreign-account layers in your own account so you control updates
resource "aws_lambda_layer_version" "vendored" {
  layer_name          = "vendored-third-party"
  compatible_runtimes = ["python3.12"]
  filename            = "third-party-layer.zip"  # downloaded from the foreign layer
  source_code_hash    = filebase64sha256("third-party-layer.zip")
}

resource "aws_lambda_function" "example" {
  function_name = "example"
  layers        = [aws_lambda_layer_version.vendored.arn]
  # ... existing config ...
}'''


@_tf("apigw-client-cert")
def _tf_aws_apigw_client_cert(f: Finding) -> str:
    return '''\
resource "aws_api_gateway_client_certificate" "main" {
  description = "Client cert for backend integration auth"
}

resource "aws_api_gateway_stage" "prod" {
  rest_api_id           = aws_api_gateway_rest_api.main.id
  stage_name            = "prod"
  client_certificate_id = aws_api_gateway_client_certificate.main.id
  # ... existing config ...
}'''


@_tf("apigw-authorizer")
def _tf_aws_apigw_authorizer(f: Finding) -> str:
    return '''\
# IAM auth on every method (replace AWS_IAM with COGNITO_USER_POOLS or CUSTOM as needed)
resource "aws_api_gateway_method" "secured_get" {
  rest_api_id   = aws_api_gateway_rest_api.main.id
  resource_id   = aws_api_gateway_resource.example.id
  http_method   = "GET"
  authorization = "AWS_IAM"  # or COGNITO_USER_POOLS / CUSTOM
}'''


@_tf("apigw-throttling")
def _tf_aws_apigw_throttle(f: Finding) -> str:
    return '''\
resource "aws_api_gateway_method_settings" "throttle" {
  rest_api_id = aws_api_gateway_rest_api.main.id
  stage_name  = aws_api_gateway_stage.prod.stage_name
  method_path = "*/*"

  settings {
    throttling_burst_limit = 200
    throttling_rate_limit  = 100
  }
}'''


@_tf("apigw-request-validation")
def _tf_aws_apigw_validate(f: Finding) -> str:
    return '''\
resource "aws_api_gateway_request_validator" "body_and_params" {
  name                        = "body-and-params"
  rest_api_id                 = aws_api_gateway_rest_api.main.id
  validate_request_body       = true
  validate_request_parameters = true
}

resource "aws_api_gateway_method" "validated" {
  rest_api_id          = aws_api_gateway_rest_api.main.id
  resource_id          = aws_api_gateway_resource.example.id
  http_method          = "POST"
  authorization        = "AWS_IAM"
  request_validator_id = aws_api_gateway_request_validator.body_and_params.id
}'''


@_tf("s3-object-ownership")
def _tf_aws_s3_oo(f: Finding) -> str:
    return '''\
resource "aws_s3_bucket_ownership_controls" "enforce" {
  bucket = aws_s3_bucket.main.id

  rule {
    object_ownership = "BucketOwnerEnforced"  # disables ACLs entirely
  }
}'''


@_tf("s3-access-logging")
def _tf_aws_s3_logging(f: Finding) -> str:
    return '''\
# A dedicated log destination bucket with Object Lock + lifecycle
resource "aws_s3_bucket" "logs" {
  bucket              = "company-s3-access-logs"
  object_lock_enabled = true
}

resource "aws_s3_bucket_logging" "main" {
  bucket        = aws_s3_bucket.main.id
  target_bucket = aws_s3_bucket.logs.id
  target_prefix = "main/"
}'''


@_tf("s3-kms-cmk")
def _tf_aws_s3_kms_cmk(f: Finding) -> str:
    return '''\
resource "aws_kms_key" "s3" {
  description         = "S3 bucket encryption"
  enable_key_rotation = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "main" {
  bucket = aws_s3_bucket.main.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.s3.arn
    }
    bucket_key_enabled = true  # Reduces KMS API costs
  }
}'''


@_tf("aws-backup-cross-region-copy")
def _tf_aws_backup_crr(f: Finding) -> str:
    return '''\
resource "aws_backup_vault" "secondary" {
  provider    = aws.us_west_2  # destination region
  name        = "secondary"
  kms_key_arn = aws_kms_key.backup_secondary.arn
}

resource "aws_backup_plan" "with_copy" {
  name = "with-cross-region-copy"

  rule {
    rule_name         = "daily"
    target_vault_name = aws_backup_vault.primary.name
    schedule          = "cron(0 5 ? * * *)"

    lifecycle {
      delete_after = 35
    }

    copy_action {
      destination_vault_arn = aws_backup_vault.secondary.arn

      lifecycle {
        delete_after = 35
      }
    }
  }
}'''


@_tf("aws-backup-vault-access-policy")
def _tf_aws_backup_access_policy(f: Finding) -> str:
    return '''\
resource "aws_backup_vault_policy" "deny_destructive" {
  backup_vault_name = aws_backup_vault.primary.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "DenyDestructiveActionsExceptBreakGlass"
      Effect = "Deny"
      NotPrincipal = {
        AWS = "arn:aws:iam::ACCOUNT_ID:role/break-glass-backup-admin"
      }
      Action = [
        "backup:DeleteBackupVault",
        "backup:DeleteRecoveryPoint",
        "backup:StartCopyJob",
        "backup:UpdateRecoveryPointLifecycle",
      ]
      Resource = "*"
    }]
  })
}'''


# ---------------------------------------------------------------------------
# Azure (azurerm) Terraform templates — covers the Stage 1/2/3 CIS Azure
# v3.0 checks. Each template is a focused snippet that the operator drops
# into the matching resource block; full resource definitions are intentionally
# avoided so we don't overwrite unrelated configuration.
# ---------------------------------------------------------------------------


def _safe(name: str) -> str:
    """Sanitize a resource name for use as a Terraform identifier."""
    return (name or "RESOURCE").replace("-", "_").replace(".", "_").replace("/", "_")


# ----- Storage Account checks -----


@_tf("azure-storage-shared-key-access")
def _tf_az_storage_shared_key(f: Finding) -> str:
    name = f.details.get("storage_account", "STORAGE_ACCOUNT")
    rg = f.details.get("resource_group", "RESOURCE_GROUP")
    return f'''\
resource "azurerm_storage_account" "{_safe(name)}" {{
  name                = "{name}"
  resource_group_name = "{rg}"
  # ... existing config ...

  # Disable account-key auth — force Entra ID-only access (CIS 3.3)
  shared_access_key_enabled = false
}}'''


@_tf("azure-storage-cross-tenant-replication")
def _tf_az_storage_cross_tenant(f: Finding) -> str:
    name = f.details.get("storage_account", "STORAGE_ACCOUNT")
    rg = f.details.get("resource_group", "RESOURCE_GROUP")
    return f'''\
resource "azurerm_storage_account" "{_safe(name)}" {{
  name                = "{name}"
  resource_group_name = "{rg}"
  # ... existing config ...

  # Block cross-tenant object replication (CIS 3.15)
  cross_tenant_replication_enabled = false
}}'''


@_tf("azure-storage-network-default-deny")
def _tf_az_storage_default_deny(f: Finding) -> str:
    name = f.details.get("storage_account", "STORAGE_ACCOUNT")
    rg = f.details.get("resource_group", "RESOURCE_GROUP")
    return f'''\
resource "azurerm_storage_account" "{_safe(name)}" {{
  name                = "{name}"
  resource_group_name = "{rg}"
  # ... existing config ...

  # Network default-Deny with explicit allowlist (CIS 3.8)
  network_rules {{
    default_action             = "Deny"
    bypass                     = ["AzureServices", "Logging", "Metrics"]
    ip_rules                   = []  # Add trusted IPs here
    virtual_network_subnet_ids = []  # Add trusted subnet IDs here
  }}
}}'''


# ----- Key Vault checks -----


@_tf("azure-keyvault-rbac-mode")
def _tf_az_kv_rbac(f: Finding) -> str:
    name = f.details.get("vault", "KEY_VAULT")
    return f'''\
resource "azurerm_key_vault" "{_safe(name)}" {{
  name = "{name}"
  # ... existing config ...

  # Use Azure RBAC instead of legacy access policies (CIS 8.5)
  enable_rbac_authorization = true
}}

# Re-grant access via RBAC role assignments after switching modes:
resource "azurerm_role_assignment" "{_safe(name)}_admin" {{
  scope                = azurerm_key_vault.{_safe(name)}.id
  role_definition_name = "Key Vault Administrator"
  principal_id         = "PRINCIPAL_OBJECT_ID"
}}'''


@_tf("azure-keyvault-public-access")
def _tf_az_kv_public_access(f: Finding) -> str:
    name = f.details.get("vault", "KEY_VAULT")
    return f'''\
resource "azurerm_key_vault" "{_safe(name)}" {{
  name = "{name}"
  # ... existing config ...

  # Disable public network access (CIS 8.7)
  public_network_access_enabled = false

  # Default-Deny network ACLs (CIS 8.6)
  network_acls {{
    default_action = "Deny"
    bypass         = "AzureServices"
    ip_rules       = []
  }}
}}

# Pair with a Private Endpoint:
resource "azurerm_private_endpoint" "{_safe(name)}_pe" {{
  name                = "{name}-pe"
  location            = "LOCATION"
  resource_group_name = "RESOURCE_GROUP"
  subnet_id           = "SUBNET_ID"

  private_service_connection {{
    name                           = "{name}-psc"
    private_connection_resource_id = azurerm_key_vault.{_safe(name)}.id
    subresource_names              = ["vault"]
    is_manual_connection           = false
  }}
}}'''


# ----- SQL Server checks -----


@_tf("azure-sql-min-tls")
def _tf_az_sql_min_tls(f: Finding) -> str:
    server = f.details.get("server", "SQL_SERVER")
    return f'''\
resource "azurerm_mssql_server" "{_safe(server)}" {{
  name = "{server}"
  # ... existing config ...

  # Enforce TLS 1.2 (CIS 4.1.7)
  minimum_tls_version = "1.2"
}}'''


@_tf("azure-sql-auditing")
def _tf_az_sql_auditing(f: Finding) -> str:
    server = f.details.get("server", "SQL_SERVER")
    return f'''\
# Server-level auditing with ≥90-day retention (CIS 4.1.1, 4.1.6)
resource "azurerm_mssql_server_extended_auditing_policy" "{_safe(server)}" {{
  server_id                               = azurerm_mssql_server.{_safe(server)}.id
  storage_endpoint                        = "https://AUDITSTORAGE.blob.core.windows.net/"
  storage_account_access_key              = ""  # Use managed identity instead
  storage_account_access_key_is_secondary = false
  retention_in_days                       = 90
  log_monitoring_enabled                  = true
}}

# Also send to Log Analytics for query + alerting:
resource "azurerm_monitor_diagnostic_setting" "{_safe(server)}_audit" {{
  name                       = "{server}-audit"
  target_resource_id         = "${{azurerm_mssql_server.{_safe(server)}.id}}/databases/master"
  log_analytics_workspace_id = "LOG_ANALYTICS_WORKSPACE_ID"

  enabled_log {{ category = "SQLSecurityAuditEvents" }}
  enabled_log {{ category = "DevOpsOperationsAudit" }}
}}'''


@_tf("azure-sql-entra-admin")
def _tf_az_sql_entra_admin(f: Finding) -> str:
    server = f.details.get("server", "SQL_SERVER")
    return f'''\
resource "azurerm_mssql_server" "{_safe(server)}" {{
  name = "{server}"
  # ... existing config ...

  # Entra ID admin (CIS 4.1.3) — prefer an Entra group for break-glass
  azuread_administrator {{
    login_username              = "sql-admins"
    object_id                   = "ENTRA_GROUP_OBJECT_ID"
    azuread_authentication_only = true
  }}
}}'''


# ----- PostgreSQL Flexible Server -----


@_tf("azure-postgres-secure-transport")
def _tf_az_pg_secure_transport(f: Finding) -> str:
    server = f.details.get("server", "PG_SERVER")
    return f'''\
# Force TLS-only connections (CIS 4.3.1)
resource "azurerm_postgresql_flexible_server_configuration" "{_safe(server)}_secure_transport" {{
  name      = "require_secure_transport"
  server_id = azurerm_postgresql_flexible_server.{_safe(server)}.id
  value     = "ON"
}}'''


@_tf("azure-postgres-log-settings")
def _tf_az_pg_log_settings(f: Finding) -> str:
    server = f.details.get("server", "PG_SERVER")
    safe = _safe(server)
    return f'''\
# Connection logging (CIS 4.3.2 - 4.3.4)
resource "azurerm_postgresql_flexible_server_configuration" "{safe}_log_connections" {{
  name      = "log_connections"
  server_id = azurerm_postgresql_flexible_server.{safe}.id
  value     = "ON"
}}

resource "azurerm_postgresql_flexible_server_configuration" "{safe}_log_disconnections" {{
  name      = "log_disconnections"
  server_id = azurerm_postgresql_flexible_server.{safe}.id
  value     = "ON"
}}

resource "azurerm_postgresql_flexible_server_configuration" "{safe}_log_checkpoints" {{
  name      = "log_checkpoints"
  server_id = azurerm_postgresql_flexible_server.{safe}.id
  value     = "ON"
}}'''


# ----- MySQL Flexible Server -----


@_tf("azure-mysql-secure-transport")
def _tf_az_mysql_secure_transport(f: Finding) -> str:
    server = f.details.get("server", "MYSQL_SERVER")
    return f'''\
# Force TLS-only connections (CIS 4.4.1)
resource "azurerm_mysql_flexible_server_configuration" "{_safe(server)}_secure_transport" {{
  name                = "require_secure_transport"
  resource_group_name = "RESOURCE_GROUP"
  server_name         = azurerm_mysql_flexible_server.{_safe(server)}.name
  value               = "ON"
}}'''


@_tf("azure-mysql-tls-version")
def _tf_az_mysql_tls_version(f: Finding) -> str:
    server = f.details.get("server", "MYSQL_SERVER")
    return f'''\
# Restrict to TLS 1.2 / 1.3 (CIS 4.4.2)
resource "azurerm_mysql_flexible_server_configuration" "{_safe(server)}_tls_version" {{
  name                = "tls_version"
  resource_group_name = "RESOURCE_GROUP"
  server_name         = azurerm_mysql_flexible_server.{_safe(server)}.name
  value               = "TLSv1.2,TLSv1.3"
}}'''


@_tf("azure-mysql-audit-log")
def _tf_az_mysql_audit_log(f: Finding) -> str:
    server = f.details.get("server", "MYSQL_SERVER")
    return f'''\
# Enable audit logging (CIS 4.4.3)
resource "azurerm_mysql_flexible_server_configuration" "{_safe(server)}_audit" {{
  name                = "audit_log_enabled"
  resource_group_name = "RESOURCE_GROUP"
  server_name         = azurerm_mysql_flexible_server.{_safe(server)}.name
  value               = "ON"
}}'''


# ----- Cosmos DB -----


@_tf("azure-cosmos-disable-local-auth")
def _tf_az_cosmos_local_auth(f: Finding) -> str:
    name = f.details.get("account", "COSMOS_ACCOUNT")
    return f'''\
resource "azurerm_cosmosdb_account" "{_safe(name)}" {{
  name = "{name}"
  # ... existing config ...

  # Force Entra ID-only access (CIS 4.5.1)
  local_authentication_disabled = true
}}'''


@_tf("azure-cosmos-public-access")
def _tf_az_cosmos_public(f: Finding) -> str:
    name = f.details.get("account", "COSMOS_ACCOUNT")
    return f'''\
resource "azurerm_cosmosdb_account" "{_safe(name)}" {{
  name = "{name}"
  # ... existing config ...

  # Disable public network access (CIS 4.5.2)
  public_network_access_enabled = false
  is_virtual_network_filter_enabled = true
}}'''


@_tf("azure-cosmos-firewall")
def _tf_az_cosmos_firewall(f: Finding) -> str:
    name = f.details.get("account", "COSMOS_ACCOUNT")
    return f'''\
resource "azurerm_cosmosdb_account" "{_safe(name)}" {{
  name = "{name}"
  # ... existing config ...

  # Restrict network access — explicit IP / VNet rules (CIS 4.5.3)
  is_virtual_network_filter_enabled = true
  ip_range_filter                   = ["198.51.100.0/24"]  # replace with trusted CIDRs

  virtual_network_rule {{
    id                                   = "SUBNET_ID"
    ignore_missing_vnet_service_endpoint = false
  }}
}}'''


# ----- App Service -----


@_tf("azure-appservice-https-only")
def _tf_az_appsvc_https(f: Finding) -> str:
    name = f.details.get("app", "APP_SERVICE")
    return f'''\
resource "azurerm_linux_web_app" "{_safe(name)}" {{
  name = "{name}"
  # ... existing config ...

  # Enforce HTTPS-only (CIS 9.2)
  https_only = true
}}'''


@_tf("azure-appservice-min-tls")
def _tf_az_appsvc_min_tls(f: Finding) -> str:
    name = f.details.get("app", "APP_SERVICE")
    return f'''\
resource "azurerm_linux_web_app" "{_safe(name)}" {{
  name = "{name}"
  # ... existing config ...

  site_config {{
    # Enforce TLS 1.2+ (CIS 9.3)
    minimum_tls_version     = "1.2"
    scm_minimum_tls_version = "1.2"
  }}
}}'''


@_tf("azure-appservice-ftps")
def _tf_az_appsvc_ftps(f: Finding) -> str:
    name = f.details.get("app", "APP_SERVICE")
    return f'''\
resource "azurerm_linux_web_app" "{_safe(name)}" {{
  name = "{name}"
  # ... existing config ...

  site_config {{
    # Block plain FTP (CIS 9.10)
    ftps_state = "Disabled"  # or "FtpsOnly" if FTPS uploads are required
  }}
}}'''


@_tf("azure-appservice-remote-debug")
def _tf_az_appsvc_remote_debug(f: Finding) -> str:
    name = f.details.get("app", "APP_SERVICE")
    return f'''\
resource "azurerm_linux_web_app" "{_safe(name)}" {{
  name = "{name}"
  # ... existing config ...

  site_config {{
    # Disable remote debugging in production (CIS 9.5)
    remote_debugging_enabled = false
  }}
}}'''


@_tf("azure-appservice-managed-identity")
def _tf_az_appsvc_msi(f: Finding) -> str:
    name = f.details.get("app", "APP_SERVICE")
    return f'''\
resource "azurerm_linux_web_app" "{_safe(name)}" {{
  name = "{name}"
  # ... existing config ...

  # Use managed identity instead of stored credentials (CIS 9.11)
  identity {{
    type = "SystemAssigned"
  }}
}}

# Then grant the identity access to the resources it needs:
resource "azurerm_role_assignment" "{_safe(name)}_kv_access" {{
  scope                = "KEY_VAULT_ID"
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_linux_web_app.{_safe(name)}.identity[0].principal_id
}}'''


# ----- Recovery Services Vault -----


@_tf("azure-rsv-soft-delete")
def _tf_az_rsv_soft_delete(f: Finding) -> str:
    name = f.details.get("vault", "RSV")
    return f'''\
resource "azurerm_recovery_services_vault" "{_safe(name)}" {{
  name = "{name}"
  # ... existing config ...

  # Enable irreversible soft delete (MCSB BR-2)
  soft_delete_enabled = true
}}'''


@_tf("azure-rsv-immutability")
def _tf_az_rsv_immutability(f: Finding) -> str:
    name = f.details.get("vault", "RSV")
    return f'''\
resource "azurerm_recovery_services_vault" "{_safe(name)}" {{
  name = "{name}"
  # ... existing config ...

  # Enable immutability and lock it (MCSB BR-2.3)
  immutability = "Locked"  # WARNING: irreversible once Locked
}}'''


@_tf("azure-rsv-redundancy")
def _tf_az_rsv_redundancy(f: Finding) -> str:
    name = f.details.get("vault", "RSV")
    return f'''\
resource "azurerm_recovery_services_vault" "{_safe(name)}" {{
  name = "{name}"
  # ... existing config ...

  # Geo-redundant storage (MCSB BR-2)
  storage_mode_type            = "GeoRedundant"
  cross_region_restore_enabled = true
}}'''


# ----- Networking / Monitoring -----


@_tf("azure-vnet-flow-logs-modern")
def _tf_az_vnet_flow_logs(f: Finding) -> str:
    return '''\
# VNet flow logs — successor to NSG flow logs (CIS 6.4)
resource "azurerm_network_watcher_flow_log" "vnet_flow" {
  network_watcher_name = "NetworkWatcher_LOCATION"
  resource_group_name  = "NetworkWatcherRG"
  name                 = "vnet-flow-log"

  target_resource_id = azurerm_virtual_network.main.id
  storage_account_id = azurerm_storage_account.flowlogs.id
  enabled            = true

  retention_policy {
    enabled = true
    days    = 90
  }

  traffic_analytics {
    enabled               = true
    workspace_id          = azurerm_log_analytics_workspace.main.workspace_id
    workspace_region      = azurerm_log_analytics_workspace.main.location
    workspace_resource_id = azurerm_log_analytics_workspace.main.id
    interval_in_minutes   = 10
  }
}'''


@_tf("azure-network-watcher-coverage")
def _tf_az_network_watcher(f: Finding) -> str:
    missing = f.details.get("missing_regions", ["LOCATION"])
    blocks = []
    for r in missing[:5]:
        safe = _safe(r)
        blocks.append(
            f'''resource "azurerm_network_watcher" "{safe}" {{
  name                = "NetworkWatcher_{r}"
  location            = "{r}"
  resource_group_name = "NetworkWatcherRG"
}}'''
        )
    return "\n\n".join(blocks)


@_tf("azure-defender-per-plan")
def _tf_az_defender_per_plan(f: Finding) -> str:
    disabled = f.details.get("disabled", [])
    plans = [d.get("plan") if isinstance(d, dict) else d for d in disabled[:8]]
    if not plans:
        plans = ["VirtualMachines", "StorageAccounts", "KeyVaults", "Containers", "Arm"]
    blocks = []
    for plan in plans:
        blocks.append(
            f'''resource "azurerm_security_center_subscription_pricing" "{_safe(plan).lower()}" {{
  tier          = "Standard"
  resource_type = "{plan}"
}}'''
        )
    return "\n\n".join(blocks)


@_tf("azure-activity-log-alerts")
def _tf_az_activity_alerts(f: Finding) -> str:
    return '''\
# CIS 5.2.x — alert on critical control-plane changes
locals {
  critical_operations = [
    "Microsoft.Network/networkSecurityGroups/write",
    "Microsoft.Network/networkSecurityGroups/delete",
    "Microsoft.Network/networkSecurityGroups/securityRules/write",
    "Microsoft.Network/networkSecurityGroups/securityRules/delete",
    "Microsoft.Sql/servers/firewallRules/write",
    "Microsoft.Authorization/policyAssignments/write",
    "Microsoft.Authorization/policyAssignments/delete",
    "Microsoft.KeyVault/vaults/write",
    "Microsoft.KeyVault/vaults/delete",
  ]
}

resource "azurerm_monitor_action_group" "secops" {
  name                = "secops-page"
  resource_group_name = "monitoring"
  short_name          = "secops"

  email_receiver {
    name          = "secops"
    email_address = "secops@example.com"
  }
}

resource "azurerm_monitor_activity_log_alert" "critical_changes" {
  for_each            = toset(local.critical_operations)
  name                = "alert-${replace(each.key, "/", "-")}"
  resource_group_name = "monitoring"
  scopes              = [data.azurerm_subscription.current.id]
  description         = "CIS 5.2.x — control-plane change alert"

  criteria {
    category       = "Administrative"
    operation_name = each.key
  }

  action {
    action_group_id = azurerm_monitor_action_group.secops.id
  }
}'''


# ----- Governance -----


@_tf("azure-resource-locks")
def _tf_az_resource_locks(f: Finding) -> str:
    rg = f.details.get("resource_group", "RESOURCE_GROUP")
    return f'''\
resource "azurerm_management_lock" "{_safe(rg)}_protect" {{
  name       = "protect-{rg}"
  scope      = "/subscriptions/SUBSCRIPTION_ID/resourceGroups/{rg}"
  lock_level = "CanNotDelete"
  notes      = "Protects sensitive resources (Key Vault / RSV / Log Analytics) from accidental deletion."
}}'''


@_tf("azure-required-tags")
def _tf_az_required_tags(f: Finding) -> str:
    return '''\
# Built-in policy: 'Require a tag and its value on resource groups'
data "azurerm_policy_definition" "require_tag" {
  display_name = "Require a tag and its value on resource groups"
}

resource "azurerm_subscription_policy_assignment" "require_owner_tag" {
  name                 = "require-owner-tag"
  subscription_id      = data.azurerm_subscription.current.id
  policy_definition_id = data.azurerm_policy_definition.require_tag.id

  parameters = jsonencode({
    tagName  = { value = "owner" }
    tagValue = { value = "REQUIRED_VALUE" }
  })
}

resource "azurerm_subscription_policy_assignment" "require_env_tag" {
  name                 = "require-environment-tag"
  subscription_id      = data.azurerm_subscription.current.id
  policy_definition_id = data.azurerm_policy_definition.require_tag.id

  parameters = jsonencode({
    tagName  = { value = "environment" }
    tagValue = { value = "production" }
  })
}'''


@_tf("azure-security-initiative")
def _tf_az_security_initiative(f: Finding) -> str:
    return '''\
# Assign the Microsoft Cloud Security Benchmark initiative (CIS 2.x)
data "azurerm_policy_set_definition" "mcsb" {
  display_name = "Microsoft cloud security benchmark"
}

resource "azurerm_subscription_policy_assignment" "mcsb" {
  name                 = "mcsb-baseline"
  subscription_id      = data.azurerm_subscription.current.id
  policy_definition_id = data.azurerm_policy_set_definition.mcsb.id
  display_name         = "Microsoft Cloud Security Benchmark"
  description          = "Continuous compliance against the MCSB."
}'''


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
    # ----- CIS AWS v3.0 Stage 1-3 explanations -----
    "cloudtrail-kms-encryption": {
        "explanation": "CloudTrail logs are stored in S3 with default SSE-S3 encryption. Adding a customer-managed KMS key gives you key-level audit (every decrypt is logged), independent rotation, and the ability to revoke access without touching the bucket itself.",
        "steps": [
            "Create a KMS key with a policy allowing cloudtrail.amazonaws.com to encrypt",
            "Update the trail with --kms-key-id <key-arn>",
            "Verify CloudTrail can still write log files",
        ],
        "effort": "moderate",
    },
    "cloudtrail-log-validation": {
        "explanation": "Without log file validation, an attacker who gains write access to the log bucket can modify or delete CloudTrail logs without detection. Log validation creates a hash chain of digest files signed by AWS — tampering breaks the chain in a way that's verifiable.",
        "steps": [
            "aws cloudtrail update-trail --name <name> --enable-log-file-validation",
            "Use `aws cloudtrail validate-logs` periodically to verify the hash chain",
        ],
        "effort": "quick",
    },
    "cloudtrail-s3-object-lock": {
        "explanation": "Object Lock with COMPLIANCE mode prevents anyone — including the root user — from deleting CloudTrail log objects before retention expires. It's the only AWS-side control that defeats a malicious admin or compromised root credential trying to wipe audit evidence.",
        "steps": [
            "Object Lock can only be enabled at bucket creation",
            "Create a new bucket with object_lock_enabled + versioning",
            "Migrate logs and update the trail to point at the new bucket",
        ],
        "effort": "significant",
    },
    "security-hub-enabled": {
        "explanation": "Security Hub aggregates findings from GuardDuty, Inspector, Macie, Access Analyzer, Config, and the AWS Foundational + CIS standards into one console. Without it, security findings are scattered across per-service consoles with no unified prioritization or auto-remediation hook.",
        "steps": [
            "Enable Security Hub in your primary operating region",
            "Subscribe to AWS Foundational Security Best Practices and CIS AWS Foundations Benchmark v3.0.0",
            "Configure SNS or EventBridge for high-severity findings",
        ],
        "effort": "moderate",
    },
    "iam-access-analyzer": {
        "explanation": "IAM Access Analyzer continuously monitors IAM resource policies (S3 buckets, KMS keys, IAM roles, Lambda, Secrets Manager) for unintended external access. It catches S3 buckets shared publicly, KMS keys assumable cross-account, and roles trusting unknown principals.",
        "steps": [
            "aws accessanalyzer create-analyzer --analyzer-name default --type ACCOUNT",
            "Or use --type ORGANIZATION from the management account for org-wide coverage",
            "Review findings in the IAM > Access analyzer console",
        ],
        "effort": "quick",
    },
    "efs-encryption": {
        "explanation": "EFS encryption can only be enabled at creation. An unencrypted EFS file system stores data in clear on AWS disks — which means a snapshot leak, account compromise, or misconfigured backup gives an attacker the raw bytes.",
        "steps": [
            "Create a new encrypted EFS file system",
            "Use AWS DataSync or a temporary EC2 instance with rsync to copy data",
            "Cut over consumers (Lambda, ECS, EC2) and delete the old file system",
        ],
        "effort": "significant",
    },
    "sns-encryption": {
        "explanation": "SNS messages may carry sensitive payloads (alerts, notifications, webhook payloads). Without KMS encryption, the message body sits in unencrypted SNS storage between publish and delivery.",
        "steps": [
            "aws sns set-topic-attributes --topic-arn <arn> --attribute-name KmsMasterKeyId --attribute-value alias/aws/sns",
        ],
        "effort": "quick",
    },
    "sqs-encryption": {
        "explanation": "SQS messages sit in queue storage between enqueue and consume. Without encryption, that storage is unencrypted disk on AWS infrastructure. SqsManagedSseEnabled adds encryption with no KMS cost.",
        "steps": [
            "aws sqs set-queue-attributes --queue-url <url> --attributes SqsManagedSseEnabled=true",
        ],
        "effort": "quick",
    },
    "secrets-manager-rotation": {
        "explanation": "Secrets without automatic rotation accumulate risk — credentials cycle outside any policy, stale secrets persist after staff turnover, and a leaked secret stays valid until someone notices. Lambda-backed rotation lets you set a 30-90 day schedule.",
        "steps": [
            "Pick or write a Lambda rotation function (AWS provides templates for RDS, Redshift, DocumentDB)",
            "Attach it to each secret with a 30-day rotation schedule",
            "Monitor CloudWatch alarms for rotation failures",
        ],
        "effort": "moderate",
    },
    "acm-expiring-certs": {
        "explanation": "Expired certificates break TLS for whatever they're attached to (CloudFront, ALB, API Gateway). DNS-validated public certs in ACM auto-renew ~60 days before expiry; imported and email-validated certs do not.",
        "steps": [
            "Switch any email-validated certs to DNS validation",
            "For imported certs, replace them or migrate to ACM-issued",
            "Set up CloudWatch alarms on AWS/CertificateManager > DaysToExpiry < 30",
        ],
        "effort": "moderate",
    },
    "elb-listener-tls": {
        "explanation": "HTTP listeners send credentials and session cookies in clear text. ELBSecurityPolicy-TLS-1-0/1.1 allows protocols vulnerable to BEAST/POODLE. Modern policies pin TLS 1.2+ with strong ciphers only.",
        "steps": [
            "Add HTTPS listeners with ELBSecurityPolicy-TLS13-1-2-2021-06",
            "Convert HTTP listeners to redirect-to-HTTPS",
        ],
        "effort": "quick",
    },
    "elb-access-logs": {
        "explanation": "Without access logs, you can't reconstruct request patterns during an incident — no source IPs, no paths, no user agents. SOC 2 expects request-level audit trail for production HTTP services.",
        "steps": [
            "Create an S3 bucket with the AWS-managed bucket policy for ELB log delivery",
            "Enable access_logs.s3.enabled and point at the bucket",
        ],
        "effort": "quick",
    },
    "elb-drop-invalid-headers": {
        "explanation": "Headers with invalid characters can be used for HTTP request smuggling and header-injection attacks against the backend. ALB has a one-flag fix to drop them at the edge.",
        "steps": [
            "Set routing.http.drop_invalid_header_fields.enabled = true on the ALB attributes",
        ],
        "effort": "quick",
    },
    "rds-iam-auth": {
        "explanation": "Static DB passwords need rotation, vaulting, and access reviews. IAM database authentication uses short-lived tokens tied to an IAM identity that's already governed by your IAM controls — no password to leak.",
        "steps": [
            "Enable iam_database_authentication on the instance",
            "Create a DB user mapped to an IAM role",
            "Update apps to call rds.generate-db-auth-token instead of passing a password",
        ],
        "effort": "moderate",
    },
    "rds-deletion-protection": {
        "explanation": "DeletionProtection prevents accidental DELETE — a misclick, a careless terraform destroy, or a compromised admin can otherwise wipe the database in seconds. Final snapshots help but add recovery time.",
        "steps": [
            "aws rds modify-db-instance --db-instance-identifier <id> --deletion-protection --apply-immediately",
        ],
        "effort": "quick",
    },
    "rds-pi-kms": {
        "explanation": "Performance Insights captures query text including bind values. If queries contain PII or credentials (which they often do), PI data needs the same protection as the underlying database.",
        "steps": [
            "Create a CMK for PI",
            "aws rds modify-db-instance --performance-insights-kms-key-id <key-arn>",
        ],
        "effort": "quick",
    },
    "rds-auto-minor-upgrade": {
        "explanation": "Without auto minor upgrades, the instance won't receive security patches without a manual operation — and CVEs in DB engines are common. Auto upgrades happen during the maintenance window with zero data risk.",
        "steps": [
            "aws rds modify-db-instance --db-instance-identifier <id> --auto-minor-version-upgrade --apply-immediately",
        ],
        "effort": "quick",
    },
    "dynamodb-pitr": {
        "explanation": "Point-in-Time Recovery lets you restore a DynamoDB table to any second within the last 35 days. Without it, accidental deletes/overwrites are unrecoverable — and there's no CLI command for 'undo'.",
        "steps": [
            "aws dynamodb update-continuous-backups --table-name <name> --point-in-time-recovery-specification PointInTimeRecoveryEnabled=true",
        ],
        "effort": "quick",
    },
    "dynamodb-kms": {
        "explanation": "DynamoDB tables are encrypted by default with an AWS-owned key — you can't audit decrypt calls and you can't revoke access independently. A customer-managed KMS key gives you key-level audit and rotation.",
        "steps": [
            "Create a CMK with rotation enabled",
            "aws dynamodb update-table --table-name <name> --sse-specification Enabled=true,SSEType=KMS,KMSMasterKeyId=<key-arn>",
        ],
        "effort": "quick",
    },
    "lambda-runtime-eol": {
        "explanation": "Functions on deprecated Lambda runtimes stop receiving security patches. AWS eventually blocks invocations after the deprecation deadline — so a function on python3.8 won't just be insecure, it'll stop running.",
        "steps": [
            "Identify each function on a deprecated runtime",
            "Bump to a current runtime (python3.12, nodejs20.x, java21, dotnet8)",
            "Test for breaking changes in dependencies, then redeploy",
        ],
        "effort": "moderate",
    },
    "lambda-env-kms": {
        "explanation": "Lambda environment variables are encrypted by default with the Lambda service key. A customer-managed KMS key gives you key-level audit and the ability to rotate the encryption key independently.",
        "steps": [
            "Create a CMK",
            "aws lambda update-function-configuration --function-name <name> --kms-key-arn <key-arn>",
        ],
        "effort": "quick",
    },
    "lambda-dlq": {
        "explanation": "Async Lambda invocation failures are silently retried then dropped. With no DLQ or destination, you lose the failed payload entirely — no debugging trail, no replay capability.",
        "steps": [
            "Create an SQS queue or SNS topic to act as the DLQ",
            "Attach via DeadLetterConfig.TargetArn or use Lambda Destinations for richer routing",
        ],
        "effort": "quick",
    },
    "lambda-code-signing": {
        "explanation": "Code signing prevents an attacker who compromises a CI pipeline from deploying tampered code — only artifacts signed by an approved Signer profile will deploy. It's the supply-chain control AWS-native equivalent of cosign.",
        "steps": [
            "Create an AWS Signer profile",
            "Define a code signing config that requires signed deployments",
            "Attach the config to each function via PutFunctionCodeSigningConfig",
        ],
        "effort": "moderate",
    },
    "apigw-logging": {
        "explanation": "Without execution logging, you cannot trace API request failures or correlate them with backend incidents. INFO level captures request/response metadata; ERROR level captures only failures.",
        "steps": [
            "Enable Execution logging at INFO level on each stage",
            "Enable Detailed CloudWatch metrics for the stage",
        ],
        "effort": "quick",
    },
    "apigw-waf": {
        "explanation": "API stages without WAF are exposed to OWASP Top 10, bot abuse, and credential stuffing. Even with auth, you need WAF for rate limiting and known-bad-input filtering.",
        "steps": [
            "Create a WAFv2 Web ACL with the AWS Managed Rules Common Rule Set",
            "Add the AWS Managed Rules Bot Control rule group",
            "wafv2:AssociateWebACL with each public API Gateway stage",
        ],
        "effort": "moderate",
    },
    "sfn-logging": {
        "explanation": "Step Functions logging level OFF means execution history is only available via the StartExecution API and is lost after a few weeks. ALL level + includeExecutionData captures every state transition for incident investigation.",
        "steps": [
            "Create a CloudWatch Log Group for Step Functions",
            "Update each state machine with logging configuration level=ALL",
        ],
        "effort": "quick",
    },
    "aws-backup-vault-lock": {
        "explanation": "Without Vault Lock in COMPLIANCE mode, an attacker (or compromised admin) with backup:DeleteRecoveryPoint can wipe every backup in the vault — defeating your entire DR plan. Vault Lock COMPLIANCE makes recovery points immutable until retention expires, even for the root user.",
        "steps": [
            "aws backup put-backup-vault-lock-configuration with --changeable-for-days 3 (after 3 days the lock is irreversible)",
            "Test that recovery points cannot be deleted before retention expires",
        ],
        "effort": "moderate",
    },
    "aws-backup-plans": {
        "explanation": "Backup vaults exist but no Backup plan schedules recovery points — meaning nothing is being backed up automatically. The vault is just an empty container.",
        "steps": [
            "Create a backup plan via the Backup console or CLI",
            "Use AWS-managed plans (Daily-35day, Monthly-1year) as a starting point",
            "Add a backup selection that targets resources with tag backup=true",
        ],
        "effort": "moderate",
    },
    "aws-vpc-endpoints": {
        "explanation": "Without VPC endpoints, EC2/ECS/EKS traffic to AWS services (S3, DynamoDB, KMS, Secrets Manager, ECR) traverses the public internet via NAT — adding NAT cost, latency, and exposure to internet-facing controls. Gateway endpoints (S3, DynamoDB) are free; interface endpoints are priced per AZ + per GB.",
        "steps": [
            "Create gateway endpoints for S3 and DynamoDB (free, no infra change)",
            "Create interface endpoints for KMS, Secrets Manager, SSM, ECR, Logs, STS",
            "Add SG rules allowing the VPC CIDR to reach the interface endpoint ENIs",
        ],
        "effort": "moderate",
    },
    "cwl-kms-encryption": {
        "explanation": "Application logs frequently contain credentials, PII, or session tokens. Log groups encrypted with the AWS-owned default key give you no key-level audit and no way to revoke decrypt access independently.",
        "steps": [
            "Create a KMS key with a policy allowing logs.<region>.amazonaws.com to encrypt",
            "aws logs associate-kms-key --log-group-name <name> --kms-key-id <key-arn>",
        ],
        "effort": "quick",
    },
    "cwl-retention": {
        "explanation": "Log groups with infinite retention accumulate cost indefinitely. Log groups with retention < 90 days lose audit evidence too fast for SOC 2 — you need at least 90 days to investigate incidents reported by customers.",
        "steps": [
            "aws logs put-retention-policy --log-group-name <name> --retention-in-days 90",
            "Use 180 / 365 days for compliance-critical groups (CloudTrail, Audit, Auth)",
        ],
        "effort": "quick",
    },
    "aws-org-scps": {
        "explanation": "Service Control Policies are the only AWS-side control that can prevent member accounts from disabling CloudTrail, leaving regions, or assuming risky roles. Without custom SCPs you have no org-wide guardrails.",
        "steps": [
            "Author SCPs that deny CloudTrail disable/delete, root account use, and resource creation outside approved regions",
            "Apply at OU level (test on a sandbox OU first)",
        ],
        "effort": "moderate",
    },
    "aws-tag-policy": {
        "explanation": "Without tag policies, resources are tagged inconsistently — making cost allocation, ownership tracking, and policy-based access control unreliable.",
        "steps": [
            "Define a tag policy enforcing 'owner' and 'environment' keys at the org root",
            "Attach to OUs and configure 'enforced for' on the resource types you care about",
        ],
        "effort": "moderate",
    },
    "aws-org-enabled": {
        "explanation": "Without AWS Organizations, you can't apply SCPs, enforce centralized logging, share resources via RAM, or use Backup / Tag policies that need org-level scope. Single-account setups don't scale beyond a small team.",
        "steps": [
            "Create an Organization from a dedicated management account",
            "Invite this account into it",
            "Enable ALL features (not just consolidated billing)",
        ],
        "effort": "moderate",
    },
    "aws-delegated-admin": {
        "explanation": "Security services should be delegated to a dedicated security account so the management account stays minimal-privilege and is rarely accessed. This is the AWS-recommended landing zone pattern.",
        "steps": [
            "Create a dedicated security/audit account",
            "register-delegated-administrator for securityhub, guardduty, config, backup, access-analyzer",
        ],
        "effort": "moderate",
    },
    "aws-backup-policy": {
        "explanation": "Without an org-level Backup policy, every member account needs its own backup plan defined manually — which scales badly and creates drift. Org policies enforce a baseline across every account automatically.",
        "steps": [
            "Define a backup policy via aws organizations create-policy --type BACKUP_POLICY",
            "Attach to OUs",
        ],
        "effort": "moderate",
    },
    "aws-backup-vault-cmk": {
        "explanation": "AWS Backup vaults encrypted with the AWS-managed key give you no key-level audit and no way to revoke decrypt independently. A customer-managed KMS key with rotation closes both gaps.",
        "steps": [
            "Recreate the vault with --encryption-key-arn pointing to a customer-managed KMS key",
        ],
        "effort": "moderate",
    },
    "aws-backup-vault-exists": {
        "explanation": "Without an AWS Backup vault, you have no centralized place to manage recovery points across services. Each service's native backups (RDS snapshots, EBS snapshots, EFS recovery points) live independently with separate retention.",
        "steps": [
            "Create a Backup vault with KMS encryption",
            "Create a Backup plan",
            "Add resource selections via tags",
        ],
        "effort": "moderate",
    },
    "docdb-encryption": {
        "explanation": "DocumentDB encryption can only be enabled at cluster creation. An unencrypted cluster means data is stored in clear on AWS disks.",
        "steps": [
            "Snapshot the cluster",
            "Restore the snapshot with --storage-encrypted",
            "Cut over and delete the old cluster",
        ],
        "effort": "significant",
    },
    "docdb-audit-logs": {
        "explanation": "DocumentDB audit logs capture authentication, DDL, and DML events. Without audit log export, anomalous queries leave no trace.",
        "steps": [
            "aws docdb modify-db-cluster --cloudwatch-logs-export-configuration EnableLogTypes=audit",
        ],
        "effort": "quick",
    },
    # ----- AWS parity sweep Stage 1: compute / KMS / IAM / CloudWatch -----
    "ec2-imdsv2-enforced": {
        "explanation": "IMDSv1 lets any process on an EC2 instance make a simple GET request to 169.254.169.254 and read the IAM role credentials. The Capital One 2019 breach used a server-side request forgery on a web app to do exactly this. IMDSv2 requires a session token via PUT, which SSRF cannot trivially perform.",
        "steps": [
            "Set the account-level default: aws ec2 modify-instance-metadata-defaults --http-tokens required --http-endpoint enabled --http-put-response-hop-limit 1",
            "For each existing instance: aws ec2 modify-instance-metadata-options --instance-id <id> --http-tokens required --http-endpoint enabled --http-put-response-hop-limit 1",
            "Verify apps still work — most modern AWS SDKs use IMDSv2 by default since 2019",
        ],
        "effort": "moderate",
    },
    "ec2-public-ips": {
        "explanation": "EC2 instances with public IPv4 addresses are directly reachable from the internet. Each one is a potential attack surface — verify each is intentional (bastion, NAT, customer-facing app) and not drift from a private-subnet design.",
        "steps": [
            "Inventory the instances and decide which need public IPs",
            "For instances that don't, move them behind a load balancer or NAT gateway",
            "For instances that do, lock down the security group to specific source CIDRs and ports",
        ],
        "effort": "moderate",
    },
    "ec2-instance-profile": {
        "explanation": "Without an instance profile, the only way an app on the instance can call AWS APIs is via long-lived access keys baked into the AMI or fetched from a config file — both anti-patterns. Instance profiles use short-lived credentials managed by IAM.",
        "steps": [
            "Create a least-privilege IAM role for the workload",
            "Wrap it in an instance profile",
            "aws ec2 associate-iam-instance-profile --instance-id <id> --iam-instance-profile Name=<profile>",
        ],
        "effort": "quick",
    },
    "ec2-ami-age": {
        "explanation": "Stale AMIs accumulate unpatched CVEs. Each instance running a stale AMI is shipping a snapshot of the security state from the day the AMI was baked. Modern patterns rebuild the AMI on a regular cadence and roll instances.",
        "steps": [
            "Set up an EC2 Image Builder pipeline that rebuilds the base AMI weekly or biweekly",
            "Configure Auto Scaling Groups to use the latest AMI version",
            "Trigger an instance refresh after each AMI rebuild",
        ],
        "effort": "significant",
    },
    "eks-private-endpoint": {
        "explanation": "A public EKS API endpoint is reachable from anywhere on the internet. Even with IAM/OIDC auth, it's a brute-force / credential-spray surface. Private cluster + bastion is the recommended pattern; if public access is required, restrict to known CIDRs.",
        "steps": [
            "aws eks update-cluster-config --name <cluster> --resources-vpc-config endpointPublicAccess=false,endpointPrivateAccess=true",
            "Set up a bastion host or VPN to reach the private endpoint",
            "Update kubeconfig to use the private endpoint URL",
        ],
        "effort": "moderate",
    },
    "eks-audit-logging": {
        "explanation": "Without EKS audit + authenticator logs, you cannot reconstruct who issued kubectl commands during a security incident. EKS lets you enable api / audit / authenticator / controllerManager / scheduler — all five are recommended for SOC 2.",
        "steps": [
            "aws eks update-cluster-config --name <cluster> --logging '{\"clusterLogging\":[{\"types\":[\"api\",\"audit\",\"authenticator\",\"controllerManager\",\"scheduler\"],\"enabled\":true}]}'",
            "Set retention on the /aws/eks/<cluster>/cluster log group to 90+ days",
        ],
        "effort": "quick",
    },
    "eks-secrets-encryption": {
        "explanation": "By default, Kubernetes secrets are stored base64-encoded (not encrypted) in etcd. A stolen etcd backup or compromised control plane node exposes every secret in the cluster. EKS supports envelope encryption with a customer-managed KMS key.",
        "steps": [
            "Create a customer-managed KMS key",
            "aws eks associate-encryption-config --cluster-name <name> --encryption-config resources=secrets,provider={keyArn=<arn>}",
            "Verify by creating a test secret and inspecting via etcdctl (in a lab cluster)",
        ],
        "effort": "moderate",
    },
    "ecs-task-privileged": {
        "explanation": "Privileged containers can mount host filesystems, load kernel modules, and escape the container boundary. They should only be used for very specific systems-level workloads (e.g. node-exporter, network plugins), never for application code.",
        "steps": [
            "Remove privileged=true from the container definition",
            "If a system-level capability is genuinely required, grant it specifically via linuxParameters.capabilities.add",
        ],
        "effort": "quick",
    },
    "ecs-task-root-user": {
        "explanation": "Containers running as root that get exploited give the attacker root inside the container — which, combined with any kernel CVE or container escape bug, can compromise the host. Containerized apps almost never need root.",
        "steps": [
            "In the Dockerfile add `USER 1000` (or your non-root uid)",
            "In the task definition set 'user': '1000' on the container",
            "Verify the app can write to whatever directories it needs (often /tmp)",
        ],
        "effort": "moderate",
    },
    "kms-key-rotation": {
        "explanation": "Without rotation, the same key material protects data forever. NIST SP 800-57 recommends annual rotation for symmetric keys protecting bulk data. AWS KMS auto-rotation is one boolean — there's no excuse to leave it off.",
        "steps": [
            "For each customer-managed CMK: aws kms enable-key-rotation --key-id <key-id>",
            "Asymmetric and HMAC keys don't support rotation; that's expected",
        ],
        "effort": "quick",
    },
    "kms-key-policy-wildcards": {
        "explanation": "A wildcard principal + wildcard action on a KMS key is the encryption-key equivalent of a public S3 bucket: anyone in any AWS account can encrypt, decrypt, schedule deletion, or take ownership of the key. And unlike S3 Public Access Block, there's no account-wide guardrail that prevents it.",
        "steps": [
            "Rewrite the key policy to scope Principal to specific account or role ARNs",
            "If cross-account access is required, use a specific account principal plus a Condition narrowing the source",
            "aws kms put-key-policy --key-id <id> --policy file://policy.json",
        ],
        "effort": "moderate",
    },
    "kms-scheduled-deletion": {
        "explanation": "A key in PendingDeletion will be permanently destroyed in 7-30 days, making any data encrypted with it permanently unrecoverable. This often indicates either a mistake (cancel deletion) or a malicious action (alert SecOps and review CloudTrail).",
        "steps": [
            "If the deletion is a mistake: aws kms cancel-key-deletion --key-id <id>; aws kms enable-key --key-id <id>",
            "If unauthorized: search CloudTrail for eventName=ScheduleKeyDeletion and identify the principal",
            "Add an SCP denying kms:ScheduleKeyDeletion except via a break-glass role",
        ],
        "effort": "quick",
    },
    "kms-no-unrestricted-principal": {
        "explanation": "Cross-account KMS access is legitimate but should always carry a SourceArn / SourceAccount condition. Without it, if the foreign account is ever compromised, the attacker inherits full use of the key.",
        "steps": [
            "Add a Condition block to each cross-account grant",
            "Use aws:SourceAccount, aws:PrincipalArn, or kms:CallerAccount to narrow the access",
        ],
        "effort": "moderate",
    },
    "iam-policy-wildcards": {
        "explanation": "A customer-managed policy that allows Action='*' on Resource='*' is functionally equivalent to AdministratorAccess but bypasses access reviews that filter on the well-known admin policy name. Auditors and access reviewers won't see it as 'admin' even though it is.",
        "steps": [
            "For each policy: review where it's attached, generate a scoped replacement from CloudTrail data via IAM Access Analyzer policy generation",
            "Detach the wildcard policy",
            "If the role genuinely needs full admin, use the built-in AdministratorAccess policy so access reviews can spot it",
        ],
        "effort": "moderate",
    },
    "iam-role-trust-external": {
        "explanation": "The 'confused deputy' attack: a third-party SaaS holds an IAM role that can assume your role. If the SaaS is compromised, the attacker can pivot into your account. The fix is to require an ExternalId condition that the SaaS must include in their AssumeRole call.",
        "steps": [
            "Generate a random ExternalId (UUID is fine)",
            "Share it with the third party out-of-band",
            "Update the trust policy with Condition.StringEquals.sts:ExternalId",
            "The third party must then include ExternalId in every AssumeRole call",
        ],
        "effort": "quick",
    },
    "iam-unused-roles": {
        "explanation": "Stale roles accumulate permissions, become forgotten attack surface, and complicate access reviews. The right lifecycle is: create role → use it → if it stops being used, delete it.",
        "steps": [
            "For each stale role, search CloudTrail for AssumeRole events to confirm it's truly unused",
            "Detach all attached policies",
            "aws iam delete-role --role-name <name>",
        ],
        "effort": "moderate",
    },
    "cloudwatch-alarms-cis-4": {
        "explanation": "CIS AWS 4.1-4.15 require real-time alerts on critical control-plane changes — root account use, IAM policy changes, CloudTrail config changes, KMS scheduled deletion, security group changes. Without these, security-relevant changes happen silently and only show up in retrospective audits.",
        "steps": [
            "Create an SNS topic with an email or PagerDuty subscriber",
            "For each CIS 4.x event: create a metric filter on the CloudTrail log group with the prescribed pattern",
            "For each metric filter: create a CloudWatch alarm with Period=300, Threshold=1, EvaluationPeriods=1, AlarmActions=[SNS topic]",
            "Test by triggering one of the events in a sandbox account",
        ],
        "effort": "significant",
    },
    "aws-config-conformance-packs": {
        "explanation": "Conformance packs bundle AWS Config rules into framework-aligned sets (CIS AWS Foundations, AWS FSBP, NIST 800-53, PCI DSS, HIPAA). Without one, you have no continuous compliance score against any external benchmark — just a list of unmapped rules.",
        "steps": [
            "Config console > Conformance packs > Deploy conformance pack",
            "Choose 'Use sample template' and select 'Operational Best Practices for CIS AWS v3.0'",
            "Review the compliance score in Config > Aggregators after the rules evaluate",
        ],
        "effort": "quick",
    },
    # ----- AWS Stage 2 of parity sweep -----
    "cloudfront-https-only": {
        "explanation": "A CloudFront cache behavior with ViewerProtocolPolicy=allow-all accepts plain HTTP requests, exposing credentials, session cookies, and request bodies in transit. Even one weak behavior on a distribution defeats every other behavior's TLS posture for matching paths.",
        "steps": [
            "For each weak cache behavior, set ViewerProtocolPolicy = redirect-to-https",
            "Verify clients can handle the 301 redirect (some legacy SDKs do not)",
        ],
        "effort": "quick",
    },
    "cloudfront-min-tls": {
        "explanation": "CloudFront's MinimumProtocolVersion pins the TLS version + cipher suite. Anything below TLSv1.2_2021 allows legacy ciphers vulnerable to BEAST/POODLE-class attacks. The default *.cloudfront.net certificate uses TLSv1, which is below the modern bar — production workloads should attach a custom ACM cert.",
        "steps": [
            "Attach a custom ACM certificate (must be in us-east-1 for CloudFront)",
            "Update the distribution viewer-certificate to MinimumProtocolVersion=TLSv1.2_2021",
        ],
        "effort": "moderate",
    },
    "cloudfront-waf": {
        "explanation": "Public-facing CloudFront edges without WAF are exposed to OWASP Top 10, bot scraping, and credential stuffing. Even with origin authentication, you need WAF for edge-level rate limiting and known-bad-input filtering.",
        "steps": [
            "Create a WAFv2 Web ACL with scope=CLOUDFRONT (must be in us-east-1)",
            "Attach AWS Managed Rules Common Rule Set + Bot Control",
            "Associate the Web ACL with the distribution",
        ],
        "effort": "moderate",
    },
    "cloudfront-geo-restrictions": {
        "explanation": "CloudFront geo restrictions allow or deny by country at the edge. They are appropriate for sanctions enforcement, data residency compliance, and content licensing. They do not replace authorization but add a defense-in-depth layer.",
        "steps": [
            "Identify whether your service has geo-restriction requirements (sanctions, data residency)",
            "If yes, configure restriction_type = whitelist/blacklist with the appropriate locations",
        ],
        "effort": "quick",
    },
    "cloudfront-oac": {
        "explanation": "Without Origin Access Control (or the legacy OAI), the S3 bucket backing a CloudFront distribution must be publicly readable so CloudFront can fetch objects. This means anyone can bypass CloudFront entirely and hit the bucket directly, defeating WAF, signed URLs, and any other edge controls.",
        "steps": [
            "Create an OAC with signing_behavior=always, signing_protocol=sigv4",
            "Attach to the distribution origin",
            "Update the S3 bucket policy to allow only the cloudfront.amazonaws.com service principal with aws:SourceArn condition",
        ],
        "effort": "moderate",
    },
    "redshift-encryption": {
        "explanation": "Redshift cluster storage is unencrypted by default. Cluster encryption can be enabled after creation but the migration is non-trivial — AWS performs a background snapshot + restore which can take hours for large clusters.",
        "steps": [
            "Schedule a maintenance window",
            "aws redshift modify-cluster --cluster-identifier <id> --encrypted --kms-key-id <key-arn>",
            "Cluster will be unavailable during the encryption operation",
        ],
        "effort": "significant",
    },
    "redshift-public-access": {
        "explanation": "A publicly accessible Redshift cluster has an internet-routable endpoint. Even with strong authentication, this is a credential-spray surface and a common audit finding.",
        "steps": [
            "aws redshift modify-cluster --cluster-identifier <id> --no-publicly-accessible",
            "Provide alternative access via VPN, AWS Client VPN, or a bastion host in the same VPC",
        ],
        "effort": "moderate",
    },
    "redshift-audit-logging": {
        "explanation": "Without Redshift audit logging (connection log, user activity log, user log), you cannot reconstruct who ran which queries during an incident. SOC 2 expects this audit trail for any database holding regulated data.",
        "steps": [
            "Create an S3 bucket for audit logs",
            "aws redshift enable-logging --cluster-identifier <id> --bucket-name <bucket> --s3-key-prefix redshift-audit/",
        ],
        "effort": "quick",
    },
    "redshift-require-ssl": {
        "explanation": "Without require_ssl=true in the Redshift parameter group, clients can connect over plaintext, exposing credentials and queries on the wire.",
        "steps": [
            "aws redshift modify-cluster-parameter-group --parameter-group-name <pg> --parameters ParameterName=require_ssl,ParameterValue=true,ApplyType=dynamic",
            "Reboot the cluster if required",
        ],
        "effort": "quick",
    },
    "elasticache-transit-encryption": {
        "explanation": "ElastiCache Redis traffic between clients and the cluster is in plaintext by default. Cached session data, API tokens, and PII traversing the cache are exposed to anyone on the network path.",
        "steps": [
            "Transit encryption can only be enabled at replication group creation",
            "Create a new replication group with transit_encryption_enabled=true",
            "Migrate data via online migration or application-level dual-write, then cut over",
        ],
        "effort": "significant",
    },
    "elasticache-at-rest-encryption": {
        "explanation": "ElastiCache snapshots and node-level disk storage are unencrypted by default. At-rest encryption can only be enabled at replication group creation.",
        "steps": [
            "Recreate the replication group with at_rest_encryption_enabled=true and a customer-managed KMS key",
            "Migrate data and cut over",
        ],
        "effort": "significant",
    },
    "elasticache-auth-token": {
        "explanation": "Without an AUTH token, anyone in the same VPC subnet can connect to Redis without credentials. The AUTH token adds a password layer on top of TLS — Redis's equivalent of a database password.",
        "steps": [
            "Generate a strong random token and store in Secrets Manager",
            "aws elasticache modify-replication-group --auth-token <token> --auth-token-update-strategy ROTATE",
            "Update applications to read the token from Secrets Manager",
        ],
        "effort": "moderate",
    },
    "neptune-encryption": {
        "explanation": "Neptune cluster storage is unencrypted by default. Encryption can only be enabled at cluster creation; existing unencrypted clusters require a snapshot, encrypted-restore, and cutover.",
        "steps": [
            "Snapshot the cluster",
            "Restore the snapshot with --storage-encrypted --kms-key-id <key>",
            "Cut over and delete the old cluster",
        ],
        "effort": "significant",
    },
    "rds-force-ssl": {
        "explanation": "Without rds.force_ssl=1 (PostgreSQL/SQL Server) or require_secure_transport=ON (MySQL/MariaDB), SSL is offered but clients can downgrade to plaintext. This is the parameter-group equivalent of Azure's secure_transport setting on PostgreSQL/MySQL Flexible Server.",
        "steps": [
            "Modify the DB parameter group to set the SSL parameter",
            "Reboot the instance for the parameter to take effect",
            "Verify clients use ssl=require / sslmode=require in connection strings",
        ],
        "effort": "moderate",
    },
    "rds-postgres-log-settings": {
        "explanation": "Without log_connections, log_disconnections, and log_checkpoints turned on in the PostgreSQL parameter group, brute-force authentication attempts and anomalous session patterns leave no trace in RDS logs. Mirrors Azure's check_postgresql_log_settings for PostgreSQL Flexible Server.",
        "steps": [
            "Modify the parameter group to enable each missing parameter",
            "Apply with ApplyMethod=immediate (no reboot needed for these params)",
            "Verify logs flow to CloudWatch Logs via enabled_cloudwatch_logs_exports",
        ],
        "effort": "quick",
    },
    "rds-min-tls": {
        "explanation": "SQL Server RDS allows TLS 1.0/1.1 unless rds.tls_version is restricted. TLS 1.0/1.1 have known cryptographic weaknesses (BEAST, POODLE) and are deprecated by every major security framework.",
        "steps": [
            "Modify the parameter group to set rds.tls_version=1.2",
            "ApplyMethod=pending-reboot (the parameter requires a restart)",
            "Schedule a maintenance window to apply",
        ],
        "effort": "moderate",
    },
    "lambda-function-url-auth": {
        "explanation": "Lambda Function URLs are a relatively new feature where Lambda gets a public HTTPS endpoint without API Gateway. They default to AuthType=NONE — meaning anyone on the internet can invoke the function and incur unbounded costs. Bot scanners find these endpoints within hours of creation. This is one of the most common new misconfigurations in AWS as of 2026.",
        "steps": [
            "aws lambda update-function-url-config --function-name <name> --auth-type AWS_IAM",
            "Update callers to sign requests with SigV4",
            "If you genuinely need an unauthenticated public endpoint, put it behind API Gateway + WAF with rate limiting, not a raw Function URL",
        ],
        "effort": "quick",
    },
    "lambda-layer-origin": {
        "explanation": "Lambda layers can be sourced from any AWS account that grants you GetLayerVersion permission. Layers from foreign accounts are a supply-chain risk: the layer publisher can ship arbitrary code that runs in your function's execution context with your function's IAM role.",
        "steps": [
            "Download each foreign layer via aws lambda get-layer-version-by-arn",
            "Re-publish in your own account via aws lambda publish-layer-version",
            "Update each function to use the in-account layer ARN",
        ],
        "effort": "moderate",
    },
    "apigw-client-cert": {
        "explanation": "Without a client certificate, the backend integration cannot verify that incoming requests originated from API Gateway. If the backend URL leaks, an attacker can call it directly and bypass any throttling, WAF, or authorizer wired into API Gateway.",
        "steps": [
            "aws apigateway generate-client-certificate",
            "Attach to each stage via aws apigateway update-stage",
            "Update the backend to verify the cert against the API Gateway public key",
        ],
        "effort": "moderate",
    },
    "apigw-authorizer": {
        "explanation": "API Gateway methods with AuthorizationType=NONE are publicly callable. This is the AWS equivalent of Azure App Service Easy Auth being disabled. If unintentional, an attacker can invoke the backend Lambda or HTTP integration without credentials.",
        "steps": [
            "Identify intentional public methods (document each in code review)",
            "For all others: aws apigateway update-method with --patch-operations to set authorizationType=AWS_IAM (or COGNITO_USER_POOLS / CUSTOM)",
        ],
        "effort": "moderate",
    },
    "apigw-throttling": {
        "explanation": "Without stage-level throttling, a single misbehaving client (or attacker) can trigger unbounded Lambda invocations, downstream DB load, and cost overruns. Account-level throttling exists as a backstop but stage-level limits are the right granularity.",
        "steps": [
            "aws apigateway update-stage with patch-operations setting throttling/burstLimit and throttling/rateLimit on the */* method path",
            "Tune the limits based on expected legitimate traffic + headroom",
        ],
        "effort": "quick",
    },
    "apigw-request-validation": {
        "explanation": "Without request validators, malformed requests are passed through to the backend Lambda — wasting compute and exposing the backend to fuzz inputs. Validators reject bad requests at the edge before they reach backend code.",
        "steps": [
            "Define request validators in the API spec (OpenAPI body schemas)",
            "Attach them to each method via patch-operations setting requestValidatorId",
        ],
        "effort": "moderate",
    },
    "s3-object-ownership": {
        "explanation": "S3 Object Ownership = BucketOwnerEnforced disables ACLs entirely. Without it, objects uploaded by other accounts can have ACLs that exclude the bucket owner — making auditing and lifecycle management harder. This is the modern AWS recommendation for new buckets.",
        "steps": [
            "aws s3api put-bucket-ownership-controls --bucket <name> --ownership-controls Rules=[{ObjectOwnership=BucketOwnerEnforced}]",
            "Migrate any existing ACL-based access patterns to bucket-policy or IAM grants",
        ],
        "effort": "quick",
    },
    "s3-access-logging": {
        "explanation": "Without S3 access logs, you cannot reconstruct who accessed which objects during an incident — no source IPs, no requester ARNs, no operation history beyond CloudTrail data events (which most accounts don't enable for cost reasons).",
        "steps": [
            "Create a dedicated log destination bucket with Object Lock + lifecycle rules",
            "aws s3api put-bucket-logging on the source bucket pointing at the log bucket",
            "Use CloudTrail data events for buckets requiring object-level audit",
        ],
        "effort": "quick",
    },
    "s3-kms-cmk": {
        "explanation": "The default S3 server-side encryption (SSE-S3) uses an AWS-owned key. Customer-managed KMS encryption (SSE-KMS) gives you key-level audit, the ability to revoke decrypt access independently of the bucket policy, and meets stricter compliance requirements (PCI, HIPAA, FedRAMP High).",
        "steps": [
            "Create a customer-managed KMS key with rotation enabled",
            "aws s3api put-bucket-encryption with SSEAlgorithm=aws:kms and KMSMasterKeyID=<arn>",
            "Enable bucket_key_enabled to reduce KMS API costs by ~99%",
        ],
        "effort": "quick",
    },
    "aws-backup-cross-region-copy": {
        "explanation": "Without cross-region backup copy actions, a single-region disaster (control plane outage, account compromise, ransomware) destroys both your primary data and your backups simultaneously. Mirrors Azure RSV cross-region restore.",
        "steps": [
            "Create a destination Backup vault in a different region",
            "Edit each backup plan rule to add a copy_action targeting the destination vault",
            "Set the destination vault's lifecycle delete_after to match or exceed the source",
        ],
        "effort": "moderate",
    },
    "aws-backup-vault-access-policy": {
        "explanation": "Without a resource-based access policy denying destructive operations to non-break-glass principals, a compromised admin can wipe backups even with Vault Lock in GOVERNANCE mode. This is the AWS analog of Azure RSV's Multi-User Authorization.",
        "steps": [
            "Define an IAM role for break-glass backup operations (separate from day-to-day admins)",
            "Write a vault access policy with Effect=Deny, NotPrincipal=<break-glass role>, and Action including DeleteBackupVault, DeleteRecoveryPoint, StartCopyJob",
            "aws backup put-backup-vault-access-policy with the policy file",
        ],
        "effort": "moderate",
    },
    # ----- Azure CIS v3.0 explanations -----
    "azure-storage-shared-key-access": {
        "explanation": "Storage account keys are like a master password — anyone holding the key bypasses Entra ID identity, RBAC, Conditional Access, and audit attribution. Disable shared-key access so every read/write must come through an authenticated Entra ID identity.",
        "steps": [
            "Audit which apps still use the storage account key (search app settings, env vars, secrets)",
            "Migrate each consumer to managed identity + Entra ID auth",
            "Set allowSharedKeyAccess = false on the storage account",
            "Confirm via the audit logs that no SharedKey requests remain",
        ],
        "effort": "moderate",
    },
    "azure-storage-cross-tenant-replication": {
        "explanation": "Object replication across tenants is a stealth exfiltration channel — a user with replication permissions can configure your storage to mirror blobs into a foreign Entra ID tenant, and the data leaves without triggering normal data-movement alerts.",
        "steps": [
            "Set allowCrossTenantReplication = false on every production storage account",
            "Audit existing object replication policies for foreign-tenant targets",
        ],
        "effort": "quick",
    },
    "azure-storage-network-default-deny": {
        "explanation": "By default, a storage account is reachable from anywhere on the internet — a leaked SAS or stolen identity becomes immediately exploitable. Default-Deny + explicit allowlist limits the blast radius to known networks.",
        "steps": [
            "Set network rules default action to Deny",
            "Add explicit IP rules for trusted office/VPN ranges",
            "Add VNet subnet rules for internal apps",
            "Allow only AzureServices, Logging, Metrics in the bypass list",
        ],
        "effort": "quick",
    },
    "azure-keyvault-rbac-mode": {
        "explanation": "Legacy Key Vault access policies are a parallel permission system that doesn't integrate with PIM, Conditional Access, or central access reviews. Switching to RBAC mode makes Key Vault permissions visible alongside every other Azure resource and lets you use Key Vault Administrator / Secrets User / Crypto User roles.",
        "steps": [
            "Document who currently has access via the access policy list",
            "Set enable_rbac_authorization = true on the vault",
            "Create RBAC role assignments mirroring the previous access policy grants",
            "Remove the legacy access_policy blocks",
        ],
        "effort": "moderate",
    },
    "azure-keyvault-public-access": {
        "explanation": "A Key Vault reachable from the public internet means a stolen workload identity can be used from anywhere — there's no network boundary on top of the identity check. Combined with token theft, this is the shortest path from compromised credential to leaked secrets.",
        "steps": [
            "Set publicNetworkAccess = Disabled on the vault",
            "Set network ACL default action to Deny",
            "Create a Private Endpoint in the VNet that needs vault access",
            "Add a Private DNS zone (privatelink.vaultcore.azure.net) linked to the VNet",
        ],
        "effort": "moderate",
    },
    "azure-sql-min-tls": {
        "explanation": "TLS 1.0 and 1.1 have known cryptographic weaknesses (BEAST, POODLE) and are deprecated by every major security framework. SQL Server's minimal_tls_version controls what the server will accept on the wire.",
        "steps": [
            "Set minimal_tls_version = '1.2' on every SQL server",
            "Verify clients are using a recent driver that supports TLS 1.2+",
        ],
        "effort": "quick",
    },
    "azure-sql-auditing": {
        "explanation": "Server-level auditing captures every login, query, and DDL change. Without it, anomalous queries and brute-force attempts leave no record — you have no incident-response trail and no detection signal for SQL injection or data exfil.",
        "steps": [
            "Create or pick a Log Analytics workspace for security data",
            "Enable extended auditing on each SQL server pointing at the workspace",
            "Set retention to ≥ 90 days (365 ideal)",
        ],
        "effort": "moderate",
    },
    "azure-sql-entra-admin": {
        "explanation": "Without an Entra ID admin, the only way to manage SQL Server is SQL authentication — meaning no MFA, no Conditional Access, and credentials cycling outside identity governance. An Entra group as admin lets you use PIM for break-glass.",
        "steps": [
            "Create an Entra group like 'sql-admins' with one or two members",
            "Set the group as the SQL server's Entra admin",
            "Enable azuread_authentication_only = true to disable mixed-mode",
        ],
        "effort": "quick",
    },
    "azure-postgres-secure-transport": {
        "explanation": "PostgreSQL Flexible Server lets clients connect over plaintext unless require_secure_transport is ON. Plaintext means anyone on the network path can read every query and credential.",
        "steps": [
            "Set require_secure_transport = ON via az postgres flexible-server parameter set",
            "Verify clients use SSL connection strings",
        ],
        "effort": "quick",
    },
    "azure-postgres-log-settings": {
        "explanation": "Connection logging is the audit trail for every authentication attempt and session. Without log_connections / log_disconnections / log_checkpoints, brute-force attempts and anomalous session patterns are invisible.",
        "steps": [
            "Set each parameter to ON via az postgres flexible-server parameter set",
            "Forward server logs to Log Analytics via diagnostic settings",
        ],
        "effort": "quick",
    },
    "azure-mysql-secure-transport": {
        "explanation": "Same as PostgreSQL: MySQL Flexible Server can accept plaintext connections unless require_secure_transport = ON. Force TLS server-side so a misconfigured client can't downgrade.",
        "steps": [
            "az mysql flexible-server parameter set --name require_secure_transport --value ON",
        ],
        "effort": "quick",
    },
    "azure-mysql-tls-version": {
        "explanation": "MySQL accepts older TLS versions by default. Restrict to TLS 1.2 / 1.3 only.",
        "steps": [
            "az mysql flexible-server parameter set --name tls_version --value 'TLSv1.2,TLSv1.3'",
        ],
        "effort": "quick",
    },
    "azure-mysql-audit-log": {
        "explanation": "MySQL audit log captures connection events and DDL/DML statements for incident investigation. It's disabled by default.",
        "steps": [
            "Enable audit_log_enabled = ON",
            "Configure audit_log_events to include CONNECTION, ADMIN, DDL at minimum",
        ],
        "effort": "quick",
    },
    "azure-cosmos-disable-local-auth": {
        "explanation": "Cosmos DB account keys are full-access bearer tokens that bypass Entra ID, RBAC, and audit attribution. Disabling local auth forces every operation through Entra ID identity, which is logged and CA-controlled.",
        "steps": [
            "Migrate apps to use DefaultAzureCredential / managed identity",
            "Grant the identity Cosmos DB Built-in Data Reader/Contributor RBAC roles",
            "Set disableLocalAuth = true on the account",
        ],
        "effort": "moderate",
    },
    "azure-cosmos-public-access": {
        "explanation": "A Cosmos account with public network access enabled is reachable from anywhere on the internet, so any leaked identity becomes immediately exploitable.",
        "steps": [
            "Set publicNetworkAccess = Disabled",
            "Create Private Endpoint for the SQL/Mongo/Cassandra subresource the app uses",
        ],
        "effort": "moderate",
    },
    "azure-cosmos-firewall": {
        "explanation": "An empty IP firewall with public access enabled means any IP can attempt to authenticate — combined with shared keys this is a direct exfiltration path.",
        "steps": [
            "Add explicit IP rules for trusted ranges, or",
            "Add VNet rules for internal apps, or",
            "Disable public network access entirely and use Private Endpoints",
        ],
        "effort": "quick",
    },
    "azure-appservice-https-only": {
        "explanation": "An App Service that accepts HTTP serves credentials and session cookies in plaintext over the wire — anyone on the network path can capture them.",
        "steps": [
            "az webapp update --https-only true -g <rg> -n <app>",
        ],
        "effort": "quick",
    },
    "azure-appservice-min-tls": {
        "explanation": "App Service defaults to TLS 1.0 in older deployments. Force TLS 1.2+ both for the app endpoint and the Kudu (SCM) deployment endpoint.",
        "steps": [
            "az webapp config set --min-tls-version 1.2 -g <rg> -n <app>",
            "Also update scm_minimum_tls_version via ARM/Terraform",
        ],
        "effort": "quick",
    },
    "azure-appservice-ftps": {
        "explanation": "Plain FTP transmits the deployment credential in clear text. Disable it entirely, or restrict to FTPS-only if FTPS uploads are required.",
        "steps": [
            "az webapp config set --ftps-state Disabled -g <rg> -n <app>",
        ],
        "effort": "quick",
    },
    "azure-appservice-remote-debug": {
        "explanation": "Remote debugging exposes a debug endpoint that lets developers attach Visual Studio to a running production process. It should only be on briefly during a debug session, never permanently.",
        "steps": [
            "az webapp config set --remote-debugging-enabled false -g <rg> -n <app>",
        ],
        "effort": "quick",
    },
    "azure-appservice-managed-identity": {
        "explanation": "Without a managed identity, the app must store credentials in app settings or config files — which then need rotation, vaulting, and access reviews. A managed identity is identity-bound to the app instance, with no secrets to leak.",
        "steps": [
            "az webapp identity assign -g <rg> -n <app>",
            "Grant the identity RBAC on the resources it needs (Key Vault, Storage, SQL, etc.)",
            "Remove static credentials from app settings",
        ],
        "effort": "moderate",
    },
    "azure-rsv-soft-delete": {
        "explanation": "Without soft delete, an attacker (or careless admin) with vault access can delete recovery points and there's no recovery — your backups are gone. Soft delete keeps them in a recoverable state for 14 days, AlwaysON makes the protection irreversible.",
        "steps": [
            "Set soft_delete_enabled = true on every Recovery Services Vault",
            "Set the soft delete state to AlwaysON via the portal for irreversibility",
        ],
        "effort": "quick",
    },
    "azure-rsv-immutability": {
        "explanation": "Immutable vaults prevent recovery points from being deleted before their retention expires — the only true protection against ransomware that targets backups. Locking the immutability setting makes the protection irreversible.",
        "steps": [
            "Enable immutability on the vault (Properties > Immutability)",
            "Test recovery on a non-production vault first",
            "Lock the setting once you're confident — this cannot be undone",
        ],
        "effort": "moderate",
    },
    "azure-rsv-redundancy": {
        "explanation": "Locally-redundant storage (LRS) means a regional outage destroys your backups along with your primary data. GRS / GZRS replicates backup data to a paired Azure region.",
        "steps": [
            "Set storage_mode_type = 'GeoRedundant' on the vault",
            "Note: redundancy can only be changed before any backup item is registered",
            "Enable cross_region_restore = true",
        ],
        "effort": "quick",
    },
    "azure-vnet-flow-logs-modern": {
        "explanation": "NSG flow logs are deprecated — no new ones can be created after June 2025, and all existing ones retire September 2027. VNet flow logs are the post-2025 successor and capture richer data including encrypted traffic patterns.",
        "steps": [
            "Create a Storage account in the same region as the VNet for flow log storage",
            "Configure VNet flow logs in Network Watcher targeting the VNet",
            "Set retention to ≥ 90 days",
            "Enable Traffic Analytics linked to a Log Analytics workspace",
        ],
        "effort": "moderate",
    },
    "azure-network-watcher-coverage": {
        "explanation": "Network Watcher is the per-region service that powers VNet flow logs, connection troubleshooter, and Traffic Analytics. Without it in a region, you can't capture flow logs for VNets in that region.",
        "steps": [
            "Create a Network Watcher resource in each region that hosts a VNet",
            "Network Watcher is normally auto-created — manual creation is only needed if it was deleted",
        ],
        "effort": "quick",
    },
    "azure-defender-per-plan": {
        "explanation": "Defender for Cloud charges per resource type ('plan'), and each plan covers a different attack surface — Defender for Servers detects malware on VMs, Defender for SQL detects SQL injection, Defender for Containers scans images, etc. Enabling only some plans leaves blind spots.",
        "steps": [
            "Identify which Defender plans are missing",
            "Enable each one via Defender for Cloud > Environment settings > Defender plans",
            "Set up email notifications for new alerts",
        ],
        "effort": "moderate",
    },
    "azure-activity-log-alerts": {
        "explanation": "CIS Azure 5.2.x requires real-time alerts on critical control-plane changes — NSG rule edits, SQL firewall changes, Policy assignment changes, Key Vault create/delete. Without these, security-relevant changes happen silently and only show up in retrospective audits.",
        "steps": [
            "Create an Action Group with email + SMS for SecOps",
            "Create one Activity Log alert per CIS-required operation",
            "Verify alerts trigger by making a test change",
        ],
        "effort": "moderate",
    },
    "azure-resource-locks": {
        "explanation": "A misclick in the Portal or a compromised admin can wipe an entire resource group containing your Key Vault, Recovery Services Vault, or log storage. CanNotDelete locks block deletion until the lock is explicitly removed — a small speed bump that prevents catastrophic mistakes.",
        "steps": [
            "Identify resource groups containing sensitive resources (KV, RSV, log Storage, Log Analytics)",
            "Apply a CanNotDelete lock to each",
            "Document the lock removal procedure for change windows",
        ],
        "effort": "quick",
    },
    "azure-required-tags": {
        "explanation": "Without owner / environment tags, incident response and access reviews are guesswork — you don't know who owns a resource or whether it's production. Azure Policy with deny effect prevents new resources from being created without the required tags.",
        "steps": [
            "Backfill missing tags on existing resource groups",
            "Assign the built-in 'Require a tag and its value on resource groups' policy",
            "Set the deny effect to enforce going forward",
        ],
        "effort": "moderate",
    },
    "azure-security-initiative": {
        "explanation": "The Microsoft Cloud Security Benchmark initiative is a pre-built bundle of security policies that maps to CIS, NIST, ISO, and PCI. Assigning it gives you a continuous compliance score in Defender for Cloud's Regulatory Compliance dashboard without writing a single policy.",
        "steps": [
            "Find the 'Microsoft cloud security benchmark' built-in initiative",
            "Assign it at the tenant root management group (or top-level MG)",
            "Review the compliance score in Defender for Cloud",
        ],
        "effort": "quick",
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
    blocks.append("# Shasta Auto-Generated Remediation Terraform")
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
