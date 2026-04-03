###############################################################################
# Continuous Compliance Monitoring Infrastructure
#
# Deploys:
#   - SecurityHub (aggregates all findings)
#   - AWS Inspector (vulnerability scanning)
#   - AWS Config Managed Rules (real-time compliance checks)
#   - EventBridge Rules (high-risk event detection)
#   - SNS Topic (alert pipeline)
#   - Lambda Function (Slack + Jira alerting)
###############################################################################

# ===========================================================================
# SecurityHub — Aggregates findings from Config, GuardDuty, Inspector
# ===========================================================================

resource "aws_securityhub_account" "main" {}

# Enable AWS Foundational Security Best Practices standard
resource "aws_securityhub_standards_subscription" "aws_foundational" {
  standards_arn = "arn:aws:securityhub:us-east-1::standards/aws-foundational-security-best-practices/v/1.0.0"

  depends_on = [aws_securityhub_account.main]
}

# ===========================================================================
# AWS Inspector — Continuous Vulnerability Scanning
# ===========================================================================

resource "aws_inspector2_enabler" "main" {
  account_ids    = [data.aws_caller_identity.current.account_id]
  resource_types = ["EC2", "ECR", "LAMBDA", "LAMBDA_CODE"]
}

# ===========================================================================
# AWS Config Managed Rules — Real-time SOC 2 Compliance Checks
# ===========================================================================

# CC6.1 — IAM password policy
resource "aws_config_config_rule" "iam_password_policy" {
  name = "shasta-iam-password-policy"

  source {
    owner             = "AWS"
    source_identifier = "IAM_PASSWORD_POLICY"
  }

  input_parameters = jsonencode({
    RequireUppercaseCharacters = "true"
    RequireLowercaseCharacters = "true"
    RequireSymbols             = "true"
    RequireNumbers             = "true"
    MinimumPasswordLength      = "14"
    PasswordReusePrevention    = "12"
    MaxPasswordAge             = "90"
  })

  depends_on = [aws_config_configuration_recorder_status.main]
}

# CC6.1 — Root account MFA
resource "aws_config_config_rule" "root_mfa" {
  name = "shasta-root-account-mfa-enabled"

  source {
    owner             = "AWS"
    source_identifier = "ROOT_ACCOUNT_MFA_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder_status.main]
}

# CC6.1 — MFA enabled for IAM console users
resource "aws_config_config_rule" "mfa_enabled" {
  name = "shasta-mfa-enabled-for-iam-console-access"

  source {
    owner             = "AWS"
    source_identifier = "MFA_ENABLED_FOR_IAM_CONSOLE_ACCESS"
  }

  depends_on = [aws_config_configuration_recorder_status.main]
}

# CC6.2 — No inline policies on users
resource "aws_config_config_rule" "no_user_policies" {
  name = "shasta-iam-user-no-policies-check"

  source {
    owner             = "AWS"
    source_identifier = "IAM_USER_NO_POLICIES_CHECK"
  }

  depends_on = [aws_config_configuration_recorder_status.main]
}

# CC6.3 — Access key rotation
resource "aws_config_config_rule" "access_key_rotation" {
  name = "shasta-access-keys-rotated"

  source {
    owner             = "AWS"
    source_identifier = "ACCESS_KEYS_ROTATED"
  }

  input_parameters = jsonencode({
    maxAccessKeyAge = "90"
  })

  depends_on = [aws_config_configuration_recorder_status.main]
}

# CC6.6 — Restricted SSH
resource "aws_config_config_rule" "restricted_ssh" {
  name = "shasta-restricted-ssh"

  source {
    owner             = "AWS"
    source_identifier = "INCOMING_SSH_DISABLED"
  }

  depends_on = [aws_config_configuration_recorder_status.main]
}

# CC6.6 — VPC flow logs enabled
resource "aws_config_config_rule" "vpc_flow_logs" {
  name = "shasta-vpc-flow-logs-enabled"

  source {
    owner             = "AWS"
    source_identifier = "VPC_FLOW_LOGS_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder_status.main]
}

# CC6.7 — S3 default encryption
resource "aws_config_config_rule" "s3_encryption" {
  name = "shasta-s3-default-encryption-kms"

  source {
    owner             = "AWS"
    source_identifier = "S3_DEFAULT_ENCRYPTION_KMS"
  }

  depends_on = [aws_config_configuration_recorder_status.main]
}

# CC6.7 — S3 bucket public access blocked
resource "aws_config_config_rule" "s3_public_access" {
  name = "shasta-s3-bucket-public-read-prohibited"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
  }

  depends_on = [aws_config_configuration_recorder_status.main]
}

# CC6.7 — S3 bucket SSL only
resource "aws_config_config_rule" "s3_ssl" {
  name = "shasta-s3-bucket-ssl-requests-only"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_SSL_REQUESTS_ONLY"
  }

  depends_on = [aws_config_configuration_recorder_status.main]
}

# CC7.1 — CloudTrail enabled
resource "aws_config_config_rule" "cloudtrail_enabled" {
  name = "shasta-cloud-trail-enabled"

  source {
    owner             = "AWS"
    source_identifier = "CLOUD_TRAIL_ENABLED"
  }

  depends_on = [aws_config_configuration_recorder_status.main]
}

# CC7.2 — GuardDuty enabled
resource "aws_config_config_rule" "guardduty_enabled" {
  name = "shasta-guardduty-enabled-centralized"

  source {
    owner             = "AWS"
    source_identifier = "GUARDDUTY_ENABLED_CENTRALIZED"
  }

  depends_on = [aws_config_configuration_recorder_status.main]
}

# ===========================================================================
# SNS Topic — Alert Pipeline
# ===========================================================================

resource "aws_sns_topic" "compliance_alerts" {
  name = "shasta-compliance-alerts"
}

# ===========================================================================
# EventBridge Rules — High-Risk Event Detection
# ===========================================================================

# Detect root account usage
resource "aws_cloudwatch_event_rule" "root_login" {
  name        = "shasta-root-account-usage"
  description = "Detect root account console sign-in or API usage"

  event_pattern = jsonencode({
    detail-type = ["AWS Console Sign In via CloudTrail", "AWS API Call via CloudTrail"]
    detail = {
      userIdentity = {
        type = ["Root"]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "root_login_sns" {
  rule      = aws_cloudwatch_event_rule.root_login.name
  target_id = "send-to-sns"
  arn       = aws_sns_topic.compliance_alerts.arn
}

# Detect security group changes
resource "aws_cloudwatch_event_rule" "sg_changes" {
  name        = "shasta-security-group-changes"
  description = "Detect security group creation or modification"

  event_pattern = jsonencode({
    source      = ["aws.ec2"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["ec2.amazonaws.com"]
      eventName   = [
        "AuthorizeSecurityGroupIngress",
        "AuthorizeSecurityGroupEgress",
        "RevokeSecurityGroupIngress",
        "RevokeSecurityGroupEgress",
        "CreateSecurityGroup",
        "DeleteSecurityGroup"
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "sg_changes_sns" {
  rule      = aws_cloudwatch_event_rule.sg_changes.name
  target_id = "send-to-sns"
  arn       = aws_sns_topic.compliance_alerts.arn
}

# Detect IAM policy changes
resource "aws_cloudwatch_event_rule" "iam_changes" {
  name        = "shasta-iam-policy-changes"
  description = "Detect IAM policy creation, attachment, or modification"

  event_pattern = jsonencode({
    source      = ["aws.iam"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["iam.amazonaws.com"]
      eventName   = [
        "AttachUserPolicy",
        "AttachGroupPolicy",
        "AttachRolePolicy",
        "CreatePolicy",
        "CreateUser",
        "DeleteUser",
        "PutUserPolicy",
        "PutGroupPolicy",
        "CreateAccessKey"
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "iam_changes_sns" {
  rule      = aws_cloudwatch_event_rule.iam_changes.name
  target_id = "send-to-sns"
  arn       = aws_sns_topic.compliance_alerts.arn
}

# Detect S3 bucket policy changes
resource "aws_cloudwatch_event_rule" "s3_changes" {
  name        = "shasta-s3-policy-changes"
  description = "Detect S3 bucket policy or encryption changes"

  event_pattern = jsonencode({
    source      = ["aws.s3"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["s3.amazonaws.com"]
      eventName   = [
        "PutBucketPolicy",
        "DeleteBucketPolicy",
        "PutBucketPublicAccessBlock",
        "DeleteBucketEncryption",
        "PutBucketAcl"
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "s3_changes_sns" {
  rule      = aws_cloudwatch_event_rule.s3_changes.name
  target_id = "send-to-sns"
  arn       = aws_sns_topic.compliance_alerts.arn
}

# Detect Config rule compliance changes (fires when any Config Rule goes NON_COMPLIANT)
resource "aws_cloudwatch_event_rule" "config_compliance_change" {
  name        = "shasta-config-compliance-change"
  description = "Detect when AWS Config rules change compliance status to NON_COMPLIANT"

  event_pattern = jsonencode({
    source      = ["aws.config"]
    detail-type = ["Config Rules Compliance Change"]
    detail = {
      messageType           = ["ComplianceChangeNotification"]
      newEvaluationResult = {
        complianceType = ["NON_COMPLIANT"]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "config_compliance_sns" {
  rule      = aws_cloudwatch_event_rule.config_compliance_change.name
  target_id = "send-to-sns"
  arn       = aws_sns_topic.compliance_alerts.arn
}

# GuardDuty findings
resource "aws_cloudwatch_event_rule" "guardduty_findings" {
  name        = "shasta-guardduty-findings"
  description = "Detect new GuardDuty findings"

  event_pattern = jsonencode({
    source      = ["aws.guardduty"]
    detail-type = ["GuardDuty Finding"]
  })
}

resource "aws_cloudwatch_event_target" "guardduty_findings_sns" {
  rule      = aws_cloudwatch_event_rule.guardduty_findings.name
  target_id = "send-to-sns"
  arn       = aws_sns_topic.compliance_alerts.arn
}

# SNS Topic Policy — allow EventBridge + Config to publish
resource "aws_sns_topic_policy" "compliance_alerts" {
  arn = aws_sns_topic.compliance_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowEventBridge"
        Effect    = "Allow"
        Principal = { Service = "events.amazonaws.com" }
        Action    = "sns:Publish"
        Resource  = aws_sns_topic.compliance_alerts.arn
      },
      {
        Sid       = "AllowConfig"
        Effect    = "Allow"
        Principal = { Service = "config.amazonaws.com" }
        Action    = "sns:Publish"
        Resource  = aws_sns_topic.compliance_alerts.arn
      }
    ]
  })
}

# ===========================================================================
# Lambda — Slack + Jira Alert Forwarder
# ===========================================================================

resource "aws_iam_role" "alert_lambda" {
  name = "shasta-alert-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "alert_lambda_basic" {
  role       = aws_iam_role.alert_lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

data "archive_file" "alert_lambda" {
  type        = "zip"
  source_file = "${path.module}/lambda/alert_forwarder.py"
  output_path = "${path.module}/lambda/alert_forwarder.zip"
}

resource "aws_lambda_function" "alert_forwarder" {
  filename         = data.archive_file.alert_lambda.output_path
  source_code_hash = data.archive_file.alert_lambda.output_base64sha256
  function_name    = "shasta-alert-forwarder"
  role             = aws_iam_role.alert_lambda.arn
  handler          = "alert_forwarder.lambda_handler"
  runtime          = "python3.12"
  timeout          = 30

  environment {
    variables = {
      SLACK_WEBHOOK_URL = var.slack_webhook_url
      JIRA_BASE_URL     = var.jira_base_url
      JIRA_EMAIL        = var.jira_email
      JIRA_API_TOKEN    = var.jira_api_token
      JIRA_PROJECT_KEY  = var.jira_project_key
    }
  }

  tags = { Name = "shasta-alert-forwarder" }
}

resource "aws_sns_topic_subscription" "alert_lambda" {
  topic_arn = aws_sns_topic.compliance_alerts.arn
  protocol  = "lambda"
  endpoint  = aws_lambda_function.alert_forwarder.arn
}

resource "aws_lambda_permission" "sns_invoke" {
  statement_id  = "AllowSNSInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.alert_forwarder.function_name
  principal     = "sns.amazonaws.com"
  source_arn    = aws_sns_topic.compliance_alerts.arn
}

# ===========================================================================
# Variables for integration credentials
# ===========================================================================

variable "slack_webhook_url" {
  description = "Slack incoming webhook URL for compliance alerts"
  type        = string
  default     = ""
  sensitive   = true
}

variable "jira_base_url" {
  description = "Jira base URL (e.g., https://yourcompany.atlassian.net)"
  type        = string
  default     = ""
}

variable "jira_email" {
  description = "Jira account email for API access"
  type        = string
  default     = ""
}

variable "jira_api_token" {
  description = "Jira API token"
  type        = string
  default     = ""
  sensitive   = true
}

variable "jira_project_key" {
  description = "Jira project key for creating compliance tickets"
  type        = string
  default     = ""
}

# ===========================================================================
# Outputs
# ===========================================================================

output "sns_topic_arn" {
  value = aws_sns_topic.compliance_alerts.arn
}

output "alert_lambda_arn" {
  value = aws_lambda_function.alert_forwarder.arn
}

output "monitoring_summary" {
  value = <<-EOT

    Continuous Monitoring Deployed!
    ===============================
    SecurityHub:   Enabled (AWS Foundational Best Practices)
    AWS Inspector: Enabled (EC2, ECR, Lambda scanning)

    Config Rules (12 real-time checks):
      - IAM password policy, root MFA, user MFA
      - No direct user policies, access key rotation
      - Restricted SSH, VPC flow logs
      - S3 encryption, public access, SSL-only
      - CloudTrail enabled, GuardDuty enabled

    EventBridge Rules (6 event detectors):
      - Root account usage
      - Security group changes
      - IAM policy changes
      - S3 bucket policy changes
      - Config compliance changes
      - GuardDuty findings

    Alert Pipeline:
      SNS Topic → Lambda → Slack + Jira
  EOT
}
