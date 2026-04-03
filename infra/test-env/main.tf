###############################################################################
# Shasta Test Environment
#
# Creates a mix of COMPLIANT and NON-COMPLIANT resources for testing
# SOC 2 compliance scanning. Each resource is tagged with its intended
# compliance state so we can validate scanner accuracy.
#
# IMPORTANT: This is a TEST environment only. Do NOT use in production.
###############################################################################

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region  = "us-east-1"
  profile = "shasta-admin"

  default_tags {
    tags = {
      Project     = "shasta-test"
      Environment = "test"
      ManagedBy   = "terraform"
    }
  }
}

# ===========================================================================
# IAM — CC6.1 (Logical Access), CC6.2 (Provisioning), CC6.3 (Removal)
# ===========================================================================

# BAD: Weak password policy (or none — we'll set a weak one)
resource "aws_iam_account_password_policy" "weak" {
  minimum_password_length        = 8   # Should be 14+
  require_lowercase_characters   = true
  require_uppercase_characters   = false # BAD: should be true
  require_numbers                = true
  require_symbols                = false # BAD: should be true
  allow_users_to_change_password = true
  max_password_age               = 0    # BAD: passwords never expire
  password_reuse_prevention      = 0    # BAD: no reuse prevention
}

# BAD: IAM user with console access but no MFA
resource "aws_iam_user" "dev_no_mfa" {
  name = "dev-no-mfa"
  tags = {
    shasta_expected = "fail"
    shasta_check    = "iam-mfa-enabled"
  }
}

resource "aws_iam_user_login_profile" "dev_no_mfa" {
  user                    = aws_iam_user.dev_no_mfa.name
  password_reset_required = false
}

# BAD: IAM user with overly broad permissions (admin access)
resource "aws_iam_user" "overprivileged" {
  name = "overprivileged-user"
  tags = {
    shasta_expected = "fail"
    shasta_check    = "iam-least-privilege"
  }
}

resource "aws_iam_user_policy_attachment" "overprivileged_admin" {
  user       = aws_iam_user.overprivileged.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# BAD: IAM user with access keys (simulating stale keys — keys are new,
# but the scanner should flag that console users also have programmatic access)
resource "aws_iam_user" "stale_keys_user" {
  name = "stale-keys-user"
  tags = {
    shasta_expected = "fail"
    shasta_check    = "iam-access-key-rotation"
  }
}

resource "aws_iam_access_key" "stale_keys" {
  user = aws_iam_user.stale_keys_user.name
}

# GOOD: IAM user in a group with scoped permissions
resource "aws_iam_user" "good_user" {
  name = "good-developer"
  tags = {
    shasta_expected = "pass"
    shasta_check    = "iam-least-privilege"
  }
}

resource "aws_iam_group" "developers" {
  name = "developers"
}

resource "aws_iam_group_membership" "developers" {
  name  = "developers-membership"
  users = [aws_iam_user.good_user.name]
  group = aws_iam_group.developers.name
}

resource "aws_iam_group_policy_attachment" "developers_readonly" {
  group      = aws_iam_group.developers.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

# ===========================================================================
# S3 — CC6.7 (Encryption in transit/at rest), CC6.6 (Boundaries)
# ===========================================================================

# BAD: S3 bucket with no encryption, no versioning, no public access block
resource "aws_s3_bucket" "insecure" {
  bucket = "shasta-test-insecure-${data.aws_caller_identity.current.account_id}"
  tags = {
    shasta_expected = "fail"
    shasta_check    = "s3-encryption s3-versioning s3-public-access"
  }
}

# GOOD: S3 bucket with encryption, versioning, and public access blocked
resource "aws_s3_bucket" "secure" {
  bucket = "shasta-test-secure-${data.aws_caller_identity.current.account_id}"
  tags = {
    shasta_expected = "pass"
    shasta_check    = "s3-encryption s3-versioning s3-public-access"
  }
}

resource "aws_s3_bucket_versioning" "secure" {
  bucket = aws_s3_bucket.secure.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "secure" {
  bucket = aws_s3_bucket.secure.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "secure" {
  bucket                  = aws_s3_bucket.secure.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Also block public access on the insecure bucket's absence is the point —
# but let's add a bucket policy that allows SSL-only on the secure one
resource "aws_s3_bucket_policy" "secure_ssl_only" {
  bucket = aws_s3_bucket.secure.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.secure.arn,
          "${aws_s3_bucket.secure.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
}

# ===========================================================================
# VPC & Networking — CC6.6 (System Boundaries)
# ===========================================================================

resource "aws_vpc" "test" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true
  tags = { Name = "shasta-test-vpc" }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.test.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "us-east-1a"
  map_public_ip_on_launch = true
  tags = { Name = "shasta-test-public" }
}

resource "aws_subnet" "private" {
  vpc_id            = aws_vpc.test.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "us-east-1a"
  tags = { Name = "shasta-test-private" }
}

resource "aws_internet_gateway" "test" {
  vpc_id = aws_vpc.test.id
  tags   = { Name = "shasta-test-igw" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.test.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.test.id
  }
  tags = { Name = "shasta-test-public-rt" }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# BAD: Security group allowing SSH from anywhere
resource "aws_security_group" "bad_ssh" {
  name        = "shasta-bad-ssh"
  description = "BAD: allows SSH from 0.0.0.0/0"
  vpc_id      = aws_vpc.test.id

  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # BAD
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name            = "shasta-bad-ssh"
    shasta_expected = "fail"
    shasta_check    = "sg-no-unrestricted-ingress"
  }
}

# BAD: Security group allowing RDP from anywhere
resource "aws_security_group" "bad_rdp" {
  name        = "shasta-bad-rdp"
  description = "BAD: allows RDP from 0.0.0.0/0"
  vpc_id      = aws_vpc.test.id

  ingress {
    description = "RDP from anywhere"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # BAD
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name            = "shasta-bad-rdp"
    shasta_expected = "fail"
    shasta_check    = "sg-no-unrestricted-ingress"
  }
}

# BAD: Security group allowing ALL traffic from anywhere
resource "aws_security_group" "bad_all" {
  name        = "shasta-bad-all-traffic"
  description = "BAD: allows all traffic from 0.0.0.0/0"
  vpc_id      = aws_vpc.test.id

  ingress {
    description = "All traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]  # BAD
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name            = "shasta-bad-all-traffic"
    shasta_expected = "fail"
    shasta_check    = "sg-no-unrestricted-ingress"
  }
}

# GOOD: Security group with restricted access
resource "aws_security_group" "good_web" {
  name        = "shasta-good-web"
  description = "GOOD: allows HTTPS only from known CIDR"
  vpc_id      = aws_vpc.test.id

  ingress {
    description = "HTTPS from office"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["203.0.113.0/24"]  # Example restricted CIDR
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name            = "shasta-good-web"
    shasta_expected = "pass"
    shasta_check    = "sg-no-unrestricted-ingress"
  }
}

# BAD: No VPC flow logs enabled (the absence is the finding)

# ===========================================================================
# CloudTrail — CC7.1 (Detection & Monitoring)
# ===========================================================================

# CloudTrail S3 bucket with encryption and access logging
resource "aws_s3_bucket" "cloudtrail" {
  bucket = "shasta-cloudtrail-${data.aws_caller_identity.current.account_id}"
  tags   = { Name = "shasta-cloudtrail-logs" }
}

resource "aws_s3_bucket_versioning" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "cloudtrail" {
  bucket                  = aws_s3_bucket.cloudtrail.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "cloudtrail" {
  bucket = aws_s3_bucket.cloudtrail.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSCloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.cloudtrail.arn
        Condition = {
          StringEquals = {
            "aws:SourceArn" = "arn:aws:cloudtrail:us-east-1:${data.aws_caller_identity.current.account_id}:trail/shasta-trail"
          }
        }
      },
      {
        Sid       = "AWSCloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.cloudtrail.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
            "aws:SourceArn" = "arn:aws:cloudtrail:us-east-1:${data.aws_caller_identity.current.account_id}:trail/shasta-trail"
          }
        }
      },
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.cloudtrail.arn,
          "${aws_s3_bucket.cloudtrail.arn}/*"
        ]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      }
    ]
  })
}

# CloudTrail — multi-region, management events, log file validation
resource "aws_cloudtrail" "main" {
  name                       = "shasta-trail"
  s3_bucket_name             = aws_s3_bucket.cloudtrail.id
  is_multi_region_trail      = true
  enable_log_file_validation = true
  include_global_service_events = true

  tags = { Name = "shasta-trail" }

  depends_on = [aws_s3_bucket_policy.cloudtrail]
}

# ===========================================================================
# GuardDuty — CC7.2 (Anomaly Monitoring)
# ===========================================================================

resource "aws_guardduty_detector" "main" {
  enable = true

  # Enable common protection features
  datasources {
    s3_logs {
      enable = true
    }
  }

  tags = { Name = "shasta-guardduty" }
}

# ===========================================================================
# AWS Config — CC8.1 (Change Management)
# ===========================================================================

# Config requires an IAM role and S3 bucket for recording
resource "aws_s3_bucket" "config" {
  bucket = "shasta-config-${data.aws_caller_identity.current.account_id}"
  tags   = { Name = "shasta-config-logs" }
}

resource "aws_s3_bucket_versioning" "config" {
  bucket = aws_s3_bucket.config.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "config" {
  bucket = aws_s3_bucket.config.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "config" {
  bucket                  = aws_s3_bucket.config.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "config" {
  bucket = aws_s3_bucket.config.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AWSConfigBucketPermissionsCheck"
        Effect    = "Allow"
        Principal = { Service = "config.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.config.arn
      },
      {
        Sid       = "AWSConfigBucketDelivery"
        Effect    = "Allow"
        Principal = { Service = "config.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.config.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/Config/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      },
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.config.arn,
          "${aws_s3_bucket.config.arn}/*"
        ]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      }
    ]
  })
}

resource "aws_iam_role" "config" {
  name = "shasta-config-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "config.amazonaws.com" }
        Action    = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "config" {
  role       = aws_iam_role.config.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

resource "aws_iam_role_policy" "config_s3" {
  name = "shasta-config-s3-delivery"
  role = aws_iam_role.config.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = ["s3:PutObject", "s3:GetBucketAcl"]
        Resource = [
          aws_s3_bucket.config.arn,
          "${aws_s3_bucket.config.arn}/*"
        ]
      }
    ]
  })
}

resource "aws_config_configuration_recorder" "main" {
  name     = "shasta-config-recorder"
  role_arn = aws_iam_role.config.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_config_delivery_channel" "main" {
  name           = "shasta-config-channel"
  s3_bucket_name = aws_s3_bucket.config.id

  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_configuration_recorder_status" "main" {
  name       = aws_config_configuration_recorder.main.name
  is_enabled = true

  depends_on = [aws_config_delivery_channel.main]
}

# ===========================================================================
# Data sources
# ===========================================================================

data "aws_caller_identity" "current" {}

# ===========================================================================
# Outputs
# ===========================================================================

output "account_id" {
  value = data.aws_caller_identity.current.account_id
}

output "vpc_id" {
  value = aws_vpc.test.id
}

output "insecure_bucket" {
  value = aws_s3_bucket.insecure.id
}

output "secure_bucket" {
  value = aws_s3_bucket.secure.id
}

output "cloudtrail_arn" {
  value = aws_cloudtrail.main.arn
}

output "guardduty_detector_id" {
  value = aws_guardduty_detector.main.id
}

output "summary" {
  value = <<-EOT

    Shasta Test Environment Created!
    ================================
    Account:  ${data.aws_caller_identity.current.account_id}

    IAM (CC6.1-CC6.3):
      - dev-no-mfa          → user with console access, NO MFA (FAIL)
      - overprivileged-user → user with AdministratorAccess (FAIL)
      - stale-keys-user     → user with access keys (FAIL)
      - good-developer      → user in group with ReadOnly (PASS)
      - Password policy     → weak settings (FAIL)

    S3 (CC6.7):
      - ${aws_s3_bucket.insecure.id} → no encryption, no versioning (FAIL)
      - ${aws_s3_bucket.secure.id}   → KMS encryption, versioning, SSL-only (PASS)

    Networking (CC6.6):
      - VPC: ${aws_vpc.test.id}
      - shasta-bad-ssh          → SSH open to 0.0.0.0/0 (FAIL)
      - shasta-bad-rdp          → RDP open to 0.0.0.0/0 (FAIL)
      - shasta-bad-all-traffic  → all ports open to 0.0.0.0/0 (FAIL)
      - shasta-good-web         → HTTPS from restricted CIDR (PASS)
      - No VPC flow logs (FAIL)

    Logging & Monitoring (CC7.1, CC7.2, CC8.1):
      - CloudTrail: shasta-trail (multi-region, log validation) (PASS)
      - GuardDuty: enabled with S3 protection (PASS)
      - AWS Config: recording all resources (PASS)
  EOT
}
