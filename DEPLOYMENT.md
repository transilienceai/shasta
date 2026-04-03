# Shasta Deployment Guide

Deploy Shasta to scan your AWS environment for SOC 2 compliance. This guide walks you through setup in under 30 minutes.

## Prerequisites

- **Python 3.11+** installed
- **AWS CLI** configured with SSO or IAM credentials
- **Terraform** installed (for deploying monitoring infrastructure)
- **Claude Code** installed (for interactive compliance guidance)
- **Git** (to clone the repo)

---

## Step 1: Clone and Install

```bash
git clone <shasta-repo-url>
cd shasta
pip install -e ".[dev]"
```

Verify installation:
```bash
python -c "import shasta; print('Shasta installed successfully')"
```

---

## Step 2: Create a Read-Only IAM Role for Scanning

Shasta scanning is **100% read-only**. It never modifies your AWS environment. All remediation is provided as Terraform scripts and instructions for YOU to review and apply.

### Option A: Use AWS Managed Policy (Quickest)

Attach the `ReadOnlyAccess` managed policy to your IAM user or role:
```
arn:aws:iam::aws:policy/ReadOnlyAccess
```

This grants read access to all AWS services. If you prefer a scoped policy, use Option B.

### Option B: Custom Scoped Policy (Least Privilege)

Create a custom IAM policy with only the permissions Shasta needs:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ShastaIdentity",
      "Effect": "Allow",
      "Action": [
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    },
    {
      "Sid": "ShastaIAMChecks",
      "Effect": "Allow",
      "Action": [
        "iam:GetAccountPasswordPolicy",
        "iam:GetAccountSummary",
        "iam:GetLoginProfile",
        "iam:ListUsers",
        "iam:ListMFADevices",
        "iam:ListAccessKeys",
        "iam:ListAttachedUserPolicies",
        "iam:ListUserPolicies",
        "iam:ListGroupsForUser",
        "iam:ListAttachedGroupPolicies",
        "iam:ListAccountAliases",
        "iam:GenerateCredentialReport",
        "iam:GetCredentialReport"
      ],
      "Resource": "*"
    },
    {
      "Sid": "ShastaNetworkChecks",
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeVpcs",
        "ec2:DescribeFlowLogs",
        "ec2:DescribeInstances",
        "ec2:DescribeSubnets",
        "ec2:DescribeNetworkInterfaces"
      ],
      "Resource": "*"
    },
    {
      "Sid": "ShastaStorageChecks",
      "Effect": "Allow",
      "Action": [
        "s3:ListAllMyBuckets",
        "s3:GetBucketEncryption",
        "s3:GetBucketVersioning",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketPolicy",
        "s3:GetBucketAcl",
        "s3:GetBucketLocation"
      ],
      "Resource": "*"
    },
    {
      "Sid": "ShastaMonitoringChecks",
      "Effect": "Allow",
      "Action": [
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus",
        "guardduty:ListDetectors",
        "guardduty:GetDetector",
        "guardduty:GetFindingsStatistics",
        "config:DescribeConfigurationRecorders",
        "config:DescribeConfigurationRecorderStatus",
        "config:DescribeDeliveryChannels"
      ],
      "Resource": "*"
    },
    {
      "Sid": "ShastaVulnerabilityChecks",
      "Effect": "Allow",
      "Action": [
        "inspector2:BatchGetAccountStatus",
        "inspector2:ListFindingAggregations",
        "inspector2:ListFindings"
      ],
      "Resource": "*"
    },
    {
      "Sid": "ShastaServiceDiscovery",
      "Effect": "Allow",
      "Action": [
        "rds:DescribeDBInstances",
        "lambda:ListFunctions",
        "kms:ListKeys",
        "ecs:ListClusters",
        "cloudwatch:DescribeAlarms"
      ],
      "Resource": "*"
    }
  ]
}
```

Save this as `shasta-scanning-policy.json` and create the policy:

```bash
aws iam create-policy \
  --policy-name ShastaReadOnlyScanning \
  --policy-document file://shasta-scanning-policy.json \
  --description "Read-only access for Shasta SOC 2 compliance scanning"
```

Then attach it to your IAM user or role:

```bash
# For an IAM user:
aws iam attach-user-policy \
  --user-name YOUR_USERNAME \
  --policy-arn arn:aws:iam::YOUR_ACCOUNT_ID:policy/ShastaReadOnlyScanning

# For an IAM role:
aws iam attach-role-policy \
  --role-name YOUR_ROLE_NAME \
  --policy-arn arn:aws:iam::YOUR_ACCOUNT_ID:policy/ShastaReadOnlyScanning
```

### Permission Summary

| Service | Permissions | Why |
|---------|-------------|-----|
| STS | GetCallerIdentity | Validate credentials, get account ID |
| IAM | List*, Get*, GenerateCredentialReport | Check MFA, passwords, access keys, policies |
| EC2 | Describe* | Check security groups, VPCs, flow logs |
| S3 | List*, GetBucket* | Check encryption, versioning, public access |
| CloudTrail | Describe*, GetTrailStatus | Verify logging is active |
| GuardDuty | List*, Get* | Verify threat detection is active |
| Config | Describe* | Verify configuration recording |
| Inspector2 | BatchGet*, List* | Check vulnerability scanning |
| RDS, Lambda, KMS, ECS, CloudWatch | List*/Describe* (1 call each) | Service discovery only |

**Total: 42 read-only API permissions. Zero write permissions.**

---

## Step 3: Configure AWS Access

### Option A: AWS CLI Profile (Recommended)

```bash
aws configure --profile shasta
# Enter your access key ID, secret key, and region (us-east-1)
```

Or if using SSO:
```bash
aws sso login --profile your-sso-profile
```

### Option B: Environment Variables

```bash
export AWS_ACCESS_KEY_ID=AKIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_DEFAULT_REGION=us-east-1
```

---

## Step 4: Verify Connection

Open Claude Code in the `shasta/` directory and run:

```
/connect-aws
```

Or manually:
```bash
python -c "
from shasta.aws.client import AWSClient
c = AWSClient(profile_name='shasta')  # or omit for env vars
info = c.validate_credentials()
services = c.discover_services()
print(f'Connected: {info.account_id} ({info.user_arn})')
print(f'Services: {services}')
"
```

---

## Step 5: Run Your First Scan

```
/scan
```

This runs all compliance checks (IAM, networking, storage, monitoring, vulnerabilities) and presents findings with plain-English explanations and remediation guidance.

---

## Step 6: Generate Reports

```
/report
```

Generates Markdown, HTML, and PDF compliance reports in `data/reports/`.

---

## Step 7: Generate Policy Documents

```
/policy-gen
```

Generates 8 SOC 2 policy documents tailored to your company name. Review and customize before adopting.

---

## Step 8 (Optional): Deploy Continuous Monitoring

This is the **only step that requires write access** to your AWS account, and it's done via Terraform that you review and apply yourself.

The monitoring infrastructure includes:
- AWS Config Rules for real-time compliance detection
- EventBridge rules for high-risk event alerting
- SNS topic for alert pipeline
- Lambda function for Slack/Jira integration
- SecurityHub aggregation
- AWS Inspector for vulnerability scanning

```bash
cd infra/test-env

# Review the Terraform before applying
terraform init
terraform plan

# Apply when satisfied
terraform apply
```

**Required permissions for monitoring deployment:**
This step requires elevated permissions (administrator or a policy with create access for Config, EventBridge, SNS, Lambda, SecurityHub, Inspector, and IAM roles). This is a one-time setup.

After deployment, you can configure Slack and Jira:
```bash
terraform apply \
  -var="slack_webhook_url=https://hooks.slack.com/services/YOUR/WEBHOOK/URL" \
  -var="jira_base_url=https://yourcompany.atlassian.net" \
  -var="jira_email=you@company.com" \
  -var="jira_api_token=YOUR_JIRA_TOKEN" \
  -var="jira_project_key=COMP"
```

---

## Ongoing Compliance

| Task | Frequency | Shasta Command |
|------|-----------|----------------|
| Full compliance scan | Weekly | `/scan` |
| Gap analysis | Monthly | `/gap-analysis` |
| Access review | Quarterly | `/review-access` |
| Evidence collection | Monthly | `/evidence` |
| Report generation | As needed | `/report` |
| Policy review | Annually | Review files in `data/policies/` |

---

## What Shasta Does NOT Do

- **Never modifies your AWS environment** — all changes are your responsibility
- **Never stores credentials** — uses standard AWS credential chain
- **Never sends data externally** — all data stays on your machine
- **Never auto-applies fixes** — generates Terraform/instructions for you to review

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `NoCredentialsError` | Run `aws configure` or set env vars |
| `AccessDenied` on a check | Verify the IAM policy has the required permissions (see table above) |
| `LoginRefreshRequired` | Run `aws sso login --profile <profile>` |
| Inspector checks fail | Inspector may not be enabled — deploy monitoring infra (Step 8) |
| PDF generation fails | Install system dependencies: `pip install xhtml2pdf` |
