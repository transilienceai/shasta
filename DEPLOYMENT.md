# Shasta Deployment Guide

Deploy Shasta and Whitney to scan your cloud environments and AI systems for SOC 2, ISO 27001, ISO 42001, and EU AI Act compliance. This guide walks you through setup in under 30 minutes.

## Prerequisites

- **Python 3.11+** installed
- **AWS CLI** configured with SSO or IAM credentials (for AWS scanning)
- **Azure CLI** configured with `az login` (for Azure scanning)
- **Terraform** installed (for deploying monitoring infrastructure)
- **Claude Code** installed (for interactive compliance guidance)
- **Git** (to clone the repo)
- **GitHub Personal Access Token** (optional — for GitHub integration and Whitney code scanning of private repos)

---

## Step 1: Clone and Install

```bash
git clone https://github.com/kkmookhey/shasta.git
cd shasta
pip install -e ".[dev]"           # Core + dev tools
pip install -e ".[azure]"         # Add Azure support (optional)
pip install -e ".[dev,azure]"     # Everything
```

Verify installation:
```bash
python -c "import shasta; print('Shasta installed successfully')"
python -c "from shasta.azure.client import AzureClient; print('Azure support installed')"
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

## Step 3b: Configure Azure Access (Optional)

If you're scanning Azure environments in addition to or instead of AWS:

### Login and identify your subscription

```bash
az login
az account show
# Note: subscription_id, tenant_id from the output
```

### Set your active subscription (if you have multiple)

```bash
az account set --subscription "YOUR_SUBSCRIPTION_ID"
```

Azure scanning uses `DefaultAzureCredential` from the Azure SDK, which automatically picks up your `az login` session. No service principal is needed for dev/testing.

**Permissions required:** Reader role on the subscription (for infrastructure checks) plus Graph API permissions for Entra ID checks:
- `User.Read.All` — user enumeration and activity
- `Policy.Read.All` — Conditional Access policies (requires Entra ID P1/P2)
- `RoleManagement.Read.Directory` — privileged role assignments
- `Application.Read.All` — app registration credential audit

If Graph API permissions are missing, the corresponding checks will return `NOT_ASSESSED` (not errors).

---

## Step 4: Verify Connection

Open Claude Code in the `shasta/` directory and run:

```
/connect-aws      # For AWS
/connect-azure    # For Azure
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

## Step 8: Configure Integrations (Optional)

### GitHub Integration

Shasta checks GitHub branch protection, required PR reviews, and CI/CD status checks (CC8.1 — Change Management). Whitney scans code repositories for AI security issues.

**1. Create a GitHub Personal Access Token (PAT):**
- Go to GitHub > Settings > Developer settings > Personal access tokens > Fine-grained tokens
- Create a token with `repo` scope (read-only) for the repositories you want to scan
- For org repos, you may need org admin approval

**2. Add to config:**

Update `shasta.config.json`:
```json
{
  "github_repos": ["your-org/repo-1", "your-org/repo-2"],
  "github_token": "ghp_..."
}
```

Or pass the token at runtime (recommended — avoids storing tokens in config files):
```bash
export GITHUB_TOKEN=ghp_...
```

**3. Verify:**
```
/scan              # Includes GitHub checks if github_repos is configured
/ai-code-review    # Whitney scans the current directory for AI security issues
```

**Note:** For a production setup, use a **GitHub App** instead of PATs. GitHub Apps provide:
- Fine-grained, read-only permissions per repository
- Org-level installation (no personal token needed)
- Automatic token rotation
- Audit trail of app access

### Slack Integration

Shasta sends scan summaries, finding alerts, drift reports, and threat advisories to Slack.

**1. Create a Slack Incoming Webhook:**
- Go to [api.slack.com/apps](https://api.slack.com/apps) > Create New App > From scratch
- Choose your workspace
- Go to Incoming Webhooks > Activate > Add New Webhook to Workspace
- Select the channel where you want compliance alerts
- Copy the webhook URL

**2. Add to config:**

Update `shasta.config.json`:
```json
{
  "slack_webhook_url": "https://hooks.slack.com/services/T.../B.../xxxx"
}
```

**3. What you'll receive in Slack:**
- Scan summaries with compliance score and grade (color-coded)
- Individual finding alerts grouped by severity
- Weekly drift reports (improvements and regressions)
- Daily personalized threat advisories (filtered to your tech stack)

**Note:** This is a one-way integration (Shasta → Slack). For a richer experience (Slack commands triggering scans, interactive approval buttons), you'd need a full Slack App — see the roadmap.

### Jira Integration

Shasta auto-creates Jira tickets for critical and high severity findings with full descriptions, labels, and priority.

**1. Create a Jira API Token:**
- Go to [id.atlassian.com/manage-profile/security/api-tokens](https://id.atlassian.com/manage-profile/security/api-tokens)
- Create a new API token
- Note your Jira email and the project key where tickets should be created

**2. Add to config:**

Update `shasta.config.json`:
```json
{
  "jira_base_url": "https://yourcompany.atlassian.net",
  "jira_email": "you@company.com",
  "jira_api_token": "your-api-token",
  "jira_project_key": "SEC"
}
```

**3. What gets created:**
- One ticket per critical/high finding
- Atlassian Document Format descriptions with finding details
- Labels: `shasta`, `compliance`, severity level
- Priority mapped from finding severity

**Security note:** The Jira API token is sent via Basic Auth (Base64-encoded, not encrypted). Always use HTTPS URLs. In a production setup, store the token in a secrets manager rather than in `shasta.config.json`.

---

## Step 9 (Optional): Set Up Whitney AI Governance

Whitney scans your AI/ML services and code repositories for AI-specific security and compliance issues.

### What Whitney covers

- **Code scanning:** Hardcoded AI API keys, prompt injection risks, PII in prompts, unguarded AI agents (15 checks)
- **AWS AI services:** Bedrock guardrails, SageMaker security, Lambda AI key exposure (15 checks)
- **Azure AI services:** OpenAI content filters, ML workspace security, Cognitive Services (15 checks)
- **Frameworks:** ISO 42001 (AI Management Systems), EU AI Act, NIST AI RMF

### Setup

No additional installation needed — Whitney is included in the Shasta package.

**1. Run AI discovery:**
```
/discover-ai
```
This scans your cloud accounts for AI/ML services (SageMaker, Bedrock, Azure OpenAI, etc.) and your code for AI SDK usage.

**2. Run AI governance scan:**
```
/ai-scan
```
Runs all AI checks (cloud + code) and scores against ISO 42001 and EU AI Act.

**3. Deep code review:**
```
/ai-code-review
```
Detailed AI security review of the current repository with file paths, line numbers, and fix suggestions.

### Permissions for AI cloud checks

**AWS (additional to Step 2 permissions):**

| Service | Permissions | Why |
|---------|-------------|-----|
| Bedrock | `bedrock:ListFoundationModels`, `bedrock:ListGuardrails`, `bedrock:GetGuardrail` | Check guardrails and content filters |
| SageMaker | `sagemaker:ListEndpoints`, `sagemaker:ListModels`, `sagemaker:ListNotebookInstances`, `sagemaker:DescribeEndpoint` | Check model security and access |
| Lambda | `lambda:ListFunctions`, `lambda:GetFunction` | Detect AI API keys in env vars |
| CloudTrail | `cloudtrail:GetEventSelectors` | Verify AI event logging |

**Azure (additional to Step 3b permissions):**

| Service | Permissions | Why |
|---------|-------------|-----|
| Cognitive Services | `Microsoft.CognitiveServices/accounts/read` | Check OpenAI and Cognitive Service configs |
| Machine Learning | `Microsoft.MachineLearningServices/workspaces/read` | Check ML workspace security |
| Monitor | `Microsoft.Insights/diagnosticSettings/read` | Verify AI service logging |

If these permissions are missing, the corresponding checks return `NOT_ASSESSED` — not errors.

---

## Step 10 (Optional): Launch the Web Dashboard

Shasta includes a local web dashboard for visual compliance monitoring.

### Install dashboard dependencies

```bash
pip install -e ".[dashboard]"
```

### Launch

```bash
python -m shasta.dashboard
# Or in Claude Code:
/dashboard
```

The dashboard runs at **http://127.0.0.1:8080** and shows:
- Compliance score gauges (SOC 2, ISO 27001, HIPAA) with letter grades
- Score trend chart over time (last 10 scans)
- Findings severity breakdown with filtering (by cloud, domain, severity, status)
- Control status grid with framework tabs
- Scan history with grade badges
- Risk register table

The dashboard reads from the same SQLite database that `/scan` writes to — no additional configuration needed.

---

## Step 11 (Optional): Auto-Fill Security Questionnaires

When a customer or prospect sends you a security questionnaire, Shasta can auto-fill ~70% of the answers from your latest scan data.

```
/questionnaire
```

Choose from:
- **SIG Lite** (79 questions) — Standardized Information Gathering
- **CAIQ** (80 questions) — Cloud Security Alliance Consensus Assessment
- **Generic Enterprise** (40 questions) — Common enterprise buyer questions

Output is saved to `data/questionnaires/` as both CSV (for spreadsheet import) and Markdown (for review). Each answer includes:
- Yes/No/Partial determination based on scan findings
- Confidence level (high/medium/low/manual)
- Evidence references (e.g., "See control test CT-IAM-003")

Questions that can't be auto-filled are marked "Manual review required."

---

## Step 12 (Optional): Deploy Continuous Monitoring

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

| Task | Frequency | Command |
|------|-----------|---------|
| Full compliance scan (cloud) | Weekly | `/scan` |
| AI governance scan | Weekly | `/ai-scan` |
| HIPAA gap analysis | Monthly | `/hipaa` |
| Gap analysis | Monthly | `/gap-analysis` |
| Access review | Quarterly | `/review-access` |
| Evidence collection | Monthly | `/evidence` |
| Report generation | As needed | `/report` |
| Security questionnaires | As received | `/questionnaire` |
| Dashboard review | Anytime | `/dashboard` |
| Policy review | Annually | Review files in `data/policies/` |
| AI code review | Per release / PR | `/ai-code-review` |
| Risk register review | Quarterly | `/risk-register` |

---

## What Shasta Does NOT Do

- **Never modifies your cloud environment** — all changes are your responsibility
- **Never stores cloud credentials** — uses standard AWS credential chain and Azure DefaultAzureCredential
- **Never sends data externally** — all data stays on your machine (except Slack/Jira if configured)
- **Never auto-applies fixes** — generates Terraform/instructions for you to review
- **Never pushes to your GitHub repos** — code scanning is read-only (clone + analyze)

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `NoCredentialsError` | Run `aws configure` or set env vars |
| `AccessDenied` on a check | Verify the IAM policy has the required permissions (see tables above) |
| `LoginRefreshRequired` | Run `aws sso login --profile <profile>` |
| Azure `AzureClientError` | Run `az login` or `az account set --subscription <ID>` |
| Inspector checks fail | Inspector may not be enabled — deploy monitoring infra (Step 10) |
| PDF generation fails | Install system dependencies: `pip install xhtml2pdf` |
| Azure SDK not installed | Run `pip install -e ".[azure]"` |
| GitHub checks return empty | Verify `github_repos` in config and that the PAT has `repo` scope |
| Slack messages not arriving | Verify the webhook URL is correct and the channel exists |
| Jira tickets not created | Verify `jira_base_url` starts with `https://`, email and API token are correct |
| Whitney NOT_ASSESSED on AI checks | AI services (Bedrock, SageMaker, Azure OpenAI) may not be deployed — this is expected |
| Code scan finds nothing | Your repo may not use AI SDKs — this means zero AI security issues (good!) |
