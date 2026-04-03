---
name: connect-aws
description: Connect to an AWS account, validate credentials, and discover what services are in use.
user_invocable: true
---

# Connect AWS

You are helping a semi-technical founder connect Shasta to their AWS account for SOC 2 compliance scanning.

## What to do

1. **Check for existing AWS credentials** by running:
   ```bash
   python -c "from shasta.aws.client import AWSClient; c = AWSClient(); info = c.validate_credentials(); print(f'Connected to AWS account {info.account_id} ({info.account_aliases or [\"no alias\"]})\nIdentity: {info.user_arn}\nRegion: {info.region}')"
   ```

2. **If credentials fail**, guide the user through setup:
   - Ask which method they prefer: AWS CLI profile, environment variables, or SSO
   - For CLI profile: `aws configure --profile shasta`
   - For env vars: set `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and optionally `AWS_DEFAULT_REGION`
   - For SSO: `aws sso login --profile <profile>`
   - Remind them the IAM user/role needs **ReadOnly** access at minimum (the `ReadOnlyAccess` AWS managed policy works)

3. **Once connected**, discover services in use:
   ```bash
   python -c "
   from shasta.aws.client import AWSClient
   c = AWSClient()
   info = c.validate_credentials()
   services = c.discover_services()
   print(f'\nAWS Account: {info.account_id}')
   print(f'Aliases: {info.account_aliases or [\"none\"]}')
   print(f'Identity: {info.user_arn}')
   print(f'Region: {info.region}')
   print(f'\nServices detected: {services if services else \"none (empty account)\"}')
   "
   ```

4. **Initialize the Shasta database**:
   ```bash
   python -c "from shasta.db.schema import ShastaDB; db = ShastaDB(); db.initialize(); print('Database initialized at data/shasta.db')"
   ```

5. **Present results** in a clear, friendly format:
   - Account ID and alias
   - Who you're authenticated as
   - Which region
   - Which services were detected
   - What Shasta will scan based on detected services
   - Next step: suggest running `/scan` to start the compliance check

## Important notes

- Never ask the user to paste AWS credentials into the chat. Always use AWS CLI configuration or environment variables.
- If the user has multiple accounts, ask which one they want to scan.
- If the user's IAM permissions are too restrictive, list which specific permissions Shasta needs.
- Be encouraging — this is likely their first step toward SOC 2 compliance.

## Required permissions

The connected IAM identity needs at minimum:
- `sts:GetCallerIdentity`
- `iam:List*`, `iam:Get*`
- `s3:ListAllMyBuckets`, `s3:GetBucket*`
- `ec2:Describe*`
- `rds:Describe*`
- `lambda:List*`
- `cloudtrail:Describe*`, `cloudtrail:GetTrailStatus`
- `guardduty:List*`
- `kms:List*`
- `ecs:List*`
- `cloudwatch:Describe*`
- `config:Describe*`

The `ReadOnlyAccess` managed policy covers all of these.
