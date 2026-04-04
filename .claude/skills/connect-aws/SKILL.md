---
name: connect-aws
description: Connect to an AWS account, validate credentials, and discover what services are in use.
user-invocable: true
---

# Connect AWS

You are helping a semi-technical founder connect Shasta to their AWS account for SOC 2 compliance scanning.

## Configuration

Shasta uses `shasta.config.json` in the project root for all settings. Before running any commands, check if this file has `aws_profile` set. If not, you'll need to configure it.

## What to do

1. **Check if shasta.config.json is configured.** Read the file. If `aws_profile` is empty, ask the user:
   - What is your AWS CLI profile name? (run `aws configure list-profiles` to show options)
   - Or are they using environment variables?
   - What region? (default: us-east-1)
   - What is their company name? (for policy generation later)
   
   Update `shasta.config.json` with their answers.

2. **Also detect the correct Python command.** Run `python3 --version` and `python --version` to find which works. Update `python_cmd` in the config.

3. **Validate AWS credentials** by running (substitute the correct python command and profile):
   ```bash
   <PYTHON_CMD> -c "
   from shasta.config import get_aws_client
   c = get_aws_client()
   info = c.validate_credentials()
   services = c.discover_services()
   print(f'AWS Account: {info.account_id}')
   print(f'Aliases: {info.account_aliases or [\"none\"]}')
   print(f'Identity: {info.user_arn}')
   print(f'Region: {info.region}')
   print(f'Services detected: {services if services else \"none (empty account)\"}')
   "
   ```

4. **Initialize the Shasta database**:
   ```bash
   <PYTHON_CMD> -c "from shasta.db.schema import ShastaDB; db = ShastaDB(); db.initialize(); print('Database initialized at data/shasta.db')"
   ```

5. **Present results** in a clear, friendly format and suggest running `/scan` next.

## Important notes

- **Never ask the user to paste AWS credentials into the chat.** Always use AWS CLI configuration or environment variables.
- Replace `<PYTHON_CMD>` with whatever works on this machine (`python3`, `python`, or `py -3.12`).
- If credentials fail, guide them through `aws configure --profile <name>` or `aws sso login`.
- The IAM role needs ReadOnly access. The scoped policy is at `infra/shasta-scanning-policy.json` (42 read-only permissions).
