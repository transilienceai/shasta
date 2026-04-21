---
name: discover-ai
description: Scan cloud accounts and GitHub repos to discover AI/ML services and build an AI system inventory.
user-invocable: true
---

# Discover AI

You are helping a founder discover what AI/ML services are running in their cloud accounts and code repositories.

## What to do

Read `shasta.config.json` for `python_cmd`, `aws_profile`, `azure_subscription_id`, and `github_repos`. Use that for all commands (shown as `<PYTHON_CMD>`).

### 1. Discover cloud AI services

**For AWS (if `aws_profile` is set):**
```bash
<PYTHON_CMD> -c "
import json
from shasta.config import get_aws_client
from shasta.aws.ai_discovery import discover_aws_ai_services

client = get_aws_client()
client.validate_credentials()
result = discover_aws_ai_services(client)
print(json.dumps(result, indent=2, default=str))
"
```

**For Azure (if `azure_subscription_id` is set):**
```bash
<PYTHON_CMD> -c "
import json
from shasta.config import get_azure_client
from shasta.azure.ai_discovery import discover_azure_ai_services

client = get_azure_client()
client.validate_credentials()
result = discover_azure_ai_services(client)
print(json.dumps(result, indent=2, default=str))
"
```

### 2. Scan GitHub repos for AI usage

Whitney is the standalone source-code scanner, shipped at
[github.com/transilienceai/whitney](https://github.com/transilienceai/whitney).
Install with `pip install whitney` if it is not already present.

```bash
whitney scan . --json > /tmp/whitney-findings.json 2>/dev/null || echo '[]' > /tmp/whitney-findings.json
<PYTHON_CMD> -c "
import json
data = json.load(open('/tmp/whitney-findings.json'))
for f in data:
    sev = (f.get('severity') or 'info').upper()
    print(f'[{sev}] {f.get(\"check_id\")}: {f.get(\"title\")}')
print(f'\nTotal: {len(data)} finding(s)')
"
```

### 3. Present results

Show a clear AI system inventory:
- Cloud AI services discovered (by service type and count)
- AI SDKs found in code (with versions)
- Any security issues found (hardcoded keys, prompt injection risks, etc.)
- Suggest running `/ai-scan` for full compliance assessment
