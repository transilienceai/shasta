---
name: remediate
description: Get interactive remediation guidance for compliance findings, including Terraform code and step-by-step instructions.
user-invocable: true
---

# Remediate

Help a founder fix their SOC 2 compliance issues. Be specific, actionable, encouraging.

## What to do

Read `shasta.config.json` for `python_cmd`. Use that for all commands (shown as `<PYTHON_CMD>`).

### Step 1: Check for recent scan

```bash
<PYTHON_CMD> -c "
from shasta.db.schema import ShastaDB
db = ShastaDB(); db.initialize()
scan = db.get_recent_scan(max_age_minutes=60)
if scan:
    print(f'RECENT_SCAN|{scan.id}|{scan.completed_at}|{len(scan.findings)} findings')
else:
    print('NO_RECENT_SCAN')
"
```

### Step 2: Generate remediations (from recent or fresh scan)

Using recent scan:
```bash
<PYTHON_CMD> -c "
import json
from shasta.db.schema import ShastaDB
from shasta.remediation.engine import generate_all_remediations, save_terraform_bundle
db = ShastaDB(); db.initialize()
scan = db.get_latest_scan()
print(f'Using scan from {scan.completed_at}')
remediations = generate_all_remediations(scan.findings)
tf_path = save_terraform_bundle(remediations)
print(json.dumps({
    'terraform_file': str(tf_path), 'total': len(remediations),
    'remediations': [{'title': r.finding.title, 'severity': r.finding.severity.value,
        'effort': r.effort, 'explanation': r.explanation, 'steps': r.steps,
        'has_terraform': bool(r.terraform), 'soc2_controls': r.finding.soc2_controls,
    } for r in remediations]
}, indent=2))
"
```

Or from fresh scan:
```bash
<PYTHON_CMD> -c "
import json
from shasta.config import get_aws_client
from shasta.scanner import run_full_scan
from shasta.remediation.engine import generate_all_remediations, save_terraform_bundle
from shasta.db.schema import ShastaDB
client = get_aws_client(); client.validate_credentials()
scan = run_full_scan(client)
db = ShastaDB(); db.initialize(); db.save_scan(scan)
remediations = generate_all_remediations(scan.findings)
tf_path = save_terraform_bundle(remediations)
print(json.dumps({
    'terraform_file': str(tf_path), 'total': len(remediations),
    'remediations': [{'title': r.finding.title, 'severity': r.finding.severity.value,
        'effort': r.effort, 'explanation': r.explanation, 'steps': r.steps,
        'has_terraform': bool(r.terraform), 'soc2_controls': r.finding.soc2_controls,
    } for r in remediations]
}, indent=2))
"
```

### Step 3: Present interactively
- Group by priority/effort, quick wins first
- Plain-English explanation, numbered steps, Terraform code blocks
- Offer to help apply fixes, then re-scan to verify
