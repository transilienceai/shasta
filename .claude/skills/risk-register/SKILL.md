---
name: risk-register
description: Create and manage a SOC 2 risk register — auto-seeds from scan findings, tracks treatment, produces audit evidence.
user-invocable: true
---

# Risk Register

You are helping a founder create and maintain a risk register for SOC 2 CC3.1 compliance.

## What to do

Read `shasta.config.json` for `python_cmd`. Use that for all commands (shown as `<PYTHON_CMD>`).

### Step 1: Check for existing register or auto-seed

```bash
<PYTHON_CMD> -c "
import json
from shasta.db.schema import ShastaDB
db = ShastaDB(); db.initialize()

# Check for existing scan to seed from
scan = db.get_recent_scan(max_age_minutes=1440)  # 24 hours
existing_risks = db.get_risk_items(scan.account_id if scan else 'unknown')

if existing_risks:
    print(f'EXISTING_REGISTER|{len(existing_risks)} risks')
    for r in existing_risks:
        print(f'  [{r[\"risk_level\"].upper():6s}] {r[\"risk_id\"]}: {r[\"title\"]} ({r[\"status\"]})')
elif scan:
    print(f'NO_REGISTER_FOUND|scan_available|{len(scan.findings)} findings')
else:
    print('NO_REGISTER_FOUND|no_scan|run /scan first')
"
```

### Step 2: If no register exists, auto-seed from latest scan

```bash
<PYTHON_CMD> -c "
import json
from shasta.db.schema import ShastaDB
from shasta.workflows.risk_register import auto_seed_from_findings, build_register, save_risk_register_report

db = ShastaDB(); db.initialize()
scan = db.get_latest_scan()
if not scan:
    print('ERROR: No scan found. Run /scan first.')
else:
    risks = auto_seed_from_findings(scan.findings, scan.account_id)
    register = build_register(risks, scan.account_id)
    db.save_risk_items(risks, scan.account_id)
    path = save_risk_register_report(register)

    print(json.dumps({
        'report_path': str(path),
        'total_risks': register.total_risks,
        'high': register.high_risk_count,
        'medium': register.medium_risk_count,
        'low': register.low_risk_count,
        'risks': [{
            'id': r.risk_id, 'title': r.title, 'level': r.risk_level,
            'score': r.risk_score, 'treatment': r.treatment,
            'owner': r.owner, 'status': r.status,
        } for r in risks]
    }, indent=2))
"
```

### Step 3: Present interactively

- Show the risk matrix (likelihood x impact grid)
- For each HIGH risk: explain why it's critical and suggest treatment
- Highlight risks that need an owner assigned ("[Assign owner]")
- Explain that the founder should:
  1. Review each auto-generated risk
  2. Assign an owner (themselves for a small team)
  3. Add business/operational risks the scanner can't detect (e.g., "key person dependency", "single cloud vendor lock-in")
  4. Review quarterly and update treatment plans
- The saved report serves as audit evidence for CC3.1
