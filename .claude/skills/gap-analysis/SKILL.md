---
name: gap-analysis
description: Run a full SOC 2 gap analysis against the connected AWS account and present findings with remediation guidance.
user-invocable: true
---

# Gap Analysis

You are performing a SOC 2 gap analysis for a semi-technical founder.

## What to do

Read `shasta.config.json` for `python_cmd`. Use that for all commands (shown as `<PYTHON_CMD>`).

### Step 1: Get scan data (reuse recent or run fresh)

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

If recent scan exists, tell the user and ask if they want to reuse it. If reusing:

```bash
<PYTHON_CMD> -c "
from shasta.db.schema import ShastaDB
from shasta.reports.generator import save_markdown_report, save_html_report
db = ShastaDB(); db.initialize()
scan = db.get_latest_scan()
md = save_markdown_report(scan)
html = save_html_report(scan)
print(f'Markdown: {md}')
print(f'HTML: {html}')
print(f'Based on scan from {scan.completed_at}')
"
```

If running fresh:
```bash
<PYTHON_CMD> -c "
from shasta.config import get_aws_client
from shasta.scanner import run_full_scan
from shasta.reports.generator import save_markdown_report, save_html_report
from shasta.db.schema import ShastaDB
client = get_aws_client(); client.validate_credentials()
print('Running full compliance scan...')
scan = run_full_scan(client)
db = ShastaDB(); db.initialize(); db.save_scan(scan)
md = save_markdown_report(scan)
html = save_html_report(scan)
print(f'Markdown: {md}')
print(f'HTML: {html}')
print(f'Scan completed at {scan.completed_at}')
"
```

### Step 2: Present interactively
- **Show scan timestamp** — "Based on scan from <time>"
- Read the Markdown report and present like a consultant
- Group by SOC 2 control, explain what auditor expects, what's missing, how to fix
- Offer `/remediate` for specific findings
