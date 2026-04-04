---
name: report
description: Generate professional compliance reports (Markdown, HTML, PDF) from the latest scan data.
user-invocable: true
---

# Report

Generate professional SOC 2 compliance reports.

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

If recent scan exists, ask user: "Generate reports from scan at <time>, or run a fresh scan first?"

### Step 2: Generate reports

Using recent scan:
```bash
<PYTHON_CMD> -c "
from shasta.db.schema import ShastaDB
from shasta.reports.generator import save_markdown_report, save_html_report
from shasta.reports.pdf import save_pdf_report
db = ShastaDB(); db.initialize()
scan = db.get_latest_scan()
print(f'Generating reports from scan at {scan.completed_at}...')
md = save_markdown_report(scan)
html = save_html_report(scan)
pdf = save_pdf_report(scan)
print(f'Markdown: {md}')
print(f'HTML:     {html}')
print(f'PDF:      {pdf}')
"
```

Or run fresh scan + generate:
```bash
<PYTHON_CMD> -c "
from shasta.config import get_aws_client
from shasta.scanner import run_full_scan
from shasta.reports.generator import save_markdown_report, save_html_report
from shasta.reports.pdf import save_pdf_report
from shasta.db.schema import ShastaDB
client = get_aws_client(); client.validate_credentials()
print('Running compliance scan...')
scan = run_full_scan(client)
db = ShastaDB(); db.initialize(); db.save_scan(scan)
print('Generating reports...')
md = save_markdown_report(scan); html = save_html_report(scan); pdf = save_pdf_report(scan)
print(f'Markdown: {md}'); print(f'HTML: {html}'); print(f'PDF: {pdf}')
"
```

### Step 3: Tell user where reports are and what each is for
- **Markdown** — working sessions, version control
- **HTML** — sharing via email/browser
- **PDF** — auditors, investors, board
