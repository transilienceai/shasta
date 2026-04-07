---
name: vendor-risk
description: Paste a vendor's domain. Get a security risk assessment in 60 seconds.
user-invocable: true
---

# Vendor Risk Assessment

You are running a third-party vendor risk assessment for a semi-technical founder. Explain findings in plain English. Be direct about risks.

## What to do

Read `shasta.config.json` for `python_cmd` and optionally `hibp_api_key`. Use that for all commands (shown as `<PYTHON_CMD>`).

### Step 1: Get the domain

If the user hasn't provided a domain, ask for it. Examples: "stripe.com", "okta.com", "notion.so".

Optionally, ask:
- Vendor name (defaults to domain)
- Tier: critical / standard / low (defaults to standard)

### Step 2: Check for recent assessment

```bash
<PYTHON_CMD> -c "
from rainier.db import RainierDB
db = RainierDB(); db.initialize()
a = db.get_recent_assessment('<DOMAIN>', max_age_hours=24)
if a:
    print(f'RECENT|{a.id}|{a.completed_at}|{a.risk_grade.value}|{a.risk_score}')
else:
    print('NO_RECENT')
db.close()
"
```

If a recent assessment exists, show the score and ask if they want to reuse it or re-scan.

### Step 3: Run vendor scan

```bash
<PYTHON_CMD> -c "
import json
from rainier.scanner import scan_vendor
from rainier.models import VendorTier
from rainier.db import RainierDB
from rainier.reports.vendor_report import save_vendor_report

assessment = scan_vendor(
    '<DOMAIN>',
    vendor_name='<NAME>',
    tier=VendorTier.<TIER>,
    hibp_api_key='<HIBP_KEY>',
)

db = RainierDB(); db.initialize()

# Create or update vendor record
from rainier.models import Vendor
from datetime import UTC, datetime
vendor = db.get_vendor('<DOMAIN>')
if not vendor:
    vendor = Vendor(name='<NAME>', domain='<DOMAIN>', tier=VendorTier.<TIER>)
vendor.last_assessed = datetime.now(UTC)
vendor.risk_score = assessment.risk_score
vendor.risk_grade = assessment.risk_grade
assessment.vendor_id = vendor.id
db.save_vendor(vendor)
db.save_assessment(assessment)

report_path = save_vendor_report(assessment, vendor)

print(json.dumps({
    'grade': assessment.risk_grade.value,
    'score': assessment.risk_score,
    'signals': assessment.signal_scores,
    'findings_count': len(assessment.findings),
    'summary': assessment.summary,
    'report': str(report_path),
}, indent=2))
db.close()
"
```

### Step 4: Present results

Show results like a security consultant briefing:

1. **Lead with the grade** — e.g., "stripe.com gets a **B** (84/100) — solid security posture with a few gaps."
2. **Signal breakdown** — show each signal's score (e.g., "SSL: A, DNS: B, Headers: C")
3. **Highlight critical/high findings** — explain each in plain English
4. **Tier context** — if a CRITICAL vendor gets a C or below, flag it as concerning
5. **Mention the report** — "Full report saved to data/reports/..."
6. **Next steps** — "Want me to assess another vendor? Or review your full vendor inventory?"

### Vendor inventory commands

To list all assessed vendors:
```bash
<PYTHON_CMD> -c "
import json
from rainier.db import RainierDB
db = RainierDB(); db.initialize()
vendors = db.list_vendors()
for v in vendors:
    grade = v.risk_grade.value if v.risk_grade else '?'
    score = v.risk_score if v.risk_score else '?'
    print(f'{v.domain} | {v.name} | {v.tier.value} | {grade} ({score})')
db.close()
"
```

### Tone
- Security consultant briefing, not audit report
- Be specific: "Their SSL cert expires in 12 days" not "SSL issues detected"
- Plain English: "Anyone can spoof emails from this domain" not "SPF record missing"
- Frame risk in business terms when possible
