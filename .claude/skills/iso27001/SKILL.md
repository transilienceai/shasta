---
name: iso27001
description: Run an ISO 27001:2022 Annex A gap analysis against your AWS environment.
user-invocable: true
---

# ISO 27001 Gap Analysis

You are running an ISO 27001:2022 compliance assessment for a founder. Same AWS checks as SOC 2, but mapped to ISO 27001 Annex A controls.

## What to do

Read `shasta.config.json` for `python_cmd`. Use that for all commands (shown as `<PYTHON_CMD>`).

### Run ISO 27001 scan + generate report

```bash
<PYTHON_CMD> -c "
import json
from shasta.config import get_aws_client
from shasta.scanner import run_full_scan
from shasta.compliance.iso27001_mapper import get_iso27001_control_summary
from shasta.compliance.iso27001_scorer import calculate_iso27001_score
from shasta.reports.iso27001_report import save_iso27001_markdown_report
from shasta.db.schema import ShastaDB

client = get_aws_client()
client.validate_credentials()
print('Running ISO 27001 compliance scan...')
scan = run_full_scan(client, framework='iso27001')

db = ShastaDB(); db.initialize(); db.save_scan(scan)

report_path = save_iso27001_markdown_report(scan)
print(f'Report saved: {report_path}')

score = calculate_iso27001_score(scan.findings)
controls = get_iso27001_control_summary(scan.findings)

output = {
    'report_path': str(report_path),
    'score': {
        'percentage': score.score_percentage,
        'grade': score.grade,
        'passing': score.passing,
        'failing': score.failing,
        'requires_policy': score.requires_policy,
    },
    'by_theme': {
        'organizational': {'pass': score.organizational_pass, 'fail': score.organizational_fail},
        'technological': {'pass': score.technological_pass, 'fail': score.technological_fail},
        'people': {'pass': score.people_pass, 'fail': score.people_fail},
    },
    'controls': {
        k: {
            'title': v['title'],
            'theme': v['theme'],
            'status': v['overall_status'],
            'pass': v['pass_count'],
            'fail': v['fail_count'],
            'soc2_equiv': v['soc2_equivalent'],
        }
        for k, v in controls.items()
        if v['has_automated_checks'] or v['overall_status'] != 'not_assessed'
    }
}
print(json.dumps(output, indent=2))
"
```

### Present results

- **Score and grade** — explain ISO 27001 certification readiness
- **Report path** — mention the saved Markdown report
- **By theme:** Organizational, People, Technological status
- **Control-by-control breakdown** — grouped by theme
- For each failing control: what it requires, what's missing, how to fix
- **Cross-reference to SOC 2:** "Fixing A.5.15 also addresses SOC 2 CC6.1 — 80% of the work overlaps"
- **Policy-required controls:** which need documentation vs. technical fixes
- Suggest `/report` for PDF generation, `/remediate` for fix guidance, `/policy-gen` for policy documents
