---
name: ai-scan
description: Run AI governance checks across cloud accounts and code repos — ISO 42001, EU AI Act, NIST AI RMF compliance.
user-invocable: true
---

# AI Governance Scan

You are running an AI governance scan for a founder. Explain findings in plain English with founder-friendly analogies.

## What to do

Read `shasta.config.json` for `python_cmd`, `aws_profile`, `azure_subscription_id`. Use that for all commands.

### Run AI governance scan

Whitney (the code scanner) ships as a separate open-source tool at
[github.com/transilienceai/whitney](https://github.com/transilienceai/whitney).
If it isn't installed yet, run `pip install whitney` first.
This skill shells out to the `whitney` CLI for source-code findings
and imports the Shasta cloud AI checks directly for cloud findings.

```bash
# 1. Run the Whitney static scanner against the current repo.
whitney scan . --json > /tmp/whitney-findings.json 2>/dev/null || \
    echo '[]' > /tmp/whitney-findings.json

# 2. Run Shasta cloud AI checks + enrich everything with compliance frameworks.
<PYTHON_CMD> -c "
import json
from pathlib import Path
from shasta.evidence.models import (
    CheckDomain, ComplianceStatus, Finding, Severity,
)

# --- Code findings: parse Whitney JSON into Shasta Finding objects ---
code_findings = []
raw = json.loads(Path('/tmp/whitney-findings.json').read_text())
for r in raw:
    code_findings.append(Finding(
        check_id=r['check_id'],
        title=r['title'],
        description=r.get('description', ''),
        severity=Severity(r['severity']),
        status=ComplianceStatus.FAIL,
        domain=CheckDomain.AI_GOVERNANCE,
        resource_type=r.get('resource_type', 'Code::Repository::File'),
        resource_id=r.get('resource_id', ''),
        region=r.get('region', 'code'),
        account_id=r.get('account_id', 'code-scan'),
        remediation=r.get('remediation', ''),
        soc2_controls=r.get('soc2_controls', []) or [],
        details=r.get('details', {}) or {},
    ))

# --- Cloud checks (if configured) ---
cloud_findings = []
try:
    from shasta.config import load_config
    cfg = load_config()
    if cfg.get('aws_profile'):
        from shasta.config import get_aws_client
        from shasta.aws.ai_checks import run_full_aws_ai_scan
        client = get_aws_client()
        client.validate_credentials()
        cloud_findings.extend(run_full_aws_ai_scan(client))
    if cfg.get('azure_subscription_id'):
        from shasta.config import get_azure_client
        from shasta.azure.ai_checks import run_full_azure_ai_scan
        azure_client = get_azure_client()
        azure_client.validate_credentials()
        cloud_findings.extend(run_full_azure_ai_scan(azure_client))
except Exception as e:
    print(f'Cloud scan note: {e}')

all_findings = code_findings + cloud_findings

# Enrich with AI compliance frameworks (ISO 42001, EU AI Act, NIST AI RMF,
# MITRE ATLAS) — Whitney only ships CWE + OWASP LLM Top 10 + OWASP Agentic
# natively; the regulatory frameworks are added here by Shasta.
from shasta.compliance.ai.mapper import enrich_findings_with_ai_controls
enrich_findings_with_ai_controls(all_findings)

# Score
from shasta.compliance.ai.scorer import calculate_ai_governance_score
score = calculate_ai_governance_score(all_findings)

# Summary
passed = sum(1 for f in all_findings if f.status == ComplianceStatus.PASS)
failed = sum(1 for f in all_findings if f.status == ComplianceStatus.FAIL)
critical = sum(1 for f in all_findings if f.severity.value == 'critical' and f.status == ComplianceStatus.FAIL)
high = sum(1 for f in all_findings if f.severity.value == 'high' and f.status == ComplianceStatus.FAIL)

print(json.dumps({
    'total_findings': len(all_findings),
    'passed': passed,
    'failed': failed,
    'critical': critical,
    'high': high,
    'code_findings': len(code_findings),
    'cloud_findings': len(cloud_findings),
    'score': {
        'iso42001_score': score.iso42001_score,
        'iso42001_grade': score.iso42001_grade,
        'eu_ai_act_score': score.eu_ai_act_score,
        'eu_ai_act_grade': score.eu_ai_act_grade,
        'combined_score': score.combined_score,
        'combined_grade': score.combined_grade,
    },
    'findings': [
        {
            'check_id': f.check_id,
            'title': f.title,
            'severity': f.severity.value,
            'status': f.status.value,
            'resource_id': f.resource_id,
            'remediation': f.remediation,
        }
        for f in all_findings if f.status in (ComplianceStatus.FAIL, ComplianceStatus.PARTIAL)
    ]
}, indent=2))
"
```

### Present results

- Show AI governance score (ISO 42001 + EU AI Act) and grade
- Group findings by severity (CRITICAL first)
- For code findings: show file path and line number
- For cloud findings: show resource ID
- Explain each finding in plain English with remediation
- Suggest running `/ai-code-review` for detailed code analysis
- Mention the AI compliance frameworks being assessed

### Tone
- Treat AI governance as the "next frontier" — frame it positively, not punitively
- Acknowledge that most startups haven't done this yet — Whitney helps them get ahead of the curve
