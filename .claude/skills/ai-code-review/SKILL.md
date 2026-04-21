---
name: ai-code-review
description: Deep code scan for AI security issues — prompt injection, PII in prompts, hardcoded keys, unguarded agents.
user-invocable: true
---

# AI Code Review

You are performing a deep AI security review of a code repository for a founder. Focus on practical, actionable findings.

## Prerequisite

Whitney is a separate open-source tool shipped at
[`github.com/transilienceai/whitney`](https://github.com/transilienceai/whitney).
Install it first if it is not already on `PATH`:

```bash
pip install whitney
```

The `whitney` CLI does the static detection. This skill wraps it with
plain-English explanations and severity grouping.

## What to do

Read `shasta.config.json` for `python_cmd`. Scan the current directory
or a specified path by calling `whitney scan --json`.

### Run code review

```bash
whitney scan . --json > /tmp/whitney-findings.json
```

If `whitney` is not installed, fall back to the module form:

```bash
<PYTHON_CMD> -m whitney.cli scan . --json > /tmp/whitney-findings.json
```

Then parse and group the output:

```bash
<PYTHON_CMD> -c "
import json
from collections import defaultdict

data = json.load(open('/tmp/whitney-findings.json'))
by_severity = defaultdict(list)
for f in data:
    details = f.get('details', {}) or {}
    by_severity[f.get('severity', 'info')].append({
        'check_id': f.get('check_id'),
        'title': f.get('title'),
        'file': details.get('file_path', 'unknown'),
        'line': details.get('line_number', '?'),
        'cwe': details.get('cwe', []),
        'owasp': details.get('owasp', []),
        'owasp_agentic': details.get('owasp_agentic', []),
        'snippet': details.get('code_snippet', ''),
        'remediation': f.get('remediation', ''),
    })

print(json.dumps({
    'total': len(data),
    'critical': len(by_severity.get('critical', [])),
    'high': len(by_severity.get('high', [])),
    'medium': len(by_severity.get('medium', [])),
    'low': len(by_severity.get('low', [])),
    'findings': dict(by_severity),
}, indent=2))
"
```

### Present results

For each finding:
- Show the file path and line number
- Show the code snippet (3 lines of context)
- Include CWE, OWASP LLM Top 10, and OWASP Agentic tags
- Explain what the risk is in plain English
- Provide specific remediation steps

Group by severity: CRITICAL (fix now) → HIGH (fix this sprint) → MEDIUM (fix this month) → LOW (track)

### Tone
- Be specific about what's wrong and how to fix it
- Show the actual code that's problematic
- Provide the fixed code where possible

### Why not compliance frameworks?

Whitney emits raw findings with CWE and the two OWASP families baked
in. Regulatory framework enrichment (ISO 42001, EU AI Act, NIST AI RMF,
MITRE ATLAS) is Shasta's job — the `/ai-scan` skill adds those tags as
a post-processing step via `shasta.compliance.ai.mapper`.
