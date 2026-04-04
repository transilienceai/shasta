---
name: threat-advisory
description: Generate a personalized threat advisory based on your tech stack — what CVEs, breaches, and supply chain attacks matter to YOU.
user-invocable: true
---

# Threat Advisory

Generate a personalized threat intelligence digest filtered to YOUR tech stack.

## What to do

Read `shasta.config.json` for `python_cmd`. Use that for all commands (shown as `<PYTHON_CMD>`).

1. **Generate the advisory:**
   ```bash
   <PYTHON_CMD> -c "
   import json
   from shasta.config import get_aws_client
   from shasta.sbom.discovery import discover_sbom
   from shasta.threat_intel.advisory import generate_daily_advisory, save_advisory_report

   client = get_aws_client()
   client.validate_credentials()
   print('Building tech stack profile...')
   sbom = discover_sbom(client)
   print('Querying threat feeds...')
   report = generate_daily_advisory(sbom, lookback_days=7)
   path = save_advisory_report(report)
   print(json.dumps({
       'report_path': str(path),
       'tech_stack': report.tech_stack_summary,
       'total_advisories': report.total_advisories,
       'critical': report.critical_count,
       'high': report.high_count,
       'advisories': [{
           'id': a.id, 'title': a.title, 'severity': a.severity,
           'affected': a.affected_component, 'action': a.action_required,
           'is_kev': a.is_kev, 'is_supply_chain': a.is_supply_chain,
       } for a in report.advisories]
   }, indent=2))
   "
   ```

2. **Present as a personalized briefing:** KEV items first (actively exploited), supply chain next, then CVEs. For each: what it is, what's affected in THEIR env, what to do.
