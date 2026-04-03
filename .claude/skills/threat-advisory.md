---
name: threat-advisory
description: Generate a personalized threat advisory based on your tech stack — what CVEs, breaches, and supply chain attacks matter to YOU.
user_invocable: true
---

# Threat Advisory

You are generating a personalized threat intelligence digest for a founder.

## What to do

1. **Generate the advisory:**
   ```bash
   py -3.12 -c "
   import json
   from shasta.aws.client import AWSClient
   from shasta.sbom.discovery import discover_sbom
   from shasta.threat_intel.advisory import generate_daily_advisory, save_advisory_report, format_advisory_slack

   client = AWSClient(profile_name='shasta-admin')
   client.validate_credentials()

   print('Building tech stack profile...')
   sbom = discover_sbom(client)

   print('Querying threat feeds...')
   report = generate_daily_advisory(sbom, lookback_days=7)
   path = save_advisory_report(report)

   print(json.dumps({
       'report_path': str(path),
       'period': report.period,
       'tech_stack': report.tech_stack_summary,
       'total_advisories': report.total_advisories,
       'critical': report.critical_count,
       'high': report.high_count,
       'advisories': [
           {
               'id': a.id,
               'title': a.title,
               'severity': a.severity,
               'affected': a.affected_component,
               'action': a.action_required,
               'is_kev': a.is_kev,
               'is_supply_chain': a.is_supply_chain,
           }
           for a in report.advisories
       ]
   }, indent=2))
   "
   ```

2. **Present as a personalized briefing:**
   - "Based on your tech stack (Python 3.12, nodejs 18, PostgreSQL), here's what's relevant"
   - Critical/KEV items first — these are being actively exploited
   - Supply chain items next — package compromises
   - Then high/medium CVEs
   - For each: what it is, what's affected in THEIR env, what to do

3. **Recommend schedule:** Run daily via Claude Code cron trigger, deliver to Slack.
