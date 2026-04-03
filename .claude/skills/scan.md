---
name: scan
description: Run SOC 2 compliance checks against the connected AWS account and display findings.
user_invocable: true
---

# Scan

You are running a SOC 2 compliance scan for a semi-technical founder. Explain findings in plain English — avoid jargon where possible and always explain *why* something matters.

## What to do

1. **Run the full compliance scan** using the Shasta scanner:
   ```bash
   py -3.12 -c "
   import json
   from shasta.aws.client import AWSClient
   from shasta.scanner import run_full_scan
   from shasta.compliance.mapper import get_control_summary
   from shasta.compliance.scorer import calculate_score
   from shasta.db.schema import ShastaDB

   client = AWSClient(profile_name='shasta-admin')
   client.validate_credentials()

   print('Running full compliance scan...')
   scan = run_full_scan(client)

   db = ShastaDB()
   db.initialize()
   db.save_scan(scan)

   score = calculate_score(scan.findings)

   output = {
       'score': {
           'percentage': score.score_percentage,
           'grade': score.grade,
           'controls_passing': score.passing,
           'controls_failing': score.failing,
           'controls_partial': score.partial,
           'controls_not_assessed': score.not_assessed,
           'controls_require_policy': score.requires_policy,
           'total_findings': score.total_findings,
           'findings_passed': score.findings_passed,
           'findings_failed': score.findings_failed,
           'findings_partial': score.findings_partial,
       },
       'findings': [
           {
               'check_id': f.check_id,
               'title': f.title,
               'description': f.description,
               'severity': f.severity.value,
               'status': f.status.value,
               'domain': f.domain.value,
               'resource_id': f.resource_id,
               'remediation': f.remediation,
               'soc2_controls': f.soc2_controls,
           }
           for f in sorted(scan.findings, key=lambda x: ['critical','high','medium','low','info'].index(x.severity.value))
       ],
       'control_summary': {
           k: {
               'title': v['title'],
               'overall_status': v['overall_status'],
               'pass_count': v['pass_count'],
               'fail_count': v['fail_count'],
               'partial_count': v['partial_count'],
           }
           for k, v in get_control_summary(scan.findings).items()
           if v['has_automated_checks'] or v['overall_status'] != 'not_assessed'
       }
   }
   print(json.dumps(output, indent=2))
   "
   ```

2. **Present results clearly** to the founder. Structure your response as:

   ### Overall Compliance Score
   Show the grade, percentage, and what it means practically. Frame it as a roadmap, not a report card.

   ### Critical & High Findings
   For each finding:
   - What was found (plain English, no AWS jargon)
   - Why it matters for SOC 2 (and for their business)
   - Exactly what to do about it (specific, actionable)

   ### Medium & Low Findings
   Summarize briefly — group similar findings where possible.

   ### SOC 2 Control Status
   Table showing each control's status. Call out controls that need policies (not just AWS config).

   ### Prioritized Next Steps
   Numbered list of what to fix first, ordered by risk and effort. Quick wins first.

## Tone guidelines
- Use analogies for security concepts ("MFA is like a second lock on your front door")
- Be specific: "restrict security group sg-xxx to your office IP" not "fix your security groups"
- Celebrate what's passing — positive reinforcement matters
- If score is low, frame as "here's where you are and what to do next" not "you're failing"
- Be encouraging but honest
