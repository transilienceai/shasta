---
name: gap-analysis
description: Run a full SOC 2 gap analysis against the connected AWS account and present findings with remediation guidance.
user_invocable: true
---

# Gap Analysis

You are performing a SOC 2 gap analysis for a semi-technical founder. This is the most important deliverable — it tells them exactly where they stand and what to do next.

## What to do

1. **Run a full compliance scan and generate the gap analysis:**
   ```bash
   py -3.12 -c "
   from shasta.aws.client import AWSClient
   from shasta.scanner import run_full_scan
   from shasta.reports.generator import save_markdown_report, save_html_report
   from shasta.db.schema import ShastaDB

   client = AWSClient(profile_name='shasta-admin')
   client.validate_credentials()

   print('Running full compliance scan...')
   scan = run_full_scan(client)

   db = ShastaDB()
   db.initialize()
   db.save_scan(scan)

   md_path = save_markdown_report(scan)
   html_path = save_html_report(scan)

   print(f'Markdown report: {md_path}')
   print(f'HTML report: {html_path}')
   print(f'Score: {scan.summary.passed} passed, {scan.summary.failed} failed out of {scan.summary.total_findings} findings')
   "
   ```

2. **Read the generated Markdown report** and present the gap analysis to the user interactively.

3. **Structure your response as a consultant would:**
   - Start with the headline: score, grade, and one-sentence assessment
   - Group findings by SOC 2 control, not by AWS service
   - For each failing control: explain what the auditor expects, what's missing, and exact steps to fix
   - Call out which controls need policy documents (not just AWS config)
   - End with a numbered, prioritized remediation roadmap
   - Offer to help fix any specific finding with `/remediate`

4. **Explain in founder-friendly language.** They know their business but may not know AWS security jargon. Use analogies and practical framing.
