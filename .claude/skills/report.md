---
name: report
description: Generate professional compliance reports (Markdown, HTML, PDF) from the latest scan data.
user_invocable: true
---

# Report

You are generating a professional SOC 2 compliance report for the founder.

## What to do

1. **Generate all report formats:**
   ```bash
   py -3.12 -c "
   from shasta.aws.client import AWSClient
   from shasta.scanner import run_full_scan
   from shasta.reports.generator import save_markdown_report, save_html_report
   from shasta.reports.pdf import save_pdf_report
   from shasta.db.schema import ShastaDB

   client = AWSClient(profile_name='shasta-admin')
   client.validate_credentials()

   print('Running compliance scan...')
   scan = run_full_scan(client)

   db = ShastaDB()
   db.initialize()
   db.save_scan(scan)

   print('Generating reports...')
   md = save_markdown_report(scan)
   html = save_html_report(scan)
   pdf = save_pdf_report(scan)

   print(f'Markdown: {md}')
   print(f'HTML:     {html}')
   print(f'PDF:      {pdf}')
   print('Done!')
   "
   ```

2. **Tell the user where the reports are** and what each format is best for:
   - **Markdown** — for working sessions, easy to review in any editor
   - **HTML** — for sharing via email or browser, interactive viewing
   - **PDF** — for formal deliverables to auditors or investors

3. **Offer next steps:**
   - `/gap-analysis` for interactive walkthrough of findings
   - `/remediate` to fix specific issues
   - `/policy-gen` to generate required policy documents
