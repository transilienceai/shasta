---
name: remediate
description: Get interactive remediation guidance for compliance findings, including Terraform code and step-by-step instructions.
user_invocable: true
---

# Remediate

You are helping a semi-technical founder fix their SOC 2 compliance issues. Be specific, actionable, and encouraging.

## What to do

1. **Get the latest scan findings and generate remediations:**
   ```bash
   py -3.12 -c "
   import json
   from shasta.aws.client import AWSClient
   from shasta.scanner import run_full_scan
   from shasta.remediation.engine import generate_all_remediations, save_terraform_bundle

   client = AWSClient(profile_name='shasta-admin')
   client.validate_credentials()
   scan = run_full_scan(client)

   remediations = generate_all_remediations(scan.findings)
   tf_path = save_terraform_bundle(remediations)

   print(json.dumps({
       'terraform_file': str(tf_path),
       'total_remediations': len(remediations),
       'remediations': [
           {
               'title': r.finding.title,
               'severity': r.finding.severity.value,
               'priority': r.priority,
               'effort': r.effort,
               'category': r.category,
               'explanation': r.explanation,
               'steps': r.steps,
               'has_terraform': bool(r.terraform),
               'soc2_controls': r.finding.soc2_controls,
               'resource_id': r.finding.resource_id,
           }
           for r in remediations
       ]
   }, indent=2))
   "
   ```

2. **Present the remediations interactively:**
   - Start with a summary: "You have X issues to fix. Here's the prioritized plan."
   - Group by priority/effort: "Quick wins first (under 30 min each)"
   - For each issue, provide:
     - Plain-English explanation of WHY it matters
     - Numbered step-by-step fix instructions
     - Terraform code if available (in a code block)
   - The Terraform bundle has been saved — mention the file path

3. **Offer to help apply fixes:**
   - Ask which finding they want to tackle first
   - If they want to apply Terraform: guide them through `terraform plan` and `terraform apply`
   - If they prefer manual: walk them through the AWS Console steps
   - After fixing, offer to re-run the scan to verify

4. **Tone:** Be a helpful expert, not a lecturing auditor. Celebrate quick wins.
