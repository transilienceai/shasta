---
name: policy-gen
description: Generate SOC 2 compliance policy documents tailored to your company.
user-invocable: true
---

# Policy Generator

Generate SOC 2 policy documents required for audit.

## What to do

Read `shasta.config.json` for `python_cmd` and `company_name`. Use that for commands (shown as `<PYTHON_CMD>`).

1. **If `company_name` is empty in config**, ask the user for their company name and update the config.

2. **Show available policies:**
   ```bash
   <PYTHON_CMD> -c "
   import json
   from shasta.policies.generator import list_policies
   print(json.dumps(list_policies(), indent=2))
   "
   ```

3. **Generate all policies:**
   ```bash
   <PYTHON_CMD> -c "
   from shasta.config import load_config
   from shasta.policies.generator import generate_all_policies
   cfg = load_config()
   paths = generate_all_policies(company_name=cfg.get('company_name', 'Acme Corp'))
   for p in paths: print(f'Generated: {p}')
   print(f'\nAll {len(paths)} policies saved to data/policies/')
   "
   ```

4. **Explain:** These are starting templates. The founder should review, customize, and have legal sign off. Offer to help tailor specific sections.

## Available Policies
| Policy | Controls | Purpose |
|--------|----------|---------|
| Access Control | CC6.1-CC6.3, CC5.1 | Authentication, authorization, offboarding |
| Change Management | CC8.1, CC5.1 | Code review, deployment, audit trail |
| Incident Response | CC7.1, CC7.2, CC2.1 | Detection, response, recovery |
| Risk Assessment | CC3.1 | Risk identification and treatment |
| Vendor Management | CC9.1 | Third-party evaluation and monitoring |
| Data Classification | CC6.7, CC9.1 | Data sensitivity levels and handling |
| Acceptable Use | CC1.1, CC2.1 | Employee responsibilities |
| Business Continuity | CC9.1 | DR, backups, recovery objectives |
