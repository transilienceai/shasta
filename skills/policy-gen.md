---
name: policy-gen
description: Generate SOC 2 compliance policy documents tailored to your company.
user_invocable: true
---

# Policy Generator

You are helping a founder generate the policy documents required for SOC 2 compliance. These are the non-technical controls that auditors will ask for.

## What to do

1. **Ask the user for their company name** if not already known.

2. **Show what policies are available:**
   ```bash
   py -3.12 -c "
   import json
   from shasta.policies.generator import list_policies
   print(json.dumps(list_policies(), indent=2))
   "
   ```

3. **Generate all policies (or specific ones the user requests):**
   ```bash
   py -3.12 -c "
   from shasta.policies.generator import generate_all_policies
   paths = generate_all_policies(company_name='COMPANY_NAME')
   for p in paths:
       print(f'Generated: {p}')
   print(f'\nAll {len(paths)} policies saved to data/policies/')
   "
   ```

4. **Present the results:**
   - List all generated policies with their SOC 2 control mappings
   - Explain that these are **starting templates** — the founder should:
     - Review each policy and customize to match their actual practices
     - Add specific team members' names and contact info
     - Adjust timelines and thresholds to match their operations
     - Have legal review before formal adoption
   - Explain which SOC 2 controls each policy satisfies

5. **Offer to help customize:**
   - Ask if they want to review any specific policy
   - Help them tailor sections to their actual practices
   - The AI can help rewrite sections for their specific context

## Available Policies

| Policy | SOC 2 Controls | Purpose |
|--------|---------------|---------|
| Access Control | CC6.1, CC6.2, CC6.3, CC5.1 | Who gets access to what, how, and when it's revoked |
| Change Management | CC8.1, CC5.1 | How code and infrastructure changes are reviewed and deployed |
| Incident Response | CC7.1, CC7.2, CC2.1 | How security incidents are detected, handled, and communicated |
| Risk Assessment | CC3.1 | How risks are identified, assessed, and managed |
| Vendor Management | CC9.1 | How third-party vendors are evaluated and monitored |
| Data Classification | CC6.7, CC9.1 | How data is categorized and protected based on sensitivity |
| Acceptable Use | CC1.1, CC2.1 | What employees can and cannot do with company systems |
| Business Continuity | CC9.1 | How the company recovers from disruptions and disasters |
