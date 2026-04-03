---
name: review-access
description: Run a periodic IAM access review — lists all users, permissions, activity, and flags issues. Required quarterly for SOC 2.
user_invocable: true
---

# Access Review

You are conducting a quarterly IAM access review for SOC 2 compliance (CC6.2, CC6.3). This is a formal process that auditors expect to see documented.

## What to do

1. **Run the access review:**
   ```bash
   py -3.12 -c "
   import json
   from shasta.aws.client import AWSClient
   from shasta.workflows.access_review import run_access_review, save_access_review

   client = AWSClient(profile_name='shasta-admin')
   client.validate_credentials()

   print('Running access review...')
   report = run_access_review(client)
   path = save_access_review(report)

   print(json.dumps({
       'report_path': str(path),
       'total_users': report.total_users,
       'users_with_console': report.users_with_console,
       'users_with_mfa': report.users_with_mfa,
       'users_with_keys': report.users_with_keys,
       'users_flagged': report.users_flagged,
       'flagged_users': [
           {
               'username': r.username,
               'flags': r.flags,
               'has_console': r.has_console,
               'has_mfa': r.has_mfa,
               'groups': r.groups,
               'attached_policies': r.attached_policies,
               'days_inactive': r.days_inactive,
               'access_keys': r.access_keys,
           }
           for r in report.records if r.flags
       ]
   }, indent=2))
   "
   ```

2. **Present the review interactively:**
   - Summary statistics (total users, MFA coverage, flagged count)
   - For each flagged user: explain what's wrong and recommend action (keep, modify, or remove)
   - Ask the founder to confirm each decision
   - Note that the report has been saved for audit evidence

3. **Recommend a schedule:** Access reviews should happen quarterly. Suggest the founder set a calendar reminder or use a Claude Code cron trigger.

4. **Remind them:** The saved report at the file path serves as audit evidence. They should keep it — auditors will ask to see access review documentation.
