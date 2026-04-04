---
name: review-access
description: Run a periodic IAM access review — lists all users, permissions, activity, and flags issues. Required quarterly for SOC 2.
user-invocable: true
---

# Access Review

Conduct a quarterly IAM access review for SOC 2 compliance (CC6.2, CC6.3).

## What to do

Read `shasta.config.json` for `python_cmd`. Use that for all commands (shown as `<PYTHON_CMD>`).

1. **Run the access review:**
   ```bash
   <PYTHON_CMD> -c "
   import json
   from shasta.config import get_aws_client
   from shasta.workflows.access_review import run_access_review, save_access_review

   client = get_aws_client()
   client.validate_credentials()
   print('Running access review...')
   report = run_access_review(client)
   path = save_access_review(report)

   print(json.dumps({
       'report_path': str(path),
       'total_users': report.total_users,
       'users_with_console': report.users_with_console,
       'users_with_mfa': report.users_with_mfa,
       'users_flagged': report.users_flagged,
       'flagged_users': [{
           'username': r.username, 'flags': r.flags,
           'has_console': r.has_console, 'has_mfa': r.has_mfa,
           'groups': r.groups, 'attached_policies': r.attached_policies,
           'days_inactive': r.days_inactive,
       } for r in report.records if r.flags]
   }, indent=2))
   "
   ```

2. **Present interactively:** summary stats, then each flagged user with recommended action (keep/modify/remove). The saved report serves as audit evidence.
