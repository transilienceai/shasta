---
name: evidence
description: Collect and store point-in-time compliance evidence snapshots for audit trail.
user_invocable: true
---

# Evidence Collection

You are collecting compliance evidence — timestamped snapshots of AWS configuration state that serve as proof during a SOC 2 audit.

## What to do

1. **Run a scan and collect evidence:**
   ```bash
   py -3.12 -c "
   import json
   from shasta.aws.client import AWSClient
   from shasta.scanner import run_full_scan
   from shasta.evidence.collector import collect_all_evidence
   from shasta.db.schema import ShastaDB

   client = AWSClient(profile_name='shasta-admin')
   client.validate_credentials()

   print('Running compliance scan...')
   scan = run_full_scan(client)

   db = ShastaDB()
   db.initialize()
   db.save_scan(scan)

   print('Collecting evidence...')
   files = collect_all_evidence(client, scan.id)

   print(json.dumps({
       'scan_id': scan.id,
       'evidence_files': [str(f) for f in files],
       'total_artifacts': len(files),
   }, indent=2))
   "
   ```

2. **Explain what was collected:**
   - IAM password policy snapshot
   - IAM credential report (all users, last login, key status)
   - IAM users with policies, groups, and MFA status
   - S3 bucket configurations (encryption, versioning, public access, policies)
   - Security group rules
   - VPC flow log status
   - CloudTrail configuration and logging status
   - GuardDuty detector status and findings summary
   - AWS Config recorder status

3. **Explain why this matters:** SOC 2 auditors need to see evidence that controls were in place *over time*, not just at audit time. Regular evidence collection (monthly recommended) builds this audit trail.

4. **Recommend a schedule:** Monthly evidence collection, stored in `data/evidence/`. Each collection is timestamped and includes a manifest.
