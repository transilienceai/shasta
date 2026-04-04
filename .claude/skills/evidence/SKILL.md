---
name: evidence
description: Collect and store point-in-time compliance evidence snapshots for audit trail.
user-invocable: true
---

# Evidence Collection

Collect timestamped compliance evidence snapshots for SOC 2 audit trail.

## What to do

Read `shasta.config.json` for `python_cmd`. Use that for all commands (shown as `<PYTHON_CMD>`).

1. **Run scan and collect evidence:**
   ```bash
   <PYTHON_CMD> -c "
   import json
   from shasta.config import get_aws_client
   from shasta.scanner import run_full_scan
   from shasta.evidence.collector import collect_all_evidence
   from shasta.db.schema import ShastaDB

   client = get_aws_client()
   client.validate_credentials()
   print('Running compliance scan...')
   scan = run_full_scan(client)
   db = ShastaDB(); db.initialize(); db.save_scan(scan)
   print('Collecting evidence...')
   files = collect_all_evidence(client, scan.id)
   print(json.dumps({
       'scan_id': scan.id,
       'evidence_files': [str(f) for f in files],
       'total_artifacts': len(files),
   }, indent=2))
   "
   ```

2. **Explain what was collected** (9 artifact types) and why monthly evidence collection builds the audit trail auditors need.
