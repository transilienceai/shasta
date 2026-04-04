---
name: sbom
description: Generate a Software Bill of Materials (SBOM) from your AWS environment and scan for vulnerable/compromised packages.
user-invocable: true
---

# SBOM — Software Bill of Materials

Discover dependencies in your AWS environment, check for vulnerabilities and supply chain compromises.

## What to do

Read `shasta.config.json` for `python_cmd`. Use that for all commands (shown as `<PYTHON_CMD>`).

1. **Run SBOM discovery and vulnerability scan:**
   ```bash
   <PYTHON_CMD> -c "
   import json
   from shasta.config import get_aws_client
   from shasta.sbom.discovery import discover_sbom, save_sbom
   from shasta.sbom.vuln_scanner import scan_sbom_vulnerabilities, save_vuln_report

   client = get_aws_client()
   client.validate_credentials()
   print('Discovering software dependencies...')
   sbom = discover_sbom(client)
   sbom_path = save_sbom(sbom)
   print(f'SBOM: {sbom.total_dependencies} dependencies across {list(sbom.ecosystems.keys())}')
   print(f'Supply chain alerts: {len(sbom.supply_chain_alerts)}')

   if sbom.total_dependencies > 0:
       print('Scanning for vulnerabilities...')
       vulns = scan_sbom_vulnerabilities(sbom)
       vuln_path = save_vuln_report(vulns)
       print(f'Vulnerabilities: {vulns.total_vulnerabilities} ({vulns.critical} critical, {vulns.high} high)')
       print(f'CISA KEV matches: {vulns.kev_count}')
   "
   ```

2. **Present results:** dependency inventory, supply chain alerts, vulnerability counts. CISA KEV matches are ACTIVELY EXPLOITED — treat as P1.
