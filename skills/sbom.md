---
name: sbom
description: Generate a Software Bill of Materials (SBOM) from your AWS environment and scan for vulnerable/compromised packages.
user_invocable: true
---

# SBOM — Software Bill of Materials

You are helping a founder understand what software dependencies are running in their AWS environment and whether any are vulnerable or compromised.

## What to do

1. **Run SBOM discovery and vulnerability scan:**
   ```bash
   py -3.12 -c "
   import json
   from shasta.aws.client import AWSClient
   from shasta.sbom.discovery import discover_sbom, save_sbom
   from shasta.sbom.vuln_scanner import scan_sbom_vulnerabilities, save_vuln_report

   client = AWSClient(profile_name='shasta-admin')
   client.validate_credentials()

   print('Discovering software dependencies...')
   sbom = discover_sbom(client)
   sbom_path = save_sbom(sbom)

   print(f'SBOM: {sbom.total_dependencies} dependencies across {list(sbom.ecosystems.keys())}')
   print(f'Supply chain alerts: {len(sbom.supply_chain_alerts)}')
   print(f'SBOM saved: {sbom_path}')

   if sbom.total_dependencies > 0:
       print('\nScanning for vulnerabilities...')
       vulns = scan_sbom_vulnerabilities(sbom)
       vuln_path = save_vuln_report(vulns)
       print(f'Vulnerabilities: {vulns.total_vulnerabilities} ({vulns.critical} critical, {vulns.high} high)')
       print(f'CISA KEV matches: {vulns.kev_count}')
       print(f'Report: {vuln_path}')
   "
   ```

2. **Present results:**
   - Show the dependency inventory grouped by ecosystem
   - Highlight any supply chain alerts (known compromised packages)
   - Show vulnerability counts by severity
   - For critical/high vulns: explain what's affected, which AWS resource, and how to fix
   - If CISA KEV matches found: these are ACTIVELY EXPLOITED — treat as P1

3. **Explain SBOM value:** "This is like an ingredient list for your software. When a supply chain attack happens (like the xz backdoor), you can instantly know if you're affected."
