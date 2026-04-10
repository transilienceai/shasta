# Changelog

All notable changes to Shasta are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.6.0] — 2026-04-09 — AWS-to-Azure parity sweep (Stage 1 + Stage 2)

Two stages of an explicit parity sweep against the Azure scanner. Stage 1
closes the categorical gaps (no compute module, no KMS module, no CIS 4.x
CloudWatch alarms). Stage 2 adds the missing service-type modules
(CloudFront, Redshift, ElastiCache, Neptune) and deepens existing modules
with the high-leverage hardening checks (Lambda Function URL auth, S3
Object Ownership, RDS parameter enforcement, AWS Backup cross-region
copy + access policy).

Net effect: AWS check functions go from 62 → 107 (+45), AWS Terraform
templates from 42 → 81 (+39). The AWS scanner is now ahead of the Azure
scanner in absolute coverage, which is the right shape for real-world
deployments where AWS is the larger surface area.

### Added — Stage 1 (AWS check_* 62 → 80)
- New module `src/shasta/aws/compute.py` (9 checks): EC2 IMDSv2 enforcement
  (Capital One breach vector), public IPv4 inventory, IAM instance profile
  attached, AMI age (90-day default), EKS private endpoint, EKS audit
  logging (api/audit/authenticator), EKS secrets envelope encryption with
  KMS, ECS task privileged-mode detection, ECS task root-user detection.
- New module `src/shasta/aws/kms.py` (4 checks): customer-managed CMK
  rotation enabled, key policy wildcards (Principal=`*` + Action=`*` with
  no Condition), keys in PendingDeletion state (CRITICAL — surfaces
  destruction-in-progress), cross-account grants without SourceArn /
  SourceAccount conditions.
- `src/shasta/aws/iam.py` extensions (3 checks, GLOBAL — no region
  iteration): customer-managed policy wildcards (`Action: "*"` on
  `Resource: "*"`), role trust policies trusting external accounts
  without an `sts:ExternalId` condition (the confused-deputy vector),
  unused IAM roles (`>90` days since last use).
- `src/shasta/aws/logging_checks.py` extensions (2 checks):
  - `check_cloudwatch_alarms_cis_4_x` — covers CIS AWS 4.1–4.15
    (15 events: unauthorized API, console-no-MFA, root use, IAM/CT/Config
    changes, KMS deletion, S3/SG/NACL/route/VPC/Org changes). Anchored to
    the multi-region CloudTrail's home region to avoid 14 false-FAIL
    findings per multi-region account. Mirrors Azure's
    `check_activity_log_alerts` (CIS 5.2.x) pattern.
  - `check_aws_config_conformance_packs` — mirrors Azure's
    `check_security_initiative_assigned`. Iterates regions; passes if any
    enabled region has a conformance pack deployed.
- 13 new `aws_*` Terraform remediation templates registered in `engine.py`,
  each matched to an `EXPLANATIONS` entry: IMDSv2 enforcement, instance
  profile, EKS private endpoint + audit logging + secrets encryption, ECS
  task hardening (no privileged / no root), KMS rotation + key policy,
  IAM policy wildcards + external-id trust, CIS 4.x metric filter+alarm,
  AWS Config conformance pack.

### Changed
- `Finding` model already has `cis_aws_controls`; every new check above
  populates it with the relevant CIS section (1.16, 1.18, 1.20, 3.8, 3.x,
  4.1–4.15, 5.4.x, 5.6, 5.x).
- `tests/test_aws/test_aws_sweep_smoke.py` gained a structural test
  `test_runner_iterates_regions_unless_global` that fails the build if any
  AWS runner is single-region without an explicit `IS_GLOBAL = True`
  module-level marker. Closes the gap that Engineering Principle #3 was
  written to prevent. The two genuinely-global modules
  (`organizations.py`, IAM extensions) are explicitly opted out via the
  `GLOBAL_AWS_MODULES` set or the `IS_GLOBAL` constant.
- README updated: top-of-file "5 Domains, 129+ Checks" → "147+ Checks";
  technical-controls row 129+ → 147+; remediation row 73 templates → 86
  templates (55 AWS + 31 Azure).

### Added — Stage 2 (AWS check_* 80 → 107)
- New module `src/shasta/aws/cloudfront.py` (5 checks, IS_GLOBAL=True so
  the structural multi-region smoke test correctly skips region iteration):
  HTTPS-only viewer protocol policy, MinimumProtocolVersion >= TLSv1.2_2021,
  WAFv2 Web ACL attached (scope=CLOUDFRONT), geo restrictions
  (informational), Origin Access Control for S3 origins.
- New module `src/shasta/aws/data_warehouse.py` (8 checks for Redshift,
  ElastiCache, Neptune): Redshift cluster encryption + public access +
  audit logging + require_ssl parameter, ElastiCache Redis transit
  encryption + at-rest encryption + AUTH token, Neptune cluster
  encryption.
- `src/shasta/aws/databases.py` extensions (3 checks): RDS
  `rds.force_ssl` / `require_secure_transport` parameter group enforcement
  (mirrors Azure's secure_transport check), PostgreSQL log_connections /
  log_disconnections / log_checkpoints (mirrors Azure's
  check_postgresql_log_settings), SQL Server `rds.tls_version` minimum
  (mirrors Azure's check_sql_min_tls).
- `src/shasta/aws/serverless.py` extensions (6 checks):
  - `check_lambda_function_url_auth` — flags Lambda Function URLs with
    `AuthType=NONE`. This is one of the most common new AWS
    misconfigurations as of 2026; bot scanners find these public
    endpoints within hours of creation.
  - `check_lambda_layer_origin` — flags layers from foreign AWS accounts
    (supply chain risk).
  - `check_apigw_client_certificate`, `check_apigw_authorizer_required`
    (mirrors Azure App Service Easy Auth), `check_apigw_throttling`
    (cost / abuse protection), `check_apigw_request_validation` (edge
    rejection of malformed requests).
- `src/shasta/aws/storage.py` extensions (3 checks):
  - `check_s3_object_ownership_enforced` — Object Ownership =
    BucketOwnerEnforced (disables ACLs entirely; modern AWS recommendation).
  - `check_s3_access_logging` — server access logging enabled.
  - `check_s3_kms_cmk_encryption` — stricter than the existing
    check_s3_encryption (which accepts SSE-S3); requires customer-managed
    KMS encryption.
- `src/shasta/aws/backup.py` extensions (2 checks):
  - `check_backup_cross_region_copy` — at least one Backup plan must
    have a cross-region copy action (mirrors Azure RSV cross-region
    restore).
  - `check_backup_vault_access_policy` — vault must have a deny-style
    resource policy denying destructive operations to non-break-glass
    principals (AWS analog of Azure RSV Multi-User Authorization).
- 26 new `aws_*` Terraform remediation templates registered in `engine.py`,
  each matched to an `EXPLANATIONS` entry: cloudfront-https-only / min-tls
  / waf / oac, redshift encryption / public-access / audit / require-ssl,
  elasticache transit / at-rest / auth-token, neptune-encryption,
  rds-force-ssl / log-settings / min-tls, lambda-function-url-auth /
  layer-origin, apigw-client-cert / authorizer / throttling /
  request-validation, s3-object-ownership / access-logging / kms-cmk,
  aws-backup-cross-region-copy / vault-access-policy.
- `tests/test_aws/test_aws_sweep_smoke.py` updated: cloudfront and
  data_warehouse added to `NEW_AWS_MODULES` and `EXPECTED_RUNNERS`;
  cloudfront added to `GLOBAL_AWS_MODULES`; 24 new parametrized
  template-render tests; new constant assertions
  (`test_cloudfront_module_is_global`,
  `test_data_warehouse_module_is_regional`); template-count threshold
  bumped to ≥75.

### Wiring — scanner.py
`_run_aws_extras` now dispatches `cloudfront.py` when
`CheckDomain.NETWORKING` is requested and `data_warehouse.py` when
`CheckDomain.STORAGE` or `CheckDomain.ENCRYPTION` is requested. Both new
modules respect the global / regional distinction.

### Numbers after Stage 1 + Stage 2
- AWS check functions: **62 → 107** (+45 total: +18 Stage 1, +27 Stage 2)
- AWS scanner modules: **12 → 16** (+ compute.py, + kms.py, + cloudfront.py,
  + data_warehouse.py)
- AWS Terraform templates: **42 → 81** (+39 total: +13 Stage 1, +26 Stage 2)
- Total Shasta + Whitney check functions: **129 → 174**
- Total Terraform templates: **73 → 112**
- Total tests: **624 → 745** (new sweep tests + structural multi-region
  enforcement)

### Documentation — unified trust story

A new top-level [`TRUST.md`](./TRUST.md) consolidates the project-wide
trust story that had grown well beyond Whitney's original scope. Three
load-bearing artifacts now sit side-by-side at the repo root:

- `README.md` — what Shasta and Whitney do
- `TRUST.md` — how to verify the claims yourself (the seven enforcement
  layers, framework coverage matrix, exact verification commands)
- `ENGINEERING_PRINCIPLES.md` — how the codebase is held together

`src/whitney/TRUST.md` is preserved but trimmed to Whitney-specific
content (vulnerability fixtures, live AWS + Azure resource validation,
Semgrep dual-engine architecture). It cross-links to the root
`TRUST.md` for the project-wide story.

`tests/test_integrity/test_doc_claims.py` gained 5 new assertions that
verify the root `TRUST.md` numeric claims (total check functions, AI vs
cloud breakdown, Terraform template count, total test count, Layer 1
sub-suite breakdown, integrity test self-count) match reality. The test
file is now at **16 parametrized assertions** (was 11). The README
gained a one-line "three load-bearing artifacts" pointer at the top.

### Engineering Principles honored

This release was developed against the discipline encoded in
`ENGINEERING_PRINCIPLES.md`:

- **#1 (numbers as tests)** — every README count update was driven by
  the doc-drift integrity test failing first; the test then re-passed
  after the README was corrected. The test caught two stale-count
  attempts during Stage 2 development.
- **#2 (no stub functions)** — every check function in the new modules
  has a real body; smoke tests verify import + signature + structure.
- **#3 (multi-region default)** — every regional runner iterates
  `client.get_enabled_regions()` via `client.for_region(r)`. The
  structural smoke test `test_runner_iterates_regions_unless_global`
  fails the build for any single-region runner without an explicit
  `IS_GLOBAL = True` marker. CloudFront opts out via the marker (it
  is a genuinely global service); the CIS 4.x CloudWatch alarms check
  uses a special anchored-to-trail-home-region pattern (also documented
  in the principle's #3 caveats).
- **#5 (empty results vs errors)** — every new check uses
  `NOT_ASSESSED` for permission errors / missing prerequisites,
  `NOT_APPLICABLE` for empty inventories, `FAIL` for actual
  non-compliance.
- **#7 (cross-cutting walkers)** — Stage 1 + 2 are deliberately
  per-service. Stage 3 (the diagnostic settings matrix walker) is the
  walker phase and was scoped out of this release.
- **#8 (configuration tables)** — `CLOUDWATCH_CIS_4_X_EVENTS`,
  `WEAK_TLS_POLICIES`, `DEPRECATED_LAMBDA_RUNTIMES`, `EXPECTED_VPC_ENDPOINTS`
  are all module-level data tables that drive the checks.
- **#9 (frameworks on the model)** — every new Finding populates
  `cis_aws_controls` with the relevant CIS section (1.16, 1.18, 1.20,
  2.x, 2.3.x, 2.4–2.6, 3.5, 3.8, 3.x, 4.1–4.15, 4.x, 5.4.x, 5.6, 5.x).
- **#10 (additive backwards compat)** — no existing field types or
  function signatures changed.
- **#15 (actionable failure messages)** — every assertion in the smoke
  tests references the exact file or constant to update on failure.

---

## [1.5.0] — 2026-04-09

This release closes the gap between the v1.0.0 baseline and a CIS-aligned
multi-cloud compliance scanner. Net result: **138 check functions, 73
Terraform remediation templates, 624 tests, full CIS AWS v3.0 + CIS Azure
v3.0 + Microsoft Cloud Security Benchmark coverage**, plus the Whitney AI
governance subsystem and a doc-vs-code drift integrity test that prevents
the failure mode that motivated this release in the first place.

### Added

#### Whitney — AI security & governance subsystem
- 46 `check_*` functions across code scanning (prompt injection, hardcoded
  keys, unguarded agents, PII in prompts) and cloud AI services (AWS
  Bedrock, SageMaker, Lambda; Azure OpenAI, ML Workspace, Cognitive
  Services, AI Search)
- 4 AI compliance frameworks: ISO 42001, EU AI Act, OWASP LLM Top 10,
  OWASP Agentic, NIST AI RMF, MITRE ATLAS
- AI-specific policy generator (7 templates), AI SBOM scanner with
  CycloneDX 1.5 output, and Whitney TRUST.md documenting the validation
  approach
- Semgrep AST-based code scanner with regex fallback (dual-engine
  architecture), so static analysis is reproducible across runs

#### Shasta — Azure parity sweep (3 stages)
- **Stage 1 — CIS Azure v3.0 critical gaps**: block legacy authentication,
  MFA-for-Azure-Management cloud app, PIM eligibility vs permanent role
  assignments, classic / co-administrators, custom-role wildcard Actions,
  guest invitation restrictions, Activity Log retention >= 365 days,
  Activity Log alerts for the CIS 5.2.x set, Defender for Cloud per-plan
  breakdown across 14 plans, storage `allowSharedKeyAccess` /
  `allowCrossTenantReplication` / network default-Deny, Key Vault RBAC
  permission model + `publicNetworkAccess` + key/secret expiry, SQL
  auditing + Entra ID admin + `minimalTlsVersion`, VNet flow logs (the
  post-2025 successor to NSG flow logs), Network Watcher per-region
- **Stage 2 — new resource-type modules**: `databases.py` (Cosmos DB,
  PostgreSQL Flexible Server, MySQL Flexible Server), `appservice.py`
  (HTTPS-only, min TLS, FTPS, remote debug, client cert, managed identity,
  public network access, Easy Auth), `backup.py` (Recovery Services Vault
  existence, soft delete AlwaysON, immutability locked, cross-region
  restore, GRS/GZRS, CMK, multi-user authorization)
- **Stage 3 — cross-cutting walkers**: `private_endpoints.py` walker
  across Storage / Key Vault / SQL / Cosmos / ACR / App Service /
  Cognitive Services; `diagnostic_settings.py` declarative
  `{resource_type: [expected_categories]}` matrix walker covering CIS
  5.1.4–5.1.7; `governance.py` for management group hierarchy + security
  initiative + CanNotDelete locks + required tag enforcement
- Multi-subscription support: `AzureClient.list_subscriptions()`,
  `for_subscription(sid)`, and `scanner.run_azure_multi_subscription()`
  mirroring the AWS multi-region pattern
- Net Azure check_* functions: **22 → 67** (+45). Net Azure modules:
  **5 → 12**.

#### Shasta — AWS parity sweep (3 stages)
- **Stage 1 — CIS AWS v3.0 critical gaps**: CloudTrail KMS encryption
  (3.5), CloudTrail log file validation (3.2), S3 Object Lock for log
  buckets, Security Hub multi-region (4.16), IAM Access Analyzer
  multi-region (1.20), EFS encryption (2.4), SNS / SQS encryption,
  Secrets Manager rotation, ACM expiring certificates, ELB v2 modern TLS
  policy + access logs + `drop_invalid_header_fields`
- **Stage 2 — new resource-type modules**: `databases.py` (RDS deep — IAM
  database authentication, deletion protection, Performance Insights with
  KMS, auto minor version upgrade; DocumentDB encryption + audit logs;
  DynamoDB PITR + customer-managed KMS), `serverless.py` (Lambda runtime
  EOL detection + env-var KMS + dead-letter + code signing; API Gateway
  logging + WAFv2 association; Step Functions execution-history logging),
  `backup.py` (AWS Backup vault existence, Vault Lock COMPLIANCE mode,
  customer-managed KMS, Backup plans)
- **Stage 3 — cross-cutting walkers**: `vpc_endpoints.py` walker (S3,
  DynamoDB, KMS, Secrets Manager, SSM, ECR, Logs, STS),
  `cloudwatch_logs.py` (KMS encryption + retention >= 90 days matrix
  walker), `organizations.py` (Org enabled + ALL features, custom SCPs,
  tag policy, backup policy, delegated administrators)
- Multi-region scanning baked into encryption / networking /
  vulnerabilities / pentest / logging modules — every `run_all_*` runner
  iterates `client.get_enabled_regions()` via `client.for_region(r)`
- Root account recent-activity check (90-day window, CC6.1/CC6.3) parses
  the credential report's `<root_account>` entry
- GuardDuty check pulls the top 10 most severe active findings per region
  with critical-type-prefix detection (credential exfiltration,
  cryptomining, trojans, backdoors, Impact/Exfiltration tactics)
- Net AWS check_* functions: **25 → 62** (+37). Net AWS modules:
  **6 → 12**.

#### Compliance framework mapping
- New optional list fields on the `Finding` model:
  `cis_aws_controls`, `cis_azure_controls`, `mcsb_controls`. Additive,
  backwards compatible. Every new check populates the relevant list.
- HIPAA Security Rule framework mapping (29 controls across 3 safeguards)
- 199-question security questionnaire auto-fill (SIG Lite, CAIQ,
  Enterprise) with ~70% auto-fill rate from scan evidence

#### Remediation engine
- 32 new `aws_*` Terraform templates registered in `engine.py`, each
  matched with an `EXPLANATIONS` entry. Coverage spans CloudTrail KMS +
  log validation + Object Lock, Security Hub, Access Analyzer, EFS / SNS /
  SQS / Secrets / ACM encryption, ELB v2 TLS / logs / headers, RDS deep,
  DynamoDB, Lambda, API Gateway WAF, AWS Backup vault lock, VPC
  endpoints, CloudWatch Logs KMS, AWS Organizations SCPs + tag policies
- 31 new `azurerm_*` Terraform templates covering Storage shared-key /
  cross-tenant / default-Deny, Key Vault RBAC + PNA, SQL TLS / auditing /
  Entra-admin, PostgreSQL / MySQL secure transport + logging, Cosmos
  local-auth / PNA / firewall, App Service HTTPS / TLS / FTPS / debug /
  MSI, RSV soft-delete / immutability / redundancy, VNet flow logs,
  Network Watcher, Defender per-plan, Activity Log alerts, resource
  locks, required-tag policy, MCSB initiative
- Net Terraform templates: **14 → 73** (+59). Breakdown: **42 AWS + 31
  Azure**.

#### Web dashboard
- FastAPI + Tailwind + HTMX + Chart.js dashboard at `localhost:8080` with
  7 routes covering compliance posture, findings, controls, risk register

#### Doc-vs-code drift integrity tests
- `tests/test_integrity/test_doc_claims.py` AST-counts every check
  function, registry entry, and Terraform template, then asserts each
  numeric claim in `README.md`, `src/whitney/README.md`, and
  `src/whitney/TRUST.md` matches reality
- 11 parametrized assertions; failure messages tell you the exact
  `file:line` to update and the new value
- "X+" claims pass when actual is greater than or equal to X; bare
  numbers must match exactly (or within explicit tolerance for fast-
  moving counters like total tests)
- Lines containing `~~strikethrough~~` are skipped — historical narrative
  is preserved untouched

#### Project hardening
- Empty-stub / false-claim integrity tests for the Whitney module tree
- `LICENSE` file added at repo root (MIT, Copyright (c) 2026 Transilience
  AI). README license section updated from "Private repository..." to
  "MIT License. See `LICENSE`."

### Fixed

- **Phantom claim**: `README.md` had stated the project shipped 22 Azure
  Terraform templates when the `engine.py` registry contained zero. The
  number was inherited from a stale `.pyc` cache and was never present in
  committed source. 31 real templates added; integrity tests added to
  prevent recurrence. (issue #3)
- **6 stale numeric claims** in `README.md` / `src/whitney/README.md` /
  `src/whitney/TRUST.md` updated to reality and locked in by integrity
  tests. (issue #4)
- **AWS scanner only walked the configured region**, leaving multi-region
  resources invisible and producing false-clean reports. Fixed in `fc0d60a`.
  (issue #5)
- **GuardDuty check reported counts only** — now ranks the top 10 most
  severe active findings per region with critical-type-prefix detection.
  (issue #11)
- **Azure NSG flow logs check used deprecated API** that retires
  2027-09-30. Replaced by `check_vnet_flow_logs_modern` targeting the
  successor VNet flow logs API. (issue #9)
- **Defender for Cloud check was binary**, hiding per-plan coverage gaps
  across 14 plans. Replaced by per-plan rollup. (issue #10)
- **Azure scanner was single-subscription only** with no way to iterate
  management groups. Multi-subscription helpers added. (issue #12)
- Lambda runtime EOL list refreshed to flag python3.7 / 3.8, nodejs14 /
  16, go1.x as deprecated for 2026
- Misc bug fixes from independent code audit: scorer edge case, drift
  null check, GuardDuty severity float-parse error, TLS 1.3 handling, NSG
  service-tag prefix list, Azure risk register mappings (21 entries)

### Changed

- README rewritten throughout to reflect the new scope. Headline:
  "5 Domains, 129+ Checks". Technical-controls row: "129+ automated
  checks across AWS and Azure (full CIS AWS v3.0 + CIS Azure v3.0
  coverage)". Remediation row: "73 Terraform templates (42 AWS + 31
  Azure azurerm)".
- All Azure findings now carry `cis_azure_controls` + `mcsb_controls`
  alongside `soc2_controls`
- All new AWS findings carry `cis_aws_controls`
- Whitney scanner is now deterministic by design — zero LLM calls in the
  scanning, scoring, mapping, policy generation, or SBOM output
  pipelines. The LLM lives in the user-interface layer (Claude Code),
  not the detection layer. Same infrastructure + same scan = same
  results, every time.

### Deprecated

Nothing.

### Removed

Nothing.

### Security

- Added Object Lock check on the S3 bucket holding CloudTrail logs (CIS
  AWS 3.x) — defeats malicious-admin / compromised-root deletion of audit
  evidence
- Added AWS Backup Vault Lock COMPLIANCE mode check (MCSB BR-2.3) —
  defeats ransomware that targets backups
- Added Azure RSV `immutability=Locked` check (MCSB BR-2.3) — same goal,
  Azure side
- Added VPC endpoint walker — flags EC2 / ECS / EKS workloads where
  traffic to S3 / KMS / Secrets Manager traverses the public internet via
  NAT instead of staying inside the VPC
- Added Azure private endpoint walker — same goal across Storage / Key
  Vault / SQL / Cosmos / ACR / App Service / Cognitive Services

### Tests

- Total tests: **~100 → 624**
  - 11 new doc-drift integrity tests
  - 34 new Azure smoke tests (`tests/test_azure/test_smoke.py`)
  - 39 new AWS sweep smoke tests (`tests/test_aws/test_aws_sweep_smoke.py`)
  - Whitney unit + integration suites grew alongside the AI governance
    subsystem
- All 624 tests green at release time

### Migration notes

This release is **backwards compatible**. New `Finding` model fields are
additive; existing call sites that produce `Finding` objects without
populating the new lists continue to work. New scanner modules (`databases`,
`serverless`, `backup`, `appservice`, `vpc_endpoints`, `cloudwatch_logs`,
`organizations`, `private_endpoints`, `diagnostic_settings`, `governance`,
plus the Azure equivalents) are auto-discovered by `scanner.py` based on
the requested check domain. No configuration changes required.

If you were relying on the previous single-region AWS scanning behaviour,
the `_run_aws_checks_multi_region` helper preserves that path; the
default `_run_aws_checks` continues to run against the configured region
plus the new multi-region rollups.

---

## [1.0.0] — 2026-04-06

Initial public release of Shasta. AWS-focused SOC 2 + ISO 27001 +
HIPAA scanner with policy generation, risk register, evidence
collection, gap analysis, and a Claude Code skill UI.

### Highlights

- 25 AWS check_* functions across IAM, networking, storage, encryption,
  monitoring, and vulnerability domains
- SOC 2 (CC1.1–CC9.1) and ISO 27001 Annex A (35 controls) framework
  mapping
- 14 Terraform remediation templates
- 8 SOC 2 policy document generators (access control, change management,
  incident response, risk assessment, vendor management, data
  classification, acceptable use, business continuity)
- 17 auditor-grade control tests
- Markdown / HTML / PDF report output
- Risk register with 33 check-to-risk mappings (later 34 in v1.5.0)
- Quarterly access review workflow
- Claude Code skills covering connect-aws, scan, gap-analysis, policy-gen,
  report, remediate, evidence, risk-register, review-access, sbom,
  pentest, threat-advisory, questionnaire, dashboard, ISO 27001, HIPAA

The frozen v1.0.0 snapshot remains available on the `release/shasta-v1`
branch and as the `v1.0.0` git tag.

[1.5.0]: https://github.com/transilienceai/shasta/releases/tag/v1.5.0
[1.0.0]: https://github.com/transilienceai/shasta/releases/tag/v1.0.0
