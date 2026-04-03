# Shasta — AWS Compliance Automation Platform for SOC 2

**An AI-native compliance toolkit that enables startup founders to achieve and maintain SOC 2 compliance through their terminal.**

Shasta is not a SaaS dashboard. It's a set of Claude Code skills, Python libraries, and AWS infrastructure that uses AI as the interface — explaining findings in plain English, generating tailored policies, producing Terraform remediation code, and delivering personalized threat intelligence. Built for founders running <50 employee companies who need SOC 2 without the $30K/year Vanta bill.

---

## Table of Contents

- [Platform Capabilities](#platform-capabilities)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Skills Reference](#skills-reference)
- [SOC 2 Coverage](#soc-2-coverage)
- [The Build Journey — A Vibe Coding Case Study](#the-build-journey--a-vibe-coding-case-study)
- [Vibe Coding Best Practices for Security Projects](#vibe-coding-best-practices-for-security-projects)
- [Build Metrics](#build-metrics)
- [What's Next](#whats-next)

---

## Platform Capabilities

### 1. Automated AWS Security Scanning (5 Domains, 40+ Checks)

| Domain | Checks | SOC 2 Controls |
|--------|--------|----------------|
| **IAM** | Password policy, root MFA, user MFA, access key rotation, inactive users, direct policies, overprivileged users | CC6.1, CC6.2, CC6.3 |
| **Networking** | Security group ingress rules, VPC flow logs, default SG lockdown, public subnet analysis | CC6.6 |
| **Storage** | S3 encryption, versioning, public access blocks, SSL-only policies | CC6.7 |
| **Encryption** | EBS encryption by default, EBS volume encryption, RDS encryption at rest, RDS public access, RDS backups | CC6.6, CC6.7 |
| **Monitoring** | CloudTrail configuration, GuardDuty status, AWS Config recording, Inspector vulnerability scanning | CC7.1, CC7.2, CC8.1 |

Every check produces a `Finding` object with: severity, compliance status, resource ID, SOC 2 control mapping, plain-English description, and remediation guidance.

### 2. SOC 2 Compliance Framework

- **Control definitions** for CC1.1 through CC9.1 with automated check mappings
- **Compliance scoring** — percentage score and letter grade (A-F) based on assessed controls
- **Control-level aggregation** — see which SOC 2 controls are passing, failing, or need policy documents
- **17 auditor-grade control tests** — formal test ID, objective, procedure, expected/actual result, evidence, pass/fail

### 3. Report Generation (3 Formats)

| Format | Use Case |
|--------|----------|
| **Markdown** | Working sessions, easy to review in any editor, version-controllable |
| **HTML** | Sharing via email/browser — styled with grade box, color-coded severity, professional layout |
| **PDF** | Formal deliverables to auditors, investors, board members |

Reports include: executive summary, SOC 2 control status table, critical/high findings with remediation, passing controls, policy-required controls, and a prioritized remediation roadmap.

### 4. Remediation Engine

- **14 Terraform template generators** covering: password policy, MFA setup, security group restriction, VPC flow logs, S3 versioning, S3 SSL enforcement, S3 encryption, S3 public access blocks, IAM group migration, least privilege policies
- **Bundled Terraform file** — all fixes in one `remediation.tf` for review and apply
- **Founder-friendly explanations** — each finding includes a plain-English "why this matters" analogy (e.g., "MFA is like a second lock on your front door")
- **Step-by-step instructions** — both AWS Console and CLI paths
- **Effort estimates** — quick (<30 min), moderate (1-4 hrs), or significant (>4 hrs)

### 5. Policy Document Generation

8 SOC 2 policy documents, generated with company name and effective date, structured for auditor review:

| Policy | SOC 2 Controls | What It Covers |
|--------|---------------|----------------|
| Access Control | CC6.1, CC6.2, CC6.3, CC5.1 | Authentication, authorization, least privilege, access reviews, offboarding |
| Change Management | CC8.1, CC5.1 | Code review, deployment process, audit trail, emergency changes |
| Incident Response | CC7.1, CC7.2, CC2.1 | Detection, classification, containment, eradication, recovery, post-mortem |
| Risk Assessment | CC3.1 | Risk identification, likelihood/impact analysis, risk register, treatment |
| Vendor Management | CC9.1 | Vendor classification, assessment, SOC 2 report review, offboarding |
| Data Classification | CC6.7, CC9.1 | Confidential/internal/public levels, handling requirements, retention |
| Acceptable Use | CC1.1, CC2.1 | Employee responsibilities, prohibited activities, security awareness |
| Business Continuity | CC9.1 | RTO/RPO targets, backup strategy, DR procedures, testing schedule |

### 6. Continuous Compliance Monitoring

#### Real-time Detection (AWS-native, seconds latency)
- **12 AWS Config managed rules** — password policy, root MFA, user MFA, no direct policies, key rotation, restricted SSH, VPC flow logs, S3 encryption, S3 public access, S3 SSL, CloudTrail, GuardDuty
- **6 EventBridge rules** — root account usage, security group changes, IAM policy changes, S3 policy changes, Config non-compliance, GuardDuty findings
- **Alert pipeline** — SNS topic → Lambda → Slack alerts + Jira ticket creation

#### Scheduled Compliance (daily/weekly via Claude Code cron triggers)
- **Full compliance scan** with drift detection — compares current vs. previous scan
- **Drift reports** — new findings (regressions), resolved findings (improvements), score trend
- **Evidence collection** — 9 configuration snapshot types, timestamped, manifested

### 7. Access Review Workflow

Quarterly IAM access review (required by SOC 2 CC6.2/CC6.3):
- Enumerates every user: console access, MFA, access keys, groups, policies, last activity
- Flags issues: `CONSOLE_NO_MFA`, `INACTIVE_90d`, `KEY_STALE_90d`, `DIRECT_POLICIES`, `OVERPRIVILEGED`
- Generates Markdown report with reviewer sign-off section for audit evidence

### 8. SBOM + Supply Chain Security

- **Dependency discovery** from Lambda functions (runtimes, layers, env vars), ECR images (via Inspector), EC2 instances (via SSM inventory)
- **Known-compromised package database** — 15+ cataloged supply chain attacks: LiteLLM, xz-utils, event-stream, ua-parser-js, polyfill.io, node-ipc, colors, faker, coa, rc, ctx, pytorch-nightly
- **Live vulnerability scanning** via OSV.dev (batch API covering NVD, PyPI, npm, Go, Maven, RubyGems, NuGet)
- **CISA KEV cross-reference** — flags actively exploited vulnerabilities
- **CycloneDX 1.5 SBOM output** — industry-standard format

### 9. Personalized Threat Advisory

Daily threat intelligence filtered to YOUR tech stack:
- Queries NVD API for recent CVEs matching detected dependencies
- Queries CISA Known Exploited Vulnerabilities for actively exploited threats
- Queries GitHub Advisory Database for supply chain incidents
- Filters everything through SBOM — only shows what's relevant to your environment
- Outputs: Markdown report + Slack-formatted message
- Example: "2 HIGH CVEs affecting Python 3.12 in the last 7 days — you run 3 Lambda functions on Python 3.12"

### 10. Automated Security Assessment (Pen Testing)

Attack surface analysis that produces auditor-grade pen test evidence:
- **Internet exposure scan** — finds EC2 instances with public IPs, public RDS, internet-facing ALBs
- **Attack path mapping** — exposed resource + open ports + known vulnerabilities = risk rating
- **Inspector network reachability** — integration with AWS Inspector for deep network analysis
- **Risk prioritization** — public databases (critical) > management ports (high) > general exposure (medium)

### 11. Integrations

| Integration | What It Does |
|------------|-------------|
| **GitHub** | Checks branch protection, required PR reviews, CI/CD status checks, force push prevention (CC8.1) |
| **Slack** | Scan summaries, finding alerts (color-coded by severity), drift reports, daily threat advisories |
| **Jira** | Auto-creates tickets for critical/high findings with full Atlassian Document Format descriptions, labels, and severity |
| **AWS SecurityHub** | Aggregates all findings from Config, GuardDuty, Inspector |
| **AWS Inspector** | Continuous vulnerability scanning of EC2, ECR, Lambda |

---

## Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                      Claude Code CLI                            │
│                (Orchestrator / User Interface)                   │
├────────────────────────────────────────────────────────────────┤
│  Skills (14 user-facing commands)                               │
│  /connect-aws  /scan  /gap-analysis  /report  /remediate       │
│  /policy-gen   /review-access  /evidence  /sbom                │
│  /threat-advisory  /pentest                                     │
├────────────────────────────────────────────────────────────────┤
│  Integrations          │  Threat Intelligence                   │
│  GitHub, Slack, Jira   │  NVD, CISA KEV, OSV.dev, GitHub Adv. │
├────────────────────────────────────────────────────────────────┤
│  Core Libraries (Python)                                        │
│  aws/  compliance/  evidence/  remediation/  reports/           │
│  policies/  sbom/  threat_intel/  workflows/  integrations/    │
├────────────────────────────────────────────────────────────────┤
│  Continuous Monitoring (AWS-native)                              │
│  Config Rules (12) │ EventBridge (6) │ SecurityHub │ Inspector │
│  SNS → Lambda → Slack/Jira alert pipeline                      │
├────────────────────────────────────────────────────────────────┤
│  Data Layer                                                     │
│  SQLite DB  │  JSON Evidence  │  CycloneDX SBOM  │  Reports   │
└────────────────────────────────────────────────────────────────┘
         │
         ▼
    AWS Account (42 read-only API permissions via boto3)
```

### Design Principles

- **Read-only by default** — Shasta never modifies your AWS environment. All remediation is provided as Terraform/CLI for you to review and apply.
- **AI-native interface** — Claude's reasoning explains findings, generates policies tailored to your environment, and walks you through fixes interactively.
- **Zero infrastructure** — runs locally, stores data in SQLite + JSON. No SaaS dependency.
- **Evidence-first** — every check produces timestamped, auditor-reviewable evidence artifacts.
- **Modular** — each compliance domain is an independent module. Add new checks without touching existing ones.

---

## Quick Start

```bash
# 1. Clone and install
git clone https://github.com/kkmookhey/shasta.git
cd shasta
pip install -e ".[dev]"

# 2. Configure AWS (read-only access)
aws configure --profile shasta
# Or use the scoped policy: infra/shasta-scanning-policy.json (42 permissions)

# 3. Open Claude Code and run
/connect-aws    # Validate credentials, discover services
/scan           # Full SOC 2 compliance scan
/gap-analysis   # Interactive gap analysis with AI guidance
/report         # Generate PDF/HTML/MD reports
/remediate      # Get Terraform fixes for findings
/policy-gen     # Generate 8 SOC 2 policy documents
```

See [DEPLOYMENT.md](DEPLOYMENT.md) for the complete setup guide including exact IAM permissions.

---

## Skills Reference

| Skill | Description | Output |
|-------|-------------|--------|
| `/connect-aws` | Validate AWS credentials, discover account topology and services | Account info, service list |
| `/scan` | Run all compliance checks (IAM, network, storage, encryption, monitoring) | Findings with AI explanations |
| `/gap-analysis` | Interactive SOC 2 gap analysis with control-by-control walkthrough | Gap analysis report |
| `/report` | Generate compliance reports in all formats | MD, HTML, PDF files |
| `/remediate` | Interactive remediation with Terraform code and step-by-step instructions | Terraform bundle + guidance |
| `/policy-gen` | Generate all 8 SOC 2 policy documents tailored to your company | Policy documents |
| `/review-access` | Quarterly IAM access review with user inventory and flags | Access review report |
| `/evidence` | Collect point-in-time configuration snapshots for audit trail | 9 JSON evidence artifacts |
| `/sbom` | Generate SBOM and scan for vulnerable/compromised packages | CycloneDX SBOM + vuln report |
| `/threat-advisory` | Personalized threat intel filtered to your tech stack | Threat advisory (MD + Slack) |
| `/pentest` | Automated security assessment — attack surface and exposure analysis | Security assessment report |

---

## SOC 2 Coverage

For a **<50 employee startup** pursuing **SOC 2 Type II Security**:

| Category | Coverage | Method |
|----------|----------|--------|
| Technical AWS controls | ~85% | 40+ automated checks across 5 domains |
| Policy/process controls | ~80% | 8 generated policy documents |
| Continuous monitoring | ~90% | 12 Config Rules + 6 EventBridge rules + GuardDuty + Inspector |
| Audit evidence | ~80% | Control tests, evidence snapshots, access reviews, reports |
| Vulnerability management | ~85% | Inspector + SBOM + OSV.dev + CISA KEV |
| Supply chain security | ~80% | SBOM discovery + known-compromised DB + live scanning |
| Change management | ~75% | GitHub integration + CloudTrail + Config |

**Overall: ~80% of SOC 2 Type II Security automated or templated.**

### What's NOT Covered (Founder Handles Manually)

- **Security awareness training** — use your company's e-learning portal
- **Background checks** — HR process, not automatable
- **Active risk register** — Shasta generates the policy template; you maintain the living document
- **Active vendor inventory** — Shasta generates the policy; you track actual vendors
- **Annual BCP/DR tabletop exercise** — process, not tooling
- **Physical security** — N/A for cloud-native companies

---

## The Build Journey — A Vibe Coding Case Study

This platform was built in a single Claude Code session through iterative human-AI collaboration. Here's how the conversation evolved from a one-paragraph idea to a 10,500-line production platform.

### The Conversation Arc

**Turn 1 — The Vision (Human)**
> "I would like to create a Vanta clone. A set of Skills, sub-agents, plug-ins, etc which a founder can use to plug into their AWS environment and conduct a gap analysis against SOC2, as well as get complete guidance on what they need to do next, and also all the capabilities to maintain their compliance through the year."

The human provided a clear, ambitious vision but left architecture and implementation entirely to the AI. This is the essence of vibe coding — describe the outcome, not the steps.

**Turn 2 — Architecture & Planning (AI)**
Claude entered plan mode and produced:
- Full system architecture diagram
- SOC 2 control-to-AWS service mapping table
- Detailed project structure (every file path)
- 6-phase implementation plan
- 8 clarifying questions to narrow scope

**Turns 3-5 — Scope Decisions (Human)**
The human made key product decisions through multiple-choice questions:
- SOC 2 Security only (not all 5 criteria) — *right call: 90% of startups need this*
- Full compliance suite (policies, not just AWS checks) — *right call: auditors need both*
- Semi-technical founder persona — *shaped all UX decisions*
- Markdown + PDF from day one — *not obvious, but founders need to share reports*
- Terraform for IaC — *most adopted by startups*
- Claude Code cron triggers for scheduling — *keeps everything in one tool*

**Turns 6-8 — Phase 1: Foundation**
Built project scaffolding, AWS client, database, data models, first skill (`/connect-aws`). Tested against live AWS account. Hit Python version mismatch (`py -3.12` vs `python`) — AI adapted and remembered for all subsequent commands.

**Turn 9 — Phase 2: First Real Checks**
IAM security checks (7 check functions). First live scan: 33.3% compliance score, 4 failures, 2 passes. 100% accuracy against expected outcomes.

**Turn 10 — Phase 3: Full Security Scanner**
Added networking, storage, and logging checks. Full scan: 34 findings, 37.5% score. Every intentionally broken resource was correctly flagged.

**Turns 11-12 — Phase 4 & 5: Reports + Remediation**
Gap analysis engine, HTML/PDF report generation (hit WeasyPrint GTK dependency issue on Windows → pivoted to xhtml2pdf), remediation engine with 14 Terraform templates, 8 policy document templates.

**Turn 13 — Phase 6: Continuous Compliance**
Access review workflow, drift detection, evidence collection. Fixed a foreign key constraint bug in the evidence store.

**Turn 14 — The Critical Self-Assessment**
Human asked: *"Review your own output as a compliance expert and compare with Vanta/Drata. What's missing?"*

This was the most valuable prompt in the session. The AI produced an honest gap analysis:
- ~25-30% coverage at that point (not 80% as might be assumed from passing checks)
- Identified 6 "audit blocker" gaps and 8 "significant" gaps
- Acknowledged the entire human/organizational dimension was missing
- Proposed Phases 7A-7E with clear prioritization

**Turn 15 — Phase 7: Closing the Gaps**
Human added requirements:
- Continuous monitoring architecture (how does real-time detection work?)
- Slack and Jira integrations
- The AI explained the three monitoring approaches (polling vs. event-driven vs. hybrid) and recommended the hybrid architecture

Built and deployed:
- 17 auditor-grade control tests
- 12 AWS Config Rules + 6 EventBridge rules + SecurityHub + Inspector
- Lambda alert forwarder for Slack/Jira
- GitHub branch protection checks
- Slack and Jira Python clients

**Turn 16 — Phase 8: Differentiation**
Human pushed further:
- Daily personalized threat advisories
- SBOM + supply chain vulnerability scanning
- Automated pen testing

These three features pushed Shasta beyond Vanta/Drata territory into genuinely differentiated capabilities. The threat advisory — filtering live CVE feeds through the founder's actual SBOM — is something no competitor offers.

**Turn 17 — EBS/RDS encryption checks**
Closed the last known gap in CC6.7 data protection coverage.

**Turn 18 — Packaging & Deployment**
Deployment guide with exact IAM policy (42 read-only permissions), GitHub repo creation, initial commit.

### Key Decision Points That Shaped the Platform

| Decision | Who Made It | Impact |
|----------|-------------|--------|
| Claude Code skills as UI (not web app) | AI | Zero infrastructure, AI reasoning is the interface |
| SOC 2 Security only for v1 | Human | Focused scope, faster to useful |
| Semi-technical founder persona | Human | Plain English everywhere, step-by-step guidance |
| Intentionally broken test resources | AI | Validated scanner accuracy (100% match) |
| Event-driven monitoring (not polling) | AI | Real-time detection, AWS does the heavy lifting |
| Self-assessment against Vanta | Human | Honest gap analysis prevented premature "done" |
| SBOM + threat advisory | Human | Genuine differentiation beyond Vanta/Drata |
| Read-only scanning only | Human | Trust model — never modify customer's AWS |

---

## Vibe Coding Best Practices for Security Projects

This build demonstrates effective patterns for using AI to build security-critical software. Here's what worked, what didn't, and what to watch for.

### 1. Start with the Outcome, Not the Architecture

**Do:** "I want founders to scan their AWS and get a SOC 2 gap analysis with remediation guidance."

**Don't:** "Create a Python module that calls boto3 to enumerate IAM users and check MFA status."

The first prompt lets the AI bring its full knowledge of SOC 2, AWS security, and compliance platforms to the architecture. The second constrains it to a single function.

### 2. Let the AI Propose, Then Steer

The most productive pattern was:
1. Human describes a goal
2. AI proposes architecture + plan + asks clarifying questions
3. Human answers questions and adds constraints
4. AI builds
5. Human tests and provides feedback
6. Repeat

The human never wrote a line of code. But every major product decision (scope, persona, output format, trust model) was the human's call.

### 3. Test Against Reality Immediately

We didn't build in a vacuum. After every phase:
- Deployed test resources to a real AWS account
- Ran the scanner against live infrastructure
- Verified every finding matched expected outcomes
- Fixed bugs discovered through real execution

The intentionally broken test environment (weak password policy, open security groups, unencrypted buckets alongside properly configured resources) was critical — it proved the scanner could distinguish good from bad.

### 4. The Self-Assessment Prompt is Essential

The highest-value prompt in this entire session was: *"Review your own output as a compliance expert and compare with Vanta/Drata. What's missing?"*

This forced honest gap analysis rather than premature celebration. The AI identified that we were at ~25-30% coverage (not the ~80% our passing checks might suggest) because we'd missed entire categories: people/HR, SaaS integrations, structured audit evidence, vendor management workflows.

**Always ask the AI to critique its own work before calling it done.**

### 5. Security-Specific Vibe Coding Patterns

#### a. Compliance Framework First, Checks Second
We defined the SOC 2 control framework before writing any AWS checks. This ensured every check maps to a real control, nothing is built without a compliance purpose, and gaps are visible in the framework before they're discovered by auditors.

#### b. Evidence-First Design
Every check produces evidence artifacts, not just pass/fail. An auditor needs to see *what was checked*, *what was found*, and *when*. Building this into the data model from day one (the `Finding` and `Evidence` models) meant evidence collection was natural, not bolted on.

#### c. Read-Only by Default
A critical trust decision: Shasta never modifies the customer's AWS environment. Remediation is Terraform code the founder reviews and applies themselves. This is the right trust model for a security tool — if it can write, it can break.

#### d. Defense in Depth for the Tool Itself
- No credentials stored — uses the standard AWS credential chain
- No data exfiltrated — everything stays on the local machine
- No external SaaS dependencies — SQLite + JSON files
- Clear IAM permission scope — 42 read-only API actions, documented

#### e. Assume the Auditor is the Reader
Reports, control tests, and evidence are structured for auditor consumption. Formal test IDs (CT-IAM-001), objectives, procedures, expected/actual results, and sign-off sections. This isn't just good UX — it's the difference between "nice security tool" and "audit-ready platform."

### 6. The Terraform Test Environment Pattern

Building a test environment with **intentionally non-compliant resources alongside properly configured ones** is a powerful pattern:
- Validates that checks detect real violations
- Validates that passing resources aren't flagged as false positives
- Creates a realistic environment without needing production data
- Can be torn down and recreated in minutes

Every test resource was tagged with `shasta_expected = "fail"` or `"pass"` so we could verify scanner accuracy against ground truth.

### 7. Iterative Scope Expansion

The build followed a natural expansion:
1. Can we connect? (Phase 1)
2. Can we detect one thing? (Phase 2 — IAM only)
3. Can we detect everything? (Phase 3 — all domains)
4. Can we explain it? (Phase 4 — reports)
5. Can we fix it? (Phase 5 — remediation)
6. Can we keep it fixed? (Phase 6 — continuous compliance)
7. Is it audit-ready? (Phase 7 — control tests, integrations)
8. Is it differentiated? (Phase 8 — SBOM, threat intel, pen testing)

Each phase was tested against reality before moving on. No phase was planned in isolation — each built on learnings from the previous one.

### 8. When the AI Gets It Wrong

Things that went wrong during this build:
- **WeasyPrint on Windows** — requires GTK/Pango native libraries. AI pivoted to xhtml2pdf.
- **xhtml2pdf + CSS variables** — xhtml2pdf doesn't support `var()`. AI added a post-processor to resolve variables to literals.
- **Python version mismatch** — `py` defaults to 3.13 but packages installed in 3.12. AI adapted and remembered `py -3.12` for all subsequent commands.
- **S3 tag values with commas** — AWS rejects commas in tag values. Fixed immediately.
- **SQLite foreign key constraint** — evidence store had a FK to findings that was too strict for general config snapshots. Fixed the schema.
- **Inspector API** — `SEVERITY` is not a valid aggregation type. Switched to `ACCOUNT` aggregation.
- **Working directory drift** — Terraform `cd` shifted the CWD. Affected subsequent file reads.

In every case, the pattern was: error → diagnose → fix → continue. No error required starting over. The AI's ability to read error messages, understand root causes, and adapt immediately is the core advantage of vibe coding.

---

## Build Metrics

### Session Statistics

| Metric | Value |
|--------|-------|
| **Total conversation turns** | ~36 (18 human, 18 AI) |
| **Wall-clock time** | ~3 hours |
| **Lines of code written** | 10,537 |
| **Files created** | 67 |
| **Python modules** | 22 |
| **Claude Code skills** | 14 (11 user-facing + 3 planned) |
| **Terraform resources deployed** | ~55 (test env + monitoring) |
| **AWS services integrated** | 15 (IAM, EC2, S3, RDS, Lambda, CloudTrail, GuardDuty, Config, Inspector, SecurityHub, EventBridge, SNS, KMS, ECS, CloudWatch) |
| **SOC 2 controls covered** | 13 (8 automated + 5 policy-only) |
| **Automated checks** | 40+ |
| **Control tests** | 17 |
| **Policy templates** | 8 |
| **Terraform remediation templates** | 14 |
| **External APIs integrated** | 5 (NVD, CISA KEV, OSV.dev, GitHub Advisory, GitHub API) |
| **Unit tests** | 9 (passing) |

### Token Consumption Estimate

| Phase | Estimated Input Tokens | Estimated Output Tokens |
|-------|----------------------|------------------------|
| Planning & Architecture | ~15,000 | ~25,000 |
| Phase 1-2 (Foundation + IAM) | ~20,000 | ~35,000 |
| Phase 3-4 (Full scan + Reports) | ~25,000 | ~45,000 |
| Phase 5-6 (Remediation + Continuous) | ~20,000 | ~50,000 |
| Self-assessment + Phase 7 | ~30,000 | ~60,000 |
| Phase 8 (SBOM + Threat Intel + Pen Test) | ~15,000 | ~50,000 |
| Packaging + README | ~10,000 | ~30,000 |
| **Total (estimated)** | **~135,000** | **~295,000** |
| **Grand total (estimated)** | **~430,000 tokens** | |

*Note: These are estimates based on conversation length and code volume. Actual token counts may vary. The session used the Claude Opus 4.6 model with 1M context window.*

### Cost Perspective

At ~430K tokens on Claude Opus, the API cost for this entire build would be roughly $15-25. Compare this to:
- Vanta annual subscription: $10,000-30,000/year
- Hiring a compliance consultant: $150-300/hour
- Building this manually: 2-4 engineer-months

---

## Project Structure

```
shasta/
├── CLAUDE.md                              # Claude Code project instructions
├── DEPLOYMENT.md                          # Complete deployment guide
├── README.md                              # This file
├── pyproject.toml                         # Python project configuration
│
├── skills/                                # Claude Code skills (user interface)
│   ├── connect-aws.md                     # AWS connection and validation
│   ├── scan.md                            # Full compliance scan
│   ├── gap-analysis.md                    # Interactive gap analysis
│   ├── report.md                          # Report generation (MD/HTML/PDF)
│   ├── remediate.md                       # Terraform remediation guidance
│   ├── policy-gen.md                      # Policy document generation
│   ├── review-access.md                   # Quarterly access review
│   ├── evidence.md                        # Evidence collection
│   ├── sbom.md                            # SBOM + supply chain scanning
│   ├── threat-advisory.md                 # Personalized threat intelligence
│   └── pentest.md                         # Automated security assessment
│
├── src/shasta/
│   ├── scanner.py                         # Scan orchestrator
│   ├── aws/                               # AWS interaction layer
│   │   ├── client.py                      # boto3 session management
│   │   ├── iam.py                         # IAM security checks (7 functions)
│   │   ├── networking.py                  # Network security checks (3 functions)
│   │   ├── storage.py                     # S3 security checks (4 functions)
│   │   ├── encryption.py                  # EBS/RDS encryption checks (5 functions)
│   │   ├── logging_checks.py             # CloudTrail/GuardDuty/Config checks
│   │   ├── vulnerabilities.py            # AWS Inspector integration
│   │   └── pentest.py                     # Attack surface analysis
│   ├── compliance/                        # SOC 2 framework
│   │   ├── framework.py                   # Control definitions (13 controls)
│   │   ├── mapper.py                      # Finding → control mapping
│   │   ├── scorer.py                      # Compliance scoring engine
│   │   └── testing.py                     # Auditor-grade control tests (17 tests)
│   ├── evidence/                          # Evidence management
│   │   ├── models.py                      # Data models (Finding, Evidence, ScanResult)
│   │   ├── store.py                       # SQLite-backed storage
│   │   └── collector.py                   # 9 evidence collection functions
│   ├── remediation/
│   │   └── engine.py                      # Remediation engine + 14 Terraform generators
│   ├── policies/
│   │   └── generator.py                   # 8 policy document templates
│   ├── reports/
│   │   ├── generator.py                   # MD + HTML report generation
│   │   └── pdf.py                         # PDF generation via xhtml2pdf
│   ├── integrations/
│   │   ├── github.py                      # Branch protection + PR review checks
│   │   ├── slack.py                       # Slack webhook integration
│   │   └── jira.py                        # Jira ticket creation
│   ├── sbom/
│   │   ├── discovery.py                   # Dependency discovery + SBOM generation
│   │   └── vuln_scanner.py                # OSV.dev + CISA KEV vulnerability scanning
│   ├── threat_intel/
│   │   └── advisory.py                    # Personalized threat advisory engine
│   ├── workflows/
│   │   ├── access_review.py               # Quarterly access review workflow
│   │   └── drift.py                       # Compliance drift detection
│   └── db/
│       └── schema.py                      # SQLite schema + CRUD operations
│
├── infra/
│   ├── shasta-scanning-policy.json        # IAM policy (42 read-only permissions)
│   └── test-env/
│       ├── main.tf                        # Test resources (compliant + non-compliant)
│       ├── monitoring.tf                  # Config Rules, EventBridge, SecurityHub, Inspector
│       └── lambda/
│           └── alert_forwarder.py         # SNS → Slack + Jira Lambda
│
├── tests/                                 # pytest test suite
│   ├── conftest.py
│   └── test_aws/
│       ├── test_client.py                 # AWS client tests (moto)
│       └── test_models.py                 # Data model + DB tests
│
└── data/                                  # Runtime data (gitignored)
    ├── shasta.db                          # SQLite database
    ├── evidence/                          # Evidence snapshots
    ├── reports/                           # Generated reports
    ├── policies/                          # Generated policy documents
    ├── sbom/                              # SBOM + vulnerability reports
    ├── advisories/                        # Threat advisory reports
    └── remediation/                       # Terraform bundles
```

---

## What's Next

### Immediate Improvements
- [ ] Risk register workflow (CSV/JSON-based, with tracking)
- [ ] Vendor inventory management (active tracking, not just policy)
- [ ] EBS snapshot encryption checks
- [ ] RDS snapshot public access checks
- [ ] Multi-region scanning support

### Medium Term
- [ ] GCP and Azure scanning modules
- [ ] ISO 27001 framework mapping
- [ ] HIPAA control framework
- [ ] Security questionnaire auto-fill from evidence
- [ ] Employee onboarding/offboarding tracking
- [ ] Trust center page generation

### Long Term
- [ ] Multi-account AWS Organizations support
- [ ] Compliance score trending dashboard (HTML)
- [ ] Audit management workflow (auditor request tracking)
- [ ] Custom control framework definitions
- [ ] CI/CD compliance gate (fail pipeline if non-compliant)

---

## License

Private repository. Contact kkmookhey for access.

---

*Built with Claude Code (Opus 4.6) in a single session. The entire platform — from architecture to deployment — was created through human-AI collaboration, demonstrating that vibe coding can produce production-quality security tooling when guided by domain expertise.*
