# Whitney — AI Security & Governance Platform

**The first open-source toolkit that audits your AI stack the same way you audit your cloud.**

Whitney scans your cloud AI services (AWS Bedrock, SageMaker, Azure OpenAI, Azure ML) and your GitHub repositories for AI security issues — prompt injection risks, hardcoded API keys, PII in prompts, unguarded AI agents, and more. Findings are mapped to ISO 42001 and the EU AI Act simultaneously.

Part of the Sierra Nevada mountain range: **Shasta** (14,179 ft) secures your cloud. **Whitney** (14,505 ft) secures your AI.

### Deterministic by Design

Whitney uses **zero LLM calls**. Every finding is produced by Semgrep AST-based pattern matching (with regex fallback), AWS/Azure SDK API calls, dictionary lookups, and arithmetic. There is no probabilistic model, no prompt, no token consumption in the scanning pipeline.

The code scanner uses a **dual-engine architecture**: when [Semgrep](https://semgrep.dev) is installed, 13 of the 20 code checks run as AST-aware Semgrep rules (more precise than regex, immune to formatting issues, won't match in comments). The 7 checks that need file-level context analysis (rate limiting, outdated SDK, MCP server security, A2A protocol security) stay as Python. If Semgrep is not installed, all 20 checks fall back to the original regex engine.

This is a deliberate architectural choice and a differentiator. Most AI security vendors (Straiker, Lakera, CalypsoAI) use LLMs in their detection pipeline, which means their results vary between runs. Whitney's results are **100% reproducible**: same code + same infrastructure = same findings, every time.

Claude Code serves as the user interface — it calls Whitney's Python functions and formats the output. But the compliance engine itself is pure deterministic code.

---

## Why Whitney?

Your customers are asking questions SOC 2 can't answer:

- *"How do you govern your use of LLMs?"*
- *"Can your AI access our customer data?"*
- *"Are you compliant with the EU AI Act?"*
- *"Show me your AI risk assessment."*

No startup has good answers today. Whitney gives you those answers — automated checks, plain-English findings, and auditor-grade evidence.

---

## How Code Scanning Works (Level 1 SAST)

Whitney's code scanner uses [Semgrep](https://semgrep.dev) for AST-based pattern matching, with a regex fallback if Semgrep is not installed. This is "Level 1 SAST" — proper static analysis that understands language grammar, not just text patterns.

### Why AST-based instead of regex?

Regex pattern matching is fast and simple but has known limitations:

| Problem | Regex | Semgrep |
|---------|-------|---------|
| `# api_key = "sk-..."` in a comment | Matches (false positive) | Skipped (AST-aware) |
| `Tool(func=lambda c: exec(c))` — dangerous? | Only matches if `exec` is within 20 lines (fragile) | `pattern-inside: Tool(...)` — structural containment |
| `model="gpt-4"` with extra whitespace or different quotes | Formatting-dependent | AST-normalized |
| Route + inference + missing auth decorator | 3 separate regex scans with sliding windows | Single rule with `pattern-not-inside: @login_required` |

### Dual-engine architecture

```
scan_repository(repo_path)
  │
  ├── If Semgrep installed:
  │     ├── Run 13 Semgrep YAML rules (AST-based)
  │     └── Run 2 Python checks (rate limiting, outdated SDK)
  │
  └── If Semgrep NOT installed (graceful fallback):
        └── Run all 15 Python regex checks (original engine)
```

The 2 checks that stay as Python need logic Semgrep doesn't model well:

- `check_no_rate_limiting` — file-level memoization (skip entire file if rate limiting found anywhere)
- `check_outdated_ai_sdk` — dependency file parsing + version constraint comparison

### Install with Semgrep

```bash
pip install -e ".[semgrep]"
```

Or run without it — the regex fallback ensures Whitney works for everyone.

### Still deterministic

Semgrep is an AST pattern matcher, not an LLM. Same code + same rules = identical findings every time. Whitney's "no LLM in the pipeline" guarantee is unchanged — see [TRUST.md](TRUST.md) for verification.

---

## What Whitney Does

### 1. Code Repository Scanning (15 checks)

Whitney scans your actual source code for AI security issues. This is the differentiator — no other compliance tool does this.

| Severity | Check | What It Finds |
|----------|-------|---------------|
| CRITICAL | `code-ai-api-key-exposed` | Hardcoded OpenAI/Anthropic/HuggingFace API keys in source code |
| CRITICAL | `code-ai-key-in-env-file` | AI API keys in committed `.env` files |
| HIGH | `code-prompt-injection-risk` | User input passed directly into LLM prompts without sanitization |
| HIGH | `code-no-output-validation` | LLM responses used without content filtering or validation |
| HIGH | `code-pii-in-prompts` | PII patterns (emails, SSNs, credit cards) in prompt templates |
| HIGH | `code-model-endpoint-public` | Model serving endpoints with no authentication |
| HIGH | `code-agent-unrestricted-tools` | AI agents with access to shell, filesystem, or DB without guardrails |
| MEDIUM | `code-rag-no-access-control` | RAG pipelines querying vector DBs without user-level access filtering |
| MEDIUM | `code-no-rate-limiting` | AI API calls without rate limiting or cost controls |
| MEDIUM | `code-meta-prompt-exposed` | System prompts extractable by end users |
| MEDIUM | `code-ai-logging-insufficient` | AI API calls not logged (no audit trail) |
| MEDIUM | `code-outdated-ai-sdk` | AI SDK versions with known CVEs (LangChain, transformers, etc.) |
| MEDIUM | `code-training-data-unencrypted` | Training data read from unencrypted or HTTP sources |
| LOW | `code-no-model-versioning` | Model version not pinned (e.g., `gpt-4` instead of `gpt-4-0613`) |
| LOW | `code-no-fallback-handler` | AI API calls without error handling or timeouts |

### 2. Cloud AI Service Checks (30 checks)

#### AWS — Bedrock, SageMaker, Lambda (15 checks)

| Check | What It Verifies |
|-------|-----------------|
| `bedrock-guardrails-configured` | Bedrock guardrails exist and are active |
| `bedrock-model-invocation-logging` | Bedrock API calls logged to CloudTrail/CloudWatch |
| `bedrock-vpc-endpoint` | Bedrock accessed via VPC endpoint, not public internet |
| `bedrock-content-filter` | Content filtering enabled on model responses |
| `bedrock-agent-guardrails` | Bedrock agents have guardrails configured |
| `sagemaker-model-registry-access` | Model registry has least-privilege IAM |
| `sagemaker-endpoint-encryption` | Endpoints use TLS + KMS encryption |
| `sagemaker-training-vpc` | Training jobs run in VPC (data isolation) |
| `sagemaker-model-approval` | Model deployment requires approval step |
| `sagemaker-data-capture` | Inference data capture enabled (audit trail) |
| `sagemaker-notebook-root-access` | Notebooks don't run as root |
| `lambda-ai-api-keys-not-hardcoded` | No AI API keys as plaintext in Lambda env vars |
| `s3-training-data-encrypted` | S3 buckets with training data are encrypted |
| `s3-training-data-versioned` | Training data buckets have versioning (lineage) |
| `cloudtrail-ai-events` | CloudTrail captures SageMaker/Bedrock data events |

#### Azure — OpenAI, ML, Cognitive Services (15 checks)

| Check | What It Verifies |
|-------|-----------------|
| `azure-openai-content-filter` | Content filtering configured and not weakened |
| `azure-openai-key-rotation` | API keys rotated within 90 days |
| `azure-openai-private-endpoint` | Accessed via Private Endpoint, not public |
| `azure-openai-diagnostic-logging` | Diagnostic settings export API call logs |
| `azure-openai-managed-identity` | Uses managed identity instead of API keys |
| `azure-openai-abuse-monitoring` | Abuse monitoring not disabled |
| `azure-ml-workspace-encryption` | Workspace encrypted with customer-managed key |
| `azure-ml-compute-rbac` | Compute targets have scoped RBAC |
| `azure-ml-model-registration` | Models registered in registry (versioned) |
| `azure-ml-data-drift-monitor` | Data drift monitoring configured |
| `azure-cognitive-network-rules` | Cognitive Services have network restrictions |
| `azure-cognitive-cmk` | Cognitive Services encrypted with CMK |
| `azure-ai-search-auth` | AI Search uses managed identity or API key auth |
| `azure-responsible-ai-dashboard` | Responsible AI dashboard deployed |
| `azure-ml-environment-pinned` | ML environments pinned (reproducible builds) |

### 3. Compliance Framework Coverage

| Framework | Controls | What It Covers |
|-----------|---------|---------------|
| **ISO 42001** (AI Management Systems) | 11 controls (7 automated + 4 policy) | AI policy, risk assessment, system lifecycle, data governance, monitoring, security, third-party AI |
| **EU AI Act** | 8 obligations | Risk management, data governance, documentation, record-keeping, transparency, human oversight, robustness |

### 4. AI Service Discovery

Automatically discovers AI/ML services running in your cloud accounts:
- **AWS:** SageMaker endpoints/models/training jobs, Bedrock models/guardrails, Comprehend, Lambda functions with AI API keys
- **Azure:** OpenAI deployments, ML workspaces/endpoints, Cognitive Services, AI Search

---

## Quick Start

### Prerequisites

- Python 3.11+
- Shasta installed (`pip install -e ".[dev]"` from the repo root)
- AWS CLI configured (for AWS AI checks) and/or Azure CLI (`az login`) for Azure AI checks
- A Git repository to scan (local or GitHub)

### Installation

Whitney is included in the Shasta package. No separate install needed:

```bash
cd shasta/
pip install -e ".[dev]"
```

### Usage

#### Option 1: Claude Code Skills (Recommended)

Open Claude Code in the `shasta/` directory:

```
/discover-ai          # Find what AI services you're running
/ai-scan              # Full AI governance scan (cloud + code)
/ai-code-review       # Deep code review for AI security issues
```

#### Option 2: Python API

**Scan a code repository:**

```python
from pathlib import Path
from whitney.code.scanner import scan_repository

# Scan current directory
findings = scan_repository(Path("."))

# Scan a GitHub repo (auto-clones)
findings = scan_repository(
    Path("/tmp/my-repo"),
    github_repo="owner/repo",
    github_token="ghp_...",
)

for f in findings:
    print(f"[{f.severity.value.upper()}] {f.check_id}")
    print(f"  {f.title}")
    print(f"  File: {f.details.get('file_path')}:{f.details.get('line_number')}")
    print(f"  Fix: {f.remediation}")
    print()
```

**Run AWS AI cloud checks:**

```python
from shasta.config import get_aws_client
from whitney.cloud.aws_checks import run_all_aws_ai_checks

client = get_aws_client()
client.validate_credentials()
findings = run_all_aws_ai_checks(client)

for f in findings:
    print(f"[{f.status.value.upper()}] {f.check_id}: {f.title}")
```

**Run Azure AI cloud checks:**

```python
from shasta.config import get_azure_client
from whitney.cloud.azure_checks import run_all_azure_ai_checks

client = get_azure_client()
client.validate_credentials()
findings = run_all_azure_ai_checks(client)

for f in findings:
    print(f"[{f.status.value.upper()}] {f.check_id}: {f.title}")
```

**Discover AI services:**

```python
from shasta.config import get_aws_client
from whitney.discovery.aws_ai import discover_aws_ai_services

client = get_aws_client()
client.validate_credentials()
inventory = discover_aws_ai_services(client)
print(inventory)
# {'sagemaker': {'endpoints': 2, 'models': 5}, 'bedrock': {'models_available': 10}, ...}
```

**Score against AI compliance frameworks:**

```python
from whitney.compliance.mapper import enrich_findings_with_ai_controls
from whitney.compliance.scorer import calculate_ai_governance_score

# Enrich findings with ISO 42001 + EU AI Act control mappings
enrich_findings_with_ai_controls(findings)

# Calculate combined score
score = calculate_ai_governance_score(findings)
print(f"ISO 42001:  {score.iso42001_score}% (Grade {score.iso42001_grade})")
print(f"EU AI Act:  {score.eu_ai_act_score}% (Grade {score.eu_ai_act_grade})")
print(f"Combined:   {score.combined_score}% (Grade {score.combined_grade})")
```

**Run everything together:**

```python
from pathlib import Path
from shasta.config import get_aws_client, get_azure_client
from whitney.code.scanner import scan_repository
from whitney.cloud.aws_checks import run_all_aws_ai_checks
from whitney.cloud.azure_checks import run_all_azure_ai_checks
from whitney.compliance.mapper import enrich_findings_with_ai_controls
from whitney.compliance.scorer import calculate_ai_governance_score

# Code scan
findings = scan_repository(Path("."))

# Cloud scans
aws = get_aws_client()
aws.validate_credentials()
findings.extend(run_all_aws_ai_checks(aws))

azure = get_azure_client()
azure.validate_credentials()
findings.extend(run_all_azure_ai_checks(azure))

# Score
enrich_findings_with_ai_controls(findings)
score = calculate_ai_governance_score(findings)

print(f"\nAI Governance Score: {score.combined_score}% ({score.combined_grade})")
print(f"Total findings: {len(findings)}")
print(f"  Code issues: {sum(1 for f in findings if f.resource_type == 'Code::Repository::File')}")
print(f"  Cloud issues: {sum(1 for f in findings if f.resource_type != 'Code::Repository::File')}")
```

---

## Architecture

```
whitney/
├── discovery/              # AI service discovery
│   ├── aws_ai.py           # SageMaker, Bedrock, Comprehend, Lambda
│   └── azure_ai.py         # Azure OpenAI, ML, Cognitive Services
├── code/                   # GitHub code scanner
│   ├── scanner.py          # Repository scanner (clone + analyze)
│   ├── checks.py           # 15 AI security check functions
│   └── patterns.py         # Regex patterns for AI SDKs, keys, prompts, PII
├── cloud/                  # Cloud AI service checks
│   ├── aws_checks.py       # 15 AWS checks (Bedrock, SageMaker, Lambda, S3)
│   └── azure_checks.py     # 15 Azure checks (OpenAI, ML, Cognitive, AI Search)
├── compliance/             # AI governance frameworks
│   ├── iso42001.py          # 11 ISO 42001 control definitions
│   ├── eu_ai_act.py         # 8 EU AI Act obligation definitions
│   ├── mapper.py            # Finding enrichment (check_id → controls)
│   └── scorer.py            # Combined scoring (ISO 42001 + EU AI Act)
├── policies/               # AI governance policy generator
│   └── generator.py        # 7 policy templates (Jinja2)
└── sbom/                   # AI Model Bill of Materials
    └── scanner.py           # CycloneDX 1.5 SBOM for AI SDKs, models, services
```

Whitney shares Shasta's core infrastructure:
- `Finding` model (with `CheckDomain.AI_GOVERNANCE`)
- SQLite database for persistence
- Report generation (Markdown, HTML, PDF)
- Risk register with auto-seeding
- Evidence collection and audit trail

---

## Compliance Framework Details

### ISO 42001 Controls

| ID | Title | Automated | Check Coverage |
|----|-------|-----------|----------------|
| AI-5.2 | AI Policy | Policy template | — |
| AI-6.1 | AI Risk Assessment | Policy template | — |
| AI-8.2 | AI System Impact Assessment | Policy template | — |
| AI-8.3 | AI System Lifecycle | Automated | Model registry, versioning, approval workflows |
| AI-8.4 | Data for AI Systems | Automated | PII scanning, training data encryption/versioning |
| AI-8.5 | AI System Monitoring | Automated | Data capture, drift monitoring, logging |
| AI-A.2 | Policies for AI | Policy template | — |
| AI-A.5 | Data Management | Automated | PII in prompts, data encryption, logging |
| AI-A.6 | Computing Resources | Automated | VPC isolation, encryption, RBAC |
| AI-A.8 | AI System Security | Automated | Prompt injection, guardrails, content filtering, key security |
| AI-A.9 | Third-Party AI | Automated | API key management, managed identity, SDK versions |

### EU AI Act Obligations (High-Risk AI)

| Article | Obligation | Whitney Coverage |
|---------|-----------|-----------------|
| Art. 9 | Risk management system | Risk register + classification engine |
| Art. 10 | Data governance | PII scanning, training data checks |
| Art. 11 | Technical documentation | Architecture review output |
| Art. 12 | Record-keeping | Logging checks (CloudTrail, diagnostics) |
| Art. 13 | Transparency | System prompt exposure detection |
| Art. 14 | Human oversight | Architecture review (human-in-the-loop) |
| Art. 15 | Accuracy, robustness, cybersecurity | Guardrails, content filters, prompt injection |
| Art. 52 | Transparency for certain AI | Disclosure policy for chatbots |

---

## What's Included

- [x] 20 code security checks for AI repositories (including MCP + A2A protocol security)
- [x] 15 AWS cloud checks (Bedrock, SageMaker, Lambda, S3, CloudTrail)
- [x] 15 Azure cloud checks (OpenAI, ML, Cognitive Services, AI Search)
- [x] 7 compliance frameworks (ISO 42001, EU AI Act, NIST AI RMF, NIST AI 600-1, OWASP LLM Top 10, OWASP Agentic Top 10, MITRE ATLAS)
- [x] AI service discovery (AWS + Azure)
- [x] ISO 42001 framework (11 controls, scoring, mapping)
- [x] EU AI Act framework (8 obligations, scoring, mapping)
- [x] AI governance policy generator (7 templates covering all policy-required controls)
- [x] AI SBOM scanner (CycloneDX 1.5 output for SDKs, models, cloud services)
- [x] 446 tests, validated against live AWS and Azure

## What's Next

- [ ] Architecture review engine (automated assessment of 8 security patterns)
- [ ] AI vendor security scorecards (OpenAI, Anthropic, Cohere, Google)
- [ ] NIST AI RMF framework mapping (19 categories, 71 subcategories)
- [ ] Bias and fairness assessment framework
- [ ] Prompt injection testing framework
