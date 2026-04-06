# Shasta & Whitney — Conversation Guide

**You don't need to memorize commands. Just talk.**

Shasta and Whitney are AI-native tools. The Claude Code CLI is your interface — you describe what you need in plain English, and Claude orchestrates the right skills, interprets the results, and guides you through next steps. Think of it as having a compliance expert and security engineer on call 24/7.

This guide shows 15 real conversations you can have. Each one demonstrates how natural language replaces the traditional compliance workflow of "log into dashboard → click through menus → export CSV → interpret results → figure out what to do."

---

## Getting Started

### 1. "I just created an AWS account for my startup. Help me understand my security posture."

**What happens:** Claude connects to your AWS account, discovers what services you're running, executes a full SOC 2 compliance scan, and walks you through every finding in plain English — what it means, why it matters, and exactly how to fix it.

**What you'd get:**
- Account topology (what services are active)
- Compliance score and grade
- Every finding explained like you're a founder, not a security engineer
- Prioritized remediation roadmap (quick wins first)
- Markdown and HTML reports saved to disk

**Example follow-up:** *"That's a lot of findings. Which 3 things should I fix this week to have the biggest impact?"*

---

### 2. "Connect to my AWS environment and run a comprehensive gap assessment against SOC 2 and ISO 27001. Give me a prioritized remediation approach and remediation Terraform scripts. Also, update the risk register."

**What happens:** Claude runs the full scan with dual-framework mapping, generates Terraform code for every fixable finding, ranks fixes by severity and effort, and auto-seeds the risk register with business-level risks derived from technical findings.

**What you'd get:**
- Dual-framework gap analysis (SOC 2 CC controls + ISO 27001 Annex A controls)
- Terraform bundle at `data/remediation/remediation.tf` ready to review and apply
- Risk register at `data/risk-register/` with likelihood/impact matrix and treatment plans
- Everything in one conversation — no switching between tools

---

### 3. "We just got our first enterprise customer prospect. They sent us a security questionnaire. Can you help me fill it out based on what you know about our environment?"

**What happens:** Claude reviews your latest scan results, policies, and evidence to help you answer each question. For questions where Shasta has automated evidence (encryption status, MFA enforcement, logging configuration), it provides specific answers with evidence references. For process questions, it points you to the relevant policy document.

**Example answer Claude might draft:** *"Question: Do you encrypt data at rest? Answer: Yes. All S3 buckets use SSE-KMS encryption (see control test CT-DATA-001). All EBS volumes are encrypted by default (see finding ebs-encryption-by-default: PASS). RDS instances use storage encryption with AES-256 (see finding rds-encryption-at-rest: PASS). Evidence: Shasta compliance scan dated 2026-04-05, evidence snapshot at data/evidence/scan-xxx/."*

---

### 4. "I also have an Azure subscription. Can you scan both clouds and give me one unified compliance view?"

**What happens:** Claude connects to Azure (prompts for subscription ID if not configured), runs all 26 Azure checks alongside the existing AWS scan, and presents a unified compliance score across both clouds. Findings show which cloud they came from, but the SOC 2 and ISO 27001 control status is aggregated — because compliance doesn't care which cloud a finding is in.

**What you'd get:**
- Combined compliance score (one grade, not two)
- Findings grouped by control, with cloud provider tags
- "Your CC6.7 (Data Protection) is PARTIAL — S3 encryption is passing on AWS but your Azure storage account allows TLS 1.0"

---

### 5. "We use OpenAI and LangChain in our product. Are there any AI security issues in our code?"

**What happens:** Claude runs Whitney's code scanner on your repository. It checks for hardcoded API keys, prompt injection vulnerabilities, PII in prompts, unguarded AI agents, outdated AI SDK versions with known CVEs, and more.

**What you'd get:**
- Findings with exact file paths and line numbers
- Code snippets showing the problematic code
- Specific fix instructions (e.g., "Move this API key to environment variables and use Secrets Manager")
- AI governance score against ISO 42001 and EU AI Act

**Example follow-up:** *"Show me the prompt injection risk in detail — I want to understand how an attacker could exploit it."*

---

### 6. "We have a board meeting next week. Generate a compliance report I can share with our investors."

**What happens:** Claude generates a PDF report with executive summary, compliance score, control status table, critical findings, and remediation roadmap. The report is formatted for a non-technical audience — it leads with the grade and risk level, not technical details.

**What you'd get:**
- PDF at `data/reports/gap-analysis-xxx.pdf`
- HTML version for email sharing
- Markdown version for version control
- Executive summary suitable for board slides

**Example follow-up:** *"Can you also create a one-page trust center page I can host on our website?"*

---

### 7. "Our auditor is coming in 3 months. What evidence do we need to collect and how far are we from being audit-ready?"

**What happens:** Claude runs an evidence collection snapshot, reviews the 17 formal control tests, checks your policy documents, access review status, and risk register. It then produces a gap list — exactly what's missing for a SOC 2 Type II audit.

**What you'd get:**
- Evidence snapshot saved to `data/evidence/`
- Control test results (17 tests with pass/fail/remediation)
- Gap list: "You're missing quarterly access reviews for Q1" or "Your Incident Response Plan hasn't been tested"
- Timeline: what to prioritize in the next 3 months

---

### 8. "Run a quarterly access review and flag any issues."

**What happens:** Claude enumerates every IAM user (AWS) and Entra ID user (Azure), checks their MFA status, last activity, role assignments, and access keys. It flags issues: inactive accounts, missing MFA, overprivileged users, stale access keys, and guest accounts.

**What you'd get:**
- User-by-user inventory with flags
- Markdown report with reviewer sign-off section (audit evidence)
- Specific recommendations: "Disable user 'dev-no-mfa' — inactive for 120 days with no MFA"
- Saved to `data/reviews/` for audit trail

**Example follow-up:** *"Disable the three inactive accounts and rotate the stale access keys. Show me the AWS CLI commands."*

---

### 9. "We ran a scan last week. What changed since then? Are we getting better or worse?"

**What happens:** Claude runs a fresh scan and compares it to the previous one using drift detection. It identifies new findings (regressions), resolved findings (improvements), and the overall trend.

**What you'd get:**
- Score delta: "+5.2% (improving)"
- New findings: "2 regressions — someone opened port 22 to 0.0.0.0/0 on sg-abc123"
- Resolved findings: "3 improvements — MFA enabled for 2 users, S3 encryption fixed"
- Trend visualization in the report

---

### 10. "We're building a RAG pipeline with LangChain and Pinecone. Review our architecture for AI security risks."

**What happens:** Claude scans the codebase, identifies the RAG pattern (vector DB queries, embedding generation, document chunking), and checks for common RAG security issues: missing access control on vector queries (user A could retrieve user B's documents), PII in embeddings, unvalidated model outputs used in responses.

**What you'd get:**
- Architecture pattern detected: "RAG pipeline with Pinecone + OpenAI embeddings"
- Specific findings: "Vector queries in `app/rag/retriever.py:45` don't filter by user_id — any user can retrieve any document"
- Fix: "Add metadata filter `filter={'user_id': current_user.id}` to the Pinecone query"
- ISO 42001 and EU AI Act mapping for each finding

---

### 11. "Generate all our compliance policies. Our company name is Acme AI and today's date is the effective date."

**What happens:** Claude generates 8 SOC 2 policy documents, each customized with your company name and effective date: Access Control, Change Management, Incident Response, Risk Assessment, Vendor Management, Data Classification, Acceptable Use, and Business Continuity.

**What you'd get:**
- 8 Markdown documents in `data/policies/`
- Each policy has sections, procedures, and responsibilities filled in
- Structured for auditor review (numbered sections, "shall" language, control mappings)

**Example follow-up:** *"We also need an AI Usage Policy for our team. Can you generate one?"*

---

### 12. "What are the most critical vulnerabilities in our AWS environment right now? Anything actively being exploited?"

**What happens:** Claude runs the SBOM scanner to discover your dependencies (Lambda, ECR, EC2), queries the NVD and CISA KEV databases for recent CVEs, and filters everything through your actual tech stack — only showing threats that are relevant to YOU.

**What you'd get:**
- Personalized threat advisory: "2 HIGH CVEs affecting Python 3.12 (you run 3 Lambda functions on 3.12)"
- CISA KEV matches flagged in red: "This vulnerability is actively being exploited in the wild"
- Supply chain risks: known-compromised packages in your dependency tree
- Slack-formatted summary if Slack is configured

---

### 13. "Can you do a pen-test style assessment? What's exposed to the internet?"

**What happens:** Claude runs the attack surface analysis — finds EC2 instances with public IPs, public RDS databases, internet-facing load balancers, and maps attack paths by correlating exposure with open ports and known vulnerabilities.

**What you'd get:**
- Attack surface map: "3 resources are internet-exposed"
- Attack paths ranked by risk: "Public RDS (CRITICAL) > EC2 with SSH open (HIGH) > ALB (INFO)"
- For each: what an attacker would see, what they could do, and how to fix it

---

### 14. "A client asked if we comply with the EU AI Act. We use GPT-4 for customer support chatbots. Help me figure out our obligations."

**What happens:** Claude classifies your AI system under the EU AI Act risk tiers (your customer support chatbot is "limited risk" — transparency obligation under Art. 52). It then checks what technical measures you have in place and what's missing.

**What you'd get:**
- Risk classification: "Limited risk — users must be informed they're interacting with AI"
- Obligation checklist: Art. 52 transparency requirement
- What you already have: content filtering on Azure OpenAI (PASS)
- What you're missing: no disclosure banner in the chatbot UI, no AI usage policy
- Recommended actions with effort estimates

---

### 15. "I want to set up automated weekly scans with drift alerts to Slack. And a monthly evidence collection. Can you help me configure that?"

**What happens:** Claude helps you set up scheduled scans using Claude Code cron triggers. It configures a weekly compliance scan with drift detection that posts a summary to Slack, and a monthly evidence collection that archives configuration snapshots.

**What you'd get:**
- Weekly scan: runs every Monday at 9am, posts score + drift to Slack
- Monthly evidence: runs on the 1st of each month, saves snapshots to `data/evidence/`
- Both configured as Claude Code cron triggers (no external infrastructure needed)
- Drift alerts: "Compliance score dropped 3% — 2 new findings since last week"

---

## Tips for Effective Conversations

1. **Be specific about what you want.** "Scan my AWS and give me the top 5 things to fix" works better than "check security."

2. **Chain requests.** "Scan, then generate a report, then create Jira tickets for the critical findings" — Claude handles multi-step workflows naturally.

3. **Ask follow-ups.** After a scan, ask "explain the MFA finding in more detail" or "show me the Terraform to fix the S3 encryption issue." Claude has full context from the scan.

4. **Reference previous work.** "Compare this scan to the one we did last Tuesday" or "update the risk register with the new Azure findings."

5. **Tell it your context.** "We have a SOC 2 audit in 6 weeks" or "our biggest customer requires ISO 27001" helps Claude prioritize the right things.

6. **Ask it to critique.** "Review the scan results as an auditor would — what would they flag?" or "are there any gaps in our compliance coverage?" — the self-assessment pattern works here too.

---

## The AI-Native Difference

Traditional compliance tools make you:
1. Log into a web dashboard
2. Navigate to the right page
3. Configure a scan
4. Wait for results
5. Click through each finding
6. Export a CSV
7. Figure out what to do
8. Open another tool to fix it

With Shasta and Whitney, you say one sentence and get the answer. The AI understands compliance frameworks, reads your cloud configuration, analyzes your code, and explains everything in language that makes sense for your role — whether you're a founder, a CTO, or an auditor.

That's not a feature. That's a fundamentally different way to do compliance.
