"""AI governance policy document generator for ISO 42001 and EU AI Act.

Generates Markdown policy documents from templates, tailored to the
company's context. These cover the controls and obligations that
require documented policies and cannot be satisfied by automated checks.

ISO 42001 mapping:
  AI-5.2 — AI Policy → AI Acceptable Use Policy
  AI-6.1 — AI Risk Assessment → AI Risk Assessment Policy
  AI-8.2 — AI Impact Assessment → AI Impact Assessment Policy
  AI-A.2 — Policies for AI → AI Governance Framework

EU AI Act mapping:
  Art. 9  (EUAI-9)  — Risk Management → AI Risk Assessment Policy
  Art. 11 (EUAI-11) — Technical Documentation → AI Technical Documentation Policy
  Art. 14 (EUAI-14) — Human Oversight → AI Human Oversight Policy
  Art. 52 (EUAI-52) — Transparency → AI Transparency & Disclosure Policy
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from jinja2 import BaseLoader, Environment

# ---------------------------------------------------------------------------
# Policy Templates
# ---------------------------------------------------------------------------

POLICIES: dict[str, dict] = {
    "ai_governance_framework": {
        "title": "AI Governance Framework",
        "controls": ["AI-A.2"],
        "filename": "ai-governance-framework.md",
        "template": """\
# AI Governance Framework

**Version:** 1.0
**Effective Date:** {{ effective_date }}
**Owner:** {{ company_name }} AI Governance Committee
**Controls:** ISO 42001 AI-A.2

## 1. Purpose

This document establishes {{ company_name }}'s framework for the responsible development, deployment, and use of artificial intelligence systems. It serves as the umbrella governance document that all subordinate AI policies reference.

## 2. Scope

This framework applies to all AI systems developed, deployed, procured, or operated by {{ company_name }}, including third-party AI services and APIs.

## 3. Governance Structure

| Role | Responsibility |
|------|---------------|
| AI Governance Committee | Strategic oversight, policy approval, risk appetite |
| AI Risk Owner | Risk identification, assessment, treatment decisions |
| Model Owner | Lifecycle management of specific AI models |
| Data Steward | Data quality, privacy, and governance for AI training data |
| Engineering Lead | Technical implementation and security controls |

## 4. AI System Inventory

{{ company_name }} maintains a register of all AI systems, including:
- System name, purpose, and classification (high/limited/minimal risk)
- Model provider (internal or third-party)
- Data inputs and outputs
- Owner and operational status
- Date of last risk assessment

Use the `/discover-ai` scan to auto-populate this inventory.

## 5. Applicable Frameworks

{{ company_name }} aligns AI governance with:
- **ISO/IEC 42001:2023** — AI Management Systems
- **EU AI Act (Regulation 2024/1689)** — Risk-based AI regulation

## 6. Subordinate Policies

| Policy | Controls |
|--------|----------|
| AI Acceptable Use Policy | AI-5.2 |
| AI Risk Assessment Policy | AI-6.1, EUAI-9 |
| AI Impact Assessment Policy | AI-8.2 |
| AI Technical Documentation Policy | EUAI-11 |
| AI Human Oversight Policy | EUAI-14 |
| AI Transparency & Disclosure Policy | EUAI-52 |

## 7. Compliance Monitoring

- Automated AI governance scans via Whitney (`/ai-scan`) run periodically
- Quarterly review of AI system inventory and risk assessments
- Annual review of this framework and all subordinate policies

## 8. Review

This framework is reviewed annually or upon significant changes to {{ company_name }}'s AI systems or regulatory requirements.
""",
    },
    "ai_acceptable_use": {
        "title": "AI Acceptable Use Policy",
        "controls": ["AI-5.2"],
        "filename": "ai-acceptable-use-policy.md",
        "template": """\
# AI Acceptable Use Policy

**Version:** 1.0
**Effective Date:** {{ effective_date }}
**Owner:** {{ company_name }} AI Governance Committee
**Controls:** ISO 42001 AI-5.2

## 1. Purpose

This policy defines the acceptable and prohibited uses of artificial intelligence within {{ company_name }} to ensure responsible, ethical, and secure AI adoption.

## 2. Scope

This policy applies to all {{ company_name }} employees, contractors, and third parties who develop, deploy, or use AI systems on behalf of {{ company_name }}.

## 3. Approved AI Systems

- All AI tools and services must be approved by the AI Governance Committee before use
- Approved systems are listed in the AI System Inventory
- Employees must not use unapproved AI tools for company work (including personal AI accounts for company data)

## 4. Acceptable Use Principles

All use of AI at {{ company_name }} must adhere to:
- **Fairness:** AI systems must not discriminate based on protected characteristics
- **Transparency:** Stakeholders are informed when AI influences decisions affecting them
- **Accountability:** A human owner is responsible for every AI system's outputs
- **Privacy:** Personal data is processed only as permitted by law and {{ company_name }}'s privacy policy
- **Security:** AI systems are protected against adversarial attacks and misuse

## 5. Prohibited Uses

The following uses of AI are prohibited at {{ company_name }}:
- Social scoring or ranking of individuals
- Deceptive content generation (deepfakes, impersonation) without disclosure
- Manipulation of user behaviour through subliminal techniques
- Processing of confidential or customer data through public AI services without approval
- Automated decision-making on employment, credit, or legal matters without human oversight
- Using AI to circumvent security controls or access restrictions

## 6. Data Handling in AI Systems

- **No PII in prompts** without explicit approval and data processing agreement
- **No confidential data** in public AI services (ChatGPT, Claude.ai, etc.) unless enterprise agreements are in place
- **Prompt content is logged** for audit and compliance purposes
- **AI outputs are validated** before use in production or customer-facing contexts

## 7. Third-Party AI Services

- Third-party AI services require vendor security assessment before adoption
- Data processing agreements must cover AI-specific risks (training data usage, model retention)
- API keys for AI services must be managed via secrets manager, never hardcoded

## 8. Violations

Violations of this policy may result in disciplinary action up to and including termination. Security incidents involving AI must be reported immediately per {{ company_name }}'s Incident Response Plan.

## 9. Review

This policy is reviewed annually or upon significant changes to {{ company_name }}'s AI usage.
""",
    },
    "ai_risk_assessment": {
        "title": "AI Risk Assessment Policy",
        "controls": ["AI-6.1", "EUAI-9"],
        "filename": "ai-risk-assessment-policy.md",
        "template": """\
# AI Risk Assessment Policy

**Version:** 1.0
**Effective Date:** {{ effective_date }}
**Owner:** {{ company_name }} AI Risk Owner
**Controls:** ISO 42001 AI-6.1, EU AI Act Art. 9 (EUAI-9)

## 1. Purpose

This policy establishes {{ company_name }}'s process for identifying, assessing, and managing risks associated with AI systems throughout their lifecycle.

## 2. Scope

This policy applies to all AI systems developed, deployed, or procured by {{ company_name }}, including foundation models, fine-tuned models, AI agents, and RAG pipelines.

## 3. Risk Classification

AI systems are classified by risk level per the EU AI Act framework:

| Risk Level | Definition | Examples | Requirements |
|------------|-----------|----------|-------------|
| Unacceptable | Banned by regulation | Social scoring, real-time biometric ID | Prohibited |
| High | Significant impact on individuals | Employment decisions, credit scoring, medical diagnosis | Full compliance obligations (Arts. 9-15) |
| Limited | Moderate transparency needs | Chatbots, content generation | Transparency obligations (Art. 52) |
| Minimal | Low risk | Spam filters, auto-complete | No specific obligations |

## 4. Risk Assessment Process

### 4.1 Identification
- New AI systems trigger a risk assessment before deployment
- Existing systems are reassessed annually or upon significant changes
- Use Whitney's `/ai-scan` to identify technical risks automatically

### 4.2 Analysis
For each identified risk, document:
- Likelihood (Rare / Unlikely / Possible / Likely / Almost Certain)
- Impact (Negligible / Minor / Moderate / Major / Severe)
- Risk score (likelihood x impact)

### 4.3 Risk Categories

| Category | Examples |
|----------|---------|
| Technical | Model drift, data poisoning, adversarial attacks, prompt injection |
| Ethical | Bias, discrimination, unfair outcomes, lack of transparency |
| Operational | Availability, latency, cost overruns, vendor lock-in |
| Legal | Regulatory non-compliance, intellectual property, liability |
| Privacy | Unauthorized PII processing, data leakage via prompts |

### 4.4 Treatment
- **Mitigate:** Implement controls (guardrails, content filters, access controls)
- **Accept:** Document accepted risk with justification and owner approval
- **Transfer:** Insurance or contractual transfer to vendor
- **Avoid:** Do not deploy the AI system

## 5. AI Risk Register

{{ company_name }} maintains an AI risk register that records:
- Risk description and category
- AI system affected
- Current controls in place
- Residual risk level
- Treatment decision and owner
- Review date

## 6. Continuous Monitoring

- Model performance metrics are monitored for drift and degradation
- Whitney scans run periodically to detect new technical risks
- Risk register is updated when new risks are identified or mitigations change

## 7. Review

This policy is reviewed annually or when {{ company_name }}'s AI risk profile changes significantly.
""",
    },
    "ai_impact_assessment": {
        "title": "AI Impact Assessment Policy",
        "controls": ["AI-8.2"],
        "filename": "ai-impact-assessment-policy.md",
        "template": """\
# AI Impact Assessment Policy

**Version:** 1.0
**Effective Date:** {{ effective_date }}
**Owner:** {{ company_name }} AI Governance Committee
**Controls:** ISO 42001 AI-8.2

## 1. Purpose

This policy requires {{ company_name }} to assess the potential impacts of AI systems on individuals, groups, and society before deployment.

## 2. Scope

An AI Impact Assessment is required before deploying any AI system classified as high-risk, and is recommended for limited-risk systems.

## 3. Assessment Triggers

An impact assessment must be conducted when:
- A new AI system is being deployed to production
- An existing AI system's use case changes significantly
- A model is retrained on substantially different data
- User complaints or incidents suggest unintended impacts

## 4. Impact Categories

| Category | Considerations |
|----------|---------------|
| Individual rights | Privacy, autonomy, dignity, non-discrimination |
| Group fairness | Bias across protected characteristics (race, gender, age, disability) |
| Societal effects | Environmental impact, labour displacement, information quality |
| Safety | Physical safety, psychological well-being, financial harm |

## 5. Assessment Process

1. **Describe the AI system:** Purpose, inputs, outputs, decision scope
2. **Identify stakeholders:** Users, affected individuals, operators, oversight bodies
3. **Analyse potential impacts:** For each impact category, assess severity and likelihood
4. **Evaluate proportionality:** Are the benefits proportionate to the risks?
5. **Define mitigations:** Technical controls, process safeguards, monitoring
6. **Document findings:** Written record with assessment date, assessors, and conclusions

## 6. Documentation Requirements

Each assessment produces a report containing:
- System description and intended purpose
- Stakeholder analysis
- Impact analysis results per category
- Mitigation measures and residual risks
- Approval decision and approver name
- Date and next review date

## 7. Review and Approval

- High-risk systems: AI Governance Committee approval required
- Limited-risk systems: AI Risk Owner approval sufficient
- Assessments are retained for the lifetime of the AI system plus 3 years

## 8. Review

This policy is reviewed annually or upon changes to regulatory requirements.
""",
    },
    "ai_technical_documentation": {
        "title": "AI Technical Documentation Policy",
        "controls": ["EUAI-11"],
        "filename": "ai-technical-documentation-policy.md",
        "template": """\
# AI Technical Documentation Policy

**Version:** 1.0
**Effective Date:** {{ effective_date }}
**Owner:** {{ company_name }} Engineering Lead
**Controls:** EU AI Act Art. 11 (EUAI-11)

## 1. Purpose

This policy ensures that {{ company_name }} maintains comprehensive technical documentation for all high-risk AI systems, as required by the EU AI Act Article 11.

## 2. Scope

This policy applies to all AI systems classified as high-risk under {{ company_name }}'s AI Risk Classification framework.

## 3. Required Documentation

Each high-risk AI system must have technical documentation covering:

### 3.1 System Description
- System name, version, and unique identifier
- Intended purpose and intended users
- Developer and deployment date
- Risk classification and rationale

### 3.2 Architecture
- System architecture diagram
- Model type and specifications (parameters, architecture family)
- Infrastructure and compute requirements
- Integration points and data flows

### 3.3 Data
- Training data description (sources, size, characteristics)
- Data preprocessing and cleaning methods
- Data quality measures and known limitations
- Privacy protections applied (anonymisation, access controls)

### 3.4 Model
- Training methodology and hyperparameters
- Evaluation metrics and benchmark results
- Known limitations and failure modes
- Model versioning and lineage information

### 3.5 Performance
- Accuracy, precision, recall, and other relevant metrics
- Performance across demographic groups (fairness evaluation)
- Latency and throughput characteristics
- Known biases or disparate performance

## 4. Documentation Lifecycle

- **Created** before the system is deployed to production
- **Updated** when the model is retrained, the use case changes, or significant issues are found
- **Maintained** for the operational lifetime of the system
- **Retained** for a minimum of 10 years after decommissioning (per EU AI Act)

## 5. Access and Storage

- Documentation is stored in {{ company_name }}'s designated documentation system
- Access is limited to authorised personnel and regulatory authorities
- Version history is maintained for all changes

## 6. Review

This policy is reviewed annually or when regulatory requirements change.
""",
    },
    "ai_human_oversight": {
        "title": "AI Human Oversight Policy",
        "controls": ["EUAI-14"],
        "filename": "ai-human-oversight-policy.md",
        "template": """\
# AI Human Oversight Policy

**Version:** 1.0
**Effective Date:** {{ effective_date }}
**Owner:** {{ company_name }} AI Governance Committee
**Controls:** EU AI Act Art. 14 (EUAI-14)

## 1. Purpose

This policy ensures that {{ company_name }}'s AI systems can be effectively overseen by natural persons, as required by the EU AI Act Article 14.

## 2. Scope

This policy applies to all high-risk AI systems and any AI system that makes or influences consequential decisions about individuals.

## 3. Oversight Models

{{ company_name }} employs three levels of human oversight:

| Model | Description | When Applied |
|-------|------------|-------------|
| Human-in-the-loop (HITL) | Human approves every AI decision before execution | High-risk decisions (employment, credit, safety) |
| Human-on-the-loop (HOTL) | Human monitors AI in real time, can intervene | Automated workflows with moderate risk |
| Human-in-command (HIC) | Human provides strategic oversight and periodic review | Low-risk, high-volume AI operations |

## 4. Oversight Requirements by Risk Level

- **High-risk systems:** HITL or HOTL required. No fully autonomous decisions.
- **Limited-risk systems:** HOTL or HIC required. Escalation path to human must exist.
- **Minimal-risk systems:** HIC sufficient. Periodic review of AI outputs.

## 5. Override and Shutdown Mechanisms

All high-risk AI systems must implement:
- **Override:** Authorised users can override any AI decision
- **Pause:** AI processing can be paused while maintaining system state
- **Shutdown:** Emergency shutdown procedure that halts AI operation immediately
- **Rollback:** Ability to revert to the last known-good state

## 6. Competency Requirements

Human overseers must:
- Understand the AI system's capabilities, limitations, and known failure modes
- Be trained on the override and shutdown procedures
- Know how to interpret the system's outputs and confidence indicators
- Receive refresher training annually or when the system changes

## 7. Monitoring and Escalation

- AI system outputs are monitored for anomalies and drift
- Escalation triggers are defined for each system (e.g., confidence below threshold, unexpected outputs)
- All human interventions and overrides are logged for audit purposes

## 8. Review

This policy is reviewed annually or upon significant changes to {{ company_name }}'s AI systems.
""",
    },
    "ai_transparency_disclosure": {
        "title": "AI Transparency & Disclosure Policy",
        "controls": ["EUAI-52"],
        "filename": "ai-transparency-disclosure-policy.md",
        "template": """\
# AI Transparency & Disclosure Policy

**Version:** 1.0
**Effective Date:** {{ effective_date }}
**Owner:** {{ company_name }} AI Governance Committee
**Controls:** EU AI Act Art. 52 (EUAI-52)

## 1. Purpose

This policy ensures that users interacting with {{ company_name }}'s AI systems are informed that they are interacting with AI, as required by the EU AI Act Article 52.

## 2. Scope

This policy applies to all AI systems operated by {{ company_name }} that interact directly with natural persons, including chatbots, virtual assistants, AI-generated content, and automated decision systems.

## 3. Disclosure Requirements

### 3.1 Conversational AI (Chatbots & Assistants)
- Users must be clearly informed before or at the start of interaction that they are communicating with an AI system
- Disclosure must be prominent, not buried in terms of service
- Example: "You are chatting with an AI assistant. A human agent is available on request."

### 3.2 AI-Generated Content
- Content generated or substantially modified by AI must be labelled
- Labelling mechanism depends on content type:
  - Text: visible label or disclaimer
  - Images: watermark or metadata tag
  - Audio/Video: disclosure at start and in metadata

### 3.3 Automated Decisions
- When AI contributes to decisions affecting individuals, the individual must be informed that AI was involved
- The individual has the right to request human review of the decision

## 4. Exceptions

Disclosure is not required when:
- The AI use is obvious from context (e.g., spell-check, auto-complete)
- Disclosure would compromise legitimate security operations, as permitted by regulation

## 5. Implementation Checklist

For each AI system, verify:
- [ ] Users are informed they are interacting with AI before or at first interaction
- [ ] AI-generated content is labelled appropriately
- [ ] A mechanism exists for users to request human interaction
- [ ] Disclosure language has been reviewed by legal
- [ ] Disclosure is tested for clarity with representative users

## 6. Review

This policy is reviewed annually or when new AI-facing features are launched.
""",
    },
}


# ---------------------------------------------------------------------------
# Generator functions
# ---------------------------------------------------------------------------


def generate_policy(
    policy_id: str,
    company_name: str = "Acme Corp",
    effective_date: str | None = None,
    **kwargs,
) -> str:
    """Generate a single AI governance policy document from a template."""
    if policy_id not in POLICIES:
        raise ValueError(f"Unknown policy: {policy_id}. Available: {list(POLICIES.keys())}")

    policy = POLICIES[policy_id]
    env = Environment(loader=BaseLoader())
    template = env.from_string(policy["template"])

    if effective_date is None:
        effective_date = datetime.now().strftime("%Y-%m-%d")

    return template.render(
        company_name=company_name,
        effective_date=effective_date,
        **kwargs,
    )


def generate_all_policies(
    company_name: str = "Acme Corp",
    output_path: Path | str = "data/policies/ai",
    **kwargs,
) -> list[Path]:
    """Generate all AI governance policy documents and save to disk."""
    output_dir = Path(output_path)
    output_dir.mkdir(parents=True, exist_ok=True)

    paths = []
    for policy_id, policy in POLICIES.items():
        content = generate_policy(policy_id, company_name=company_name, **kwargs)
        filepath = output_dir / policy["filename"]
        filepath.write_text(content, encoding="utf-8")
        paths.append(filepath)

    return paths


def list_policies() -> list[dict]:
    """List all available AI governance policy templates."""
    return [
        {
            "id": pid,
            "title": p["title"],
            "controls": p["controls"],
            "filename": p["filename"],
        }
        for pid, p in POLICIES.items()
    ]
