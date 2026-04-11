"""NIST AI 600-1: Generative AI Profile definitions.

Maps Whitney AI checks to the 12 unique risks identified in the NIST AI
600-1 Generative AI Profile (released July 2024).  This profile
supplements the NIST AI RMF 1.0 with risks specific to foundation models,
large language models, and generative AI systems.

Reference: https://www.nist.gov/publications/artificial-intelligence-risk-management-framework-generative-artificial-intelligence
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class NISTAI6001Risk:
    """A single NIST AI 600-1 generative-AI risk."""

    id: str  # e.g., "GAI-1"
    title: str
    description: str
    check_ids: list[str] = field(default_factory=list)
    requires_policy: bool = False
    nist_rmf_crosswalk: list[str] = field(default_factory=list)
    guidance: str = ""


# ---------------------------------------------------------------------------
# NIST AI 600-1 Risks (12 total)
# ---------------------------------------------------------------------------

NIST_AI_600_1_RISKS: dict[str, NISTAI6001Risk] = {
    "GAI-1": NISTAI6001Risk(
        id="GAI-1",
        title="Confabulation / Hallucination",
        description=(
            "GenAI can produce confidently stated but factually incorrect "
            "outputs (confabulations / hallucinations) that appear plausible "
            "and are difficult for users to distinguish from accurate content."
        ),
        check_ids=[
            "code-no-output-validation",
            "code-no-fallback-handler",
            "bedrock-guardrails-configured",
            "azure-openai-content-filter",
        ],
        nist_rmf_crosswalk=["MEASURE-2", "MAP-3"],
        guidance=(
            "Implement output validation and grounding checks. Deploy "
            "guardrails that compare outputs against retrieved context. "
            "Add fallback handlers for low-confidence responses."
        ),
    ),
    "GAI-2": NISTAI6001Risk(
        id="GAI-2",
        title="Data Privacy",
        description=(
            "GenAI systems may leak, memorise, or inadvertently disclose "
            "personal data, trade secrets, or confidential information "
            "through model outputs, training data extraction, or prompt "
            "context."
        ),
        check_ids=[
            "code-pii-in-prompts",
            "code-ai-api-key-exposed",
            "code-ai-key-in-env-file",
            "s3-training-data-encrypted",
        ],
        nist_rmf_crosswalk=["MEASURE-2", "MANAGE-2"],
        guidance=(
            "Redact PII before sending to LLM APIs. Encrypt training data "
            "at rest. Never include API keys or secrets in prompts. Use "
            "guardrails to filter PII from outputs."
        ),
    ),
    "GAI-3": NISTAI6001Risk(
        id="GAI-3",
        title="Bias Amplification",
        description=(
            "GenAI systems can amplify and propagate biases present in "
            "training data, producing discriminatory, stereotyping, or "
            "inequitable outputs at scale."
        ),
        check_ids=[],
        requires_policy=True,
        nist_rmf_crosswalk=["MEASURE-1", "MEASURE-2"],
        guidance=(
            "Conduct bias evaluations on model outputs using demographic "
            "parity and equalised odds metrics. Document findings in the "
            "AI Impact Assessment. Monitor for bias drift in production."
        ),
    ),
    "GAI-4": NISTAI6001Risk(
        id="GAI-4",
        title="Homogenisation of Outputs",
        description=(
            "Widespread use of a small number of foundation models may "
            "lead to homogenisation of outputs, reducing diversity of "
            "perspectives and creating systemic concentration risk."
        ),
        check_ids=[
            "code-no-model-versioning",
        ],
        nist_rmf_crosswalk=["MAP-3"],
        guidance=(
            "Pin model versions to enable reproducibility. Document model "
            "selection rationale. Consider multi-model strategies for "
            "critical applications to reduce single-point-of-failure risk."
        ),
    ),
    "GAI-5": NISTAI6001Risk(
        id="GAI-5",
        title="Harmful Content Generation",
        description=(
            "GenAI systems can generate toxic, violent, sexually explicit, "
            "or otherwise harmful content, including CSAM, disinformation, "
            "or content that facilitates illegal activities."
        ),
        check_ids=[
            "bedrock-guardrails-configured",
            "bedrock-content-filter",
            "azure-openai-content-filter",
        ],
        nist_rmf_crosswalk=["MEASURE-2", "MANAGE-2"],
        guidance=(
            "Configure content filters on all GenAI endpoints. Deploy "
            "Bedrock guardrails with topic-deny policies. Enable Azure "
            "OpenAI content filtering at the deployment level."
        ),
    ),
    "GAI-6": NISTAI6001Risk(
        id="GAI-6",
        title="Data Poisoning / Integrity",
        description=(
            "Training data can be corrupted, poisoned, or manipulated to "
            "introduce backdoors, biases, or degraded performance that "
            "may not be detected by standard evaluation benchmarks."
        ),
        check_ids=[
            "s3-training-data-encrypted",
            "s3-training-data-versioned",
            "code-training-data-unencrypted",
        ],
        nist_rmf_crosswalk=["MAP-4", "MANAGE-2"],
        guidance=(
            "Encrypt training data at rest and in transit. Enable "
            "versioning to detect unauthorised modifications. Validate "
            "data provenance before fine-tuning."
        ),
    ),
    "GAI-7": NISTAI6001Risk(
        id="GAI-7",
        title="Prompt Injection",
        description=(
            "Attackers can craft inputs that override model instructions, "
            "bypass safety controls, or cause unintended actions through "
            "direct or indirect prompt injection."
        ),
        check_ids=[
            "code-prompt-injection-risk",
            "code-no-output-validation",
            "code-agent-unrestricted-tools",
            "bedrock-guardrails-configured",
            "bedrock-agent-guardrails",
        ],
        nist_rmf_crosswalk=["MEASURE-2", "MANAGE-2"],
        guidance=(
            "Never concatenate untrusted input directly into prompts. "
            "Validate and sanitise all user inputs. Deploy guardrails "
            "with prompt-attack detection. Restrict agent tool capabilities."
        ),
    ),
    "GAI-8": NISTAI6001Risk(
        id="GAI-8",
        title="Information Leakage",
        description=(
            "GenAI systems can leak system prompts, internal instructions, "
            "fine-tuning data, or other sensitive implementation details "
            "through crafted queries or side-channel extraction."
        ),
        check_ids=[
            "code-meta-prompt-exposed",
            "code-ai-api-key-exposed",
            "code-ai-key-in-env-file",
        ],
        nist_rmf_crosswalk=["MEASURE-2", "MANAGE-3"],
        guidance=(
            "Do not expose system prompts in client-side code. Protect "
            "API keys with secrets managers. Implement output filtering "
            "to prevent instruction leakage."
        ),
    ),
    "GAI-9": NISTAI6001Risk(
        id="GAI-9",
        title="Third-Party / Supply Chain Risk",
        description=(
            "Reliance on third-party foundation models, APIs, and AI "
            "SDKs introduces supply chain risks including model "
            "compromise, SDK vulnerabilities, API deprecation, and "
            "vendor lock-in."
        ),
        check_ids=[
            "code-outdated-ai-sdk",
            "lambda-ai-api-keys-not-hardcoded",
            "azure-openai-managed-identity",
            "azure-openai-key-rotation",
        ],
        nist_rmf_crosswalk=["GOVERN-6", "MANAGE-3"],
        guidance=(
            "Track AI dependencies via SBOM. Keep SDKs updated. Use "
            "managed identities instead of API keys. Rotate credentials "
            "regularly. Monitor for CVEs in AI packages."
        ),
    ),
    "GAI-10": NISTAI6001Risk(
        id="GAI-10",
        title="Model Theft / Extraction",
        description=(
            "Attackers may attempt to steal or replicate proprietary "
            "models through repeated API queries (model extraction), "
            "side-channel attacks, or direct access to model weights."
        ),
        check_ids=[
            "sagemaker-endpoint-encryption",
            "sagemaker-training-vpc",
            "bedrock-vpc-endpoint",
            "azure-openai-private-endpoint",
            "azure-ml-workspace-encryption",
            "code-model-endpoint-public",
        ],
        nist_rmf_crosswalk=["MANAGE-2"],
        guidance=(
            "Encrypt model endpoints. Isolate training in VPCs. Use "
            "private endpoints for AI services. Implement rate limiting "
            "on inference APIs. Monitor for unusual query patterns."
        ),
    ),
    "GAI-11": NISTAI6001Risk(
        id="GAI-11",
        title="Overreliance / Automation Bias",
        description=(
            "Users may develop excessive trust in GenAI outputs, failing "
            "to verify factual claims, check for errors, or exercise "
            "appropriate human judgement in critical decisions."
        ),
        check_ids=[
            "code-no-fallback-handler",
            "code-no-output-validation",
            "bedrock-agent-guardrails",
        ],
        nist_rmf_crosswalk=["MAP-3", "MEASURE-2"],
        guidance=(
            "Implement fallback handlers that flag low-confidence outputs. "
            "Add human-in-the-loop for high-stakes decisions. Validate "
            "outputs before acting on them. Deploy agent guardrails."
        ),
    ),
    "GAI-12": NISTAI6001Risk(
        id="GAI-12",
        title="Environmental Impact",
        description=(
            "Training and operating large GenAI models requires "
            "significant compute resources, contributing to energy "
            "consumption, carbon emissions, and water usage."
        ),
        check_ids=[],
        requires_policy=True,
        nist_rmf_crosswalk=["GOVERN-1"],
        guidance=(
            "Track compute usage for AI workloads. Document energy "
            "consumption in technical documentation. Consider model "
            "efficiency (distillation, quantisation) when selecting "
            "models. Include environmental impact in AI assessments."
        ),
    ),
}


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def get_nist_ai_600_1_risk(risk_id: str) -> NISTAI6001Risk | None:
    """Look up a NIST AI 600-1 risk by ID."""
    return NIST_AI_600_1_RISKS.get(risk_id)


def get_nist_ai_600_1_risks_for_check(
    check_id: str,
) -> list[NISTAI6001Risk]:
    """Find all NIST AI 600-1 risks that a given check maps to."""
    return [r for r in NIST_AI_600_1_RISKS.values() if check_id in r.check_ids]


def get_automated_nist_ai_600_1_risks() -> list[NISTAI6001Risk]:
    """Get all risks that have automated checks."""
    return [r for r in NIST_AI_600_1_RISKS.values() if r.check_ids]


def get_policy_required_nist_ai_600_1_risks() -> list[NISTAI6001Risk]:
    """Get all risks that require policy documents."""
    return [r for r in NIST_AI_600_1_RISKS.values() if r.requires_policy]
