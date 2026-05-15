"""NIST AI Risk Management Framework (AI RMF 1.0) definitions.

Maps Whitney AI checks to the NIST AI RMF's four core functions
(GOVERN, MAP, MEASURE, MANAGE) and 19 categories.

Reference: https://www.nist.gov/itl/ai-risk-management-framework
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class NISTAIRMFCategory:
    """A single NIST AI RMF category within a function."""

    id: str  # e.g., "GOVERN-1"
    function: str  # "GOVERN", "MAP", "MEASURE", "MANAGE"
    title: str
    description: str
    check_ids: list[str] = field(default_factory=list)
    requires_policy: bool = False
    soc2_equivalent: list[str] = field(default_factory=list)
    guidance: str = ""


# ---------------------------------------------------------------------------
# NIST AI RMF Categories (19 total across 4 functions)
# ---------------------------------------------------------------------------

NIST_AI_RMF_CATEGORIES: dict[str, NISTAIRMFCategory] = {
    # =========================================================================
    # GOVERN — Cultivate culture of AI risk management
    # =========================================================================
    "GOVERN-1": NISTAIRMFCategory(
        id="GOVERN-1",
        function="GOVERN",
        title="Policies and Procedures",
        description=(
            "Policies, processes, procedures, and practices across the "
            "organisation are in place, transparent, and implemented "
            "effectively to govern AI risks."
        ),
        requires_policy=True,
        soc2_equivalent=["CC1.1", "CC5.1"],
        guidance=(
            "Establish AI governance policies using Whitney's policy "
            "generator. Ensure policies cover acceptable use, risk "
            "assessment, and impact assessment."
        ),
    ),
    "GOVERN-2": NISTAIRMFCategory(
        id="GOVERN-2",
        function="GOVERN",
        title="Accountability Structures",
        description=(
            "Accountability structures are in place so that the "
            "appropriate teams and individuals are empowered, "
            "responsible, and trained for AI risk management."
        ),
        requires_policy=True,
        soc2_equivalent=["CC1.1"],
        guidance=(
            "Define AI governance roles: AI Ethics Lead, AI Risk Owner, "
            "Model Owner. Document in the AI Governance Framework."
        ),
    ),
    "GOVERN-3": NISTAIRMFCategory(
        id="GOVERN-3",
        function="GOVERN",
        title="Workforce Diversity and AI Expertise",
        description=(
            "Workforce diversity, equity, inclusion, and accessibility "
            "processes are prioritised in AI system development and use."
        ),
        requires_policy=True,
        soc2_equivalent=["CC1.1"],
        guidance=(
            "Include diverse perspectives in AI system design and review. "
            "Document in impact assessment policy."
        ),
    ),
    "GOVERN-4": NISTAIRMFCategory(
        id="GOVERN-4",
        function="GOVERN",
        title="Organisational Culture",
        description=(
            "Organisational teams are committed to a culture that considers "
            "and communicates AI risk."
        ),
        requires_policy=True,
        soc2_equivalent=["CC1.1", "CC2.1"],
        guidance=("Foster risk-aware culture through training and the AI Acceptable Use Policy."),
    ),
    "GOVERN-5": NISTAIRMFCategory(
        id="GOVERN-5",
        function="GOVERN",
        title="Stakeholder Engagement",
        description=(
            "Processes are in place for robust engagement with relevant "
            "AI actors and affected stakeholders."
        ),
        requires_policy=True,
        soc2_equivalent=["CC2.1"],
        guidance=(
            "Document stakeholder engagement in impact assessment. "
            "Include affected parties in AI risk reviews."
        ),
    ),
    "GOVERN-6": NISTAIRMFCategory(
        id="GOVERN-6",
        function="GOVERN",
        title="Supply Chain Risk Management",
        description=(
            "Policies and procedures address AI risks from third-party "
            "entities, including supply chain, partnerships, and "
            "commercial providers."
        ),
        check_ids=[
            "code-outdated-ai-sdk",
            "lambda-ai-api-keys-not-hardcoded",
            "azure-openai-managed-identity",
        ],
        soc2_equivalent=["CC9.1"],
        guidance=(
            "Use AI SBOM to track third-party AI dependencies. Keep SDKs "
            "updated. Use managed identities for AI service access."
        ),
    ),
    # =========================================================================
    # MAP — Contextualise risks within the AI system's scope
    # =========================================================================
    "MAP-1": NISTAIRMFCategory(
        id="MAP-1",
        function="MAP",
        title="Context and Intended Purpose",
        description=(
            "Context is established and understood, including the intended "
            "purpose, deployment context, and assumptions about the AI system."
        ),
        requires_policy=True,
        soc2_equivalent=["CC3.1"],
        guidance=(
            "Document AI system context in technical documentation. "
            "Define intended use cases and operational boundaries."
        ),
    ),
    "MAP-2": NISTAIRMFCategory(
        id="MAP-2",
        function="MAP",
        title="AI System Categorisation",
        description=(
            "Categorisation of the AI system is performed, including "
            "risk classification per EU AI Act levels."
        ),
        check_ids=[],
        requires_policy=True,
        soc2_equivalent=["CC3.1"],
        guidance=(
            "Classify AI systems by risk level (Unacceptable, High, "
            "Limited, Minimal) using the AI Risk Assessment Policy."
        ),
    ),
    "MAP-3": NISTAIRMFCategory(
        id="MAP-3",
        function="MAP",
        title="AI System Capabilities and Limitations",
        description=(
            "Scientifically valid AI system capabilities, limitations, "
            "and potential failure modes are understood and documented."
        ),
        check_ids=[
            "code-no-model-versioning",
            "code-no-fallback-handler",
        ],
        soc2_equivalent=["CC7.2"],
        guidance=(
            "Pin model versions for reproducibility. Implement fallback "
            "handlers for failure modes. Document known limitations."
        ),
    ),
    "MAP-4": NISTAIRMFCategory(
        id="MAP-4",
        function="MAP",
        title="Risk Identification and Mapping",
        description=(
            "Risks and benefits are mapped for all components of the AI "
            "system including third-party components."
        ),
        check_ids=[
            "code-outdated-ai-sdk",
        ],
        requires_policy=True,
        soc2_equivalent=["CC3.1", "CC9.1"],
        guidance=(
            "Use AI SBOM and vulnerability scanning to identify third-party "
            "risks. Document in the AI Risk Register."
        ),
    ),
    "MAP-5": NISTAIRMFCategory(
        id="MAP-5",
        function="MAP",
        title="Impact Characterisation",
        description=(
            "Impacts to individuals, groups, communities, organisations, "
            "and society are characterised."
        ),
        requires_policy=True,
        soc2_equivalent=["CC3.1"],
        guidance=(
            "Conduct impact assessments per the AI Impact Assessment Policy. "
            "Consider societal, ethical, and individual impacts."
        ),
    ),
    # =========================================================================
    # MEASURE — Quantify, assess, track, and benchmark risks
    # =========================================================================
    "MEASURE-1": NISTAIRMFCategory(
        id="MEASURE-1",
        function="MEASURE",
        title="Metrics and Methods",
        description=(
            "Appropriate methods and metrics are identified and applied "
            "to measure AI risks and trustworthiness characteristics."
        ),
        check_ids=[
            "sagemaker-data-capture",
            "azure-ml-data-drift-monitor",
        ],
        soc2_equivalent=["CC7.2"],
        guidance=(
            "Enable data capture on SageMaker endpoints. Configure drift "
            "monitors in Azure ML. Define performance metrics for AI systems."
        ),
    ),
    "MEASURE-2": NISTAIRMFCategory(
        id="MEASURE-2",
        function="MEASURE",
        title="Trustworthiness Evaluation",
        description=(
            "AI systems are evaluated for trustworthy characteristics "
            "including validity, reliability, safety, fairness, security, "
            "resilience, transparency, explainability, and privacy."
        ),
        check_ids=[
            "code-prompt-injection-risk",
            "code-pii-in-prompts",
            "code-no-output-validation",
            "bedrock-guardrails-configured",
        ],
        soc2_equivalent=["CC7.2", "CC6.1"],
        guidance=(
            "Run Whitney code and cloud scans to evaluate security and "
            "privacy. Configure guardrails for safety. Document fairness "
            "considerations in impact assessments."
        ),
    ),
    "MEASURE-3": NISTAIRMFCategory(
        id="MEASURE-3",
        function="MEASURE",
        title="Risk Tracking",
        description=(
            "Mechanisms for tracking identified AI risks over time are "
            "in place, including monitoring for emergent risks."
        ),
        check_ids=[
            "code-ai-logging-insufficient",
            "bedrock-model-invocation-logging",
            "azure-openai-diagnostic-logging",
            "cloudtrail-ai-events",
        ],
        soc2_equivalent=["CC7.2", "CC7.3"],
        guidance=(
            "Log all AI interactions. Enable model invocation logging. "
            "Configure CloudTrail for AI events. Use continuous scanning "
            "to track risk posture over time."
        ),
    ),
    "MEASURE-4": NISTAIRMFCategory(
        id="MEASURE-4",
        function="MEASURE",
        title="Measurement Feedback",
        description=(
            "Feedback on the effectiveness of measurement approaches "
            "is collected and integrated for improvement."
        ),
        requires_policy=True,
        soc2_equivalent=["CC7.3"],
        guidance=(
            "Review scan results periodically. Adjust risk thresholds "
            "based on operational experience. Document lessons learned."
        ),
    ),
    # =========================================================================
    # MANAGE — Allocate resources, prioritise, respond to risks
    # =========================================================================
    "MANAGE-1": NISTAIRMFCategory(
        id="MANAGE-1",
        function="MANAGE",
        title="Risk Prioritisation and Response",
        description=(
            "AI risks are prioritised and resources allocated based on "
            "assessed impact and likelihood."
        ),
        check_ids=[],
        requires_policy=True,
        soc2_equivalent=["CC3.1"],
        guidance=(
            "Use Whitney's compliance scoring to prioritise remediation. "
            "Maintain the AI Risk Register with treatment decisions."
        ),
    ),
    "MANAGE-2": NISTAIRMFCategory(
        id="MANAGE-2",
        function="MANAGE",
        title="Risk Treatment",
        description=(
            "Strategies to maximise AI benefits and minimise negative "
            "impacts are planned, prepared, and implemented."
        ),
        check_ids=[
            "sagemaker-endpoint-encryption",
            "sagemaker-training-vpc",
            "azure-ml-workspace-encryption",
            "azure-openai-private-endpoint",
        ],
        soc2_equivalent=["CC6.1", "CC6.7"],
        guidance=(
            "Implement technical controls: encrypt endpoints, isolate "
            "training in VPCs, use private endpoints. Address findings "
            "by severity."
        ),
    ),
    "MANAGE-3": NISTAIRMFCategory(
        id="MANAGE-3",
        function="MANAGE",
        title="Third-Party Risk Management",
        description=(
            "AI risks from third-party resources and tools are managed throughout the lifecycle."
        ),
        check_ids=[
            "code-outdated-ai-sdk",
            "lambda-ai-api-keys-not-hardcoded",
            "code-ai-api-key-exposed",
        ],
        soc2_equivalent=["CC9.1"],
        guidance=(
            "Track AI dependencies via SBOM. Keep SDKs updated. "
            "Manage API keys securely. Assess third-party AI vendors."
        ),
    ),
    "MANAGE-4": NISTAIRMFCategory(
        id="MANAGE-4",
        function="MANAGE",
        title="Post-Deployment Monitoring",
        description=(
            "AI systems are regularly monitored and assessed for ongoing "
            "risks, including performance degradation, drift, and "
            "emerging threats."
        ),
        check_ids=[
            "sagemaker-data-capture",
            "azure-ml-data-drift-monitor",
            "code-ai-logging-insufficient",
            "bedrock-model-invocation-logging",
        ],
        soc2_equivalent=["CC7.2", "CC7.3"],
        guidance=(
            "Enable data capture and drift monitoring. Run periodic "
            "Whitney scans. Monitor AI system performance metrics. "
            "Maintain audit trails."
        ),
    ),
}


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def get_nist_ai_rmf_category(category_id: str) -> NISTAIRMFCategory | None:
    """Look up a NIST AI RMF category by ID."""
    return NIST_AI_RMF_CATEGORIES.get(category_id)


def get_nist_ai_rmf_categories_for_check(check_id: str) -> list[NISTAIRMFCategory]:
    """Find all NIST AI RMF categories that a given check maps to."""
    return [c for c in NIST_AI_RMF_CATEGORIES.values() if check_id in c.check_ids]


def get_automated_nist_ai_rmf_categories() -> list[NISTAIRMFCategory]:
    """Get all categories that have automated checks."""
    return [c for c in NIST_AI_RMF_CATEGORIES.values() if c.check_ids]


def get_policy_required_nist_ai_rmf_categories() -> list[NISTAIRMFCategory]:
    """Get all categories that require policy documents."""
    return [c for c in NIST_AI_RMF_CATEGORIES.values() if c.requires_policy]


def get_nist_ai_rmf_categories_by_function(function: str) -> list[NISTAIRMFCategory]:
    """Get all categories for a specific function (GOVERN, MAP, MEASURE, MANAGE)."""
    return [c for c in NIST_AI_RMF_CATEGORIES.values() if c.function == function]
