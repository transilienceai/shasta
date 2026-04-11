"""OWASP Top 10 for Agentic AI framework definitions.

Maps Whitney AI checks to the OWASP Agentic AI Top 10 risk items,
covering agent autonomy, tool calling, MCP servers, multi-agent
communication, and identity/access concerns unique to AI agents.

Reference: https://owasp.org/www-project-top-10-for-large-language-model-applications/
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class OWASPAgenticRisk:
    """A single OWASP Agentic AI Top 10 risk item."""

    id: str  # e.g., "AGENTIC01"
    title: str
    description: str
    check_ids: list[str] = field(default_factory=list)
    soc2_equivalent: list[str] = field(default_factory=list)
    guidance: str = ""


# ---------------------------------------------------------------------------
# OWASP Agentic AI Top 10 Risk Items
# ---------------------------------------------------------------------------

OWASP_AGENTIC_TOP10: dict[str, OWASPAgenticRisk] = {
    "AGENTIC01": OWASPAgenticRisk(
        id="AGENTIC01",
        title="Excessive Agency and Autonomy",
        description=(
            "Agents granted overly broad permissions, tools, or decision-making "
            "authority without appropriate human oversight or scope limitations."
        ),
        check_ids=[
            "code-agent-unrestricted-tools",
            "bedrock-agent-guardrails",
            "code-a2a-delegation-scope",
        ],
        soc2_equivalent=["CC6.1", "CC6.3"],
        guidance=(
            "Apply least-privilege to agent tool sets. Define explicit scope "
            "boundaries. Require human approval for high-impact actions. "
            "Attach guardrails to Bedrock agents."
        ),
    ),
    "AGENTIC02": OWASPAgenticRisk(
        id="AGENTIC02",
        title="Tool and Function Abuse",
        description=(
            "Agents invoking tools or functions in unintended ways, including "
            "shell execution, file system access, database manipulation, and "
            "API calls beyond intended scope."
        ),
        check_ids=[
            "code-agent-unrestricted-tools",
            "code-mcp-tool-scope",
            "code-mcp-input-validation",
        ],
        soc2_equivalent=["CC6.1", "CC7.2"],
        guidance=(
            "Sandbox agent tools. Use allowlists for permitted operations. "
            "Validate tool inputs and outputs. Log all tool invocations "
            "for audit. Define typed schemas for MCP tools."
        ),
    ),
    "AGENTIC03": OWASPAgenticRisk(
        id="AGENTIC03",
        title="Insecure MCP Server Configuration",
        description=(
            "MCP (Model Context Protocol) servers deployed without "
            "authentication, TLS, or access controls, enabling unauthorised "
            "tool access and data exposure."
        ),
        check_ids=[
            "code-mcp-server-auth",
            "code-mcp-tool-scope",
            "code-mcp-input-validation",
        ],
        soc2_equivalent=["CC6.1", "CC6.6"],
        guidance=(
            "Require authentication on all MCP servers. Use TLS for "
            "transport. Restrict tool exposure per server. Audit MCP "
            "server configurations with /discover-ai."
        ),
    ),
    "AGENTIC04": OWASPAgenticRisk(
        id="AGENTIC04",
        title="Agent Identity and Credential Mismanagement",
        description=(
            "Agents operating with shared credentials, hardcoded API keys, "
            "or overprivileged service accounts rather than scoped, "
            "per-agent identity."
        ),
        check_ids=[
            "code-ai-api-key-exposed",
            "code-ai-key-in-env-file",
            "lambda-ai-api-keys-not-hardcoded",
            "azure-openai-managed-identity",
            "code-a2a-agent-auth",
        ],
        soc2_equivalent=["CC6.1", "CC6.2"],
        guidance=(
            "Use managed identities instead of API keys. Never hardcode "
            "credentials. Assign per-agent service accounts with "
            "least-privilege IAM policies. Require authentication in "
            "A2A Agent Cards."
        ),
    ),
    "AGENTIC05": OWASPAgenticRisk(
        id="AGENTIC05",
        title="Inadequate Agent Logging and Observability",
        description=(
            "Insufficient logging of agent decisions, tool calls, and "
            "multi-turn traces, preventing incident investigation and "
            "compliance audit."
        ),
        check_ids=[
            "code-ai-logging-insufficient",
            "bedrock-model-invocation-logging",
            "azure-openai-diagnostic-logging",
            "cloudtrail-ai-events",
        ],
        soc2_equivalent=["CC7.2", "CC7.3"],
        guidance=(
            "Log all agent interactions including tool calls and decisions. "
            "Enable model invocation logging on Bedrock. Configure "
            "diagnostic settings on Azure OpenAI. Capture CloudTrail "
            "AI events."
        ),
    ),
    "AGENTIC06": OWASPAgenticRisk(
        id="AGENTIC06",
        title="Multi-Agent Communication Attacks",
        description=(
            "Adversarial manipulation of communication between agents in "
            "multi-agent systems, including message injection, agent "
            "impersonation, and consensus poisoning."
        ),
        check_ids=[],  # Future: multi-agent-auth, agent-message-validation
        soc2_equivalent=["CC6.1", "CC7.2"],
        guidance=(
            "Authenticate inter-agent messages. Validate agent identity "
            "before accepting instructions. Implement message integrity "
            "checks for multi-agent orchestration."
        ),
    ),
    "AGENTIC07": OWASPAgenticRisk(
        id="AGENTIC07",
        title="RAG and Knowledge Base Poisoning",
        description=(
            "Adversarial manipulation of retrieval-augmented generation "
            "pipelines through document injection, metadata manipulation, "
            "or access control bypass in vector databases."
        ),
        check_ids=[
            "code-rag-no-access-control",
        ],
        soc2_equivalent=["CC6.1", "CC6.3"],
        guidance=(
            "Implement user-level access filtering on vector DB queries. "
            "Validate document sources before indexing. Monitor for "
            "anomalous document additions."
        ),
    ),
    "AGENTIC08": OWASPAgenticRisk(
        id="AGENTIC08",
        title="Agent Prompt Injection via Tools",
        description=(
            "Indirect prompt injection through data returned by tool "
            "calls — the agent processes malicious instructions embedded "
            "in tool output, web pages, or database records."
        ),
        check_ids=[
            "code-prompt-injection-risk",
            "code-no-output-validation",
        ],
        soc2_equivalent=["CC6.1", "CC7.2"],
        guidance=(
            "Treat all tool outputs as untrusted. Sanitise data before "
            "including in agent context. Use separate system prompts for "
            "tool result processing."
        ),
    ),
    "AGENTIC09": OWASPAgenticRisk(
        id="AGENTIC09",
        title="Uncontrolled Agent Resource Consumption",
        description=(
            "Agents consuming excessive compute, API calls, or cost "
            "through unbounded loops, recursive tool calls, or "
            "adversarially triggered expensive operations."
        ),
        check_ids=[
            "code-no-rate-limiting",
            "code-no-fallback-handler",
        ],
        soc2_equivalent=["CC6.1", "CC7.5"],
        guidance=(
            "Set per-agent cost budgets and call limits. Implement "
            "circuit breakers and timeouts. Rate-limit agent-facing "
            "endpoints."
        ),
    ),
    "AGENTIC10": OWASPAgenticRisk(
        id="AGENTIC10",
        title="Insufficient Agent Guardrails",
        description=(
            "Deploying agents without content filtering, output validation, "
            "or behavioural guardrails, allowing harmful, biased, or "
            "off-policy outputs."
        ),
        check_ids=[
            "bedrock-guardrails-configured",
            "bedrock-content-filter",
            "azure-openai-content-filter",
            "code-no-output-validation",
        ],
        soc2_equivalent=["CC7.2"],
        guidance=(
            "Configure guardrails and content filters on all AI services. "
            "Validate agent outputs before acting on them. Deploy Bedrock "
            "guardrails and Azure content filters."
        ),
    ),
}


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


def get_owasp_agentic_risk(risk_id: str) -> OWASPAgenticRisk | None:
    """Look up an OWASP Agentic AI risk by ID."""
    return OWASP_AGENTIC_TOP10.get(risk_id)


def get_owasp_agentic_risks_for_check(check_id: str) -> list[OWASPAgenticRisk]:
    """Find all OWASP Agentic AI risks that a given check maps to."""
    return [r for r in OWASP_AGENTIC_TOP10.values() if check_id in r.check_ids]


def get_automated_owasp_agentic_risks() -> list[OWASPAgenticRisk]:
    """Get all risk items that have automated checks."""
    return [r for r in OWASP_AGENTIC_TOP10.values() if r.check_ids]
