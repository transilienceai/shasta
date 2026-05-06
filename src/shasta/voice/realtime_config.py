"""OpenAI Realtime session configuration: Distiller prompt, 14 tool schemas, VAD."""
import os
from typing import Any

SYSTEM_PROMPT = """You are Shasta's voice compliance assistant. You are talking to a security engineer or founder over voice. Their data is real — you have read access to their actual scan findings, compliance scores across SOC 2 / ISO 27001 / HIPAA / ISO 42001 / EU AI Act, and risk register.

VOICE OUTPUT RULES (non-negotiable):
- Maximum 25 words per response unless the user explicitly asks for detail.
- Lead with the most important fact. Numbers before context. Severity before description. Failed counts before passing counts.
- Never read JSON, ARNs, IP addresses, or long control IDs out loud unless the user asks.
- If listing items, name at most 3. Offer to continue ("...and 5 more — want the full list?").
- Use plain words, not compliance jargon, unless the user uses jargon first.

TOOL USE:
- For any question about findings, scores, controls, scans, or risks, call a tool. Never invent data.
- For ambiguous questions, make the most reasonable assumption (default: status=fail, scope=latest scan) and proceed; mention your assumption briefly.
- After an action tool succeeds (add_risk_item, update_risk), confirm in one short sentence.
- If a tool returns "no_data" or empty, say so honestly. Do not invent.

REDIRECTS (out of scope for voice — Shasta runs these via Claude Code skills):
- RUN A SCAN → "Run /scan in Claude Code. Want me to summarize what it'll do first?"
- GENERATE A REPORT/PDF → "Run /report — voice can't deliver PDFs. I can summarize the latest scan."
- GENERATE TERRAFORM → "Run /remediate for the Terraform. I can describe what the fix does."
- GENERATE POLICY DOCS → "Run /policy-gen for the policy docs."

PERSONA:
- Calm, precise, slightly understated. Experienced compliance engineer on a Tuesday afternoon.
- Adjust register to the audience — technical for engineers, plainer for founders.
- Never apologize for tool latency. Never say "let me check that for you" — just do it.
"""

TOOL_SCHEMAS: list[dict[str, Any]] = [
    {
        "type": "function", "name": "list_findings",
        "description": "List compliance findings from the latest scan. Filter by severity, status, domain, cloud, framework, control.",
        "parameters": {
            "type": "object",
            "properties": {
                "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
                "status": {"type": "string", "enum": ["pass", "fail", "partial", "not_assessed", "not_applicable"]},
                "domain": {"type": "string", "enum": ["iam", "networking", "encryption", "logging", "compute", "storage", "monitoring", "ai_governance"]},
                "cloud": {"type": "string", "enum": ["aws", "azure"]},
                "framework": {"type": "string", "enum": ["soc2", "iso27001", "hipaa"]},
                "control_id": {"type": "string", "description": "e.g., CC6.1 — only meaningful with framework set"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 100},
            },
            "additionalProperties": False,
        },
    },
    {
        "type": "function", "name": "get_finding",
        "description": "Get full detail of a single finding by ID — description, remediation, affected resource, control mappings.",
        "parameters": {
            "type": "object",
            "properties": {"finding_id": {"type": "string"}},
            "required": ["finding_id"],
            "additionalProperties": False,
        },
    },
    {
        "type": "function", "name": "list_top_blockers",
        "description": "List the highest-severity unresolved findings. Use for 'what should I fix first?' questions.",
        "parameters": {
            "type": "object",
            "properties": {"limit": {"type": "integer", "minimum": 1, "maximum": 20}},
            "additionalProperties": False,
        },
    },
    {
        "type": "function", "name": "get_resource_findings",
        "description": "List all findings for a specific cloud resource (by ARN or Azure resource ID).",
        "parameters": {
            "type": "object",
            "properties": {"resource_id": {"type": "string"}},
            "required": ["resource_id"],
            "additionalProperties": False,
        },
    },
    {
        "type": "function", "name": "get_compliance_score",
        "description": "Get the compliance score for one framework. Use when the user asks about a specific standard.",
        "parameters": {
            "type": "object",
            "properties": {"framework": {"type": "string", "enum": ["soc2", "iso27001", "hipaa", "iso42001", "eu_ai_act", "ai_governance"]}},
            "required": ["framework"],
            "additionalProperties": False,
        },
    },
    {
        "type": "function", "name": "get_multi_framework_score",
        "description": "Get scores for ALL frameworks at once. Use for 'how am I doing across the board?' or 'overall posture' questions.",
        "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "type": "function", "name": "get_score_trend",
        "description": "Get score history for a framework across recent scans. Use for 'how does that compare to last week?' questions.",
        "parameters": {
            "type": "object",
            "properties": {
                "framework": {"type": "string", "enum": ["soc2", "iso27001", "hipaa"]},
                "limit": {"type": "integer", "minimum": 2, "maximum": 50},
            },
            "required": ["framework"],
            "additionalProperties": False,
        },
    },
    {
        "type": "function", "name": "get_control_summary",
        "description": "Get summary of a specific control (e.g., CC6.1) or all controls in a framework. Returns pass/fail counts + finding IDs.",
        "parameters": {
            "type": "object",
            "properties": {
                "framework": {"type": "string", "enum": ["soc2", "iso27001", "hipaa"]},
                "control_id": {"type": "string"},
            },
            "required": ["framework"],
            "additionalProperties": False,
        },
    },
    {
        "type": "function", "name": "list_scans",
        "description": "List recent scans with summary stats (date, total findings, pass/fail counts).",
        "parameters": {
            "type": "object",
            "properties": {"limit": {"type": "integer", "minimum": 1, "maximum": 50}},
            "additionalProperties": False,
        },
    },
    {
        "type": "function", "name": "get_latest_scan",
        "description": "Get summary of the most recent scan: when it ran, total findings, severity counts.",
        "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "type": "function", "name": "list_risk_items",
        "description": "List risk register items. Filter by status (open/in_progress/accepted/resolved) or level (high/medium/low).",
        "parameters": {
            "type": "object",
            "properties": {
                "account_id": {"type": "string", "description": "Cloud account ID — pass the user's account from latest scan if unknown"},
                "status": {"type": "string", "enum": ["open", "in_progress", "accepted", "resolved"]},
                "level": {"type": "string", "enum": ["high", "medium", "low"]},
            },
            "required": ["account_id"],
            "additionalProperties": False,
        },
    },
    {
        "type": "function", "name": "get_risk_item",
        "description": "Get a single risk register item by ID.",
        "parameters": {
            "type": "object",
            "properties": {"risk_id": {"type": "string"}, "account_id": {"type": "string"}},
            "required": ["risk_id"],
            "additionalProperties": False,
        },
    },
    {
        "type": "function", "name": "add_risk_item",
        "description": "Add a new risk to the risk register. Use when the user explicitly asks to record a risk.",
        "parameters": {
            "type": "object",
            "properties": {
                "account_id": {"type": "string"},
                "title": {"type": "string"},
                "description": {"type": "string"},
                "category": {"type": "string", "description": "e.g., iam, logging, encryption"},
                "likelihood": {"type": "string", "enum": ["low", "medium", "high"]},
                "impact": {"type": "string", "enum": ["low", "medium", "high"]},
                "treatment": {"type": "string", "enum": ["mitigate", "accept", "transfer", "avoid"]},
                "treatment_plan": {"type": "string"},
                "related_finding": {"type": "string", "description": "Optional finding ID this risk relates to"},
            },
            "required": ["account_id", "title", "description", "category", "likelihood", "impact", "treatment"],
            "additionalProperties": False,
        },
    },
    {
        "type": "function", "name": "update_risk",
        "description": "Update an existing risk register item. Pass risk_id plus any fields to change.",
        "parameters": {
            "type": "object",
            "properties": {
                "risk_id": {"type": "string"},
                "account_id": {"type": "string"},
                "treatment": {"type": "string", "enum": ["mitigate", "accept", "transfer", "avoid"]},
                "treatment_plan": {"type": "string"},
                "status": {"type": "string", "enum": ["open", "in_progress", "accepted", "resolved"]},
                "review_notes": {"type": "string"},
            },
            "required": ["risk_id"],
            "additionalProperties": False,
        },
    },
]


VAD_CONFIG: dict[str, Any] = {
    "type": "server_vad",
    "threshold": 0.5,
    "prefix_padding_ms": 300,
    "silence_duration_ms": 500,
}


def build_session_payload() -> dict[str, Any]:
    return {
        "model": os.environ.get("OPENAI_REALTIME_MODEL", "gpt-realtime"),
        "voice": os.environ.get("OPENAI_REALTIME_VOICE", "cedar"),
        "instructions": SYSTEM_PROMPT,
        "tools": TOOL_SCHEMAS,
        "turn_detection": VAD_CONFIG,
        "input_audio_format": "pcm16",
        "output_audio_format": "pcm16",
        "input_audio_transcription": {"model": "whisper-1"},
    }
