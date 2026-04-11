"""Regex patterns for AI code security scanning.

All patterns used by check functions are defined here for reuse
and maintainability.
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# AI API key patterns
# ---------------------------------------------------------------------------

AI_API_KEY_PATTERNS: dict[str, re.Pattern[str]] = {
    "openai": re.compile(r"sk-[a-zA-Z0-9]{20,}"),
    "anthropic": re.compile(r"sk-ant-[a-zA-Z0-9\-]{20,}"),
    "huggingface": re.compile(r"hf_[a-zA-Z0-9]{20,}"),
    "cohere": re.compile(r"[a-zA-Z0-9]{40}"),  # Cohere keys are 40-char hex
    "azure_openai": re.compile(r"[a-f0-9]{32}"),  # Azure cognitive services keys
}

# More targeted patterns for hardcoded assignment in source files
AI_KEY_ASSIGNMENT_PATTERNS: list[re.Pattern[str]] = [
    re.compile(
        r"""(?:OPENAI_API_KEY|ANTHROPIC_API_KEY|HUGGINGFACE_TOKEN|COHERE_API_KEY|AZURE_OPENAI_KEY)\s*[=:]\s*["'][^"']{10,}["']"""
    ),
    re.compile(r"""api_key\s*=\s*["']sk-[a-zA-Z0-9]{20,}["']"""),
    re.compile(r"""api_key\s*=\s*["']sk-ant-[a-zA-Z0-9\-]{20,}["']"""),
    re.compile(r"""api_key\s*=\s*["']hf_[a-zA-Z0-9]{20,}["']"""),
]

# Patterns specifically for .env files
ENV_AI_KEY_PATTERNS: list[re.Pattern[str]] = [
    re.compile(
        r"^(?:OPENAI_API_KEY|ANTHROPIC_API_KEY|HUGGINGFACE_TOKEN|COHERE_API_KEY|AZURE_OPENAI_KEY|AI_API_KEY)\s*=\s*.+",
        re.MULTILINE,
    ),
    re.compile(r"^[A-Z_]*(?:API_KEY|SECRET_KEY|ACCESS_TOKEN)\s*=\s*sk-[a-zA-Z0-9]", re.MULTILINE),
    re.compile(
        r"^[A-Z_]*(?:API_KEY|SECRET_KEY|ACCESS_TOKEN)\s*=\s*sk-ant-[a-zA-Z0-9]", re.MULTILINE
    ),
    re.compile(r"^[A-Z_]*(?:API_KEY|SECRET_KEY|ACCESS_TOKEN)\s*=\s*hf_[a-zA-Z0-9]", re.MULTILINE),
]

# ---------------------------------------------------------------------------
# Prompt-related patterns
# ---------------------------------------------------------------------------

PROMPT_ROLE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"""["']role["']\s*:\s*["'](?:system|user|assistant)["']"""),
    re.compile(r"""role\s*=\s*["'](?:system|user|assistant)["']"""),
    re.compile(r"SystemMessage\s*\("),
    re.compile(r"HumanMessage\s*\("),
    re.compile(r"ChatPromptTemplate"),
]

USER_INPUT_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"request\.(?:body|json|form|data|args|params|query)"),
    re.compile(r"input\s*\("),
    re.compile(r"sys\.argv"),
    re.compile(r"req\.body"),
    re.compile(r"req\.query"),
    re.compile(r"params\["),
    re.compile(r"request\.GET"),
    re.compile(r"request\.POST"),
]

FSTRING_OR_FORMAT_PATTERN: re.Pattern[str] = re.compile(r'(?:f["\']|\.format\s*\(|%\s*\()')

META_PROMPT_PATTERNS: list[re.Pattern[str]] = [
    # Require system-prompt-like phrasing — "You are a/an ..." or "Your role is ..."
    re.compile(
        r"""["'](?:you are (?:a |an |the )|your role is|"""
        r"""your task is to|you must (?:always |never ))""",
        re.IGNORECASE,
    ),
    # "As an AI" with continuation — not just the phrase in isolation
    re.compile(
        r"""["']as an ai (?:assistant|agent|model|system)""",
        re.IGNORECASE,
    ),
]

# ---------------------------------------------------------------------------
# PII patterns
# ---------------------------------------------------------------------------

PII_PATTERNS: dict[str, re.Pattern[str]] = {
    "email": re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
    "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "credit_card": re.compile(r"\b(?:\d{4}[\s-]?){3}\d{4}\b"),
    "phone": re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
}

# ---------------------------------------------------------------------------
# AI SDK patterns
# ---------------------------------------------------------------------------

AI_SDK_IMPORT_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?:import|from)\s+openai"),
    re.compile(r"(?:import|from)\s+anthropic"),
    re.compile(r"(?:import|from)\s+langchain"),
    re.compile(r"(?:import|from)\s+transformers"),
    re.compile(r"(?:import|from)\s+cohere"),
    re.compile(r"(?:import|from)\s+huggingface_hub"),
    re.compile(r"""require\s*\(\s*["']openai["']\s*\)"""),
    re.compile(r"""require\s*\(\s*["']@anthropic-ai/sdk["']\s*\)"""),
    re.compile(r"""from\s+["']openai["']"""),
    re.compile(r"""from\s+["']@anthropic-ai/sdk["']"""),
]

AI_API_CALL_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"openai\.chat\.completions\.create"),
    re.compile(r"client\.chat\.completions\.create"),
    re.compile(r"anthropic\.messages\.create"),
    re.compile(r"client\.messages\.create"),
    re.compile(r"ChatCompletion\.create"),
    re.compile(r"Completion\.create"),
    re.compile(r"client\.invoke"),
    re.compile(r"chain\.invoke"),
    re.compile(r"chain\.run"),
    re.compile(r"llm\.\("),
    re.compile(r"model\.generate"),
    # Require pipeline with a task string to avoid CI/data pipeline matches
    re.compile(r"""pipeline\s*\(\s*["']"""),
]

AI_RESPONSE_DIRECT_USE: list[re.Pattern[str]] = [
    re.compile(r"response\.choices\[0\]\.message\.content"),
    re.compile(r"completion\.choices\[0\]\.message\.content"),
    re.compile(r"response\.content\[0\]\.text"),
    re.compile(r"result\.content"),
    re.compile(r"response\.text"),
]

# ---------------------------------------------------------------------------
# Dangerous tool / agent patterns
# ---------------------------------------------------------------------------

DANGEROUS_TOOL_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"os\.system\s*\("),
    re.compile(r"subprocess\.(?:run|call|Popen|check_output)\s*\("),
    re.compile(r"exec\s*\("),
    re.compile(r"eval\s*\("),
    re.compile(r"shutil\.(?:rmtree|move|copy)"),
    re.compile(r'open\s*\(.+["\']w["\']'),
    re.compile(r"requests\.(?:post|put|delete|patch)\s*\("),
    re.compile(r"cursor\.execute\s*\("),
    re.compile(r'\.execute\s*\(\s*["\'](?:INSERT|UPDATE|DELETE|DROP|ALTER)', re.IGNORECASE),
]

AGENT_TOOL_DEFINITION_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"Tool\s*\("),
    re.compile(r"StructuredTool\s*\("),
    re.compile(r"@tool"),
    re.compile(r"ToolKit\s*\("),
    re.compile(r'"type"\s*:\s*"function"'),
    re.compile(r"""["']function["']\s*:\s*\{"""),
]

# ---------------------------------------------------------------------------
# Vector DB / RAG patterns
# ---------------------------------------------------------------------------

VECTOR_DB_QUERY_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"pinecone\.(?:Index|query)"),
    re.compile(r"chroma\.(?:query|get)"),
    re.compile(r"vectorstore\.(?:similarity_search|as_retriever)"),
    re.compile(r"(?:vector_store|vectordb|vector_db)\.(?:query|search)\s*\("),
    re.compile(r"Qdrant.*\.search"),
    re.compile(r"weaviate.*\.query"),
    re.compile(r"(?:Chroma|FAISS|Milvus|Pinecone|Weaviate|Qdrant)\w*\.(?:query|search)\s*\("),
    re.compile(r"similarity_search\s*\("),
    re.compile(r"\.as_retriever\s*\("),
]

ACCESS_CONTROL_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?:user_id|tenant_id|org_id|owner|namespace)\s*[=:]"),
    re.compile(r"filter\s*=.*(?:user|tenant|org)"),
    re.compile(r"metadata_filter.*(?:user|tenant|org)"),
    re.compile(r"where\s*=.*(?:user|tenant|org)"),
]

# ---------------------------------------------------------------------------
# Rate limiting patterns
# ---------------------------------------------------------------------------

RATE_LIMIT_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"@(?:rate_limit|ratelimit|throttle|limiter\.limit)"),
    re.compile(r"RateLimiter\s*\("),
    re.compile(r"Limiter\s*\("),
    re.compile(r"slowapi"),
    re.compile(r"express-rate-limit"),
    re.compile(r"rateLimit\s*\("),
    re.compile(r"token_bucket"),
    re.compile(r"Retry\s*\("),
    re.compile(r"backoff\."),
]

# ---------------------------------------------------------------------------
# Auth decorator patterns
# ---------------------------------------------------------------------------

AUTH_DECORATOR_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"@login_required"),
    re.compile(r"@requires_auth"),
    re.compile(r"@auth_required"),
    re.compile(r"@jwt_required"),
    re.compile(r"@authenticated"),
    re.compile(r"@permission_required"),
    re.compile(r"@protect"),
    re.compile(r"authenticate\s*\("),
    re.compile(r"verify_token\s*\("),
    re.compile(r"Depends\s*\(\s*(?:get_current_user|auth|verify)"),
]

# ---------------------------------------------------------------------------
# Route patterns
# ---------------------------------------------------------------------------

ROUTE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"@app\.(?:route|get|post|put|delete|patch)\s*\("),
    re.compile(r"@router\.(?:get|post|put|delete|patch)\s*\("),
    re.compile(r"app\.(?:get|post|put|delete|patch)\s*\("),
    re.compile(r"router\.(?:get|post|put|delete|patch)\s*\("),
]

MODEL_INFERENCE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"model\.predict\s*\("),
    re.compile(r"model\.generate\s*\("),
    re.compile(r"\.completions\.create\s*\("),
    re.compile(r"\.messages\.create\s*\("),
    # Require pipeline with a task string to avoid matching CI/data pipelines
    re.compile(r"""pipeline\s*\(\s*["']"""),
]

# ---------------------------------------------------------------------------
# Logging patterns
# ---------------------------------------------------------------------------

LOGGING_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"logger\.(?:info|debug|warning|error|critical)\s*\("),
    re.compile(r"logging\.(?:info|debug|warning|error|critical)\s*\("),
    re.compile(r"print\s*\("),
    re.compile(r"console\.(?:log|warn|error)\s*\("),
    re.compile(r"log\.(?:info|debug|warn|error)\s*\("),
    re.compile(r"\.track\s*\("),
    re.compile(r"\.emit\s*\("),
    re.compile(r"sentry_sdk\.capture"),
]

# ---------------------------------------------------------------------------
# SDK version vulnerability database
# ---------------------------------------------------------------------------

VULNERABLE_SDK_VERSIONS: dict[str, list[dict[str, str]]] = {
    "langchain": [
        {
            "constraint": "< 0.0.325",
            "cve": "CVE-2023-46229",
            "description": "Arbitrary code execution via prompt injection in PALChain",
        },
    ],
    "openai": [
        {
            "constraint": "< 1.0.0",
            "cve": "N/A",
            "description": "Pre-1.0 SDK has deprecated API patterns and lacks safety defaults",
        },
    ],
    "transformers": [
        {
            "constraint": "< 4.36.0",
            "cve": "CVE-2023-49810",
            "description": "Unsafe pickle deserialization in model loading",
        },
    ],
}

# ---------------------------------------------------------------------------
# Model version patterns
# ---------------------------------------------------------------------------

GENERIC_MODEL_NAMES: list[re.Pattern[str]] = [
    re.compile(r"""model\s*=\s*["']gpt-4["']"""),
    re.compile(r"""model\s*=\s*["']gpt-3\.5-turbo["']"""),
    re.compile(r"""model\s*=\s*["']gpt-4-turbo["']"""),
    re.compile(r"""model\s*=\s*["']gpt-4o["']"""),
    re.compile(r"""model\s*=\s*["']claude-3-opus["']"""),
    re.compile(r"""model\s*=\s*["']claude-3-sonnet["']"""),
    re.compile(r"""model\s*=\s*["']claude-3-haiku["']"""),
]

# Models with date suffixes are considered "pinned"
PINNED_MODEL_PATTERN: re.Pattern[str] = re.compile(r"""model\s*=\s*["'][a-z0-9-]+-\d{4,8}["']""")

# ---------------------------------------------------------------------------
# Training data patterns
# ---------------------------------------------------------------------------

UNENCRYPTED_DATA_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"""open\s*\(\s*["'][^"']*(?:train|data|dataset|corpus)[^"']*["']""", re.IGNORECASE),
    re.compile(r"""pd\.read_csv\s*\(\s*["']http://"""),
    re.compile(r"""requests\.get\s*\(\s*["']http://"""),
    re.compile(r"""urllib\.request\.urlopen\s*\(\s*["']http://"""),
    re.compile(r"""wget\s+http://"""),
    re.compile(r"""curl\s+http://"""),
]

TRAINING_CONTEXT_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"model\.(?:train|fit)\s*\("),
    re.compile(r"trainer\.train\s*\("),
    re.compile(r"\.fit\s*\("),
    re.compile(r"training_args"),
    re.compile(r"TrainingArguments"),
    re.compile(r"DataLoader\s*\("),
]

# ---------------------------------------------------------------------------
# Error handling patterns
# ---------------------------------------------------------------------------

ERROR_HANDLING_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"try\s*:"),
    re.compile(r"except\s"),
    re.compile(r"\.catch\s*\("),
    re.compile(r"try\s*\{"),
    re.compile(r"catch\s*\("),
]

# ---------------------------------------------------------------------------
# File extension sets
# ---------------------------------------------------------------------------

SOURCE_CODE_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".py",
        ".js",
        ".ts",
        ".jsx",
        ".tsx",
        ".go",
        ".rs",
        ".java",
        ".rb",
    }
)

CONFIG_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".yaml",
        ".yml",
        ".json",
        ".toml",
        ".cfg",
        ".ini",
    }
)

ALL_SCANNABLE_EXTENSIONS: frozenset[str] = (
    SOURCE_CODE_EXTENSIONS
    | CONFIG_EXTENSIONS
    | frozenset(
        {
            ".txt",
            ".md",
            ".env",
            ".sh",
            ".bash",
        }
    )
)

# Paths to exclude from scanning
EXCLUDED_PATH_SEGMENTS: frozenset[str] = frozenset(
    {
        "node_modules",
        ".git",
        "__pycache__",
        ".venv",
        "venv",
        ".tox",
        ".mypy_cache",
        ".pytest_cache",
        "dist",
        "build",
        ".egg-info",
        ".eggs",
    }
)

# Files to exclude for key scanning (likely not real secrets)
KEY_SCAN_EXCLUDED_FILES: frozenset[str] = frozenset(
    {
        ".env.example",
        ".env.sample",
        ".env.template",
        "README.md",
        "README.rst",
        "CONTRIBUTING.md",
    }
)

# ---------------------------------------------------------------------------
# MCP (Model Context Protocol) patterns
# ---------------------------------------------------------------------------

MCP_SERVER_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?:from\s+mcp|import\s+mcp|require\s*\(\s*['\"].*mcp)", re.IGNORECASE),
    re.compile(r"McpServer|MCPServer|mcp\.server|StdioServerTransport", re.IGNORECASE),
    re.compile(r"@mcp\.tool|@server\.tool|\.add_tool\(", re.IGNORECASE),
]

# Indicators that an MCP server lacks authentication
MCP_NO_AUTH_PATTERNS: list[re.Pattern[str]] = [
    # stdio transport — inherently local, no auth needed
    re.compile(r"StdioServerTransport|stdio_server", re.IGNORECASE),
]

# MCP tool definitions that grant dangerous capabilities
MCP_DANGEROUS_TOOL_PATTERNS: list[re.Pattern[str]] = [
    re.compile(
        r"""(?:subprocess|os\.system|os\.popen|exec\s*\(|eval\s*\(|"""
        r"""shutil\.rmtree|shutil\.move|open\s*\(.+['\"]w)"""
    ),
    re.compile(r"(?:DROP\s+TABLE|DELETE\s+FROM|TRUNCATE\s+TABLE)", re.IGNORECASE),
]

# MCP tool definitions without input schema validation
MCP_NO_SCHEMA_PATTERNS: list[re.Pattern[str]] = [
    # Tool definition with **kwargs or *args (no typed schema)
    re.compile(r"def\s+\w+\s*\(\s*\*\*kwargs\s*\)"),
    re.compile(r"def\s+\w+\s*\(\s*\*args\s*\)"),
]

# ---------------------------------------------------------------------------
# A2A (Agent-to-Agent) protocol patterns
# ---------------------------------------------------------------------------

A2A_PATTERNS: list[re.Pattern[str]] = [
    # a2a-sdk Python package: from a2a.server import ..., from a2a.types import ...
    re.compile(r"(?:from\s+a2a\b|import\s+a2a\b)", re.IGNORECASE),
    # Core A2A types (PascalCase class names from the SDK)
    re.compile(r"AgentCard|A2AServer|A2AClient|A2AStarletteApplication"),
    # Well-known agent card path (spec: /.well-known/agent-card.json)
    re.compile(r"agent[_-]?card\.json|\.well-known/agent", re.IGNORECASE),
    # A2A message types
    re.compile(r"TaskSendParams|MessageSendParams|SendTaskRequest"),
    # Agent skill/capability declarations
    re.compile(r"AgentSkill|AgentCapabilities|AgentProvider"),
]

# A2A agent cards without authentication requirements
A2A_NO_AUTH_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"""['\"]authentication['\"]?\s*:\s*(?:None|null|['\"]['\"]|\[\s*\])"""),
    re.compile(r"""['\"]auth['\"]?\s*:\s*(?:None|null|['\"]['\"]|\{\s*\})"""),
]

MAX_FILE_SIZE_BYTES: int = 1_048_576  # 1 MB
