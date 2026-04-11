"""Tests for Whitney AI code security check functions.

Each of the 15 checks gets at least a 'detect' test (vulnerable code)
and a 'clean' test (safe code, no findings) using realistic code snippets.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from whitney.code.checks import (
    ALL_CHECKS,
    check_a2a_agent_auth,
    check_a2a_delegation_scope,
    check_ai_api_key_exposed,
    check_ai_key_in_env_file,
    check_ai_logging_insufficient,
    check_agent_unrestricted_tools,
    check_mcp_input_validation,
    check_mcp_server_auth,
    check_mcp_tool_scope,
    check_meta_prompt_exposed,
    check_model_endpoint_public,
    check_no_fallback_handler,
    check_no_model_versioning,
    check_no_output_validation,
    check_no_rate_limiting,
    check_outdated_ai_sdk,
    check_pii_in_prompts,
    check_prompt_injection_risk,
    check_rag_no_access_control,
    check_training_data_unencrypted,
)
from shasta.evidence.models import Severity, ComplianceStatus

from tests.test_whitney.conftest import write_file


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _assert_finding(findings, *, check_id, severity=None):
    """Assert that at least one finding matches check_id and optional severity."""
    matches = [f for f in findings if f.check_id == check_id]
    assert matches, f"Expected finding with check_id={check_id}, got {[f.check_id for f in findings]}"
    if severity:
        assert any(f.severity == severity for f in matches), (
            f"Expected severity {severity} for {check_id}"
        )


# ---------------------------------------------------------------------------
# CRITICAL: check_ai_api_key_exposed
# ---------------------------------------------------------------------------


class TestCheckAIApiKeyExposed:
    """Test detection of hardcoded AI API keys in source files."""

    def test_detects_openai_key_assignment(self, tmp_path):
        write_file(tmp_path, "app.py", 'api_key = "sk-abcdef1234567890abcdefghij"\n')
        findings = check_ai_api_key_exposed(tmp_path)
        _assert_finding(findings, check_id="code-ai-api-key-exposed", severity=Severity.CRITICAL)

    def test_detects_anthropic_key_assignment(self, tmp_path):
        write_file(tmp_path, "app.py", 'api_key = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz"\n')
        findings = check_ai_api_key_exposed(tmp_path)
        _assert_finding(findings, check_id="code-ai-api-key-exposed")

    def test_detects_named_key_variable(self, tmp_path):
        write_file(tmp_path, "config.py", 'OPENAI_API_KEY = "sk-abcdef1234567890abcdefghij"\n')
        findings = check_ai_api_key_exposed(tmp_path)
        _assert_finding(findings, check_id="code-ai-api-key-exposed")

    def test_skips_comments(self, tmp_path):
        write_file(tmp_path, "app.py", '# api_key = "sk-abcdef1234567890abcdefghij"\n')
        findings = check_ai_api_key_exposed(tmp_path)
        assert len(findings) == 0

    def test_skips_readme(self, tmp_path):
        # README.md is in KEY_SCAN_EXCLUDED_FILES, but it's also not a SOURCE_CODE_EXTENSIONS file
        write_file(tmp_path, "app.py", "key = os.environ.get('OPENAI_API_KEY')\n")
        findings = check_ai_api_key_exposed(tmp_path)
        assert len(findings) == 0

    def test_clean_code_no_findings(self, tmp_path):
        write_file(
            tmp_path,
            "app.py",
            "import os\napi_key = os.environ.get('OPENAI_API_KEY')\n",
        )
        findings = check_ai_api_key_exposed(tmp_path)
        assert len(findings) == 0

    def test_finding_has_code_snippet(self, tmp_path):
        write_file(tmp_path, "app.py", 'key = "sk-abcdef1234567890abcdefghij"\n')
        findings = check_ai_api_key_exposed(tmp_path)
        assert findings[0].details["code_snippet"]
        assert findings[0].details["line_number"] == 1


# ---------------------------------------------------------------------------
# CRITICAL: check_ai_key_in_env_file
# ---------------------------------------------------------------------------


class TestCheckAIKeyInEnvFile:
    """Test detection of AI keys in .env files."""

    def test_detects_key_in_env(self, tmp_path):
        write_file(tmp_path, ".env", "OPENAI_API_KEY=sk-abcdef1234567890abcdefghij\n")
        findings = check_ai_key_in_env_file(tmp_path)
        _assert_finding(findings, check_id="code-ai-key-in-env-file")

    def test_critical_when_not_gitignored(self, tmp_path):
        write_file(tmp_path, ".env", "OPENAI_API_KEY=sk-abcdef1234567890abcdefghij\n")
        findings = check_ai_key_in_env_file(tmp_path)
        _assert_finding(findings, check_id="code-ai-key-in-env-file", severity=Severity.CRITICAL)

    def test_medium_when_gitignored(self, tmp_path):
        write_file(tmp_path, ".gitignore", ".env\n")
        write_file(tmp_path, ".env", "OPENAI_API_KEY=sk-abcdef1234567890abcdefghij\n")
        findings = check_ai_key_in_env_file(tmp_path)
        _assert_finding(findings, check_id="code-ai-key-in-env-file", severity=Severity.MEDIUM)

    def test_skips_env_example(self, tmp_path):
        write_file(tmp_path, ".env.example", "OPENAI_API_KEY=your-key-here\n")
        findings = check_ai_key_in_env_file(tmp_path)
        assert len(findings) == 0

    def test_no_env_no_findings(self, tmp_path):
        write_file(tmp_path, "app.py", "print('hello')\n")
        findings = check_ai_key_in_env_file(tmp_path)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# HIGH: check_prompt_injection_risk
# ---------------------------------------------------------------------------


class TestCheckPromptInjectionRisk:
    """Test detection of user input interpolated into AI prompts."""

    def test_detects_vulnerable_flask_chat(self, tmp_path):
        code = '''from flask import request
import openai

@app.route("/chat", methods=["POST"])
def chat():
    user_msg = request.json["message"]
    response = openai.chat.completions.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": "You are a helpful assistant"},
            {"role": "user", "content": f"Help with: {user_msg}"}
        ]
    )
'''
        write_file(tmp_path, "app.py", code)
        findings = check_prompt_injection_risk(tmp_path)
        _assert_finding(findings, check_id="code-prompt-injection-risk", severity=Severity.HIGH)

    def test_no_user_input_no_finding(self, tmp_path):
        code = '''import openai
response = openai.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "system", "content": "You are a helper"}]
)
'''
        write_file(tmp_path, "app.py", code)
        findings = check_prompt_injection_risk(tmp_path)
        assert len(findings) == 0

    def test_role_only_no_finding(self, tmp_path):
        code = '''messages = [{"role": "user", "content": "hardcoded content"}]
'''
        write_file(tmp_path, "app.py", code)
        findings = check_prompt_injection_risk(tmp_path)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# HIGH: check_no_output_validation
# ---------------------------------------------------------------------------


class TestCheckNoOutputValidation:
    """Test detection of unvalidated LLM responses."""

    def test_detects_direct_use(self, tmp_path):
        code = '''import openai
response = openai.chat.completions.create(model="gpt-4", messages=[])
output = response.choices[0].message.content
return output
'''
        write_file(tmp_path, "app.py", code)
        findings = check_no_output_validation(tmp_path)
        _assert_finding(findings, check_id="code-no-output-validation", severity=Severity.HIGH)

    def test_no_finding_with_validation(self, tmp_path):
        code = '''import openai
response = openai.chat.completions.create(model="gpt-4", messages=[])
raw = response.choices[0].message.content
validated = sanitize(raw)
return validated
'''
        write_file(tmp_path, "app.py", code)
        findings = check_no_output_validation(tmp_path)
        assert len(findings) == 0

    def test_no_finding_with_json_parse(self, tmp_path):
        code = '''response = client.messages.create(model="claude-3", messages=[])
raw = response.content[0].text
data = json.loads(raw)
return data
'''
        write_file(tmp_path, "app.py", code)
        findings = check_no_output_validation(tmp_path)
        assert len(findings) == 0

    def test_no_ai_response_no_finding(self, tmp_path):
        code = "x = 1 + 2\nreturn x\n"
        write_file(tmp_path, "app.py", code)
        findings = check_no_output_validation(tmp_path)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# HIGH: check_pii_in_prompts
# ---------------------------------------------------------------------------


class TestCheckPiiInPrompts:
    """Test detection of PII in prompt strings."""

    def test_detects_ssn_in_prompt(self, tmp_path):
        code = '''messages = [{"role": "user", "content": "SSN is 123-45-6789"}]
'''
        write_file(tmp_path, "app.py", code)
        findings = check_pii_in_prompts(tmp_path)
        _assert_finding(findings, check_id="code-pii-in-prompts", severity=Severity.HIGH)

    def test_detects_email_in_prompt(self, tmp_path):
        code = '''prompt = f"User email: user@example.com"
messages = [{"role": "user", "content": prompt}]
'''
        write_file(tmp_path, "app.py", code)
        findings = check_pii_in_prompts(tmp_path)
        _assert_finding(findings, check_id="code-pii-in-prompts")

    def test_no_pii_outside_prompt_context(self, tmp_path):
        code = '''# Just a regular file
email = "user@example.com"
print(email)
'''
        write_file(tmp_path, "app.py", code)
        findings = check_pii_in_prompts(tmp_path)
        assert len(findings) == 0

    def test_detects_db_reference_in_prompt(self, tmp_path):
        code = '''messages = [{"role": "system", "content": f"Data: {user.name}, {customer.email}"}]
'''
        write_file(tmp_path, "app.py", code)
        findings = check_pii_in_prompts(tmp_path)
        _assert_finding(findings, check_id="code-pii-in-prompts")


# ---------------------------------------------------------------------------
# HIGH: check_model_endpoint_public
# ---------------------------------------------------------------------------


class TestCheckModelEndpointPublic:
    """Test detection of unauthenticated model endpoints."""

    def test_detects_unauth_endpoint(self, tmp_path):
        code = '''from flask import Flask
app = Flask(__name__)

@app.post("/api/chat")
def chat():
    result = model.predict(request.json)
    return result
'''
        write_file(tmp_path, "app.py", code)
        findings = check_model_endpoint_public(tmp_path)
        _assert_finding(findings, check_id="code-model-endpoint-public", severity=Severity.HIGH)

    def test_no_finding_with_auth(self, tmp_path):
        code = '''from flask import Flask
app = Flask(__name__)

@login_required
@app.post("/api/chat")
def chat():
    result = model.predict(request.json)
    return result
'''
        write_file(tmp_path, "app.py", code)
        findings = check_model_endpoint_public(tmp_path)
        assert len(findings) == 0

    def test_no_finding_without_inference(self, tmp_path):
        code = '''@app.get("/health")
def health():
    return {"status": "ok"}
'''
        write_file(tmp_path, "app.py", code)
        findings = check_model_endpoint_public(tmp_path)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# HIGH: check_agent_unrestricted_tools
# ---------------------------------------------------------------------------


class TestCheckAgentUnrestrictedTools:
    """Test detection of AI agent tools with dangerous capabilities."""

    def test_detects_tool_with_exec(self, tmp_path):
        code = '''from langchain.tools import Tool

code_tool = Tool(
    name="code_executor",
    func=lambda code: exec(code),
    description="Executes Python code"
)
'''
        write_file(tmp_path, "app.py", code)
        findings = check_agent_unrestricted_tools(tmp_path)
        _assert_finding(
            findings, check_id="code-agent-unrestricted-tools", severity=Severity.HIGH
        )

    def test_detects_tool_with_subprocess(self, tmp_path):
        code = '''@tool
def run_command(cmd: str):
    """Run a shell command."""
    return subprocess.run(cmd, shell=True, capture_output=True)
'''
        write_file(tmp_path, "app.py", code)
        findings = check_agent_unrestricted_tools(tmp_path)
        _assert_finding(findings, check_id="code-agent-unrestricted-tools")

    def test_no_finding_safe_tool(self, tmp_path):
        code = '''@tool
def get_weather(city: str):
    """Get weather for a city."""
    return weather_api.get(city)
'''
        write_file(tmp_path, "app.py", code)
        findings = check_agent_unrestricted_tools(tmp_path)
        assert len(findings) == 0

    def test_no_finding_no_tool_def(self, tmp_path):
        code = "import subprocess\nsubprocess.run(['ls'])\n"
        write_file(tmp_path, "app.py", code)
        findings = check_agent_unrestricted_tools(tmp_path)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# MEDIUM: check_rag_no_access_control
# ---------------------------------------------------------------------------


class TestCheckRagNoAccessControl:
    """Test detection of RAG queries without access filtering."""

    def test_detects_unfiltered_query(self, tmp_path):
        code = '''results = vectorstore.similarity_search(query)
return results
'''
        write_file(tmp_path, "app.py", code)
        findings = check_rag_no_access_control(tmp_path)
        _assert_finding(findings, check_id="code-rag-no-access-control", severity=Severity.MEDIUM)

    def test_no_finding_with_user_filter(self, tmp_path):
        code = '''results = vectorstore.similarity_search(
    query,
    filter={"user_id": current_user.id}
)
return results
'''
        write_file(tmp_path, "app.py", code)
        findings = check_rag_no_access_control(tmp_path)
        assert len(findings) == 0

    def test_no_finding_without_vector_query(self, tmp_path):
        code = "results = db.execute('SELECT * FROM users')\n"
        write_file(tmp_path, "app.py", code)
        findings = check_rag_no_access_control(tmp_path)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# MEDIUM: check_no_rate_limiting
# ---------------------------------------------------------------------------


class TestCheckNoRateLimiting:
    """Test detection of AI API calls without rate limiting."""

    def test_detects_unrated_route(self, tmp_path):
        code = '''from flask import Flask
app = Flask(__name__)

@app.post("/api/chat")
def chat():
    response = client.chat.completions.create(
        model="gpt-4", messages=[]
    )
    return response
'''
        write_file(tmp_path, "app.py", code)
        findings = check_no_rate_limiting(tmp_path)
        _assert_finding(findings, check_id="code-no-rate-limiting", severity=Severity.MEDIUM)

    def test_no_finding_with_rate_limiter(self, tmp_path):
        code = '''from flask import Flask
from slowapi import Limiter
app = Flask(__name__)

@app.post("/api/chat")
@limiter.limit("10/minute")
def chat():
    response = client.chat.completions.create(
        model="gpt-4", messages=[]
    )
    return response
'''
        write_file(tmp_path, "app.py", code)
        findings = check_no_rate_limiting(tmp_path)
        assert len(findings) == 0

    def test_no_finding_without_route(self, tmp_path):
        code = '''def process():
    response = client.chat.completions.create(
        model="gpt-4", messages=[]
    )
    return response
'''
        write_file(tmp_path, "app.py", code)
        findings = check_no_rate_limiting(tmp_path)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# MEDIUM: check_meta_prompt_exposed
# ---------------------------------------------------------------------------


class TestCheckMetaPromptExposed:
    """Test detection of system prompts in user-facing code."""

    def test_detects_meta_prompt_in_route_file(self, tmp_path):
        code = '''from flask import Flask
app = Flask(__name__)

SYSTEM_PROMPT = "You are a helpful assistant"

@app.post("/chat")
def chat():
    return call_ai(SYSTEM_PROMPT)
'''
        write_file(tmp_path, "app.py", code)
        findings = check_meta_prompt_exposed(tmp_path)
        _assert_finding(findings, check_id="code-meta-prompt-exposed", severity=Severity.MEDIUM)

    def test_no_finding_without_routes(self, tmp_path):
        code = '''SYSTEM_PROMPT = "You are a helpful assistant"
result = call_ai(SYSTEM_PROMPT)
'''
        write_file(tmp_path, "utils.py", code)
        findings = check_meta_prompt_exposed(tmp_path)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# MEDIUM: check_ai_logging_insufficient
# ---------------------------------------------------------------------------


class TestCheckAILoggingInsufficient:
    """Test detection of AI API calls without logging."""

    def test_detects_unlogged_ai_call(self, tmp_path):
        code = '''response = client.chat.completions.create(
    model="gpt-4", messages=[]
)
return response
'''
        write_file(tmp_path, "app.py", code)
        findings = check_ai_logging_insufficient(tmp_path)
        _assert_finding(
            findings, check_id="code-ai-logging-insufficient", severity=Severity.MEDIUM
        )

    def test_no_finding_with_logging(self, tmp_path):
        code = '''logger.info("Calling AI model")
response = client.chat.completions.create(
    model="gpt-4", messages=[]
)
logger.info(f"AI response: {response.id}")
return response
'''
        write_file(tmp_path, "app.py", code)
        findings = check_ai_logging_insufficient(tmp_path)
        assert len(findings) == 0

    def test_no_finding_without_ai_call(self, tmp_path):
        code = "x = 1 + 2\nprint(x)\n"
        write_file(tmp_path, "app.py", code)
        findings = check_ai_logging_insufficient(tmp_path)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# MEDIUM: check_outdated_ai_sdk
# ---------------------------------------------------------------------------


class TestCheckOutdatedAiSdk:
    """Test detection of vulnerable AI SDK versions."""

    def test_detects_vulnerable_langchain(self, tmp_path):
        write_file(tmp_path, "requirements.txt", "langchain==0.0.300\n")
        findings = check_outdated_ai_sdk(tmp_path)
        _assert_finding(findings, check_id="code-outdated-ai-sdk", severity=Severity.MEDIUM)
        assert "CVE" in findings[0].description

    def test_detects_vulnerable_openai(self, tmp_path):
        write_file(tmp_path, "requirements.txt", "openai==0.28.0\n")
        findings = check_outdated_ai_sdk(tmp_path)
        _assert_finding(findings, check_id="code-outdated-ai-sdk")

    def test_detects_vulnerable_transformers(self, tmp_path):
        write_file(tmp_path, "requirements.txt", "transformers==4.35.0\n")
        findings = check_outdated_ai_sdk(tmp_path)
        _assert_finding(findings, check_id="code-outdated-ai-sdk")

    def test_safe_version_no_finding(self, tmp_path):
        write_file(tmp_path, "requirements.txt", "langchain==0.1.0\nopenai==1.5.0\n")
        findings = check_outdated_ai_sdk(tmp_path)
        assert len(findings) == 0

    def test_no_dep_file_no_findings(self, tmp_path):
        write_file(tmp_path, "app.py", "print('hello')\n")
        findings = check_outdated_ai_sdk(tmp_path)
        assert len(findings) == 0

    def test_package_json_detection(self, tmp_path):
        write_file(
            tmp_path,
            "package.json",
            '{"dependencies": {"langchain": "0.0.300"}}',
        )
        findings = check_outdated_ai_sdk(tmp_path)
        _assert_finding(findings, check_id="code-outdated-ai-sdk")


# ---------------------------------------------------------------------------
# MEDIUM: check_training_data_unencrypted
# ---------------------------------------------------------------------------


class TestCheckTrainingDataUnencrypted:
    """Test detection of unencrypted training data sources."""

    def test_detects_http_data_fetch(self, tmp_path):
        code = '''import pandas as pd
data = pd.read_csv("http://example.com/training_data.csv")
model.train(data)
'''
        write_file(tmp_path, "train.py", code)
        findings = check_training_data_unencrypted(tmp_path)
        _assert_finding(
            findings, check_id="code-training-data-unencrypted", severity=Severity.MEDIUM
        )

    def test_no_finding_https(self, tmp_path):
        code = '''import pandas as pd
data = pd.read_csv("https://example.com/training_data.csv")
model.train(data)
'''
        write_file(tmp_path, "train.py", code)
        findings = check_training_data_unencrypted(tmp_path)
        assert len(findings) == 0

    def test_no_finding_clean_code(self, tmp_path):
        code = "x = 1 + 2\n"
        write_file(tmp_path, "app.py", code)
        findings = check_training_data_unencrypted(tmp_path)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# LOW: check_no_model_versioning
# ---------------------------------------------------------------------------


class TestCheckNoModelVersioning:
    """Test detection of unpinned model versions."""

    def test_detects_generic_gpt4(self, tmp_path):
        code = '''response = client.chat.completions.create(
    model="gpt-4",
    messages=[]
)
'''
        write_file(tmp_path, "app.py", code)
        findings = check_no_model_versioning(tmp_path)
        _assert_finding(findings, check_id="code-no-model-versioning", severity=Severity.LOW)

    def test_detects_generic_claude(self, tmp_path):
        code = '''response = client.messages.create(
    model="claude-3-opus",
    messages=[]
)
'''
        write_file(tmp_path, "app.py", code)
        findings = check_no_model_versioning(tmp_path)
        _assert_finding(findings, check_id="code-no-model-versioning")

    def test_no_finding_pinned_model(self, tmp_path):
        code = '''response = client.chat.completions.create(
    model="gpt-4-20240125",
    messages=[]
)
'''
        write_file(tmp_path, "app.py", code)
        findings = check_no_model_versioning(tmp_path)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# LOW: check_no_fallback_handler
# ---------------------------------------------------------------------------


class TestCheckNoFallbackHandler:
    """Test detection of AI API calls without error handling."""

    def test_detects_unhandled_call(self, tmp_path):
        code = '''response = client.chat.completions.create(
    model="gpt-4", messages=[]
)
return response
'''
        write_file(tmp_path, "app.py", code)
        findings = check_no_fallback_handler(tmp_path)
        _assert_finding(findings, check_id="code-no-fallback-handler", severity=Severity.LOW)

    def test_no_finding_with_try_except(self, tmp_path):
        code = '''try:
    response = client.chat.completions.create(
        model="gpt-4", messages=[]
    )
    return response
except Exception as e:
    return fallback_response()
'''
        write_file(tmp_path, "app.py", code)
        findings = check_no_fallback_handler(tmp_path)
        assert len(findings) == 0

    def test_no_finding_without_ai_call(self, tmp_path):
        code = "result = db.query('SELECT 1')\n"
        write_file(tmp_path, "app.py", code)
        findings = check_no_fallback_handler(tmp_path)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# Meta: ALL_CHECKS list
# ---------------------------------------------------------------------------


class TestAllChecks:
    """Verify the ALL_CHECKS aggregation."""

    def test_all_checks_count(self):
        assert len(ALL_CHECKS) == 20

    def test_all_checks_are_callable(self):
        for check_fn in ALL_CHECKS:
            assert callable(check_fn)

    def test_empty_repo_no_crashes(self, tmp_path):
        """All checks should handle an empty repo without errors."""
        for check_fn in ALL_CHECKS:
            findings = check_fn(tmp_path)
            assert isinstance(findings, list)

    def test_all_findings_are_fail_status(self, tmp_path):
        """Code checks should produce FAIL findings (security issues found)."""
        write_file(tmp_path, "app.py", 'api_key = "sk-abcdef1234567890abcdefghij"\n')
        findings = check_ai_api_key_exposed(tmp_path)
        for f in findings:
            assert f.status == ComplianceStatus.FAIL


# ---------------------------------------------------------------------------
# MCP: check_mcp_server_auth
# ---------------------------------------------------------------------------


class TestCheckMCPServerAuth:
    """Test detection of MCP servers without authentication."""

    def test_detects_mcp_server_no_auth(self, tmp_path):
        write_file(
            tmp_path,
            "server.py",
            (
                "from mcp.server import McpServer\n"
                "from mcp.server.sse import SseServerTransport\n"
                "server = McpServer('my-server')\n"
                "@server.tool()\n"
                "def fetch_data(url: str):\n"
                "    return requests.get(url).text\n"
            ),
        )
        findings = check_mcp_server_auth(tmp_path)
        _assert_finding(findings, check_id="code-mcp-server-auth")

    def test_detects_stdio_transport(self, tmp_path):
        write_file(
            tmp_path,
            "server.py",
            (
                "from mcp.server import McpServer\n"
                "from mcp.server.stdio import StdioServerTransport\n"
                "server = McpServer('local-server')\n"
                "@server.tool()\n"
                "def read_file(path: str):\n"
                "    return open(path).read()\n"
            ),
        )
        findings = check_mcp_server_auth(tmp_path)
        _assert_finding(
            findings, check_id="code-mcp-server-auth", severity=Severity.MEDIUM
        )

    def test_clean_mcp_server_with_auth(self, tmp_path):
        write_file(
            tmp_path,
            "server.py",
            (
                "from mcp.server import McpServer\n"
                "from mcp.server.sse import SseServerTransport\n"
                "server = McpServer('secure-server')\n"
                "auth = BearerTokenAuth(token=os.environ['MCP_TOKEN'])\n"
                "@server.tool()\n"
                "def safe_tool(query: str):\n"
                "    return db.query(query)\n"
            ),
        )
        findings = check_mcp_server_auth(tmp_path)
        assert len(findings) == 0

    def test_no_mcp_code_no_findings(self, tmp_path):
        write_file(tmp_path, "app.py", "import flask\napp = flask.Flask(__name__)\n")
        findings = check_mcp_server_auth(tmp_path)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# MCP: check_mcp_tool_scope
# ---------------------------------------------------------------------------


class TestCheckMCPToolScope:
    """Test detection of overprivileged MCP tools."""

    def test_detects_subprocess_in_mcp_tool(self, tmp_path):
        write_file(
            tmp_path,
            "server.py",
            (
                "from mcp.server import McpServer\n"
                "server = McpServer('shell-server')\n"
                "@server.tool()\n"
                "def run_command(cmd: str):\n"
                "    return subprocess.run(cmd, shell=True, capture_output=True)\n"
            ),
        )
        findings = check_mcp_tool_scope(tmp_path)
        _assert_finding(
            findings, check_id="code-mcp-tool-scope", severity=Severity.HIGH
        )

    def test_detects_eval_in_mcp_tool(self, tmp_path):
        write_file(
            tmp_path,
            "server.py",
            (
                "from mcp.server import McpServer\n"
                "server = McpServer('eval-server')\n"
                "@server.tool()\n"
                "def evaluate(expression: str):\n"
                "    return eval(expression)\n"
            ),
        )
        findings = check_mcp_tool_scope(tmp_path)
        _assert_finding(findings, check_id="code-mcp-tool-scope")

    def test_clean_mcp_tool(self, tmp_path):
        write_file(
            tmp_path,
            "server.py",
            (
                "from mcp.server import McpServer\n"
                "server = McpServer('safe-server')\n"
                "@server.tool()\n"
                "def lookup(term: str):\n"
                "    return dictionary.get(term, 'Not found')\n"
            ),
        )
        findings = check_mcp_tool_scope(tmp_path)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# MCP: check_mcp_input_validation
# ---------------------------------------------------------------------------


class TestCheckMCPInputValidation:
    """Test detection of MCP tools without input validation."""

    def test_detects_kwargs_tool(self, tmp_path):
        write_file(
            tmp_path,
            "server.py",
            (
                "from mcp.server import McpServer\n"
                "server = McpServer('untyped-server')\n"
                "@server.tool()\n"
                "def process(**kwargs):\n"
                "    return str(kwargs)\n"
            ),
        )
        findings = check_mcp_input_validation(tmp_path)
        _assert_finding(findings, check_id="code-mcp-input-validation")

    def test_clean_typed_tool(self, tmp_path):
        write_file(
            tmp_path,
            "server.py",
            (
                "from mcp.server import McpServer\n"
                "server = McpServer('typed-server')\n"
                "@server.tool()\n"
                "def search(query: str, limit: int = 10):\n"
                "    return db.search(query, limit)\n"
            ),
        )
        findings = check_mcp_input_validation(tmp_path)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# A2A: check_a2a_agent_auth
# ---------------------------------------------------------------------------


class TestCheckA2AAgentAuth:
    """Test detection of A2A agents without authentication."""

    def test_detects_null_auth_in_agent_card(self, tmp_path):
        write_file(
            tmp_path,
            "agent_config.py",
            (
                "from a2a.server import A2AServer\n"
                "agent_card = {\n"
                '    "name": "my-agent",\n'
                '    "authentication": None,\n'
                '    "skills": ["summarize", "translate"],\n'
                "}\n"
            ),
        )
        findings = check_a2a_agent_auth(tmp_path)
        _assert_finding(
            findings, check_id="code-a2a-agent-auth", severity=Severity.HIGH
        )

    def test_detects_empty_auth_list(self, tmp_path):
        write_file(
            tmp_path,
            "agent_config.json",
            (
                '{\n'
                '  "name": "my-agent",\n'
                '  "authentication": [],\n'
                '  "skills": ["search"]\n'
                '}\n'
            ),
        )
        # Need A2A pattern in the file
        write_file(
            tmp_path,
            "agent.py",
            (
                "from a2a.server import A2AServer\n"
                'card = {"authentication": []}\n'
            ),
        )
        findings = check_a2a_agent_auth(tmp_path)
        _assert_finding(findings, check_id="code-a2a-agent-auth")

    def test_clean_a2a_with_auth(self, tmp_path):
        write_file(
            tmp_path,
            "agent.py",
            (
                "from a2a.server import A2AServer\n"
                "agent_card = {\n"
                '    "name": "secure-agent",\n'
                '    "authentication": {"type": "oauth2"},\n'
                '    "skills": ["search"],\n'
                "}\n"
            ),
        )
        findings = check_a2a_agent_auth(tmp_path)
        assert len(findings) == 0

    def test_no_a2a_code_no_findings(self, tmp_path):
        write_file(tmp_path, "app.py", "import flask\n")
        findings = check_a2a_agent_auth(tmp_path)
        assert len(findings) == 0


# ---------------------------------------------------------------------------
# A2A: check_a2a_delegation_scope
# ---------------------------------------------------------------------------


class TestCheckA2ADelegationScope:
    """Test detection of unrestricted A2A task delegation."""

    def test_detects_unscoped_delegation(self, tmp_path):
        write_file(
            tmp_path,
            "orchestrator.py",
            (
                "from a2a.client import A2AClient\n"
                "client = A2AClient('http://agent-b')\n"
                "def process_request(user_input):\n"
                "    result = client.send_task(user_input)\n"
                "    return result\n"
            ),
        )
        findings = check_a2a_delegation_scope(tmp_path)
        _assert_finding(findings, check_id="code-a2a-delegation-scope")

    def test_clean_delegation_with_scope(self, tmp_path):
        write_file(
            tmp_path,
            "orchestrator.py",
            (
                "from a2a.client import A2AClient\n"
                "client = A2AClient('http://agent-b')\n"
                "ALLOWED_CAPABILITIES = {'search', 'summarize'}\n"
                "def process_request(user_input):\n"
                "    if not check_scope(user_input, ALLOWED_CAPABILITIES):\n"
                "        raise PermissionError('Not allowed')\n"
                "    result = client.send_task(user_input)\n"
                "    return result\n"
            ),
        )
        findings = check_a2a_delegation_scope(tmp_path)
        assert len(findings) == 0
