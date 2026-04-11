"""Tests for Whitney regex pattern library.

Validates that all patterns correctly match real-world examples
and reject safe inputs — no mocking, pure regex validation.
"""

import pytest

from whitney.code.patterns import (
    AI_API_KEY_PATTERNS,
    AI_KEY_ASSIGNMENT_PATTERNS,
    ENV_AI_KEY_PATTERNS,
    PROMPT_ROLE_PATTERNS,
    USER_INPUT_PATTERNS,
    FSTRING_OR_FORMAT_PATTERN,
    META_PROMPT_PATTERNS,
    PII_PATTERNS,
    AI_SDK_IMPORT_PATTERNS,
    AI_API_CALL_PATTERNS,
    AI_RESPONSE_DIRECT_USE,
    DANGEROUS_TOOL_PATTERNS,
    AGENT_TOOL_DEFINITION_PATTERNS,
    VECTOR_DB_QUERY_PATTERNS,
    ACCESS_CONTROL_PATTERNS,
    RATE_LIMIT_PATTERNS,
    AUTH_DECORATOR_PATTERNS,
    ROUTE_PATTERNS,
    LOGGING_PATTERNS,
    GENERIC_MODEL_NAMES,
    PINNED_MODEL_PATTERN,
    VULNERABLE_SDK_VERSIONS,
    SOURCE_CODE_EXTENSIONS,
    CONFIG_EXTENSIONS,
    ALL_SCANNABLE_EXTENSIONS,
    EXCLUDED_PATH_SEGMENTS,
    KEY_SCAN_EXCLUDED_FILES,
    MAX_FILE_SIZE_BYTES,
)


# ---------------------------------------------------------------------------
# AI API Key Patterns
# ---------------------------------------------------------------------------


class TestAIAPIKeyPatterns:
    """Test AI API key detection patterns."""

    @pytest.mark.parametrize(
        "key,should_match",
        [
            ("sk-1234567890abcdefghijklmnopqrst", True),
            ("sk-abcDEF1234567890abcdefghij", True),
            ("sk-short", False),
            ("not-a-key-at-all", False),
        ],
    )
    def test_openai_key_pattern(self, key, should_match):
        pattern = AI_API_KEY_PATTERNS["openai"]
        assert bool(pattern.search(key)) == should_match

    @pytest.mark.parametrize(
        "key,should_match",
        [
            ("sk-ant-api03-xxxxxxxxxxxxxxxxxxxxxxxx", True),
            ("sk-ant-1234567890abcdefghij12", True),
            ("sk-ant-short", False),
            ("sk-not-anthropic-key", False),
        ],
    )
    def test_anthropic_key_pattern(self, key, should_match):
        pattern = AI_API_KEY_PATTERNS["anthropic"]
        assert bool(pattern.search(key)) == should_match

    @pytest.mark.parametrize(
        "key,should_match",
        [
            ("hf_ABCdefGHIjklMNOpqrSTUvwx", True),
            ("hf_1234567890123456789012345", True),
            ("hf_short", False),
            ("not_a_hf_token", False),
        ],
    )
    def test_huggingface_key_pattern(self, key, should_match):
        pattern = AI_API_KEY_PATTERNS["huggingface"]
        assert bool(pattern.search(key)) == should_match


class TestAIKeyAssignmentPatterns:
    """Test hardcoded key assignment detection."""

    @pytest.mark.parametrize(
        "code,should_match",
        [
            ('OPENAI_API_KEY = "sk-abcDEF1234567890abcdefghij"', True),
            ('ANTHROPIC_API_KEY = "sk-ant-api03-xxxxxxxxxxxxxxxx"', True),
            ('api_key = "sk-abcDEF1234567890abcdefghij"', True),
            ('api_key = "sk-ant-api03-xxxxxxxxxxxxxxxx"', True),
            ('api_key = os.environ["OPENAI_API_KEY"]', False),
            ("api_key = get_secret()", False),
        ],
    )
    def test_key_assignment_patterns(self, code, should_match):
        matched = any(p.search(code) for p in AI_KEY_ASSIGNMENT_PATTERNS)
        assert matched == should_match


class TestEnvAIKeyPatterns:
    """Test .env file key detection."""

    @pytest.mark.parametrize(
        "line,should_match",
        [
            ("OPENAI_API_KEY=sk-proj-abc123", True),
            ("ANTHROPIC_API_KEY=sk-ant-api03-xxx", True),
            ("MY_API_KEY=sk-1234567890abcdefghij", True),
            ("DATABASE_URL=postgres://localhost", False),
            ("# OPENAI_API_KEY=commented_out", False),
        ],
    )
    def test_env_key_patterns(self, line, should_match):
        matched = any(p.search(line) for p in ENV_AI_KEY_PATTERNS)
        assert matched == should_match


# ---------------------------------------------------------------------------
# Prompt Patterns
# ---------------------------------------------------------------------------


class TestPromptRolePatterns:
    """Test LLM prompt role detection."""

    @pytest.mark.parametrize(
        "code,should_match",
        [
            ('"role": "system"', True),
            ("'role': 'user'", True),
            ('role="assistant"', True),
            ("SystemMessage(", True),
            ("HumanMessage(", True),
            ("ChatPromptTemplate", True),
            ("# just a comment about roles", False),
        ],
    )
    def test_role_patterns(self, code, should_match):
        matched = any(p.search(code) for p in PROMPT_ROLE_PATTERNS)
        assert matched == should_match


class TestUserInputPatterns:
    """Test user input source detection."""

    @pytest.mark.parametrize(
        "code,should_match",
        [
            ('request.json["message"]', True),
            ("request.body", True),
            ("input()", True),
            ("sys.argv", True),
            ("req.body", True),
            ("params[0]", True),
            ("request.GET", True),
            ("hardcoded_string = 'hello'", False),
        ],
    )
    def test_user_input_patterns(self, code, should_match):
        matched = any(p.search(code) for p in USER_INPUT_PATTERNS)
        assert matched == should_match


class TestFstringPattern:
    """Test f-string / format detection."""

    @pytest.mark.parametrize(
        "code,should_match",
        [
            ('f"Hello {name}"', True),
            ('"Hello {}".format(name)', True),
            ('"Hello %s" % (name,)', True),
            ('"Hello world"', False),
        ],
    )
    def test_fstring_pattern(self, code, should_match):
        assert bool(FSTRING_OR_FORMAT_PATTERN.search(code)) == should_match


class TestMetaPromptPatterns:
    """Test system prompt keyword detection."""

    @pytest.mark.parametrize(
        "text,should_match",
        [
            ('"You are a helpful assistant"', True),
            ('"Your role is to assist users"', True),
            ('"Instructions: Follow these steps"', False),  # tightened — too generic
            ('"Your task is to classify text"', True),
            ('"Hello world"', False),
        ],
    )
    def test_meta_prompt_patterns(self, text, should_match):
        matched = any(p.search(text) for p in META_PROMPT_PATTERNS)
        assert matched == should_match


# ---------------------------------------------------------------------------
# PII Patterns
# ---------------------------------------------------------------------------


class TestPIIPatterns:
    """Test PII detection patterns with realistic examples."""

    @pytest.mark.parametrize(
        "text,should_match",
        [
            ("user@example.com", True),
            ("jane.doe+tag@company.co.uk", True),
            ("not-an-email", False),
        ],
    )
    def test_email_pattern(self, text, should_match):
        assert bool(PII_PATTERNS["email"].search(text)) == should_match

    @pytest.mark.parametrize(
        "text,should_match",
        [
            ("123-45-6789", True),
            ("000-00-0000", True),
            ("12345-6789", False),
            ("12-345-6789", False),
        ],
    )
    def test_ssn_pattern(self, text, should_match):
        assert bool(PII_PATTERNS["ssn"].search(text)) == should_match

    @pytest.mark.parametrize(
        "text,should_match",
        [
            ("4111 1111 1111 1111", True),
            ("4111-1111-1111-1111", True),
            ("4111111111111111", True),
            ("411111", False),
        ],
    )
    def test_credit_card_pattern(self, text, should_match):
        assert bool(PII_PATTERNS["credit_card"].search(text)) == should_match

    @pytest.mark.parametrize(
        "text,should_match",
        [
            ("(555) 123-4567", True),
            ("555-123-4567", True),
            ("+1 555 123 4567", True),
            ("12345", False),
        ],
    )
    def test_phone_pattern(self, text, should_match):
        assert bool(PII_PATTERNS["phone"].search(text)) == should_match


# ---------------------------------------------------------------------------
# Dangerous Tool Patterns
# ---------------------------------------------------------------------------


class TestDangerousToolPatterns:
    """Test detection of dangerous operations in AI agent context."""

    @pytest.mark.parametrize(
        "code,should_match",
        [
            ("os.system('ls')", True),
            ("subprocess.run(['cmd'])", True),
            ("subprocess.Popen(['cmd'])", True),
            ("exec(user_code)", True),
            ("eval(expression)", True),
            ("shutil.rmtree(path)", True),
            ("requests.post(url)", True),
            ("cursor.execute(sql)", True),
            ("print('hello')", False),
            ("os.path.exists(path)", False),
        ],
    )
    def test_dangerous_tool_patterns(self, code, should_match):
        matched = any(p.search(code) for p in DANGEROUS_TOOL_PATTERNS)
        assert matched == should_match


# ---------------------------------------------------------------------------
# SDK / API Patterns
# ---------------------------------------------------------------------------


class TestAISDKImportPatterns:
    """Test AI SDK import detection."""

    @pytest.mark.parametrize(
        "code,should_match",
        [
            ("import openai", True),
            ("from anthropic import Anthropic", True),
            ("from langchain import LLMChain", True),
            ("from transformers import pipeline", True),
            ('require("openai")', True),
            ("import json", False),
            ("import requests", False),
        ],
    )
    def test_sdk_import_patterns(self, code, should_match):
        matched = any(p.search(code) for p in AI_SDK_IMPORT_PATTERNS)
        assert matched == should_match


class TestAIAPICallPatterns:
    """Test AI API call detection."""

    @pytest.mark.parametrize(
        "code,should_match",
        [
            ("client.chat.completions.create(", True),
            ("client.messages.create(", True),
            ("model.generate(", True),
            ("client.invoke(", True),
            ("requests.get(url)", False),
        ],
    )
    def test_api_call_patterns(self, code, should_match):
        matched = any(p.search(code) for p in AI_API_CALL_PATTERNS)
        assert matched == should_match


class TestAIResponseDirectUse:
    """Test unvalidated AI response usage detection."""

    @pytest.mark.parametrize(
        "code,should_match",
        [
            ("response.choices[0].message.content", True),
            ("response.content[0].text", True),
            ("result.content", True),
            ("response.status_code", False),
        ],
    )
    def test_response_patterns(self, code, should_match):
        matched = any(p.search(code) for p in AI_RESPONSE_DIRECT_USE)
        assert matched == should_match


# ---------------------------------------------------------------------------
# Model Version Patterns
# ---------------------------------------------------------------------------


class TestModelVersionPatterns:
    """Test generic vs pinned model name detection."""

    @pytest.mark.parametrize(
        "code,should_match",
        [
            ('model="gpt-4"', True),
            ('model="gpt-3.5-turbo"', True),
            ('model="claude-3-opus"', True),
            ('model="gpt-4o"', True),
        ],
    )
    def test_generic_model_names(self, code, should_match):
        matched = any(p.search(code) for p in GENERIC_MODEL_NAMES)
        assert matched == should_match

    @pytest.mark.parametrize(
        "code,should_match",
        [
            ('model="gpt-4-0125"', True),
            ('model="gpt-4-20240125"', True),
            ('model="claude-3-opus-20240229"', True),
        ],
    )
    def test_pinned_model_pattern(self, code, should_match):
        assert bool(PINNED_MODEL_PATTERN.search(code)) == should_match


# ---------------------------------------------------------------------------
# File Extension Sets
# ---------------------------------------------------------------------------


class TestFileExtensions:
    """Test file extension set contents."""

    def test_source_code_extensions(self):
        assert ".py" in SOURCE_CODE_EXTENSIONS
        assert ".js" in SOURCE_CODE_EXTENSIONS
        assert ".ts" in SOURCE_CODE_EXTENSIONS
        assert ".go" in SOURCE_CODE_EXTENSIONS
        assert ".java" in SOURCE_CODE_EXTENSIONS
        assert ".txt" not in SOURCE_CODE_EXTENSIONS

    def test_config_extensions(self):
        assert ".yaml" in CONFIG_EXTENSIONS
        assert ".json" in CONFIG_EXTENSIONS
        assert ".toml" in CONFIG_EXTENSIONS
        assert ".py" not in CONFIG_EXTENSIONS

    def test_all_scannable_includes_both(self):
        assert SOURCE_CODE_EXTENSIONS.issubset(ALL_SCANNABLE_EXTENSIONS)
        assert CONFIG_EXTENSIONS.issubset(ALL_SCANNABLE_EXTENSIONS)
        assert ".env" in ALL_SCANNABLE_EXTENSIONS
        assert ".md" in ALL_SCANNABLE_EXTENSIONS

    def test_excluded_path_segments(self):
        assert "node_modules" in EXCLUDED_PATH_SEGMENTS
        assert ".git" in EXCLUDED_PATH_SEGMENTS
        assert "__pycache__" in EXCLUDED_PATH_SEGMENTS
        assert ".venv" in EXCLUDED_PATH_SEGMENTS
        assert "src" not in EXCLUDED_PATH_SEGMENTS

    def test_key_scan_excluded_files(self):
        assert ".env.example" in KEY_SCAN_EXCLUDED_FILES
        assert "README.md" in KEY_SCAN_EXCLUDED_FILES
        assert ".env" not in KEY_SCAN_EXCLUDED_FILES

    def test_max_file_size(self):
        assert MAX_FILE_SIZE_BYTES == 1_048_576


# ---------------------------------------------------------------------------
# Vulnerable SDK Versions
# ---------------------------------------------------------------------------


class TestVulnerableSDKVersions:
    """Test the vulnerable SDK version database."""

    def test_langchain_entry(self):
        assert "langchain" in VULNERABLE_SDK_VERSIONS
        entry = VULNERABLE_SDK_VERSIONS["langchain"][0]
        assert entry["constraint"] == "< 0.0.325"
        assert "CVE" in entry["cve"]

    def test_openai_entry(self):
        assert "openai" in VULNERABLE_SDK_VERSIONS
        entry = VULNERABLE_SDK_VERSIONS["openai"][0]
        assert entry["constraint"] == "< 1.0.0"

    def test_transformers_entry(self):
        assert "transformers" in VULNERABLE_SDK_VERSIONS
        entry = VULNERABLE_SDK_VERSIONS["transformers"][0]
        assert entry["constraint"] == "< 4.36.0"
        assert "CVE" in entry["cve"]


# ---------------------------------------------------------------------------
# Route & Auth Patterns
# ---------------------------------------------------------------------------


class TestRoutePatterns:
    """Test web framework route detection."""

    @pytest.mark.parametrize(
        "code,should_match",
        [
            ('@app.route("/chat")', True),
            ('@app.post("/api/chat")', True),
            ('@router.get("/health")', True),
            ('app.get("/api/v1/chat",', True),
            ("some_function()", False),
        ],
    )
    def test_route_patterns(self, code, should_match):
        matched = any(p.search(code) for p in ROUTE_PATTERNS)
        assert matched == should_match


class TestAuthDecoratorPatterns:
    """Test authentication decorator detection."""

    @pytest.mark.parametrize(
        "code,should_match",
        [
            ("@login_required", True),
            ("@jwt_required", True),
            ("@requires_auth", True),
            ("Depends(get_current_user)", True),
            ("verify_token(request)", True),
            ("@app.route", False),
        ],
    )
    def test_auth_patterns(self, code, should_match):
        matched = any(p.search(code) for p in AUTH_DECORATOR_PATTERNS)
        assert matched == should_match


class TestRateLimitPatterns:
    """Test rate limiting detection."""

    @pytest.mark.parametrize(
        "code,should_match",
        [
            ("@rate_limit", True),
            ("@limiter.limit", True),
            ("RateLimiter(", True),
            ("Retry(", True),
            ("backoff.expo", True),
            ("time.sleep(1)", False),
        ],
    )
    def test_rate_limit_patterns(self, code, should_match):
        matched = any(p.search(code) for p in RATE_LIMIT_PATTERNS)
        assert matched == should_match


class TestLoggingPatterns:
    """Test logging detection."""

    @pytest.mark.parametrize(
        "code,should_match",
        [
            ("logger.info('called AI')", True),
            ("logging.warning('issue')", True),
            ("print('debug output')", True),
            ("console.log('response')", True),
            ("sentry_sdk.capture_exception(e)", True),
            ("x = 1 + 2", False),
        ],
    )
    def test_logging_patterns(self, code, should_match):
        matched = any(p.search(code) for p in LOGGING_PATTERNS)
        assert matched == should_match
