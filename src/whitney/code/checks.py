"""AI code security check functions.

Each function scans a repository for a specific class of AI security issues
and returns a list of Finding objects.
"""

from __future__ import annotations

import re
from pathlib import Path

from shasta.evidence.models import (
    CheckDomain,
    CloudProvider,
    ComplianceStatus,
    Finding,
    Severity,
)
from whitney.code.patterns import (
    A2A_NO_AUTH_PATTERNS,
    A2A_PATTERNS,
    ACCESS_CONTROL_PATTERNS,
    AGENT_TOOL_DEFINITION_PATTERNS,
    AI_API_CALL_PATTERNS,
    AI_API_KEY_PATTERNS,
    AI_KEY_ASSIGNMENT_PATTERNS,
    AI_RESPONSE_DIRECT_USE,
    ALL_SCANNABLE_EXTENSIONS,
    AUTH_DECORATOR_PATTERNS,
    DANGEROUS_TOOL_PATTERNS,
    ENV_AI_KEY_PATTERNS,
    ERROR_HANDLING_PATTERNS,
    EXCLUDED_PATH_SEGMENTS,
    FSTRING_OR_FORMAT_PATTERN,
    GENERIC_MODEL_NAMES,
    KEY_SCAN_EXCLUDED_FILES,
    LOGGING_PATTERNS,
    MAX_FILE_SIZE_BYTES,
    MCP_DANGEROUS_TOOL_PATTERNS,
    MCP_NO_AUTH_PATTERNS,
    MCP_NO_SCHEMA_PATTERNS,
    MCP_SERVER_PATTERNS,
    META_PROMPT_PATTERNS,
    MODEL_INFERENCE_PATTERNS,
    PII_PATTERNS,
    PROMPT_ROLE_PATTERNS,
    RATE_LIMIT_PATTERNS,
    ROUTE_PATTERNS,
    SOURCE_CODE_EXTENSIONS,
    TRAINING_CONTEXT_PATTERNS,
    UNENCRYPTED_DATA_PATTERNS,
    USER_INPUT_PATTERNS,
    VECTOR_DB_QUERY_PATTERNS,
    VULNERABLE_SDK_VERSIONS,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _repo_name(repo_path: Path) -> str:
    """Derive a short repo name from its path."""
    return repo_path.name


def _iter_files(
    repo_path: Path,
    extensions: frozenset[str] | None = None,
    include_hidden_env: bool = False,
) -> list[Path]:
    """Walk *repo_path* and yield files matching *extensions*.

    Skips binary-looking files, files > 1 MB, and common vendor directories.
    If *include_hidden_env* is True, also yield ``.env`` files.
    """
    if extensions is None:
        extensions = ALL_SCANNABLE_EXTENSIONS
    files: list[Path] = []
    for path in repo_path.rglob("*"):
        if not path.is_file():
            continue
        # Skip excluded directories
        if any(seg in path.parts for seg in EXCLUDED_PATH_SEGMENTS):
            continue
        # Skip large files
        try:
            if path.stat().st_size > MAX_FILE_SIZE_BYTES:
                continue
        except OSError:
            continue
        suffix = path.suffix.lower()
        if suffix in extensions:
            files.append(path)
        elif (
            include_hidden_env
            and path.name.startswith(".env")
            and not path.name.endswith(".example")
        ):
            files.append(path)
    return files


def _read_file(path: Path) -> str | None:
    """Read file contents, returning None on encoding errors."""
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _get_lines(content: str) -> list[str]:
    """Split content into lines."""
    return content.splitlines()


def _snippet(lines: list[str], line_idx: int, context: int = 3) -> str:
    """Return a code snippet around *line_idx* with *context* lines of padding."""
    start = max(0, line_idx - context)
    end = min(len(lines), line_idx + context + 1)
    snippet_lines: list[str] = []
    for i in range(start, end):
        marker = ">>> " if i == line_idx else "    "
        snippet_lines.append(f"{marker}{i + 1}: {lines[i]}")
    return "\n".join(snippet_lines)


def _make_finding(
    *,
    check_id: str,
    title: str,
    description: str,
    severity: Severity,
    repo_path: Path,
    file_path: Path,
    line_number: int,
    matched_pattern: str,
    code_snippet: str,
    remediation: str = "",
    soc2_controls: list[str] | None = None,
) -> Finding:
    """Create a standardised Finding for a code security issue."""
    rel_path = str(file_path.relative_to(repo_path))
    return Finding(
        check_id=check_id,
        title=title,
        description=description,
        severity=severity,
        status=ComplianceStatus.FAIL,
        domain=CheckDomain.AI_GOVERNANCE,
        cloud_provider=CloudProvider.AWS,
        resource_type="Code::Repository::File",
        resource_id=f"{_repo_name(repo_path)}:{rel_path}:{line_number}",
        region="code",
        account_id="code-scan",
        remediation=remediation,
        soc2_controls=soc2_controls or [],
        details={
            "file_path": rel_path,
            "line_number": line_number,
            "matched_pattern": matched_pattern,
            "code_snippet": code_snippet,
        },
    )


def _search_files(
    repo_path: Path,
    patterns: list[re.Pattern[str]],
    extensions: frozenset[str] | None = None,
    *,
    exclude_names: frozenset[str] | None = None,
) -> list[tuple[Path, int, str, str]]:
    """Search files for any of *patterns*, returning (path, line_no, match, snippet)."""
    results: list[tuple[Path, int, str, str]] = []
    for fpath in _iter_files(repo_path, extensions):
        if exclude_names and fpath.name in exclude_names:
            continue
        content = _read_file(fpath)
        if content is None:
            continue
        lines = _get_lines(content)
        for idx, line in enumerate(lines):
            for pat in patterns:
                m = pat.search(line)
                if m:
                    results.append((fpath, idx + 1, m.group(), _snippet(lines, idx)))
                    break  # one match per line is enough
    return results


# ---------------------------------------------------------------------------
# CRITICAL checks
# ---------------------------------------------------------------------------


def check_ai_api_key_exposed(repo_path: Path) -> list[Finding]:
    """Detect AI API keys hardcoded in source files."""
    repo_path = Path(repo_path)
    findings: list[Finding] = []

    # Combine the targeted key patterns (the generic AI_API_KEY_PATTERNS
    # are too noisy on their own — we rely on the assignment-style patterns).
    all_patterns = list(AI_KEY_ASSIGNMENT_PATTERNS) + [
        AI_API_KEY_PATTERNS["openai"],
        AI_API_KEY_PATTERNS["anthropic"],
        AI_API_KEY_PATTERNS["huggingface"],
    ]

    for fpath in _iter_files(repo_path, SOURCE_CODE_EXTENSIONS):
        # Exclude known-safe files
        if fpath.name in KEY_SCAN_EXCLUDED_FILES:
            continue
        rel = str(fpath.relative_to(repo_path))
        # Exclude docs / test fixtures with fake keys
        lower_rel = rel.lower()
        if any(seg in lower_rel for seg in ("readme", "docs/", "doc/", "test_fixture", "testdata")):
            continue

        content = _read_file(fpath)
        if content is None:
            continue
        lines = _get_lines(content)
        for idx, line in enumerate(lines):
            # Skip comments
            stripped = line.strip()
            if stripped.startswith("#") or stripped.startswith("//"):
                continue
            for pat in all_patterns:
                m = pat.search(line)
                if m:
                    findings.append(
                        _make_finding(
                            check_id="code-ai-api-key-exposed",
                            title=f"AI API key exposed in {fpath.name}",
                            description=(
                                f"A potential AI API key was found hardcoded "
                                f"in source code at line {idx + 1} of {rel}."
                            ),
                            severity=Severity.CRITICAL,
                            repo_path=repo_path,
                            file_path=fpath,
                            line_number=idx + 1,
                            matched_pattern=pat.pattern,
                            code_snippet=_snippet(lines, idx),
                            remediation=(
                                "Move the key to an environment variable or "
                                "secrets manager. Rotate the exposed key immediately."
                            ),
                            soc2_controls=["CC6.1"],
                        )
                    )
                    break  # one finding per line
    return findings


def check_ai_key_in_env_file(repo_path: Path) -> list[Finding]:
    """Detect committed .env files containing AI API keys."""
    repo_path = Path(repo_path)
    findings: list[Finding] = []

    # Check if .gitignore mentions .env
    gitignore = repo_path / ".gitignore"
    gitignore_content = ""
    if gitignore.is_file():
        gitignore_content = _read_file(gitignore) or ""

    for fpath in repo_path.rglob(".env*"):
        if not fpath.is_file():
            continue
        if any(seg in fpath.parts for seg in EXCLUDED_PATH_SEGMENTS):
            continue
        # Skip example/template files
        if fpath.name in KEY_SCAN_EXCLUDED_FILES:
            continue
        if fpath.suffix in (".example", ".sample", ".template"):
            continue

        # If .env is in gitignore, it's likely not committed — but the file
        # exists on disk, so still flag it as informational. We flag as
        # CRITICAL only when .env does NOT appear in .gitignore.
        env_in_gitignore = ".env" in gitignore_content

        content = _read_file(fpath)
        if content is None:
            continue
        lines = _get_lines(content)
        for idx, line in enumerate(lines):
            for pat in ENV_AI_KEY_PATTERNS:
                m = pat.search(line)
                if m:
                    sev = Severity.MEDIUM if env_in_gitignore else Severity.CRITICAL
                    rel = str(fpath.relative_to(repo_path))
                    findings.append(
                        _make_finding(
                            check_id="code-ai-key-in-env-file",
                            title=f"AI API key found in {fpath.name}",
                            description=(
                                f"An AI API key is present in {rel} at line {idx + 1}. "
                                + (
                                    "The file appears in .gitignore."
                                    if env_in_gitignore
                                    else "The file is NOT in .gitignore and may be committed."
                                )
                            ),
                            severity=sev,
                            repo_path=repo_path,
                            file_path=fpath,
                            line_number=idx + 1,
                            matched_pattern=pat.pattern,
                            code_snippet=_snippet(lines, idx),
                            remediation=(
                                "Add .env to .gitignore. Use a secrets "
                                "manager for production deployments."
                            ),
                            soc2_controls=["CC6.1"],
                        )
                    )
                    break
    return findings


# ---------------------------------------------------------------------------
# HIGH checks
# ---------------------------------------------------------------------------


def check_prompt_injection_risk(repo_path: Path) -> list[Finding]:
    """Detect user input interpolated into AI prompts."""
    repo_path = Path(repo_path)
    findings: list[Finding] = []

    for fpath in _iter_files(repo_path, SOURCE_CODE_EXTENSIONS):
        content = _read_file(fpath)
        if content is None:
            continue
        lines = _get_lines(content)

        # Scan with a sliding window — look for regions where user input,
        # f-string formatting, and prompt roles all appear within a 15-line window.
        window = 15
        for idx in range(len(lines)):
            chunk = "\n".join(lines[max(0, idx - window) : idx + 1])

            has_user_input = any(p.search(chunk) for p in USER_INPUT_PATTERNS)
            has_format = FSTRING_OR_FORMAT_PATTERN.search(chunk) is not None
            has_role = any(p.search(chunk) for p in PROMPT_ROLE_PATTERNS)

            if has_user_input and has_format and has_role:
                # Only flag the line that has the formatting
                if FSTRING_OR_FORMAT_PATTERN.search(lines[idx]):
                    rel = str(fpath.relative_to(repo_path))
                    findings.append(
                        _make_finding(
                            check_id="code-prompt-injection-risk",
                            title=f"Prompt injection risk in {fpath.name}",
                            description=(
                                f"User input appears to be interpolated "
                                f"into an AI prompt near line {idx + 1} "
                                f"of {rel}. This may allow prompt injection."
                            ),
                            severity=Severity.HIGH,
                            repo_path=repo_path,
                            file_path=fpath,
                            line_number=idx + 1,
                            matched_pattern="user_input + f-string/format + prompt role",
                            code_snippet=_snippet(lines, idx),
                            remediation=(
                                "Sanitise user input before including in "
                                "prompts. Use structured message APIs "
                                "rather than string interpolation."
                            ),
                            soc2_controls=["CC6.1", "CC7.2"],
                        )
                    )
    return findings


def check_no_output_validation(repo_path: Path) -> list[Finding]:
    """Detect LLM responses used without validation or sanitisation."""
    repo_path = Path(repo_path)
    findings: list[Finding] = []

    for fpath in _iter_files(repo_path, SOURCE_CODE_EXTENSIONS):
        content = _read_file(fpath)
        if content is None:
            continue
        lines = _get_lines(content)
        for idx, line in enumerate(lines):
            for pat in AI_RESPONSE_DIRECT_USE:
                if pat.search(line):
                    # Check if surrounding lines show any validation
                    window_start = max(0, idx - 5)
                    window_end = min(len(lines), idx + 6)
                    window = "\n".join(lines[window_start:window_end])

                    validation_indicators = [
                        "sanitize",
                        "validate",
                        "filter",
                        "escape",
                        "strip",
                        "clean",
                        "check",
                        "verify",
                        "parse",
                        "json.loads",
                        "pydantic",
                        "schema",
                    ]
                    has_validation = any(v in window.lower() for v in validation_indicators)

                    if not has_validation:
                        rel = str(fpath.relative_to(repo_path))
                        findings.append(
                            _make_finding(
                                check_id="code-no-output-validation",
                                title=f"Unvalidated LLM output in {fpath.name}",
                                description=(
                                    f"LLM response content is used without "
                                    f"apparent validation at line "
                                    f"{idx + 1} of {rel}."
                                ),
                                severity=Severity.HIGH,
                                repo_path=repo_path,
                                file_path=fpath,
                                line_number=idx + 1,
                                matched_pattern=pat.pattern,
                                code_snippet=_snippet(lines, idx),
                                remediation=(
                                    "Validate and sanitise LLM outputs "
                                    "before using them. Parse structured "
                                    "responses with Pydantic or JSON schema."
                                ),
                                soc2_controls=["CC7.2"],
                            )
                        )
                    break
    return findings


def check_pii_in_prompts(repo_path: Path) -> list[Finding]:
    """Detect PII patterns or database references in prompt strings."""
    repo_path = Path(repo_path)
    findings: list[Finding] = []

    for fpath in _iter_files(repo_path, SOURCE_CODE_EXTENSIONS):
        content = _read_file(fpath)
        if content is None:
            continue
        lines = _get_lines(content)
        for idx, line in enumerate(lines):
            # Only look in lines that appear to be part of prompts
            is_prompt_line = any(p.search(line) for p in PROMPT_ROLE_PATTERNS) or any(
                kw in line.lower()
                for kw in ("prompt", "system_message", "human_message", "messages")
            )
            if not is_prompt_line:
                continue

            for pii_name, pii_pat in PII_PATTERNS.items():
                m = pii_pat.search(line)
                if m:
                    rel = str(fpath.relative_to(repo_path))
                    findings.append(
                        _make_finding(
                            check_id="code-pii-in-prompts",
                            title=f"Potential {pii_name} in prompt ({fpath.name})",
                            description=(
                                f"A {pii_name} pattern was found in what "
                                f"appears to be an AI prompt at line "
                                f"{idx + 1} of {rel}."
                            ),
                            severity=Severity.HIGH,
                            repo_path=repo_path,
                            file_path=fpath,
                            line_number=idx + 1,
                            matched_pattern=pii_pat.pattern,
                            code_snippet=_snippet(lines, idx),
                            remediation=(
                                "Remove PII from prompts. Use anonymisation "
                                "before sending data to AI models."
                            ),
                            soc2_controls=["CC6.1", "P6.1"],
                        )
                    )
                    break

            # Also flag direct DB query references in prompt contexts
            db_patterns = [
                re.compile(r"(?:SELECT|INSERT|query)\s.*(?:FROM|INTO)\s", re.IGNORECASE),
                re.compile(r"\.find\(|\.find_one\(|\.aggregate\("),
                re.compile(r"user\.\w+|customer\.\w+|patient\.\w+"),
            ]
            for db_pat in db_patterns:
                m = db_pat.search(line)
                if m:
                    rel = str(fpath.relative_to(repo_path))
                    findings.append(
                        _make_finding(
                            check_id="code-pii-in-prompts",
                            title=f"Database reference in prompt ({fpath.name})",
                            description=(
                                f"A database query or user record reference "
                                f"appears in an AI prompt at line "
                                f"{idx + 1} of {rel}."
                            ),
                            severity=Severity.HIGH,
                            repo_path=repo_path,
                            file_path=fpath,
                            line_number=idx + 1,
                            matched_pattern=db_pat.pattern,
                            code_snippet=_snippet(lines, idx),
                            remediation=(
                                "Avoid passing raw database records to AI "
                                "models. Filter to only necessary fields."
                            ),
                            soc2_controls=["CC6.1", "P6.1"],
                        )
                    )
                    break
    return findings


def check_model_endpoint_public(repo_path: Path) -> list[Finding]:
    """Detect model inference endpoints without authentication."""
    repo_path = Path(repo_path)
    findings: list[Finding] = []

    for fpath in _iter_files(repo_path, SOURCE_CODE_EXTENSIONS):
        content = _read_file(fpath)
        if content is None:
            continue
        lines = _get_lines(content)

        for idx, line in enumerate(lines):
            # Look for route definitions
            is_route = any(p.search(line) for p in ROUTE_PATTERNS)
            if not is_route:
                continue

            # Check a window after the route for model inference
            window_end = min(len(lines), idx + 25)
            window_text = "\n".join(lines[idx:window_end])

            has_inference = any(p.search(window_text) for p in MODEL_INFERENCE_PATTERNS)
            if not has_inference:
                continue

            # Check for auth decorators in the lines above and the route line itself
            auth_window_start = max(0, idx - 5)
            auth_text = "\n".join(lines[auth_window_start:window_end])
            has_auth = any(p.search(auth_text) for p in AUTH_DECORATOR_PATTERNS)

            if not has_auth:
                rel = str(fpath.relative_to(repo_path))
                findings.append(
                    _make_finding(
                        check_id="code-model-endpoint-public",
                        title=f"Unauthenticated model endpoint in {fpath.name}",
                        description=(
                            f"A route serving model inference at line {idx + 1} of {rel} "
                            f"does not appear to have authentication."
                        ),
                        severity=Severity.HIGH,
                        repo_path=repo_path,
                        file_path=fpath,
                        line_number=idx + 1,
                        matched_pattern="route + model inference without auth",
                        code_snippet=_snippet(lines, idx),
                        remediation=(
                            "Add authentication middleware or decorators to AI model endpoints."
                        ),
                        soc2_controls=["CC6.1", "CC6.2"],
                    )
                )
    return findings


def check_agent_unrestricted_tools(repo_path: Path) -> list[Finding]:
    """Detect AI agent tool definitions with dangerous capabilities."""
    repo_path = Path(repo_path)
    findings: list[Finding] = []

    for fpath in _iter_files(repo_path, SOURCE_CODE_EXTENSIONS):
        content = _read_file(fpath)
        if content is None:
            continue
        lines = _get_lines(content)

        for idx, line in enumerate(lines):
            # Look for tool definitions
            is_tool_def = any(p.search(line) for p in AGENT_TOOL_DEFINITION_PATTERNS)
            if not is_tool_def:
                continue

            # Check surrounding context for dangerous patterns
            window_start = max(0, idx - 3)
            window_end = min(len(lines), idx + 20)
            window_text = "\n".join(lines[window_start:window_end])

            for danger_pat in DANGEROUS_TOOL_PATTERNS:
                m = danger_pat.search(window_text)
                if m:
                    rel = str(fpath.relative_to(repo_path))
                    findings.append(
                        _make_finding(
                            check_id="code-agent-unrestricted-tools",
                            title=f"Agent tool with dangerous capability in {fpath.name}",
                            description=(
                                f"An AI agent tool definition near line {idx + 1} of {rel} "
                                f"includes a dangerous operation: {m.group()}."
                            ),
                            severity=Severity.HIGH,
                            repo_path=repo_path,
                            file_path=fpath,
                            line_number=idx + 1,
                            matched_pattern=danger_pat.pattern,
                            code_snippet=_snippet(lines, idx),
                            remediation=(
                                "Restrict agent tool capabilities. Use "
                                "allowlists, sandboxing, and human-in-the-"
                                "loop for dangerous operations."
                            ),
                            soc2_controls=["CC6.1", "CC7.2"],
                        )
                    )
                    break
    return findings


# ---------------------------------------------------------------------------
# MEDIUM checks
# ---------------------------------------------------------------------------


def check_rag_no_access_control(repo_path: Path) -> list[Finding]:
    """Detect vector DB queries without user-level access filtering."""
    repo_path = Path(repo_path)
    findings: list[Finding] = []

    for fpath in _iter_files(repo_path, SOURCE_CODE_EXTENSIONS):
        content = _read_file(fpath)
        if content is None:
            continue
        lines = _get_lines(content)

        for idx, line in enumerate(lines):
            has_vector_query = any(p.search(line) for p in VECTOR_DB_QUERY_PATTERNS)
            if not has_vector_query:
                continue

            # Check surrounding context for access control
            window_start = max(0, idx - 10)
            window_end = min(len(lines), idx + 10)
            window_text = "\n".join(lines[window_start:window_end])

            has_access = any(p.search(window_text) for p in ACCESS_CONTROL_PATTERNS)
            if not has_access:
                rel = str(fpath.relative_to(repo_path))
                findings.append(
                    _make_finding(
                        check_id="code-rag-no-access-control",
                        title=f"RAG query without access control in {fpath.name}",
                        description=(
                            f"A vector database query at line {idx + 1} of {rel} does not appear "
                            f"to filter by user, tenant, or organisation."
                        ),
                        severity=Severity.MEDIUM,
                        repo_path=repo_path,
                        file_path=fpath,
                        line_number=idx + 1,
                        matched_pattern="vector_query without access_control",
                        code_snippet=_snippet(lines, idx),
                        remediation=(
                            "Add user-level or tenant-level metadata "
                            "filters to vector DB queries to prevent "
                            "cross-tenant data access."
                        ),
                        soc2_controls=["CC6.1", "CC6.3"],
                    )
                )
    return findings


def check_no_rate_limiting(repo_path: Path) -> list[Finding]:
    """Detect AI API usage without rate limiting."""
    repo_path = Path(repo_path)
    findings: list[Finding] = []

    for fpath in _iter_files(repo_path, SOURCE_CODE_EXTENSIONS):
        content = _read_file(fpath)
        if content is None:
            continue
        lines = _get_lines(content)

        # Check the whole file for rate limiting indicators
        has_rate_limit = any(p.search(content) for p in RATE_LIMIT_PATTERNS)
        if has_rate_limit:
            continue  # File has some rate limiting — skip

        for idx, line in enumerate(lines):
            has_ai_call = any(p.search(line) for p in AI_API_CALL_PATTERNS)
            if not has_ai_call:
                continue

            # Also check if this is within a route handler (public-facing)
            window_start = max(0, idx - 20)
            pre_context = "\n".join(lines[window_start:idx])
            in_route = any(p.search(pre_context) for p in ROUTE_PATTERNS)

            if in_route:
                rel = str(fpath.relative_to(repo_path))
                findings.append(
                    _make_finding(
                        check_id="code-no-rate-limiting",
                        title=f"AI API call without rate limiting in {fpath.name}",
                        description=(
                            f"An AI API call in a route handler at line {idx + 1} of {rel} "
                            f"has no apparent rate limiting, risking cost overruns and abuse."
                        ),
                        severity=Severity.MEDIUM,
                        repo_path=repo_path,
                        file_path=fpath,
                        line_number=idx + 1,
                        matched_pattern="ai_api_call in route without rate_limit",
                        code_snippet=_snippet(lines, idx),
                        remediation=(
                            "Add rate limiting to AI-serving endpoints "
                            "using slowapi, express-rate-limit, or a "
                            "custom token bucket."
                        ),
                        soc2_controls=["CC6.1"],
                    )
                )
    return findings


def check_meta_prompt_exposed(repo_path: Path) -> list[Finding]:
    """Detect system prompts that may be extractable by end users."""
    repo_path = Path(repo_path)
    findings: list[Finding] = []

    for fpath in _iter_files(repo_path, SOURCE_CODE_EXTENSIONS):
        content = _read_file(fpath)
        if content is None:
            continue
        lines = _get_lines(content)

        # Only flag files that also contain route definitions (user-facing)
        has_routes = any(p.search(content) for p in ROUTE_PATTERNS)
        if not has_routes:
            continue

        for idx, line in enumerate(lines):
            for pat in META_PROMPT_PATTERNS:
                m = pat.search(line)
                if m:
                    rel = str(fpath.relative_to(repo_path))
                    findings.append(
                        _make_finding(
                            check_id="code-meta-prompt-exposed",
                            title=f"System prompt may be extractable in {fpath.name}",
                            description=(
                                f"A system prompt with instructional "
                                f"language was found at line {idx + 1} "
                                f"of {rel}, in a file with route "
                                f"definitions. Users may extract it."
                            ),
                            severity=Severity.MEDIUM,
                            repo_path=repo_path,
                            file_path=fpath,
                            line_number=idx + 1,
                            matched_pattern=pat.pattern,
                            code_snippet=_snippet(lines, idx),
                            remediation=(
                                "Store system prompts in environment "
                                "variables or a config service, not "
                                "inline in route handlers."
                            ),
                            soc2_controls=["CC6.1"],
                        )
                    )
                    break
    return findings


def check_ai_logging_insufficient(repo_path: Path) -> list[Finding]:
    """Detect AI API calls without corresponding logging."""
    repo_path = Path(repo_path)
    findings: list[Finding] = []

    for fpath in _iter_files(repo_path, SOURCE_CODE_EXTENSIONS):
        content = _read_file(fpath)
        if content is None:
            continue
        lines = _get_lines(content)

        for idx, line in enumerate(lines):
            has_ai_call = any(p.search(line) for p in AI_API_CALL_PATTERNS)
            if not has_ai_call:
                continue

            # Check surrounding lines for logging
            window_start = max(0, idx - 5)
            window_end = min(len(lines), idx + 6)
            window_text = "\n".join(lines[window_start:window_end])

            has_logging = any(p.search(window_text) for p in LOGGING_PATTERNS)
            if not has_logging:
                rel = str(fpath.relative_to(repo_path))
                findings.append(
                    _make_finding(
                        check_id="code-ai-logging-insufficient",
                        title=f"AI API call without logging in {fpath.name}",
                        description=(
                            f"An AI API call at line {idx + 1} of "
                            f"{rel} has no apparent logging nearby. "
                            f"AI interactions should be logged."
                        ),
                        severity=Severity.MEDIUM,
                        repo_path=repo_path,
                        file_path=fpath,
                        line_number=idx + 1,
                        matched_pattern="ai_api_call without logging",
                        code_snippet=_snippet(lines, idx),
                        remediation=(
                            "Add logging around AI API calls "
                            "capturing: request metadata, response "
                            "status, latency, and token usage."
                        ),
                        soc2_controls=["CC7.2", "CC7.3"],
                    )
                )
    return findings


def check_outdated_ai_sdk(repo_path: Path) -> list[Finding]:
    """Detect known-vulnerable AI SDK versions in dependency files."""
    repo_path = Path(repo_path)
    findings: list[Finding] = []

    dep_files = {
        "requirements.txt": _parse_requirements_txt,
        "pyproject.toml": _parse_pyproject_toml,
        "package.json": _parse_package_json,
    }

    for fname, parser in dep_files.items():
        for fpath in repo_path.rglob(fname):
            if any(seg in fpath.parts for seg in EXCLUDED_PATH_SEGMENTS):
                continue
            content = _read_file(fpath)
            if content is None:
                continue
            deps = parser(content)
            for pkg_name, version_str in deps.items():
                if pkg_name not in VULNERABLE_SDK_VERSIONS:
                    continue
                for vuln in VULNERABLE_SDK_VERSIONS[pkg_name]:
                    if _version_matches_constraint(version_str, vuln["constraint"]):
                        rel = str(fpath.relative_to(repo_path))
                        findings.append(
                            _make_finding(
                                check_id="code-outdated-ai-sdk",
                                title=(
                                    f"Vulnerable {pkg_name} version ({version_str}) in {fpath.name}"
                                ),
                                description=(
                                    f"{pkg_name}=={version_str} in {rel} matches vulnerability "
                                    f"constraint '{vuln['constraint']}': {vuln['description']} "
                                    f"({vuln['cve']})."
                                ),
                                severity=Severity.MEDIUM,
                                repo_path=repo_path,
                                file_path=fpath,
                                line_number=1,
                                matched_pattern=f"{pkg_name} {vuln['constraint']}",
                                code_snippet=f"{pkg_name}=={version_str}",
                                remediation=(f"Upgrade {pkg_name} past '{vuln['constraint']}'."),
                                soc2_controls=["CC7.1"],
                            )
                        )
    return findings


def _parse_requirements_txt(content: str) -> dict[str, str]:
    """Extract package==version pairs from requirements.txt."""
    deps: dict[str, str] = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        for sep in ("==", ">=", "<=", "~=", "!="):
            if sep in line:
                name, version = line.split(sep, 1)
                deps[name.strip().lower()] = version.strip().split(",")[0].split(";")[0].strip()
                break
    return deps


def _parse_pyproject_toml(content: str) -> dict[str, str]:
    """Best-effort extraction of dependencies from pyproject.toml."""
    deps: dict[str, str] = {}
    # Match lines like:  "langchain>=0.0.300"  or  langchain = ">=0.0.300"
    for m in re.finditer(r'"([a-zA-Z0-9_-]+)\s*([><=!~]+)\s*([0-9][0-9a-zA-Z.]*)"', content):
        deps[m.group(1).lower()] = m.group(3)
    return deps


def _parse_package_json(content: str) -> dict[str, str]:
    """Best-effort extraction of dependencies from package.json."""
    import json as _json

    deps: dict[str, str] = {}
    try:
        data = _json.loads(content)
    except _json.JSONDecodeError:
        return deps
    for section in ("dependencies", "devDependencies"):
        for name, version in data.get(section, {}).items():
            # Strip ^, ~, >= prefixes
            clean = re.sub(r"^[^0-9]*", "", version)
            if clean:
                deps[name.lower()] = clean
    return deps


def _version_matches_constraint(version_str: str, constraint: str) -> bool:
    """Check if *version_str* matches a simple '< X.Y.Z' constraint."""
    # Only handle "< X.Y.Z" constraints for now
    m = re.match(r"<\s*([0-9][0-9a-zA-Z.]*)", constraint)
    if not m:
        return False
    threshold = m.group(1)
    try:
        return _version_tuple(version_str) < _version_tuple(threshold)
    except (ValueError, TypeError):
        return False


def _version_tuple(version: str) -> tuple[int, ...]:
    """Convert '1.2.3' to (1, 2, 3)."""
    parts: list[int] = []
    for p in version.split("."):
        # Strip non-numeric suffixes like "0b1"
        num = re.match(r"(\d+)", p)
        if num:
            parts.append(int(num.group(1)))
        else:
            break
    return tuple(parts)


def check_training_data_unencrypted(repo_path: Path) -> list[Finding]:
    """Detect training data loaded from unencrypted or HTTP sources."""
    repo_path = Path(repo_path)
    findings: list[Finding] = []

    for fpath in _iter_files(repo_path, SOURCE_CODE_EXTENSIONS):
        content = _read_file(fpath)
        if content is None:
            continue
        lines = _get_lines(content)

        # Check if file has training context
        has_training = any(p.search(content) for p in TRAINING_CONTEXT_PATTERNS)

        for idx, line in enumerate(lines):
            for pat in UNENCRYPTED_DATA_PATTERNS:
                m = pat.search(line)
                if m:
                    # Only flag if in a training context or if it's an HTTP (not HTTPS) URL
                    is_http = "http://" in line.lower()
                    if not has_training and not is_http:
                        continue
                    rel = str(fpath.relative_to(repo_path))
                    findings.append(
                        _make_finding(
                            check_id="code-training-data-unencrypted",
                            title=f"Unencrypted training data source in {fpath.name}",
                            description=(
                                f"Training data is loaded from an "
                                f"unencrypted source at line {idx + 1} "
                                f"of {rel}. Use HTTPS for data in "
                                f"transit; encrypt data at rest."
                            ),
                            severity=Severity.MEDIUM,
                            repo_path=repo_path,
                            file_path=fpath,
                            line_number=idx + 1,
                            matched_pattern=pat.pattern,
                            code_snippet=_snippet(lines, idx),
                            remediation=(
                                "Use HTTPS for remote data. Encrypt "
                                "training data at rest. Avoid plaintext."
                            ),
                            soc2_controls=["CC6.1", "CC6.7"],
                        )
                    )
                    break
    return findings


# ---------------------------------------------------------------------------
# LOW checks
# ---------------------------------------------------------------------------


def check_no_model_versioning(repo_path: Path) -> list[Finding]:
    """Detect AI model calls using generic (unpinned) model names."""
    repo_path = Path(repo_path)
    findings: list[Finding] = []

    for fpath in _iter_files(repo_path, SOURCE_CODE_EXTENSIONS):
        content = _read_file(fpath)
        if content is None:
            continue
        lines = _get_lines(content)

        for idx, line in enumerate(lines):
            for pat in GENERIC_MODEL_NAMES:
                m = pat.search(line)
                if m:
                    rel = str(fpath.relative_to(repo_path))
                    findings.append(
                        _make_finding(
                            check_id="code-no-model-versioning",
                            title=f"Unpinned model version in {fpath.name}",
                            description=(
                                f"Model '{m.group()}' at line {idx + 1}"
                                f" of {rel} uses a generic identifier "
                                f"without a date-pinned version."
                            ),
                            severity=Severity.LOW,
                            repo_path=repo_path,
                            file_path=fpath,
                            line_number=idx + 1,
                            matched_pattern=pat.pattern,
                            code_snippet=_snippet(lines, idx),
                            remediation=(
                                "Pin model versions with date suffixes "
                                "(e.g., gpt-4-0613) for reproducibility."
                            ),
                            soc2_controls=["CC8.1"],
                        )
                    )
                    break
    return findings


def check_no_fallback_handler(repo_path: Path) -> list[Finding]:
    """Detect AI API calls without error handling."""
    repo_path = Path(repo_path)
    findings: list[Finding] = []

    for fpath in _iter_files(repo_path, SOURCE_CODE_EXTENSIONS):
        content = _read_file(fpath)
        if content is None:
            continue
        lines = _get_lines(content)

        for idx, line in enumerate(lines):
            has_ai_call = any(p.search(line) for p in AI_API_CALL_PATTERNS)
            if not has_ai_call:
                continue

            # Check for error handling in surrounding context
            window_start = max(0, idx - 10)
            window_end = min(len(lines), idx + 10)
            window_text = "\n".join(lines[window_start:window_end])

            has_error_handling = any(p.search(window_text) for p in ERROR_HANDLING_PATTERNS)
            if not has_error_handling:
                rel = str(fpath.relative_to(repo_path))
                findings.append(
                    _make_finding(
                        check_id="code-no-fallback-handler",
                        title=f"AI API call without error handling in {fpath.name}",
                        description=(
                            f"An AI API call at line {idx + 1} of {rel} is not wrapped in "
                            f"try/except or .catch() error handling."
                        ),
                        severity=Severity.LOW,
                        repo_path=repo_path,
                        file_path=fpath,
                        line_number=idx + 1,
                        matched_pattern="ai_api_call without error_handling",
                        code_snippet=_snippet(lines, idx),
                        remediation=(
                            "Wrap AI API calls in try/except blocks "
                            "with fallback behaviour for timeouts "
                            "and rate limits."
                        ),
                        soc2_controls=["CC7.2", "CC7.5"],
                    )
                )
    return findings


# ---------------------------------------------------------------------------
# MCP (Model Context Protocol) security checks
# ---------------------------------------------------------------------------


def check_mcp_server_auth(repo_path: Path) -> list[Finding]:
    """Detect MCP servers deployed without authentication."""
    repo_path = Path(repo_path)
    findings: list[Finding] = []

    for fpath in _iter_files(repo_path, SOURCE_CODE_EXTENSIONS):
        content = _read_file(fpath)
        if content is None:
            continue

        # Only scan files that contain MCP server code
        has_mcp = any(p.search(content) for p in MCP_SERVER_PATTERNS)
        if not has_mcp:
            continue

        lines = _get_lines(content)

        # Check if stdio transport is used (no network auth possible)
        uses_stdio = any(p.search(content) for p in MCP_NO_AUTH_PATTERNS)

        # Look for auth configuration indicators
        has_auth = bool(
            re.search(
                r"(?:auth|authenticate|bearer|api[_-]?key|token|oauth)",
                content,
                re.IGNORECASE,
            )
        )

        if uses_stdio:
            # stdio is local-only — INFO, not a failure, but flag for
            # production awareness
            for idx, line in enumerate(lines):
                if any(p.search(line) for p in MCP_NO_AUTH_PATTERNS):
                    findings.append(
                        _make_finding(
                            check_id="code-mcp-server-auth",
                            title=(f"MCP server uses stdio transport in {fpath.name}"),
                            description=(
                                f"MCP server at line {idx + 1} uses "
                                f"stdio transport which cannot enforce "
                                f"network-level authentication. "
                                f"Ensure this is not exposed remotely "
                                f"in production."
                            ),
                            severity=Severity.MEDIUM,
                            repo_path=repo_path,
                            file_path=fpath,
                            line_number=idx + 1,
                            matched_pattern="StdioServerTransport",
                            code_snippet=_snippet(lines, idx),
                            remediation=(
                                "For production deployments, use SSE or "
                                "HTTP transport with OAuth 2.1 or API "
                                "key authentication instead of stdio."
                            ),
                            soc2_controls=["CC6.1", "CC6.6"],
                        )
                    )
                    break
        elif not has_auth:
            # Network MCP server with no auth — HIGH
            for idx, line in enumerate(lines):
                if any(p.search(line) for p in MCP_SERVER_PATTERNS):
                    findings.append(
                        _make_finding(
                            check_id="code-mcp-server-auth",
                            title=(f"MCP server without authentication in {fpath.name}"),
                            description=(
                                f"MCP server defined at line {idx + 1} "
                                f"has no apparent authentication. "
                                f"Unauthenticated MCP servers allow "
                                f"any client to invoke tools."
                            ),
                            severity=Severity.HIGH,
                            repo_path=repo_path,
                            file_path=fpath,
                            line_number=idx + 1,
                            matched_pattern="MCP server without auth",
                            code_snippet=_snippet(lines, idx),
                            remediation=(
                                "Add authentication to the MCP server: "
                                "OAuth 2.1, API key validation, or mTLS. "
                                "Reject unauthenticated tool calls."
                            ),
                            soc2_controls=["CC6.1", "CC6.6"],
                        )
                    )
                    break
    return findings


def check_mcp_tool_scope(repo_path: Path) -> list[Finding]:
    """Detect MCP tool definitions with dangerous or overprivileged capabilities."""
    repo_path = Path(repo_path)
    findings: list[Finding] = []

    for fpath in _iter_files(repo_path, SOURCE_CODE_EXTENSIONS):
        content = _read_file(fpath)
        if content is None:
            continue

        has_mcp = any(p.search(content) for p in MCP_SERVER_PATTERNS)
        if not has_mcp:
            continue

        lines = _get_lines(content)
        for idx, line in enumerate(lines):
            for pat in MCP_DANGEROUS_TOOL_PATTERNS:
                m = pat.search(line)
                if m:
                    findings.append(
                        _make_finding(
                            check_id="code-mcp-tool-scope",
                            title=(f"MCP tool with dangerous capability in {fpath.name}"),
                            description=(
                                f"MCP tool at line {idx + 1} grants "
                                f"access to dangerous operations "
                                f"({m.group(0).strip()}). "
                                f"Overprivileged tools can be exploited "
                                f"via prompt injection."
                            ),
                            severity=Severity.HIGH,
                            repo_path=repo_path,
                            file_path=fpath,
                            line_number=idx + 1,
                            matched_pattern=pat.pattern,
                            code_snippet=_snippet(lines, idx),
                            remediation=(
                                "Restrict MCP tool capabilities to the "
                                "minimum necessary. Sandbox shell/file "
                                "operations. Use allowlists for permitted "
                                "actions."
                            ),
                            soc2_controls=["CC6.1", "CC7.2"],
                        )
                    )
                    break
    return findings


def check_mcp_input_validation(repo_path: Path) -> list[Finding]:
    """Detect MCP tool functions that accept unvalidated input."""
    repo_path = Path(repo_path)
    findings: list[Finding] = []

    for fpath in _iter_files(repo_path, SOURCE_CODE_EXTENSIONS):
        content = _read_file(fpath)
        if content is None:
            continue

        has_mcp = any(p.search(content) for p in MCP_SERVER_PATTERNS)
        if not has_mcp:
            continue

        lines = _get_lines(content)
        for idx, line in enumerate(lines):
            for pat in MCP_NO_SCHEMA_PATTERNS:
                m = pat.search(line)
                if m:
                    findings.append(
                        _make_finding(
                            check_id="code-mcp-input-validation",
                            title=(f"MCP tool accepts unvalidated input in {fpath.name}"),
                            description=(
                                f"Tool function at line {idx + 1} "
                                f"uses **kwargs or *args without a "
                                f"typed schema. Unvalidated inputs "
                                f"can be exploited for injection."
                            ),
                            severity=Severity.MEDIUM,
                            repo_path=repo_path,
                            file_path=fpath,
                            line_number=idx + 1,
                            matched_pattern=pat.pattern,
                            code_snippet=_snippet(lines, idx),
                            remediation=(
                                "Define typed input schemas for all MCP "
                                "tools using Pydantic models or JSON "
                                "Schema. Validate inputs before processing."
                            ),
                            soc2_controls=["CC6.1"],
                        )
                    )
                    break
    return findings


# ---------------------------------------------------------------------------
# A2A (Agent-to-Agent) protocol security checks
# ---------------------------------------------------------------------------


def check_a2a_agent_auth(repo_path: Path) -> list[Finding]:
    """Detect A2A Agent Cards or servers without authentication requirements."""
    repo_path = Path(repo_path)
    findings: list[Finding] = []

    for fpath in _iter_files(repo_path, ALL_SCANNABLE_EXTENSIONS):
        content = _read_file(fpath)
        if content is None:
            continue

        has_a2a = any(p.search(content) for p in A2A_PATTERNS)
        if not has_a2a:
            continue

        lines = _get_lines(content)

        # Check for Agent Cards with empty or null authentication
        for idx, line in enumerate(lines):
            for pat in A2A_NO_AUTH_PATTERNS:
                m = pat.search(line)
                if m:
                    findings.append(
                        _make_finding(
                            check_id="code-a2a-agent-auth",
                            title=(f"A2A agent without authentication in {fpath.name}"),
                            description=(
                                f"Agent Card or A2A configuration at "
                                f"line {idx + 1} declares empty or "
                                f"null authentication. Agents accepting "
                                f"unauthenticated requests are "
                                f"vulnerable to impersonation."
                            ),
                            severity=Severity.HIGH,
                            repo_path=repo_path,
                            file_path=fpath,
                            line_number=idx + 1,
                            matched_pattern=pat.pattern,
                            code_snippet=_snippet(lines, idx),
                            remediation=(
                                "Require authentication in the Agent "
                                "Card. Use OAuth 2.0, API keys, or "
                                "mTLS for agent-to-agent communication."
                            ),
                            soc2_controls=["CC6.1", "CC6.6"],
                        )
                    )
                    break
    return findings


def check_a2a_delegation_scope(repo_path: Path) -> list[Finding]:
    """Detect A2A task delegation without scope restriction."""
    repo_path = Path(repo_path)
    findings: list[Finding] = []

    # Pattern: sending tasks to other agents without permission checks
    delegation_pattern = re.compile(
        r"(?:send_task|delegate|forward_task|TaskSendParams)\s*\(",
        re.IGNORECASE,
    )
    scope_pattern = re.compile(
        r"(?:scope|permission|allowed|restrict|authoriz|capabilities)",
        re.IGNORECASE,
    )

    for fpath in _iter_files(repo_path, SOURCE_CODE_EXTENSIONS):
        content = _read_file(fpath)
        if content is None:
            continue

        has_a2a = any(p.search(content) for p in A2A_PATTERNS)
        if not has_a2a:
            continue

        lines = _get_lines(content)
        for idx, line in enumerate(lines):
            if not delegation_pattern.search(line):
                continue

            # Check surrounding context for scope/permission checks
            window_start = max(0, idx - 5)
            window_end = min(len(lines), idx + 6)
            window = "\n".join(lines[window_start:window_end])

            if not scope_pattern.search(window):
                findings.append(
                    _make_finding(
                        check_id="code-a2a-delegation-scope",
                        title=(f"A2A task delegation without scope check in {fpath.name}"),
                        description=(
                            f"Task delegation at line {idx + 1} "
                            f"has no apparent scope or permission "
                            f"check. Unrestricted delegation can "
                            f"lead to privilege escalation across "
                            f"agent chains."
                        ),
                        severity=Severity.MEDIUM,
                        repo_path=repo_path,
                        file_path=fpath,
                        line_number=idx + 1,
                        matched_pattern=delegation_pattern.pattern,
                        code_snippet=_snippet(lines, idx),
                        remediation=(
                            "Validate that the delegating agent has "
                            "permission to invoke the target agent. "
                            "Restrict delegation scope to declared "
                            "capabilities. Log all cross-agent calls."
                        ),
                        soc2_controls=["CC6.1", "CC6.2"],
                    )
                )
    return findings


# ---------------------------------------------------------------------------
# Aggregated list of all checks
# ---------------------------------------------------------------------------

ALL_CHECKS = [
    check_ai_api_key_exposed,
    check_ai_key_in_env_file,
    check_prompt_injection_risk,
    check_no_output_validation,
    check_pii_in_prompts,
    check_model_endpoint_public,
    check_agent_unrestricted_tools,
    check_rag_no_access_control,
    check_no_rate_limiting,
    check_meta_prompt_exposed,
    check_ai_logging_insufficient,
    check_outdated_ai_sdk,
    check_training_data_unencrypted,
    check_no_model_versioning,
    check_no_fallback_handler,
    # MCP protocol security
    check_mcp_server_auth,
    check_mcp_tool_scope,
    check_mcp_input_validation,
    # A2A protocol security
    check_a2a_agent_auth,
    check_a2a_delegation_scope,
]

# Checks that cannot be expressed as Semgrep rules and must always run as Python.
# - check_no_rate_limiting: file-level memoization (skip file if rate limiting exists anywhere)
# - check_outdated_ai_sdk: dependency file parsing + version constraint comparison
# - check_mcp_*: multi-pattern context checks requiring file-level MCP detection
# - check_a2a_*: multi-pattern context checks requiring file-level A2A detection
PYTHON_ONLY_CHECKS = [
    check_no_rate_limiting,
    check_outdated_ai_sdk,
    check_mcp_server_auth,
    check_mcp_tool_scope,
    check_mcp_input_validation,
    check_a2a_agent_auth,
    check_a2a_delegation_scope,
]
