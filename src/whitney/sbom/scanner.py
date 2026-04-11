"""AI SBOM (Model Bill of Materials) scanner.

Discovers AI components across code repositories and cloud environments,
outputting a CycloneDX 1.5 JSON inventory of AI SDKs, models, and services.

Three scan modes:
  - Code-only: scans dependency files and source code for AI SDKs and models
  - Cloud-only: discovers AI services from AWS and/or Azure
  - Full: combines code + cloud scanning
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

from whitney.code.checks import (
    _iter_files,
    _parse_package_json,
    _parse_pyproject_toml,
    _parse_requirements_txt,
    _read_file,
    _version_matches_constraint,
)
from whitney.code.patterns import (
    EXCLUDED_PATH_SEGMENTS,
    GENERIC_MODEL_NAMES,
    PINNED_MODEL_PATTERN,
    SOURCE_CODE_EXTENSIONS,
    VULNERABLE_SDK_VERSIONS,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Known AI packages: lowercase name -> provider
KNOWN_AI_PACKAGES: dict[str, str] = {
    "openai": "openai",
    "anthropic": "anthropic",
    "langchain": "langchain",
    "langchain-core": "langchain",
    "langchain-community": "langchain",
    "langchain-openai": "langchain",
    "transformers": "huggingface",
    "cohere": "cohere",
    "huggingface_hub": "huggingface",
    "huggingface-hub": "huggingface",
    "google-generativeai": "google",
    "replicate": "replicate",
    "together": "together",
    "groq": "groq",
    "mistralai": "mistral",
    "boto3": "aws",  # included when used with bedrock/sagemaker
    "azure-ai-openai": "azure",
    "litellm": "litellm",
    "ollama": "ollama",
    "vllm": "vllm",
    # npm
    "@anthropic-ai/sdk": "anthropic",
    "@google/generative-ai": "google",
}

# Model name prefix -> provider
MODEL_PROVIDER_PREFIXES: dict[str, str] = {
    "gpt-": "openai",
    "o1-": "openai",
    "o3-": "openai",
    "claude-": "anthropic",
    "gemini-": "google",
    "llama-": "meta",
    "mistral-": "mistral",
    "mixtral-": "mistral",
    "command-": "cohere",
    "embed-": "cohere",
}

# Broader model= assignment pattern
MODEL_ASSIGNMENT_PATTERN: re.Pattern[str] = re.compile(
    r"""model\s*=\s*["']([a-zA-Z0-9._/-]+(?:[-:][a-zA-Z0-9._/-]+)*)["']"""
)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


class AIComponentType(str, Enum):
    """Type of AI component in the inventory."""

    SDK = "sdk"
    MODEL = "model"
    CLOUD_SERVICE = "cloud_service"


@dataclass
class AIComponent:
    """A single AI component discovered in the inventory."""

    name: str
    version: str  # "1.3.0" for SDKs, "" for models/services
    component_type: AIComponentType
    provider: str  # "openai", "anthropic", "aws", "azure", etc.
    ecosystem: str  # "pypi", "npm", "aws", "azure"
    source: str  # "code:requirements.txt", "aws:bedrock", etc.
    purl: str = ""


@dataclass
class AISBOMReport:
    """AI-specific Software Bill of Materials report."""

    account_id: str
    generated_at: str
    total_components: int = 0
    component_types: dict[str, int] = field(default_factory=dict)
    sources: list[str] = field(default_factory=list)
    components: list[AIComponent] = field(default_factory=list)
    vulnerabilities: list[dict] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _infer_model_provider(model_name: str) -> str:
    """Infer the AI provider from a model name."""
    lower = model_name.lower()
    for prefix, provider in MODEL_PROVIDER_PREFIXES.items():
        if lower.startswith(prefix):
            return provider
    return "unknown"


def _make_purl(ecosystem: str, name: str, version: str = "") -> str:
    """Build a Package URL string."""
    if version:
        return f"pkg:{ecosystem}/{name}@{version}"
    return f"pkg:{ecosystem}/{name}"


# ---------------------------------------------------------------------------
# Code scanning
# ---------------------------------------------------------------------------


def scan_code_for_ai_components(repo_path: str | Path) -> list[AIComponent]:
    """Scan dependency files and source code for AI SDKs and models.

    Returns a list of AIComponent objects for discovered AI SDKs (from
    dependency files) and AI models (from model= assignments in source code).
    """
    repo_path = Path(repo_path)
    components: list[AIComponent] = []
    seen_sdks: set[tuple[str, str]] = set()  # (name, version) dedup
    seen_models: set[str] = set()  # model name dedup

    # --- 1. Scan dependency files for AI SDKs ---
    dep_files: dict[str, tuple] = {
        "requirements.txt": (_parse_requirements_txt, "pypi"),
        "pyproject.toml": (_parse_pyproject_toml, "pypi"),
        "package.json": (_parse_package_json, "npm"),
    }

    for fname, (parser, ecosystem) in dep_files.items():
        for fpath in repo_path.rglob(fname):
            if any(seg in fpath.parts for seg in EXCLUDED_PATH_SEGMENTS):
                continue
            content = _read_file(fpath)
            if content is None:
                continue
            deps = parser(content)
            for pkg_name, version in deps.items():
                pkg_lower = pkg_name.lower()
                if pkg_lower not in KNOWN_AI_PACKAGES:
                    continue
                key = (pkg_lower, version)
                if key in seen_sdks:
                    continue
                seen_sdks.add(key)
                provider = KNOWN_AI_PACKAGES[pkg_lower]
                rel = str(fpath.relative_to(repo_path))
                components.append(
                    AIComponent(
                        name=pkg_lower,
                        version=version,
                        component_type=AIComponentType.SDK,
                        provider=provider,
                        ecosystem=ecosystem,
                        source=f"code:{rel}",
                        purl=_make_purl(ecosystem, pkg_lower, version),
                    )
                )

    # --- 2. Scan source files for model= assignments ---
    for fpath in _iter_files(repo_path, SOURCE_CODE_EXTENSIONS):
        content = _read_file(fpath)
        if content is None:
            continue
        for m in MODEL_ASSIGNMENT_PATTERN.finditer(content):
            model_name = m.group(1)
            if model_name in seen_models:
                continue
            seen_models.add(model_name)
            provider = _infer_model_provider(model_name)
            rel = str(fpath.relative_to(repo_path))
            components.append(
                AIComponent(
                    name=model_name,
                    version="",
                    component_type=AIComponentType.MODEL,
                    provider=provider,
                    ecosystem="ai",
                    source=f"code:{rel}",
                    purl=_make_purl("ai", f"{provider}/{model_name}"),
                )
            )

    return components


# ---------------------------------------------------------------------------
# Cloud scanning
# ---------------------------------------------------------------------------


def scan_aws_for_ai_components(client: object) -> list[AIComponent]:
    """Discover AI components from AWS services.

    Delegates to ``discover_aws_ai_services()`` and transforms the
    results into AIComponent objects.
    """
    from whitney.discovery.aws_ai import discover_aws_ai_services

    inventory = discover_aws_ai_services(client)  # type: ignore[arg-type]
    components: list[AIComponent] = []

    # Bedrock foundation models
    for model in inventory.get("bedrock", {}).get("foundation_models", []):
        model_id = model.get("model_id", model.get("modelId", ""))
        provider = model.get("provider", model.get("providerName", "unknown"))
        if model_id:
            components.append(
                AIComponent(
                    name=model_id,
                    version="",
                    component_type=AIComponentType.CLOUD_SERVICE,
                    provider=provider.lower(),
                    ecosystem="aws",
                    source="aws:bedrock",
                    purl=_make_purl("aws", f"bedrock/{model_id}"),
                )
            )

    # SageMaker endpoints
    for ep in inventory.get("sagemaker", {}).get("endpoints", []):
        name = ep.get("name", ep.get("EndpointName", ""))
        if name:
            components.append(
                AIComponent(
                    name=name,
                    version="",
                    component_type=AIComponentType.CLOUD_SERVICE,
                    provider="aws",
                    ecosystem="aws",
                    source="aws:sagemaker/endpoint",
                    purl=_make_purl("aws", f"sagemaker/{name}"),
                )
            )

    # SageMaker models
    for model in inventory.get("sagemaker", {}).get("models", []):
        name = model.get("name", model.get("ModelName", ""))
        if name:
            components.append(
                AIComponent(
                    name=name,
                    version="",
                    component_type=AIComponentType.CLOUD_SERVICE,
                    provider="aws",
                    ecosystem="aws",
                    source="aws:sagemaker/model",
                    purl=_make_purl("aws", f"sagemaker/{name}"),
                )
            )

    # Lambda functions with AI keys
    for fn in inventory.get("lambda_ai", {}).get("functions_with_ai_vars", []):
        name = fn.get("name", fn.get("FunctionName", ""))
        if name:
            components.append(
                AIComponent(
                    name=name,
                    version="",
                    component_type=AIComponentType.CLOUD_SERVICE,
                    provider="aws",
                    ecosystem="aws",
                    source="aws:lambda",
                    purl=_make_purl("aws", f"lambda/{name}"),
                )
            )

    return components


def scan_azure_for_ai_components(client: object) -> list[AIComponent]:
    """Discover AI components from Azure services.

    Delegates to ``discover_azure_ai_services()`` and transforms the
    results into AIComponent objects.
    """
    from whitney.discovery.azure_ai import discover_azure_ai_services

    inventory = discover_azure_ai_services(client)  # type: ignore[arg-type]
    components: list[AIComponent] = []

    # Azure OpenAI deployments
    for dep in inventory.get("azure_openai", {}).get("deployments", []):
        name = dep.get("name", "")
        model = dep.get("model", "")
        if name:
            components.append(
                AIComponent(
                    name=name,
                    version="",
                    component_type=AIComponentType.CLOUD_SERVICE,
                    provider="openai",
                    ecosystem="azure",
                    source="azure:openai",
                    purl=_make_purl("azure", f"openai/{name}"),
                )
            )

    # Azure ML workspaces
    for ws in inventory.get("azure_ml", {}).get("workspaces", []):
        name = ws.get("name", "")
        if name:
            components.append(
                AIComponent(
                    name=name,
                    version="",
                    component_type=AIComponentType.CLOUD_SERVICE,
                    provider="azure",
                    ecosystem="azure",
                    source="azure:ml",
                    purl=_make_purl("azure", f"ml/{name}"),
                )
            )

    # Cognitive Services
    for svc in inventory.get("cognitive_services", {}).get("services", []):
        name = svc.get("name", "")
        kind = svc.get("kind", "unknown")
        if name:
            components.append(
                AIComponent(
                    name=name,
                    version="",
                    component_type=AIComponentType.CLOUD_SERVICE,
                    provider=kind.lower(),
                    ecosystem="azure",
                    source="azure:cognitive",
                    purl=_make_purl("azure", f"cognitive/{name}"),
                )
            )

    return components


# ---------------------------------------------------------------------------
# Vulnerability checking
# ---------------------------------------------------------------------------


def check_ai_component_vulnerabilities(
    components: list[AIComponent],
) -> list[dict]:
    """Cross-reference SDK components against known vulnerable versions.

    Returns a list of vulnerability dicts for components matching
    constraints in VULNERABLE_SDK_VERSIONS.
    """
    vulns: list[dict] = []
    for comp in components:
        if comp.component_type != AIComponentType.SDK:
            continue
        if comp.name not in VULNERABLE_SDK_VERSIONS:
            continue
        for vuln_entry in VULNERABLE_SDK_VERSIONS[comp.name]:
            if _version_matches_constraint(comp.version, vuln_entry["constraint"]):
                vulns.append(
                    {
                        "package": comp.name,
                        "version": comp.version,
                        "constraint": vuln_entry["constraint"],
                        "cve": vuln_entry["cve"],
                        "description": vuln_entry["description"],
                        "severity": "medium",
                    }
                )
    return vulns


# ---------------------------------------------------------------------------
# CycloneDX output
# ---------------------------------------------------------------------------


def generate_ai_sbom(
    components: list[AIComponent],
    account_id: str = "code-scan",
    vulnerabilities: list[dict] | None = None,
) -> dict:
    """Produce a CycloneDX 1.5 JSON dict from discovered AI components.

    Returns a dict matching the CycloneDX 1.5 specification, with
    Whitney-specific properties on each component.
    """
    now = datetime.now(timezone.utc)
    timestamp = now.strftime("%Y-%m-%dT%H:%M:%SZ")

    # Map component types to CycloneDX types
    type_map = {
        AIComponentType.SDK: "library",
        AIComponentType.MODEL: "framework",
        AIComponentType.CLOUD_SERVICE: "service",
    }

    cdx_components = []
    for comp in components:
        entry: dict = {
            "type": type_map.get(comp.component_type, "library"),
            "name": comp.name,
            "version": comp.version or "latest",
            "purl": comp.purl,
            "properties": [
                {"name": "shasta:component_type", "value": comp.component_type.value},
                {"name": "shasta:provider", "value": comp.provider},
                {"name": "shasta:ecosystem", "value": comp.ecosystem},
                {"name": "shasta:source", "value": comp.source},
            ],
        }
        cdx_components.append(entry)

    cdx_vulns = []
    for i, vuln in enumerate(vulnerabilities or []):
        cdx_vulns.append(
            {
                "id": vuln.get("cve", f"WHITNEY-AI-{i + 1}"),
                "description": vuln["description"],
                "affects": [{"ref": vuln["package"]}],
                "ratings": [{"severity": vuln.get("severity", "medium")}],
                "properties": [
                    {"name": "shasta:package", "value": vuln["package"]},
                    {"name": "shasta:version", "value": vuln["version"]},
                    {"name": "shasta:constraint", "value": vuln.get("constraint", "")},
                ],
            }
        )

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:whitney:{account_id}:{timestamp}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": [
                {
                    "vendor": "Whitney",
                    "name": "Whitney AI SBOM Scanner",
                    "version": "0.1.0",
                }
            ],
            "component": {
                "type": "application",
                "name": f"ai-inventory-{account_id}",
                "version": "1.0.0",
            },
        },
        "components": cdx_components,
        "vulnerabilities": cdx_vulns,
    }


# ---------------------------------------------------------------------------
# Convenience orchestrators
# ---------------------------------------------------------------------------


def scan_ai_sbom_code_only(repo_path: str | Path) -> dict:
    """Code-only scan: discover AI SDKs and models from a repository."""
    components = scan_code_for_ai_components(repo_path)
    vulns = check_ai_component_vulnerabilities(components)
    return generate_ai_sbom(components, account_id="code-scan", vulnerabilities=vulns)


def scan_ai_sbom_full(
    repo_path: str | Path,
    *,
    aws_client: object | None = None,
    azure_client: object | None = None,
    account_id: str = "unknown",
) -> dict:
    """Full scan: code + cloud AI component discovery."""
    components = scan_code_for_ai_components(repo_path)
    if aws_client:
        components.extend(scan_aws_for_ai_components(aws_client))
    if azure_client:
        components.extend(scan_azure_for_ai_components(azure_client))
    vulns = check_ai_component_vulnerabilities(components)
    return generate_ai_sbom(components, account_id=account_id, vulnerabilities=vulns)
