"""Tests for Whitney AI SBOM (Model Bill of Materials) scanner."""

from __future__ import annotations

from unittest.mock import patch

import pytest

from whitney.sbom.scanner import (
    AIComponent,
    AIComponentType,
    AISBOMReport,
    KNOWN_AI_PACKAGES,
    check_ai_component_vulnerabilities,
    generate_ai_sbom,
    scan_ai_sbom_code_only,
    scan_aws_for_ai_components,
    scan_azure_for_ai_components,
    scan_code_for_ai_components,
    _infer_model_provider,
    _make_purl,
)
from tests.test_whitney.conftest import write_file


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class TestHelpers:
    """Test helper functions."""

    def test_infer_model_provider_openai(self):
        assert _infer_model_provider("gpt-4") == "openai"
        assert _infer_model_provider("gpt-3.5-turbo") == "openai"

    def test_infer_model_provider_anthropic(self):
        assert _infer_model_provider("claude-3-opus") == "anthropic"

    def test_infer_model_provider_google(self):
        assert _infer_model_provider("gemini-pro") == "google"

    def test_infer_model_provider_unknown(self):
        assert _infer_model_provider("my-custom-model") == "unknown"

    def test_make_purl_with_version(self):
        assert _make_purl("pypi", "openai", "1.3.0") == "pkg:pypi/openai@1.3.0"

    def test_make_purl_without_version(self):
        assert _make_purl("ai", "openai/gpt-4") == "pkg:ai/openai/gpt-4"


# ---------------------------------------------------------------------------
# Code scanning: SDKs
# ---------------------------------------------------------------------------


class TestScanCodeForAISDKs:
    """Test AI SDK discovery from dependency files."""

    def test_requirements_txt(self, tmp_path):
        write_file(tmp_path, "requirements.txt", "openai==1.3.0\nflask==2.0.0\nrequests==2.31.0\n")
        components = scan_code_for_ai_components(tmp_path)
        sdks = [c for c in components if c.component_type == AIComponentType.SDK]
        assert len(sdks) == 1
        assert sdks[0].name == "openai"
        assert sdks[0].version == "1.3.0"
        assert sdks[0].ecosystem == "pypi"
        assert sdks[0].purl == "pkg:pypi/openai@1.3.0"

    def test_pyproject_toml(self, tmp_path):
        content = '[project]\ndependencies = [\n  "anthropic>=0.18.0",\n  "pydantic>=2.0"\n]\n'
        write_file(tmp_path, "pyproject.toml", content)
        components = scan_code_for_ai_components(tmp_path)
        sdks = [c for c in components if c.component_type == AIComponentType.SDK]
        assert len(sdks) == 1
        assert sdks[0].name == "anthropic"
        assert sdks[0].provider == "anthropic"

    def test_package_json(self, tmp_path):
        write_file(
            tmp_path,
            "package.json",
            '{"dependencies": {"openai": "^4.0.0", "express": "^4.18.0"}}',
        )
        components = scan_code_for_ai_components(tmp_path)
        sdks = [c for c in components if c.component_type == AIComponentType.SDK]
        assert len(sdks) == 1
        assert sdks[0].ecosystem == "npm"

    def test_multiple_ai_sdks(self, tmp_path):
        write_file(
            tmp_path,
            "requirements.txt",
            "openai==1.3.0\nanthropic==0.18.0\nlangchain==0.1.0\nflask==2.0.0\n",
        )
        components = scan_code_for_ai_components(tmp_path)
        sdks = [c for c in components if c.component_type == AIComponentType.SDK]
        names = {s.name for s in sdks}
        assert "openai" in names
        assert "anthropic" in names
        assert "langchain" in names
        assert len(sdks) == 3

    def test_non_ai_packages_filtered_out(self, tmp_path):
        write_file(tmp_path, "requirements.txt", "flask==2.0.0\nrequests==2.31.0\npydantic==2.0\n")
        components = scan_code_for_ai_components(tmp_path)
        sdks = [c for c in components if c.component_type == AIComponentType.SDK]
        assert len(sdks) == 0

    def test_deduplication(self, tmp_path):
        write_file(tmp_path, "requirements.txt", "openai==1.3.0\n")
        write_file(tmp_path, "sub/requirements.txt", "openai==1.3.0\n")
        components = scan_code_for_ai_components(tmp_path)
        sdks = [c for c in components if c.component_type == AIComponentType.SDK]
        assert len(sdks) == 1  # deduplicated by (name, version)


# ---------------------------------------------------------------------------
# Code scanning: Models
# ---------------------------------------------------------------------------


class TestScanCodeForModels:
    """Test AI model discovery from source code."""

    def test_detects_generic_model(self, tmp_path):
        write_file(tmp_path, "app.py", 'response = client.chat(model="gpt-4", messages=[])\n')
        components = scan_code_for_ai_components(tmp_path)
        models = [c for c in components if c.component_type == AIComponentType.MODEL]
        assert len(models) == 1
        assert models[0].name == "gpt-4"
        assert models[0].provider == "openai"

    def test_detects_pinned_model(self, tmp_path):
        write_file(tmp_path, "app.py", 'response = client.chat(model="gpt-4-20240125", messages=[])\n')
        components = scan_code_for_ai_components(tmp_path)
        models = [c for c in components if c.component_type == AIComponentType.MODEL]
        assert len(models) == 1
        assert "20240125" in models[0].name

    def test_detects_claude_model(self, tmp_path):
        write_file(tmp_path, "app.py", 'response = client.messages.create(model="claude-3-opus")\n')
        components = scan_code_for_ai_components(tmp_path)
        models = [c for c in components if c.component_type == AIComponentType.MODEL]
        assert len(models) == 1
        assert models[0].provider == "anthropic"

    def test_model_deduplication(self, tmp_path):
        write_file(tmp_path, "a.py", 'model="gpt-4"\n')
        write_file(tmp_path, "b.py", 'model="gpt-4"\n')
        components = scan_code_for_ai_components(tmp_path)
        models = [c for c in components if c.component_type == AIComponentType.MODEL]
        assert len(models) == 1

    def test_empty_repo(self, tmp_path):
        components = scan_code_for_ai_components(tmp_path)
        assert components == []


# ---------------------------------------------------------------------------
# Vulnerability checking
# ---------------------------------------------------------------------------


class TestCheckVulnerabilities:
    """Test vulnerability cross-referencing."""

    def test_vulnerable_langchain(self):
        comp = AIComponent(
            name="langchain",
            version="0.0.300",
            component_type=AIComponentType.SDK,
            provider="langchain",
            ecosystem="pypi",
            source="code:requirements.txt",
            purl="pkg:pypi/langchain@0.0.300",
        )
        vulns = check_ai_component_vulnerabilities([comp])
        assert len(vulns) == 1
        assert vulns[0]["cve"] == "CVE-2023-46229"
        assert vulns[0]["package"] == "langchain"

    def test_safe_version_no_vuln(self):
        comp = AIComponent(
            name="langchain",
            version="1.0.0",
            component_type=AIComponentType.SDK,
            provider="langchain",
            ecosystem="pypi",
            source="code:requirements.txt",
            purl="pkg:pypi/langchain@1.0.0",
        )
        vulns = check_ai_component_vulnerabilities([comp])
        assert len(vulns) == 0

    def test_skips_non_sdk_components(self):
        comp = AIComponent(
            name="gpt-4",
            version="",
            component_type=AIComponentType.MODEL,
            provider="openai",
            ecosystem="ai",
            source="code:app.py",
        )
        vulns = check_ai_component_vulnerabilities([comp])
        assert len(vulns) == 0

    def test_unknown_package_no_vuln(self):
        comp = AIComponent(
            name="my-custom-sdk",
            version="1.0.0",
            component_type=AIComponentType.SDK,
            provider="custom",
            ecosystem="pypi",
            source="code:requirements.txt",
        )
        vulns = check_ai_component_vulnerabilities([comp])
        assert len(vulns) == 0


# ---------------------------------------------------------------------------
# CycloneDX output
# ---------------------------------------------------------------------------


class TestGenerateAISBOM:
    """Test CycloneDX JSON output generation."""

    def test_cyclonedx_format(self):
        components = [
            AIComponent(
                name="openai",
                version="1.3.0",
                component_type=AIComponentType.SDK,
                provider="openai",
                ecosystem="pypi",
                source="code:requirements.txt",
                purl="pkg:pypi/openai@1.3.0",
            )
        ]
        result = generate_ai_sbom(components, account_id="test-123")
        assert result["bomFormat"] == "CycloneDX"
        assert result["specVersion"] == "1.5"
        assert "urn:whitney:test-123" in result["serialNumber"]
        assert result["metadata"]["tools"][0]["name"] == "Whitney AI SBOM Scanner"

    def test_components_present(self):
        components = [
            AIComponent(
                name="openai",
                version="1.3.0",
                component_type=AIComponentType.SDK,
                provider="openai",
                ecosystem="pypi",
                source="code:requirements.txt",
                purl="pkg:pypi/openai@1.3.0",
            ),
            AIComponent(
                name="gpt-4",
                version="",
                component_type=AIComponentType.MODEL,
                provider="openai",
                ecosystem="ai",
                source="code:app.py",
                purl="pkg:ai/openai/gpt-4",
            ),
        ]
        result = generate_ai_sbom(components)
        assert len(result["components"]) == 2
        sdk = result["components"][0]
        assert sdk["type"] == "library"
        assert sdk["name"] == "openai"
        model = result["components"][1]
        assert model["type"] == "framework"
        assert model["name"] == "gpt-4"

    def test_properties_on_components(self):
        components = [
            AIComponent(
                name="openai",
                version="1.3.0",
                component_type=AIComponentType.SDK,
                provider="openai",
                ecosystem="pypi",
                source="code:requirements.txt",
                purl="pkg:pypi/openai@1.3.0",
            )
        ]
        result = generate_ai_sbom(components)
        props = {p["name"]: p["value"] for p in result["components"][0]["properties"]}
        assert props["shasta:component_type"] == "sdk"
        assert props["shasta:provider"] == "openai"
        assert props["shasta:ecosystem"] == "pypi"
        assert props["shasta:source"] == "code:requirements.txt"

    def test_vulnerabilities_in_output(self):
        vulns = [
            {
                "package": "langchain",
                "version": "0.0.300",
                "constraint": "< 0.0.325",
                "cve": "CVE-2023-46229",
                "description": "Arbitrary code execution",
                "severity": "medium",
            }
        ]
        result = generate_ai_sbom([], vulnerabilities=vulns)
        assert len(result["vulnerabilities"]) == 1
        assert result["vulnerabilities"][0]["id"] == "CVE-2023-46229"

    def test_empty_components(self):
        result = generate_ai_sbom([])
        assert result["components"] == []
        assert result["vulnerabilities"] == []


# ---------------------------------------------------------------------------
# Cloud scanning (mocked)
# ---------------------------------------------------------------------------


class TestScanAWSComponents:
    """Test AWS AI component discovery with mocked discovery."""

    @patch("whitney.discovery.aws_ai.discover_aws_ai_services")
    def test_bedrock_models(self, mock_discover):
        mock_discover.return_value = {
            "bedrock": {
                "models": [
                    {"model_id": "anthropic.claude-3-sonnet-20240229-v1:0", "provider": "Anthropic"}
                ]
            },
            "sagemaker": {"endpoints": [], "models": []},
            "lambda_ai": {"functions_with_ai_keys": []},
        }
        components = scan_aws_for_ai_components(None)
        assert len(components) == 1
        assert components[0].name == "anthropic.claude-3-sonnet-20240229-v1:0"
        assert components[0].component_type == AIComponentType.CLOUD_SERVICE
        assert components[0].ecosystem == "aws"

    @patch("whitney.discovery.aws_ai.discover_aws_ai_services")
    def test_sagemaker_endpoints(self, mock_discover):
        mock_discover.return_value = {
            "bedrock": {"models": []},
            "sagemaker": {
                "endpoints": [{"name": "my-ml-endpoint"}],
                "models": [],
            },
            "lambda_ai": {"functions_with_ai_keys": []},
        }
        components = scan_aws_for_ai_components(None)
        assert len(components) == 1
        assert components[0].source == "aws:sagemaker/endpoint"


class TestScanAzureComponents:
    """Test Azure AI component discovery with mocked discovery."""

    @patch("whitney.discovery.azure_ai.discover_azure_ai_services")
    def test_openai_deployments(self, mock_discover):
        mock_discover.return_value = {
            "azure_openai": {
                "deployments": [{"name": "gpt4-deployment", "model": "gpt-4"}]
            },
            "azure_ml": {"workspaces": []},
            "cognitive_services": {"services": []},
        }
        components = scan_azure_for_ai_components(None)
        assert len(components) == 1
        assert components[0].name == "gpt4-deployment"
        assert components[0].ecosystem == "azure"
        assert components[0].source == "azure:openai"


# ---------------------------------------------------------------------------
# End-to-end: code-only scan
# ---------------------------------------------------------------------------


class TestScanAISBOMCodeOnly:
    """Test the code-only convenience orchestrator."""

    def test_end_to_end(self, tmp_path):
        write_file(tmp_path, "requirements.txt", "openai==1.3.0\nlangchain==0.0.300\n")
        write_file(tmp_path, "app.py", 'response = client.chat(model="gpt-4", messages=[])\n')
        result = scan_ai_sbom_code_only(tmp_path)

        assert result["bomFormat"] == "CycloneDX"
        assert len(result["components"]) >= 3  # 2 SDKs + 1 model
        assert len(result["vulnerabilities"]) >= 1  # langchain vuln

        # Verify component types present
        types = {c["type"] for c in result["components"]}
        assert "library" in types  # SDKs
        assert "framework" in types  # model

    def test_empty_repo(self, tmp_path):
        result = scan_ai_sbom_code_only(tmp_path)
        assert result["bomFormat"] == "CycloneDX"
        assert result["components"] == []
        assert result["vulnerabilities"] == []
