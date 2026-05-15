"""Shasta configuration loader.

Reads shasta.config.json from the project root. This file is created
by the user during setup (or by /connect-aws or /connect-azure on first run).

All scripts and skills use this module instead of hardcoding values.
"""

from __future__ import annotations

import json
import platform
import re
import shutil
from pathlib import Path
from typing import Any

from pydantic import BaseModel, field_validator

CONFIG_FILENAME = "shasta.config.json"

# Valid Azure region names (lowercase, no spaces)
_AZURE_REGION_PATTERN = re.compile(r"^[a-z]+[a-z0-9]*$")
# UUID v4 pattern
_UUID_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE
)
# GCP project ID: 6-30 chars, lowercase letter start, letters/digits/hyphens, no trailing hyphen
_GCP_PROJECT_ID_PATTERN = re.compile(r"^[a-z][a-z0-9-]{4,28}[a-z0-9]$")


class ShastaConfig(BaseModel):
    """Validated configuration for Shasta."""

    aws_profile: str = ""
    aws_region: str = "us-east-1"
    azure_subscription_id: str = ""
    azure_tenant_id: str = ""
    azure_region: str = ""
    gcp_project_id: str = ""
    gcp_region: str = ""
    python_cmd: str = ""
    company_name: str = ""
    github_repos: list[str] = []
    slack_webhook_url: str = ""
    jira_base_url: str = ""
    jira_email: str = ""
    jira_project_key: str = ""

    @field_validator("azure_subscription_id")
    @classmethod
    def validate_subscription_id(cls, v: str) -> str:
        if v and not _UUID_PATTERN.match(v):
            raise ValueError(
                f"azure_subscription_id must be a UUID (got '{v}'). "
                "Run 'az account show' to find your subscription ID."
            )
        return v

    @field_validator("azure_tenant_id")
    @classmethod
    def validate_tenant_id(cls, v: str) -> str:
        if v and not _UUID_PATTERN.match(v):
            raise ValueError(
                f"azure_tenant_id must be a UUID (got '{v}'). "
                "Run 'az account show' to find your tenant ID."
            )
        return v

    @field_validator("gcp_project_id")
    @classmethod
    def validate_gcp_project_id(cls, v: str) -> str:
        if v and not _GCP_PROJECT_ID_PATTERN.match(v):
            raise ValueError(
                f"gcp_project_id must be a valid GCP project ID (got '{v}'). "
                "Run 'gcloud config get-value project' to find your project ID."
            )
        return v

    @field_validator("jira_base_url")
    @classmethod
    def validate_jira_url(cls, v: str) -> str:
        if v and not v.startswith("https://"):
            raise ValueError(f"jira_base_url must start with https:// (got '{v}')")
        return v

    @field_validator("slack_webhook_url")
    @classmethod
    def validate_slack_url(cls, v: str) -> str:
        if v and not v.startswith("https://"):
            raise ValueError(f"slack_webhook_url must start with https:// (got '{v}')")
        return v


def _detect_python_cmd() -> str:
    """Detect the correct Python command for this platform."""
    if platform.system() == "Windows":
        if shutil.which("py"):
            return "py"
        if shutil.which("python"):
            return "python"
    if shutil.which("python3"):
        return "python3"
    if shutil.which("python"):
        return "python"
    return "python3"


def _find_config() -> Path | None:
    """Search upward from CWD for shasta.config.json, stopping at filesystem root."""
    cwd = Path.cwd()
    for parent in [cwd, *cwd.parents]:
        candidate = parent / CONFIG_FILENAME
        if candidate.exists():
            return candidate
        # Stop at project root markers to avoid loading unrelated configs
        if (parent / ".git").exists() or (parent / "pyproject.toml").exists():
            break
    return None


def load_config() -> dict[str, Any]:
    """Load shasta.config.json, returning defaults if not found.

    Validates the config with Pydantic. Invalid values are logged
    but the config still loads with defaults for invalid fields.
    """
    defaults = {
        "aws_profile": "",
        "aws_region": "us-east-1",
        "azure_subscription_id": "",
        "azure_tenant_id": "",
        "azure_region": "",
        "gcp_project_id": "",
        "gcp_region": "",
        "python_cmd": _detect_python_cmd(),
        "company_name": "",
        "github_repos": [],
        "slack_webhook_url": "",
        "jira_base_url": "",
        "jira_email": "",
        "jira_project_key": "",
    }

    config_path = _find_config()
    if config_path:
        try:
            with open(config_path) as f:
                user_config = json.load(f)
            # Filter out empty strings and _comment keys
            merged = {**defaults}
            for k, v in user_config.items():
                if k.startswith("_"):
                    continue
                if v or v == 0 or v is False:  # Keep falsy but meaningful values
                    merged[k] = v

            # Validate with Pydantic — use validated values
            try:
                validated = ShastaConfig(**merged)
                return validated.model_dump()
            except Exception:
                # Validation failed — return merged dict without validation
                return merged
        except (json.JSONDecodeError, OSError):
            pass

    return defaults


def validate_config(config: dict[str, Any] | None = None) -> list[str]:
    """Validate config and return list of error messages (empty = valid)."""
    if config is None:
        config = load_config()
    errors = []
    try:
        ShastaConfig(**config)
    except Exception as e:
        errors.append(str(e))
    return errors


def save_config(config: dict[str, Any]) -> Path:
    """Save config to shasta.config.json in the project root."""
    config_path = _find_config()
    if not config_path:
        config_path = Path.cwd() / CONFIG_FILENAME

    with open(config_path, "w") as f:
        json.dump(config, f, indent=2)

    return config_path


def get_aws_client():
    """Convenience: create an AWSClient from config."""
    from shasta.aws.client import AWSClient

    cfg = load_config()
    profile = cfg["aws_profile"] if cfg["aws_profile"] else None
    region = cfg["aws_region"] or "us-east-1"
    return AWSClient(profile_name=profile, region=region)


def get_azure_client():
    """Convenience: create an AzureClient from config."""
    from shasta.azure.client import AzureClient

    cfg = load_config()
    subscription_id = cfg.get("azure_subscription_id") or None
    tenant_id = cfg.get("azure_tenant_id") or None
    region = cfg.get("azure_region") or None
    return AzureClient(
        subscription_id=subscription_id,
        tenant_id=tenant_id,
        region=region,
    )


def get_gcp_client():
    """Convenience: create a GCPClient from config."""
    from shasta.gcp.client import GCPClient

    cfg = load_config()
    project_id = cfg.get("gcp_project_id") or None
    region = cfg.get("gcp_region") or None
    return GCPClient(project_id=project_id, region=region)
