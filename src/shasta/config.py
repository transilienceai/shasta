"""Shasta configuration loader.

Reads shasta.config.json from the project root. This file is created
by the user during setup (or by /connect-aws on first run).

All scripts and skills use this module instead of hardcoding values.
"""

from __future__ import annotations

import json
import platform
import shutil
from pathlib import Path
from typing import Any

CONFIG_FILENAME = "shasta.config.json"


def _detect_python_cmd() -> str:
    """Detect the correct Python command for this platform."""
    if platform.system() == "Windows":
        # On Windows, 'py' is the standard launcher
        if shutil.which("py"):
            return "py"
        if shutil.which("python"):
            return "python"
    # Unix/macOS
    if shutil.which("python3"):
        return "python3"
    if shutil.which("python"):
        return "python"
    return "python3"


# Search upward from CWD to find config
def _find_config() -> Path | None:
    cwd = Path.cwd()
    for parent in [cwd, *cwd.parents]:
        candidate = parent / CONFIG_FILENAME
        if candidate.exists():
            return candidate
    return None


def load_config() -> dict[str, Any]:
    """Load shasta.config.json, returning defaults if not found."""
    defaults = {
        "aws_profile": "",
        "aws_region": "us-east-1",
        "azure_subscription_id": "",
        "azure_tenant_id": "",
        "azure_region": "",
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
            defaults.update({k: v for k, v in user_config.items() if v})
            return defaults
        except (json.JSONDecodeError, OSError):
            pass

    return defaults


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
