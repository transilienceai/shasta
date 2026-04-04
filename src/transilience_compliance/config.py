"""Configuration loader for Transilience Community Compliance.

Primary config file: ``config.toml`` in the current working directory or
any parent directory. Legacy ``shasta.config.json`` files are still read so
existing local setups can migrate without breaking.
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import tomllib
from pathlib import Path
from typing import Any

CONFIG_FILENAME = "config.toml"
LEGACY_CONFIG_FILENAME = "shasta.config.json"
CONFIG_ENV_VAR = "TRANSILIENCE_COMPLIANCE_CONFIG"


def _detect_python_cmd() -> str:
    """Detect the best Python launcher for the current platform."""
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


def _default_config() -> dict[str, Any]:
    return {
        "aws_profile": "",
        "aws_region": "us-east-1",
        "company_name": "Acme Corp",
        "github_repos": [],
        "slack_webhook_url": "",
        "jira_base_url": "",
        "jira_email": "",
        "jira_project_key": "",
        "output_dir": "data",
        "python_cmd": _detect_python_cmd(),
    }


def resolve_config_path(explicit_path: str | Path | None = None) -> Path | None:
    """Locate the active config file.

    Resolution order:
    1. Explicit path
    2. ``TRANSILIENCE_COMPLIANCE_CONFIG`` environment variable
    3. ``config.toml`` or legacy ``shasta.config.json`` in CWD or any parent
    """
    candidates: list[Path] = []

    if explicit_path:
        candidates.append(Path(explicit_path).expanduser())

    env_value = os.environ.get(CONFIG_ENV_VAR)
    if env_value:
        candidates.append(Path(env_value).expanduser())

    cwd = Path.cwd()
    for parent in [cwd, *cwd.parents]:
        candidates.append(parent / CONFIG_FILENAME)
        candidates.append(parent / LEGACY_CONFIG_FILENAME)

    for candidate in candidates:
        if candidate.exists():
            return candidate.resolve()
    return None


def load_config(config_path: str | Path | None = None) -> dict[str, Any]:
    """Load configuration from TOML or legacy JSON."""
    defaults = _default_config()
    resolved = resolve_config_path(config_path)
    if not resolved:
        return defaults

    try:
        if resolved.suffix == ".json":
            with resolved.open(encoding="utf-8") as handle:
                user_config = json.load(handle)
        else:
            with resolved.open("rb") as handle:
                user_config = tomllib.load(handle)
    except (OSError, json.JSONDecodeError, tomllib.TOMLDecodeError):
        return defaults

    defaults.update({key: value for key, value in user_config.items() if value not in ("", None, [])})
    return defaults


def _toml_value(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, list):
        quoted = ", ".join(json.dumps(item) for item in value)
        return f"[{quoted}]"
    return json.dumps("" if value is None else str(value))


def save_config(config: dict[str, Any], config_path: str | Path | None = None) -> Path:
    """Save configuration to ``config.toml``."""
    resolved = resolve_config_path(config_path)
    target = Path(config_path).expanduser() if config_path else resolved
    if target is None or target.suffix == ".json":
        target = Path.cwd() / CONFIG_FILENAME

    serialized = "\n".join(
        [
            "# Transilience Community Compliance configuration",
            f'aws_profile = {_toml_value(config.get("aws_profile", ""))}',
            f'aws_region = {_toml_value(config.get("aws_region", "us-east-1"))}',
            f'company_name = {_toml_value(config.get("company_name", "Acme Corp"))}',
            f'output_dir = {_toml_value(config.get("output_dir", "data"))}',
            f'github_repos = {_toml_value(config.get("github_repos", []))}',
            f'slack_webhook_url = {_toml_value(config.get("slack_webhook_url", ""))}',
            f'jira_base_url = {_toml_value(config.get("jira_base_url", ""))}',
            f'jira_email = {_toml_value(config.get("jira_email", ""))}',
            f'jira_project_key = {_toml_value(config.get("jira_project_key", ""))}',
            f'python_cmd = {_toml_value(config.get("python_cmd", _detect_python_cmd()))}',
            "",
        ]
    )
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(serialized, encoding="utf-8")
    return target


def get_aws_client(config_path: str | Path | None = None):
    """Create an ``AWSClient`` using the active configuration."""
    from transilience_compliance.aws.client import AWSClient

    cfg = load_config(config_path)
    profile = cfg["aws_profile"] if cfg.get("aws_profile") else None
    region = cfg.get("aws_region") or "us-east-1"
    return AWSClient(profile_name=profile, region=region)

