"""Trust center configuration.

All branding, section toggles, and theming in one Pydantic model.
Defaults are sensible for a startup with SOC 2 + ISO 27001 in scope.
Override via TrustCenterConfig constructor or trust-center.config.json.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class TrustCenterConfig:
    """Configuration for the trust center page."""

    # Branding
    company_name: str = ""
    company_tagline: str = "Enterprise-grade security for your data"
    logo_url: str = ""  # URL or empty for text-only header
    contact_email: str = ""
    dpo_email: str = ""
    privacy_url: str = ""

    # Section toggles (Engineering Principle #8: configuration table)
    show_soc2: bool = True
    show_iso27001: bool = True
    show_hipaa: bool = False  # opt-in (many startups don't need HIPAA)
    show_controls_summary: bool = True
    show_policies: bool = True
    show_data_protection: bool = True
    show_infrastructure: bool = True
    show_subprocessors: bool = True

    # Theming
    primary_color: str = "#6366f1"  # Indigo (matches existing dashboard)
    accent_color: str = "#10b981"  # Emerald green for pass states

    # Subprocessors (manually entered, not from scan data)
    subprocessors: list[dict[str, str]] = field(default_factory=list)
    # Each: {"name": "AWS", "purpose": "Cloud infrastructure", "location": "US"}


def load_config(
    overrides: TrustCenterConfig | None = None,
    config_path: Path | str = "trust-center.config.json",
    shasta_config_path: Path | str = "shasta.config.json",
) -> TrustCenterConfig:
    """Load trust center config with layered defaults.

    Priority: explicit overrides > trust-center.config.json > shasta.config.json > defaults.
    """
    config = overrides or TrustCenterConfig()

    # Layer 1: pull company_name from shasta.config.json if not set
    if not config.company_name:
        try:
            shasta_cfg = json.loads(Path(shasta_config_path).read_text(encoding="utf-8"))
            config.company_name = shasta_cfg.get("company_name", "")
        except (FileNotFoundError, json.JSONDecodeError):
            pass

    # Layer 2: overlay with trust-center.config.json if it exists
    try:
        tc_cfg = json.loads(Path(config_path).read_text(encoding="utf-8"))
        for key, value in tc_cfg.items():
            if hasattr(config, key):
                setattr(config, key, value)
    except (FileNotFoundError, json.JSONDecodeError):
        pass

    # Fallback: if still no company name, use a placeholder
    if not config.company_name:
        config.company_name = "Your Company"

    return config
