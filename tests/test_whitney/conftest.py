"""Shared fixtures and helpers for Whitney tests."""

from __future__ import annotations

from pathlib import Path

from shasta.evidence.models import (
    CheckDomain,
    CloudProvider,
    ComplianceStatus,
    Finding,
    Severity,
)


def _make_finding(
    check_id: str,
    status: ComplianceStatus,
    severity: Severity = Severity.HIGH,
    domain: CheckDomain = CheckDomain.AI_GOVERNANCE,
    resource_type: str = "AI::Code::Repository",
    resource_id: str = "repo://test-repo",
    region: str = "us-east-1",
    account_id: str = "123456789012",
    cloud_provider: CloudProvider = CloudProvider.AWS,
    details: dict | None = None,
) -> Finding:
    """Helper to create a Finding with AI governance defaults."""
    return Finding(
        check_id=check_id,
        title=f"Test finding: {check_id}",
        description=f"Description for {check_id}",
        severity=severity,
        status=status,
        domain=domain,
        resource_type=resource_type,
        resource_id=resource_id,
        region=region,
        account_id=account_id,
        cloud_provider=cloud_provider,
        details=details or {},
    )


def write_file(base: Path, relative_path: str, content: str) -> Path:
    """Create a file in a temporary repo with specific content."""
    filepath = base / relative_path
    filepath.parent.mkdir(parents=True, exist_ok=True)
    filepath.write_text(content, encoding="utf-8")
    return filepath
