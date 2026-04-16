"""Core data models for Shasta compliance findings and evidence."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Finding severity levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ComplianceStatus(str, Enum):
    """Compliance status for a control or finding."""

    PASS = "pass"
    FAIL = "fail"
    PARTIAL = "partial"
    NOT_ASSESSED = "not_assessed"
    NOT_APPLICABLE = "not_applicable"


class CloudProvider(str, Enum):
    """Cloud provider for a finding or scan."""

    AWS = "aws"
    AZURE = "azure"


class CheckDomain(str, Enum):
    """Compliance check domains (cloud-agnostic)."""

    IAM = "iam"
    NETWORKING = "networking"
    ENCRYPTION = "encryption"
    LOGGING = "logging"
    COMPUTE = "compute"
    STORAGE = "storage"
    MONITORING = "monitoring"
    AI_GOVERNANCE = "ai_governance"


class Finding(BaseModel):
    """A single compliance finding from a cloud check.

    Each check function produces one or more Findings. A Finding represents
    a specific resource or configuration that was evaluated.
    """

    id: str = Field(default_factory=lambda: uuid4().hex[:12])

    @classmethod
    def not_assessed(
        cls,
        check_id: str,
        title: str,
        description: str,
        domain: "CheckDomain",
        resource_type: str,
        account_id: str,
        region: str,
        cloud_provider: "CloudProvider" = CloudProvider.AWS,  # type: ignore[assignment]
    ) -> "Finding":
        """Create a NOT_ASSESSED finding for when an API call fails.

        Use this instead of returning an empty list on error — empty lists
        are indistinguishable from 'no resources found', which produces
        false-clean reports.
        """
        return cls(
            check_id=check_id,
            title=title,
            description=description,
            severity=Severity.MEDIUM,
            status=ComplianceStatus.NOT_ASSESSED,
            domain=domain,
            resource_type=resource_type,
            resource_id="N/A",
            region=region,
            account_id=account_id,
            cloud_provider=cloud_provider,
        )
    check_id: str  # e.g., "iam-mfa-enabled", "azure-nsg-unrestricted-ingress"
    title: str  # Human-readable title
    description: str  # What was found
    severity: Severity
    status: ComplianceStatus
    domain: CheckDomain
    resource_type: str  # e.g., "AWS::IAM::User", "Azure::Network::NSG"
    resource_id: str  # ARN or Azure resource ID
    region: str
    account_id: str  # AWS account ID or Azure subscription ID
    cloud_provider: CloudProvider = CloudProvider.AWS
    remediation: str = ""  # Brief remediation guidance
    details: dict[str, Any] = Field(default_factory=dict)  # Raw evidence data
    soc2_controls: list[str] = Field(default_factory=list)  # e.g., ["CC6.1", "CC6.2"]
    cis_aws_controls: list[str] = Field(default_factory=list)  # e.g., ["1.4", "3.1"]
    cis_azure_controls: list[str] = Field(default_factory=list)  # e.g., ["1.1.4", "5.2.1"]
    mcsb_controls: list[str] = Field(default_factory=list)  # e.g., ["IM-6", "DP-5"]
    iso27001_controls: list[str] = Field(default_factory=list)  # e.g., ["A.8.5", "A.5.15"]
    hipaa_controls: list[str] = Field(default_factory=list)  # e.g., ["164.312(a)(1)", "164.312(e)(1)"]
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))


class ScanResult(BaseModel):
    """Result of a compliance scan across one or more domains."""

    id: str = Field(default_factory=lambda: uuid4().hex[:12])
    account_id: str  # AWS account ID or Azure subscription ID
    region: str
    cloud_provider: CloudProvider = CloudProvider.AWS
    domains_scanned: list[CheckDomain]
    findings: list[Finding] = Field(default_factory=list)
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime | None = None
    summary: ScanSummary | None = None

    def complete(self) -> None:
        """Mark the scan as completed and generate summary."""
        self.completed_at = datetime.now(UTC)
        self.summary = ScanSummary.from_findings(self.findings)


class ScanSummary(BaseModel):
    """Aggregated summary of scan findings."""

    total_findings: int = 0
    passed: int = 0
    failed: int = 0
    partial: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    by_domain: dict[str, dict[str, int]] = Field(default_factory=dict)
    by_soc2_control: dict[str, dict[str, int]] = Field(default_factory=dict)

    @classmethod
    def from_findings(cls, findings: list[Finding]) -> ScanSummary:
        summary = cls()
        summary.total_findings = len(findings)

        for f in findings:
            # Status counts
            if f.status == ComplianceStatus.PASS:
                summary.passed += 1
            elif f.status == ComplianceStatus.FAIL:
                summary.failed += 1
            elif f.status == ComplianceStatus.PARTIAL:
                summary.partial += 1

            # Severity counts
            match f.severity:
                case Severity.CRITICAL:
                    summary.critical_count += 1
                case Severity.HIGH:
                    summary.high_count += 1
                case Severity.MEDIUM:
                    summary.medium_count += 1
                case Severity.LOW:
                    summary.low_count += 1
                case Severity.INFO:
                    summary.info_count += 1

            # By domain
            domain = f.domain.value
            if domain not in summary.by_domain:
                summary.by_domain[domain] = {"pass": 0, "fail": 0, "partial": 0}
            if f.status in (ComplianceStatus.PASS, ComplianceStatus.FAIL, ComplianceStatus.PARTIAL):
                summary.by_domain[domain][f.status.value] += 1

            # By SOC2 control
            for ctrl in f.soc2_controls:
                if ctrl not in summary.by_soc2_control:
                    summary.by_soc2_control[ctrl] = {"pass": 0, "fail": 0, "partial": 0}
                if f.status in (
                    ComplianceStatus.PASS,
                    ComplianceStatus.FAIL,
                    ComplianceStatus.PARTIAL,
                ):
                    summary.by_soc2_control[ctrl][f.status.value] += 1

        return summary


class Evidence(BaseModel):
    """An evidence artifact collected for audit purposes.

    Evidence is a snapshot of an AWS resource state at a point in time,
    stored for auditor review.
    """

    id: str = Field(default_factory=lambda: uuid4().hex[:12])
    scan_id: str
    finding_id: str
    evidence_type: str  # "api_response", "config_snapshot", "policy_document"
    description: str
    data: dict[str, Any] = Field(default_factory=dict)
    collected_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
