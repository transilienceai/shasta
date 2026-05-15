"""Pydantic I/O models for voice tools — JSON-serializable views over Shasta core models."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

Severity = Literal["critical", "high", "medium", "low", "info"]
Status = Literal["pass", "fail", "partial", "not_assessed", "not_applicable"]
Cloud = Literal["aws", "azure"]
Framework = Literal["soc2", "iso27001", "hipaa", "iso42001", "eu_ai_act", "ai_governance"]


class FindingSummary(BaseModel):
    id: str
    check_id: str
    title: str
    severity: Severity
    status: Status
    domain: str
    resource_id: str
    cloud_provider: Cloud
    soc2_controls: list[str] = Field(default_factory=list)
    iso27001_controls: list[str] = Field(default_factory=list)
    hipaa_controls: list[str] = Field(default_factory=list)


class FindingDetailView(FindingSummary):
    description: str
    remediation: str = ""
    region: str
    account_id: str
    details: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime


class ComplianceScoreView(BaseModel):
    framework: Framework
    score_percentage: float
    grade: str
    total_controls: int
    passing: int
    failing: int
    partial: int
    not_assessed: int
    total_findings: int
    findings_failed: int


class MultiFrameworkScoreView(BaseModel):
    frameworks: list[ComplianceScoreView] = Field(default_factory=list)
    not_enabled: list[Framework] = Field(default_factory=list)


class ScoreTrendView(BaseModel):
    framework: Framework
    points: list[dict[str, Any]] = Field(default_factory=list)
    delta: float  # latest - earliest


class ControlSummaryView(BaseModel):
    framework: Framework
    control_id: str
    title: str
    overall_status: str
    pass_count: int
    fail_count: int
    partial_count: int
    finding_ids: list[str] = Field(default_factory=list)


class RiskItemView(BaseModel):
    risk_id: str
    title: str
    description: str
    category: str
    likelihood: str
    impact: str
    risk_score: int
    risk_level: str
    treatment: str
    treatment_plan: str | None = None
    status: str
    soc2_controls: list[str] = Field(default_factory=list)
    related_finding: str | None = None


class ScanSummaryView(BaseModel):
    scan_id: str
    account_id: str
    cloud_provider: Cloud
    completed_at: datetime | None
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    passed: int
    failed: int


class ActionResult(BaseModel):
    success: bool
    message: str
    record_id: str | None = None
