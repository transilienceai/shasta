"""Shared test fixtures for voice tests — seeded SQLite at tmp_path."""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from shasta.db.schema import ShastaDB
from shasta.evidence.models import (
    CheckDomain,
    CloudProvider,
    ComplianceStatus,
    Finding,
    ScanResult,
    Severity,
)


def _ago(hours: float) -> datetime:
    return datetime.now(UTC) - timedelta(hours=hours)


def _make_finding(
    *,
    id: str,
    check_id: str,
    title: str,
    severity: Severity,
    status: ComplianceStatus,
    domain: CheckDomain,
    resource_id: str,
    soc2: list[str] | None = None,
    iso27001: list[str] | None = None,
    hipaa: list[str] | None = None,
    cloud: CloudProvider = CloudProvider.AWS,
    description: str = "desc",
    remediation: str = "fix",
) -> Finding:
    return Finding(
        id=id,
        check_id=check_id,
        title=title,
        description=description,
        severity=severity,
        status=status,
        domain=domain,
        resource_type="AWS::IAM::User",
        resource_id=resource_id,
        region="us-east-1",
        account_id="123456789012",
        cloud_provider=cloud,
        remediation=remediation,
        soc2_controls=soc2 or [],
        iso27001_controls=iso27001 or [],
        hipaa_controls=hipaa or [],
        timestamp=_ago(1),
    )


@pytest.fixture
def seeded_db_path(tmp_path: Path) -> Path:
    """Return a path to a fresh SQLite seeded with realistic scan + findings + risks."""
    db_path = tmp_path / "shasta-test.db"
    db = ShastaDB(db_path=db_path)
    db.initialize()

    findings = [
        # 4 critical, mixed clouds and frameworks
        _make_finding(id="f-001", check_id="iam-mfa-enabled", title="MFA missing on root",
                     severity=Severity.CRITICAL, status=ComplianceStatus.FAIL,
                     domain=CheckDomain.IAM, resource_id="arn:aws:iam::123:root",
                     soc2=["CC6.1"], iso27001=["A.5.15"], hipaa=["164.312(a)(1)"]),
        _make_finding(id="f-002", check_id="s3-public-access-block", title="S3 bucket allows public access",
                     severity=Severity.CRITICAL, status=ComplianceStatus.FAIL,
                     domain=CheckDomain.STORAGE, resource_id="arn:aws:s3:::prod-data",
                     soc2=["CC6.1", "CC6.6"], iso27001=["A.5.10"]),
        _make_finding(id="f-003", check_id="azure-sql-tls", title="SQL TLS below 1.2",
                     severity=Severity.CRITICAL, status=ComplianceStatus.FAIL,
                     domain=CheckDomain.ENCRYPTION, resource_id="/subscriptions/x/sql/y",
                     cloud=CloudProvider.AZURE, soc2=["CC6.7"]),
        _make_finding(id="f-004", check_id="cloudtrail-enabled", title="CloudTrail disabled in audit account",
                     severity=Severity.CRITICAL, status=ComplianceStatus.FAIL,
                     domain=CheckDomain.LOGGING, resource_id="arn:aws:cloudtrail::123:trail/audit",
                     soc2=["CC7.1", "CC7.2"]),
        # 3 high
        _make_finding(id="f-010", check_id="iam-stale-key", title="Stale IAM key >180d",
                     severity=Severity.HIGH, status=ComplianceStatus.FAIL,
                     domain=CheckDomain.IAM, resource_id="arn:aws:iam::123:user/legacy-bot",
                     soc2=["CC6.3"]),
        _make_finding(id="f-011", check_id="sg-open-22", title="Security group open on 22",
                     severity=Severity.HIGH, status=ComplianceStatus.FAIL,
                     domain=CheckDomain.NETWORKING, resource_id="sg-0e1f2a3b",
                     soc2=["CC6.6"]),
        _make_finding(id="f-012", check_id="lambda-perm-role", title="Lambda overly permissive role",
                     severity=Severity.HIGH, status=ComplianceStatus.FAIL,
                     domain=CheckDomain.IAM, resource_id="arn:aws:lambda::123:function/proc",
                     soc2=["CC6.1"]),
        # 3 medium, mixed status
        _make_finding(id="f-020", check_id="s3-versioning", title="S3 versioning off",
                     severity=Severity.MEDIUM, status=ComplianceStatus.FAIL,
                     domain=CheckDomain.STORAGE, resource_id="arn:aws:s3:::dev-build"),
        _make_finding(id="f-021", check_id="ebs-encryption-default", title="EBS default encryption",
                     severity=Severity.MEDIUM, status=ComplianceStatus.PASS,
                     domain=CheckDomain.ENCRYPTION, resource_id="ebs-default",
                     soc2=["CC6.7"]),
        _make_finding(id="f-022", check_id="vpc-flow-logs", title="VPC flow logs off",
                     severity=Severity.MEDIUM, status=ComplianceStatus.PARTIAL,
                     domain=CheckDomain.MONITORING, resource_id="vpc-abc",
                     soc2=["CC7.2"]),
    ]

    scan = ScanResult(
        id="scan-test-001",
        account_id="123456789012",
        region="us-east-1",
        cloud_provider=CloudProvider.AWS,
        domains_scanned=[CheckDomain.IAM, CheckDomain.STORAGE, CheckDomain.NETWORKING,
                         CheckDomain.ENCRYPTION, CheckDomain.LOGGING, CheckDomain.MONITORING],
        findings=findings,
        started_at=_ago(2),
    )
    scan.complete()
    db.save_scan(scan)

    # Save an older scan too so trend queries have at least 2 datapoints
    older_findings = [
        _make_finding(id=f"old-{f.id}", check_id=f.check_id, title=f.title,
                      severity=f.severity, status=f.status, domain=f.domain,
                      resource_id=f.resource_id, soc2=f.soc2_controls,
                      iso27001=f.iso27001_controls, hipaa=f.hipaa_controls)
        for f in findings[:7]  # fewer findings = different score
    ]
    older_scan = ScanResult(
        id="scan-test-old",
        account_id="123456789012",
        region="us-east-1",
        cloud_provider=CloudProvider.AWS,
        domains_scanned=[CheckDomain.IAM, CheckDomain.STORAGE],
        findings=older_findings,
        started_at=_ago(72),
    )
    older_scan.complete()
    db.save_scan(older_scan)

    db.close()
    return db_path


@pytest.fixture
def store(seeded_db_path: Path):
    """Convenience: a Store instance pointed at the seeded DB."""
    from shasta.voice.store import Store
    s = Store(db_path=seeded_db_path)
    yield s
    s.close()


@pytest.fixture
def client(seeded_db_path: Path):
    """FastAPI TestClient bound to the seeded DB."""
    import os
    os.environ.setdefault("OPENAI_API_KEY", "test-key")
    os.environ.setdefault("ALLOWED_ORIGINS", "http://localhost:8090")
    from fastapi.testclient import TestClient

    from shasta.voice.app import create_app
    app = create_app(db_path=seeded_db_path, serve_static=False)
    return TestClient(app)
