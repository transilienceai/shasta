"""Tests for data models and SQLite persistence."""

from transilience_compliance.evidence.models import (
    CheckDomain,
    ComplianceStatus,
    Evidence,
    Finding,
    ScanResult,
    ScanSummary,
    Severity,
)


def test_finding_creation():
    """Test creating a finding with required fields."""
    f = Finding(
        check_id="iam-mfa-enabled",
        title="MFA not enabled for IAM user",
        description="IAM user 'dev-user' does not have MFA enabled",
        severity=Severity.HIGH,
        status=ComplianceStatus.FAIL,
        domain=CheckDomain.IAM,
        resource_type="AWS::IAM::User",
        resource_id="arn:aws:iam::123456789012:user/dev-user",
        region="us-east-1",
        account_id="123456789012",
        soc2_controls=["CC6.1"],
    )

    assert f.id  # auto-generated
    assert f.check_id == "iam-mfa-enabled"
    assert f.severity == Severity.HIGH
    assert f.status == ComplianceStatus.FAIL
    assert "CC6.1" in f.soc2_controls


def test_scan_summary_from_findings():
    """Test summary generation from a list of findings."""
    findings = [
        Finding(
            check_id="iam-mfa",
            title="MFA check",
            description="pass",
            severity=Severity.HIGH,
            status=ComplianceStatus.PASS,
            domain=CheckDomain.IAM,
            resource_type="AWS::IAM::User",
            resource_id="user1",
            region="us-east-1",
            account_id="123",
            soc2_controls=["CC6.1"],
        ),
        Finding(
            check_id="iam-stale-key",
            title="Stale key",
            description="fail",
            severity=Severity.CRITICAL,
            status=ComplianceStatus.FAIL,
            domain=CheckDomain.IAM,
            resource_type="AWS::IAM::AccessKey",
            resource_id="key1",
            region="us-east-1",
            account_id="123",
            soc2_controls=["CC6.3"],
        ),
        Finding(
            check_id="s3-encryption",
            title="S3 encryption",
            description="partial",
            severity=Severity.MEDIUM,
            status=ComplianceStatus.PARTIAL,
            domain=CheckDomain.STORAGE,
            resource_type="AWS::S3::Bucket",
            resource_id="bucket1",
            region="us-east-1",
            account_id="123",
            soc2_controls=["CC6.7"],
        ),
    ]

    summary = ScanSummary.from_findings(findings)

    assert summary.total_findings == 3
    assert summary.passed == 1
    assert summary.failed == 1
    assert summary.partial == 1
    assert summary.critical_count == 1
    assert summary.high_count == 1
    assert summary.medium_count == 1
    assert summary.by_domain["iam"]["pass"] == 1
    assert summary.by_domain["iam"]["fail"] == 1
    assert summary.by_soc2_control["CC6.1"]["pass"] == 1


def test_scan_result_complete():
    """Test completing a scan generates summary."""
    scan = ScanResult(
        account_id="123",
        region="us-east-1",
        domains_scanned=[CheckDomain.IAM],
    )
    scan.findings.append(
        Finding(
            check_id="test",
            title="Test",
            description="test",
            severity=Severity.LOW,
            status=ComplianceStatus.PASS,
            domain=CheckDomain.IAM,
            resource_type="test",
            resource_id="test",
            region="us-east-1",
            account_id="123",
        )
    )
    scan.complete()

    assert scan.completed_at is not None
    assert scan.summary is not None
    assert scan.summary.total_findings == 1
    assert scan.summary.passed == 1


def test_db_round_trip(db):
    """Test saving and retrieving a scan from the database."""
    scan = ScanResult(
        account_id="123456789012",
        region="us-east-1",
        domains_scanned=[CheckDomain.IAM],
    )
    scan.findings.append(
        Finding(
            check_id="iam-mfa",
            title="MFA Check",
            description="MFA enabled",
            severity=Severity.HIGH,
            status=ComplianceStatus.PASS,
            domain=CheckDomain.IAM,
            resource_type="AWS::IAM::User",
            resource_id="user1",
            region="us-east-1",
            account_id="123456789012",
            soc2_controls=["CC6.1"],
        )
    )
    scan.complete()

    db.save_scan(scan)

    loaded = db.get_latest_scan("123456789012")
    assert loaded is not None
    assert loaded.id == scan.id
    assert len(loaded.findings) == 1
    assert loaded.findings[0].check_id == "iam-mfa"
    assert loaded.summary is not None
