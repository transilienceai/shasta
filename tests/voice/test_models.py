from datetime import UTC, datetime

from shasta.voice.models import (
    ActionResult,
    ComplianceScoreView,
    ControlSummaryView,
    FindingDetailView,
    FindingSummary,
    MultiFrameworkScoreView,
    RiskItemView,
    ScanSummaryView,
    ScoreTrendView,
)


def test_finding_summary_minimal():
    f = FindingSummary(
        id="abc123",
        check_id="iam-mfa-enabled",
        title="MFA missing on user",
        severity="critical",
        status="fail",
        domain="iam",
        resource_id="arn:aws:iam::1:user/x",
        cloud_provider="aws",
        soc2_controls=["CC6.1"],
        iso27001_controls=[],
        hipaa_controls=[],
    )
    assert f.severity == "critical"
    assert f.soc2_controls == ["CC6.1"]


def test_finding_detail_extends_summary():
    d = FindingDetailView(
        id="abc123",
        check_id="iam-mfa-enabled",
        title="t",
        severity="critical",
        status="fail",
        domain="iam",
        resource_id="r",
        cloud_provider="aws",
        soc2_controls=[],
        iso27001_controls=[],
        hipaa_controls=[],
        description="desc",
        remediation="fix",
        region="us-east-1",
        account_id="1",
        details={"foo": "bar"},
        timestamp=datetime(2026, 5, 5, tzinfo=UTC),
    )
    assert d.description == "desc"
    assert d.details == {"foo": "bar"}


def test_compliance_score_view():
    s = ComplianceScoreView(
        framework="soc2",
        score_percentage=82.5,
        grade="B",
        total_controls=40,
        passing=30,
        failing=8,
        partial=2,
        not_assessed=0,
        total_findings=120,
        findings_failed=15,
    )
    assert s.framework == "soc2"
    assert s.score_percentage == 82.5


def test_multi_framework_score_view():
    m = MultiFrameworkScoreView(
        frameworks=[
            ComplianceScoreView(
                framework="soc2",
                score_percentage=82.5,
                grade="B",
                total_controls=40,
                passing=30,
                failing=8,
                partial=2,
                not_assessed=0,
                total_findings=120,
                findings_failed=15,
            ),
        ],
        not_enabled=["hipaa"],
    )
    assert len(m.frameworks) == 1
    assert m.not_enabled == ["hipaa"]


def test_score_trend_view():
    t = ScoreTrendView(
        framework="soc2",
        points=[
            {"scan_id": "s1", "completed_at": "2026-05-01T00:00:00Z", "score_percentage": 78.0},
            {"scan_id": "s2", "completed_at": "2026-05-04T00:00:00Z", "score_percentage": 82.5},
        ],
        delta=4.5,
    )
    assert t.delta == 4.5
    assert len(t.points) == 2


def test_control_summary_view():
    c = ControlSummaryView(
        framework="soc2",
        control_id="CC6.1",
        title="Logical access security",
        overall_status="fail",
        pass_count=2,
        fail_count=3,
        partial_count=1,
        finding_ids=["a", "b", "c"],
    )
    assert c.overall_status == "fail"
    assert c.fail_count == 3


def test_risk_item_view():
    r = RiskItemView(
        risk_id="R-001",
        title="t",
        description="d",
        category="cat",
        likelihood="medium",
        impact="high",
        risk_score=6,
        risk_level="high",
        treatment="mitigate",
        treatment_plan="plan",
        status="open",
        soc2_controls=["CC6.1"],
        related_finding=None,
    )
    assert r.risk_score == 6


def test_action_result():
    res = ActionResult(success=True, message="ok", record_id="R-001")
    assert res.success is True


def test_scan_summary_view():
    s = ScanSummaryView(
        scan_id="s1",
        account_id="1",
        cloud_provider="aws",
        completed_at=datetime(2026, 5, 5, tzinfo=UTC),
        total_findings=34,
        critical_count=4,
        high_count=11,
        medium_count=15,
        low_count=4,
        passed=20,
        failed=14,
    )
    assert s.total_findings == 34
