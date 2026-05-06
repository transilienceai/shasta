
from shasta.voice.store import Store


def test_get_latest_scan_summary(store: Store):
    s = store.get_latest_scan()
    assert s is not None
    assert s.scan_id == "scan-test-001"
    assert s.total_findings == 10
    assert s.critical_count == 4


def test_list_findings_unfiltered(store: Store):
    findings = store.list_findings()
    assert len(findings) == 10


def test_list_findings_severity_critical(store: Store):
    findings = store.list_findings(severity="critical")
    assert len(findings) == 4
    assert all(f.severity == "critical" for f in findings)


def test_list_findings_status_fail(store: Store):
    findings = store.list_findings(status="fail")
    assert len(findings) == 8
    assert all(f.status == "fail" for f in findings)


def test_list_findings_cloud_azure(store: Store):
    findings = store.list_findings(cloud="azure")
    assert len(findings) == 1
    assert findings[0].id == "f-003"


def test_list_findings_framework_soc2(store: Store):
    findings = store.list_findings(framework="soc2")
    assert all(f.soc2_controls for f in findings)


def test_list_findings_control_id(store: Store):
    findings = store.list_findings(framework="soc2", control_id="CC6.1")
    assert all("CC6.1" in f.soc2_controls for f in findings)
    assert len(findings) == 3


def test_list_findings_limit(store: Store):
    findings = store.list_findings(limit=3)
    assert len(findings) == 3


def test_get_finding_known(store: Store):
    f = store.get_finding("f-001")
    assert f is not None
    assert f.title == "MFA missing on root"
    assert f.description == "desc"


def test_get_finding_unknown(store: Store):
    assert store.get_finding("does-not-exist") is None


def test_list_top_blockers_default(store: Store):
    blockers = store.list_top_blockers()
    assert len(blockers) == 5
    # Sorted by severity (critical > high > medium), then status=fail first
    assert blockers[0].severity == "critical"


def test_get_resource_findings(store: Store):
    findings = store.get_resource_findings("arn:aws:s3:::prod-data")
    assert len(findings) == 1
    assert findings[0].id == "f-002"


def test_get_compliance_score_soc2(store: Store):
    score = store.get_compliance_score("soc2")
    assert score.framework == "soc2"
    assert 0 <= score.score_percentage <= 100
    assert score.grade in ("A", "B", "C", "D", "F")


def test_get_multi_framework_score(store: Store):
    multi = store.get_multi_framework_score()
    frameworks_present = {s.framework for s in multi.frameworks}
    assert "soc2" in frameworks_present


def test_get_score_trend_soc2(store: Store):
    trend = store.get_score_trend("soc2", limit=10)
    assert trend.framework == "soc2"
    assert len(trend.points) >= 2


def test_get_control_summary_soc2_specific(store: Store):
    summaries = store.get_control_summary("soc2", control_id="CC6.1")
    assert len(summaries) == 1
    assert summaries[0].control_id == "CC6.1"
    assert summaries[0].fail_count >= 1


def test_get_control_summary_soc2_all(store: Store):
    summaries = store.get_control_summary("soc2")
    assert len(summaries) >= 1


def test_list_scans(store: Store):
    scans = store.list_scans(limit=10)
    assert len(scans) == 2
    # Most recent first
    assert scans[0].scan_id == "scan-test-001"
