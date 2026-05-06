from shasta.voice.store import Store
from shasta.voice.tools import findings as findings_tool


def test_list_findings_returns_dicts(store: Store):
    result = findings_tool.list_findings(store=store)
    assert isinstance(result, list)
    assert all(isinstance(item, dict) for item in result)
    assert all("severity" in item for item in result)


def test_list_findings_with_filters(store: Store):
    result = findings_tool.list_findings(store=store, severity="critical", status="fail")
    assert len(result) == 4


def test_get_finding_known(store: Store):
    result = findings_tool.get_finding(store=store, finding_id="f-001")
    assert result["id"] == "f-001"
    assert "description" in result


def test_get_finding_unknown_returns_error(store: Store):
    result = findings_tool.get_finding(store=store, finding_id="nope")
    assert result == {"error": "finding_not_found", "finding_id": "nope"}


def test_list_top_blockers(store: Store):
    result = findings_tool.list_top_blockers(store=store)
    assert len(result) == 5


def test_get_resource_findings_unknown_returns_empty_list(store: Store):
    result = findings_tool.get_resource_findings(store=store, resource_id="not-here")
    assert result == []
