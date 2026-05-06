from shasta.voice.store import Store
from shasta.voice.tools import scans as scans_tool


def test_list_scans(store: Store):
    res = scans_tool.list_scans(store=store, limit=10)
    assert isinstance(res, list)
    assert len(res) == 2


def test_get_latest_scan(store: Store):
    res = scans_tool.get_latest_scan(store=store)
    assert res["scan_id"] == "scan-test-001"
