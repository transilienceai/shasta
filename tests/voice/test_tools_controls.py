from shasta.voice.store import Store
from shasta.voice.tools import controls as controls_tool


def test_get_control_summary_specific(store: Store):
    res = controls_tool.get_control_summary(store=store, framework="soc2", control_id="CC6.1")
    assert isinstance(res, list)
    assert len(res) == 1
    assert res[0]["control_id"] == "CC6.1"


def test_get_control_summary_all(store: Store):
    res = controls_tool.get_control_summary(store=store, framework="soc2")
    assert isinstance(res, list)
    assert len(res) >= 1
