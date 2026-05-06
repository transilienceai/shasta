from shasta.voice.store import Store
from shasta.voice.tools import scores as scores_tool


def test_get_compliance_score_soc2(store: Store):
    res = scores_tool.get_compliance_score(store=store, framework="soc2")
    assert res["framework"] == "soc2"
    assert "score_percentage" in res


def test_get_compliance_score_unknown_framework_returns_error(store: Store):
    res = scores_tool.get_compliance_score(store=store, framework="bogus")
    assert "error" in res


def test_get_multi_framework_score(store: Store):
    res = scores_tool.get_multi_framework_score(store=store)
    assert "frameworks" in res
    assert isinstance(res["frameworks"], list)


def test_get_score_trend(store: Store):
    res = scores_tool.get_score_trend(store=store, framework="soc2", limit=10)
    assert res["framework"] == "soc2"
    assert "delta" in res
    assert "points" in res
