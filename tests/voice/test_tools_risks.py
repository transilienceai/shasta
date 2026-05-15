from shasta.voice.store import Store
from shasta.voice.tools import risks as risks_tool


def test_list_risk_items_empty(store: Store):
    assert risks_tool.list_risk_items(store=store, account_id="123456789012") == []


def test_add_risk_item_success(store: Store):
    res = risks_tool.add_risk_item(
        store=store,
        account_id="123456789012",
        title="t",
        description="d",
        category="iam",
        likelihood="medium",
        impact="high",
        treatment="mitigate",
    )
    assert res["success"] is True
    assert res["record_id"]


def test_get_risk_item_known(store: Store):
    add = risks_tool.add_risk_item(
        store=store,
        account_id="123456789012",
        title="t",
        description="d",
        category="iam",
        likelihood="low",
        impact="low",
        treatment="accept",
    )
    res = risks_tool.get_risk_item(store=store, risk_id=add["record_id"])
    assert res["risk_id"] == add["record_id"]


def test_get_risk_item_unknown_returns_error(store: Store):
    res = risks_tool.get_risk_item(store=store, risk_id="R-NOPE")
    assert res == {"error": "risk_not_found", "risk_id": "R-NOPE"}


def test_update_risk(store: Store):
    add = risks_tool.add_risk_item(
        store=store,
        account_id="123456789012",
        title="t",
        description="d",
        category="iam",
        likelihood="low",
        impact="low",
        treatment="accept",
    )
    upd = risks_tool.update_risk(store=store, risk_id=add["record_id"], status="resolved")
    assert upd["success"] is True
