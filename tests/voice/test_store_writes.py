"""Tests for Store write methods — risk register operations."""

from shasta.voice.store import Store


def test_list_risk_items_empty(store: Store):
    items = store.list_risk_items(account_id="123456789012")
    assert items == []


def test_add_risk_item_then_list(store: Store):
    res = store.add_risk_item(
        account_id="123456789012",
        title="Unblock CloudTrail",
        description="CloudTrail must be on across all regions",
        category="logging",
        likelihood="medium",
        impact="high",
        treatment="mitigate",
        treatment_plan="Enable CloudTrail in audit account",
        related_finding="f-004",
    )
    assert res.success is True
    assert res.record_id is not None

    items = store.list_risk_items(account_id="123456789012")
    assert len(items) == 1
    assert items[0].title == "Unblock CloudTrail"
    assert items[0].risk_score >= 1


def test_get_risk_item_by_id(store: Store):
    res = store.add_risk_item(
        account_id="123456789012",
        title="t",
        description="d",
        category="iam",
        likelihood="low",
        impact="medium",
        treatment="accept",
    )
    r = store.get_risk_item(res.record_id)
    assert r is not None
    assert r.risk_id == res.record_id


def test_update_risk_status(store: Store):
    res = store.add_risk_item(
        account_id="123456789012",
        title="t",
        description="d",
        category="iam",
        likelihood="low",
        impact="medium",
        treatment="accept",
    )
    upd = store.update_risk(risk_id=res.record_id, status="resolved", review_notes="closed")
    assert upd.success is True
    r = store.get_risk_item(res.record_id)
    assert r.status == "resolved"


def test_update_risk_treatment(store: Store):
    res = store.add_risk_item(
        account_id="123456789012",
        title="t",
        description="d",
        category="iam",
        likelihood="low",
        impact="medium",
        treatment="accept",
    )
    upd = store.update_risk(risk_id=res.record_id, treatment="mitigate", treatment_plan="new plan")
    assert upd.success is True


def test_update_risk_unknown_fails(store: Store):
    res = store.update_risk(risk_id="R-NOT-EXIST", status="resolved")
    assert res.success is False
