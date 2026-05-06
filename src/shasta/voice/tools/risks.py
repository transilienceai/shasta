"""Tool functions for risk-register operations."""
from typing import Any

from shasta.voice.store import Store


def list_risk_items(*, store: Store, account_id: str, status: str | None = None, level: str | None = None) -> list[dict[str, Any]]:
    return [r.model_dump(mode="json") for r in store.list_risk_items(account_id, status=status, level=level)]


def get_risk_item(*, store: Store, risk_id: str, account_id: str = "123456789012") -> dict[str, Any]:
    r = store.get_risk_item(risk_id, account_id=account_id)
    if r is None:
        return {"error": "risk_not_found", "risk_id": risk_id}
    return r.model_dump(mode="json")


def add_risk_item(
    *,
    store: Store,
    account_id: str,
    title: str,
    description: str,
    category: str,
    likelihood: str,
    impact: str,
    treatment: str,
    treatment_plan: str | None = None,
    related_finding: str | None = None,
) -> dict[str, Any]:
    return store.add_risk_item(
        account_id=account_id, title=title, description=description, category=category,
        likelihood=likelihood, impact=impact, treatment=treatment,
        treatment_plan=treatment_plan, related_finding=related_finding,
    ).model_dump(mode="json")


def update_risk(
    *,
    store: Store,
    risk_id: str,
    treatment: str | None = None,
    treatment_plan: str | None = None,
    status: str | None = None,
    review_notes: str | None = None,
    account_id: str = "123456789012",
) -> dict[str, Any]:
    return store.update_risk(
        risk_id=risk_id, treatment=treatment, treatment_plan=treatment_plan,
        status=status, review_notes=review_notes, account_id=account_id,
    ).model_dump(mode="json")
