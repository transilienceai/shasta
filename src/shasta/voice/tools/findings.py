"""Tool functions for finding queries."""

from typing import Any

from shasta.voice.store import Store


def list_findings(
    *,
    store: Store,
    severity: str | None = None,
    status: str | None = None,
    domain: str | None = None,
    cloud: str | None = None,
    framework: str | None = None,
    control_id: str | None = None,
    limit: int | None = None,
) -> list[dict[str, Any]]:
    items = store.list_findings(
        severity=severity,
        status=status,
        domain=domain,
        cloud=cloud,
        framework=framework,
        control_id=control_id,
        limit=limit,
    )
    return [i.model_dump(mode="json") for i in items]


def get_finding(*, store: Store, finding_id: str) -> dict[str, Any]:
    detail = store.get_finding(finding_id)
    if detail is None:
        return {"error": "finding_not_found", "finding_id": finding_id}
    return detail.model_dump(mode="json")


def list_top_blockers(*, store: Store, limit: int = 5) -> list[dict[str, Any]]:
    return [i.model_dump(mode="json") for i in store.list_top_blockers(limit=limit)]


def get_resource_findings(*, store: Store, resource_id: str) -> list[dict[str, Any]]:
    return [i.model_dump(mode="json") for i in store.get_resource_findings(resource_id)]
