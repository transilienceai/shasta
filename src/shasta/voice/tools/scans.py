"""Tool functions for scan queries."""
from typing import Any

from shasta.voice.store import Store


def list_scans(*, store: Store, limit: int = 10) -> list[dict[str, Any]]:
    return [s.model_dump(mode="json") for s in store.list_scans(limit=limit)]


def get_latest_scan(*, store: Store) -> dict[str, Any]:
    s = store.get_latest_scan()
    if s is None:
        return {"error": "no_scan_data"}
    return s.model_dump(mode="json")
