"""Tool functions for control summaries."""

from typing import Any

from shasta.voice.store import Store


def get_control_summary(
    *, store: Store, framework: str, control_id: str | None = None
) -> list[dict[str, Any]]:
    return [
        c.model_dump(mode="json")
        for c in store.get_control_summary(framework, control_id=control_id)
    ]  # type: ignore[arg-type]
