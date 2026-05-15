"""Structured logging for tool calls."""

import json
import logging
import os
from typing import Any

_LOGGER = logging.getLogger("shasta.voice")


def configure_logging() -> None:
    level = os.environ.get("LOG_LEVEL", "INFO").upper()
    logging.basicConfig(level=level, format="%(message)s")
    _LOGGER.setLevel(level)


def log_tool_call(
    tool_name: str,
    args: dict[str, Any],
    latency_ms: float,
    result_size: int,
    error: str | None = None,
) -> None:
    payload: dict[str, Any] = {
        "event": "tool_call",
        "tool_name": tool_name,
        "args": args,
        "latency_ms": round(latency_ms, 2),
        "result_size": result_size,
    }
    if error:
        payload["error"] = error
    _LOGGER.info(json.dumps(payload))
