import json
import logging

from shasta.voice.observability import configure_logging, log_tool_call


def test_log_tool_call_emits_json(caplog):
    configure_logging()
    with caplog.at_level(logging.INFO, logger="shasta.voice"):
        log_tool_call(tool_name="list_findings", args={"severity": "critical"}, latency_ms=1.234, result_size=4)
    payloads = [json.loads(r.message) for r in caplog.records if r.message.startswith("{")]
    assert any(p.get("tool_name") == "list_findings" for p in payloads)
    matching = [p for p in payloads if p.get("tool_name") == "list_findings"][0]
    assert matching["latency_ms"] == 1.23
    assert matching["result_size"] == 4
