import json

from shasta.voice.realtime_config import SYSTEM_PROMPT, TOOL_SCHEMAS, VAD_CONFIG, build_session_payload


def test_system_prompt_mentions_shasta_and_25_words():
    assert "Shasta" in SYSTEM_PROMPT
    assert "25 words" in SYSTEM_PROMPT


def test_system_prompt_mentions_redirects():
    assert "/scan" in SYSTEM_PROMPT
    assert "/report" in SYSTEM_PROMPT


def test_tool_schemas_cover_all_14_tools():
    names = {t["name"] for t in TOOL_SCHEMAS}
    assert names == {
        "list_findings", "get_finding", "list_top_blockers", "get_resource_findings",
        "get_compliance_score", "get_multi_framework_score", "get_score_trend",
        "get_control_summary",
        "list_scans", "get_latest_scan",
        "list_risk_items", "get_risk_item", "add_risk_item", "update_risk",
    }


def test_tool_schemas_have_required_fields():
    for s in TOOL_SCHEMAS:
        assert s["type"] == "function"
        assert "name" in s and "description" in s and "parameters" in s
        assert s["parameters"]["type"] == "object"


def test_vad_config_uses_server_vad():
    assert VAD_CONFIG["type"] == "server_vad"


def test_build_session_payload_shape():
    p = build_session_payload()
    assert p["model"]
    assert p["voice"]
    assert p["instructions"] == SYSTEM_PROMPT
    assert p["tools"] == TOOL_SCHEMAS
    assert p["input_audio_transcription"]["model"] == "whisper-1"
    json.dumps(p)  # serializable
