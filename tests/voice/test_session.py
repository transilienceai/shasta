from unittest.mock import MagicMock, patch


def test_session_token_endpoint_calls_openai(client):
    fake = MagicMock()
    fake.status_code = 200
    fake.json.return_value = {"client_secret": {"value": "ek_x", "expires_at": 1735000000}}

    with patch("shasta.voice.session.httpx.post", return_value=fake) as mock_post:
        resp = client.post("/session/token")
        assert resp.status_code == 200
        body = resp.json()
        assert body["client_secret"] == "ek_x"
        sent = mock_post.call_args.kwargs["json"]
        assert sent["model"]
        assert "Shasta" in sent["instructions"]
        assert len(sent["tools"]) == 14


def test_session_token_endpoint_handles_openai_error(client):
    fake = MagicMock()
    fake.status_code = 401
    fake.text = "Invalid key"

    with patch("shasta.voice.session.httpx.post", return_value=fake):
        resp = client.post("/session/token")
        assert resp.status_code == 502
