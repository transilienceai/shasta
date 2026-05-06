"""Ephemeral OpenAI Realtime token endpoint."""
import os

import httpx
from fastapi import APIRouter, HTTPException

from shasta.voice.realtime_config import build_session_payload

router = APIRouter()


@router.post("/session/token")
def mint_session_token() -> dict:
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key or api_key == "sk-replace-me":
        raise HTTPException(status_code=500, detail="OPENAI_API_KEY not configured")

    payload = build_session_payload()
    try:
        response = httpx.post(
            "https://api.openai.com/v1/realtime/sessions",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json=payload,
            timeout=10.0,
        )
    except httpx.HTTPError as e:
        raise HTTPException(status_code=502, detail=f"OpenAI request failed: {e}") from e

    if response.status_code != 200:
        raise HTTPException(status_code=502, detail=f"OpenAI session creation failed ({response.status_code}): {response.text[:200]}")

    body = response.json()
    return {
        "client_secret": body["client_secret"]["value"],
        "expires_at": body["client_secret"]["expires_at"],
        "model": payload["model"],
    }
