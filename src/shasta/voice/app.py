"""FastAPI application for the voice console."""
import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from shasta.voice.observability import configure_logging
from shasta.voice.session import router as session_router
from shasta.voice.store import Store
from shasta.voice.tools.router import router as tools_router


def create_app(*, db_path: str | Path | None = None, serve_static: bool = True) -> FastAPI:
    configure_logging()
    app = FastAPI(title="Shasta Voice Console", version="0.1.0")

    allowed = os.environ.get("ALLOWED_ORIGINS", "http://localhost:8090").split(",")
    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed,
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type"],
    )

    # One Store per process — reuses the same SQLite connection
    app.state.store = Store(db_path=db_path)

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok"}

    app.include_router(session_router)
    app.include_router(tools_router)

    if serve_static:
        dist = Path(__file__).parent / "web" / "dist"
        if dist.exists():
            app.mount("/", StaticFiles(directory=str(dist), html=True), name="static")
    return app


# Module-level app for `uvicorn shasta.voice.app:app`
app = create_app()
