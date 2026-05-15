"""`python -m shasta.voice` entrypoint."""

import argparse
import os
import sys
import webbrowser
from pathlib import Path

from shasta.voice.app import create_app


def main() -> int:
    parser = argparse.ArgumentParser(prog="shasta.voice", description="Voice console for Shasta")
    parser.add_argument("--port", type=int, default=8090)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--no-open", action="store_true", help="don't auto-launch browser")
    parser.add_argument(
        "--db", type=Path, default=None, help="path to shasta.db (default: data/shasta.db)"
    )
    args = parser.parse_args()

    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key or api_key == "sk-replace-me":
        print("✗ OPENAI_API_KEY not set in environment", file=sys.stderr)
        print("  Add to your shell: export OPENAI_API_KEY=sk-...", file=sys.stderr)
        return 2

    db_path = args.db or Path("data/shasta.db")
    if not db_path.exists():
        print(f"✗ No scan data at {db_path}", file=sys.stderr)
        print("  Run a scan first: open Claude Code and use /scan", file=sys.stderr)
        return 2

    # Verify the DB has at least one scan
    from shasta.voice.store import Store

    s = Store(db_path=db_path)
    if not s.has_data():
        print(f"✗ {db_path} exists but contains no scan data", file=sys.stderr)
        print("  Run a scan first: open Claude Code and use /scan", file=sys.stderr)
        s.close()
        return 2
    latest = s.get_latest_scan()
    s.close()

    print("✓ OPENAI_API_KEY found")
    print(f"✓ {db_path} (latest scan: {latest.completed_at}, {latest.total_findings} findings)")
    url = f"http://{args.host}:{args.port}"
    print(f"→ Starting voice console at {url}")

    if not args.no_open:
        try:
            webbrowser.open(url)
        except Exception:
            pass

    import uvicorn

    app = create_app(db_path=db_path)
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
