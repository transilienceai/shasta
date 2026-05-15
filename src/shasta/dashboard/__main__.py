"""Entry point for running the Shasta dashboard.

Bug #6 from 2026-04-11: running this twice in the same shell caused the
second invocation to fail silently inside uvicorn with an opaque
``[Errno 10048]`` after the user had already seen the startup banner.
We now probe the port first and emit a clear error pointing to the fix.
"""

from __future__ import annotations

import argparse
import socket
import sys

import uvicorn
from rich.console import Console

from shasta.dashboard.app import app

_DEFAULT_HOST = "127.0.0.1"
_DEFAULT_PORT = 8080


def _port_in_use(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.5)
        return sock.connect_ex((host, port)) == 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="shasta.dashboard")
    parser.add_argument("--host", default=_DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=_DEFAULT_PORT)
    args = parser.parse_args()

    console = Console()

    if _port_in_use(args.host, args.port):
        console.print(
            f"[red bold]Shasta Dashboard cannot start:[/red bold] "
            f"port [yellow]{args.port}[/yellow] on [yellow]{args.host}[/yellow] "
            f"is already in use."
        )
        console.print(
            "  • The dashboard may already be running — open "
            f"[cyan]http://{args.host}:{args.port}[/cyan] in your browser."
        )
        console.print(
            "  • To start a second instance, pass a different port: "
            "[cyan]py -m shasta.dashboard --port 8081[/cyan]"
        )
        return 2

    console.print(f"Shasta Dashboard starting at [cyan]http://{args.host}:{args.port}[/cyan]")
    uvicorn.run(app, host=args.host, port=args.port)
    return 0


if __name__ == "__main__":
    sys.exit(main())
