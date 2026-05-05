from __future__ import annotations

import webbrowser
from http.server import HTTPServer

from .server import DEFAULT_HOST, DEFAULT_PORT, create_dashboard_server, dashboard_url


def run_app(
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    language: str = "ko",
    *,
    open_browser: bool = True,
    port_attempts: int = 20,
) -> int:
    resolved_port, server = _create_available_server(host, port, language, port_attempts)
    url = dashboard_url(host, resolved_port)
    print(f"SecChk is running: {url}")
    print("Press Ctrl+C in this window to stop the local app.")
    if open_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping SecChk.")
    finally:
        server.server_close()
    return 0


def _create_available_server(
    host: str,
    start_port: int,
    language: str,
    attempts: int,
) -> tuple[int, HTTPServer]:
    if start_port <= 0:
        raise ValueError("port must be positive")
    if attempts <= 0:
        raise ValueError("port_attempts must be positive")

    last_error: OSError | None = None
    for port in range(start_port, start_port + attempts):
        try:
            return port, create_dashboard_server(host, port, language)
        except OSError as exc:
            last_error = exc
    raise RuntimeError(f"No available port from {start_port} to {start_port + attempts - 1}") from last_error
