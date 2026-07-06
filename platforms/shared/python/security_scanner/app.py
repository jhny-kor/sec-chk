from __future__ import annotations

import threading
import webbrowser
from http.server import HTTPServer
from os import environ

from .server import DEFAULT_HOST, DEFAULT_PORT, create_dashboard_server, dashboard_url


def run_app(
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    language: str = "ko",
    *,
    open_browser: bool = True,
    port_attempts: int = 20,
) -> int:
    display_name = environ.get("KODA_DISPLAY_NAME", "SecChk")
    resolved_port, server = _create_available_server(host, port, language, port_attempts)
    url = dashboard_url(host, resolved_port)
    print(f"{display_name} is running: {url}")
    print("Press Ctrl+C in this window to stop the local app.")
    browser_timer: threading.Timer | None = None
    if open_browser:
        browser_timer = _schedule_browser_open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print(f"\nStopping {display_name}.")
    finally:
        if browser_timer is not None:
            browser_timer.cancel()
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


def _schedule_browser_open(url: str) -> threading.Timer:
    timer = threading.Timer(0.05, webbrowser.open, args=(url,))
    timer.daemon = True
    timer.start()
    return timer
