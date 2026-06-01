"""PyInstaller entry point for the KODA single-window desktop app.

Unlike ``koda-app.py`` (which prints to a console window and opens the system
web browser), this entry point:

  1. Starts the local KODA dashboard server on a background daemon thread.
  2. Hosts the dashboard inside ONE native desktop window (Edge WebView2 on
     Windows) via pywebview -- no terminal window, no separate browser tab.

This mirrors the macOS KODA app, which is a single native window. If the native
webview runtime is unavailable, it falls back to opening the default browser so
the user is never left without the dashboard.
"""
from __future__ import annotations

import os
import sys
import threading
import webbrowser
from pathlib import Path

from security_scanner.app import _create_available_server
from security_scanner.server import DEFAULT_HOST, DEFAULT_PORT, dashboard_url

WINDOW_MIN_WIDTH = 980
WINDOW_MIN_HEIGHT = 720


def _set_safe_working_directory() -> None:
    """Start from the user's home folder instead of the installer directory."""
    try:
        os.chdir(Path.home().resolve())
    except Exception:
        pass


def _start_dashboard_server(host: str, port: int, language: str) -> str:
    """Bind the dashboard server and serve it on a background daemon thread."""
    resolved_port, server = _create_available_server(host, port, language, 20)
    url = dashboard_url(host, resolved_port)

    thread = threading.Thread(target=server.serve_forever, name="koda-dashboard", daemon=True)
    thread.start()
    return url


def _run_native_window(url: str, display_name: str) -> bool:
    """Show the dashboard in a single native window. Return False if unavailable."""
    try:
        import webview  # type: ignore
    except Exception:
        return False

    try:
        webview.create_window(
            display_name,
            url=url,
            width=1180,
            height=860,
            min_size=(WINDOW_MIN_WIDTH, WINDOW_MIN_HEIGHT),
            text_select=True,
        )
        # gui=None lets pywebview auto-select the best backend
        # (Edge WebView2 on Windows, WebKit on macOS, GTK/Qt on Linux).
        webview.start()
        return True
    except Exception:
        return False


def main() -> int:
    display_name = os.environ.setdefault("KODA_DISPLAY_NAME", "KODA")
    _set_safe_working_directory()

    host = os.environ.get("KODA_HOST", DEFAULT_HOST)
    port = int(os.environ.get("KODA_PORT", DEFAULT_PORT))
    language = os.environ.get("KODA_LANGUAGE", "ko")

    url = _start_dashboard_server(host, port, language)

    if _run_native_window(url, display_name):
        return 0

    # Fallback: the native webview runtime is missing. Open the browser so the
    # dashboard is still reachable, then keep the server alive.
    webbrowser.open(url)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
