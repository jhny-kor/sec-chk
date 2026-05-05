from __future__ import annotations

import json
import platform
import subprocess
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .config import expand_path
from .models import CATEGORIES, SEVERITIES, ScannerConfig, TargetConfig
from .reporting import build_dashboard_payload, filter_by_min_severity, render_html
from .scanner import SecurityScanner
from .standards import (
    DEFAULT_STANDARD,
    DEFAULT_STANDARD_CATEGORY,
    SECURITY_STANDARD_IDS,
    filter_findings_by_standard,
    resolve_standard_selection,
)


DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8765


def create_dashboard_server(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT, language: str = "ko") -> HTTPServer:
    return HTTPServer((host, port), _handler(language))


def dashboard_url(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> str:
    display_host = "127.0.0.1" if host in {"", "0.0.0.0"} else host
    return f"http://{display_host}:{port}/security-dashboard.html"


def serve_dashboard(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT, language: str = "ko") -> int:
    server = create_dashboard_server(host, port, language)
    url = dashboard_url(host, port)
    print(f"Serving local security dashboard: {url}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping local security dashboard.")
    finally:
        server.server_close()
    return 0


def scan_directory_payload(
    path_value: str,
    *,
    language: str = "ko",
    min_severity: str = "low",
    discover_projects: bool = True,
    discovery_depth: int = 2,
    categories: tuple[str, ...] = CATEGORIES,
    standard: str = DEFAULT_STANDARD,
    standard_category: str = DEFAULT_STANDARD_CATEGORY,
    max_file_size_bytes: int = 524288,
    base_dir: Path | None = None,
) -> dict[str, object]:
    if min_severity not in SEVERITIES:
        raise ValueError(f"Unsupported min_severity: {min_severity}")
    unknown_categories = sorted(set(categories) - set(CATEGORIES))
    if unknown_categories:
        raise ValueError(f"Unsupported categories: {', '.join(unknown_categories)}")
    standard_selection = resolve_standard_selection(standard, standard_category, categories)
    if discovery_depth < 0:
        raise ValueError("discovery_depth must be zero or greater")
    if max_file_size_bytes <= 0:
        raise ValueError("max_file_size_bytes must be positive")

    target_path = expand_path(path_value, base_dir or Path.cwd())
    if not target_path.exists():
        raise ValueError(f"Path does not exist: {target_path}")
    if not target_path.is_dir():
        raise ValueError(f"Path is not a directory: {target_path}")

    target = TargetConfig(
        name=target_path.name or "scan-target",
        path=target_path,
        categories=standard_selection.scanner_categories,
        max_file_size_bytes=max_file_size_bytes,
        discover_projects=discover_projects,
        discovery_depth=discovery_depth,
    )
    config = ScannerConfig(targets=(target,))
    scanner = SecurityScanner(config)
    findings = filter_findings_by_standard(scanner.scan(), standard_selection)
    findings = filter_by_min_severity(findings, min_severity)
    effective_targets = scanner.effective_targets or config.targets
    target_names = tuple(item.name for item in effective_targets)
    target_paths = {item.name: str(item.path) for item in effective_targets}
    return build_dashboard_payload(
        findings,
        target_names,
        language,
        target_paths=target_paths,
        warnings=tuple(scanner.warnings),
        scan_path=str(target_path),
        standard=standard_selection.standard,
        standard_category=standard_selection.category,
    )


def _handler(language: str):
    class DashboardHandler(BaseHTTPRequestHandler):
        server_version = "SecChkDashboard/0.1"

        def do_GET(self) -> None:
            path = urlparse(self.path).path
            if path in {"/", "/security-dashboard.html"}:
                self._send_html(render_html([], language=language))
                return
            if path == "/api/health":
                self._send_json({"ok": True})
                return
            self.send_error(HTTPStatus.NOT_FOUND)

        def do_POST(self) -> None:
            path = urlparse(self.path).path
            if path == "/api/select-directory":
                self._handle_select_directory()
                return
            if path != "/api/scan":
                self.send_error(HTTPStatus.NOT_FOUND)
                return

            try:
                request = self._read_json()
                payload = scan_directory_payload(
                    _string_value(request, "path"),
                    language=_choice_value(request, "language", {"en", "ko"}, language),
                    min_severity=_choice_value(request, "min_severity", set(SEVERITIES), "low"),
                    discover_projects=bool(request.get("discover_projects", True)),
                    discovery_depth=int(request.get("discovery_depth", 2)),
                    categories=_categories_value(request),
                    standard=_choice_value(
                        request,
                        "standard",
                        set(SECURITY_STANDARD_IDS),
                        DEFAULT_STANDARD,
                    ),
                    standard_category=_string_value(request, "standard_category", default=DEFAULT_STANDARD_CATEGORY),
                    max_file_size_bytes=int(request.get("max_file_size_bytes", 524288)),
                )
            except (json.JSONDecodeError, TypeError, ValueError) as exc:
                self._send_json({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)
                return

            self._send_json(payload)

        def _handle_select_directory(self) -> None:
            try:
                request = self._read_json(required=False)
                selected = select_directory(str(request.get("current_path", "")))
            except (json.JSONDecodeError, TypeError, ValueError, RuntimeError) as exc:
                self._send_json({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)
                return
            if selected is None:
                self._send_json({"path": "", "cancelled": True})
                return
            self._send_json({"path": selected, "cancelled": False})

        def log_message(self, format: str, *args: object) -> None:
            print(f"{self.address_string()} - {format % args}")

        def _read_json(self, *, required: bool = True) -> dict[str, Any]:
            content_length = int(self.headers.get("Content-Length", "0"))
            if content_length <= 0:
                if required:
                    raise ValueError("Missing JSON body")
                return {}
            if content_length > 32768:
                raise ValueError("JSON body is too large")
            data = json.loads(self.rfile.read(content_length).decode("utf-8"))
            if not isinstance(data, dict):
                raise ValueError("JSON body must be an object")
            return data

        def _send_html(self, content: str) -> None:
            body = content.encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _send_json(self, payload: dict[str, object], status: HTTPStatus = HTTPStatus.OK) -> None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return DashboardHandler


def select_directory(current_path: str = "") -> str | None:
    initial_dir = _initial_directory(current_path)
    try:
        return _select_directory_tk(initial_dir)
    except RuntimeError as tk_error:
        if platform.system() == "Darwin":
            try:
                return _select_directory_macos(initial_dir)
            except RuntimeError as mac_error:
                raise RuntimeError(f"Folder picker is not available: {mac_error}") from mac_error
        raise RuntimeError("Folder picker is not available in this Python environment") from tk_error


def _select_directory_tk(initial_dir: Path) -> str | None:
    try:
        import tkinter as tk
        from tkinter import filedialog
    except Exception as exc:  # pragma: no cover - depends on local Python build
        raise RuntimeError("Tk folder picker is not available") from exc

    try:
        root = tk.Tk()
    except Exception as exc:  # pragma: no cover - depends on local GUI/session state
        raise RuntimeError("Tk folder picker could not start") from exc
    try:
        root.withdraw()
        root.update()
        selected = filedialog.askdirectory(
            parent=root,
            initialdir=str(initial_dir),
            mustexist=True,
            title="Select folder to scan",
        )
    finally:
        root.destroy()

    return _normalize_selected_directory(selected)


def _select_directory_macos(initial_dir: Path) -> str | None:
    script_lines = (
        f'set initialFolder to POSIX file "{_applescript_string(str(initial_dir))}" as alias',
        'set selectedFolder to choose folder with prompt "Select folder to scan" default location initialFolder',
        "POSIX path of selectedFolder",
    )
    command = ["osascript"]
    for line in script_lines:
        command.extend(("-e", line))
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=False)
    except FileNotFoundError as exc:  # pragma: no cover - macOS normally provides osascript
        raise RuntimeError("macOS folder picker command was not found") from exc
    if result.returncode != 0:
        message = (result.stderr or result.stdout or "").strip()
        if "User canceled" in message or "-128" in message:
            return None
        raise RuntimeError(message or "macOS folder picker failed")
    return _normalize_selected_directory(result.stdout.strip())


def _applescript_string(value: str) -> str:
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _normalize_selected_directory(selected: str) -> str | None:
    if not selected:
        return None
    selected_path = Path(selected).expanduser().resolve()
    if not selected_path.is_dir():
        raise ValueError(f"Selected path is not a directory: {selected_path}")
    return str(selected_path)


def _initial_directory(current_path: str) -> Path:
    if current_path:
        candidate = Path(current_path).expanduser()
        if candidate.is_dir():
            return candidate.resolve()
        if candidate.parent.is_dir():
            return candidate.parent.resolve()
    return Path.home().resolve()


def _string_value(request: dict[str, Any], key: str, *, default: str | None = None) -> str:
    value = request.get(key, default)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"'{key}' must be a non-empty string")
    return value


def _choice_value(request: dict[str, Any], key: str, choices: set[str], default: str) -> str:
    value = request.get(key, default)
    if not isinstance(value, str):
        raise ValueError(f"'{key}' must be a string")
    normalized = value.lower()
    if normalized not in choices:
        raise ValueError(f"Unsupported {key}: {value}")
    return normalized


def _categories_value(request: dict[str, Any]) -> tuple[str, ...]:
    value = request.get("categories", CATEGORIES)
    if value == "all":
        return CATEGORIES
    if not isinstance(value, list | tuple):
        raise ValueError("'categories' must be a list or 'all'")
    categories = tuple(str(item).lower() for item in value)
    if not categories:
        raise ValueError("'categories' must not be empty")
    unknown = sorted(set(categories) - set(CATEGORIES))
    if unknown:
        raise ValueError(f"Unsupported categories: {', '.join(unknown)}")
    return categories
