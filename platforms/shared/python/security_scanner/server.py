from __future__ import annotations

import json
import platform
import subprocess
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .config import expand_path
from .models import CATEGORIES, DEFAULT_CATEGORIES, SEVERITIES, ScannerConfig, TargetConfig
from .reporting import (
    build_dashboard_payload,
    build_rule_catalog,
    filter_by_min_severity,
    filter_disabled_rules,
    render_html,
    render_hwpx,
    render_markdown_from_payload,
    render_xlsx,
)
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
LOCAL_CORS_HOSTS = {"127.0.0.1", "localhost", "::1"}


def create_dashboard_server(host: str = DEFAULT_HOST, port: int = DEFAULT_PORT, language: str = "ko") -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), _handler(language))
    server.daemon_threads = True
    return server


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
    categories: tuple[str, ...] = DEFAULT_CATEGORIES,
    standard: str = DEFAULT_STANDARD,
    standard_category: str = DEFAULT_STANDARD_CATEGORY,
    max_file_size_bytes: int = 524288,
    base_dir: Path | None = None,
    enable_osv: bool = False,
    include_host: bool = False,
    disabled_rules: tuple[str, ...] = (),
) -> dict[str, object]:
    if min_severity not in SEVERITIES:
        raise ValueError(f"Unsupported min_severity: {min_severity}")
    unknown_categories = sorted(set(categories) - set(CATEGORIES))
    if unknown_categories:
        raise ValueError(f"Unsupported categories: {', '.join(unknown_categories)}")
    standard_selection = resolve_standard_selection(standard, standard_category, categories)
    scanner_categories = standard_selection.scanner_categories
    if include_host and "host" not in scanner_categories:
        scanner_categories = scanner_categories + ("host",)
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
        categories=scanner_categories,
        max_file_size_bytes=max_file_size_bytes,
        discover_projects=discover_projects,
        discovery_depth=discovery_depth,
    )
    config = ScannerConfig(targets=(target,), enable_osv=enable_osv, enable_vuln_intel=enable_osv)
    scanner = SecurityScanner(config)
    raw_findings = scanner.scan()
    findings = filter_findings_by_standard(raw_findings, standard_selection)
    if include_host:
        # Host posture is opt-in and orthogonal to the selected standard's rule_id
        # filter, so keep host findings that the standard filter would have dropped.
        host_findings = [item for item in raw_findings if item.category == "host"]
        findings = findings + [item for item in host_findings if item not in findings]
    findings = filter_by_min_severity(findings, min_severity)
    findings = filter_disabled_rules(findings, disabled_rules)
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
        components=scanner.components,
        enable_osv=enable_osv,
    )


def web_scan_payload(
    url: str,
    *,
    language: str = "ko",
    min_severity: str = "info",
    timeout: float = 15.0,
    crawl: bool = False,
    max_pages: int = 50,
    max_depth: int = 3,
    delay: float = 0.3,
    render: bool = False,
    auth: dict[str, object] | None = None,
) -> dict[str, object]:
    if min_severity not in SEVERITIES:
        raise ValueError(f"Unsupported min_severity: {min_severity}")
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Enter an http(s) URL, e.g. https://example.com")

    from .web import build_auth_opener, crawl_web, login

    auth = auth or {}
    extra_headers = _headers_from_text(str(auth.get("headers") or ""))
    opener = build_auth_opener()
    warnings: list[str] = []
    login_url = str(auth.get("login_url") or "").strip()
    if login_url:
        username = str(auth.get("username") or "")
        password = str(auth.get("password") or "")
        if not username or not password:
            raise ValueError("Form login requires both a username and a password.")
        warnings.extend(
            login(
                opener,
                login_url,
                username,
                password,
                user_field=(str(auth.get("user_field")) or None) if auth.get("user_field") else None,
                pass_field=(str(auth.get("pass_field")) or None) if auth.get("pass_field") else None,
                timeout=timeout,
            )
        )

    findings, crawl_warnings, pages = crawl_web(
        url,
        timeout=timeout,
        max_pages=max_pages if crawl else 1,
        max_depth=max_depth if crawl else 0,
        delay=delay,
        opener=opener,
        extra_headers=extra_headers or None,
        render=render,
    )
    warnings.extend(crawl_warnings)
    findings = filter_by_min_severity(findings, min_severity)
    target_name = parsed.netloc
    payload = build_dashboard_payload(
        findings,
        (target_name,),
        language,
        target_paths={target_name: url},
        warnings=tuple(warnings),
        scan_path=url,
    )
    payload["pages_scanned"] = pages
    return payload


def _headers_from_text(raw: str) -> dict[str, str]:
    """Parse a textarea of ``Name: value`` lines into a header dict.

    A line whose name-part contains ``=`` (or that has no colon at all) is a bare
    cookie string pasted from the browser (``a=b; c=d``); treat it as a Cookie
    value rather than dropping it — that silent drop is the common "I pasted a
    cookie and nothing happened" failure.
    """
    headers: dict[str, str] = {}
    bare_cookies: list[str] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        name, sep, value = line.partition(":")
        if sep and name.strip() and "=" not in name:
            if name.strip().lower() == "cookie":
                bare_cookies.append(value.strip())
            else:
                headers[name.strip()] = value.strip()
        else:
            bare_cookies.append(line)
    if bare_cookies:
        headers["Cookie"] = "; ".join(bare_cookies)
    return headers


PREVENTION_KIT_ACTIONS = {"toolkit", "hook", "ignore"}


def prevention_kit_payload(
    action: str,
    path_value: str,
    *,
    base_dir: Path | None = None,
) -> dict[str, object]:
    if action not in PREVENTION_KIT_ACTIONS:
        raise ValueError(f"Unsupported action: {action}")
    target_path = expand_path(path_value, base_dir or Path.cwd())
    if not target_path.exists():
        raise ValueError(f"Path does not exist: {target_path}")
    if not target_path.is_dir():
        raise ValueError(f"Path is not a directory: {target_path}")

    from .toolkit import (
        install_pre_commit_hook,
        write_ignore_template,
        write_security_template_files,
    )

    if action == "toolkit":
        results = write_security_template_files(target_path)
    elif action == "hook":
        results = [install_pre_commit_hook(target_path)]
    else:
        results = [write_ignore_template(target_path)]

    return {
        "action": action,
        "results": [{"path": str(item.path), "status": item.status} for item in results],
    }


def _handler(language: str):
    initial_html = render_html([], language=language)

    class DashboardHandler(BaseHTTPRequestHandler):
        server_version = "SecChkDashboard/0.1"

        def do_GET(self) -> None:
            path = urlparse(self.path).path
            if path in {"/", "/security-dashboard.html"}:
                self._send_html(initial_html)
                return
            if path == "/api/health":
                self._send_json({"ok": True})
                return
            if path == "/api/rules":
                lang = _choice_value_query(urlparse(self.path).query, "lang", {"en", "ko"}, language)
                self._send_json({"groups": build_rule_catalog(lang)})
                return
            self.send_error(HTTPStatus.NOT_FOUND)

        def do_OPTIONS(self) -> None:
            path = urlparse(self.path).path
            if path in {"/api/health", "/api/scan", "/api/web-scan", "/api/select-directory", "/api/prevention-kit", "/api/export"}:
                self.send_response(HTTPStatus.NO_CONTENT)
                self._send_cors_headers()
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self.send_error(HTTPStatus.NOT_FOUND)

        def do_POST(self) -> None:
            path = urlparse(self.path).path
            if path == "/api/select-directory":
                self._handle_select_directory()
                return
            if path == "/api/web-scan":
                self._handle_web_scan()
                return
            if path == "/api/prevention-kit":
                self._handle_prevention_kit()
                return
            if path == "/api/export":
                self._handle_export()
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
                    enable_osv=bool(request.get("enable_osv", False)),
                    include_host=bool(request.get("include_host", False)),
                    disabled_rules=_disabled_rules_value(request),
                )
            except (json.JSONDecodeError, TypeError, ValueError) as exc:
                self._send_json({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)
                return

            self._send_json(payload)

        def _handle_web_scan(self) -> None:
            try:
                request = self._read_json()
                auth = request.get("auth") if isinstance(request.get("auth"), dict) else {}
                payload = web_scan_payload(
                    _string_value(request, "url"),
                    language=_choice_value(request, "language", {"en", "ko"}, language),
                    min_severity=_choice_value(request, "min_severity", set(SEVERITIES), "info"),
                    crawl=bool(request.get("crawl")),
                    max_pages=_bounded_int(request.get("max_pages"), default=50, low=1, high=500),
                    max_depth=_bounded_int(request.get("max_depth"), default=3, low=0, high=20),
                    delay=_bounded_float(request.get("delay"), default=0.3, low=0.0, high=10.0),
                    render=bool(request.get("render")),
                    auth=auth,
                )
            except (json.JSONDecodeError, TypeError, ValueError) as exc:
                self._send_json({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)
                return
            self._send_json(payload)

        def _handle_prevention_kit(self) -> None:
            try:
                request = self._read_json()
                payload = prevention_kit_payload(
                    _choice_value(request, "action", PREVENTION_KIT_ACTIONS, "toolkit"),
                    _string_value(request, "path"),
                )
            except (json.JSONDecodeError, TypeError, ValueError) as exc:
                self._send_json({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)
                return
            self._send_json(payload)

        def _handle_export(self) -> None:
            try:
                request = self._read_json(max_bytes=4_194_304)
                report_format = _choice_value(request, "format", {"md", "markdown", "xlsx", "hwpx"}, "md")
                lang = _choice_value(request, "language", {"en", "ko"}, language)
                payload = request.get("payload")
                if not isinstance(payload, dict):
                    raise ValueError("'payload' must be an object")
            except (json.JSONDecodeError, TypeError, ValueError) as exc:
                self._send_json({"error": str(exc)}, status=HTTPStatus.BAD_REQUEST)
                return

            if report_format in {"md", "markdown"}:
                body = render_markdown_from_payload(payload, lang).encode("utf-8")
                content_type, extension = "text/markdown; charset=utf-8", "md"
            elif report_format == "xlsx":
                body = render_xlsx(payload, lang)
                content_type = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                extension = "xlsx"
            else:
                body = render_hwpx(payload, lang)
                content_type, extension = "application/hwp+zip", "hwpx"
            self._send_bytes(body, content_type, f"koda-report.{extension}")

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

        def _read_json(self, *, required: bool = True, max_bytes: int = 32768) -> dict[str, Any]:
            content_length = int(self.headers.get("Content-Length", "0"))
            if content_length <= 0:
                if required:
                    raise ValueError("Missing JSON body")
                return {}
            if content_length > max_bytes:
                raise ValueError("JSON body is too large")
            data = json.loads(self.rfile.read(content_length).decode("utf-8"))
            if not isinstance(data, dict):
                raise ValueError("JSON body must be an object")
            return data

        def _send_html(self, content: str) -> None:
            body = content.encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self._send_cors_headers()
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _send_json(self, payload: dict[str, object], status: HTTPStatus = HTTPStatus.OK) -> None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self._send_cors_headers()
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _send_bytes(self, body: bytes, content_type: str, filename: str) -> None:
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
            self._send_cors_headers()
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _send_cors_headers(self) -> None:
            origin = allowed_cors_origin(self.headers.get("Origin"))
            if origin is None:
                return
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
            self.send_header("Vary", "Origin")

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
    result = _run_macos_folder_picker(initial_dir)
    if result.returncode != 0 and _should_retry_macos_picker_without_default(result):
        result = _run_macos_folder_picker(None)
    if result.returncode != 0:
        message = (result.stderr or result.stdout or "").strip()
        if "User canceled" in message or "-128" in message:
            return None
        raise RuntimeError(message or "macOS folder picker failed")
    return _normalize_selected_directory(result.stdout.strip())


def _run_macos_folder_picker(initial_dir: Path | None) -> subprocess.CompletedProcess[str]:
    if initial_dir is None:
        script_lines = (
            'set selectedFolder to choose folder with prompt "Select folder to scan"',
            "POSIX path of selectedFolder",
        )
    else:
        script_lines = (
            f'set initialFolder to POSIX file "{_applescript_string(str(initial_dir))}" as alias',
            'set selectedFolder to choose folder with prompt "Select folder to scan" default location initialFolder',
            "POSIX path of selectedFolder",
        )
    command = ["osascript"]
    for line in script_lines:
        command.extend(("-e", line))
    try:
        return subprocess.run(command, capture_output=True, text=True, check=False)
    except FileNotFoundError as exc:  # pragma: no cover - macOS normally provides osascript
        raise RuntimeError("macOS folder picker command was not found") from exc


def _should_retry_macos_picker_without_default(result: subprocess.CompletedProcess[str]) -> bool:
    message = (result.stderr or result.stdout or "").lower()
    return "expected pattern" in message or "can't make" in message or "cannot make" in message


def allowed_cors_origin(origin: str | None) -> str | None:
    if origin is None:
        return None
    if origin == "null":
        return origin
    parsed = urlparse(origin)
    if parsed.scheme in {"http", "https"} and parsed.hostname in LOCAL_CORS_HOSTS:
        return origin
    return None


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


def _bounded_int(value: object, *, default: int, low: int, high: int) -> int:
    try:
        result = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default
    return max(low, min(high, result))


def _bounded_float(value: object, *, default: float, low: float, high: float) -> float:
    try:
        result = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default
    return max(low, min(high, result))


def _choice_value(request: dict[str, Any], key: str, choices: set[str], default: str) -> str:
    value = request.get(key, default)
    if not isinstance(value, str):
        raise ValueError(f"'{key}' must be a string")
    normalized = value.lower()
    if normalized not in choices:
        raise ValueError(f"Unsupported {key}: {value}")
    return normalized


def _choice_value_query(query: str, key: str, choices: set[str], default: str) -> str:
    from urllib.parse import parse_qs

    values = parse_qs(query).get(key)
    if not values:
        return default
    normalized = values[0].lower()
    return normalized if normalized in choices else default


def _disabled_rules_value(request: dict[str, Any]) -> tuple[str, ...]:
    value = request.get("disabled_rules", ())
    if not isinstance(value, list | tuple):
        return ()
    return tuple(str(item) for item in value if isinstance(item, str))


def _categories_value(request: dict[str, Any]) -> tuple[str, ...]:
    value = request.get("categories", DEFAULT_CATEGORIES)
    if value == "all":
        # "all" means all file-based categories; host posture is opt-in only.
        return DEFAULT_CATEGORIES
    if not isinstance(value, list | tuple):
        raise ValueError("'categories' must be a list or 'all'")
    categories = tuple(str(item).lower() for item in value)
    if not categories:
        raise ValueError("'categories' must not be empty")
    unknown = sorted(set(categories) - set(CATEGORIES))
    if unknown:
        raise ValueError(f"Unsupported categories: {', '.join(unknown)}")
    return categories
