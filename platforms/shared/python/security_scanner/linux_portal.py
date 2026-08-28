"""Linux-only authenticated portal; the Windows/local dashboard stays in server.py."""
from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import queue
import re
import tempfile
import threading
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .grype_adapter import inspect_grype
from .portal_identity import IdentityError, IdentityUnavailable, identity_from_headers
from .portal_store import SCREEN_PERMISSIONS, PortalStore, VersionConflict
from .portal_views import (
    PERMISSION_METADATA,
    ROLE_DESCRIPTIONS,
    ROLE_LABELS,
    admin_page,
    dashboard,
    esc,
    format_portal_time,
    guide_page,
    login_page,
    new_scan_page,
    page,
    project_page,
    projects_page,
    run_page,
    runs_page,
    script_json,
)

MAX_JSON_BYTES = 36 * 1024 * 1024
MAX_INPUT_BYTES = 1024 * 1024 * 1024
_KODA_ICON = Path(__file__).with_name("assets") / "KODA.ico"


def _safe_next(value: str) -> str:
    if not value.startswith("/koda/") or value.startswith("//") or "\\" in value or not re.fullmatch(r"/koda/[A-Za-z0-9._~!$&'()*+,;=:@/?%-]*", value):
        return "/koda/"
    parsed = urlparse(value)
    return value if not parsed.scheme and not parsed.netloc else "/koda/"


def _vulnerability_database_status() -> dict[str, object]:
    value = os.environ.get("KODA_GRYPE_BIN", "").strip()
    return inspect_grype(Path(value).expanduser() if value else None)


def _run_scan(store: PortalStore, run_id: str) -> None:
    if not store.mark_run_running(run_id):
        return
    try:
        run = store.run(run_id)
        source = store.input(run["input_id"])
        snapshot = run["snapshot"]
        if not store.set_run_progress(run_id, "preparing", 15):
            return store.complete_run(run_id)
        with tempfile.TemporaryDirectory(prefix="koda-portal-") as extraction:
            from .archive_input import prepare_input_target
            from .server import scan_directory_payload

            target = prepare_input_target(Path(source["path"]), Path(extraction))
            if not store.set_run_progress(run_id, "scanning", 35):
                return store.complete_run(run_id)
            scan_scope = str(snapshot.get("scan_scope") or "all")
            result = scan_directory_payload(
                str(target), language="ko", standard=snapshot["standard"],
                standard_category=snapshot["standard_category"],
                disabled_rules=tuple(snapshot["disabled_rules"]), allow_file=True,
                display_path=source["name"], scan_scope=scan_scope,
                enable_local_vulnerabilities=scan_scope in {"all", "library"},
                cve_only=scan_scope == "library",
            )
            result["findings"] = result.get("findings_by_language", {}).get("ko", [])
            result["analysis_stages"] = _analysis_stages(result, scan_scope)
            result["analysis_overall"] = "partial" if any(
                stage["status"] in {"failed", "warning"} for stage in result["analysis_stages"].values()
            ) else "completed"
            if not store.set_run_progress(run_id, "finalizing", 90):
                return store.complete_run(run_id)
        store.complete_run(run_id, result=result)
    except Exception as exc:  # worker errors are durable and visible per round
        store.complete_run(run_id, error=str(exc)[:2000])


def _analysis_stages(result: dict, scan_scope: str = "all") -> dict[str, dict[str, object]]:
    findings = result.get("findings", []) if isinstance(result.get("findings"), list) else []
    counts = {"source": 0, "library": 0, "quality": 0}
    for finding in findings:
        category = str(finding.get("category", "")).lower()
        group = "library" if category == "dependencies" else ("quality" if category in {"quality", "screen_quality"} else "source")
        counts[group] += 1
    local = result.get("scan", {}).get("local_vulnerability", {})
    library_status = str(local.get("status", "failed"))
    active_groups = {
        "all": {"source", "library", "quality"},
        "library": {"library"},
        "source": {"source"},
    }.get(scan_scope, {"source", "library", "quality"})
    return {
        "source": {"status": "completed" if "source" in active_groups else "skipped", "finding_count": counts["source"]},
        "library": {
            "status": library_status if "library" in active_groups else "skipped",
            "finding_count": counts["library"],
            "queried_components": int(local.get("queried_components", 0) or 0),
            "matched_vulnerabilities": int(local.get("matched_vulnerabilities", 0) or 0),
            "version": str(local.get("version", "")),
            "database": local.get("database", {}),
            "warning": str(local.get("warning", "")),
        },
        "quality": {"status": "completed" if "quality" in active_groups else "skipped", "finding_count": counts["quality"]},
    }


class _PortalWorker:
    def __init__(self, store: PortalStore):
        self.store = store
        self.jobs: queue.Queue[str | None] = queue.Queue()
        self.thread = threading.Thread(target=self._work, name="koda-portal-worker", daemon=True)
        self.thread.start()
        for run_id in store.recover_incomplete_runs():
            self.jobs.put(run_id)

    @property
    def available(self) -> bool:
        return self.thread.is_alive()

    def enqueue(self, run_id: str) -> None:
        if not self.available:
            raise RuntimeError("scan worker unavailable")
        self.jobs.put(run_id)

    def _work(self) -> None:
        while (run_id := self.jobs.get()) is not None:
            _run_scan(self.store, run_id)

    def close(self) -> None:
        if self.available:
            self.jobs.put(None)
            self.thread.join(timeout=5)


class _PortalServer(ThreadingHTTPServer):
    def server_close(self):
        worker = getattr(self, "portal_worker", None)
        if worker:
            worker.close()
        super().server_close()


def create_portal_server(host="127.0.0.1", port=8765, language="ko", db_path=None, input_dir=None):
    store = PortalStore(db_path or os.environ.get("KODA_PORTAL_DB", "koda-portal.sqlite3"))
    uploads = Path(input_dir or os.environ.get("KODA_PORTAL_INPUT_DIR", "koda-portal-inputs")).expanduser()
    uploads.mkdir(parents=True, exist_ok=True)

    class Handler(BaseHTTPRequestHandler):
        server_version = "KODA-Portal/1"

        def _send(self, status, raw, content_type, headers=None):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'")
            for name, value in (headers or {}).items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(raw)

        def _json(self, status, value):
            self._send(status, json.dumps(value, ensure_ascii=False).encode(), "application/json; charset=utf-8")

        def _html(self, status, value):
            self._send(status, value.encode(), "text/html; charset=utf-8")

        def _identity(self, api=False):
            try:
                identity = identity_from_headers(self.headers)
            except IdentityUnavailable as exc:
                self._json(503, {"code": "identity_unavailable", "detail": str(exc)})
                return None
            except IdentityError as exc:
                if api:
                    self._json(401, {"code": "unauthorized", "detail": str(exc)})
                else:
                    self.send_response(302)
                    self.send_header("Location", "/koda/login?next=" + _safe_next(self.path))
                    self.send_header("Cache-Control", "no-store")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                return None
            subject = store.ensure_subject(identity.subject_id, identity.display)
            if subject["status"] == "pending":
                subject = store.set_subject(identity.subject_id, status="enabled", actor="tracker-sso")
            return identity, subject

        def _enabled(self, api=False):
            authenticated = self._identity(api)
            if not authenticated:
                return None
            identity, subject = authenticated
            if subject["status"] != "enabled":
                self._deny_subject(subject, api)
                return None
            return identity, subject

        def _deny_subject(self, subject, api=False):
            if api:
                return self._json(403, {"code": "subject_not_enabled", "status": subject["status"]})
            return self._html(403, page("KODA 접근 차단", "<p>KODA 접근이 차단되었습니다. KODA 관리자에게 접근 허용을 요청하세요.</p>"))

        @staticmethod
        def _admin(subject):
            return bool(subject["system_admin"])

        def _project(self, identity, project_id, permission="project.view"):
            projects = {item["project_id"]: item for item in store.list_projects(identity.subject_id)}
            if project_id not in projects or not store.can(identity.subject_id, project_id, permission):
                return None
            return projects[project_id]

        def _screen_projects(self, identity, subject, projects, permission):
            if self._admin(subject):
                return projects
            return [project for project in projects if store.can(identity.subject_id, project["project_id"], permission)]

        def _nav_permissions(self, identity, subject, projects):
            if self._admin(subject):
                return set(SCREEN_PERMISSIONS)
            return {
                permission for permission in SCREEN_PERMISSIONS
                if any(store.can(identity.subject_id, project["project_id"], permission) for project in projects)
            }

        def _deny_screen(self, admin, nav_permissions, *, api=False):
            if api:
                return self._json(403, {"code": "forbidden"})
            return self._html(403, page(
                "권한 없음", "<p>이 화면에 접근할 권한이 없습니다.</p>",
                admin=admin, nav_permissions=nav_permissions,
            ))

        def _payload(self):
            if self.headers.get_content_type() != "application/json":
                self._json(415, {"code": "json_required", "detail": "Content-Type application/json이 필요합니다"})
                return None
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = MAX_JSON_BYTES + 1
            if length < 0 or length > MAX_JSON_BYTES:
                self._json(413, {"code": "payload_too_large"})
                return None
            try:
                value = json.loads(self.rfile.read(length) or b"{}")
            except (json.JSONDecodeError, UnicodeDecodeError):
                self._json(422, {"code": "invalid_json"})
                return None
            if not isinstance(value, dict):
                self._json(422, {"code": "object_required"})
                return None
            return value

        def _exact(self, payload, fields):
            unknown, missing = sorted(set(payload) - fields), sorted(fields - set(payload))
            if unknown or missing:
                self._json(422, {"code": "invalid_fields", "unknown": unknown, "missing": missing})
                return False
            return True

        def _stream_input(self, identity, project_id, parsed):
            if not self._project(identity, project_id, "input.manage"):
                return self._json(404, {"code": "not_found"})
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = 0
            if length <= 0:
                return self._json(411, {"code": "content_length_required"})
            if length > MAX_INPUT_BYTES:
                return self._json(413, {"code": "input_too_large", "max_bytes": MAX_INPUT_BYTES})
            name = parse_qs(parsed.query).get("name", [""])[0]
            safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", Path(str(name)).name)[:180] or "input.bin"
            temporary = uploads / f".upload-{os.urandom(12).hex()}"
            target = uploads / f"{os.urandom(8).hex()}-{safe_name}"
            digest, remaining = hashlib.sha256(), length
            try:
                with temporary.open("xb") as output:
                    while remaining:
                        chunk = self.rfile.read(min(1024 * 1024, remaining))
                        if not chunk:
                            raise ValueError("upload ended before Content-Length bytes were received")
                        output.write(chunk)
                        digest.update(chunk)
                        remaining -= len(chunk)
                temporary.replace(target)
                try:
                    input_id = store.add_input(project_id, safe_name, target, identity.subject_id, digest.hexdigest())
                except Exception:
                    target.unlink(missing_ok=True)
                    raise
            except Exception:
                temporary.unlink(missing_ok=True)
                raise
            return self._json(201, {"input_id": input_id, "name": safe_name, "size": length})

        def do_GET(self):
            parsed, path = urlparse(self.path), urlparse(self.path).path.rstrip("/") or "/"
            # Branding is a public static asset so the login page can render
            # before gateway authentication.  The package ships the existing
            # Windows icon under security_scanner/assets for offline installs.
            if path in {"/favicon.ico", "/koda/assets/KODA.ico"}:
                try:
                    self._send(200, _KODA_ICON.read_bytes(), "image/x-icon")
                except OSError:
                    self._send(404, b"Not found", "text/plain; charset=utf-8")
                return
            if path.startswith("/koda/assets/"):
                self._send(404, b"Not found", "text/plain; charset=utf-8")
                return
            if path == "/koda/live":
                return self._json(200, {"status": "live"})
            if path == "/koda/ready":
                try:
                    with store._db() as db:
                        db.execute("SELECT 1").fetchone()
                    if not self.server.portal_worker.available:
                        raise RuntimeError("worker unavailable")
                    return self._json(200, {"status": "ready"})
                except Exception:
                    return self._json(503, {"status": "not_ready"})
            if path == "/koda/login":
                next_path = _safe_next(parse_qs(parsed.query).get("next", ["/koda/"])[0])
                return self._html(200, login_page(next_path))
            api = path.startswith("/koda/api/")
            authenticated = self._identity(api)
            if not authenticated:
                return
            identity, subject = authenticated
            if path == "/koda/api/v1/me":
                return self._json(200, {"subject_id": identity.subject_id, "display": identity.display, "status": subject["status"], "system_admin": bool(subject["system_admin"])})
            if subject["status"] != "enabled":
                return self._deny_subject(subject, api)
            admin = self._admin(subject)
            projects = store.list_projects(identity.subject_id)
            nav_permissions = self._nav_permissions(identity, subject, projects)
            if path == "/koda/guide":
                return self._html(200, guide_page(admin=admin, nav_permissions=nav_permissions))
            if path in {"/koda", "/"}:
                visible = self._screen_projects(identity, subject, projects, "dashboard.view")
                if not admin and not visible:
                    return self._deny_screen(admin, nav_permissions)
                project_runs = [
                    (project, [store.run(run["run_id"]) for run in store.list_runs(project["project_id"])])
                    for project in visible
                ]
                return self._html(200, dashboard(identity, visible, project_runs, admin=admin, nav_permissions=nav_permissions))
            if path in {"/koda/scans/new", "/koda/scans/library", "/koda/scans/source"}:
                if path == "/koda/scans/new":
                    scope = "all"
                    screen_permission = None
                elif path == "/koda/scans/source":
                    scope, screen_permission = "source", "scan.source.view"
                else:
                    scope, screen_permission = "library", "scan.library.view"
                if screen_permission:
                    visible = self._screen_projects(identity, subject, projects, screen_permission)
                elif self._admin(subject):
                    visible = projects
                else:
                    visible = [
                        project for project in projects
                        if store.can(identity.subject_id, project["project_id"], "scan.library.view")
                        and store.can(identity.subject_id, project["project_id"], "scan.source.view")
                    ]
                if not admin and not visible:
                    return self._deny_screen(admin, nav_permissions)
                scan_projects = [
                    {
                        **project,
                        "can_upload": store.can(identity.subject_id, project["project_id"], "input.manage"),
                        "can_scan": store.can(identity.subject_id, project["project_id"], "scan.create"),
                    }
                    for project in visible
                ]
                return self._html(200, new_scan_page(scan_projects, admin=admin, scan_scope=scope, nav_permissions=nav_permissions))
            if path == "/koda/projects":
                visible = self._screen_projects(identity, subject, projects, "projects.view")
                if not admin and not visible:
                    return self._deny_screen(admin, nav_permissions)
                enriched = [
                    {**project, "inputs": store.list_inputs(project["project_id"]), "runs": store.list_runs(project["project_id"])}
                    for project in visible
                ]
                return self._html(200, projects_page(enriched, admin=admin, nav_permissions=nav_permissions))
            match = re.fullmatch(r"/koda/projects/([0-9a-f-]+)", path)
            if match:
                project = self._project(identity, match.group(1), "projects.view")
                if not project:
                    return self._html(404, page("찾을 수 없음", "<p>프로젝트가 없습니다.</p>", admin=admin, nav_permissions=nav_permissions))
                project_id = project["project_id"]
                return self._html(200, project_page(project, store.list_inputs(project_id), store.list_runs(project_id), can_upload=store.can(identity.subject_id, project_id, "input.manage"), can_scan=store.can(identity.subject_id, project_id, "scan.create"), admin=admin, nav_permissions=nav_permissions))
            if path == "/koda/runs":
                visible = self._screen_projects(identity, subject, projects, "runs.view")
                if not admin and not visible:
                    return self._deny_screen(admin, nav_permissions)
                return self._html(200, runs_page([(p, store.list_runs(p["project_id"])) for p in visible], admin=admin, nav_permissions=nav_permissions))
            match = re.fullmatch(r"/koda/runs/([0-9a-f-]+)", path)
            if match:
                try:
                    run = store.run(match.group(1))
                except KeyError:
                    return self._html(404, page("찾을 수 없음", "<p>분석 회차가 없습니다.</p>", admin=admin, nav_permissions=nav_permissions))
                project = self._project(identity, run["project_id"], "runs.view")
                if not project:
                    return self._html(404, page("찾을 수 없음", "<p>분석 회차가 없습니다.</p>", admin=admin, nav_permissions=nav_permissions))
                return self._html(200, run_page(run, project_name=project["name"], admin=admin, nav_permissions=nav_permissions))
            if path == "/koda/compare":
                visible = self._screen_projects(identity, subject, projects, "compare.view")
                if not admin and not visible:
                    return self._deny_screen(admin, nav_permissions)
                left, right = parse_qs(parsed.query).get("left", [""])[0], parse_qs(parsed.query).get("right", [""])[0]
                return self._html(200, _compare_page(store, identity.subject_id, left, right, admin, nav_permissions))
            if path == "/koda/api/v1/standards":
                if not ({"scan.library.view", "scan.source.view"} & nav_permissions):
                    return self._deny_screen(admin, nav_permissions, api=True)
                from .standards import standards_payload
                return self._json(200, standards_payload())
            if path == "/koda/api/v1/vulnerability-db":
                if "scan.library.view" not in nav_permissions:
                    return self._deny_screen(admin, nav_permissions, api=True)
                return self._json(200, _vulnerability_database_status())
            if path == "/koda/api/v1/compare":
                if "compare.view" not in nav_permissions:
                    return self._deny_screen(admin, nav_permissions, api=True)
                query = parse_qs(parsed.query)
                try:
                    comparison = _comparison_data(store, identity.subject_id, query.get("left", [""])[0], query.get("right", [""])[0])
                except KeyError:
                    return self._json(404, {"code": "not_found"})
                except ValueError as exc:
                    return self._json(422, {"code": "invalid_comparison", "detail": str(exc)})
                export_format = query.get("format", ["json"])[0]
                if export_format == "json":
                    raw, content_type, extension = (json.dumps(comparison, ensure_ascii=False, indent=2) + "\n").encode(), "application/json; charset=utf-8", "json"
                elif export_format == "csv":
                    output = io.StringIO(newline="")
                    writer = csv.DictWriter(output, fieldnames=("status", "severity", "rule_id", "category", "path", "line", "title"), lineterminator="\r\n")
                    writer.writeheader()
                    writer.writerows(comparison["findings"])
                    raw, content_type, extension = b"\xef\xbb\xbf" + output.getvalue().encode("utf-8"), "text/csv; charset=utf-8", "csv"
                else:
                    return self._json(422, {"code": "unsupported_comparison_format"})
                return self._send(200, raw, content_type, {"Content-Disposition": f'attachment; filename="koda-comparison.{extension}"'})
            if path == "/koda/api/v1/projects":
                visible = self._screen_projects(identity, subject, projects, "projects.view")
                if not admin and not visible:
                    return self._deny_screen(admin, nav_permissions, api=True)
                return self._json(200, visible)
            match = re.fullmatch(r"/koda/api/v1/projects/([0-9a-f-]+)/inputs", path)
            if match:
                return self._json(200, store.list_inputs(match.group(1))) if self._project(identity, match.group(1), "projects.view") else self._json(404, {"code": "not_found"})
            match = re.fullmatch(r"/koda/api/v1/projects/([0-9a-f-]+)/runs", path)
            if match:
                return self._json(200, store.list_runs(match.group(1))) if self._project(identity, match.group(1), "runs.view") else self._json(404, {"code": "not_found"})
            match = re.fullmatch(r"/koda/api/v1/runs/([0-9a-f-]+)", path)
            if match:
                try:
                    run = store.run(match.group(1))
                except KeyError:
                    return self._json(404, {"code": "not_found"})
                return self._json(200, run) if self._project(identity, run["project_id"], "runs.view") else self._json(404, {"code": "not_found"})
            match = re.fullmatch(r"/koda/api/v1/runs/([0-9a-f-]+)/sbom", path)
            if match:
                try:
                    run = store.run(match.group(1))
                except KeyError:
                    return self._json(404, {"code": "not_found"})
                if not self._project(identity, run["project_id"], "runs.view"):
                    return self._json(404, {"code": "not_found"})
                if run["status"] != "completed":
                    return self._json(409, {"code": "run_not_completed"})
                sbom_format = parse_qs(parsed.query).get("format", ["nis-sbom"])[0]
                result = run.get("result") or {}
                if sbom_format == "nis-sbom":
                    from .sbom import render_nis_sbom_rows

                    nis = result.get("nis_sbom") or {}
                    rows = nis.get("rows") if isinstance(nis, dict) else None
                    if not rows:
                        rows = [
                            {
                                "Component Name": component.get("name", ""),
                                "Component Version": component.get("version", ""),
                                "Component Path": component.get("path", ""),
                                "Unique Identifier": component.get("purl", ""),
                            }
                            for component in result.get("components", [])
                            if isinstance(component, dict)
                        ]
                    if not rows:
                        return self._json(409, {"code": "sbom_unavailable"})
                    raw = render_nis_sbom_rows(rows, product_name=f"KODA analysis round {run['round_number']}").encode("utf-8")
                    filename = f"koda-round-{run['round_number']}-nis-sbom-1.0.csv"
                    return self._send(200, raw, "text/csv; charset=utf-8", {"Content-Disposition": f'attachment; filename="{filename}"'})
                if sbom_format == "cyclonedx":
                    sbom = result.get("sbom")
                    if not isinstance(sbom, dict) or not sbom.get("components"):
                        return self._json(409, {"code": "sbom_unavailable"})
                    raw = (json.dumps(sbom, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
                    filename = f"koda-round-{run['round_number']}-cyclonedx-1.6.json"
                    return self._send(200, raw, "application/vnd.cyclonedx+json; charset=utf-8", {"Content-Disposition": f'attachment; filename="{filename}"'})
                return self._json(422, {"code": "unsupported_sbom_format"})
            match = re.fullmatch(r"/koda/api/v1/runs/([0-9a-f-]+)/(report|report(?:-detail)?\.html)", path)
            if match:
                try:
                    run = store.run(match.group(1))
                except KeyError:
                    return self._json(404, {"code": "not_found"})
                if not self._project(identity, run["project_id"], "runs.view"):
                    return self._json(404, {"code": "not_found"})
                if run["status"] != "completed":
                    return self._json(409, {"code": "run_not_completed"})
                from .reporting import (
                    PdfExportError,
                    render_html_pair_zip_from_payload,
                    render_hwpx,
                    render_markdown_from_payload,
                    render_pdf,
                    render_xlsx,
                )

                report_format = parse_qs(parsed.query).get("format", ["html"])[0]
                result = dict(run.get("result") or {})
                scan = dict(result.get("scan") or {})
                snapshot = run.get("snapshot") or {}
                scan.setdefault("scope", snapshot.get("scan_scope") or "all")
                scan.setdefault("standard", run.get("standard") or snapshot.get("standard"))
                scan.setdefault("standard_category", run.get("standard_category") or snapshot.get("standard_category"))
                result["scan"] = scan
                filename = f"koda-round-{run['round_number']}-report"
                if match.group(2) in {"report.html", "report-detail.html"}:
                    archive = render_html_pair_zip_from_payload(result, language)
                    with zipfile.ZipFile(io.BytesIO(archive)) as reports:
                        return self._send(200, reports.read(match.group(2)), "text/html; charset=utf-8")
                if report_format == "html":
                    raw, content_type, extension = render_html_pair_zip_from_payload(result, language), "application/zip", "zip"
                elif report_format in {"md", "markdown"}:
                    raw, content_type, extension = render_markdown_from_payload(result, language).encode("utf-8"), "text/markdown; charset=utf-8", "md"
                elif report_format == "xlsx":
                    raw, content_type, extension = render_xlsx(result, language), "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "xlsx"
                elif report_format == "hwpx":
                    raw, content_type, extension = render_hwpx(result, language), "application/hwp+zip", "hwpx"
                elif report_format == "pdf":
                    try:
                        raw = render_pdf(result, language)
                    except PdfExportError as exc:
                        return self._json(503, {"code": "pdf_unavailable", "detail": str(exc)})
                    content_type, extension = "application/pdf", "pdf"
                elif report_format == "json":
                    raw, content_type, extension = (json.dumps(result, ensure_ascii=False, indent=2) + "\n").encode("utf-8"), "application/json; charset=utf-8", "json"
                else:
                    return self._json(422, {"code": "unsupported_report_format"})
                return self._send(200, raw, content_type, {"Content-Disposition": f'attachment; filename="{filename}.{extension}"'})
            if path == "/koda/api/v1/admin/audit":
                if not admin:
                    return self._json(403, {"code": "forbidden"})
                if parse_qs(parsed.query).get("format", [""])[0] != "xlsx":
                    return self._json(422, {"code": "unsupported_audit_format"})
                from .reporting import render_rows_xlsx

                project_names = {project["project_id"]: project["name"] for project in projects}
                rows = [["서울 시각", "주체 ID", "동작", "프로젝트명", "프로젝트 ID", "상세 JSON"]]
                rows.extend([
                    format_portal_time(event["created_at"]),
                    event.get("subject_id") or "",
                    event["action"],
                    project_names.get(event.get("project_id"), ""),
                    event.get("project_id") or "",
                    event["detail_json"],
                ] for event in store.audit_events(None))
                raw = render_rows_xlsx("Audit", rows)
                return self._send(200, raw, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", {
                    "Content-Disposition": 'attachment; filename="koda-audit.xlsx"',
                })
            if path.startswith("/koda/admin"):
                if not admin:
                    return self._html(403, page("권한 없음", "<p>시스템 관리자만 접근할 수 있습니다.</p>"))
                return self._admin_get(path, parsed, identity, nav_permissions)
            self._json(404, {"code": "not_found"}) if api else self._html(404, page("찾을 수 없음", "<p>요청한 화면이 없습니다.</p>", admin=admin))

        def _admin_get(self, path, parsed, identity, nav_permissions):
            projects = store.list_projects(identity.subject_id)
            if path in {"/koda/admin", "/koda/admin/subjects"}:
                subjects = store.list_subjects()
                subject_options = "".join(f"<option value='{esc(s['subject_id'])}' data-status='{esc(s['status'])}' data-admin='{int(s['system_admin'])}'>{esc(s['display'] or s['subject_id'])}</option>" for s in subjects if s["status"] in {"enabled", "disabled"})
                rows = "".join(f"<tr data-page-item><td>{esc(s['display'])}</td><td><code>{esc(s['subject_id'])}</code></td><td>{esc(s['status'])}</td><td>{'예' if s['system_admin'] else '아니오'}</td></tr>" for s in subjects)
                enabled_subjects = [s for s in subjects if s["status"] == "enabled"]
                access_subject_options = "".join(f"<option value='{esc(s['subject_id'])}'>{esc(s['display'] or s['subject_id'])}</option>" for s in enabled_subjects)
                project_options = "".join(f"<option value='{esc(p['project_id'])}'>{esc(p['name'])}</option>" for p in projects)
                policy = store.role_policy()
                role_options = "<option value=''>접근 해제</option>" + "".join(f"<option value='{esc(role)}'>{esc(ROLE_LABELS.get(role, role))}</option>" for role in policy["roles"])
                access_rows = "".join(
                    f"<tr data-page-item><td>{esc(m['project_name'])}</td><td>{esc(m['display'])}</td><td><code>{esc(m['subject_id'])}</code></td><td>{esc(ROLE_LABELS.get(m['role'], m['role']))}<br><code>{esc(m['role'])}</code></td></tr>"
                    for m in store.list_memberships_all()
                ) or "<tr><td colspan='4' class='empty'>배정된 프로젝트 접근 권한이 없습니다.</td></tr>"
                form = f"<section class='panel'><div class='panel-head'><h2>KODA 접근 제어</h2></div><div class='panel-body'><form id='subject'><label>공유 계정<select name='subject_id'>{subject_options}</select></label><label>KODA 접근<select name='status'><option value='enabled'>허용</option><option value='disabled'>차단</option></select></label><label class='check-label'><input type='checkbox' name='system_admin'>KODA 시스템 관리자</label><div class='toolbar-submit'><button>저장</button></div></form></div></section>"
                access = f"<section class='panel'><div class='panel-head'><div><h2>사용자별 프로젝트 접근</h2><p class='muted'>역할 정의는 KODA 전체에 공통으로 적용되고, 접근 가능한 프로젝트와 역할은 사용자별로 배정합니다.</p></div></div><div class='panel-body'><form id='membership' class='toolbar'><label>프로젝트<select name='project_id'>{project_options}</select></label><label>공유 계정<select name='subject_id'>{access_subject_options}</select></label><label>역할<select name='role'>{role_options}</select></label><button>적용</button></form></div><div class='table-wrap' data-pager data-page-size='10'><table><thead><tr><th>프로젝트</th><th>계정</th><th>UUID</th><th>역할</th></tr></thead><tbody>{access_rows}</tbody></table></div></section>"
                script = "<script>const subjectForm=document.querySelector('#subject'),subjectSelect=subjectForm.elements.subject_id;function syncSubject(){const option=subjectSelect.selectedOptions[0];subjectForm.elements.status.value=option?.dataset.status||'enabled';subjectForm.elements.system_admin.checked=option?.dataset.admin==='1'}subjectSelect.addEventListener('change',syncSubject);syncSubject();subjectForm.addEventListener('submit',async e=>{e.preventDefault();const f=new FormData(e.currentTarget);try{await json('/koda/api/v1/admin/subjects',{method:'POST',body:JSON.stringify({subject_id:f.get('subject_id'),status:f.get('status'),system_admin:f.get('system_admin')==='on'})});location.reload()}catch(x){alert(x.message)}});document.querySelector('#membership')?.addEventListener('submit',async e=>{e.preventDefault();const f=new FormData(e.currentTarget);try{await json('/koda/api/v1/admin/memberships',{method:'POST',body:JSON.stringify({project_id:f.get('project_id'),subject_id:f.get('subject_id'),role:f.get('role')})});location.reload()}catch(x){alert(x.message)}})</script>"
                body = form + access + f"<section class='panel'><div class='panel-head'><h2>공유 계정 현황</h2><input id='subject-search' type='search' placeholder='계정 검색'></div><div class='table-wrap' data-pager data-page-size='10'><table id='subject-table'><thead><tr><th>표시</th><th>UUID</th><th>KODA 상태</th><th>관리자</th></tr></thead><tbody>{rows}</tbody></table></div></section>" + script + "<script>document.querySelector('#subject-search').addEventListener('input',e=>{document.querySelectorAll('#subject-table tbody tr').forEach(r=>r.dataset.filtered=String(!r.textContent.toLowerCase().includes(e.target.value.toLowerCase())));document.querySelector('#subject-table').closest('[data-pager]')._paginate()})</script>"
                return self._html(200, admin_page("KODA 접근 관리", body, active="subjects", nav_permissions=nav_permissions))
            if path == "/koda/admin/audit":
                project_names = {project["project_id"]: project["name"] for project in projects}
                rows = "".join(
                    f"<tr data-page-item><td>{esc(format_portal_time(e['created_at']))}</td><td><code>{esc(e['subject_id'] or '')}</code></td><td>{esc(e['action'])}</td><td>{esc(project_names.get(e['project_id'], ''))}<br><code>{esc(e['project_id'] or '')}</code></td><td><details><summary>보기</summary><pre>{esc(e['detail_json'])}</pre></details></td></tr>"
                    for e in store.audit_events(None)
                )
                body = f"<section class='panel'><div class='panel-head'><div><h2>감사 로그</h2><p class='muted'>사용자 표시 시각은 서울 기준입니다.</p></div><div class='toolbar'><input id='audit-search' type='search' placeholder='계정, 동작, 프로젝트 검색'><a class='button primary' href='/koda/api/v1/admin/audit?format=xlsx'>Excel 다운로드</a></div></div><div class='table-wrap' data-pager data-page-size='10'><table id='audit-table'><thead><tr><th>서울 시각</th><th>주체 ID</th><th>동작</th><th>프로젝트</th><th>상세 JSON</th></tr></thead><tbody>{rows}</tbody></table></div></section><script>document.querySelector('#audit-search').addEventListener('input',e=>{{document.querySelectorAll('#audit-table tbody tr').forEach(r=>r.dataset.filtered=String(!r.textContent.toLowerCase().includes(e.target.value.toLowerCase())));document.querySelector('#audit-table').closest('[data-pager]')._paginate()}})</script>"
                return self._html(200, admin_page("감사 로그", body, active="audit", nav_permissions=nav_permissions))
            if path == "/koda/admin/vulnerability-db":
                status = _vulnerability_database_status()
                available = bool(status.get("available"))
                label = "점검 가능" if available else "점검 불가"
                body = f"<section class='panel'><div class='panel-head'><div><h2>오프라인 취약점 DB</h2><p class='muted'>KODA가 라이브러리 취약점 점검에 실제 사용하는 Grype와 DB 상태입니다.</p></div><span class='status status-{'completed' if available else 'failed'}'>{label}</span></div><div class='panel-body'><ul class='summary-list'><li><span>설정</span><strong>{'예' if status.get('configured') else '아니오'}</strong></li><li><span>Grype 버전</span><strong>{esc(status.get('version') or '확인 불가')}</strong></li></ul><h3>DB 정보</h3><pre>{esc(json.dumps(status.get('database') or {}, ensure_ascii=False, indent=2))}</pre><p class='error'>{esc(status.get('warning') or '')}</p><a class='button primary' href='/koda/admin/vulnerability-db'>다시 확인</a></div></section>"
                return self._html(200, admin_page("취약점 DB", body, active="vulnerability-db", nav_permissions=nav_permissions))
            project_id = parse_qs(parsed.query).get("project", [projects[0]["project_id"] if projects else ""])[0]
            options = "".join(f"<option value='{esc(p['project_id'])}' {'selected' if p['project_id']==project_id else ''}>{esc(p['name'])}</option>" for p in projects)
            if path == "/koda/admin/roles":
                policy = store.role_policy()
                role_headers = "".join(
                    f"<th class='role-head'><strong>{esc(ROLE_LABELS.get(role, role))}</strong><small class='muted'>{esc(ROLE_DESCRIPTIONS.get(role, '사용자 정의 역할'))}</small><code>{esc(role)}</code></th>"
                    for role in policy["roles"]
                )
                def permission_table(title, permissions):
                    rows = []
                    for permission in permissions:
                        screen, feature, description = PERMISSION_METADATA[permission]
                        cells = "".join(
                            f"<td class='permission-check'><input type='checkbox' name='{esc(role)}' value='{esc(permission)}' {'checked' if permission in values else ''} aria-label='{esc(ROLE_LABELS.get(role, role))} · {esc(screen)} · {esc(feature)}'></td>"
                            for role, values in policy["roles"].items()
                        )
                        rows.append(f"<tr><th><strong>{esc(screen)}</strong><br><small>{esc(feature)}</small><br><code>{esc(permission)}</code></th><td class='wrap'>{esc(description)}</td>{cells}</tr>")
                    return f"<h3 class='panel-body'>{esc(title)}</h3><div class='table-wrap'><table><thead><tr><th>화면·기능</th><th>설명</th>{role_headers}</tr></thead><tbody>{''.join(rows)}</tbody></table></div>"
                screen_table = permission_table("화면 접근 권한", (
                    "dashboard.view", "scan.library.view", "scan.source.view", "runs.view", "compare.view", "projects.view",
                ))
                # Project creation is a global system-admin operation; only
                # project-scoped actions are exposed as role-level features.
                feature_table = permission_table("기능 실행 권한", ("input.manage", "scan.create"))
                body = f"<section class='panel'><div class='panel-head'><div><h2>KODA 전역 역할 정책</h2><p class='muted'>역할 정의는 모든 프로젝트에 공통 적용됩니다. 사용자별 프로젝트 접근은 KODA 접근 탭에서 배정합니다.</p></div></div><form id='roles'><input type='hidden' name='expected_version' value='{policy['version']}'>{screen_table}{feature_table}<div class='panel-body'><button class='primary'>역할 정책 저장</button></div></form></section><script>document.querySelector('#roles')?.addEventListener('submit',async e=>{{e.preventDefault();const f=new FormData(e.currentTarget),roles={script_json({role: [] for role in policy['roles']})};for(const [k,v] of f)if(k in roles)roles[k].push(v);try{{await json('/koda/api/v1/admin/roles',{{method:'POST',body:JSON.stringify({{expected_version:Number(f.get('expected_version')),roles}})}});location.reload()}}catch(x){{alert(x.message)}}}})</script>"
                return self._html(200, admin_page("역할 정책", body, active="roles", nav_permissions=nav_permissions))
            if path == "/koda/admin/rules":
                policy = store.rule_policy(project_id) if project_id else {"version": 0, "disabled_rules": []}
                from .reporting import build_rule_catalog
                from .standards import rule_standard_mappings_payload

                disabled = set(policy["disabled_rules"])
                mappings = rule_standard_mappings_payload()
                catalog = build_rule_catalog("ko")
                visible_catalog = [group for group in catalog if group.get("key") != "local"]
                known_rules = sorted({rule["id"] for group in visible_catalog for rule in group.get("rules", [])})
                preserved_disabled = sorted(disabled - set(known_rules))
                rule_groups = []
                for group in visible_catalog:
                    choices = []
                    for rule in group.get("rules", []):
                        rows = []
                        relevant = [mapping for mapping in mappings.get(rule["id"], []) if mapping.get("standard_id") == group["key"]]
                        for mapping in relevant or [{}]:
                            standard_labels = mapping.get("standard_labels") if isinstance(mapping.get("standard_labels"), dict) else {}
                            category_labels = mapping.get("category_labels") if isinstance(mapping.get("category_labels"), dict) else {}
                            cwe_ids = ", ".join(str(value) for value in mapping.get("cwe_ids", []))
                            rows.append(
                                "<li>"
                                f"<strong>{esc(standard_labels.get('ko') or group['label'])}</strong> · "
                                f"카테고리 {esc(category_labels.get('ko') or mapping.get('category_id') or '—')} · "
                                f"공식 통제 ID {esc(mapping.get('official_id') or mapping.get('control_id') or '—')} · "
                                f"SW49 가이드 ID {esc(mapping.get('guide_id') or '—')} · "
                                f"CWE {esc(cwe_ids or '—')} · 지원 수준 {esc(mapping.get('support_level') or '—')}"
                                "</li>"
                            )
                        choices.append(
                            f"<div class='choice' data-rule-card><label><input type='checkbox' name='rule' value='{esc(rule['id'])}' data-rule-id='{esc(rule['id'])}' {'' if rule['id'] in disabled else 'checked'}> {esc(rule['title'])} <small class='muted'>{esc(rule['id'])}</small></label>"
                            f"<details><summary>상세 매핑</summary><ul>{''.join(rows)}</ul></details></div>"
                        )
                    rule_groups.append(f"<details data-rule-group><summary>{esc(group['label'])} ({len(group.get('rules', []))})</summary>{''.join(choices)}</details>")
                rule_groups = "".join(rule_groups)
                body = f"<form method='get' class='toolbar toolbar-spaced'><label>프로젝트<select name='project'>{options}</select></label><button>열기</button></form><section class='panel'><div class='panel-head'><div><h2>점검 규칙</h2><p class='muted'>보안 기준별 카드에서 공식 매핑을 확인합니다. 같은 규칙은 모든 카드에서 함께 켜지고 꺼집니다.</p></div><input id='rule-search' type='search' placeholder='규칙 검색'></div><form id='rules' class='panel-body'><input type='hidden' name='project_id' value='{esc(project_id)}'><input type='hidden' name='expected_version' value='{policy['version']}'>{rule_groups}<button class='primary toolbar-submit'>저장</button></form></section><script>const knownRules={script_json(known_rules)},preservedDisabled={script_json(preserved_disabled)};document.querySelectorAll('[data-rule-id]').forEach(box=>box.addEventListener('change',()=>document.querySelectorAll('[data-rule-id]').forEach(peer=>{{if(peer.dataset.ruleId===box.dataset.ruleId)peer.checked=box.checked}})));document.querySelector('#rule-search').addEventListener('input',e=>{{const q=e.target.value.toLowerCase();document.querySelectorAll('[data-rule-card]').forEach(card=>card.hidden=!card.textContent.toLowerCase().includes(q));document.querySelectorAll('[data-rule-group]').forEach(group=>group.hidden=![...group.querySelectorAll('[data-rule-card]')].some(card=>!card.hidden))}});document.querySelector('#rules')?.addEventListener('submit',async e=>{{e.preventDefault();const f=new FormData(e.currentTarget),enabled=new Set([...document.querySelectorAll('[data-rule-id]:checked')].map(x=>x.value)),disabled=[...new Set([...preservedDisabled,...knownRules.filter(id=>!enabled.has(id))])];try{{await json('/koda/api/v1/admin/rules',{{method:'POST',body:JSON.stringify({{project_id:f.get('project_id'),expected_version:Number(f.get('expected_version')),disabled_rules:disabled}})}});location.reload()}}catch(x){{alert(x.message)}}}})</script>"
                return self._html(200, admin_page("보안·품질 점검 설정", body, active="rules", nav_permissions=nav_permissions))
            return self._html(404, admin_page("찾을 수 없음", "<p>관리 화면이 없습니다.</p>", nav_permissions=nav_permissions))

        def do_POST(self):
            parsed = urlparse(self.path)
            path = parsed.path.rstrip("/")
            if path == "/koda/login":
                return self._html(405, login_page())
            authenticated = self._enabled(True)
            if not authenticated:
                return
            identity, subject = authenticated
            input_match = re.fullmatch(r"/koda/api/v1/projects/([0-9a-f-]+)/inputs", path)
            if input_match and self.headers.get_content_type() == "application/octet-stream":
                try:
                    return self._stream_input(identity, input_match.group(1), parsed)
                except PermissionError:
                    return self._json(403, {"code": "forbidden"})
                except KeyError:
                    return self._json(404, {"code": "not_found"})
                except (OSError, ValueError) as exc:
                    return self._json(422, {"code": "upload_failed", "detail": str(exc)})
            payload = self._payload()
            if payload is None:
                return
            admin = self._admin(subject)
            try:
                if path == "/koda/api/v1/projects":
                    if not admin:
                        return self._json(403, {"code": "forbidden"})
                    if not self._exact(payload, {"name"}):
                        return
                    project_id = store.create_project(payload["name"], identity.subject_id)
                    return self._json(201, {"project_id": project_id})
                match = re.fullmatch(r"/koda/api/v1/projects/([0-9a-f-]+)/inputs", path)
                if match:
                    return self._json(415, {"code": "binary_upload_required", "detail": "Content-Type application/octet-stream이 필요합니다"})
                if path == "/koda/api/v1/scans":
                    fields = {"project_id", "input_id", "standard", "standard_category"}
                    if not self._exact(payload, fields | ({"scan_scope"} if "scan_scope" in payload else set())):
                        return
                    payload.setdefault("scan_scope", "all")
                    screen_permissions = {
                        "library": ("scan.library.view",),
                        "source": ("scan.source.view",),
                        "all": ("scan.library.view", "scan.source.view"),
                    }.get(payload["scan_scope"], ())
                    if not screen_permissions or any(
                        not self._project(identity, payload["project_id"], permission)
                        for permission in screen_permissions
                    ) or not self._project(identity, payload["project_id"], "scan.create"):
                        return self._json(404, {"code": "not_found"})
                    if not self.server.portal_worker.available:
                        return self._json(503, {"code": "worker_unavailable"})
                    run = store.create_scan(identity.subject_id, **payload)
                    self.server.portal_worker.enqueue(run["run_id"])
                    return self._json(202, run)
                match = re.fullmatch(r"/koda/api/v1/runs/([0-9a-f-]+)/cancel", path)
                if match:
                    if not self._exact(payload, set()):
                        return
                    run = store.run(match.group(1))
                    if not self._project(identity, run["project_id"], "runs.view") or not self._project(identity, run["project_id"], "scan.create"):
                        return self._json(404, {"code": "not_found"})
                    return self._json(200, store.request_cancel(run["run_id"], identity.subject_id))
                if path == "/koda/api/v1/admin/subjects":
                    if not admin or not self._exact(payload, {"subject_id", "status", "system_admin"}):
                        return self._json(403, {"code": "forbidden"}) if not admin else None
                    return self._json(200, store.set_subject(payload["subject_id"], status=payload["status"], system_admin=payload["system_admin"], actor=identity.subject_id))
                if path == "/koda/api/v1/admin/roles":
                    if not admin or not self._exact(payload, {"expected_version", "roles"}):
                        return self._json(403, {"code": "forbidden"}) if not admin else None
                    return self._json(200, store.set_role_policy(payload["roles"], payload["expected_version"], identity.subject_id))
                if path == "/koda/api/v1/admin/memberships":
                    if not admin or not self._exact(payload, {"project_id", "subject_id", "role"}):
                        return self._json(403, {"code": "forbidden"}) if not admin else None
                    if payload["role"]:
                        store.set_membership(payload["project_id"], payload["subject_id"], payload["role"], identity.subject_id)
                    else:
                        store.remove_membership(payload["project_id"], payload["subject_id"], identity.subject_id)
                    return self._json(200, {"ok": True})
                if path == "/koda/api/v1/admin/rules":
                    project_id = payload.get("project_id")
                    if not admin:
                        return self._json(403, {"code": "forbidden"})
                    if not self._exact(payload, {"project_id", "expected_version", "disabled_rules"}):
                        return
                    from .reporting import build_rule_catalog
                    known_rules = {rule["id"] for group in build_rule_catalog("ko") for rule in group.get("rules", [])}
                    unknown_rules = sorted(set(payload["disabled_rules"]) - known_rules)
                    if unknown_rules:
                        return self._json(422, {"code": "unknown_rules", "rules": unknown_rules})
                    return self._json(200, store.set_rule_policy(project_id, payload["disabled_rules"], payload["expected_version"], identity.subject_id))
            except VersionConflict as exc:
                return self._json(409, {"code": "version_conflict", "detail": str(exc)})
            except PermissionError:
                return self._json(403, {"code": "forbidden"})
            except KeyError:
                return self._json(404, {"code": "not_found"})
            except (ValueError, TypeError) as exc:
                return self._json(422, {"code": "invalid_request", "detail": str(exc)})
            self._json(404, {"code": "not_found"})

    server = _PortalServer((host, port), Handler)
    server.daemon_threads = True
    server.portal_store = store
    server.portal_worker = _PortalWorker(store)
    return server


def _compare_page(store: PortalStore, subject_id: str, left: str, right: str, admin: bool, nav_permissions=None) -> str:
    projects = [
        project for project in store.list_projects(subject_id)
        if store.can(subject_id, project["project_id"], "compare.view")
    ]
    available = [
        {"project_id": project["project_id"], "project_name": project["name"], "runs": store.list_runs(project["project_id"])}
        for project in projects
    ]
    if right and not left:
        try:
            selected = store.run(right)
            runs = store.list_runs(selected["project_id"])
            current = next(i for i, run in enumerate(runs) if run["run_id"] == right)
            left = runs[current + 1]["run_id"] if current + 1 < len(runs) else ""
        except (KeyError, StopIteration):
            pass
    selected_project = ""
    for candidate in (right, left):
        if candidate:
            try:
                selected_project = store.run(candidate)["project_id"]
                break
            except KeyError:
                pass
    selected_project = selected_project or (available[0]["project_id"] if available else "")
    project_options = "".join(
        f"<option value='{esc(project['project_id'])}' {'selected' if project['project_id'] == selected_project else ''}>{esc(project['project_name'])}</option>"
        for project in available
    )
    form = f"""<form id='comparison-form' class='compare-layout'><section class='panel panel-body'><label>프로젝트<select id='compare-project'>{project_options}</select></label></section><section class='panel panel-body'><label>기준 회차<select name='left' id='compare-left'></select></label><label>대상 회차<select name='right' id='compare-right'></select></label><button class='primary toolbar-submit'>비교</button></section></form>
<script>const comparisonProjects={script_json(available)},selectedLeft={script_json(left)},selectedRight={script_json(right)};function comparisonLabel(x){{if(x.scan_scope==='library')return 'CVE 점검';if(x.scan_scope==='source'&&x.standard==='local'&&x.standard_category==='all')return '전체 / 전체';return `${{x.standard}} / ${{x.standard_category}}`}}function comparisonOptions(){{const p=comparisonProjects.find(x=>x.project_id===document.querySelector('#compare-project').value),options=(p?.runs||[]).map(x=>`<option value="${{x.run_id}}">#${{x.round_number}} · ${{comparisonLabel(x)}} · ${{x.status}}</option>`).join('');for(const id of ['compare-left','compare-right'])document.querySelector('#'+id).innerHTML=options;document.querySelector('#compare-left').value=selectedLeft;document.querySelector('#compare-right').value=selectedRight}}document.querySelector('#compare-project').addEventListener('change',comparisonOptions);document.querySelector('#comparison-form').addEventListener('submit',e=>{{e.preventDefault();location=`/koda/compare?left=${{encodeURIComponent(document.querySelector('#compare-left').value)}}&right=${{encodeURIComponent(document.querySelector('#compare-right').value)}}`}});comparisonOptions()</script>"""
    if not left or not right:
        return page("회차 비교", form + "<section class='panel empty compare-wide'>비교할 두 회차를 선택하세요.</section>", admin=admin, nav_permissions=nav_permissions)
    try:
        comparison = _comparison_data(store, subject_id, left, right)
    except (KeyError, ValueError):
        return page("회차 비교", form + "<p class='error'>비교할 회차를 찾을 수 없습니다.</p>", admin=admin, nav_permissions=nav_permissions)
    counts = comparison["counts"]
    rows = "".join(
        f"<tr data-page-item><td><span class='status status-{esc(item['status'])}'>{esc({'new':'신규','resolved':'해결','persistent':'유지'}[item['status']])}</span></td><td class='sev sev-{esc(item['severity'])}'>{esc(item['severity'])}</td><td><code>{esc(item['rule_id'])}</code></td><td>{esc(item['path'])}</td><td>{esc(item['line'])}</td><td>{esc(item['title'])}</td></tr>"
        for item in comparison["findings"]
    ) or "<tr><td colspan='6' class='empty'>변경된 항목이 없습니다.</td></tr>"
    query = f"left={left}&right={right}"
    body = f"""{form}<div class='compare-layout'><section class='panel summary-strip compare-wide'><div><small>신규</small><strong>{counts['new']}</strong></div><div><small>해결</small><strong>{counts['resolved']}</strong></div><div><small>유지</small><strong>{counts['persistent']}</strong></div></section><section class='panel compare-wide'><div class='panel-head'><h2>{esc(comparison['project_name'])} 항목별 비교</h2><div class='toolbar'><input id='comparison-search' type='search' placeholder='규칙, 파일, 제목 검색'><select id='comparison-status'><option value=''>모든 상태</option><option value='new'>신규</option><option value='resolved'>해결</option><option value='persistent'>유지</option></select><a class='button' href='/koda/api/v1/compare?{query}&format=csv'>CSV</a><a class='button' href='/koda/api/v1/compare?{query}&format=json'>JSON</a></div></div><div class='table-wrap' data-pager data-page-size='10'><table id='comparison-table'><thead><tr><th>상태</th><th>심각도</th><th>규칙</th><th>파일</th><th>위치</th><th>제목</th></tr></thead><tbody>{rows}</tbody></table></div></section></div><script>function filterComparison(){{const q=document.querySelector('#comparison-search').value.toLowerCase(),s=document.querySelector('#comparison-status').value;document.querySelectorAll('#comparison-table tbody tr').forEach(r=>r.dataset.filtered=String((q&&!r.textContent.toLowerCase().includes(q))||(s&&!r.querySelector('.status')?.classList.contains('status-'+s))));document.querySelector('#comparison-table').closest('[data-pager]')?._paginate()}}document.querySelector('#comparison-search').addEventListener('input',filterComparison);document.querySelector('#comparison-status').addEventListener('change',filterComparison)</script>"""
    return page("회차 비교", body, admin=admin, nav_permissions=nav_permissions)


def _comparison_data(store: PortalStore, subject_id: str, left: str, right: str) -> dict[str, object]:
    if not left or not right:
        raise ValueError("two different runs are required")
    before, after = store.run(left), store.run(right)
    if not store.can(subject_id, before["project_id"], "compare.view") or not store.can(subject_id, after["project_id"], "compare.view"):
        raise KeyError("run not found")
    if left == right:
        raise ValueError("two different runs are required")
    if before["project_id"] != after["project_id"]:
        raise ValueError("runs must belong to the same project")
    if before["status"] != "completed" or after["status"] != "completed":
        raise ValueError("completed runs are required")
    def mapped(run):
        values = (run.get("result") or {}).get("findings", [])
        return {(item.get("rule_id"), item.get("path"), item.get("line")): item for item in values}
    old, new = mapped(before), mapped(after)
    rows = []
    for key in sorted(set(old) | set(new), key=lambda value: tuple(str(item or "") for item in value)):
        status = "new" if key not in old else ("resolved" if key not in new else "persistent")
        item = new.get(key) or old.get(key) or {}
        rows.append({
            "status": status,
            "severity": str(item.get("severity", "info")),
            "rule_id": str(item.get("rule_id", "")),
            "category": str(item.get("category", "")),
            "path": str(item.get("path", "")),
            "line": item.get("line", ""),
            "title": str(item.get("title", "")),
        })
    return {
        "project_id": before["project_id"],
        "project_name": (store.project(before["project_id"]) or {}).get("name", ""),
        "left": left,
        "right": right,
        "counts": {status: sum(item["status"] == status for item in rows) for status in ("new", "resolved", "persistent")},
        "findings": rows,
    }


def serve_portal(host="127.0.0.1", port=8765, language="ko", db_path=None):
    server = create_portal_server(host, port, language, db_path)
    print(f"Serving KODA Linux portal at http://127.0.0.1:{port}/koda/")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0
