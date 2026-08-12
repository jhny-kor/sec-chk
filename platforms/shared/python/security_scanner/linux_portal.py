"""Linux-only authenticated portal; the Windows/local dashboard stays in server.py."""
from __future__ import annotations

import base64
import json
import os
import queue
import re
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .portal_identity import IdentityError, IdentityUnavailable, identity_from_headers
from .portal_store import PROJECT_PERMISSIONS, PortalStore, VersionConflict
from .portal_views import (
    admin_page,
    dashboard,
    esc,
    login_page,
    page,
    project_page,
    projects_page,
    run_page,
    runs_page,
)

MAX_JSON_BYTES = 36 * 1024 * 1024
MAX_INPUT_BYTES = 25 * 1024 * 1024
_KODA_ICON = Path(__file__).with_name("assets") / "KODA.ico"


def _safe_next(value: str) -> str:
    if not value.startswith("/koda/") or value.startswith("//") or "\\" in value or not re.fullmatch(r"/koda/[A-Za-z0-9._~!$&'()*+,;=:@/?%-]*", value):
        return "/koda/"
    parsed = urlparse(value)
    return value if not parsed.scheme and not parsed.netloc else "/koda/"


def _run_scan(store: PortalStore, run_id: str) -> None:
    store.mark_run_running(run_id)
    try:
        run = store.run(run_id)
        source = store.input(run["input_id"])
        snapshot = run["snapshot"]
        with tempfile.TemporaryDirectory(prefix="koda-portal-") as extraction:
            from .archive_input import prepare_input_target
            from .server import scan_directory_payload

            target = prepare_input_target(Path(source["path"]), Path(extraction))
            result = scan_directory_payload(
                str(target), language="ko", standard=snapshot["standard"],
                standard_category=snapshot["standard_category"],
                disabled_rules=tuple(snapshot["disabled_rules"]), allow_file=True,
                display_path=source["name"],
            )
        store.complete_run(run_id, result=result)
    except Exception as exc:  # worker errors are durable and visible per round
        store.complete_run(run_id, error=str(exc)[:2000])


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

        def _send(self, status, raw, content_type):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'")
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
            return identity, store.ensure_subject(identity.subject_id, identity.display)

        def _enabled(self, api=False):
            authenticated = self._identity(api)
            if not authenticated:
                return None
            identity, subject = authenticated
            if subject["status"] != "enabled":
                if api:
                    self._json(403, {"code": "subject_not_enabled", "status": subject["status"]})
                else:
                    self._html(403, page("접근 대기", "<p>관리자 승인 후 사용할 수 있습니다.</p>"))
                return None
            return identity, subject

        @staticmethod
        def _admin(subject):
            return bool(subject["system_admin"])

        def _project(self, identity, project_id, permission="project.view"):
            projects = {item["project_id"]: item for item in store.list_projects(identity.subject_id)}
            if project_id not in projects or not store.can(identity.subject_id, project_id, permission):
                return None
            return projects[project_id]

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

        def do_GET(self):
            parsed, path = urlparse(self.path), urlparse(self.path).path.rstrip("/") or "/"
            # Branding is a public static asset so the login page can render
            # before gateway authentication.  The package ships the existing
            # Windows icon under security_scanner/assets for offline installs.
            if path == "/koda/assets/KODA.ico":
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
                return self._json(403, {"code": "subject_not_enabled"}) if api else self._html(403, page("접근 대기", "<p>관리자 승인 후 사용할 수 있습니다.</p>"))
            admin = self._admin(subject)
            projects = store.list_projects(identity.subject_id)
            if path in {"/koda", "/"}:
                return self._html(200, dashboard(identity, projects, sum(len(store.list_runs(p["project_id"])) for p in projects), admin=admin))
            if path == "/koda/projects":
                return self._html(200, projects_page(projects, admin=admin))
            match = re.fullmatch(r"/koda/projects/([0-9a-f-]+)", path)
            if match:
                project = self._project(identity, match.group(1))
                if not project:
                    return self._html(404, page("찾을 수 없음", "<p>프로젝트가 없습니다.</p>", admin=admin))
                project_id = project["project_id"]
                return self._html(200, project_page(project, store.list_inputs(project_id), store.list_runs(project_id), can_upload=store.can(identity.subject_id, project_id, "input.manage"), can_scan=store.can(identity.subject_id, project_id, "scan.create"), admin=admin))
            if path == "/koda/runs":
                return self._html(200, runs_page([(p, store.list_runs(p["project_id"])) for p in projects], admin=admin))
            match = re.fullmatch(r"/koda/runs/([0-9a-f-]+)", path)
            if match:
                try:
                    run = store.run(match.group(1))
                except KeyError:
                    return self._html(404, page("찾을 수 없음", "<p>분석 회차가 없습니다.</p>", admin=admin))
                if not self._project(identity, run["project_id"]):
                    return self._html(404, page("찾을 수 없음", "<p>분석 회차가 없습니다.</p>", admin=admin))
                return self._html(200, run_page(run, admin=admin))
            if path == "/koda/compare":
                left, right = parse_qs(parsed.query).get("left", [""])[0], parse_qs(parsed.query).get("right", [""])[0]
                return self._html(200, _compare_page(store, identity.subject_id, left, right, admin))
            if path == "/koda/api/v1/standards":
                from .standards import standards_payload
                return self._json(200, standards_payload())
            if path == "/koda/api/v1/projects":
                return self._json(200, projects)
            match = re.fullmatch(r"/koda/api/v1/projects/([0-9a-f-]+)/inputs", path)
            if match:
                return self._json(200, store.list_inputs(match.group(1))) if self._project(identity, match.group(1)) else self._json(404, {"code": "not_found"})
            match = re.fullmatch(r"/koda/api/v1/projects/([0-9a-f-]+)/runs", path)
            if match:
                return self._json(200, store.list_runs(match.group(1))) if self._project(identity, match.group(1)) else self._json(404, {"code": "not_found"})
            match = re.fullmatch(r"/koda/api/v1/runs/([0-9a-f-]+)", path)
            if match:
                try:
                    run = store.run(match.group(1))
                except KeyError:
                    return self._json(404, {"code": "not_found"})
                return self._json(200, run) if self._project(identity, run["project_id"]) else self._json(404, {"code": "not_found"})
            if path.startswith("/koda/admin"):
                if not admin:
                    return self._html(403, page("권한 없음", "<p>시스템 관리자만 접근할 수 있습니다.</p>"))
                return self._admin_get(path, parsed)
            self._json(404, {"code": "not_found"}) if api else self._html(404, page("찾을 수 없음", "<p>요청한 화면이 없습니다.</p>", admin=admin))

        def _admin_get(self, path, parsed):
            projects = store.list_projects(self._identity(True)[0].subject_id)
            if path in {"/koda/admin", "/koda/admin/subjects"}:
                rows = "".join(f"<tr><td>{esc(s['display'])}</td><td><code>{esc(s['subject_id'])}</code></td><td>{esc(s['status'])}</td><td>{'예' if s['system_admin'] else '아니오'}</td></tr>" for s in store.list_subjects())
                form = "<section><h2>계정 승인/권한</h2><form id='subject'><label>Tracker UUID<input name='subject_id' required></label><label>상태<select name='status'><option>enabled</option><option>disabled</option><option>pending</option><option>tombstoned</option></select></label><label><input type='checkbox' name='system_admin'> 시스템 관리자</label><button>저장</button></form></section>"
                script = "<script>document.querySelector('#subject').addEventListener('submit',async e=>{e.preventDefault();const f=new FormData(e.currentTarget);try{await json('/koda/api/v1/admin/subjects',{method:'POST',body:JSON.stringify({subject_id:f.get('subject_id'),status:f.get('status'),system_admin:f.get('system_admin')==='on'})});location.reload()}catch(x){alert(x.message)}})</script>"
                return self._html(200, admin_page("계정 관리", form + f"<section><table><tr><th>표시</th><th>UUID</th><th>상태</th><th>관리자</th></tr>{rows}</table></section>" + script))
            if path == "/koda/admin/audit":
                rows = "".join(f"<tr><td>{esc(e['created_at'])}</td><td>{esc(e['subject_id'])}</td><td>{esc(e['action'])}</td><td>{esc(e['project_id'])}</td></tr>" for e in store.audit_events())
                return self._html(200, admin_page("감사 로그", f"<section><table><tr><th>시각</th><th>주체</th><th>동작</th><th>프로젝트</th></tr>{rows}</table></section>"))
            project_id = parse_qs(parsed.query).get("project", [projects[0]["project_id"] if projects else ""])[0]
            options = "".join(f"<option value='{esc(p['project_id'])}' {'selected' if p['project_id']==project_id else ''}>{esc(p['name'])}</option>" for p in projects)
            if path == "/koda/admin/roles":
                policy = store.role_policy(project_id) if project_id else {"version": 0, "roles": {}}
                memberships = store.list_memberships(project_id) if project_id else []
                member_rows = "".join(f"<tr><td>{esc(m['display'])}</td><td><code>{esc(m['subject_id'])}</code></td><td>{esc(m['role'])}</td></tr>" for m in memberships)
                role_options = "".join(f"<option>{esc(role)}</option>" for role in policy["roles"])
                membership_form = f"<section><h2>계정별 역할</h2><form id='membership'><input type='hidden' name='project_id' value='{esc(project_id)}'><label>Tracker UUID<input name='subject_id' required></label><label>역할<select name='role'>{role_options}</select></label><button>배정</button></form><table><tr><th>계정</th><th>UUID</th><th>역할</th></tr>{member_rows}</table></section>"
                return self._html(200, admin_page("역할 정책", f"<form method='get'><select name='project'>{options}</select><button>열기</button></form><section><form id='roles'><input type='hidden' name='project_id' value='{esc(project_id)}'><input type='hidden' name='expected_version' value='{policy['version']}'><label>역할 정책 JSON<textarea name='roles' rows='16'>{esc(json.dumps(policy['roles'],ensure_ascii=False,indent=2))}</textarea></label><p>프로젝트 권한: {esc(', '.join(sorted(PROJECT_PERMISSIONS)))}</p><button>저장</button></form></section>{membership_form}<script>document.querySelector('#roles')?.addEventListener('submit',async e=>{{e.preventDefault();const f=new FormData(e.currentTarget);try{{await json('/koda/api/v1/admin/roles',{{method:'POST',body:JSON.stringify({{project_id:f.get('project_id'),expected_version:Number(f.get('expected_version')),roles:JSON.parse(f.get('roles'))}})}});location.reload()}}catch(x){{alert(x.message)}}}});document.querySelector('#membership')?.addEventListener('submit',async e=>{{e.preventDefault();const f=new FormData(e.currentTarget);try{{await json('/koda/api/v1/admin/memberships',{{method:'POST',body:JSON.stringify({{project_id:f.get('project_id'),subject_id:f.get('subject_id'),role:f.get('role')}})}});location.reload()}}catch(x){{alert(x.message)}}}})</script>"))
            if path == "/koda/admin/rules":
                policy = store.rule_policy(project_id) if project_id else {"version": 0, "disabled_rules": []}
                return self._html(200, admin_page("보안·품질 점검 설정", f"<form method='get'><select name='project'>{options}</select><button>열기</button></form><section><p>이 설정은 관리자만 바꿀 수 있습니다. 사용자는 검사 기준만 선택합니다.</p><form id='rules'><input type='hidden' name='project_id' value='{esc(project_id)}'><input type='hidden' name='expected_version' value='{policy['version']}'><label>비활성 규칙 (한 줄 하나)<textarea name='rules' rows='16'>{esc(chr(10).join(policy['disabled_rules']))}</textarea></label><button>저장</button></form></section><script>document.querySelector('#rules')?.addEventListener('submit',async e=>{{e.preventDefault();const f=new FormData(e.currentTarget);try{{await json('/koda/api/v1/admin/rules',{{method:'POST',body:JSON.stringify({{project_id:f.get('project_id'),expected_version:Number(f.get('expected_version')),disabled_rules:String(f.get('rules')).split(/\n/).map(x=>x.trim()).filter(Boolean)}})}});location.reload()}}catch(x){{alert(x.message)}}}})</script>"))
            return self._html(404, admin_page("찾을 수 없음", "<p>관리 화면이 없습니다.</p>"))

        def do_POST(self):
            path = urlparse(self.path).path.rstrip("/")
            if path == "/koda/login":
                return self._html(405, login_page())
            authenticated = self._enabled(True)
            if not authenticated:
                return
            identity, subject = authenticated
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
                    project_id = match.group(1)
                    if not self._project(identity, project_id, "input.manage"):
                        return self._json(404, {"code": "not_found"})
                    if not self._exact(payload, {"name", "contentBase64"}):
                        return
                    try:
                        content = base64.b64decode(payload["contentBase64"], validate=True)
                    except (ValueError, TypeError):
                        return self._json(422, {"code": "invalid_base64"})
                    if not content or len(content) > MAX_INPUT_BYTES:
                        return self._json(413, {"code": "input_too_large"})
                    safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", Path(str(payload["name"])).name)[:180] or "input.bin"
                    target = uploads / f"{os.urandom(8).hex()}-{safe_name}"
                    target.write_bytes(content)
                    input_id = store.add_input(project_id, safe_name, target, identity.subject_id)
                    return self._json(201, {"input_id": input_id})
                if path == "/koda/api/v1/scans":
                    fields = {"project_id", "input_id", "standard", "standard_category"}
                    if not self._exact(payload, fields):
                        return
                    if not self.server.portal_worker.available:
                        return self._json(503, {"code": "worker_unavailable"})
                    run = store.create_scan(identity.subject_id, **payload)
                    self.server.portal_worker.enqueue(run["run_id"])
                    return self._json(202, run)
                if path == "/koda/api/v1/admin/subjects":
                    if not admin or not self._exact(payload, {"subject_id", "status", "system_admin"}):
                        return self._json(403, {"code": "forbidden"}) if not admin else None
                    return self._json(200, store.set_subject(payload["subject_id"], status=payload["status"], system_admin=payload["system_admin"], actor=identity.subject_id))
                if path == "/koda/api/v1/admin/roles":
                    if not admin or not self._exact(payload, {"project_id", "expected_version", "roles"}):
                        return self._json(403, {"code": "forbidden"}) if not admin else None
                    return self._json(200, store.set_role_policy(payload["project_id"], payload["roles"], payload["expected_version"], identity.subject_id))
                if path == "/koda/api/v1/admin/memberships":
                    if not admin or not self._exact(payload, {"project_id", "subject_id", "role"}):
                        return self._json(403, {"code": "forbidden"}) if not admin else None
                    store.set_membership(payload["project_id"], payload["subject_id"], payload["role"], identity.subject_id)
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


def _compare_page(store: PortalStore, subject_id: str, left: str, right: str, admin: bool) -> str:
    form = f"<form><label>기준 회차 ID<input name='left' value='{esc(left)}'></label><label>대상 회차 ID<input name='right' value='{esc(right)}'></label><button>비교</button></form>"
    if not left or not right:
        return page("회차 비교", form, admin=admin)
    try:
        a, b = store.run(left), store.run(right)
        if not store.can(subject_id, a["project_id"]) or not store.can(subject_id, b["project_id"]):
            raise KeyError
    except KeyError:
        return page("회차 비교", form + "<p class='error'>비교할 회차를 찾을 수 없습니다.</p>", admin=admin)
    af = {(item.get("rule_id"), item.get("path"), item.get("line")) for item in (a.get("result") or {}).get("findings", [])}
    bf = {(item.get("rule_id"), item.get("path"), item.get("line")) for item in (b.get("result") or {}).get("findings", [])}
    return page("회차 비교", form + f"<div class='grid'><section><h2>신규</h2><strong>{len(bf-af)}</strong></section><section><h2>해결</h2><strong>{len(af-bf)}</strong></section><section><h2>유지</h2><strong>{len(af&bf)}</strong></section></div>", admin=admin)


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
