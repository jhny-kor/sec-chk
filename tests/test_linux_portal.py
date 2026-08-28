import datetime as dt
import base64
from collections import Counter
import csv
import hashlib
import http.client
import io
import json
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
import uuid
import zipfile
from pathlib import Path
from unittest.mock import patch

from security_scanner.portal_identity import IdentityError, identity_from_headers
from security_scanner.linux_portal import MAX_INPUT_BYTES, create_portal_server
from security_scanner.grype_adapter import GrypeMatch, GrypeResult
from security_scanner.portal_store import GLOBAL_ROLE_POLICY_ID, SCREEN_PERMISSIONS, PortalStore
from security_scanner.portal_views import format_portal_time
from security_scanner.reporting import render_html_pair_zip_from_payload
from security_scanner.server import scan_directory_payload


class LinuxPortalStoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = PortalStore(Path(self.tmp.name) / "portal.sqlite3")
        self.admin = str(uuid.uuid4())
        self.store.bootstrap(self.admin)
        self.project = self.store.create_project("demo")
        self.store.set_membership(self.project, self.admin, "admin")
        target = Path(self.tmp.name) / "input.txt"
        target.write_text("secret", encoding="utf-8")
        self.input_id = self.store.add_input(self.project, "input.txt", target)

    def tearDown(self):
        self.tmp.cleanup()

    def test_header_identity_and_expiry(self):
        headers = {
            "X-KODA-Identity-ID": self.admin,
            "X-KODA-Identity-Expires": (dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=1)).isoformat(),
            "X-KODA-Identity-Display": "YWRtaW4",
        }
        self.assertEqual(identity_from_headers(headers).display, "admin")
        headers["X-KODA-Identity-Expires"] = "2000-01-01T00:00:00+00:00"
        with self.assertRaises(IdentityError):
            identity_from_headers(headers)

    def test_round_snapshot_and_injection_rejection(self):
        run = self.store.create_scan(self.admin, self.project, self.input_id, "local", "all")
        snapshot = run["snapshot"]
        self.assertEqual(run["round_number"], 1)
        self.assertEqual(snapshot["input_hash"], hashlib.sha256(b"secret").hexdigest())
        with self.assertRaises(ValueError):
            self.store.create_scan(self.admin, self.project, self.input_id, "local", "all", disabled_rules=("secret.x",))
        self.store.set_rule_policy(self.project, ("secret.x",), expected_version=1)
        run2 = self.store.create_scan(self.admin, self.project, self.input_id, "local", "all")
        self.assertEqual(run2["round_number"], 2)
        self.assertEqual(run["snapshot"]["rule_policy_version"], 1)

    def test_scan_scope_is_immutable_and_validated(self):
        library = self.store.create_scan(self.admin, self.project, self.input_id, "ignored", "ignored", "library")
        self.assertEqual(library["snapshot"]["scan_scope"], "library")
        self.assertEqual((library["standard"], library["standard_category"]), ("local", "all"))
        source = self.store.create_scan(self.admin, self.project, self.input_id, "local", "all", "source")
        self.assertEqual(source["snapshot"]["scan_scope"], "source")
        self.assertEqual(self.store.list_runs(self.project)[0]["scan_scope"], "source")
        with self.assertRaises(ValueError):
            self.store.create_scan(self.admin, self.project, self.input_id, "local", "all", "unknown")

    def test_last_admin_and_project_isolation(self):
        with self.assertRaises(ValueError):
            self.store.set_subject(self.admin, status="disabled")
        other = str(uuid.uuid4()); self.store.ensure_subject(other); self.store.set_subject(other, status="enabled")
        with self.assertRaises(ValueError):
            self.store.bootstrap(other)
        self.assertFalse(self.store.can(other, str(uuid.uuid4())))

    def test_role_policy_is_global_and_persists_after_restart(self):
        viewer = str(uuid.uuid4())
        self.store.ensure_subject(viewer, "viewer")
        self.store.set_subject(viewer, status="enabled", actor=self.admin)
        self.store.set_membership(self.project, viewer, "viewer", self.admin)
        self.assertTrue(self.store.can(viewer, self.project, "project.view"))
        self.assertFalse(self.store.can(viewer, self.project, "scan.create"))
        with self.assertRaises(ValueError):
            self.store.set_role_policy({"viewer": ["system.admin"]}, 1, self.admin)
        second = self.store.create_project("second")
        self.store.set_membership(second, viewer, "viewer", self.admin)
        policy = self.store.role_policy()
        self.store.set_role_policy({"viewer": ["dashboard.view"]}, policy["version"], self.admin)
        self.assertTrue(self.store.can(viewer, self.project, "dashboard.view"))
        self.assertTrue(self.store.can(viewer, second, "dashboard.view"))
        self.assertFalse(self.store.can(viewer, second, "runs.view"))
        reopened = PortalStore(Path(self.tmp.name) / "portal.sqlite3")
        self.assertEqual(reopened.list_inputs(self.project)[0]["input_id"], self.input_id)
        self.assertEqual(reopened.role_policy()["version"], 2)

    def test_legacy_project_view_migrates_once_to_screen_permissions(self):
        encoded = self.store._json({"legacy": ["project.view"]})
        with self.store._db() as db:
            db.execute("DELETE FROM role_policies WHERE project_id=?", (GLOBAL_ROLE_POLICY_ID,))
            db.execute(
                "INSERT INTO role_policies VALUES(?,?,?,?,?)",
                (self.project, 2, encoded, hashlib.sha256(encoded.encode()).hexdigest(), self.store._now()),
            )
        reopened = PortalStore(Path(self.tmp.name) / "portal.sqlite3")
        policy = reopened.role_policy()
        self.assertEqual(policy["version"], 1)
        self.assertEqual(set(policy["roles"]["legacy"]), set(SCREEN_PERMISSIONS))
        self.assertNotIn("project.view", policy["roles"]["legacy"])
        self.assertIn("role_policy.migrated", {event["action"] for event in reopened.audit_events(None)})
        self.assertEqual(PortalStore(Path(self.tmp.name) / "portal.sqlite3").role_policy()["version"], 1)

    def test_user_visible_time_is_seoul_without_changing_utc_storage(self):
        self.assertEqual(format_portal_time("2026-01-01T00:00:00+00:00"), "2026-01-01 09:00:00")
        self.assertRegex(self.store._now(), r"[+]00:00$")

    def test_cve_only_scan_drops_non_cve_dependency_results(self):
        target = Path(self.tmp.name) / "requirements.txt"
        target.write_text("demo==1.0\n", encoding="utf-8")
        cve = GrypeMatch(
            "GHSA-with-cve", ("CVE-2026-1234",), "demo", "1.0", "pkg:pypi/demo@1.0",
            ("1.1",), "high", ("requirements.txt",), (), ("GHSA-with-cve",),
        )
        ghsa = GrypeMatch(
            "GHSA-only", (), "demo", "1.0", "pkg:pypi/demo@1.0",
            (), "high", ("requirements.txt",), (), ("GHSA-only",),
        )
        grype = GrypeResult((cve, ghsa), "test", {"built": "2026-08-28"}, "", False)
        with patch("security_scanner.server.inspect_grype", return_value={"available": True}), patch(
            "security_scanner.server.run_grype_purls", return_value=grype
        ):
            payload = scan_directory_payload(
                str(target), allow_file=True, standard="local", standard_category="all",
                scan_scope="library", enable_local_vulnerabilities=True, cve_only=True,
            )
        encoded = json.dumps(payload, ensure_ascii=False)
        self.assertEqual(payload["scan"]["local_vulnerability"]["matched_vulnerabilities"], 1)
        self.assertIn("CVE-2026-1234", encoded)
        self.assertNotIn("GHSA-only", encoded)

    def test_run_progress_cancel_and_recovery(self):
        run = self.store.create_scan(self.admin, self.project, self.input_id, "local", "all")
        self.assertTrue(self.store.mark_run_running(run["run_id"]))
        self.assertTrue(self.store.set_run_progress(run["run_id"], "scanning", 35))
        cancelling = self.store.request_cancel(run["run_id"], self.admin)
        self.assertEqual(cancelling["status"], "cancelling")
        self.store.complete_run(run["run_id"], result={"findings": []})
        cancelled = self.store.run(run["run_id"])
        self.assertEqual((cancelled["status"], cancelled["stage"], cancelled["result"]), ("cancelled", "cancelled", None))
        self.assertFalse(Path(self.store.input(self.input_id)["path"]).exists())
        with self.assertRaises(ValueError):
            self.store.create_scan(self.admin, self.project, self.input_id, "local", "all")

    def test_recovery_removes_terminal_input_left_by_previous_process(self):
        run = self.store.create_scan(self.admin, self.project, self.input_id, "local", "all")
        self.store.complete_run(run["run_id"], result={"findings": []})
        path = Path(self.store.input(self.input_id)["path"])
        path.write_text("stale copy", encoding="utf-8")
        reopened = PortalStore(Path(self.tmp.name) / "portal.sqlite3")
        self.assertEqual(reopened.recover_incomplete_runs(), [])
        self.assertFalse(path.exists())


class LinuxPortalHttpTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.admin = str(uuid.uuid4())
        self.server = create_portal_server(
            "127.0.0.1", 0, db_path=Path(self.tmp.name) / "portal.sqlite3",
            input_dir=Path(self.tmp.name) / "inputs",
        )
        self.server.portal_store.bootstrap(self.admin)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.tmp.cleanup()

    def headers(self, subject=None, display="admin"):
        return {
            "X-KODA-Identity-ID": subject or self.admin,
            "X-KODA-Identity-Expires": (dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=5)).isoformat(),
            "X-KODA-Identity-Display": base64.urlsafe_b64encode(display.encode()).rstrip(b"=").decode(),
        }

    def request(self, path, *, method="GET", payload=None, headers=None):
        body = json.dumps(payload).encode() if payload is not None else None
        request = urllib.request.Request(self.base + path, data=body, method=method, headers=headers or {})
        if payload is not None:
            request.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(request, timeout=10) as response:
                raw = response.read()
                return response.status, json.loads(raw) if response.headers.get_content_type() == "application/json" else (raw if response.headers.get_content_type() == "image/x-icon" else raw.decode())
        except urllib.error.HTTPError as exc:
            try:
                raw = exc.read()
                return exc.code, json.loads(raw) if exc.headers.get_content_type() == "application/json" else raw.decode()
            finally:
                exc.close()

    def test_login_registration_and_admin_pages(self):
        status, body = self.request("/koda/login?next=https://evil.example")
        self.assertEqual(status, 200)
        self.assertIn("LDAP 계정", body)
        self.assertIn("<link rel='icon' href='/koda/assets/KODA.ico'>", body)
        self.assertIn("/koda/assets/KODA.ico", body)
        self.assertNotIn("Tracker", body)
        self.assertIn('location="/koda/"', body)
        status, body = self.request("/koda/login?next=/koda/%3C/script%3Ealert(1)%3C/script%3E")
        self.assertEqual(status, 200)
        self.assertNotIn("<script>alert(1)</script>", body)
        self.assertIn('location="/koda/"', body)
        self.assertIn("회원가입", body)
        self.assertIn("/api/v1/auth/register", body)
        approved_tracker_user = str(uuid.uuid4())
        status, me = self.request("/koda/api/v1/me", headers=self.headers(approved_tracker_user, "approved"))
        self.assertEqual((status, me["status"]), (200, "enabled"))
        self.assertEqual(self.request("/koda/api/v1/projects", headers=self.headers(approved_tracker_user)), (403, {"code": "forbidden"}))
        status, admin_page = self.request("/koda/admin/subjects", headers=self.headers())
        self.assertEqual(status, 200)
        self.assertIn("<link rel='icon' href='/koda/assets/KODA.ico'>", admin_page)
        self.assertIn("/koda/assets/KODA.ico", admin_page)
        self.assertNotIn("Tracker", admin_page.split("</nav>", 1)[0])
        self.assertNotIn("회원가입과 계정 승인은 KODA-SBOM-Tracker", admin_page)
        self.assertIn("KODA 접근 제어", admin_page)
        self.assertIn("<div class='toolbar-submit'><button>저장</button></div>", admin_page)
        self.assertIn("class='topbar'", admin_page)
        self.assertIn("id='account-toggle'", admin_page)
        self.assertIn("id='account-panel'", admin_page)
        self.assertIn("id='account-logout'", admin_page)
        self.assertIn("json('/koda/api/v1/me')", admin_page)
        self.assertNotIn("class='side-bottom'", admin_page)
        self.assertNotIn("id='logout'", admin_page)
        self.assertNotIn("<option>pending</option>", admin_page)
        self.assertIn("syncSubject()", admin_page)

    def test_admin_controls_project_access_per_user(self):
        project = self.server.portal_store.create_project("project access", self.admin)
        viewer = str(uuid.uuid4())
        self.server.portal_store.ensure_subject(viewer, "viewer")
        self.server.portal_store.set_subject(viewer, status="enabled", actor=self.admin)
        status, page = self.request("/koda/admin/subjects", headers=self.headers())
        self.assertEqual(status, 200)
        self.assertIn("사용자별 프로젝트 접근", page)
        self.assertIn("class='check-label'", page)
        self.assertIn("접근 해제", page)
        self.assertIn("project access", page)

        payload = {"project_id": project, "subject_id": viewer, "role": "viewer"}
        self.assertEqual(self.request("/koda/api/v1/admin/memberships", method="POST", payload=payload, headers=self.headers()), (200, {"ok": True}))
        self.assertTrue(self.server.portal_store.can(viewer, project, "runs.view"))
        status, page = self.request("/koda/admin/subjects", headers=self.headers())
        self.assertEqual(status, 200)
        self.assertIn(viewer, page)
        payload["role"] = ""
        self.assertEqual(self.request("/koda/api/v1/admin/memberships", method="POST", payload=payload, headers=self.headers()), (200, {"ok": True}))
        self.assertFalse(self.server.portal_store.can(viewer, project, "runs.view"))
        self.assertIn("membership.removed", {event["action"] for event in self.server.portal_store.audit_events(None)})

    def test_user_guide_is_available_without_project_permissions(self):
        viewer = str(uuid.uuid4())
        status, guide = self.request("/koda/guide", headers=self.headers(viewer, "일반 사용자"))
        self.assertEqual(status, 200)
        self.assertIn("KODA 사용 가이드", guide)
        self.assertIn("data-nav='guide'", guide)
        self.assertIn("라이브러리 취약점 점검", guide)
        self.assertIn("CVE", guide)
        self.assertIn("CVSS", guide)
        self.assertIn("CWE", guide)
        self.assertIn("OWASP Top 10:2025", guide)
        self.assertIn("소프트웨어 개발보안 49", guide)
        self.assertIn("현재 KODA 카탈로그에 등록된 27개 기준", guide)
        self.assertNotIn("<strong>전체</strong><code>local</code>", guide)
        self.assertNotIn("관리자 설정</h3>", guide)
        self.assertNotIn("사용 가이드 목차", guide)
        self.assertNotIn("권한에 따라 보이는 실행 메뉴", guide)

    def test_empty_project_pages_explain_onboarding(self):
        status, body = self.request("/koda/scans/new", headers=self.headers())
        self.assertEqual(status, 200)
        self.assertIn("프로젝트 생성으로 이동", body)
        status, body = self.request("/koda/projects", headers=self.headers())
        self.assertEqual(status, 200)
        self.assertIn("프로젝트를 생성하면", body)

        viewer = str(uuid.uuid4())
        viewer_headers = self.headers(viewer, "승인된 사용자")
        status, body = self.request("/koda/scans/new", headers=viewer_headers)
        self.assertEqual(status, 403)
        self.assertIn("이 화면에 접근할 권한이 없습니다", body)
        status, body = self.request("/koda/projects", headers=viewer_headers)
        self.assertEqual(status, 403)
        self.assertIn("이 화면에 접근할 권한이 없습니다", body)

    def test_scope_menus_render_independent_scan_pages(self):
        project = self.server.portal_store.create_project("scope pages", self.admin)
        target = Path(self.tmp.name) / "scope.py"
        target.write_text("print('scope')\n", encoding="utf-8")
        self.server.portal_store.add_input(project, target.name, target, self.admin)
        status, library = self.request("/koda/scans/library", headers=self.headers())
        self.assertEqual(status, 200)
        self.assertIn("라이브러리 보안취약점 점검", library)
        self.assertIn("scope=\"library\"", library)
        self.assertIn("CVE가 연결된 Grype 결과만 표시", library)
        self.assertNotIn("<select id='standards'", library)
        self.assertNotIn("<select id='category'", library)
        self.assertIn("<input id='input' type='hidden'>", library)
        self.assertNotIn("등록된 입력", library)
        self.assertIn("href='/koda/scans/source'", library)
        status, all_scan = self.request("/koda/scans/new", headers=self.headers())
        self.assertEqual(status, 200)
        self.assertIn('scope="all"', all_scan)
        self.assertIn("<select id='standards'>", all_scan)
        status, source = self.request("/koda/scans/source", headers=self.headers())
        self.assertEqual(status, 200)
        self.assertIn("소스코드 보안취약점 점검", source)
        self.assertIn("scope=\"source\"", source)
        self.assertIn('<option value="local">전체</option>', source)
        self.assertNotIn("등록된 입력", source)
        self.assertIn("href='/koda/scans/library'", source)

    def test_screen_permissions_hide_navigation_and_keep_resource_404(self):
        project = self.server.portal_store.create_project("partial access", self.admin)
        target = Path(self.tmp.name) / "partial.py"
        target.write_text("print('ok')\n", encoding="utf-8")
        input_id = self.server.portal_store.add_input(project, target.name, target, self.admin)
        run = self.server.portal_store.create_scan(self.admin, project, input_id, "local", "all")
        viewer = str(uuid.uuid4())
        self.server.portal_store.ensure_subject(viewer, "viewer")
        self.server.portal_store.set_subject(viewer, status="enabled", actor=self.admin)
        self.server.portal_store.set_membership(project, viewer, "viewer", self.admin)
        policy = self.server.portal_store.role_policy()
        self.server.portal_store.set_role_policy({"viewer": ["dashboard.view"]}, policy["version"], self.admin)
        viewer_headers = self.headers(viewer, "viewer")

        status, dashboard_page = self.request("/koda", headers=viewer_headers)
        self.assertEqual(status, 200)
        navigation = dashboard_page.split("</nav>", 1)[0]
        self.assertNotIn("href='/koda/runs'", navigation)
        self.assertNotIn("href='/koda/scans/library'", navigation)
        self.assertNotIn("href='/koda/projects'", navigation)
        self.assertEqual(self.request("/koda/runs", headers=viewer_headers)[0], 403)
        self.assertEqual(self.request("/koda/scans/library", headers=viewer_headers)[0], 403)
        self.assertEqual(self.request(f"/koda/api/v1/runs/{run['run_id']}", headers=viewer_headers)[0], 404)
        self.assertEqual(self.request("/koda/runs", headers=self.headers())[0], 200)

    def test_compare_hides_unauthorized_cross_project_runs_as_404(self):
        first = self.server.portal_store.create_project("compare allowed", self.admin)
        second = self.server.portal_store.create_project("compare hidden", self.admin)
        target = Path(self.tmp.name) / "compare.py"
        target.write_text("print('compare')\n", encoding="utf-8")
        first_input = self.server.portal_store.add_input(first, target.name, target, self.admin)
        second_input = self.server.portal_store.add_input(second, target.name, target, self.admin)
        first_run = self.server.portal_store.create_scan(self.admin, first, first_input, "local", "all")
        second_run = self.server.portal_store.create_scan(self.admin, second, second_input, "local", "all")
        self.server.portal_store.complete_run(first_run["run_id"], result={"findings": []})
        self.server.portal_store.complete_run(second_run["run_id"], result={"findings": []})
        viewer = str(uuid.uuid4())
        self.server.portal_store.ensure_subject(viewer, "viewer")
        self.server.portal_store.set_subject(viewer, status="enabled", actor=self.admin)
        self.server.portal_store.set_membership(first, viewer, "viewer", self.admin)
        policy = self.server.portal_store.role_policy()
        self.server.portal_store.set_role_policy({"viewer": ["compare.view"]}, policy["version"], self.admin)
        status, body = self.request(
            f"/koda/api/v1/compare?left={first_run['run_id']}&right={second_run['run_id']}",
            headers=self.headers(viewer, "viewer"),
        )
        self.assertEqual(status, 404)
        self.assertEqual(body, {"code": "not_found"})

    def test_role_policy_labels_screens_and_features_in_korean(self):
        self.server.portal_store.create_project("role labels", self.admin)
        status, body = self.request("/koda/admin/roles", headers=self.headers())
        self.assertEqual(status, 200)
        self.assertIn("KODA 전역 역할 정책", body)
        self.assertIn("화면 접근 권한", body)
        self.assertIn("기능 실행 권한", body)
        self.assertIn("라이브러리 점검", body)
        self.assertIn("프로젝트 관리자", body)
        self.assertIn("dashboard.view", body)
        self.assertNotIn("project.view", body)
        self.assertNotIn("project.manage", body)
        self.assertNotIn("<th>권한</th>", body)
        self.assertNotIn("<select name='project'>", body)
        self.assertIn("aria-current='page'", body)

        policy = self.server.portal_store.role_policy()
        status, updated = self.request("/koda/api/v1/admin/roles", method="POST", payload={
            "expected_version": policy["version"], "roles": {"viewer": ["dashboard.view"]},
        }, headers=self.headers())
        self.assertEqual((status, updated["version"]), (200, policy["version"] + 1))
        self.assertEqual(self.request("/koda/api/v1/admin/roles", method="POST", payload={
            "project_id": "legacy", "expected_version": updated["version"], "roles": updated["roles"],
        }, headers=self.headers())[0], 422)

    def test_rule_cards_include_all_standards_and_sync_duplicate_rules(self):
        project = self.server.portal_store.create_project("rule catalog", self.admin)
        status, body = self.request(f"/koda/admin/rules?project={project}", headers=self.headers())
        self.assertEqual(status, 200)
        self.assertIn("OWASP", body)
        self.assertIn("SW49", body)
        self.assertIn("상세 매핑", body)
        self.assertIn("공식 통제 ID", body)
        self.assertIn("지원 수준", body)
        self.assertIn("CWE-862", body)
        self.assertNotIn("<summary>전체 (106)</summary>", body)
        self.assertIn("[data-rule-card]+[data-rule-card]", body)
        rule_ids = Counter(value.split("'", 1)[0] for value in body.split("data-rule-id='")[1:])
        self.assertTrue(any(count > 1 for count in rule_ids.values()))
        self.assertIn("peer.dataset.ruleId===box.dataset.ruleId", body)

    def test_audit_xlsx_contains_kst_actor_project_and_detail(self):
        project = self.server.portal_store.create_project("audit project", self.admin)
        with self.server.portal_store._db() as db:
            db.execute(
                "INSERT INTO audit_events(subject_id,action,project_id,detail_json,created_at) VALUES(?,?,?,?,?)",
                (self.admin, "audit.test", project, '{"note":"확인"}', "2026-01-01T00:00:00+00:00"),
            )
        request = urllib.request.Request(
            self.base + "/koda/api/v1/admin/audit?format=xlsx", headers=self.headers(),
        )
        with urllib.request.urlopen(request, timeout=10) as response:
            raw = response.read()
            self.assertEqual(response.headers.get_content_type(), "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            sheet = archive.read("xl/worksheets/sheet1.xml").decode("utf-8")
        for expected in ("서울 시각", "주체 ID", "프로젝트명", "상세 JSON", "2026-01-01 09:00:00", self.admin, "audit project", project, "audit.test", "확인"):
            self.assertIn(expected, sheet)

        viewer = str(uuid.uuid4())
        self.server.portal_store.ensure_subject(viewer, "viewer")
        self.server.portal_store.set_subject(viewer, status="enabled", actor=self.admin)
        self.assertEqual(self.request("/koda/api/v1/admin/audit?format=xlsx", headers=self.headers(viewer))[0], 403)

    def test_public_koda_icon_asset(self):
        status, body = self.request("/koda/assets/KODA.ico")
        self.assertEqual(status, 200)
        self.assertTrue(body.startswith(b"\x00\x00\x01\x00"))
        self.assertEqual(self.request("/koda/assets/missing.ico")[0], 404)

    def test_project_upload_scan_round_and_injection_rejection(self):
        status, created = self.request("/koda/api/v1/projects", method="POST", payload={"name": "portal"}, headers=self.headers())
        self.assertEqual(status, 201)
        project_id = created["project_id"]
        request = urllib.request.Request(
            self.base + f"/koda/api/v1/projects/{project_id}/inputs?name=demo.py",
            data=b"AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP\n", method="POST",
            headers={**self.headers(), "Content-Type": "application/octet-stream"},
        )
        with urllib.request.urlopen(request, timeout=10) as response:
            status, uploaded = response.status, json.loads(response.read())
        self.assertEqual(status, 201)
        scan = {"project_id": project_id, "input_id": uploaded["input_id"], "standard": "local", "standard_category": "all"}
        injected = dict(scan, disabled_rules=["secret.rule"])
        self.assertEqual(self.request("/koda/api/v1/scans", method="POST", payload=injected, headers=self.headers())[0], 422)
        status, run = self.request("/koda/api/v1/scans", method="POST", payload=scan, headers=self.headers())
        self.assertEqual((status, run["round_number"]), (202, 1))
        for _ in range(100):
            _, detail = self.request(f"/koda/api/v1/runs/{run['run_id']}", headers=self.headers())
            if detail["status"] in {"completed", "failed"}:
                break
            time.sleep(.02)
        self.assertEqual(detail["status"], "completed", detail.get("error"))
        self.assertEqual(detail["snapshot"]["requested_by"], self.admin)
        self.assertIsInstance(detail["result"], dict)
        self.assertTrue(detail["result"]["findings"])
        self.assertIn("analysis_stages", detail["result"])
        self.assertIn("local_vulnerability", detail["result"]["scan"])
        self.assertIn("queried_components", detail["result"]["scan"]["local_vulnerability"])
        self.assertFalse(Path(self.server.portal_store.input(uploaded["input_id"])["path"]).exists())

    def test_streaming_upload_limit_and_vulnerability_database_status(self):
        _, created = self.request("/koda/api/v1/projects", method="POST", payload={"name": "large input"}, headers=self.headers())
        project_id = created["project_id"]
        request = urllib.request.Request(
            self.base + f"/koda/api/v1/projects/{project_id}/inputs?name=demo.zip",
            data=b"zip-content", method="POST", headers={**self.headers(), "Content-Type": "application/octet-stream"},
        )
        with urllib.request.urlopen(request, timeout=10) as response:
            uploaded = json.loads(response.read())
            self.assertEqual(response.status, 201)
        self.assertEqual(uploaded["size"], len(b"zip-content"))
        self.assertEqual(self.server.portal_store.list_inputs(project_id)[0]["name"], "demo.zip")
        status, scan_page = self.request("/koda/scans/new", headers=self.headers())
        self.assertEqual(status, 200)
        self.assertIn("최대 1 GB", scan_page)
        self.assertNotIn("최대 1 GiB", scan_page)
        self.assertIn("application/octet-stream", scan_page)
        self.assertIn("/koda/api/v1/vulnerability-db", scan_page)
        self.assertEqual(
            self.request(
                f"/koda/api/v1/projects/{project_id}/inputs?name=legacy.json",
                method="POST", payload={"content": "emlw"}, headers=self.headers(),
            )[0],
            415,
        )

        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_address[1], timeout=10)
        connection.putrequest("POST", f"/koda/api/v1/projects/{project_id}/inputs?name=too-large.zip")
        for name, value in self.headers().items():
            connection.putheader(name, value)
        connection.putheader("Content-Type", "application/octet-stream")
        connection.putheader("Content-Length", str(MAX_INPUT_BYTES + 1))
        connection.endheaders()
        response = connection.getresponse()
        self.assertEqual(response.status, 413)
        response.read(); connection.close()

        status_value = {"configured": True, "available": True, "version": "0.99.1", "database": {"built": "2026-08-17"}, "warning": ""}
        with patch("security_scanner.linux_portal._vulnerability_database_status", return_value=status_value):
            self.assertEqual(self.request("/koda/api/v1/vulnerability-db", headers=self.headers()), (200, status_value))
            status, page = self.request("/koda/admin/vulnerability-db", headers=self.headers())
        self.assertEqual(status, 200)
        self.assertIn("0.99.1", page)
        self.assertIn("2026-08-17", page)
        self.assertIn("<div class='panel-body'><ul class='summary-list'>", page)

    def test_cancel_and_comparison_exports(self):
        project = self.server.portal_store.create_project("history", self.admin)
        targets = [Path(self.tmp.name) / name for name in ("history-first.py", "history-second.py", "history-comparison.py")]
        for target in targets:
            target.write_text("print('history')\n", encoding="utf-8")
        input_ids = [self.server.portal_store.add_input(project, target.name, target, self.admin) for target in targets]
        first = self.server.portal_store.create_scan(self.admin, project, input_ids[0], "local", "all")
        self.server.portal_store.complete_run(first["run_id"], result={"findings": [{"rule_id": "rule.old", "title": "old", "severity": "low", "category": "code", "path": "a.py", "line": 1}]})
        second = self.server.portal_store.create_scan(self.admin, project, input_ids[1], "local", "all")
        status, cancelled = self.request(f"/koda/api/v1/runs/{second['run_id']}/cancel", method="POST", payload={}, headers=self.headers())
        self.assertEqual((status, cancelled["status"]), (200, "cancelled"))
        cancelled_comparison = f"left={first['run_id']}&right={second['run_id']}"
        self.assertEqual(self.request(f"/koda/api/v1/compare?{cancelled_comparison}", headers=self.headers())[0], 422)
        self.assertEqual(self.request(f"/koda/api/v1/runs/{second['run_id']}/retry", method="POST", payload={}, headers=self.headers())[0], 404)

        comparison_run = self.server.portal_store.create_scan(self.admin, project, input_ids[2], "local", "all")
        self.server.portal_store.complete_run(comparison_run["run_id"], result={"findings": [{"rule_id": "rule.new", "title": "new", "severity": "high", "category": "code", "path": "b.py", "line": 2}]})
        query = f"left={first['run_id']}&right={comparison_run['run_id']}"
        status, page = self.request(f"/koda/compare?{query}", headers=self.headers())
        self.assertEqual(status, 200)
        self.assertIn("항목별 비교", page)
        self.assertIn("rule.old", page)
        self.assertIn("rule.new", page)
        status, comparison = self.request(f"/koda/api/v1/compare?{query}&format=json", headers=self.headers())
        self.assertEqual((status, comparison["counts"]), (200, {"new": 1, "resolved": 1, "persistent": 0}))
        request = urllib.request.Request(self.base + f"/koda/api/v1/compare?{query}&format=csv", headers=self.headers())
        with urllib.request.urlopen(request, timeout=10) as response:
            self.assertTrue(response.read().startswith(b"\xef\xbb\xbf"))

    def test_cross_project_run_is_hidden_and_policy_versions_conflict(self):
        project = self.server.portal_store.create_project("private", self.admin)
        target = Path(self.tmp.name) / "input.txt"
        target.write_text("safe", encoding="utf-8")
        input_id = self.server.portal_store.add_input(project, "input.txt", target, self.admin)
        run = self.server.portal_store.create_scan(self.admin, project, input_id, "local", "all")
        other = str(uuid.uuid4())
        self.server.portal_store.ensure_subject(other, "other")
        self.server.portal_store.set_subject(other, status="enabled", actor=self.admin)
        self.assertEqual(self.request(f"/koda/api/v1/runs/{run['run_id']}", headers=self.headers(other, "other"))[0], 404)
        body = {"project_id": project, "expected_version": 0, "disabled_rules": []}
        self.assertEqual(self.request("/koda/api/v1/admin/rules", method="POST", payload=body, headers=self.headers())[0], 409)

    def test_completed_run_downloads_authorized_nis_sbom_csv(self):
        project = self.server.portal_store.create_project("NIS export", self.admin)
        target = Path(self.tmp.name) / "dependency.txt"
        target.write_text("package", encoding="utf-8")
        input_id = self.server.portal_store.add_input(project, "dependency.txt", target, self.admin)
        run = self.server.portal_store.create_scan(self.admin, project, input_id, "local", "all")
        self.server.portal_store.complete_run(run["run_id"], result={
            "findings": [],
            "components": [{"name": "demo", "version": "1.2.3", "path": "requirements.txt", "purl": "pkg:pypi/demo@1.2.3"}],
            "sbom": {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [{"name": "demo", "version": "1.2.3"}]},
            "nis_sbom": {"rows": [{"SBOM Standard": "NIS 1.0", "Product Name": "demo-app", "Component Name": "demo", "Component Version": "1.2.3"}]},
        })

        status, page = self.request(f"/koda/runs/{run['run_id']}", headers=self.headers())
        self.assertEqual(status, 200)
        self.assertIn("국정원 NIS-SBOM 1.0 (CSV)", page)
        self.assertIn(f"/koda/api/v1/runs/{run['run_id']}/sbom", page)

        request = urllib.request.Request(
            self.base + f"/koda/api/v1/runs/{run['run_id']}/sbom?format=nis-sbom",
            headers=self.headers(),
        )
        with urllib.request.urlopen(request, timeout=10) as response:
            raw, headers = response.read(), response.headers
            self.assertEqual(response.status, 200)
        self.assertEqual(headers.get_content_type(), "text/csv")
        self.assertEqual(headers.get_content_charset(), "utf-8")
        self.assertEqual(headers["Content-Disposition"], 'attachment; filename="koda-round-1-nis-sbom-1.0.csv"')
        self.assertEqual(headers["X-Content-Type-Options"], "nosniff")
        rows = list(csv.DictReader(io.StringIO(raw.decode("utf-8-sig"))))
        self.assertEqual(rows[0]["SBOM Standard"], "NIS 1.0")
        self.assertEqual(rows[0]["Component Name"], "demo")

        unauthorized = {"X-KODA-Identity-Display": base64.urlsafe_b64encode(b"unknown").rstrip(b"=").decode()}
        self.assertEqual(self.request(f"/koda/api/v1/runs/{run['run_id']}/sbom?format=nis-sbom", headers=unauthorized)[0], 401)
        other = str(uuid.uuid4())
        self.server.portal_store.ensure_subject(other, "other")
        self.server.portal_store.set_subject(other, status="enabled", actor=self.admin)
        self.assertEqual(self.request(f"/koda/api/v1/runs/{run['run_id']}/sbom?format=nis-sbom", headers=self.headers(other, "other"))[0], 404)

    def test_completed_run_separates_library_source_and_quality_tabs(self):
        project = self.server.portal_store.create_project("분류 탭", self.admin)
        target = Path(self.tmp.name) / "app.py"
        target.write_text("print('demo')\n", encoding="utf-8")
        input_id = self.server.portal_store.add_input(project, target.name, target, self.admin)
        run = self.server.portal_store.create_scan(self.admin, project, input_id, "local", "all")
        self.server.portal_store.complete_run(run["run_id"], result={"findings": [
            {"rule_id": "dependency.osv", "title": "취약한 라이브러리", "severity": "high", "category": "dependencies", "path": "requirements.txt"},
            {"rule_id": "code.sql", "title": "동적 SQL", "severity": "critical", "category": "code", "path": target.name},
            {"rule_id": "secret.literal", "title": "비밀정보", "severity": "high", "category": "secrets", "path": target.name},
            {"rule_id": "screen.alt", "title": "대체 텍스트", "severity": "low", "category": "screen_quality", "path": "index.html"},
        ]})

        status, result_page = self.request(f"/koda/runs/{run['run_id']}", headers=self.headers())
        self.assertEqual(status, 200)
        self.assertIn("라이브러리 취약점 1", result_page)
        self.assertIn("소스코드 취약점 2", result_page)
        self.assertIn("품질 점검 1", result_page)
        self.assertEqual(result_page.count("data-group='library'"), 1)
        self.assertEqual(result_page.count("data-group='source'"), 2)
        self.assertEqual(result_page.count("data-group='quality'"), 1)
        self.assertIn(">라이브러리</td>", result_page)
        self.assertIn(">소스코드</td>", result_page)
        self.assertIn(">비밀정보</td>", result_page)
        self.assertIn(">화면품질</td>", result_page)
        self.assertNotIn("다시 실행", result_page)
        self.assertNotIn("/retry", result_page)
        self.assertNotIn("format=hwpx", result_page)
        self.assertNotIn("href='/koda/compare?right=", result_page)
        self.assertNotIn("<a class='button' href='/koda/scans/library'>", result_page)
        self.assertNotIn("<a class='button' href='/koda/scans/source'>", result_page)
        self.assertIn("class='resizable-table'", result_page)
        self.assertEqual(result_page.count("class='column-resizer'"), 6)
        self.assertIn("ArrowRight", result_page)
        self.assertIn("align-items:center;justify-content:center;text-align:center", result_page)

    def test_completed_run_report_uses_the_shared_windows_cli_renderer(self):
        project = self.server.portal_store.create_project("CLI report", self.admin)
        target = Path(self.tmp.name) / "unsafe.py"
        target.write_text("password = 'secret'\n", encoding="utf-8")
        input_id = self.server.portal_store.add_input(project, target.name, target, self.admin)
        run = self.server.portal_store.create_scan(self.admin, project, input_id, "local", "all")
        result = {
            "scan": {"path": target.name, "kind": "source", "standard": "local", "standard_category": "all"},
            "findings": [{"rule_id": "secret.literal", "title": "하드코딩된 비밀정보", "severity": "high", "category": "security", "path": target.name, "line": 1}],
            "components": [],
        }
        self.server.portal_store.complete_run(run["run_id"], result=result)

        request = urllib.request.Request(
            self.base + f"/koda/api/v1/runs/{run['run_id']}/report?format=html",
            headers=self.headers(),
        )
        with urllib.request.urlopen(request, timeout=10) as response:
            actual, response_headers = response.read(), response.headers
        self.assertEqual(response_headers.get_content_type(), "application/zip")
        self.assertEqual(response_headers["Content-Disposition"], 'attachment; filename="koda-round-1-report.zip"')

        expected = render_html_pair_zip_from_payload(result, "ko")
        with zipfile.ZipFile(io.BytesIO(actual)) as actual_zip, zipfile.ZipFile(io.BytesIO(expected)) as expected_zip:
            self.assertEqual(actual_zip.namelist(), ["report.html", "report-detail.html"])
            for name in actual_zip.namelist():
                self.assertEqual(actual_zip.read(name), expected_zip.read(name))
                request = urllib.request.Request(
                    self.base + f"/koda/api/v1/runs/{run['run_id']}/{name}",
                    headers=self.headers(),
                )
                with urllib.request.urlopen(request, timeout=10) as response:
                    self.assertEqual(response.headers.get_content_type(), "text/html")
                    self.assertEqual(response.read(), expected_zip.read(name))

        status, markdown = self.request(f"/koda/api/v1/runs/{run['run_id']}/report?format=markdown", headers=self.headers())
        self.assertEqual(status, 200)
        self.assertIn("하드코딩된 비밀정보", markdown)
        self.assertEqual(self.request(f"/koda/api/v1/runs/{run['run_id']}/report?format=unknown", headers=self.headers())[0], 422)

    def test_library_run_opens_a_library_vulnerability_report(self):
        project = self.server.portal_store.create_project("library report", self.admin)
        target = Path(self.tmp.name) / "requirements.txt"
        target.write_text("demo==1.0\n", encoding="utf-8")
        input_id = self.server.portal_store.add_input(project, target.name, target, self.admin)
        run = self.server.portal_store.create_scan(self.admin, project, input_id, "local", "all", scan_scope="library")
        result = {
            "findings": [{"rule_id": "CVE-2026-0001", "title": "취약한 라이브러리", "severity": "critical", "category": "dependencies", "path": target.name}],
            "components": [],
        }
        self.server.portal_store.complete_run(run["run_id"], result=result)

        status, result_page = self.request(f"/koda/runs/{run['run_id']}", headers=self.headers())
        self.assertEqual(status, 200)
        self.assertIn("라이브러리 취약점 보고서", result_page)
        status, main = self.request(f"/koda/api/v1/runs/{run['run_id']}/report.html", headers=self.headers())
        self.assertEqual(status, 200)
        self.assertIn("라이브러리 취약점 분석 요약", main)
        self.assertIn("LIBRARY VULNERABILITY REPORT", main)
        self.assertNotIn("소스 보안 분석 요약", main)
        status, detail = self.request(f"/koda/api/v1/runs/{run['run_id']}/report-detail.html", headers=self.headers())
        self.assertEqual(status, 200)
        self.assertIn("라이브러리 취약점 상세", detail)
        self.assertIn("구성요소 근거", detail)


if __name__ == "__main__":
    unittest.main()
