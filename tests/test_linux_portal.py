import datetime as dt
import base64
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
from security_scanner.portal_store import PortalStore
from security_scanner.reporting import render_html_pair_zip_from_payload


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
        library = self.store.create_scan(self.admin, self.project, self.input_id, "local", "all", "library")
        self.assertEqual(library["snapshot"]["scan_scope"], "library")
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

    def test_role_policy_is_project_local_and_persists_after_restart(self):
        viewer = str(uuid.uuid4())
        self.store.ensure_subject(viewer, "viewer")
        self.store.set_subject(viewer, status="enabled", actor=self.admin)
        self.store.set_membership(self.project, viewer, "viewer", self.admin)
        self.assertTrue(self.store.can(viewer, self.project, "project.view"))
        self.assertFalse(self.store.can(viewer, self.project, "scan.create"))
        with self.assertRaises(ValueError):
            self.store.set_role_policy(self.project, {"viewer": ["system.admin"]}, 1, self.admin)
        reopened = PortalStore(Path(self.tmp.name) / "portal.sqlite3")
        self.assertEqual(reopened.list_inputs(self.project)[0]["input_id"], self.input_id)

    def test_run_progress_cancel_and_recovery(self):
        run = self.store.create_scan(self.admin, self.project, self.input_id, "local", "all")
        self.assertTrue(self.store.mark_run_running(run["run_id"]))
        self.assertTrue(self.store.set_run_progress(run["run_id"], "scanning", 35))
        cancelling = self.store.request_cancel(run["run_id"], self.admin)
        self.assertEqual(cancelling["status"], "cancelling")
        self.store.complete_run(run["run_id"], result={"findings": []})
        cancelled = self.store.run(run["run_id"])
        self.assertEqual((cancelled["status"], cancelled["stage"], cancelled["result"]), ("cancelled", "cancelled", None))


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
        self.assertEqual(self.request("/koda/api/v1/projects", headers=self.headers(approved_tracker_user)), (200, []))
        status, admin_page = self.request("/koda/admin/subjects", headers=self.headers())
        self.assertEqual(status, 200)
        self.assertIn("<link rel='icon' href='/koda/assets/KODA.ico'>", admin_page)
        self.assertIn("/koda/assets/KODA.ico", admin_page)
        self.assertNotIn("Tracker", admin_page.split("</nav>", 1)[0])
        self.assertIn("회원가입과 계정 승인은 KODA-SBOM-Tracker", admin_page)
        self.assertIn("KODA 접근 제어", admin_page)
        self.assertNotIn("<option>pending</option>", admin_page)
        self.assertIn("syncSubject()", admin_page)

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
        self.assertEqual(status, 200)
        self.assertIn("KODA 관리자에게 프로젝트 생성 및", body)
        status, body = self.request("/koda/projects", headers=viewer_headers)
        self.assertEqual(status, 200)
        self.assertIn("Tracker 승인 후에도 KODA 관리자가", body)
        self.assertNotIn("id='create'", body)

    def test_scope_menus_render_independent_scan_pages(self):
        project = self.server.portal_store.create_project("scope pages", self.admin)
        target = Path(self.tmp.name) / "scope.py"
        target.write_text("print('scope')\n", encoding="utf-8")
        self.server.portal_store.add_input(project, target.name, target, self.admin)
        status, library = self.request("/koda/scans/library", headers=self.headers())
        self.assertEqual(status, 200)
        self.assertIn("라이브러리 보안취약점 점검", library)
        self.assertIn("scope=\"library\"", library)
        self.assertIn("href='/koda/scans/source'", library)
        status, source = self.request("/koda/scans/source", headers=self.headers())
        self.assertEqual(status, 200)
        self.assertIn("소스코드 보안취약점 점검", source)
        self.assertIn("scope=\"source\"", source)
        self.assertIn("href='/koda/scans/library'", source)

    def test_role_policy_labels_screens_and_features_in_korean(self):
        project = self.server.portal_store.create_project("role labels", self.admin)
        status, body = self.request(f"/koda/admin/roles?project={project}", headers=self.headers())
        self.assertEqual(status, 200)
        self.assertIn("화면·기능별 역할 권한", body)
        self.assertIn("프로젝트·결과", body)
        self.assertIn("라이브러리·소스코드 점검", body)
        self.assertIn("프로젝트 관리자", body)
        self.assertIn("value='admin'>프로젝트 관리자", body)
        self.assertIn("project.view", body)

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
        self.assertIn("최대 1 GiB", scan_page)
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

    def test_cancel_retry_and_comparison_exports(self):
        project = self.server.portal_store.create_project("history", self.admin)
        target = Path(self.tmp.name) / "history.py"
        target.write_text("print('history')\n", encoding="utf-8")
        input_id = self.server.portal_store.add_input(project, target.name, target, self.admin)
        first = self.server.portal_store.create_scan(self.admin, project, input_id, "local", "all")
        self.server.portal_store.complete_run(first["run_id"], result={"findings": [{"rule_id": "rule.old", "title": "old", "severity": "low", "category": "code", "path": "a.py", "line": 1}]})
        second = self.server.portal_store.create_scan(self.admin, project, input_id, "local", "all")
        status, cancelled = self.request(f"/koda/api/v1/runs/{second['run_id']}/cancel", method="POST", payload={}, headers=self.headers())
        self.assertEqual((status, cancelled["status"]), (200, "cancelled"))
        cancelled_comparison = f"left={first['run_id']}&right={second['run_id']}"
        self.assertEqual(self.request(f"/koda/api/v1/compare?{cancelled_comparison}", headers=self.headers())[0], 422)
        status, retried = self.request(f"/koda/api/v1/runs/{second['run_id']}/retry", method="POST", payload={}, headers=self.headers())
        self.assertEqual((status, retried["round_number"]), (202, 3))

        comparison_run = self.server.portal_store.create_scan(self.admin, project, input_id, "local", "all")
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


if __name__ == "__main__":
    unittest.main()
