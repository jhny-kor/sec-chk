import datetime as dt
import base64
import hashlib
import json
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
import uuid
from pathlib import Path

from security_scanner.portal_identity import IdentityError, identity_from_headers
from security_scanner.linux_portal import create_portal_server
from security_scanner.portal_store import PortalStore


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

    def test_login_pending_and_admin_pages(self):
        status, body = self.request("/koda/login?next=https://evil.example")
        self.assertEqual(status, 200)
        self.assertIn("LDAP 계정", body)
        self.assertIn("/koda/assets/KODA.ico", body)
        self.assertNotIn("Tracker", body)
        self.assertIn('location="/koda/"', body)
        status, body = self.request("/koda/login?next=/koda/%3C/script%3Ealert(1)%3C/script%3E")
        self.assertEqual(status, 200)
        self.assertNotIn("<script>alert(1)</script>", body)
        self.assertIn('location="/koda/"', body)
        pending = str(uuid.uuid4())
        status, me = self.request("/koda/api/v1/me", headers=self.headers(pending, "pending"))
        self.assertEqual((status, me["status"]), (200, "pending"))
        self.assertEqual(self.request("/koda/api/v1/projects", headers=self.headers(pending))[0], 403)
        status, admin_page = self.request("/koda/admin/subjects", headers=self.headers())
        self.assertEqual(status, 200)
        self.assertIn("/koda/assets/KODA.ico", admin_page)
        self.assertNotIn("Tracker", admin_page.split("</nav>", 1)[0])

    def test_public_koda_icon_asset(self):
        status, body = self.request("/koda/assets/KODA.ico")
        self.assertEqual(status, 200)
        self.assertTrue(body.startswith(b"\x00\x00\x01\x00"))
        self.assertEqual(self.request("/koda/assets/missing.ico")[0], 404)

    def test_project_upload_scan_round_and_injection_rejection(self):
        status, created = self.request("/koda/api/v1/projects", method="POST", payload={"name": "portal"}, headers=self.headers())
        self.assertEqual(status, 201)
        project_id = created["project_id"]
        status, uploaded = self.request(
            f"/koda/api/v1/projects/{project_id}/inputs", method="POST",
            payload={"name": "demo.py", "contentBase64": base64.b64encode(b"print('ok')\n").decode()}, headers=self.headers(),
        )
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


if __name__ == "__main__":
    unittest.main()
