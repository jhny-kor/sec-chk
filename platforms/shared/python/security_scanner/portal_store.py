"""Durable SQLite state for the authenticated Linux portal."""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from pathlib import Path

from .models import SCAN_SCOPE_CATEGORIES


SCREEN_PERMISSIONS = frozenset({
    "dashboard.view", "scan.library.view", "scan.source.view", "runs.view", "compare.view", "projects.view",
})
FEATURE_PERMISSIONS = frozenset({"input.manage", "scan.create", "project.manage"})
LEGACY_PROJECT_PERMISSION = "project.view"
DEFAULT_ROLE_PERMISSIONS = {
    "admin": {*SCREEN_PERMISSIONS, *FEATURE_PERMISSIONS},
    "manager": {*SCREEN_PERMISSIONS, "input.manage", "scan.create"},
    "analyst": {*SCREEN_PERMISSIONS, "input.manage", "scan.create"},
    "uploader": {"dashboard.view", "scan.library.view", "scan.source.view", "runs.view", "projects.view", "input.manage", "scan.create"},
    "viewer": {"dashboard.view", "runs.view", "projects.view"},
}
PROJECT_PERMISSIONS = frozenset().union(*DEFAULT_ROLE_PERMISSIONS.values(), {LEGACY_PROJECT_PERMISSION})
RESERVED_PERMISSIONS = {"system.admin", "subjects.manage", "roles.manage", "rules.manage"}
TERMINAL_RUN_STATUSES = frozenset({"completed", "failed", "cancelled"})
GLOBAL_ROLE_POLICY_ID = "__koda_global__"


class VersionConflict(ValueError):
    pass


class PortalStore:
    def __init__(self, path: str | Path):
        self.path = str(Path(path).expanduser())
        self._lock = threading.RLock()
        self._init()

    @contextmanager
    def _db(self):
        db = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        try:
            yield db
        finally:
            db.close()

    def _init(self) -> None:
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        with self._db() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS subjects(
                  subject_id TEXT PRIMARY KEY, display TEXT NOT NULL,
                  status TEXT NOT NULL CHECK(status IN ('pending','enabled','disabled','tombstoned')),
                  system_admin INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS projects(
                  project_id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS memberships(
                  project_id TEXT NOT NULL, subject_id TEXT NOT NULL, role TEXT NOT NULL,
                  PRIMARY KEY(project_id,subject_id),
                  FOREIGN KEY(project_id) REFERENCES projects(project_id),
                  FOREIGN KEY(subject_id) REFERENCES subjects(subject_id));
                CREATE TABLE IF NOT EXISTS role_policies(
                  project_id TEXT NOT NULL, version INTEGER NOT NULL,
                  roles_json TEXT NOT NULL, hash TEXT NOT NULL, created_at TEXT NOT NULL,
                  PRIMARY KEY(project_id,version));
                CREATE TABLE IF NOT EXISTS inputs(
                  input_id TEXT PRIMARY KEY, project_id TEXT NOT NULL, name TEXT NOT NULL,
                  path TEXT NOT NULL, content_hash TEXT NOT NULL, created_at TEXT NOT NULL,
                  FOREIGN KEY(project_id) REFERENCES projects(project_id));
                CREATE TABLE IF NOT EXISTS rule_policies(
                  project_id TEXT NOT NULL, version INTEGER NOT NULL,
                  rules_json TEXT NOT NULL, hash TEXT NOT NULL, created_at TEXT NOT NULL,
                  PRIMARY KEY(project_id,version));
                CREATE TABLE IF NOT EXISTS scan_runs(
                  run_id TEXT PRIMARY KEY, project_id TEXT NOT NULL, round_number INTEGER NOT NULL,
                  status TEXT NOT NULL, standard TEXT NOT NULL, standard_category TEXT NOT NULL,
                  input_id TEXT NOT NULL, policy_version INTEGER NOT NULL, requested_by TEXT NOT NULL,
                  snapshot_json TEXT NOT NULL, result_json TEXT, error TEXT,
                  created_at TEXT NOT NULL, completed_at TEXT,
                  stage TEXT NOT NULL DEFAULT 'queued', progress INTEGER NOT NULL DEFAULT 0,
                  cancel_requested INTEGER NOT NULL DEFAULT 0,
                  UNIQUE(project_id,round_number));
                CREATE TABLE IF NOT EXISTS analysis_revisions(
                  revision_id TEXT PRIMARY KEY, run_id TEXT NOT NULL, sequence INTEGER NOT NULL,
                  snapshot_json TEXT NOT NULL, result_json TEXT, created_at TEXT NOT NULL,
                  UNIQUE(run_id,sequence));
                CREATE TABLE IF NOT EXISTS audit_events(
                  id INTEGER PRIMARY KEY AUTOINCREMENT, subject_id TEXT, action TEXT NOT NULL,
                  project_id TEXT, detail_json TEXT NOT NULL, created_at TEXT NOT NULL);
                """
            )
            columns = {row[1] for row in db.execute("PRAGMA table_info(scan_runs)")}
            for definition in (
                "stage TEXT NOT NULL DEFAULT 'queued'",
                "progress INTEGER NOT NULL DEFAULT 0",
                "cancel_requested INTEGER NOT NULL DEFAULT 0",
            ):
                if definition.split()[0] not in columns:
                    db.execute(f"ALTER TABLE scan_runs ADD COLUMN {definition}")
            self._migrate_legacy_role_permissions(db)
            self._ensure_global_role_policy(db)

    def _migrate_legacy_role_permissions(self, db) -> None:
        """Give legacy project viewers explicit access to every screen once."""
        db.execute("BEGIN IMMEDIATE")
        try:
            rows = db.execute(
                "SELECT p.project_id,p.version,p.roles_json FROM role_policies p "
                "WHERE p.version=(SELECT max(version) FROM role_policies WHERE project_id=p.project_id)"
            ).fetchall()
            for row in rows:
                roles = json.loads(row["roles_json"])
                migrated = False
                for permissions in roles.values():
                    if LEGACY_PROJECT_PERMISSION in permissions:
                        merged = (set(permissions) - {LEGACY_PROJECT_PERMISSION}) | SCREEN_PERMISSIONS
                        if merged != set(permissions):
                            permissions[:] = sorted(merged)
                            migrated = True
                if not migrated:
                    continue
                encoded, now = self._json(roles), self._now()
                version = int(row["version"]) + 1
                digest = hashlib.sha256(encoded.encode()).hexdigest()
                db.execute("INSERT INTO role_policies VALUES(?,?,?,?,?)", (row["project_id"], version, encoded, digest, now))
                self._audit_db(db, None, "role_policy.migrated", row["project_id"], {
                    "from_version": int(row["version"]), "version": version, "reason": "legacy project.view screen access",
                })
            db.execute("COMMIT")
        except Exception:
            db.execute("ROLLBACK")
            raise

    def _ensure_global_role_policy(self, db) -> None:
        """Create one KODA-wide role policy from the most evolved legacy policy."""
        if db.execute("SELECT 1 FROM role_policies WHERE project_id=? LIMIT 1", (GLOBAL_ROLE_POLICY_ID,)).fetchone():
            return
        source = db.execute(
            "SELECT project_id,roles_json FROM role_policies WHERE project_id!=? "
            "ORDER BY version DESC,created_at DESC LIMIT 1",
            (GLOBAL_ROLE_POLICY_ID,),
        ).fetchone()
        roles_json = source["roles_json"] if source else self._json({key: sorted(value) for key, value in DEFAULT_ROLE_PERMISSIONS.items()})
        now = self._now()
        digest = hashlib.sha256(roles_json.encode()).hexdigest()
        db.execute("INSERT INTO role_policies VALUES(?,?,?,?,?)", (GLOBAL_ROLE_POLICY_ID, 1, roles_json, digest, now))
        self._audit_db(db, None, "role_policy.globalized", None, {
            "version": 1, "source_project_id": source["project_id"] if source else None,
        })

    @staticmethod
    def _now() -> str:
        return dt.datetime.now(dt.timezone.utc).isoformat()

    @staticmethod
    def _json(value: object) -> str:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))

    @staticmethod
    def _dict(row: sqlite3.Row | None) -> dict | None:
        return dict(row) if row else None

    def subject(self, subject_id: str) -> dict | None:
        with self._db() as db:
            return self._dict(db.execute("SELECT * FROM subjects WHERE subject_id=?", (str(subject_id),)).fetchone())

    def project(self, project_id: str) -> dict | None:
        with self._db() as db:
            return self._dict(db.execute("SELECT * FROM projects WHERE project_id=?", (str(project_id),)).fetchone())

    def ensure_subject(self, subject_id: str, display: str = "") -> dict:
        subject_id, now = str(uuid.UUID(str(subject_id))), self._now()
        with self._lock, self._db() as db:
            db.execute(
                "INSERT OR IGNORE INTO subjects(subject_id,display,status,created_at,updated_at) "
                "VALUES(?,?,'pending',?,?)",
                (subject_id, display[:128], now, now),
            )
            db.execute(
                "UPDATE subjects SET display=?,updated_at=? WHERE subject_id=? AND status!='tombstoned' AND display!=?",
                (display[:128], now, subject_id, display[:128]),
            )
            return dict(db.execute("SELECT * FROM subjects WHERE subject_id=?", (subject_id,)).fetchone())

    def list_subjects(self) -> list[dict]:
        with self._db() as db:
            return [dict(row) for row in db.execute("SELECT * FROM subjects ORDER BY display,subject_id")]

    def set_subject(self, subject_id: str, *, status=None, system_admin=None, display=None, actor=None) -> dict:
        with self._lock, self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM subjects WHERE subject_id=?", (str(subject_id),)).fetchone()
            if not row:
                raise KeyError("subject not found")
            new_status = status if status is not None else row["status"]
            if new_status not in {"pending", "enabled", "disabled", "tombstoned"}:
                raise ValueError("invalid subject status")
            new_admin = int(row["system_admin"] if system_admin is None else bool(system_admin))
            if row["system_admin"] and row["status"] == "enabled" and (new_status != "enabled" or not new_admin):
                count = db.execute(
                    "SELECT count(*) FROM subjects WHERE status='enabled' AND system_admin=1"
                ).fetchone()[0]
                if count <= 1:
                    raise ValueError("last enabled system administrator")
            db.execute(
                "UPDATE subjects SET status=?,system_admin=?,display=?,updated_at=? WHERE subject_id=?",
                (new_status, new_admin, display if display is not None else row["display"], self._now(), str(subject_id)),
            )
            updated = dict(db.execute("SELECT * FROM subjects WHERE subject_id=?", (str(subject_id),)).fetchone())
            self._audit_db(db, actor, "subject.updated", None, {"subject_id": str(subject_id), "status": new_status, "system_admin": bool(new_admin)})
            db.execute("COMMIT")
            return updated

    def bootstrap(self, subject_id: str) -> dict:
        with self._db() as db:
            existing_admin = db.execute(
                "SELECT subject_id FROM subjects WHERE status='enabled' AND system_admin=1 LIMIT 1"
            ).fetchone()
        if existing_admin and existing_admin["subject_id"] != str(subject_id):
            raise ValueError("portal bootstrap has already been completed")
        existing = self.subject(subject_id)
        if existing and existing["status"] == "tombstoned":
            raise ValueError("tombstoned subject cannot be bootstrapped")
        self.ensure_subject(subject_id)
        return self.set_subject(subject_id, status="enabled", system_admin=True, actor=subject_id)

    def create_project(self, name: str, actor: str | None = None, project_id: str | None = None) -> str:
        name = name.strip()
        if not 1 <= len(name) <= 128:
            raise ValueError("project name is required")
        project_id, now = str(project_id or uuid.uuid4()), self._now()
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("INSERT INTO projects(project_id,name,created_at) VALUES(?,?,?)", (project_id, name, now))
            rules = self._json([])
            db.execute("INSERT INTO rule_policies VALUES(?,?,?,?,?)", (project_id, 1, rules, hashlib.sha256(rules.encode()).hexdigest(), now))
            if actor:
                db.execute("INSERT INTO memberships VALUES(?,?,?)", (project_id, str(actor), "admin"))
            self._audit_db(db, actor, "project.created", project_id, {"name": name})
            db.execute("COMMIT")
        return project_id

    def list_projects(self, subject_id: str) -> list[dict]:
        subject = self.subject(subject_id)
        if not subject or subject["status"] != "enabled":
            return []
        with self._db() as db:
            if subject["system_admin"]:
                rows = db.execute("SELECT * FROM projects ORDER BY name")
            else:
                rows = db.execute(
                    "SELECT p.* FROM projects p JOIN memberships m USING(project_id) "
                    "WHERE m.subject_id=? ORDER BY p.name",
                    (str(subject_id),),
                )
            return [dict(row) for row in rows]

    def set_membership(self, project_id: str, subject_id: str, role: str, actor: str | None = None) -> None:
        policy = self.role_policy()
        if role not in policy["roles"]:
            raise ValueError("unknown role")
        with self._db() as db:
            db.execute(
                "INSERT INTO memberships(project_id,subject_id,role) VALUES(?,?,?) "
                "ON CONFLICT(project_id,subject_id) DO UPDATE SET role=excluded.role",
                (str(project_id), str(subject_id), role),
            )
            self._audit_db(db, actor, "membership.updated", project_id, {"subject_id": str(subject_id), "role": role})

    def list_memberships(self, project_id: str) -> list[dict]:
        with self._db() as db:
            rows = db.execute(
                "SELECT m.project_id,m.subject_id,m.role,s.display,s.status FROM memberships m "
                "JOIN subjects s USING(subject_id) WHERE m.project_id=? ORDER BY s.display,m.subject_id",
                (str(project_id),),
            )
            return [dict(row) for row in rows]

    def list_memberships_all(self) -> list[dict]:
        with self._db() as db:
            rows = db.execute(
                "SELECT m.project_id,p.name AS project_name,m.subject_id,m.role,s.display,s.status "
                "FROM memberships m JOIN projects p USING(project_id) JOIN subjects s USING(subject_id) "
                "ORDER BY p.name,s.display,m.subject_id"
            )
            return [dict(row) for row in rows]

    def remove_membership(self, project_id: str, subject_id: str, actor: str | None = None) -> None:
        with self._db() as db:
            db.execute("DELETE FROM memberships WHERE project_id=? AND subject_id=?", (str(project_id), str(subject_id)))
            self._audit_db(db, actor, "membership.removed", project_id, {"subject_id": str(subject_id)})

    def role_policy(self, project_id: str | None = None) -> dict:
        with self._db() as db:
            row = db.execute(
                "SELECT * FROM role_policies WHERE project_id=? ORDER BY version DESC LIMIT 1", (GLOBAL_ROLE_POLICY_ID,)
            ).fetchone()
        if not row:
            raise KeyError("role policy not found")
        result = dict(row)
        result["roles"] = json.loads(result.pop("roles_json"))
        return result

    def set_role_policy(self, roles: dict, expected_version: int, actor: str | None = None) -> dict:
        normalized: dict[str, list[str]] = {}
        for role, permissions in dict(roles).items():
            if not isinstance(role, str) or not role or not isinstance(permissions, list):
                raise ValueError("invalid role policy")
            permission_set = set(permissions)
            if len(permission_set) != len(permissions) or permission_set - PROJECT_PERMISSIONS or permission_set & RESERVED_PERMISSIONS:
                raise ValueError("unknown, duplicate, or reserved permission")
            if LEGACY_PROJECT_PERMISSION in permission_set:
                permission_set = (permission_set - {LEGACY_PROJECT_PERMISSION}) | SCREEN_PERMISSIONS
            normalized[role] = sorted(permission_set)
        if not normalized:
            raise ValueError("at least one role is required")
        encoded, now = self._json(normalized), self._now()
        with self._lock, self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            current = db.execute("SELECT max(version) FROM role_policies WHERE project_id=?", (GLOBAL_ROLE_POLICY_ID,)).fetchone()[0] or 0
            if int(expected_version) != current:
                raise VersionConflict("stale role policy version")
            version = current + 1
            digest = hashlib.sha256(encoded.encode()).hexdigest()
            db.execute("INSERT INTO role_policies VALUES(?,?,?,?,?)", (GLOBAL_ROLE_POLICY_ID, version, encoded, digest, now))
            self._audit_db(db, actor, "role_policy.updated", None, {"version": version})
            db.execute("COMMIT")
        return {"version": version, "hash": digest, "roles": normalized}

    def can(self, subject_id: str, project_id: str, permission: str = "project.view") -> bool:
        subject = self.subject(subject_id)
        if not subject or subject["status"] != "enabled":
            return False
        if subject["system_admin"]:
            return True
        with self._db() as db:
            member = db.execute(
                "SELECT role FROM memberships WHERE project_id=? AND subject_id=?", (str(project_id), str(subject_id))
            ).fetchone()
        if not member:
            return False
        try:
            permissions = set(self.role_policy()["roles"].get(member["role"], []))
        except KeyError:
            return False
        aliases = {"view": "project.view", "scan": "scan.create", "upload": "input.manage", "manage": "project.manage"}
        requested = aliases.get(permission, permission)
        return requested in permissions or (requested == LEGACY_PROJECT_PERMISSION and bool(permissions & SCREEN_PERMISSIONS))

    def add_input(self, project_id: str, name: str, path: str | Path, actor: str | None = None, content_hash="") -> str:
        path = Path(path)
        content_hash = content_hash or hashlib.sha256(path.read_bytes()).hexdigest()
        input_id = str(uuid.uuid4())
        with self._db() as db:
            db.execute("INSERT INTO inputs VALUES(?,?,?,?,?,?)", (input_id, str(project_id), name[:255], str(path), content_hash, self._now()))
            self._audit_db(db, actor, "input.created", project_id, {"input_id": input_id, "name": name[:255], "sha256": content_hash})
        return input_id

    def list_inputs(self, project_id: str) -> list[dict]:
        with self._db() as db:
            rows = [dict(row) for row in db.execute("SELECT * FROM inputs WHERE project_id=? ORDER BY created_at DESC", (str(project_id),))]
        for row in rows:
            row["available"] = Path(row["path"]).is_file()
        return rows

    def input(self, input_id: str) -> dict:
        with self._db() as db:
            row = db.execute("SELECT * FROM inputs WHERE input_id=?", (str(input_id),)).fetchone()
        if not row:
            raise KeyError("input not found")
        return dict(row)

    def rule_policy(self, project_id: str) -> dict:
        with self._db() as db:
            row = db.execute("SELECT * FROM rule_policies WHERE project_id=? ORDER BY version DESC LIMIT 1", (str(project_id),)).fetchone()
        if not row:
            raise KeyError("rule policy not found")
        result = dict(row)
        result["disabled_rules"] = json.loads(result.pop("rules_json"))
        return result

    def set_rule_policy(self, project_id: str, rules: list[str] | tuple[str, ...], expected_version: int, actor: str | None = None) -> dict:
        if not isinstance(rules, (list, tuple)) or any(not isinstance(item, str) or not item for item in rules):
            raise ValueError("invalid disabled rule list")
        encoded, now = self._json(sorted(set(rules))), self._now()
        with self._lock, self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            current = db.execute("SELECT max(version) FROM rule_policies WHERE project_id=?", (str(project_id),)).fetchone()[0] or 0
            if int(expected_version) != current:
                raise VersionConflict("stale rule policy version")
            version, digest = current + 1, hashlib.sha256(encoded.encode()).hexdigest()
            db.execute("INSERT INTO rule_policies VALUES(?,?,?,?,?)", (str(project_id), version, encoded, digest, now))
            self._audit_db(db, actor, "rule_policy.updated", project_id, {"version": version})
            db.execute("COMMIT")
        return {"version": version, "hash": digest, "disabled_rules": json.loads(encoded)}

    def create_scan(
        self,
        subject_id: str,
        project_id: str,
        input_id: str,
        standard: str,
        standard_category: str,
        scan_scope: str = "all",
        **unsafe,
    ) -> dict:
        if scan_scope == "library":
            standard, standard_category = "local", "all"
        if (
            unsafe
            or not isinstance(standard, str)
            or not isinstance(standard_category, str)
            or scan_scope not in SCAN_SCOPE_CATEGORIES
        ):
            raise ValueError("unsupported scan options")
        if not self.can(subject_id, project_id, "scan.create"):
            raise PermissionError("project access denied")
        # Validate the selection before reserving a durable round.
        from .standards import resolve_standard_selection

        resolve_standard_selection(standard, standard_category)
        with self._lock, self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            if not self.can(subject_id, project_id, "scan.create"):
                raise PermissionError("project access denied")
            source = db.execute("SELECT * FROM inputs WHERE input_id=? AND project_id=?", (str(input_id), str(project_id))).fetchone()
            if not source:
                raise KeyError("input not found")
            if not Path(source["path"]).is_file():
                raise ValueError("input file is no longer available; upload it again")
            policy = db.execute("SELECT * FROM rule_policies WHERE project_id=? ORDER BY version DESC LIMIT 1", (str(project_id),)).fetchone()
            if not policy:
                raise KeyError("rule policy not found")
            round_number = (db.execute("SELECT max(round_number) FROM scan_runs WHERE project_id=?", (str(project_id),)).fetchone()[0] or 0) + 1
            disabled_rules = json.loads(policy["rules_json"])
            snapshot = {
                "input_id": str(input_id), "input_hash": source["content_hash"],
                "standard": standard, "standard_category": standard_category,
                "scan_scope": scan_scope,
                "disabled_rules": disabled_rules, "rule_policy_version": policy["version"],
                "rule_policy_hash": policy["hash"], "scanner_version": _scanner_version(),
                "requested_by": str(subject_id),
            }
            run_id, revision_id, now = str(uuid.uuid4()), str(uuid.uuid4()), self._now()
            db.execute(
                "INSERT INTO scan_runs(run_id,project_id,round_number,status,standard,standard_category,input_id,policy_version,requested_by,snapshot_json,created_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (run_id, str(project_id), round_number, "queued", standard, standard_category, str(input_id), policy["version"], str(subject_id), self._json(snapshot), now),
            )
            db.execute("INSERT INTO analysis_revisions(revision_id,run_id,sequence,snapshot_json,created_at) VALUES(?,?,?,?,?)", (revision_id, run_id, 1, self._json(snapshot), now))
            self._audit_db(db, subject_id, "scan.created", project_id, {"run_id": run_id, "round_number": round_number})
            db.execute("COMMIT")
        return self.run(run_id)

    def mark_run_running(self, run_id: str) -> bool:
        with self._db() as db:
            changed = db.execute(
                "UPDATE scan_runs SET status='running',stage='preparing',progress=5 "
                "WHERE run_id=? AND status='queued' AND cancel_requested=0",
                (str(run_id),),
            ).rowcount
            return bool(changed)

    def set_run_progress(self, run_id: str, stage: str, progress: int) -> bool:
        if stage not in {"preparing", "scanning", "finalizing"} or not 0 <= int(progress) <= 99:
            raise ValueError("invalid run progress")
        with self._db() as db:
            changed = db.execute(
                "UPDATE scan_runs SET stage=?,progress=? WHERE run_id=? AND status='running' AND cancel_requested=0",
                (stage, int(progress), str(run_id)),
            ).rowcount
            return bool(changed)

    def request_cancel(self, run_id: str, actor: str | None = None) -> dict:
        with self._lock, self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM scan_runs WHERE run_id=?", (str(run_id),)).fetchone()
            if not row:
                raise KeyError("run not found")
            if row["status"] not in {"queued", "running", "cancelling"}:
                raise ValueError("run is not cancellable")
            status, stage, completed = (
                ("cancelled", "cancelled", self._now())
                if row["status"] == "queued"
                else ("cancelling", "cancelling", None)
            )
            db.execute(
                "UPDATE scan_runs SET cancel_requested=1,status=?,stage=?,completed_at=COALESCE(?,completed_at) WHERE run_id=?",
                (status, stage, completed, str(run_id)),
            )
            self._audit_db(db, actor, "scan.cancel_requested", row["project_id"], {"run_id": str(run_id)})
            db.execute("COMMIT")
        result = self.run(run_id)
        if result["status"] == "cancelled":
            self.cleanup_input_for_run(run_id)
        return result

    def recover_incomplete_runs(self) -> list[str]:
        with self._lock, self._db() as db:
            db.execute("UPDATE scan_runs SET status='cancelled',stage='cancelled',completed_at=? WHERE status IN ('running','cancelling') AND cancel_requested=1", (self._now(),))
            db.execute("UPDATE scan_runs SET status='queued',stage='queued',progress=0 WHERE status IN ('running','cancelling') AND cancel_requested=0")
            queued = [row[0] for row in db.execute("SELECT run_id FROM scan_runs WHERE status='queued' ORDER BY created_at")]
        self.cleanup_terminal_inputs()
        return queued

    def cleanup_input_for_run(self, run_id: str) -> bool:
        """Remove a terminal run's source file while retaining its result metadata."""
        with self._lock:
            with self._db() as db:
                run = db.execute("SELECT input_id,status FROM scan_runs WHERE run_id=?", (str(run_id),)).fetchone()
                if not run or run["status"] not in TERMINAL_RUN_STATUSES:
                    return False
                active = db.execute(
                    "SELECT 1 FROM scan_runs WHERE input_id=? AND status NOT IN ('completed','failed','cancelled') LIMIT 1",
                    (run["input_id"],),
                ).fetchone()
                if active:
                    return False
                source = db.execute("SELECT path FROM inputs WHERE input_id=?", (run["input_id"],)).fetchone()
                if not source:
                    return False
                path = Path(source["path"])
            try:
                path.unlink(missing_ok=True)
            except OSError:
                return False
            return True

    def cleanup_terminal_inputs(self) -> int:
        with self._lock:
            with self._db() as db:
                run_ids = [row[0] for row in db.execute("SELECT run_id FROM scan_runs WHERE status IN ('completed','failed','cancelled')")]
            return sum(self.cleanup_input_for_run(run_id) for run_id in run_ids)

    def complete_run(self, run_id: str, result: dict | None = None, error: str | None = None) -> None:
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            current = db.execute("SELECT cancel_requested FROM scan_runs WHERE run_id=?", (str(run_id),)).fetchone()
            if not current:
                db.execute("ROLLBACK")
                raise KeyError("run not found")
            cancelled = bool(current["cancel_requested"])
            status = "cancelled" if cancelled else ("failed" if error else "completed")
            stage, progress, completed = status, (0 if cancelled else 100), self._now()
            result_json = None if cancelled else (self._json(result) if result is not None else None)
            db.execute(
                "UPDATE scan_runs SET status=?,stage=?,progress=?,result_json=?,error=?,completed_at=? WHERE run_id=?",
                (status, stage, progress, result_json, None if cancelled else error, completed, str(run_id)),
            )
            db.execute("UPDATE analysis_revisions SET result_json=? WHERE run_id=? AND sequence=1", (result_json, str(run_id)))
            row = db.execute("SELECT requested_by,project_id FROM scan_runs WHERE run_id=?", (str(run_id),)).fetchone()
            if row:
                self._audit_db(db, row["requested_by"], f"scan.{status}", row["project_id"], {"run_id": str(run_id), "error": error or ""})
            db.execute("COMMIT")
        self.cleanup_input_for_run(run_id)

    def run(self, run_id: str) -> dict:
        with self._db() as db:
            row = db.execute("SELECT * FROM scan_runs WHERE run_id=?", (str(run_id),)).fetchone()
        if not row:
            raise KeyError("run not found")
        result = dict(row)
        result["snapshot"] = json.loads(result.pop("snapshot_json"))
        result_json = result.pop("result_json")
        result["result"] = json.loads(result_json) if result_json else None
        return result

    def list_runs(self, project_id: str) -> list[dict]:
        with self._db() as db:
            rows = db.execute("SELECT * FROM scan_runs WHERE project_id=? ORDER BY round_number DESC", (str(project_id),))
            runs = []
            for row in rows:
                value = dict(row)
                snapshot = json.loads(value.pop("snapshot_json"))
                value.pop("result_json", None)
                value["scan_scope"] = snapshot.get("scan_scope", "all")
                runs.append(value)
            return runs

    def audit_events(self, limit: int | None = 100) -> list[dict]:
        with self._db() as db:
            if limit is None:
                rows = db.execute("SELECT * FROM audit_events ORDER BY id DESC")
            else:
                rows = db.execute("SELECT * FROM audit_events ORDER BY id DESC LIMIT ?", (min(max(int(limit), 1), 500),))
            return [dict(row) for row in rows]

    def _audit_db(self, db, subject_id, action, project_id, detail) -> None:
        db.execute(
            "INSERT INTO audit_events(subject_id,action,project_id,detail_json,created_at) VALUES(?,?,?,?,?)",
            (str(subject_id) if subject_id else None, action, str(project_id) if project_id else None, self._json(detail), self._now()),
        )


def _scanner_version() -> str:
    try:
        from importlib.metadata import version

        return version("koda-security-scanner")
    except Exception:
        return "development"
