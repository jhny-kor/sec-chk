"""Bounded, positive-only SARIF 2.1.0 importer."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from .models import Finding

MAX_SARIF_BYTES = 8 * 1024 * 1024
MAX_SARIF_RESULTS = 10_000


class SarifImportError(ValueError):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def load_sarif(path: Path, *, max_bytes: int = MAX_SARIF_BYTES) -> dict[str, Any]:
    try:
        if path.stat().st_size > max_bytes:
            raise SarifImportError("sarif_oversized")
        raw = path.read_bytes()
    except SarifImportError:
        raise
    except OSError as exc:
        raise SarifImportError("sarif_unreadable") from exc
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SarifImportError("sarif_invalid_json") from exc
    if not isinstance(value, dict):
        raise SarifImportError("sarif_invalid_document")
    return value


def import_sarif(
    document: Mapping[str, Any],
    target: Path,
    allowlist: Mapping[tuple[str, str], Mapping[str, Any]] | None = None,
    *,
    allowed_paths: frozenset[str] | None = None,
) -> tuple[tuple[Finding, ...], tuple[str, ...]]:
    if document.get("version") != "2.1.0":
        raise SarifImportError("sarif_wrong_version")
    runs = document.get("runs")
    if not isinstance(runs, list) or not runs:
        raise SarifImportError("sarif_missing_runs")
    root = target.resolve()
    findings: list[Finding] = []
    warnings: list[str] = []
    for run in runs:
        if not isinstance(run, dict):
            raise SarifImportError("sarif_invalid_run")
        tool = run.get("tool")
        driver = tool.get("driver") if isinstance(tool, dict) else None
        if not isinstance(driver, dict) or not isinstance(driver.get("name"), str):
            raise SarifImportError("sarif_missing_tool")
        analyzer = driver["name"]
        analyzer_key = analyzer.strip().lower()
        version = str(driver.get("version", ""))
        declared_rules = driver.get("rules", [])
        if not isinstance(declared_rules, list):
            raise SarifImportError("sarif_invalid_rules")
        declared_rule_ids = {
            item.get("id") for item in declared_rules
            if isinstance(item, dict) and isinstance(item.get("id"), str)
        }
        results = run.get("results", [])
        if not isinstance(results, list):
            raise SarifImportError("sarif_invalid_results")
        if len(results) > MAX_SARIF_RESULTS:
            raise SarifImportError("sarif_too_many_results")
        for result in results:
            if not isinstance(result, dict):
                warnings.append("sarif_result_ignored")
                continue
            rule = result.get("ruleId")
            mapping = allowlist.get((analyzer_key, rule)) if allowlist is not None and isinstance(rule, str) else None
            if mapping is None:
                warnings.append(f"sarif_rule_unmapped:{str(rule)[:128]}")
                continue
            if rule not in declared_rule_ids:
                warnings.append(f"sarif_rule_undeclared:{str(rule)[:128]}")
                continue
            expected_versions = tuple(str(item) for item in mapping.get("analyzer_versions", ()))
            if expected_versions and version not in expected_versions:
                warnings.append(f"sarif_analyzer_version_unmapped:{version[:64]}")
                continue
            locations = result.get("locations")
            if not isinstance(locations, list) or not locations:
                warnings.append("sarif_location_missing")
                continue
            primary = _location(locations[0], root)
            if primary is None:
                warnings.append("sarif_path_outside_target")
                continue
            path, line, column, message = primary
            base = root if root.is_dir() else root.parent
            rel = path.relative_to(base).as_posix()
            if allowed_paths is not None and rel not in allowed_paths:
                warnings.append("sarif_path_not_in_manifest")
                continue
            if not message and isinstance(result.get("message"), dict):
                message = str(result["message"].get("text", ""))
            trace = _trace(result, root, allowed_paths)
            evidence_kind = "dataflow" if trace else str(mapping.get("evidence_kind", "candidate"))
            if evidence_kind not in {"direct", "dataflow", "control_flow", "lifetime", "candidate"}:
                evidence_kind = "candidate"
            status = str(mapping.get("verification_status", "needs_review"))
            if status not in {"confirmed", "needs_review"}:
                status = "needs_review"
            if bool(mapping.get("trace_required")) and len(trace) < 2:
                status = "needs_review"
                evidence_kind = "candidate"
            evidence_id = hashlib.sha256(f"{analyzer}|{version}|{rule}|{rel}|{line}|{trace}".encode()).hexdigest()
            findings.append(Finding(
                rule_id=str(mapping.get("rule_id", rule)), category=str(mapping.get("category", "code")),
                severity=_severity(result.get("level")), title=str(mapping.get("title", rule)), path=path,
                line=line, target=str(mapping.get("target", "")), evidence=message,
                description=str(mapping.get("description", "")), recommendation=str(mapping.get("recommendation", "")),
                verification_status=status, verification_note="Imported from validated SARIF positive evidence.",
                analyzer=analyzer, analyzer_version=version, analyzer_rule_id=rule, cwe_ids=tuple(mapping.get("cwe_ids", ())),
                evidence_kind=evidence_kind, trace=trace, evidence_id=evidence_id,
                issue_key=f"{mapping.get('rule_id', rule)}|{rel}|{line}",
            ))
    return tuple(findings), tuple(warnings[:100])


def _location(value: Any, root: Path) -> tuple[Path, int | None, int | None, str] | None:
    if not isinstance(value, dict):
        return None
    physical = value.get("physicalLocation")
    if not isinstance(physical, dict):
        return None
    artifact = physical.get("artifactLocation")
    uri = artifact.get("uri") if isinstance(artifact, dict) else None
    if not isinstance(uri, str) or not uri or uri.startswith(("file:", "/", "\\")):
        return None
    base = root if root.is_dir() else root.parent
    candidate = (base / Path(uri)).resolve()
    try:
        candidate.relative_to(base)
    except ValueError:
        return None
    if not candidate.is_file():
        return None
    if root.is_file() and candidate != root:
        return None
    region = physical.get("region")
    line = region.get("startLine") if isinstance(region, dict) else None
    column = region.get("startColumn") if isinstance(region, dict) else None
    if line is not None and (isinstance(line, bool) or not isinstance(line, int) or line < 1):
        return None
    return candidate, line, column if isinstance(column, int) else None, str(value.get("message", {}).get("text", "")) if isinstance(value.get("message"), dict) else ""


def _trace(result: Mapping[str, Any], root: Path, allowed_paths: frozenset[str] | None = None) -> tuple[dict[str, object], ...]:
    steps: list[dict[str, object]] = []
    for flow in result.get("codeFlows", []) if isinstance(result.get("codeFlows", []), list) else []:
        for thread in flow.get("threadFlows", []) if isinstance(flow, dict) and isinstance(flow.get("threadFlows", []), list) else []:
            for item in thread.get("locations", []) if isinstance(thread, dict) and isinstance(thread.get("locations", []), list) else []:
                loc = item.get("location") if isinstance(item, dict) else None
                parsed = _location(loc, root)
                if parsed:
                    path, line, column, message = parsed
                    rel = path.relative_to(root if root.is_dir() else root.parent).as_posix()
                    if allowed_paths is None or rel in allowed_paths:
                        steps.append({"path": rel, "line": line, "column": column, "message": message})
    return tuple(steps[:256])


def _severity(level: Any) -> str:
    return {"error": "high", "warning": "medium", "note": "low", "none": "info"}.get(str(level).lower(), "medium")
