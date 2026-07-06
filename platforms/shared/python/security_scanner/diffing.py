from __future__ import annotations

import json
from pathlib import Path


def load_report_findings(path: Path) -> list[dict[str, object]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    findings = payload.get("findings", []) if isinstance(payload, dict) else []
    return [item for item in findings if isinstance(item, dict)]


def diff_reports(baseline: Path, current: Path) -> dict[str, object]:
    baseline_findings = load_report_findings(baseline)
    current_findings = load_report_findings(current)
    baseline_map = {_finding_key(item): item for item in baseline_findings}
    current_map = {_finding_key(item): item for item in current_findings}
    baseline_keys = set(baseline_map)
    current_keys = set(current_map)
    added = [current_map[key] for key in sorted(current_keys - baseline_keys)]
    resolved = [baseline_map[key] for key in sorted(baseline_keys - current_keys)]
    unchanged = [current_map[key] for key in sorted(current_keys & baseline_keys)]
    return {
        "baseline": str(baseline),
        "current": str(current),
        "summary": {
            "added": len(added),
            "resolved": len(resolved),
            "unchanged": len(unchanged),
            "baseline_total": len(baseline_findings),
            "current_total": len(current_findings),
        },
        "added": added,
        "resolved": resolved,
        "unchanged": unchanged,
    }


def render_diff_json(diff: dict[str, object]) -> str:
    return json.dumps(diff, indent=2, ensure_ascii=False)


def render_diff_markdown(diff: dict[str, object], *, language: str = "ko") -> str:
    summary = diff["summary"] if isinstance(diff.get("summary"), dict) else {}
    title = "KODA 점검결과 변경 리포트" if language == "ko" else "KODA Scan Diff Report"
    added_title = "새로 발생" if language == "ko" else "Added"
    resolved_title = "해결됨" if language == "ko" else "Resolved"
    unchanged_title = "유지됨" if language == "ko" else "Unchanged"
    lines = [
        f"# {title}",
        "",
        f"- Baseline: {diff.get('baseline')}",
        f"- Current: {diff.get('current')}",
        f"- {added_title}: {summary.get('added', 0)}",
        f"- {resolved_title}: {summary.get('resolved', 0)}",
        f"- {unchanged_title}: {summary.get('unchanged', 0)}",
        "",
    ]
    lines.extend(_section(added_title, diff.get("added", [])))
    lines.extend(_section(resolved_title, diff.get("resolved", [])))
    return "\n".join(lines)


def _section(title: str, findings: object) -> list[str]:
    lines = [f"## {title}", ""]
    if not isinstance(findings, list) or not findings:
        lines.extend(["- none", ""])
        return lines
    for item in findings:
        if not isinstance(item, dict):
            continue
        lines.append(
            f"- [{item.get('severity', 'unknown')}] {item.get('rule_id', 'unknown')} - {item.get('path', '')}"
        )
    lines.append("")
    return lines


def _finding_key(item: dict[str, object]) -> tuple[str, str, str, str]:
    return (
        str(item.get("rule_id", "")),
        str(item.get("target", "")),
        str(item.get("path", "")),
        str(item.get("line", "")),
    )
