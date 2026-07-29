from __future__ import annotations

import html
import json
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .sbom_verification import ActualArchiveIdentity, VerificationItem


def write_verification_reports(
    output_dir: Path,
    results: tuple[VerificationItem, ...],
    baseline_changes: tuple[VerificationItem, ...],
    actual: tuple[ActualArchiveIdentity, ...],
    summary: dict[str, int],
    metadata: dict[str, object],
    report_format: str,
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    payload = {
        "summary": summary,
        "results": [item.payload() for item in results],
        "baseline_changes": [item.payload() for item in baseline_changes],
        "manual_review_candidates": [item.payload() for item in (*results, *baseline_changes) if item.status in {"UNRESOLVED_COMPONENT", "AMBIGUOUS_MATCH"}],
        "warnings": metadata.get("warnings", []),
        "metadata": metadata,
    }
    (output_dir / "sbom-verification.json").write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (output_dir / "current-inventory.json").write_text(json.dumps({"components": [_actual_payload(item) for item in actual]}, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (output_dir / "verification-metadata.json").write_text(json.dumps(metadata, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    (output_dir / "sbom-verification.md").write_text(_markdown(payload), encoding="utf-8")
    (output_dir / "sbom-verification.html").write_text(_html(payload), encoding="utf-8")


def _actual_payload(item: ActualArchiveIdentity) -> dict[str, object]:
    return {
        "group": item.group,
        "name": item.name,
        "version": item.version,
        "purl": item.purl,
        "sha256": item.sha256,
        "filename": item.filename,
        "locations": list(item.locations),
        "version_source": item.version_source,
        "confidence": item.confidence,
        "identity_status": item.identity_status,
        "nested": item.nested,
        "filename_version": item.filename_version,
        "filename_version_mismatch": item.filename_version_mismatch,
    }


def _markdown(payload: dict[str, object]) -> str:
    summary = payload["summary"]
    lines = ["# SBOM Verification", "", f"Target: {payload['metadata']['target']}", "", "## Summary", ""]
    lines.extend(f"- {key}: {value}" for key, value in summary.items())
    lines.extend(["", "## Results", "", "| Status | Component | SBOM version | Actual version | SHA-256 | Locations | Details |", "| --- | --- | --- | --- | --- | --- | --- |"])
    for item in [*payload["results"], *payload["baseline_changes"]]:
        lines.append(f"| {item['status']} | {item['component_name']} | {item['sbom_version'] or '-'} | {item['actual_version'] or '-'} | {item['actual_sha256'] or item['sbom_sha256'] or '-'} | {'<br>'.join(item['locations']) or '-'} | {item['details']} |")
    if not payload["results"] and not payload["baseline_changes"]:
        lines.append("| - | - | - | - | - | - | No components were compared. |")
    return "\n".join(lines) + "\n"


def _html(payload: dict[str, object]) -> str:
    summary = payload["summary"]
    cards = "".join(f'<div class="metric"><b>{html.escape(key)}</b><br>{value}</div>' for key, value in summary.items())
    rows = []
    for item in [*payload["results"], *payload["baseline_changes"]]:
        rows.append("<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
            html.escape(str(item["status"])), html.escape(str(item["component_name"])), html.escape(str(item["sbom_version"] or "-")), html.escape(str(item["actual_version"] or "-")), html.escape(str(item["actual_sha256"] or item["sbom_sha256"] or "-")), html.escape("<br>".join(item["locations"]) or "-"), html.escape(str(item["details"])),
        ))
    body = "".join(rows) or '<tr><td colspan="7">No components were compared.</td></tr>'
    return f'''<!doctype html><meta charset="utf-8"><title>SBOM Verification</title>
<style>body{{font:14px system-ui;margin:2rem;color:#172033}}.summary{{display:flex;gap:.6rem;flex-wrap:wrap}}.metric{{padding:.7rem 1rem;background:#f4f6fa;border-radius:8px}}table{{border-collapse:collapse;width:100%;margin-top:1rem}}td,th{{border:1px solid #ccd3df;padding:.45rem;text-align:left;vertical-align:top}}th{{background:#eef2f7}}</style>
<h1>SBOM Verification</h1><p>Target: {html.escape(str(payload["metadata"]["target"]))}</p><div class="summary">{cards}</div>
<table><thead><tr><th>Status</th><th>Component</th><th>SBOM version</th><th>Actual version</th><th>SHA-256</th><th>Locations</th><th>Details</th></tr></thead><tbody>{body}</tbody></table>'''
