from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .integrations import zap_baseline_command
from .models import Finding


RISK_TO_SEVERITY = {
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "info",
    "info": "info",
}


@dataclass(frozen=True)
class ZAPRunResult:
    exit_code: int
    command: str
    output_dir: Path
    findings: tuple[Finding, ...]
    stdout: str = ""
    stderr: str = ""


def run_zap_baseline(
    target_url: str,
    *,
    output_dir: Path,
    minutes: int = 1,
    dry_run: bool = False,
    timeout_seconds: int = 900,
) -> ZAPRunResult:
    command = zap_baseline_command(target_url, output_dir=str(output_dir), minutes=minutes)
    output_dir.mkdir(parents=True, exist_ok=True)
    if dry_run:
        return ZAPRunResult(exit_code=0, command=command, output_dir=output_dir, findings=())

    completed = subprocess.run(
        command,
        shell=True,
        text=True,
        capture_output=True,
        timeout=timeout_seconds,
        check=False,
    )
    json_path = output_dir / "zap-baseline.json"
    findings = tuple(findings_from_zap_json(json_path, target_url=target_url)) if json_path.exists() else ()
    return ZAPRunResult(
        exit_code=completed.returncode,
        command=command,
        output_dir=output_dir,
        findings=findings,
        stdout=completed.stdout,
        stderr=completed.stderr,
    )


def findings_from_zap_json(path: Path, *, target_url: str = "") -> list[Finding]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    findings: list[Finding] = []
    for alert in _iter_alerts(payload):
        risk = str(alert.get("riskdesc") or alert.get("risk") or "informational")
        severity = _severity_from_risk(risk)
        name = str(alert.get("name") or alert.get("alert") or "ZAP baseline finding")
        plugin_id = str(alert.get("pluginid") or alert.get("pluginId") or "unknown")
        uri = _first_uri(alert) or target_url
        evidence = str(alert.get("evidence") or alert.get("param") or uri)
        findings.append(
            Finding(
                rule_id=f"dast.zap.{plugin_id}",
                category="configuration",
                severity=severity,
                title=f"ZAP baseline: {name}",
                path=Path(uri or target_url or path),
                evidence=evidence,
                description=_plain_text(str(alert.get("desc") or alert.get("description") or "")),
                recommendation=_plain_text(str(alert.get("solution") or alert.get("recommendation") or "Review the ZAP alert and remediate the affected endpoint.")),
            )
        )
    return findings


def render_zap_findings_json(findings: list[Finding] | tuple[Finding, ...]) -> str:
    return json.dumps(
        [
            {
                "rule_id": finding.rule_id,
                "category": finding.category,
                "severity": finding.severity,
                "title": finding.title,
                "path": str(finding.path),
                "evidence": finding.evidence,
                "description": finding.description,
                "recommendation": finding.recommendation,
            }
            for finding in findings
        ],
        indent=2,
        ensure_ascii=False,
    )


def _iter_alerts(payload: object):
    if isinstance(payload, dict):
        alerts = payload.get("alerts")
        if isinstance(alerts, list):
            yield from (alert for alert in alerts if isinstance(alert, dict))
        site = payload.get("site")
        if isinstance(site, list):
            for site_item in site:
                if isinstance(site_item, dict):
                    site_alerts = site_item.get("alerts")
                    if isinstance(site_alerts, list):
                        yield from (alert for alert in site_alerts if isinstance(alert, dict))
    elif isinstance(payload, list):
        yield from (alert for alert in payload if isinstance(alert, dict))


def _severity_from_risk(risk: str) -> str:
    lowered = risk.lower().split()[0].strip("()")
    return RISK_TO_SEVERITY.get(lowered, "info")


def _first_uri(alert: dict[str, object]) -> str:
    instances = alert.get("instances")
    if isinstance(instances, list):
        for item in instances:
            if isinstance(item, dict) and item.get("uri"):
                return str(item["uri"])
    return str(alert.get("uri") or alert.get("url") or "")


def _plain_text(value: str) -> str:
    return value.replace("<p>", "").replace("</p>", "").replace("<br>", "\n").strip()
