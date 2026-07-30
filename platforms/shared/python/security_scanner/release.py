from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from pathlib import Path

from .evidence import render_evidence_checklist
from .models import ReportConfig, ScannerConfig, TargetConfig
from .scanner import SecurityScanner
from .sbom import render_cyclonedx
from .vex import render_cyclonedx_vex


def build_release_security_package(
    *,
    target: Path,
    output_dir: Path,
    project_name: str = "",
    language: str = "ko",
    enable_vuln_intel: bool = False,
) -> dict[str, object]:
    output_dir.mkdir(parents=True, exist_ok=True)
    target_config = TargetConfig(name=project_name or target.name or "project", path=target)
    scanner = SecurityScanner(
        ScannerConfig(
            targets=(target_config,),
            report=ReportConfig(format="json", min_severity="info", language=language),
            enable_osv=enable_vuln_intel,
            enable_vuln_intel=enable_vuln_intel,
        )
    )
    scan_result = scanner.scan()
    findings = list(scan_result.findings)

    files: list[Path] = []
    files.append(_write(output_dir / "koda-sbom.cdx.json", render_cyclonedx(scanner.components)))
    files.append(_write(output_dir / "koda-vex.cdx.json", render_cyclonedx_vex(findings)))
    files.append(_write(output_dir / "manual-evidence-checklist.md", render_evidence_checklist(project_name=project_name or target.name, language=language)))
    files.append(_write(output_dir / "scan-findings.json", _findings_json(findings, scan_result.source_analysis)))
    files.append(_write(output_dir / "README.md", _readme(project_name or target.name, language=language)))
    checksums = _checksums(files)
    files.append(_write(output_dir / "checksums.txt", checksums))
    manifest = {
        "project": project_name or target.name,
        "target": str(target),
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "files": [{"path": path.name, "sha256": _sha256(path)} for path in files],
        "finding_count": len(findings),
        "component_count": len(scanner.components),
        "warnings": scanner.warnings,
    }
    _write(output_dir / "release-security-manifest.json", json.dumps(manifest, indent=2, ensure_ascii=False))
    return manifest


def _write(path: Path, content: str) -> Path:
    path.write_text(content, encoding="utf-8")
    return path


def _findings_json(findings, source_analysis=None) -> str:
    analysis = _source_analysis_json(source_analysis)
    if isinstance(analysis, dict):
        all_findings = analysis.pop("all_findings", ())
        report_findings = analysis.pop("report_findings", ())
        analysis["all_finding_count"] = len(all_findings) if isinstance(all_findings, list) else 0
        analysis["report_finding_count"] = len(report_findings) if isinstance(report_findings, list) else 0
    payload = {
        "source_analysis": analysis,
        "findings": [
            {
                "rule_id": finding.rule_id,
                "category": finding.category,
                "severity": finding.severity,
                "title": finding.title,
                "path": str(finding.path),
                "line": finding.line,
                "evidence": finding.evidence,
                "description": finding.description,
                "recommendation": finding.recommendation,
                "verification_status": finding.verification_status,
                "verification_note": finding.verification_note,
                "analyzer": finding.analyzer,
                "analyzer_version": finding.analyzer_version,
                "analyzer_rule_id": finding.analyzer_rule_id,
                "cwe_ids": list(finding.cwe_ids),
                "evidence_kind": finding.evidence_kind,
                "trace": list(finding.trace),
                "evidence_id": finding.evidence_id,
                "issue_key": finding.issue_key,
            }
            for finding in findings
        ],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def _source_analysis_json(value):
    if value is None:
        return None
    if hasattr(value, "to_dict"):
        value = value.to_dict()
    elif is_dataclass(value):
        value = asdict(value)
    elif hasattr(value, "__dict__"):
        value = vars(value)
    if isinstance(value, dict):
        return {str(key): _source_analysis_json(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_source_analysis_json(item) for item in value]
    if hasattr(value, "value") and not isinstance(value, (str, int, float, bool)):
        return str(value.value)
    if isinstance(value, Path):
        return str(value)
    return value


def _readme(project_name: str, *, language: str) -> str:
    if language == "ko":
        return f"""# {project_name} 릴리스 보안 패키지

이 폴더는 KODA가 생성한 릴리스 보안 산출물입니다.

- `koda-sbom.cdx.json`: CycloneDX SBOM
- `koda-vex.cdx.json`: 검토 대기 상태의 CycloneDX VEX 초안
- `scan-findings.json`: 로컬 보안 점검 결과
- `manual-evidence-checklist.md`: 증적 확인 필요 기준을 위한 수동 증적 체크리스트
- `checksums.txt`: 산출물 SHA-256 체크섬
- `release-security-manifest.json`: 패키지 메타데이터
"""
    return f"""# {project_name} Release Security Package

This folder contains release security artifacts generated by KODA.

- `koda-sbom.cdx.json`: CycloneDX SBOM
- `koda-vex.cdx.json`: in-triage CycloneDX VEX draft
- `scan-findings.json`: local security scan findings
- `manual-evidence-checklist.md`: manual evidence checklist for standards that require evidence review
- `checksums.txt`: SHA-256 checksums
- `release-security-manifest.json`: package metadata
"""


def _checksums(files: list[Path]) -> str:
    return "\n".join(f"{_sha256(path)}  {path.name}" for path in files) + "\n"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
