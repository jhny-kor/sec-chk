from __future__ import annotations

import json
import html
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

from . import __version__
from .models import Finding, SEVERITIES, SEVERITY_RANK


SEVERITY_WEIGHTS = {
    "critical": 100,
    "high": 40,
    "medium": 10,
    "low": 3,
    "info": 1,
}

SEVERITY_SECURITY_SCORES = {
    "critical": "9.5",
    "high": "8.0",
    "medium": "5.0",
    "low": "2.0",
    "info": "0.0",
}

TRANSLATIONS = {
    "en": {
        "html_lang": "en",
        "title": "Local Security Dashboard",
        "generated": "Generated",
        "risk_score": "Risk score",
        "targets": "Targets",
        "findings": "Findings",
        "filters": "Filters",
        "search_placeholder": "Search title, rule, path, evidence",
        "reset": "Reset",
        "project_risk": "Project Risk",
        "severity_distribution": "Severity Distribution",
        "severity": "Severity",
        "finding": "Finding",
        "target": "Target",
        "location": "Location",
        "evidence": "Evidence",
        "action": "Action",
        "no_findings_display": "No findings to display.",
        "no_findings_filter": "No findings match the current filters.",
        "no_targets_recorded": "No targets recorded.",
        "all_severities": "All severities",
        "all_categories": "All categories",
        "all_targets": "All targets",
        "risk_score_metric": "Risk Score",
        "risk_score_sub": "weighted local score",
        "critical_sub": "immediate review",
        "high_sub": "near-term fix",
        "medium_sub": "planned remediation",
        "low_info_metric": "Low + Info",
        "low_info_sub": "hygiene backlog",
        "blocking": "Blocking",
        "blocking_sub": "critical or high",
        "remediate": "Remediate",
        "review_this_finding": "Review this finding.",
        "finding_singular": "finding",
        "finding_plural": "findings",
        "unknown": "unknown",
        "report_heading": "Local Security Scan Report",
        "summary": "Summary",
        "total_findings": "Total findings",
        "scanned_targets": "Scanned targets",
        "no_threshold_findings": "No findings matched the selected severity threshold.",
        "rule": "Rule",
        "category": "Category",
        "why_it_matters": "Why it matters",
        "recommendation": "Recommendation",
        "severity_labels": {
            "critical": "Critical",
            "high": "High",
            "medium": "Medium",
            "low": "Low",
            "info": "Info",
        },
    },
    "ko": {
        "html_lang": "ko",
        "title": "로컬 보안 대시보드",
        "generated": "생성 시각",
        "risk_score": "위험 점수",
        "targets": "점검 대상",
        "findings": "발견 항목",
        "filters": "필터",
        "search_placeholder": "제목, 규칙, 경로, 근거 검색",
        "reset": "초기화",
        "project_risk": "프로젝트 위험도",
        "severity_distribution": "심각도 분포",
        "severity": "심각도",
        "finding": "발견 항목",
        "target": "대상",
        "location": "위치",
        "evidence": "근거",
        "action": "조치",
        "no_findings_display": "표시할 발견 항목이 없습니다.",
        "no_findings_filter": "현재 필터와 일치하는 발견 항목이 없습니다.",
        "no_targets_recorded": "기록된 대상이 없습니다.",
        "all_severities": "모든 심각도",
        "all_categories": "모든 종류",
        "all_targets": "모든 대상",
        "risk_score_metric": "위험 점수",
        "risk_score_sub": "가중 로컬 점수",
        "critical_sub": "즉시 검토",
        "high_sub": "빠른 수정 필요",
        "medium_sub": "계획된 조치",
        "low_info_metric": "낮음 + 정보",
        "low_info_sub": "보안 위생 백로그",
        "blocking": "차단 항목",
        "blocking_sub": "치명 또는 높음",
        "remediate": "조치 보기",
        "review_this_finding": "이 발견 항목을 검토하세요.",
        "finding_singular": "건",
        "finding_plural": "건",
        "unknown": "알 수 없음",
        "report_heading": "로컬 보안 점검 리포트",
        "summary": "요약",
        "total_findings": "전체 발견 항목",
        "scanned_targets": "점검 대상",
        "no_threshold_findings": "선택한 심각도 기준에 해당하는 발견 항목이 없습니다.",
        "rule": "규칙",
        "category": "종류",
        "why_it_matters": "중요한 이유",
        "recommendation": "권장 조치",
        "severity_labels": {
            "critical": "치명",
            "high": "높음",
            "medium": "중간",
            "low": "낮음",
            "info": "정보",
        },
    },
}

RULE_TRANSLATIONS_KO = {
    "secret.private-key": {
        "title": "개인 키 자료",
        "description": "개인 키로 보이는 값이 로컬 프로젝트 파일에 포함되어 있습니다.",
        "recommendation": "개인 키를 보안 저장소로 옮기고 실제로 사용된 키라면 즉시 교체하세요.",
    },
    "secret.aws-access-key": {
        "title": "AWS 액세스 키 ID",
        "description": "AWS 액세스 키로 보이는 값이 로컬 프로젝트 파일에 포함되어 있습니다.",
        "recommendation": "키를 환경 변수나 보안 저장소로 옮기고 실제 키라면 회전하세요.",
    },
    "secret.github-token": {
        "title": "GitHub 토큰",
        "description": "GitHub 토큰으로 보이는 값이 로컬 프로젝트 파일에 포함되어 있습니다.",
        "recommendation": "토큰을 폐기하거나 회전하고, 앞으로는 보안 저장소에서 주입하세요.",
    },
    "secret.openai-key": {
        "title": "OpenAI API 키",
        "description": "OpenAI API 키로 보이는 값이 로컬 프로젝트 파일에 포함되어 있습니다.",
        "recommendation": "키를 보안 저장소로 옮기고 실제 키라면 회전하세요.",
    },
    "secret.slack-token": {
        "title": "Slack 토큰",
        "description": "Slack 토큰으로 보이는 값이 로컬 프로젝트 파일에 포함되어 있습니다.",
        "recommendation": "토큰을 회전하고 환경 변수나 보안 저장소에서만 주입하세요.",
    },
    "secret.generic-assignment": {
        "title": "하드코딩된 비밀값 의심 대입",
        "description": "비밀값처럼 보이는 값이 로컬 프로젝트 파일에 직접 대입되어 있습니다.",
        "recommendation": "비밀값을 환경 변수나 로컬 보안 저장소로 옮기고 실제 값이면 회전하세요.",
    },
    "dependency.package-json-invalid": {
        "title": "잘못된 package.json",
        "description": "잘못된 의존성 매니페스트는 의존성 검토와 재현 가능한 설치를 방해할 수 있습니다.",
        "recommendation": "의존성 도구가 안정적으로 검사할 수 있도록 package.json 문법을 수정하세요.",
    },
    "dependency.node-missing-lockfile": {
        "title": "Node 프로젝트에 lockfile이 없음",
        "description": "lockfile이 없으면 설치 결과가 재현되지 않아 공급망 변경 위험이 커집니다.",
        "recommendation": "프로젝트에서 사용하는 패키지 매니저의 lockfile을 커밋하세요.",
    },
    "dependency.node-unbounded-version": {
        "title": "범위가 제한되지 않은 Node 의존성 버전",
        "description": "제한 없는 의존성 버전은 설치 시 예상하지 못한 코드를 가져올 수 있습니다.",
        "recommendation": "검토한 semver 범위로 제한하고 lockfile을 최신으로 유지하세요.",
    },
    "dependency.node-insecure-url": {
        "title": "HTTP로 가져오는 의존성",
        "description": "HTTP 의존성 소스는 전송 중 변조될 수 있습니다.",
        "recommendation": "HTTPS 또는 신뢰할 수 있는 패키지 레지스트리 소스를 사용하세요.",
    },
    "dependency.remote-shell-script": {
        "title": "원격 콘텐츠를 셸로 실행하는 패키지 스크립트",
        "description": "패키지 스크립트에서 원격 콘텐츠를 바로 실행하면 감사하기 어렵고 내용이 바뀔 수 있습니다.",
        "recommendation": "설치 스크립트를 vendoring하거나 체크섬을 검증하는 명시적 단계로 바꾸세요.",
    },
    "dependency.python-insecure-url": {
        "title": "HTTP로 가져오는 Python 의존성",
        "description": "HTTP 의존성 소스는 전송 중 변조될 수 있습니다.",
        "recommendation": "HTTPS 또는 신뢰할 수 있는 패키지 인덱스를 사용하세요.",
    },
    "dependency.python-unpinned-requirement": {
        "title": "고정되지 않은 Python 의존성",
        "description": "고정되지 않은 requirements는 설치 시점마다 달라질 수 있어 의존성 검토가 어려워집니다.",
        "recommendation": "배포 requirements에는 버전을 고정하거나 생성된 lockfile을 사용하세요.",
    },
    "dependency.python-wildcard-version": {
        "title": "와일드카드 Python 의존성 버전",
        "description": "와일드카드 버전은 설치 시 예상하지 못한 코드를 가져올 수 있습니다.",
        "recommendation": "검토한 버전 범위나 lockfile을 사용하세요.",
    },
    "dependency.docker-unpinned-base": {
        "title": "Docker 베이스 이미지가 고정되지 않음",
        "description": "떠 있는 베이스 이미지 태그는 검토 없이 바뀔 수 있습니다.",
        "recommendation": "검토한 태그 또는 digest로 고정하세요.",
    },
    "dependency.docker-remote-shell": {
        "title": "Docker 빌드에서 원격 콘텐츠를 셸로 실행",
        "description": "빌드 중 원격 콘텐츠를 바로 실행하면 감사하기 어렵고 내용이 바뀔 수 있습니다.",
        "recommendation": "아티팩트를 내려받은 뒤 서명이나 체크섬을 검증하고 실행하세요.",
    },
    "config.env-file-present": {
        "title": "환경 파일이 프로젝트 트리에 있음",
        "description": "로컬 환경 파일에는 자격 증명이나 운영 설정이 들어 있는 경우가 많습니다.",
        "recommendation": "실제 환경 파일은 저장소 밖에 두고, 커밋할 때는 정리된 예제 파일만 포함하세요.",
    },
    "config.private-key-like-file": {
        "title": "개인 키로 보이는 파일",
        "description": "테스트 전용이 아니라면 개인 키 자료는 프로젝트 폴더 안에 두지 않아야 합니다.",
        "recommendation": "개인 키를 보안 저장소로 옮기고 실제로 사용된 키라면 회전하세요.",
    },
    "config.debug-enabled": {
        "title": "디버그 모드가 활성화된 것으로 보임",
        "description": "디버그 모드는 배포 환경에서 내부 정보, 스택 트레이스, 위험한 엔드포인트를 노출할 수 있습니다.",
        "recommendation": "공유, 스테이징, 운영 설정에서는 디버그 모드를 비활성화하세요.",
    },
    "config.development-environment": {
        "title": "개발 환경 플래그가 있음",
        "description": "개발 환경 설정이 배포에 재사용되면 런타임 보안 가정이 약해질 수 있습니다.",
        "recommendation": "로컬 개발 설정과 배포 설정을 분리하세요.",
    },
    "config.docker-root-user": {
        "title": "Docker 이미지가 root로 실행되도록 설정됨",
        "description": "root 컨테이너는 프로세스 침해 시 영향 범위를 키웁니다.",
        "recommendation": "root가 꼭 필요하지 않다면 최소 권한 사용자로 실행하세요.",
    },
    "config.docker-add-http": {
        "title": "Dockerfile ADD가 HTTP를 사용함",
        "description": "HTTP 다운로드는 이미지 빌드 중 전송 경로에서 변조될 수 있습니다.",
        "recommendation": "HTTPS를 사용하고 아티팩트 체크섬을 검증하세요.",
    },
    "config.docker-no-user": {
        "title": "Dockerfile에 비root USER가 없음",
        "description": "USER 지시어가 없는 이미지는 보통 root로 실행됩니다.",
        "recommendation": "가능하면 런타임 단계에 비root USER를 추가하세요.",
    },
    "config.compose-privileged": {
        "title": "Compose 서비스가 privileged 모드를 사용함",
        "description": "privileged 컨테이너는 호스트에 대한 광범위한 접근 권한을 가집니다.",
        "recommendation": "privileged 모드를 제거하고 필요한 capability만 명시적으로 부여하세요.",
    },
    "config.compose-host-network": {
        "title": "Compose 서비스가 host 네트워크를 사용함",
        "description": "host 네트워크는 격리를 약화시키고 로컬 서비스를 노출할 수 있습니다.",
        "recommendation": "host 네트워크가 꼭 필요하지 않다면 명시적 포트 매핑을 사용하세요.",
    },
    "config.compose-docker-sock": {
        "title": "Compose 서비스가 Docker 소켓을 마운트함",
        "description": "Docker 소켓 접근은 사실상 호스트 수준 제어 권한에 가깝습니다.",
        "recommendation": "Docker 소켓 마운트를 피하거나 목적별 프록시 뒤로 격리하세요.",
    },
}


def filter_by_min_severity(findings: list[Finding], min_severity: str) -> list[Finding]:
    threshold = SEVERITY_RANK[min_severity]
    return [finding for finding in findings if SEVERITY_RANK[finding.severity] >= threshold]


def render_report(
    findings: list[Finding],
    report_format: str,
    target_names: tuple[str, ...] = (),
    language: str = "en",
    *,
    target_paths: dict[str, str] | None = None,
) -> str:
    if report_format == "json":
        return render_json(findings, target_names, language, target_paths=target_paths)
    if report_format == "markdown":
        return render_markdown(findings, target_names, language, target_paths=target_paths)
    if report_format == "html":
        return render_html(findings, target_names, language, target_paths=target_paths)
    if report_format == "sarif":
        return render_sarif(findings)
    raise ValueError(f"Unsupported report format: {report_format}")


def render_json(
    findings: list[Finding],
    target_names: tuple[str, ...] = (),
    language: str = "en",
    *,
    target_paths: dict[str, str] | None = None,
) -> str:
    payload = {
        "generated_at": _generated_at()[0],
        "language": _labels(language)["html_lang"],
        "scanner": {"name": "local-security-scanner", "version": __version__},
        "summary": _summary(findings, target_names, target_paths),
        "findings": [_finding_payload(finding) for finding in findings],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def render_markdown(
    findings: list[Finding],
    target_names: tuple[str, ...] = (),
    language: str = "en",
    *,
    target_paths: dict[str, str] | None = None,
) -> str:
    labels = _labels(language)
    generated_at, generated_display = _generated_at()
    summary = _summary(findings, target_names, target_paths)
    lines = [
        f"# {labels['report_heading']}",
        "",
        f"{labels['generated']}: {generated_display}",
        "",
        f"## {labels['summary']}",
        "",
        f"- {labels['total_findings']}: {len(findings)}",
        f"- {labels['scanned_targets']}: {summary['target_count']}",
        f"- {labels['risk_score']}: {summary['risk_score']}",
    ]
    for severity in reversed(SEVERITIES):
        count = summary["by_severity"].get(severity, 0)
        if count:
            lines.append(f"- {labels['severity_labels'][severity]}: {count}")
    for category, count in sorted(summary["by_category"].items()):
        lines.append(f"- {category}: {count}")
    for target, count in sorted(summary["by_target"].items()):
        if target:
            lines.append(f"- {labels['target']} `{_target_display(target, summary)}`: {count}")

    if not findings:
        lines.extend(["", str(labels["no_threshold_findings"])])
        return "\n".join(lines) + "\n"

    grouped: dict[str, list[Finding]] = defaultdict(list)
    for finding in findings:
        grouped[finding.severity].append(finding)

    for severity in reversed(SEVERITIES):
        severity_findings = grouped.get(severity, [])
        if not severity_findings:
            continue
        lines.extend(["", f"## {labels['severity_labels'][severity]} {labels['findings']}", ""])
        for finding in severity_findings:
            location = str(finding.path)
            if finding.line:
                location = f"{location}:{finding.line}"
            display = _localized_finding_payload(finding, language)
            lines.extend(
                [
                    f"### {display['title']}",
                    "",
                    f"- {labels['rule']}: `{finding.rule_id}`",
                    f"- {labels['category']}: `{finding.category}`",
                    f"- {labels['target']}: `{_target_display(finding.target, summary)}`",
                    f"- {labels['location']}: `{location}`",
                ]
            )
            if finding.evidence:
                lines.append(f"- {labels['evidence']}: `{finding.evidence}`")
            if display["description"]:
                lines.append(f"- {labels['why_it_matters']}: {display['description']}")
            if display["recommendation"]:
                lines.append(f"- {labels['recommendation']}: {display['recommendation']}")
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_sarif(findings: list[Finding]) -> str:
    rules_by_id: dict[str, Finding] = {}
    for finding in findings:
        rules_by_id.setdefault(finding.rule_id, finding)

    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "local-security-scanner",
                        "semanticVersion": __version__,
                        "rules": [_sarif_rule(finding) for finding in rules_by_id.values()],
                    }
                },
                "results": [_sarif_result(finding) for finding in findings],
            }
        ],
    }
    return json.dumps(payload, indent=2, ensure_ascii=False)


def render_html(
    findings: list[Finding],
    target_names: tuple[str, ...] = (),
    language: str = "en",
    *,
    target_paths: dict[str, str] | None = None,
) -> str:
    generated, generated_display = _generated_at()
    summary = _summary(findings, target_names, target_paths)
    labels = _labels(language)
    payload = {
        "generated_at": generated,
        "generated_display": generated_display,
        "language": labels["html_lang"],
        "labels_by_language": TRANSLATIONS,
        "scanner": {"name": "local-security-scanner", "version": __version__},
        "summary": summary,
        "findings_by_language": {
            "en": [_finding_payload(finding) for finding in findings],
            "ko": [_localized_finding_payload(finding, "ko") for finding in findings],
        },
    }
    json_payload = json.dumps(payload, ensure_ascii=False).replace("</", "<\\/")
    replacements = {
        "__DATA__": json_payload,
        "__INITIAL_LANG__": html.escape(str(labels["html_lang"]), quote=True),
        "__INITIAL_TITLE__": html.escape(str(labels["title"]), quote=True),
        "__INITIAL_FILTERS__": html.escape(str(labels["filters"]), quote=True),
        "__INITIAL_SEARCH_PLACEHOLDER__": html.escape(str(labels["search_placeholder"]), quote=True),
        "__INITIAL_RESET__": html.escape(str(labels["reset"])),
        "__INITIAL_PROJECT_RISK__": html.escape(str(labels["project_risk"])),
        "__INITIAL_SEVERITY_DISTRIBUTION__": html.escape(str(labels["severity_distribution"])),
        "__INITIAL_SEVERITY__": html.escape(str(labels["severity"])),
        "__INITIAL_FINDING__": html.escape(str(labels["finding"])),
        "__INITIAL_TARGET__": html.escape(str(labels["target"])),
        "__INITIAL_LOCATION__": html.escape(str(labels["location"])),
        "__INITIAL_EVIDENCE__": html.escape(str(labels["evidence"])),
        "__INITIAL_ACTION__": html.escape(str(labels["action"])),
        "__INITIAL_EMPTY__": html.escape(str(labels["no_findings_display"])),
    }
    content = HTML_TEMPLATE
    for placeholder, value in replacements.items():
        content = content.replace(placeholder, value)
    return content


def write_report(content: str, output: Path | None) -> None:
    if output is None:
        print(content, end="")
        return
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(content, encoding="utf-8")


def _finding_payload(finding: Finding) -> dict[str, object]:
    return {
        "rule_id": finding.rule_id,
        "category": finding.category,
        "severity": finding.severity,
        "title": finding.title,
        "target": finding.target,
        "path": str(finding.path),
        "line": finding.line,
        "evidence": finding.evidence,
        "description": finding.description,
        "recommendation": finding.recommendation,
    }


def _localized_finding_payload(finding: Finding, language: str) -> dict[str, object]:
    payload = _finding_payload(finding)
    if language != "ko":
        return payload

    translated = RULE_TRANSLATIONS_KO.get(finding.rule_id)
    if not translated:
        return payload

    payload.update(translated)
    return payload


def _summary(
    findings: list[Finding],
    target_names: tuple[str, ...] = (),
    target_paths: dict[str, str] | None = None,
) -> dict[str, object]:
    by_target = Counter({target: 0 for target in target_names})
    by_target.update(finding.target for finding in findings)
    by_severity = Counter(finding.severity for finding in findings)
    risk_score = sum(by_severity[severity] * SEVERITY_WEIGHTS[severity] for severity in SEVERITIES)
    resolved_target_paths = dict(target_paths or {})
    return {
        "target_count": len(target_names) if target_names else len({finding.target for finding in findings if finding.target}),
        "risk_score": risk_score,
        "by_severity": dict(by_severity),
        "by_category": dict(Counter(finding.category for finding in findings)),
        "by_target": dict(by_target),
        "target_paths": resolved_target_paths,
    }


def _labels(language: str) -> dict[str, object]:
    return TRANSLATIONS.get(language, TRANSLATIONS["en"])


def _target_display(target: str, summary: dict[str, object]) -> str:
    if not target:
        return ""
    target_paths = summary.get("target_paths", {})
    if isinstance(target_paths, dict):
        return str(target_paths.get(target, target))
    return target


def _generated_at() -> tuple[str, str]:
    generated = datetime.now().astimezone()
    return generated.isoformat(timespec="seconds"), generated.strftime("%Y-%m-%d %H:%M:%S")


def _sarif_rule(finding: Finding) -> dict[str, object]:
    return {
        "id": finding.rule_id,
        "name": finding.title,
        "shortDescription": {"text": finding.title},
        "fullDescription": {"text": finding.description or finding.title},
        "help": {"text": finding.recommendation or "Review this finding."},
        "properties": {
            "category": finding.category,
            "severity": finding.severity,
            "security-severity": SEVERITY_SECURITY_SCORES[finding.severity],
        },
    }


def _sarif_result(finding: Finding) -> dict[str, object]:
    region = {"startLine": finding.line or 1}
    return {
        "ruleId": finding.rule_id,
        "level": _sarif_level(finding.severity),
        "message": {"text": _sarif_message(finding)},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": str(finding.path)},
                    "region": region,
                }
            }
        ],
        "properties": {
            "category": finding.category,
            "severity": finding.severity,
            "target": finding.target,
            "evidence": finding.evidence,
        },
    }


def _sarif_level(severity: str) -> str:
    if severity in {"critical", "high"}:
        return "error"
    if severity in {"medium", "low"}:
        return "warning"
    return "note"


def _sarif_message(finding: Finding) -> str:
    parts = [finding.title]
    if finding.evidence:
        parts.append(f"Evidence: {finding.evidence}")
    if finding.recommendation:
        parts.append(f"Recommendation: {finding.recommendation}")
    return " | ".join(parts)


HTML_TEMPLATE = """<!doctype html>
<html lang="__INITIAL_LANG__">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="icon" href="data:,">
  <title>__INITIAL_TITLE__</title>
  <style>
    :root {
      --bg: #f6f7f9;
      --panel: #ffffff;
      --ink: #14171f;
      --muted: #667085;
      --line: #d9dee8;
      --critical: #7f1d1d;
      --high: #c2410c;
      --medium: #b7791f;
      --low: #2563eb;
      --info: #64748b;
      --ok: #0f766e;
      --focus: #3157d5;
    }

    * { box-sizing: border-box; }
    body {
      margin: 0;
      background: var(--bg);
      color: var(--ink);
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      font-size: 14px;
      line-height: 1.45;
    }

    header {
      background: #111827;
      color: #fff;
      border-bottom: 1px solid #0b1220;
    }

    .shell {
      width: min(1440px, calc(100vw - 32px));
      margin: 0 auto;
    }

    .topbar {
      position: relative;
      min-height: 76px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 24px;
    }

    h1 {
      margin: 0;
      font-size: 24px;
      font-weight: 700;
      letter-spacing: 0;
    }

    .meta {
      color: #cbd5e1;
      font-size: 13px;
      text-align: right;
      white-space: nowrap;
    }

    .header-side {
      display: flex;
      align-items: flex-start;
      gap: 14px;
    }

    .language-toggle {
      display: inline-flex;
      overflow: hidden;
      border: 1px solid rgba(203, 213, 225, 0.42);
      border-radius: 999px;
      background: rgba(15, 23, 42, 0.7);
      flex: 0 0 auto;
    }

    .language-toggle button {
      width: 42px;
      min-width: 42px;
      min-height: 30px;
      padding: 5px 9px;
      border: 0;
      border-radius: 0;
      background: transparent;
      color: #cbd5e1;
      font-size: 12px;
      font-weight: 800;
    }

    .language-toggle button.active {
      background: #ffffff;
      color: #111827;
    }

    main {
      padding: 24px 0 36px;
    }

    .metrics {
      display: grid;
      grid-template-columns: repeat(6, minmax(0, 1fr));
      gap: 12px;
      margin-bottom: 16px;
    }

    .metric, .panel {
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: 0 1px 2px rgba(15, 23, 42, 0.04);
    }

    .metric {
      padding: 14px;
      min-height: 96px;
    }

    .metric-label {
      color: var(--muted);
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0;
    }

    .metric-value {
      margin-top: 8px;
      font-size: 30px;
      line-height: 1;
      font-weight: 760;
    }

    .metric-sub {
      margin-top: 8px;
      color: var(--muted);
      font-size: 12px;
    }

    .critical { color: var(--critical); }
    .high { color: var(--high); }
    .medium { color: var(--medium); }
    .low { color: var(--low); }
    .info { color: var(--info); }
    .ok { color: var(--ok); }

    .filters {
      display: grid;
      grid-template-columns: minmax(220px, 2fr) repeat(3, minmax(140px, 1fr)) auto;
      gap: 10px;
      padding: 12px;
      margin-bottom: 16px;
      align-items: center;
    }

    input, select, button {
      width: 100%;
      min-height: 38px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: #fff;
      color: var(--ink);
      font: inherit;
      padding: 8px 10px;
    }

    button {
      width: auto;
      min-width: 88px;
      background: #111827;
      color: #fff;
      border-color: #111827;
      font-weight: 700;
      cursor: pointer;
    }

    input:focus, select:focus, button:focus {
      outline: 2px solid var(--focus);
      outline-offset: 1px;
    }

    .grid {
      display: grid;
      grid-template-columns: minmax(320px, 0.9fr) minmax(0, 1.4fr);
      gap: 16px;
      margin-bottom: 16px;
    }

    .panel {
      padding: 16px;
      min-width: 0;
    }

    .panel h2 {
      margin: 0 0 12px;
      font-size: 15px;
      line-height: 1.2;
    }

    .bars {
      display: grid;
      gap: 11px;
    }

    .bar-row {
      display: grid;
      grid-template-columns: 78px 1fr 40px;
      gap: 10px;
      align-items: center;
    }

    .bar-label {
      color: var(--muted);
      font-weight: 700;
      text-transform: capitalize;
    }

    .bar-track {
      height: 10px;
      border-radius: 999px;
      background: #eef2f7;
      overflow: hidden;
    }

    .bar-fill {
      height: 100%;
      min-width: 0;
      border-radius: inherit;
    }

    .project-list {
      display: grid;
      gap: 8px;
      max-height: 280px;
      overflow: auto;
      padding-right: 2px;
    }

    .project-row {
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      gap: 12px;
      align-items: center;
      padding: 10px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: #fbfcfe;
    }

    .project-name {
      overflow-wrap: anywhere;
      font-weight: 700;
    }

    .project-count {
      color: var(--muted);
      font-variant-numeric: tabular-nums;
    }

    .table-wrap {
      overflow: auto;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #fff;
    }

    table {
      width: 100%;
      border-collapse: collapse;
      min-width: 960px;
    }

    th, td {
      padding: 11px 12px;
      border-bottom: 1px solid var(--line);
      text-align: left;
      vertical-align: top;
    }

    th {
      position: sticky;
      top: 0;
      z-index: 1;
      background: #f8fafc;
      color: var(--muted);
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0;
    }

    tr:last-child td {
      border-bottom: 0;
    }

    .severity-pill {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-width: 72px;
      min-height: 24px;
      border-radius: 999px;
      padding: 2px 8px;
      color: #fff;
      font-size: 12px;
      font-weight: 800;
      text-transform: uppercase;
    }

    .pill-critical { background: var(--critical); }
    .pill-high { background: var(--high); }
    .pill-medium { background: var(--medium); color: #111827; }
    .pill-low { background: var(--low); }
    .pill-info { background: var(--info); }

    .location, .evidence {
      max-width: 380px;
      color: var(--muted);
      overflow-wrap: anywhere;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
      font-size: 12px;
    }

    details {
      max-width: 520px;
    }

    summary {
      cursor: pointer;
      font-weight: 700;
    }

    .detail-body {
      margin-top: 8px;
      color: var(--muted);
    }

    .empty {
      padding: 36px;
      text-align: center;
      color: var(--muted);
    }

    @media (max-width: 1000px) {
      .metrics { grid-template-columns: repeat(3, minmax(0, 1fr)); }
      .filters { grid-template-columns: 1fr 1fr; }
      .grid { grid-template-columns: 1fr; }
      button { width: 100%; }
    }

    @media (max-width: 640px) {
      .shell { width: min(100% - 20px, 1440px); }
      .topbar { align-items: flex-start; flex-direction: column; padding: 16px 0; gap: 8px; }
      .header-side { width: 100%; padding-top: 32px; }
      .language-toggle { position: absolute; top: 16px; right: 0; }
      .meta { text-align: left; white-space: normal; }
      .metrics, .filters { grid-template-columns: 1fr; }
      .metric { min-height: 84px; }
      .metric-value { font-size: 26px; }
    }
  </style>
</head>
<body>
  <header>
    <div class="shell topbar">
      <div>
        <h1 id="dashboard-title">__INITIAL_TITLE__</h1>
      </div>
      <div class="header-side">
        <div class="language-toggle" role="group" aria-label="Language">
          <button id="lang-ko" type="button">KO</button>
          <button id="lang-en" type="button">EN</button>
        </div>
        <div class="meta">
          <div id="generated-line"></div>
          <div id="summary-line"></div>
        </div>
      </div>
    </div>
  </header>

  <main class="shell">
    <section class="metrics" id="metrics"></section>

    <section class="panel filters" id="filters-panel" aria-label="__INITIAL_FILTERS__">
      <input id="search" type="search" placeholder="__INITIAL_SEARCH_PLACEHOLDER__">
      <select id="severity"></select>
      <select id="category"></select>
      <select id="target"></select>
      <button id="reset" type="button">__INITIAL_RESET__</button>
    </section>

    <section class="grid">
      <div class="panel">
        <h2 id="project-risk-title">__INITIAL_PROJECT_RISK__</h2>
        <div id="projects" class="project-list"></div>
      </div>
      <div class="panel">
        <h2 id="severity-distribution-title">__INITIAL_SEVERITY_DISTRIBUTION__</h2>
        <div id="bars" class="bars"></div>
      </div>
    </section>

    <section class="table-wrap">
      <table>
        <thead>
          <tr>
            <th id="th-severity">__INITIAL_SEVERITY__</th>
            <th id="th-finding">__INITIAL_FINDING__</th>
            <th id="th-target">__INITIAL_TARGET__</th>
            <th id="th-location">__INITIAL_LOCATION__</th>
            <th id="th-evidence">__INITIAL_EVIDENCE__</th>
            <th id="th-action">__INITIAL_ACTION__</th>
          </tr>
        </thead>
        <tbody id="findings"></tbody>
      </table>
      <div id="empty" class="empty" hidden>__INITIAL_EMPTY__</div>
    </section>
  </main>

  <script id="findings-data" type="application/json">__DATA__</script>
  <script>
    const payload = JSON.parse(document.getElementById("findings-data").textContent);
    const summary = payload.summary;
    const severityOrder = ["critical", "high", "medium", "low", "info"];
    const severityColors = { critical: "#7f1d1d", high: "#c2410c", medium: "#d69e2e", low: "#2563eb", info: "#64748b" };

    const state = {
      search: "",
      severity: "all",
      category: "all",
      target: "all",
      language: payload.language || "en",
    };

    function byId(id) {
      return document.getElementById(id);
    }

    function escapeText(value) {
      return String(value ?? "").replace(/[&<>"']/g, (char) => ({
        "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
      }[char]));
    }

    function countBy(items, key) {
      return items.reduce((acc, item) => {
        const value = item[key] || "unknown";
        acc[value] = (acc[value] || 0) + 1;
        return acc;
      }, {});
    }

    function riskScore(items) {
      const weights = { critical: 100, high: 40, medium: 10, low: 3, info: 1 };
      return items.reduce((total, item) => total + (weights[item.severity] || 0), 0);
    }

    function labels() {
      return payload.labels_by_language[state.language] || payload.labels_by_language.en;
    }

    function findings() {
      return payload.findings_by_language[state.language] || payload.findings_by_language.en || [];
    }

    function severityLabels() {
      return labels().severity_labels;
    }

    function targetDisplay(target) {
      return (summary.target_paths && summary.target_paths[target]) || target || labels().unknown;
    }

    function setText(id, value) {
      byId(id).textContent = value;
    }

    function renderChrome() {
      const activeLabels = labels();
      document.documentElement.lang = activeLabels.html_lang;
      document.title = activeLabels.title;
      setText("dashboard-title", activeLabels.title);
      setText("generated-line", `${activeLabels.generated} ${payload.generated_display}`);
      setText(
        "summary-line",
        `${activeLabels.risk_score} ${summary.risk_score} | ${activeLabels.targets} ${summary.target_count} | ${activeLabels.findings} ${findings().length}`
      );
      byId("filters-panel").setAttribute("aria-label", activeLabels.filters);
      byId("search").placeholder = activeLabels.search_placeholder;
      setText("reset", activeLabels.reset);
      setText("project-risk-title", activeLabels.project_risk);
      setText("severity-distribution-title", activeLabels.severity_distribution);
      setText("th-severity", activeLabels.severity);
      setText("th-finding", activeLabels.finding);
      setText("th-target", activeLabels.target);
      setText("th-location", activeLabels.location);
      setText("th-evidence", activeLabels.evidence);
      setText("th-action", activeLabels.action);
      byId("lang-ko").classList.toggle("active", state.language === "ko");
      byId("lang-en").classList.toggle("active", state.language === "en");
    }

    function metric(label, value, sub, colorClass = "") {
      return `
        <article class="metric">
          <div class="metric-label">${escapeText(label)}</div>
          <div class="metric-value ${colorClass}">${escapeText(value)}</div>
          <div class="metric-sub">${escapeText(sub)}</div>
        </article>
      `;
    }

    function renderMetrics(items) {
      const activeLabels = labels();
      const activeSeverityLabels = severityLabels();
      const counts = countBy(items, "severity");
      const blocked = (counts.critical || 0) + (counts.high || 0);
      byId("metrics").innerHTML = [
        metric(activeLabels.risk_score_metric, riskScore(items), activeLabels.risk_score_sub, riskScore(items) ? "high" : "ok"),
        metric(activeSeverityLabels.critical, counts.critical || 0, activeLabels.critical_sub, "critical"),
        metric(activeSeverityLabels.high, counts.high || 0, activeLabels.high_sub, "high"),
        metric(activeSeverityLabels.medium, counts.medium || 0, activeLabels.medium_sub, "medium"),
        metric(activeLabels.low_info_metric, (counts.low || 0) + (counts.info || 0), activeLabels.low_info_sub, "low"),
        metric(activeLabels.blocking, blocked, activeLabels.blocking_sub, blocked ? "high" : "ok"),
      ].join("");
    }

    function renderFilters() {
      const activeLabels = labels();
      const activeSeverityLabels = severityLabels();
      const items = findings();
      const categories = Array.from(new Set(items.map((item) => item.category))).sort();
      const targets = Object.keys(summary.by_target || {}).sort();
      fillSelect(byId("severity"), [["all", activeLabels.all_severities], ...severityOrder.map((sev) => [sev, activeSeverityLabels[sev]])], state.severity);
      fillSelect(byId("category"), [["all", activeLabels.all_categories], ...categories.map((cat) => [cat, cat])], state.category);
      fillSelect(byId("target"), [["all", activeLabels.all_targets], ...targets.map((target) => [target, targetDisplay(target)])], state.target);
    }

    function fillSelect(select, entries, selected) {
      select.innerHTML = entries.map(([value, label]) => `<option value="${escapeText(value)}">${escapeText(label)}</option>`).join("");
      select.value = selected;
    }

    function filteredFindings() {
      const query = state.search.trim().toLowerCase();
      return findings().filter((finding) => {
        if (state.severity !== "all" && finding.severity !== state.severity) return false;
        if (state.category !== "all" && finding.category !== state.category) return false;
        if (state.target !== "all" && finding.target !== state.target) return false;
        if (!query) return true;
        return [finding.title, finding.rule_id, finding.path, targetDisplay(finding.target), finding.evidence, finding.recommendation]
          .join(" ")
          .toLowerCase()
          .includes(query);
      });
    }

    function renderBars(items) {
      const activeSeverityLabels = severityLabels();
      const counts = countBy(items, "severity");
      const max = Math.max(1, ...Object.values(counts));
      byId("bars").innerHTML = severityOrder.map((severity) => {
        const count = counts[severity] || 0;
        const width = `${Math.round((count / max) * 100)}%`;
        return `
          <div class="bar-row">
            <div class="bar-label">${activeSeverityLabels[severity]}</div>
            <div class="bar-track"><div class="bar-fill" style="width: ${width}; background: ${severityColors[severity]}"></div></div>
            <div>${count}</div>
          </div>
        `;
      }).join("");
    }

    function renderProjects(items) {
      const activeLabels = labels();
      const counts = { ...(summary.by_target || {}) };
      for (const finding of items) {
        counts[finding.target] = (counts[finding.target] || 0);
      }
      const rows = Object.entries(counts)
        .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
      byId("projects").innerHTML = rows.length
        ? rows.map(([name, count]) => `
            <div class="project-row">
              <div class="project-name">${escapeText(targetDisplay(name))}</div>
              <div class="project-count">${count} ${count === 1 ? activeLabels.finding_singular : activeLabels.finding_plural}</div>
            </div>
          `).join("")
        : `<div class="empty">${escapeText(activeLabels.no_targets_recorded)}</div>`;
    }

    function renderTable(items) {
      const activeLabels = labels();
      const activeSeverityLabels = severityLabels();
      const body = byId("findings");
      const empty = byId("empty");
      body.innerHTML = items.map((finding) => {
        const location = `${finding.path}${finding.line ? `:${finding.line}` : ""}`;
        return `
          <tr>
            <td><span class="severity-pill pill-${escapeText(finding.severity)}">${escapeText(activeSeverityLabels[finding.severity] || finding.severity)}</span></td>
            <td>
              <strong>${escapeText(finding.title)}</strong><br>
              <span class="location">${escapeText(finding.rule_id)} | ${escapeText(finding.category)}</span>
            </td>
            <td>${escapeText(targetDisplay(finding.target))}</td>
            <td class="location">${escapeText(location)}</td>
            <td class="evidence">${escapeText(finding.evidence || "")}</td>
            <td>
              <details>
                <summary>${escapeText(activeLabels.remediate)}</summary>
                <div class="detail-body">
                  ${escapeText(finding.description || "")}
                  <br><br>
                  ${escapeText(finding.recommendation || activeLabels.review_this_finding)}
                </div>
              </details>
            </td>
          </tr>
        `;
      }).join("");
      empty.textContent = findings().length === 0 ? activeLabels.no_findings_display : activeLabels.no_findings_filter;
      empty.hidden = items.length > 0;
    }

    function render() {
      renderChrome();
      renderFilters();
      const items = filteredFindings();
      renderMetrics(items);
      renderBars(items);
      renderProjects(items);
      renderTable(items);
    }

    byId("search").addEventListener("input", (event) => {
      state.search = event.target.value;
      render();
    });
    byId("severity").addEventListener("change", (event) => {
      state.severity = event.target.value;
      render();
    });
    byId("category").addEventListener("change", (event) => {
      state.category = event.target.value;
      render();
    });
    byId("target").addEventListener("change", (event) => {
      state.target = event.target.value;
      render();
    });
    byId("reset").addEventListener("click", () => {
      state.search = "";
      state.severity = "all";
      state.category = "all";
      state.target = "all";
      byId("search").value = "";
      byId("severity").value = "all";
      byId("category").value = "all";
      byId("target").value = "all";
      render();
    });
    byId("lang-ko").addEventListener("click", () => {
      state.language = "ko";
      render();
    });
    byId("lang-en").addEventListener("click", () => {
      state.language = "en";
      render();
    });

    render();
  </script>
</body>
</html>
"""
