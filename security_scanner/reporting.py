from __future__ import annotations

import json
import html
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

from . import __version__
from .dependency_inventory import component_payload
from .models import DependencyComponent, Finding, SEVERITIES, SEVERITY_RANK
from .sbom import cyclonedx_payload, render_cyclonedx
from .standards import DEFAULT_STANDARD, DEFAULT_STANDARD_CATEGORY, rule_standard_mappings_payload, standards_payload
from .vex import render_cyclonedx_vex


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
        "help": "Help",
        "dashboard": "Dashboard",
        "help_title": "Security Standards Help",
        "help_intro": "Review each selectable standard, what SecChk checks locally, and links to the official source.",
        "coverage_matrix": "Coverage Matrix",
        "coverage": "Coverage",
        "official_links": "Official links",
        "check_categories": "Check criteria",
        "mapped_checks": "mapped checks",
        "auto_supported": "automatic",
        "automatic_coverage": "automatic checks",
        "external_required": "external integration required",
        "evidence_required": "evidence review required",
        "local_coverage": "automatic checks",
        "rule_details": "Rule Details",
        "related_standards": "Related standards",
        "no_related_standards": "No standard mapping recorded.",
        "dependency_components": "Components",
        "download_sbom": "Download SBOM",
        "sbom_unavailable": "No dependency components available for SBOM.",
        "osv_toggle": "OSV/CVE + KEV/EPSS lookup",
        "osv_network_note": "Queries exact dependency versions through OSV.dev and enriches CVEs with CISA KEV and FIRST EPSS priority data.",
        "supported": "supported",
        "not_supported": "not supported",
        "scan_directory": "Scan Directory",
        "scan_standard": "Security Standard",
        "scan_standard_category": "Standard Category",
        "scan_path_placeholder": "No folder selected",
        "choose_folder": "Choose Folder",
        "scan_now": "Scan",
        "discover_projects": "Discover projects",
        "discovery_depth": "Depth",
        "scan_status_idle": "Ready",
        "scan_status_running": "Scanning...",
        "scan_status_done": "Scan complete",
        "scan_status_failed": "Scan failed",
        "scan_category_not_supported": "not yet supported",
        "folder_selection_cancelled": "Folder selection cancelled.",
        "folder_selection_failed": "Folder selection failed",
        "folder_selected": "Folder selected",
        "server_required": "Run python3 -m security_scanner app and open the local dashboard.",
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
        "risk_score_formula": "Calculation: critical 100, high 40, medium 10, low 3, info 1 per finding.",
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
        "category_labels": {
            "secrets": "Secrets",
            "dependencies": "Dependencies",
            "configuration": "Configuration",
            "code": "Code Patterns",
            "prevention": "Prevention Guardrails",
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
        "help": "도움말",
        "dashboard": "대시보드",
        "help_title": "보안 점검 기준 도움말",
        "help_intro": "선택 가능한 보안 기준, 로컬 점검 범위, 공식 출처 링크를 확인합니다.",
        "coverage_matrix": "커버리지 매트릭스",
        "coverage": "점검 범위",
        "official_links": "공식 링크",
        "check_categories": "점검 기준",
        "mapped_checks": "매핑된 점검",
        "auto_supported": "자동",
        "automatic_coverage": "자동 점검",
        "external_required": "외부 연동 필요",
        "evidence_required": "증적 확인 필요",
        "local_coverage": "자동 점검",
        "rule_details": "룰 상세 도움말",
        "related_standards": "관련 보안 기준",
        "no_related_standards": "연결된 기준 매핑이 없습니다.",
        "dependency_components": "컴포넌트",
        "download_sbom": "SBOM 다운로드",
        "sbom_unavailable": "SBOM으로 내보낼 의존성 컴포넌트가 없습니다.",
        "osv_toggle": "OSV/CVE + KEV/EPSS 조회",
        "osv_network_note": "정확한 의존성 버전을 OSV.dev로 조회하고 CVE에 CISA KEV와 FIRST EPSS 우선순위 정보를 덧붙입니다.",
        "supported": "지원",
        "not_supported": "미지원",
        "scan_directory": "점검 경로",
        "scan_standard": "보안 기준",
        "scan_standard_category": "기준 카테고리",
        "scan_path_placeholder": "선택된 폴더 없음",
        "choose_folder": "폴더 선택",
        "scan_now": "점검 실행",
        "discover_projects": "하위 프로젝트 탐색",
        "discovery_depth": "깊이",
        "scan_status_idle": "대기 중",
        "scan_status_running": "점검 중...",
        "scan_status_done": "점검 완료",
        "scan_status_failed": "점검 실패",
        "scan_category_not_supported": "아직 미지원",
        "folder_selection_cancelled": "폴더 선택이 취소되었습니다.",
        "folder_selection_failed": "폴더 선택 실패",
        "folder_selected": "폴더 선택됨",
        "server_required": "python3 -m security_scanner app으로 로컬 대시보드를 열어주세요.",
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
        "risk_score_formula": "계산: 발견 항목마다 치명 100점, 높음 40점, 중간 10점, 낮음 3점, 정보 1점씩 합산합니다.",
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
        "category_labels": {
            "secrets": "비밀값",
            "dependencies": "의존성",
            "configuration": "설정",
            "code": "코드 패턴",
            "prevention": "예방 가드레일",
        },
    },
}

RULE_TRANSLATIONS_KO = {
    "prevention.security-policy-missing": {
        "title": "보안 정책 문서가 없음",
        "description": "취약점 신고, 지원 버전, 공개 절차를 설명하는 SECURITY.md가 없습니다.",
        "recommendation": "SECURITY.md에 신고 연락처, 지원 범위, 취약점 공개 기대사항을 작성하세요.",
    },
    "prevention.dependency-update-automation-missing": {
        "title": "의존성 업데이트 자동화가 없음",
        "description": "Dependabot 또는 Renovate 설정이 없어 취약·노후 의존성을 지속적으로 확인하기 어렵습니다.",
        "recommendation": "Dependabot 또는 Renovate를 추가해 의존성 업데이트와 취약점 알림을 자동화하세요.",
    },
    "prevention.ci-security-scan-missing": {
        "title": "CI 보안 점검 워크플로가 없음",
        "description": "CI에서 실행되는 보안 점검 워크플로가 확인되지 않았습니다.",
        "recommendation": "KODA/SecChk, CodeQL, Semgrep, OSV, Trivy, Gitleaks, ZAP baseline 같은 보안 점검을 CI에 추가하세요.",
    },
    "prevention.env-not-gitignored": {
        "title": ".env 파일이 gitignore로 제외되지 않음",
        "description": "환경 파일이 존재하지만 .gitignore에서 제외하는 패턴이 확인되지 않았습니다.",
        "recommendation": ".gitignore에 .env, .env.* 또는 동등한 제외 패턴을 추가하세요.",
    },
    "prevention.env-example-missing": {
        "title": "정제된 환경 예시 파일이 없음",
        "description": "실제 환경 파일은 있으나 안전하게 공유 가능한 .env.example 또는 .env.sample이 없습니다.",
        "recommendation": "실제 값은 저장소 밖에 두고, 필요한 키만 담은 .env.example 또는 .env.sample을 커밋하세요.",
    },
    "prevention.dockerignore-missing": {
        "title": ".dockerignore가 없음",
        "description": "Dockerfile이 있지만 Docker 빌드 컨텍스트에서 제외할 파일 목록이 없습니다.",
        "recommendation": ".dockerignore를 추가해 비밀값, VCS 메타데이터, 빌드 산출물, 로컬 파일이 이미지 빌드에 포함되지 않게 하세요.",
    },
    "prevention.sbom-missing": {
        "title": "SBOM 산출물이 없음",
        "description": "의존성 매니페스트는 있으나 로컬 SBOM 산출물이 확인되지 않았습니다.",
        "recommendation": "릴리스 또는 CI 단계에서 CycloneDX나 SPDX SBOM을 생성하고 보관하세요.",
    },
    "prevention.sast-workflow-missing": {
        "title": "SAST 워크플로가 없음",
        "description": "CodeQL, Semgrep 등 정적 분석 workflow가 확인되지 않았습니다.",
        "recommendation": "Pull request에서 코드 수준 보안 점검이 실행되도록 CodeQL 또는 Semgrep 같은 SAST workflow를 추가하세요.",
    },
    "prevention.openssf-scorecard-missing": {
        "title": "OpenSSF Scorecard 워크플로가 없음",
        "description": "공급망 보안 상태를 지속적으로 점검하는 OpenSSF Scorecard workflow가 확인되지 않았습니다.",
        "recommendation": "토큰 권한, 고정된 액션, SAST, 의존성 업데이트 자동화 상태를 추적하도록 OpenSSF Scorecard를 CI에 추가하세요.",
    },
    "prevention.github-token-permissions-not-readonly": {
        "title": "GitHub Actions 토큰 권한이 읽기 전용으로 제한되지 않음",
        "description": "workflow token의 기본 권한이 최소 권한으로 명시되어 있지 않습니다.",
        "recommendation": "workflow 최상단에 permissions: contents: read를 설정하고, 쓰기 권한은 필요한 job에만 별도로 부여하세요.",
    },
    "prevention.github-actions-unpinned": {
        "title": "GitHub Actions 참조가 느슨하게 고정됨",
        "description": "main, master, latest 같은 mutable branch/ref를 참조하는 GitHub Actions가 있습니다.",
        "recommendation": "외부 GitHub Actions는 검토한 버전 태그나 immutable commit SHA로 고정하세요.",
    },
    "prevention.slsa-sigstore-missing": {
        "title": "릴리스 서명 또는 출처 증명이 없음",
        "description": "SLSA provenance, Sigstore, cosign, attestation workflow가 확인되지 않았습니다.",
        "recommendation": "릴리스 산출물에 Sigstore/cosign 서명 또는 SLSA provenance 생성을 추가하세요.",
    },
    "prevention.zap-baseline-missing": {
        "title": "DAST baseline이 설정되지 않음",
        "description": "웹 프로젝트로 보이나 OWASP ZAP baseline workflow 또는 가이드가 확인되지 않았습니다.",
        "recommendation": "권한이 있는 staging URL에 대해 OWASP ZAP baseline 점검 또는 DAST 인수인계 절차를 추가하세요.",
    },
    "prevention.dependency-track-integration-missing": {
        "title": "Dependency-Track SBOM 업로드가 설정되지 않음",
        "description": "의존성 매니페스트는 있으나 Dependency-Track 같은 SBOM 분석 backend로 업로드하는 workflow가 없습니다.",
        "recommendation": "릴리스 SBOM을 Dependency-Track 또는 동등한 SBOM 분석 backend에 업로드하도록 자동화하세요.",
    },
    "prevention.vex-missing": {
        "title": "VEX 문서가 없음",
        "description": "의존성 취약점 검토 결과를 추적할 VEX 산출물이 확인되지 않았습니다.",
        "recommendation": "검토된 의존성 취약점에 대해 exploitable, fixed, not_affected 같은 VEX 결정을 문서화하세요.",
    },
    "prevention.binary-artifact-committed": {
        "title": "바이너리 릴리스 산출물이 저장소에 포함됨",
        "description": "소스 저장소에 실행 파일 또는 빌드 산출물로 보이는 파일이 포함되어 있습니다.",
        "recommendation": "의도적으로 vendoring한 파일이 아니라면 제거하고, 필요한 경우 출처 증명·체크섬·서명을 함께 관리하세요.",
    },
    "prevention.threat-model-missing": {
        "title": "위협 모델 문서가 없음",
        "description": "신뢰 경계, 주요 자산, 악용 시나리오, 보안 가정이 문서화되어 있지 않습니다.",
        "recommendation": "출시 전 위협 모델을 작성하고 인증, 데이터, 외부 연동, 운영 권한의 경계를 정리하세요.",
    },
    "prevention.secret-rotation-runbook-missing": {
        "title": "비밀값 회전 절차 문서가 없음",
        "description": "비밀값 노출 시 폐기, 재발급, 사용 이력 확인, 재점검 절차가 문서화되어 있지 않습니다.",
        "recommendation": "비밀값 노출 대응 runbook을 작성하고 키 회전, 감사, 재점검 책임자를 지정하세요.",
    },
    "prevention.ai-llm-security-plan-missing": {
        "title": "AI/LLM 보안 계획이 없음",
        "description": "AI 또는 LLM 사용 흔적이 있으나 프롬프트 인젝션, 도구 권한, 민감정보 처리 기준이 문서화되어 있지 않습니다.",
        "recommendation": "프롬프트 경계, 도구 allowlist, 민감정보 마스킹, 모델/제공자 목록, 적대적 테스트를 문서화하세요.",
    },
    "prevention.mobile-security-plan-missing": {
        "title": "모바일 보안 계획이 없음",
        "description": "모바일 프로젝트 파일이 있으나 MASVS 범위, 플랫폼 설정, 저장소/네트워크/릴리스 테스트 기준이 문서화되어 있지 않습니다.",
        "recommendation": "Android/iOS 설정, 저장소, 통신, 서명, 기기 테스트 요구사항을 모바일 보안 계획에 정리하세요.",
    },
    "prevention.nist-csf-profile-missing": {
        "title": "NIST CSF 2.0 프로파일이 없음",
        "description": "Govern, Identify, Protect, Detect, Respond, Recover 기능에 대한 프로젝트 증적 매핑이 없습니다.",
        "recommendation": "NIST CSF 2.0 기능별 소유자, 증적, 점검 주기, 예외 처리 기준을 문서화하세요.",
    },
    "prevention.cisa-attestation-missing": {
        "title": "CISA 보안 소프트웨어 개발 확인서 증적이 없음",
        "description": "CISA/OMB 확인서에 필요한 개발, 검증, 공급망, 취약점 대응 증적이 문서화되어 있지 않습니다.",
        "recommendation": "SSDF 기반 개발 환경, 제3자 구성요소, 검증, 취약점 대응 증적을 확인서 체크리스트로 관리하세요.",
    },
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
    "config.compose-dangerous-capability": {
        "title": "Compose 서비스가 광범위한 Linux capability를 부여함",
        "description": "SYS_ADMIN, NET_ADMIN 같은 capability는 컨테이너 격리와 호스트 보호를 약화시킬 수 있습니다.",
        "recommendation": "불필요한 capability를 제거하고 필요한 권한만 명시적으로 부여하세요.",
    },
    "config.compose-host-pid": {
        "title": "Compose 서비스가 host PID namespace를 사용함",
        "description": "host PID namespace는 호스트 프로세스 가시성을 넓혀 격리를 약화시킵니다.",
        "recommendation": "host PID 접근이 꼭 필요한 경우가 아니면 기본 PID namespace를 사용하세요.",
    },
    "config.k8s-privileged-container": {
        "title": "Kubernetes 컨테이너가 privileged 모드를 사용함",
        "description": "privileged 컨테이너는 호스트 수준 접근 권한을 얻을 수 있습니다.",
        "recommendation": "privileged 모드를 제거하고 필요한 Linux capability만 명시하세요.",
    },
    "config.k8s-allow-privilege-escalation": {
        "title": "Kubernetes 컨테이너가 권한 상승을 허용함",
        "description": "권한 상승 허용은 컨테이너 격리를 약화시킵니다.",
        "recommendation": "문서화된 요구사항이 없다면 allowPrivilegeEscalation: false를 설정하세요.",
    },
    "config.k8s-host-network": {
        "title": "Kubernetes workload가 host network를 사용함",
        "description": "host network는 일반적인 Pod 네트워크 격리를 우회합니다.",
        "recommendation": "필요하지 않다면 Pod 네트워크와 Service/NetworkPolicy를 사용하세요.",
    },
    "config.k8s-hostpath-volume": {
        "title": "Kubernetes workload가 hostPath 볼륨을 마운트함",
        "description": "hostPath는 호스트 파일시스템 경로를 컨테이너에 노출합니다.",
        "recommendation": "가능하면 PersistentVolume으로 대체하고, 불가피한 경우 사유를 문서화하세요.",
    },
    "config.k8s-run-as-root": {
        "title": "Kubernetes workload가 root 실행을 허용함",
        "description": "root 사용자 실행은 컨테이너 침해 시 영향 범위를 키울 수 있습니다.",
        "recommendation": "runAsNonRoot: true와 비root 런타임 사용자를 설정하세요.",
    },
    "config.k8s-service-account-token": {
        "title": "Kubernetes service account token 자동 마운트",
        "description": "불필요한 service account token은 Pod 침해 시 Kubernetes API 접근 경로가 될 수 있습니다.",
        "recommendation": "Kubernetes API 접근이 필요하지 않다면 automountServiceAccountToken: false를 설정하세요.",
    },
    "config.k8s-unpinned-image": {
        "title": "Kubernetes 이미지가 고정되지 않음",
        "description": "latest 또는 태그 없는 이미지는 검토 없이 내용이 바뀔 수 있습니다.",
        "recommendation": "검토된 버전 태그 또는 immutable digest로 이미지를 고정하세요.",
    },
    "config.terraform-public-storage": {
        "title": "Terraform 저장소 ACL이 public으로 설정됨",
        "description": "공개 저장소 설정은 데이터 노출로 이어질 수 있습니다.",
        "recommendation": "private ACL을 기본값으로 두고, 공개가 필요한 경우 명시적 정책 검토를 남기세요.",
    },
    "config.terraform-public-access-block-disabled": {
        "title": "Terraform public access block이 비활성화됨",
        "description": "public access block 통제를 끄면 실수로 공개될 가능성이 커집니다.",
        "recommendation": "문서화된 공개 버킷 설계가 없다면 public access block을 유지하세요.",
    },
    "config.terraform-open-admin-port": {
        "title": "Terraform 보안그룹이 관리자 포트를 인터넷에 공개함",
        "description": "SSH/RDP를 0.0.0.0/0에 공개하면 초기 침투 경로가 될 수 있습니다.",
        "recommendation": "관리자 포트는 VPN, bastion, 승인된 CIDR로 제한하세요.",
    },
    "config.terraform-wildcard-iam-action": {
        "title": "Terraform IAM 정책이 wildcard action을 허용함",
        "description": "IAM action wildcard는 최소 권한 원칙을 약화시키고 권한 확대 위험을 키웁니다.",
        "recommendation": "필요한 최소 action만 명시하고 예외 사유를 문서화하세요.",
    },
    "config.terraform-wildcard-principal": {
        "title": "Terraform IAM 정책이 wildcard principal을 허용함",
        "description": "wildcard principal은 의도하지 않은 주체에게 접근을 허용할 수 있습니다.",
        "recommendation": "승인된 계정, 역할, 서비스 주체로 principal을 제한하세요.",
    },
    "config.github-pull-request-target": {
        "title": "GitHub Actions가 pull_request_target을 사용함",
        "description": "pull_request_target은 권한 있는 저장소 컨텍스트에서 실행되어 PR 코드와 함께 쓰면 위험합니다.",
        "recommendation": "비신뢰 PR 코드는 pull_request에서 실행하고, 권한 작업과 checkout/build 단계를 분리하세요.",
    },
    "config.github-untrusted-event-in-run": {
        "title": "GitHub Actions run 단계에 이벤트 데이터가 직접 삽입됨",
        "description": "PR 이벤트 필드는 공격자가 제어할 수 있는 문자열을 포함할 수 있습니다.",
        "recommendation": "이벤트 값은 환경변수로 전달하고 셸 사용 전에 quoting과 검증을 적용하세요.",
    },
    "config.android-debuggable": {
        "title": "Android 앱이 debuggable로 설정됨",
        "description": "릴리스 앱의 debuggable 설정은 런타임 조작과 정보 노출 위험을 높입니다.",
        "recommendation": "릴리스 빌드에서는 android:debuggable을 비활성화하고 빌드 타입별 설정을 분리하세요.",
    },
    "config.android-allow-backup": {
        "title": "Android 백업이 허용됨",
        "description": "민감 데이터가 포함된 앱에서 백업 허용은 로컬 데이터 유출 위험을 키울 수 있습니다.",
        "recommendation": "민감 앱은 백업을 비활성화하거나 백업 제외 규칙을 명확히 설정하세요.",
    },
    "config.android-cleartext-traffic": {
        "title": "Android cleartext traffic이 허용됨",
        "description": "평문 HTTP 통신은 네트워크 구간에서 변조와 도청 위험이 있습니다.",
        "recommendation": "HTTPS를 기본으로 강제하고 예외는 network security config로 제한하세요.",
    },
    "config.android-exported-component": {
        "title": "Android component가 exported로 설정됨",
        "description": "exported component는 외부 앱의 진입점이 될 수 있어 권한 검토가 필요합니다.",
        "recommendation": "의도한 component만 export하고 민감 component에는 permission을 요구하세요.",
    },
    "config.ios-ats-arbitrary-loads": {
        "title": "iOS ATS가 임의 네트워크 로드를 허용함",
        "description": "NSAllowsArbitraryLoads는 앱 전체의 전송 보안 기본값을 약화시킬 수 있습니다.",
        "recommendation": "ATS를 유지하고 필요한 예외는 검토된 도메인 단위로 제한하세요.",
    },
    "config.ios-file-sharing-enabled": {
        "title": "iOS 파일 공유가 활성화됨",
        "description": "UIFileSharingEnabled는 앱 문서를 사용자가 직접 접근할 수 있게 하므로 민감 파일 검토가 필요합니다.",
        "recommendation": "민감 문서가 아니라는 근거가 없다면 파일 공유를 비활성화하세요.",
    },
    "config.ios-open-documents-in-place": {
        "title": "iOS 문서 제자리 열기가 활성화됨",
        "description": "문서 provider 흐름에서 외부 앱과 파일 변경 범위가 넓어질 수 있습니다.",
        "recommendation": "문서 provider 흐름과 민감 파일 처리 범위를 검토하고 필요한 경우 제한하세요.",
    },
    "code.xss-dom-sink": {
        "title": "XSS 의심 HTML 출력 지점",
        "description": "사용자 입력으로 보이는 값이 HTML 렌더링 지점으로 전달되는 패턴입니다.",
        "recommendation": "텍스트 렌더링, 컨텍스트별 출력 인코딩, 검증된 sanitizer를 사용하세요.",
    },
    "code.sql-dynamic-query": {
        "title": "동적 SQL 쿼리로 인한 SQL 삽입 의심",
        "description": "SQL 문자열이 실행 직전에 동적으로 조립되는 패턴입니다.",
        "recommendation": "문자열 조합 대신 파라미터 바인딩이나 ORM의 안전한 쿼리 API를 사용하세요.",
    },
    "code.command-injection": {
        "title": "명령어 삽입 의심",
        "description": "셸 또는 프로세스 실행 API에 동적 입력이나 사용자 입력이 전달되는 패턴입니다.",
        "recommendation": "사용자 입력을 셸에 넘기지 말고, 고정된 인자 배열과 allowlist 검증을 사용하세요.",
    },
    "code.path-traversal": {
        "title": "경로 조작 의심",
        "description": "파일 시스템 API가 사용자 제어 경로 데이터를 사용하는 패턴입니다.",
        "recommendation": "허용된 기준 디렉터리 안에서 경로를 정규화하고, 상위 경로 이동을 차단하세요.",
    },
    "code.csrf-disabled": {
        "title": "CSRF 보호 비활성화 의심",
        "description": "라우트 또는 애플리케이션에서 CSRF 보호를 비활성화하는 패턴입니다.",
        "recommendation": "브라우저 인증을 쓰는 상태 변경 요청에는 CSRF 보호를 유지하거나 보완 통제를 문서화하세요.",
    },
    "code.auth-disabled-endpoint": {
        "title": "인증 또는 인가 우회 설정 의심",
        "description": "엔드포인트나 핸들러에서 인증 또는 인가를 명시적으로 우회하는 패턴입니다.",
        "recommendation": "정말 공개 엔드포인트인지 확인하고, 민감한 작업에는 인가 검사를 강제하세요.",
    },
    "code.eval-user-input": {
        "title": "eval 계열 API를 통한 코드 삽입 의심",
        "description": "사용자 입력이 동적 코드 실행 API로 전달되는 패턴입니다.",
        "recommendation": "동적 코드 실행을 제거하고, 허용된 작업만 고정 dispatch table로 처리하세요.",
    },
    "code.unsafe-deserialization": {
        "title": "위험한 역직렬화 API 사용",
        "description": "신뢰할 수 없는 데이터에 위험할 수 있는 역직렬화 API가 사용된 패턴입니다.",
        "recommendation": "안전한 파서를 사용하고, 역직렬화는 서명된 신뢰 입력으로 제한하세요.",
    },
    "code.ssrf-user-url": {
        "title": "사용자 제어 URL 요청으로 인한 SSRF 의심",
        "description": "서버 측 HTTP 클라이언트가 사용자 입력에서 온 URL을 요청하는 패턴입니다.",
        "recommendation": "허용된 호스트만 요청하고 사설망 대역을 차단하며 임의 URL 전달을 피하세요.",
    },
    "code.unrestricted-file-upload": {
        "title": "제한 없는 파일 업로드 의심",
        "description": "업로드 파일을 클라이언트가 제어하는 이름이나 느슨한 저장 설정으로 저장하는 패턴입니다.",
        "recommendation": "콘텐츠 타입과 확장자를 검증하고 서버 측 파일명을 생성하며 실행 경로 밖에 저장하세요.",
    },
    "code.dangerous-c-buffer-api": {
        "title": "위험한 C/C++ 버퍼 API 사용",
        "description": "버퍼 오버플로우와 자주 연결되는 오래된 C/C++ API가 사용된 패턴입니다.",
        "recommendation": "경계가 있는 대체 API를 사용하고 대상 버퍼 크기를 검증하세요.",
    },
    "code.unbounded-request-body": {
        "title": "요청 본문 크기 제한이 보이지 않음",
        "description": "명시적 크기 제한 없이 요청 본문 파서가 활성화된 패턴입니다.",
        "recommendation": "보수적인 요청 본문 크기 제한을 설정하고 과도한 요청은 초기에 거부하세요.",
    },
    "code.logging-sensitive-data": {
        "title": "민감정보 로깅 의심",
        "description": "로그 또는 콘솔 출력에 자격 증명, 토큰, 세션, 쿠키 정보가 포함될 수 있는 패턴입니다.",
        "recommendation": "민감값은 로그에서 제거하고, 필요한 경우 마스킹된 식별자나 안전한 이벤트 메타데이터만 남기세요.",
    },
    "code.empty-exception-handler": {
        "title": "빈 예외 처리 블록",
        "description": "예외를 기록하거나 복구하지 않고 무시하는 패턴입니다.",
        "recommendation": "예상 가능한 예외만 명시적으로 처리하고, 보안상 중요한 실패는 정제된 컨텍스트로 기록하세요.",
    },
    "code.stack-trace-exposure": {
        "title": "스택 트레이스 노출 의심",
        "description": "애플리케이션 코드에서 원시 스택 트레이스를 출력할 수 있는 패턴입니다.",
        "recommendation": "중앙화된 오류 처리로 라우팅하고 로컬 디버깅 외에는 원시 스택 트레이스를 출력하지 마세요.",
    },
    "code.unversioned-api-route": {
        "title": "버전 없는 API 라우트",
        "description": "공개 API로 보이는 라우트에 명시적인 버전 경로가 없는 패턴입니다.",
        "recommendation": "공개 API를 인벤토리화하고 /api/v1/... 같은 명시적 버전 경로를 사용하세요.",
    },
    "code.insecure-temp-file": {
        "title": "안전하지 않은 임시 파일 사용",
        "description": "예측 가능한 임시 파일명 또는 직접 지정한 /tmp 경로를 파일 작업에 사용하는 패턴입니다.",
        "recommendation": "원자적으로 파일을 생성하는 안전한 임시 파일 API를 사용하고 예측 가능한 공유 경로를 피하세요.",
    },
    "code.wildcard-cors": {
        "title": "와일드카드 CORS 허용",
        "description": "모든 출처의 요청을 허용하는 CORS 설정 패턴입니다.",
        "recommendation": "신뢰할 수 있는 애플리케이션 도메인만 허용하고, 자격 증명 허용과 와일드카드 출처를 함께 사용하지 마세요.",
    },
    "code.public-bind-all-interfaces": {
        "title": "모든 인터페이스 바인딩",
        "description": "서비스가 모든 네트워크 인터페이스에서 수신하도록 설정된 패턴입니다.",
        "recommendation": "개발 서비스는 기본적으로 localhost에 바인딩하고, 외부 노출은 명시적 설정으로만 허용하세요.",
    },
    "code.insecure-cookie-settings": {
        "title": "안전하지 않은 쿠키 설정",
        "description": "세션 쿠키의 Secure 또는 HttpOnly 보호가 비활성화된 것으로 보이는 패턴입니다.",
        "recommendation": "세션 쿠키에 Secure, HttpOnly, 적절한 SameSite 속성을 설정하고 로컬 개발 외에는 약화하지 마세요.",
    },
    "code.directory-listing-enabled": {
        "title": "디렉터리 리스팅 활성화 의심",
        "description": "웹 서버 설정에서 디렉터리 목록 노출이 활성화된 것으로 보이는 패턴입니다.",
        "recommendation": "디렉터리 리스팅을 비활성화하고 의도한 파일만 통제된 라우트나 정적 자산 설정으로 제공하세요.",
    },
    "code.webdav-enabled": {
        "title": "WebDAV 활성화 의심",
        "description": "WebDAV 또는 HTTP PUT 기반 게시 기능이 활성화된 것으로 보이는 패턴입니다.",
        "recommendation": "명시적으로 필요하지 않다면 WebDAV를 비활성화하고, 필요한 경우 인증과 네트워크 통제로 제한하세요.",
    },
    "code.legacy-board-software": {
        "title": "레거시 게시판 소프트웨어 흔적",
        "description": "과거 반복적인 웹 침해와 연결되었던 레거시 게시판 소프트웨어 흔적이 포함된 패턴입니다.",
        "recommendation": "실제 사용 여부를 확인하고, 업데이트 또는 제거하며 업로드/다운로드 기능은 보완 통제 뒤로 격리하세요.",
    },
    "code.weak-hash": {
        "title": "약한 해시 알고리즘 사용 의심",
        "description": "비밀번호, 서명, 무결성 확인에 부적절할 수 있는 MD5 또는 SHA-1 사용 패턴입니다.",
        "recommendation": "자격 증명에는 전용 비밀번호 해시를 사용하고, 무결성에는 필요한 경우 SHA-256 이상 승인 알고리즘을 사용하세요.",
    },
    "code.xml-external-entity": {
        "title": "XML 외부 엔티티 처리 위험",
        "description": "외부 엔티티 처리를 비활성화하지 않으면 위험할 수 있는 XML 파서 사용 패턴입니다.",
        "recommendation": "DTD와 외부 엔티티 해석을 비활성화하거나 신뢰할 수 없는 XML에는 강화된 파서 설정을 사용하세요.",
    },
    "code.llm-prompt-user-concat": {
        "title": "LLM 프롬프트에 사용자 입력이 직접 결합됨",
        "description": "사용자 제어 입력이 system/developer prompt 또는 메시지 구성에 직접 섞이는 패턴입니다.",
        "recommendation": "시스템 지시는 고정하고 사용자 콘텐츠는 별도 메시지 필드로 분리하며 프롬프트 인젝션 테스트를 추가하세요.",
    },
    "code.llm-tool-unrestricted": {
        "title": "LLM 도구 호출 권한이 넓게 열려 있음",
        "description": "모델이 셸, 파일, 브라우저, HTTP, 데이터베이스 같은 광범위한 도구를 제한 없이 호출할 수 있는 패턴입니다.",
        "recommendation": "작업별 도구 allowlist, 인자 검증, 부작용 작업 확인, 도구 호출 로그를 적용하세요.",
    },
    "code.llm-sensitive-data-in-prompt": {
        "title": "민감정보가 LLM 프롬프트로 전달될 수 있음",
        "description": "credential, token, cookie, session 같은 민감 필드가 LLM 요청에 포함될 수 있는 패턴입니다.",
        "recommendation": "LLM 호출 전 민감값을 제거하거나 마스킹하고 프롬프트가 로컬 신뢰 경계를 벗어나는지 문서화하세요.",
    },
    "dependency.osv-known-vulnerability": {
        "title": "OSV에 보고된 알려진 취약 의존성",
        "description": "OSV가 이 정확한 의존성 버전에 대해 알려진 취약점을 보고했습니다.",
        "recommendation": "OSV 상세 페이지를 확인한 뒤 업그레이드, 패치, 대체, 또는 보완 통제를 문서화하세요.",
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
    components: tuple[DependencyComponent, ...] = (),
) -> str:
    if report_format == "cyclonedx":
        return render_cyclonedx(components)
    if report_format == "cyclonedx-vex":
        return render_cyclonedx_vex(findings)
    if report_format == "json":
        return render_json(findings, target_names, language, target_paths=target_paths, components=components)
    if report_format == "markdown":
        return render_markdown(findings, target_names, language, target_paths=target_paths)
    if report_format == "html":
        return render_html(findings, target_names, language, target_paths=target_paths, components=components)
    if report_format == "sarif":
        return render_sarif(findings)
    raise ValueError(f"Unsupported report format: {report_format}")


def render_json(
    findings: list[Finding],
    target_names: tuple[str, ...] = (),
    language: str = "en",
    *,
    target_paths: dict[str, str] | None = None,
    components: tuple[DependencyComponent, ...] = (),
) -> str:
    payload = {
        "generated_at": _generated_at()[0],
        "language": _labels(language)["html_lang"],
        "scanner": {"name": "local-security-scanner", "version": __version__},
        "summary": _summary(findings, target_names, target_paths),
        "components": [component_payload(component) for component in components],
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
        lines.append(f"- {_category_label(category, language)}: {count}")
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
                    f"- {labels['category']}: `{_category_label(finding.category, language)}`",
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
    components: tuple[DependencyComponent, ...] = (),
) -> str:
    payload = build_dashboard_payload(findings, target_names, language, target_paths=target_paths, components=components)
    labels = _labels(language)
    json_payload = json.dumps(payload, ensure_ascii=False).replace("</", "<\\/")
    replacements = _html_replacements(labels, json_payload)
    content = HTML_TEMPLATE
    for placeholder, value in replacements.items():
        content = content.replace(placeholder, value)
    return content


def build_dashboard_payload(
    findings: list[Finding],
    target_names: tuple[str, ...] = (),
    language: str = "en",
    *,
    target_paths: dict[str, str] | None = None,
    warnings: tuple[str, ...] = (),
    scan_path: str | None = None,
    standard: str = DEFAULT_STANDARD,
    standard_category: str = DEFAULT_STANDARD_CATEGORY,
    components: tuple[DependencyComponent, ...] = (),
    enable_osv: bool = False,
) -> dict[str, object]:
    generated, generated_display = _generated_at()
    summary = _summary(findings, target_names, target_paths)
    labels = _labels(language)
    return {
        "generated_at": generated,
        "generated_display": generated_display,
        "language": labels["html_lang"],
        "labels_by_language": TRANSLATIONS,
        "standards": standards_payload(),
        "rule_mappings": _rule_mappings_for_findings(findings),
        "components": [component_payload(component) for component in components],
        "sbom": cyclonedx_payload(components),
        "scanner": {"name": "local-security-scanner", "version": __version__},
        "summary": summary,
        "scan": {
            "path": scan_path or "",
            "standard": standard,
            "standard_category": standard_category,
            "warnings": list(warnings),
            "enable_osv": enable_osv,
        },
        "findings_by_language": {
            "en": [_finding_payload(finding) for finding in findings],
            "ko": [_localized_finding_payload(finding, "ko") for finding in findings],
        },
    }


def _html_replacements(labels: dict[str, object], json_payload: str) -> dict[str, str]:
    return {
        "__DATA__": json_payload,
        "__INITIAL_LANG__": html.escape(str(labels["html_lang"]), quote=True),
        "__INITIAL_TITLE__": html.escape(str(labels["title"]), quote=True),
        "__INITIAL_HELP__": html.escape(str(labels["help"])),
        "__INITIAL_HELP_TITLE__": html.escape(str(labels["help_title"])),
        "__INITIAL_HELP_INTRO__": html.escape(str(labels["help_intro"])),
        "__INITIAL_FILTERS__": html.escape(str(labels["filters"]), quote=True),
        "__INITIAL_SCAN_DIRECTORY__": html.escape(str(labels["scan_directory"])),
        "__INITIAL_SCAN_STANDARD__": html.escape(str(labels["scan_standard"])),
        "__INITIAL_SCAN_STANDARD_CATEGORY__": html.escape(str(labels["scan_standard_category"])),
        "__INITIAL_SCAN_PATH_PLACEHOLDER__": html.escape(str(labels["scan_path_placeholder"]), quote=True),
        "__INITIAL_CHOOSE_FOLDER__": html.escape(str(labels["choose_folder"])),
        "__INITIAL_SCAN_NOW__": html.escape(str(labels["scan_now"])),
        "__INITIAL_DISCOVER_PROJECTS__": html.escape(str(labels["discover_projects"])),
        "__INITIAL_DISCOVERY_DEPTH__": html.escape(str(labels["discovery_depth"])),
        "__INITIAL_SCAN_STATUS_IDLE__": html.escape(str(labels["scan_status_idle"])),
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


def _rule_mappings_for_findings(findings: list[Finding]) -> dict[str, list[dict[str, object]]]:
    rule_ids = {finding.rule_id for finding in findings}
    if not rule_ids:
        return {}
    all_mappings = rule_standard_mappings_payload()
    return {rule_id: all_mappings.get(rule_id, []) for rule_id in sorted(rule_ids)}


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


def _category_label(category: str, language: str) -> str:
    category_labels = _labels(language).get("category_labels", {})
    if isinstance(category_labels, dict):
        return str(category_labels.get(category, category))
    return category


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

    .topbar-action {
      min-width: 78px;
      min-height: 30px;
      padding: 5px 12px;
      border: 1px solid rgba(203, 213, 225, 0.42);
      border-radius: 999px;
      background: rgba(15, 23, 42, 0.7);
      color: #ffffff;
      font-size: 12px;
      font-weight: 800;
      flex: 0 0 auto;
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

    .risk-score-note {
      margin: -6px 0 16px;
      color: var(--muted);
      font-size: 12px;
      line-height: 1.5;
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

    .scan-panel {
      display: grid;
      gap: 12px;
      margin-bottom: 16px;
    }

    .scan-panel h2 {
      margin: 0;
      font-size: 15px;
      line-height: 1.2;
    }

    .scan-form {
      display: grid;
      grid-template-columns: minmax(280px, 1fr) auto auto minmax(88px, 110px) auto;
      gap: 10px;
      align-items: center;
    }

    .scan-standard-form {
      display: grid;
      grid-template-columns: repeat(2, minmax(220px, 1fr));
      gap: 10px;
      align-items: end;
    }

    .scan-actions {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      align-items: center;
    }

    .scan-select {
      display: grid;
      gap: 6px;
      color: var(--muted);
      font-size: 12px;
      font-weight: 700;
    }

    .scan-option {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      color: var(--muted);
      font-weight: 700;
      white-space: nowrap;
    }

    .scan-option input {
      width: auto;
      min-height: auto;
      margin: 0;
    }

    .scan-note {
      color: var(--muted);
      font-size: 12px;
    }

    .scan-depth {
      display: grid;
      grid-template-columns: auto minmax(54px, 1fr);
      gap: 8px;
      align-items: center;
      color: var(--muted);
      font-weight: 700;
      white-space: nowrap;
    }

    .scan-status {
      min-height: 20px;
      color: var(--muted);
      overflow-wrap: anywhere;
      font-size: 13px;
    }

    .scan-status.error {
      color: var(--critical);
      font-weight: 700;
    }

    .scan-status.ok {
      color: var(--ok);
      font-weight: 700;
    }

    .path-display {
      cursor: default;
      background: #f8fafc;
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

    .help-view {
      display: grid;
      gap: 14px;
    }

    .help-view[hidden] {
      display: none;
    }

    .help-heading {
      display: grid;
      gap: 6px;
      margin-bottom: 2px;
    }

    .help-heading h2 {
      margin: 0;
      font-size: 20px;
      line-height: 1.2;
    }

    .help-heading p {
      margin: 0;
      color: var(--muted);
    }

    .coverage-table {
      width: 100%;
      min-width: 760px;
      border-collapse: collapse;
      background: #ffffff;
      border: 1px solid var(--line);
      border-radius: 8px;
      overflow: hidden;
      box-shadow: 0 1px 2px rgba(15, 23, 42, 0.04);
    }

    .coverage-table th, .coverage-table td {
      padding: 10px 12px;
      border-bottom: 1px solid var(--line);
    }

    .coverage-table-wrap {
      overflow: auto;
      border-radius: 8px;
    }

    .status-badge {
      display: inline-flex;
      align-items: center;
      min-height: 24px;
      border-radius: 999px;
      padding: 3px 8px;
      background: #fff7ed;
      color: #9a3412;
      font-size: 12px;
      font-weight: 800;
      white-space: nowrap;
    }

    .status-badge.local {
      background: #ecfdf5;
      color: #047857;
    }

    .status-badge.external {
      background: #eff6ff;
      color: #1d4ed8;
    }

    .status-badge.evidence {
      background: #fff7ed;
      color: #9a3412;
    }

    .standards-help {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 12px;
    }

    .standard-card {
      display: grid;
      gap: 12px;
      min-width: 0;
      padding: 16px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #ffffff;
      box-shadow: 0 1px 2px rgba(15, 23, 42, 0.04);
    }

    .standard-head {
      display: grid;
      grid-template-columns: minmax(0, 1fr) auto;
      gap: 12px;
      align-items: start;
    }

    .standard-card h3 {
      margin: 0 0 6px;
      font-size: 16px;
      line-height: 1.25;
    }

    .standard-card p {
      margin: 0;
      color: var(--muted);
    }

    .standard-count {
      min-width: 78px;
      border-radius: 999px;
      padding: 4px 8px;
      background: #eef2f7;
      color: var(--muted);
      font-size: 12px;
      font-weight: 800;
      text-align: center;
      white-space: nowrap;
    }

    .help-meta {
      display: grid;
      gap: 4px;
      color: var(--muted);
    }

    .help-meta strong {
      color: var(--ink);
    }

    .category-chips, .standard-links {
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
    }

    .category-chip {
      border-radius: 999px;
      padding: 4px 8px;
      background: #eef6ff;
      color: #1d4ed8;
      font-size: 12px;
      font-weight: 800;
    }

    .category-chip.unsupported {
      background: #f1f5f9;
      color: var(--muted);
      font-weight: 700;
    }

    .rule-related {
      display: flex;
      flex-wrap: wrap;
      gap: 5px;
      margin-top: 6px;
    }

    .standard-links a {
      display: inline-flex;
      align-items: center;
      min-height: 28px;
      border-radius: 999px;
      padding: 4px 9px;
      background: #111827;
      color: #ffffff;
      font-size: 12px;
      font-weight: 800;
      text-decoration: none;
    }

    @media (max-width: 1000px) {
      .metrics { grid-template-columns: repeat(3, minmax(0, 1fr)); }
      .filters, .scan-form, .scan-standard-form { grid-template-columns: 1fr 1fr; }
      .scan-actions { align-items: stretch; }
      .standards-help { grid-template-columns: 1fr; }
      .grid { grid-template-columns: 1fr; }
      button { width: 100%; }
      .topbar-action { width: auto; }
    }

    @media (max-width: 640px) {
      .shell { width: min(100% - 20px, 1440px); }
      .topbar { align-items: flex-start; flex-direction: column; padding: 16px 0; gap: 8px; }
      .header-side { width: 100%; padding-top: 34px; flex-wrap: wrap; }
      .topbar-action { position: absolute; top: 16px; right: 96px; }
      .language-toggle { position: absolute; top: 16px; right: 0; }
      .meta { text-align: left; white-space: normal; }
      .metrics, .filters, .scan-form, .scan-standard-form { grid-template-columns: 1fr; }
      .scan-actions { display: grid; grid-template-columns: 1fr; }
      .standard-head { grid-template-columns: 1fr; }
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
        <button id="help-toggle" class="topbar-action" type="button">__INITIAL_HELP__</button>
        <div class="meta">
          <div id="generated-line"></div>
          <div id="summary-line"></div>
        </div>
      </div>
    </div>
  </header>

  <main class="shell">
    <div id="dashboard-view">
      <section class="panel scan-panel" id="scan-panel">
      <h2 id="scan-directory-title">__INITIAL_SCAN_DIRECTORY__</h2>
      <div class="scan-form">
        <input id="scan-path" class="path-display" type="text" autocomplete="off" readonly aria-readonly="true" placeholder="__INITIAL_SCAN_PATH_PLACEHOLDER__">
        <button id="scan-choose" type="button">__INITIAL_CHOOSE_FOLDER__</button>
        <label class="scan-option">
          <input id="scan-discover" type="checkbox" checked>
          <span id="scan-discover-label">__INITIAL_DISCOVER_PROJECTS__</span>
        </label>
        <label class="scan-depth">
          <span id="scan-depth-label">__INITIAL_DISCOVERY_DEPTH__</span>
          <input id="scan-depth" type="number" min="0" max="20" value="2">
        </label>
        <button id="scan-run" type="button">__INITIAL_SCAN_NOW__</button>
      </div>
      <div class="scan-standard-form">
        <label class="scan-select">
          <span id="scan-standard-label">__INITIAL_SCAN_STANDARD__</span>
          <select id="scan-standard"></select>
        </label>
        <label class="scan-select">
          <span id="scan-standard-category-label">__INITIAL_SCAN_STANDARD_CATEGORY__</span>
          <select id="scan-standard-category"></select>
        </label>
      </div>
      <div class="scan-actions">
        <label class="scan-option" title="">
          <input id="scan-osv" type="checkbox">
          <span id="scan-osv-label"></span>
        </label>
        <button id="sbom-download" type="button"></button>
        <span id="scan-osv-note" class="scan-note"></span>
      </div>
      <div id="scan-status" class="scan-status">__INITIAL_SCAN_STATUS_IDLE__</div>
    </section>

    <section class="metrics" id="metrics"></section>
    <p id="risk-score-note" class="risk-score-note"></p>

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
    </div>

    <section id="help-view" class="help-view" hidden>
      <div class="help-heading">
        <h2 id="help-title">__INITIAL_HELP_TITLE__</h2>
        <p id="help-intro">__INITIAL_HELP_INTRO__</p>
      </div>
      <div class="coverage-table-wrap">
        <table class="coverage-table">
          <thead>
            <tr>
              <th id="coverage-standard-heading"></th>
              <th id="coverage-auto-heading"></th>
              <th id="coverage-status-heading"></th>
            </tr>
          </thead>
          <tbody id="coverage-matrix"></tbody>
        </table>
      </div>
      <div id="standards-help" class="standards-help"></div>
    </section>
  </main>

  <script id="findings-data" type="application/json">__DATA__</script>
  <script>
    let payload = JSON.parse(document.getElementById("findings-data").textContent);
    let summary = payload.summary;
    const severityOrder = ["critical", "high", "medium", "low", "info"];
    const severityColors = { critical: "#7f1d1d", high: "#c2410c", medium: "#d69e2e", low: "#2563eb", info: "#64748b" };

    const state = {
      search: "",
      severity: "all",
      category: "all",
      target: "all",
      language: payload.language || "en",
      scanStatus: "",
      scanStatusClass: "",
      scanRunning: false,
      scanStandard: (payload.scan && payload.scan.standard) || "local",
      scanStandardCategory: (payload.scan && payload.scan.standard_category) || "all",
      view: location.hash === "#help" ? "help" : "dashboard",
      helpRenderedLanguage: "",
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

    function categoryLabels() {
      return labels().category_labels || {};
    }

    function categoryLabel(category) {
      return categoryLabels()[category] || category;
    }

    function labelFor(item) {
      return (item.labels && (item.labels[state.language] || item.labels.en)) || item.id || "";
    }

    function localizedText(map, fallback = "") {
      return (map && (map[state.language] || map.en)) || fallback;
    }

    function standardDefinitions() {
      return payload.standards || [];
    }

    function ruleMappings() {
      return payload.rule_mappings || {};
    }

    function components() {
      return payload.components || [];
    }

    function currentStandard() {
      return standardDefinitions().find((standard) => standard.id === state.scanStandard) || standardDefinitions()[0];
    }

    function currentStandardCategory() {
      const standard = currentStandard();
      if (!standard) return null;
      return (standard.categories || []).find((category) => category.id === state.scanStandardCategory) || null;
    }

    function firstSupportedCategory(standard) {
      return (standard.categories || []).find((category) => category.supported) || null;
    }

    function targetDisplay(target) {
      return (summary.target_paths && summary.target_paths[target]) || target || labels().unknown;
    }

    function setText(id, value) {
      byId(id).textContent = value;
    }

    function apiEndpoint(path) {
      const endpoint = path || "/api/scan";
      if (location.protocol === "http:" || location.protocol === "https:") {
        return endpoint;
      }
      return `http://127.0.0.1:8765${endpoint}`;
    }

    async function parseJsonResponse(response) {
      try {
        return await response.json();
      } catch (error) {
        return {};
      }
    }

    function userFacingApiError(error, fallback) {
      const message = error && error.message ? error.message : "";
      if (location.protocol === "file:" && (message.includes("expected pattern") || message.includes("Failed to fetch"))) {
        return fallback;
      }
      return message || fallback;
    }

    function renderChrome() {
      const activeLabels = labels();
      document.documentElement.lang = activeLabels.html_lang;
      document.title = activeLabels.title;
      setText("dashboard-title", activeLabels.title);
      setText("help-title", activeLabels.help_title);
      setText("help-intro", activeLabels.help_intro);
      setText("generated-line", `${activeLabels.generated} ${payload.generated_display}`);
      setText(
        "summary-line",
        `${activeLabels.risk_score} ${summary.risk_score} | ${activeLabels.targets} ${summary.target_count} | ${activeLabels.findings} ${findings().length}`
      );
      byId("filters-panel").setAttribute("aria-label", activeLabels.filters);
      setText("scan-directory-title", activeLabels.scan_directory);
      byId("scan-path").placeholder = activeLabels.scan_path_placeholder;
      setText("scan-choose", activeLabels.choose_folder);
      setText("scan-standard-label", activeLabels.scan_standard);
      setText("scan-standard-category-label", activeLabels.scan_standard_category);
      setText("scan-discover-label", activeLabels.discover_projects);
      setText("scan-depth-label", activeLabels.discovery_depth);
      setText("scan-osv-label", activeLabels.osv_toggle);
      setText("scan-osv-note", activeLabels.osv_network_note);
      setText("sbom-download", activeLabels.download_sbom);
      setText("scan-run", state.scanRunning ? activeLabels.scan_status_running : activeLabels.scan_now);
      byId("scan-run").disabled = state.scanRunning;
      byId("scan-choose").disabled = state.scanRunning;
      byId("scan-standard").disabled = state.scanRunning;
      byId("scan-standard-category").disabled = state.scanRunning;
      byId("scan-osv").disabled = state.scanRunning;
      byId("sbom-download").disabled = components().length === 0;
      const scanStatus = byId("scan-status");
      scanStatus.textContent = state.scanStatus || activeLabels.scan_status_idle;
      scanStatus.className = `scan-status ${state.scanStatusClass}`;
      setText("risk-score-note", activeLabels.risk_score_formula);
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
      setText("coverage-standard-heading", activeLabels.scan_standard);
      setText("coverage-auto-heading", activeLabels.auto_supported);
      setText("coverage-status-heading", activeLabels.coverage);
      byId("lang-ko").classList.toggle("active", state.language === "ko");
      byId("lang-en").classList.toggle("active", state.language === "en");
    }

    function renderScanStandards() {
      const standards = standardDefinitions();
      fillSelect(
        byId("scan-standard"),
        standards.map((standard) => [standard.id, labelFor(standard)]),
        state.scanStandard
      );
      const standard = currentStandard();
      if (!standard) return;
      const selectedCategory = currentStandardCategory();
      if (!selectedCategory || !selectedCategory.supported) {
        const fallback = firstSupportedCategory(standard);
        state.scanStandardCategory = fallback ? fallback.id : "all";
      }
      fillSelectOptions(
        byId("scan-standard-category"),
        (standard.categories || []).map((category) => ({
          value: category.id,
          label: category.supported ? labelFor(category) : `${labelFor(category)} (${labels().scan_category_not_supported})`,
          disabled: !category.supported,
        })),
        state.scanStandardCategory
      );
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
      fillSelect(byId("category"), [["all", activeLabels.all_categories], ...categories.map((cat) => [cat, categoryLabel(cat)])], state.category);
      fillSelect(byId("target"), [["all", activeLabels.all_targets], ...targets.map((target) => [target, targetDisplay(target)])], state.target);
    }

    function fillSelect(select, entries, selected) {
      select.innerHTML = entries.map(([value, label]) => `<option value="${escapeText(value)}">${escapeText(label)}</option>`).join("");
      select.value = selected;
    }

    function fillSelectOptions(select, entries, selected) {
      select.innerHTML = entries.map((entry) => {
        const disabled = entry.disabled ? " disabled" : "";
        return `<option value="${escapeText(entry.value)}"${disabled}>${escapeText(entry.label)}</option>`;
      }).join("");
      select.value = selected;
    }

    function filteredFindings() {
      const query = state.search.trim().toLowerCase();
      return findings().filter((finding) => {
        if (state.severity !== "all" && finding.severity !== state.severity) return false;
        if (state.category !== "all" && finding.category !== state.category) return false;
        if (state.target !== "all" && finding.target !== state.target) return false;
        if (!query) return true;
        return [finding.title, finding.rule_id, categoryLabel(finding.category), finding.path, targetDisplay(finding.target), finding.evidence, finding.recommendation]
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

    function relatedStandardsHtml(ruleId) {
      const activeLabels = labels();
      const mappings = ruleMappings()[ruleId] || [];
      if (!mappings.length) {
        return `<span>${escapeText(activeLabels.no_related_standards)}</span>`;
      }
      return `<div class="rule-related">${mappings.slice(0, 12).map((mapping) => `
        <span class="category-chip">${escapeText(labelFor({ labels: mapping.standard_labels }))} · ${escapeText(labelFor({ labels: mapping.category_labels }))}</span>
      `).join("")}</div>`;
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
              <span class="location">${escapeText(finding.rule_id)} | ${escapeText(categoryLabel(finding.category))}</span>
            </td>
            <td>${escapeText(targetDisplay(finding.target))}</td>
            <td class="location">${escapeText(location)}</td>
            <td class="evidence">${escapeText(finding.evidence || "")}</td>
            <td>
              <details>
                <summary>${escapeText(activeLabels.remediate)}</summary>
                <div class="detail-body">
                  <strong>${escapeText(activeLabels.rule_details)}</strong>
                  <br>
                  ${escapeText(finding.description || "")}
                  <br><br>
                  ${escapeText(finding.recommendation || activeLabels.review_this_finding)}
                  <br><br>
                  <strong>${escapeText(activeLabels.related_standards)}</strong>
                  ${relatedStandardsHtml(finding.rule_id)}
                </div>
              </details>
            </td>
          </tr>
        `;
      }).join("");
      empty.textContent = findings().length === 0 ? activeLabels.no_findings_display : activeLabels.no_findings_filter;
      empty.hidden = items.length > 0;
    }

    function renderView() {
      const isHelp = state.view === "help";
      byId("dashboard-view").hidden = isHelp;
      byId("help-view").hidden = !isHelp;
      setText("help-toggle", isHelp ? labels().dashboard : labels().help);
      byId("help-toggle").setAttribute("aria-pressed", isHelp ? "true" : "false");
    }

    function coverageStatus(level, activeLabels) {
      const normalized = level || "evidence";
      if (normalized === "local") {
        return {
          className: "local",
          label: activeLabels.automatic_coverage || activeLabels.local_coverage,
        };
      }
      if (normalized === "external") {
        return {
          className: "external",
          label: activeLabels.external_required,
        };
      }
      return {
        className: "evidence",
        label: activeLabels.evidence_required,
      };
    }

    function renderHelp() {
      if (state.helpRenderedLanguage === state.language) {
        return;
      }
      const activeLabels = labels();
      const standards = standardDefinitions();
      byId("coverage-matrix").innerHTML = standards.map((standard) => {
        const leafCategories = (standard.categories || []).filter((category) => category.id !== "all");
        const supportedCount = leafCategories.filter((category) => category.supported).length;
        const total = Math.max(leafCategories.length, 1);
        const status = coverageStatus(standard.coverage_level, activeLabels);
        return `
          <tr>
            <td>${escapeText(labelFor(standard))}</td>
            <td>${supportedCount}/${total}</td>
            <td><span class="status-badge ${status.className}">${escapeText(status.label)}</span></td>
          </tr>
        `;
      }).join("");
      byId("standards-help").innerHTML = standards.map((standard) => {
        const categories = standard.categories || [];
        const leafCategories = categories.filter((category) => category.id !== "all");
        const supportedCount = leafCategories.filter((category) => category.supported).length;
        const status = coverageStatus(standard.coverage_level, activeLabels);
        const references = standard.references || [];
        const links = references.length
          ? references.map((reference) => `
              <a href="${escapeText(reference.url)}" target="_blank" rel="noopener noreferrer">${escapeText(labelFor(reference))}</a>
            `).join("")
          : `<span class="category-chip unsupported">${escapeText(activeLabels.not_supported)}</span>`;
        const categoryChips = categories.map((category) => `
          <span class="category-chip ${category.supported ? "" : "unsupported"}" title="${escapeText(category.supported ? activeLabels.supported : activeLabels.not_supported)}">
            ${escapeText(labelFor(category))}
          </span>
        `).join("");
        return `
          <article class="standard-card">
            <div class="standard-head">
              <div>
                <h3>${escapeText(labelFor(standard))}</h3>
                <p>${escapeText(localizedText(standard.description, ""))}</p>
              </div>
              <div class="standard-count">${supportedCount}/${Math.max(leafCategories.length, 1)} ${escapeText(activeLabels.mapped_checks)}</div>
            </div>
            <div><span class="status-badge ${status.className}">${escapeText(status.label)}</span></div>
            <div class="help-meta">
              <strong>${escapeText(activeLabels.coverage)}</strong>
              <span>${escapeText(localizedText(standard.coverage, ""))}</span>
            </div>
            <div class="help-meta">
              <strong>${escapeText(activeLabels.check_categories)}</strong>
              <div class="category-chips">${categoryChips}</div>
            </div>
            <div class="help-meta">
              <strong>${escapeText(activeLabels.official_links)}</strong>
              <div class="standard-links">${links}</div>
            </div>
          </article>
        `;
      }).join("");
      state.helpRenderedLanguage = state.language;
    }

    function render() {
      renderChrome();
      renderScanStandards();
      renderView();
      if (state.view === "help") {
        renderHelp();
      }
      renderFilters();
      const items = filteredFindings();
      renderMetrics(items);
      renderBars(items);
      renderProjects(items);
      renderTable(items);
    }

    function applyPayload(nextPayload) {
      payload = nextPayload;
      summary = payload.summary;
      state.search = "";
      state.severity = "all";
      state.category = "all";
      state.target = "all";
      state.scanStandard = (payload.scan && payload.scan.standard) || state.scanStandard;
      state.scanStandardCategory = (payload.scan && payload.scan.standard_category) || state.scanStandardCategory;
      byId("search").value = "";
      render();
    }

    async function chooseDirectory() {
      const activeLabels = labels();
      state.scanStatus = "";
      state.scanStatusClass = "";
      render();

      try {
        const response = await fetch(apiEndpoint("/api/select-directory"), {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ current_path: byId("scan-path").value || "" }),
        });
        const result = await parseJsonResponse(response);
        if (!response.ok) {
          throw new Error(result.error || activeLabels.folder_selection_failed);
        }
        if (result.cancelled) {
          state.scanStatus = activeLabels.folder_selection_cancelled;
          state.scanStatusClass = "";
          render();
          return;
        }
        byId("scan-path").value = result.path || "";
        state.scanStatus = `${activeLabels.folder_selected}: ${result.path || ""}`;
        state.scanStatusClass = "ok";
        render();
      } catch (error) {
        state.scanStatus = `${activeLabels.folder_selection_failed}: ${userFacingApiError(error, activeLabels.server_required)}`;
        state.scanStatusClass = "error";
        render();
      }
    }

    async function runDirectoryScan() {
      const activeLabels = labels();
      const path = byId("scan-path").value.trim();
      if (!path) {
        state.scanStatus = activeLabels.scan_path_placeholder;
        state.scanStatusClass = "error";
        render();
        return;
      }

      state.scanRunning = true;
      state.scanStatus = activeLabels.scan_status_running;
      state.scanStatusClass = "";
      render();

      try {
        const response = await fetch(apiEndpoint("/api/scan"), {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            path,
            language: state.language,
            discover_projects: byId("scan-discover").checked,
            discovery_depth: Number(byId("scan-depth").value || 0),
            standard: state.scanStandard,
            standard_category: state.scanStandardCategory,
            min_severity: "low",
            enable_osv: byId("scan-osv").checked,
          }),
        });
        const nextPayload = await parseJsonResponse(response);
        if (!response.ok) {
          throw new Error(nextPayload.error || activeLabels.scan_status_failed);
        }
        state.scanRunning = false;
        state.scanStatus = `${labels().scan_status_done}: ${nextPayload.scan.path || path}`;
        state.scanStatusClass = "ok";
        applyPayload(nextPayload);
      } catch (error) {
        state.scanRunning = false;
        state.scanStatus = `${activeLabels.scan_status_failed}: ${userFacingApiError(error, activeLabels.server_required)}`;
        state.scanStatusClass = "error";
        render();
      }
    }

    function downloadSbom() {
      const activeLabels = labels();
      if (!components().length || !payload.sbom) {
        state.scanStatus = activeLabels.sbom_unavailable;
        state.scanStatusClass = "error";
        render();
        return;
      }
      const blob = new Blob([JSON.stringify(payload.sbom, null, 2)], { type: "application/json" });
      const link = document.createElement("a");
      link.href = URL.createObjectURL(blob);
      link.download = "sec-chk-cyclonedx-sbom.json";
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(link.href);
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
    byId("scan-standard").addEventListener("change", (event) => {
      state.scanStandard = event.target.value;
      const standard = currentStandard();
      const fallback = standard ? firstSupportedCategory(standard) : null;
      state.scanStandardCategory = fallback ? fallback.id : "all";
      render();
    });
    byId("scan-standard-category").addEventListener("change", (event) => {
      state.scanStandardCategory = event.target.value;
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
    byId("scan-choose").addEventListener("click", () => {
      chooseDirectory();
    });
    byId("scan-run").addEventListener("click", () => {
      runDirectoryScan();
    });
    byId("sbom-download").addEventListener("click", () => {
      downloadSbom();
    });
    byId("help-toggle").addEventListener("click", () => {
      state.view = state.view === "help" ? "dashboard" : "help";
      if (state.view === "help") {
        location.hash = "help";
      } else if (location.hash === "#help") {
        history.replaceState(null, document.title, location.href.split("#")[0]);
      }
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
    window.addEventListener("hashchange", () => {
      state.view = location.hash === "#help" ? "help" : "dashboard";
      render();
    });

    render();
  </script>
</body>
</html>
"""
