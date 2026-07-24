from __future__ import annotations

from typing import Final, Literal


ReportLanguage = Literal["ko", "en"]

_TEXT: Final[dict[ReportLanguage, dict[str, str]]] = {
    "en": {
        "title": "KODA Java Library Vulnerability Report",
        "eyebrow": "Offline Java security audit",
        "offline_complete": "Offline analysis complete",
        "target": "Target",
        "completed": "Completed",
        "data_as_of": "Data as of",
        "archives": "Archives",
        "components": "Components",
        "identity_review": "Identity review",
        "duplicates": "Duplicates",
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "kev": "KEV",
        "severity": "Severity",
        "all": "All",
        "review": "Review",
        "search": "Search",
        "search_placeholder": "Search library, vulnerability ID, or path",
        "summary_heading": "Scan summary",
        "resize_column": "Drag or use Left/Right arrow keys to resize this column",
        "vulnerabilities": "Vulnerabilities",
        "raw_matches": "Raw matches",
        "unique_vulnerabilities": "Unique vulnerabilities",
        "affected_library_versions": "Affected library versions",
        "cve": "Vulnerability ID",
        "library": "Library",
        "installed_version": "Installed version",
        "fixed": "Fixed",
        "final": "Final",
        "cvss": "CVSS",
        "server_path": "Server path",
        "identity": "Identity",
        "action": "Action",
        "yes": "Yes",
        "no": "No",
        "manual_review": "Manual review required",
        "none": "No matching vulnerability was found in the supplied data for identified libraries.",
        "none_detail": "This does not prove that the target has no vulnerabilities.",
        "update": "Upgrade to {versions}.",
        "vendor_review": "Review the advisory directly and confirm whether remediation is required.",
        "update_final": "Upgrade to the final version {version}.",
        "unknown": "Unknown",
        "kev_priority": "Prioritize this item because it is listed in CISA KEV.",
        "findings_heading": "Remediation by library",
        "findings_intro": "Vulnerabilities are consolidated by library and installed version.",
        "key_observation": "Key observation",
        "key_observation_body": "Alias and repeated-path matches are consolidated by library and installed version. Fixed is the first release named by each advisory; Final is the lowest candidate with no known vulnerability in the same database.",
        "priority_heading": "Priority recommendation",
        "priority_kev": "Start with the CISA KEV findings, then validate compatibility and move to the Final versions.",
        "priority_default": "Address Critical and High findings first, then validate compatibility before applying the Final versions.",
        "interpretation_heading": "Interpretation note",
        "interpretation_body": "Final is a candidate with no known vulnerability as of the report's Grype database date. It does not guarantee application compatibility or future safety. Review any identity that is not Resolved before remediation.",
        "showing_items": "Showing {visible} of {total} items",
        "column_width_note": "Column widths reset when the report is reopened.",
        "scroll_hint": "Scroll horizontally to see all columns.",
        "more": "More",
        "collapse": "Collapse",
    },
    "ko": {
        "title": "KODA Java 라이브러리 취약점 보고서",
        "eyebrow": "오프라인 Java 보안 감사",
        "offline_complete": "오프라인 분석 완료",
        "target": "점검 대상",
        "completed": "완료 시각",
        "data_as_of": "데이터 기준일",
        "archives": "아카이브",
        "components": "컴포넌트",
        "identity_review": "식별 확인 필요",
        "duplicates": "중복 파일",
        "critical": "치명",
        "high": "높음",
        "medium": "중간",
        "low": "낮음",
        "kev": "KEV",
        "severity": "심각도",
        "all": "전체",
        "review": "검토",
        "search": "검색",
        "search_placeholder": "라이브러리, 취약점 ID 또는 경로 검색",
        "summary_heading": "점검 요약",
        "resize_column": "드래그하거나 좌우 방향키로 컬럼 너비 조정",
        "vulnerabilities": "취약점",
        "raw_matches": "원본 매치",
        "unique_vulnerabilities": "고유 취약점",
        "affected_library_versions": "영향받은 라이브러리 버전",
        "cve": "취약점 ID",
        "library": "라이브러리",
        "installed_version": "설치 버전",
        "fixed": "수정 버전",
        "final": "최종 버전",
        "cvss": "CVSS",
        "server_path": "서버 경로",
        "identity": "식별 상태",
        "action": "조치",
        "yes": "예",
        "no": "아니요",
        "manual_review": "확인 필요",
        "none": "식별된 라이브러리와 반입된 취약점 데이터에서 일치 항목을 찾지 못했습니다.",
        "none_detail": "대상에 취약점이 없다는 의미는 아닙니다.",
        "update": "{versions} 버전 이상으로 업데이트하세요.",
        "vendor_review": "권고문을 직접 검토하여 조치여부를 확인하세요.",
        "update_final": "최종 버전 {version}(으)로 업데이트하세요.",
        "unknown": "확인 불가",
        "kev_priority": "CISA KEV에 등재되어 있으므로 우선 조치하세요.",
        "findings_heading": "라이브러리별 조치 현황",
        "findings_intro": "동일 라이브러리·설치 버전의 취약점을 한 행으로 통합했습니다.",
        "key_observation": "핵심 관찰",
        "key_observation_body": "취약점 별칭과 여러 경로에서 반복된 결과를 라이브러리·설치 버전 단위로 통합했습니다. 수정 버전은 각 권고문의 최초 안내이며, 최종 버전은 동일 DB에서 알려진 취약점이 없는 가장 낮은 후보입니다.",
        "priority_heading": "우선 조치 권고",
        "priority_kev": "CISA KEV 항목부터 호환성을 검토하고, 최종 버전으로 먼저 변경하세요.",
        "priority_default": "치명·높음 항목부터 검토하고, 호환성을 확인한 뒤 최종 버전을 적용하세요.",
        "interpretation_heading": "해석 시 유의사항",
        "interpretation_body": "최종 버전은 보고서의 Grype DB 기준일에 알려진 취약점이 없는 후보입니다. 애플리케이션 호환성이나 이후 공개될 취약점까지 보장하지 않으며, 식별 상태가 확인됨이 아닌 항목은 조치 전에 별도 검토가 필요합니다.",
        "showing_items": "전체 {total}개 중 {visible}개 항목 표시",
        "column_width_note": "컬럼 너비는 보고서를 다시 열면 초기화됩니다.",
        "scroll_hint": "좌우로 밀어 전체 컬럼을 확인할 수 있습니다.",
        "more": "더보기",
        "collapse": "접기",
    },
}

_HELP: Final[dict[ReportLanguage, tuple[str, str, tuple[tuple[str, str], ...]]]] = {
    "en": (
        "How to read this report",
        "The report inventories JAR, WAR, and EAR files, then compares identified components with the bundled Grype database. NVD adds CVSS detail and CISA KEV marks vulnerabilities known to be exploited.",
        (
            ("Severity", "Critical, High, Medium, and Low come from the vulnerability match. Address critical and high findings first, but evaluate service exposure and business impact."),
            ("KEV", "Yes means the CVE appears in CISA's Known Exploited Vulnerabilities catalog. It is a prioritization signal, not proof that this server was compromised."),
            ("Identity", "Resolved means Maven coordinates or a version were confirmed from pom.properties, pom.xml, or MANIFEST.MF. Inferred means the filename supplied the version. Unresolved means the library identity could not be determined. Review non-resolved identities before acting."),
            ("Fixed", "Each vulnerability ID appears on its own line with the first known fixed release from that advisory. Do not assume a Fixed version is the final upgrade target."),
            ("Final", "Starting with the Fixed candidates, KODA follows every newly reported fixed version until the same Grype database finds no vulnerability for a candidate. Final is the lowest verified clean candidate; it is evidence for the database date, not a compatibility or future-vulnerability guarantee."),
            ("Scope", "The server path identifies the scanned archive location. Backups, unused archives, and unreachable code still require operational confirmation. No matches do not prove the absence of vulnerabilities."),
        ),
    ),
    "ko": (
        "보고서 읽는 방법",
        "이 보고서는 JAR, WAR, EAR 파일에서 라이브러리를 식별한 뒤 번들된 Grype DB와 비교합니다. NVD는 CVSS 상세정보를 보강하고, CISA KEV는 실제 악용 사실이 알려진 CVE를 우선 표시합니다.",
        (
            ("심각도", "치명·높음·중간·낮음은 취약점 매칭 결과입니다. 치명과 높음을 우선 조치하되, 서비스 노출 여부와 업무 영향을 함께 판단하세요."),
            ("KEV", "예는 해당 CVE가 CISA의 Known Exploited Vulnerabilities 목록에 있다는 뜻입니다. 이 서버가 이미 침해됐다는 증거는 아니며, 조치 우선순위 신호입니다."),
            ("식별 상태", "확인됨은 pom.properties, pom.xml 또는 MANIFEST.MF에서 좌표나 버전을 확인한 상태입니다. 파일명 추정은 파일명에서 버전을 추정한 상태, 미확인은 라이브러리 식별에 실패한 상태입니다. 확인됨 이외의 항목은 조치 전에 확인하세요."),
            ("수정 버전", "취약점 ID별로 한 줄씩 해당 권고문에서 처음 안내한 수정 릴리스를 표시합니다. 수정 버전이 곧 최종 업그레이드 대상이라는 뜻은 아닙니다."),
            ("최종 버전", "수정 버전 후보부터 시작해 후보에서 새로 발견된 취약점의 수정 버전을 계속 추적하고, 동일한 Grype DB에서 취약점이 발견되지 않은 가장 낮은 후보를 표시합니다. DB 기준일에 대한 증거이며 호환성이나 이후 공개될 취약점까지 보장하지 않습니다."),
            ("점검 범위", "서버 경로는 실제로 검사한 아카이브 위치입니다. 백업 파일, 미사용 아카이브, 도달 불가능한 코드는 운영자가 추가로 확인해야 합니다. 일치 항목이 없더라도 취약점이 없다고 단정할 수 없습니다."),
        ),
    ),
}


def normalize_language(value: str | None) -> ReportLanguage:
    return "ko" if value in {None, "ko"} else "en"


def text(language: ReportLanguage, key: str) -> str:
    return _TEXT[language][key]


def severity_label(language: ReportLanguage, severity: str) -> str:
    return text(language, severity) if severity in {"critical", "high", "medium", "low"} else severity


def identity_label(language: ReportLanguage, status: str) -> str:
    labels = {
        "resolved": ("확인됨", "Resolved"),
        "partial": ("부분 확인", "Partial"),
        "inferred": ("파일명 추정", "Inferred"),
        "unresolved": ("미확인", "Unresolved"),
    }
    values = labels.get(status)
    if values is None:
        return status
    return values[0] if language == "ko" else values[1]


def help_html(language: ReportLanguage, element_id: str = "report-help", open_by_default: bool = True) -> str:
    title, introduction, items = _HELP[language]
    details = "".join(f"<dt>{heading}</dt><dd>{description}</dd>" for heading, description in items)
    open_attribute = " open" if open_by_default else ""
    return f"<details id=\"{element_id}\"{open_attribute}><summary>{title}</summary><p>{introduction}</p><dl>{details}</dl></details>"
