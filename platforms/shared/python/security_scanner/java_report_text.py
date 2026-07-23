from __future__ import annotations

from typing import Final, Literal


ReportLanguage = Literal["ko", "en"]

_TEXT: Final[dict[ReportLanguage, dict[str, str]]] = {
    "en": {
        "title": "KODA Java Library Vulnerability Report",
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
        "vendor_review": "Review the advisory and remediate with the vendor-supported release.",
        "update_final": "Upgrade to the verified final version {version}.",
        "unknown": "Unknown",
        "kev_priority": "Prioritize this item because it is listed in CISA KEV.",
    },
    "ko": {
        "title": "KODA Java 라이브러리 취약점 보고서",
        "target": "점검 대상",
        "completed": "완료 시각",
        "data_as_of": "데이터 기준일",
        "archives": "아카이브",
        "components": "컴포넌트",
        "identity_review": "식별 확인 필요",
        "duplicates": "중복 파일",
        "critical": "치명적",
        "high": "높음",
        "medium": "중간",
        "low": "낮음",
        "kev": "KEV",
        "severity": "심각도",
        "all": "전체",
        "review": "검토",
        "search": "검색",
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
        "manual_review": "수동 확인 필요",
        "none": "식별된 라이브러리와 반입된 취약점 데이터에서 일치 항목을 찾지 못했습니다.",
        "none_detail": "대상에 취약점이 없다는 의미는 아닙니다.",
        "update": "{versions} 버전 이상으로 업데이트하세요.",
        "vendor_review": "권고문을 검토하고 공급업체가 지원하는 수정 릴리스로 조치하세요.",
        "update_final": "검증된 최종 버전 {version}(으)로 업데이트하세요.",
        "unknown": "확인 불가",
        "kev_priority": "CISA KEV에 등재되어 있으므로 우선 조치하세요.",
    },
}

_HELP: Final[dict[ReportLanguage, tuple[str, str, tuple[tuple[str, str], ...]]]] = {
    "en": (
        "How to read this report",
        "The report inventories JAR, WAR, and EAR files, then compares identified components with the bundled Grype database. NVD adds CVSS detail and CISA KEV marks vulnerabilities known to be exploited.",
        (
            ("Severity", "Critical, High, Medium, and Low come from the vulnerability match. Address critical and high findings first, but evaluate service exposure and business impact."),
            ("KEV", "Yes means the CVE appears in CISA's Known Exploited Vulnerabilities catalog. It is a prioritization signal, not proof that this server was compromised."),
            ("Identity", "Resolved means Maven coordinates came from pom.properties or pom.xml. Partial means only Manifest metadata was available. Inferred means the filename supplied the version. Unresolved means the library identity could not be determined. Review non-resolved identities before acting."),
            ("Fixed", "A listed version is the first known fixed release from the advisory. Select a currently supported and application-compatible release that resolves every affected CVE; do not assume the listed version is the final upgrade target."),
            ("Final", "Final is the lowest candidate verified against the same Grype database with no matching vulnerability. It is evidence for the database date, not a guarantee that the release is compatible or free of newly published issues."),
            ("Scope", "The server path identifies the scanned archive location. Backups, unused archives, and unreachable code still require operational confirmation. No matches do not prove the absence of vulnerabilities."),
        ),
    ),
    "ko": (
        "보고서 읽는 방법",
        "이 보고서는 JAR, WAR, EAR 파일에서 라이브러리를 식별한 뒤 번들된 Grype DB와 비교합니다. NVD는 CVSS 상세정보를 보강하고, CISA KEV는 실제 악용 사실이 알려진 CVE를 우선 표시합니다.",
        (
            ("심각도", "치명적·높음·중간·낮음은 취약점 매칭 결과입니다. 치명적과 높음을 우선 조치하되, 서비스 노출 여부와 업무 영향을 함께 판단하세요."),
            ("KEV", "예는 해당 CVE가 CISA의 Known Exploited Vulnerabilities 목록에 있다는 뜻입니다. 이 서버가 이미 침해됐다는 증거는 아니며, 조치 우선순위 신호입니다."),
            ("식별 상태", "resolved는 pom.properties 또는 pom.xml에서 Maven 좌표를 확인한 상태입니다. partial은 Manifest 정보만 확인한 상태, inferred는 파일명에서 버전을 추정한 상태, unresolved는 라이브러리 식별에 실패한 상태입니다. resolved 이외의 항목은 조치 전에 확인하세요."),
            ("수정 버전", "표시된 버전은 권고문에서 확인된 최초 수정 릴리스입니다. 모든 CVE를 해결하면서 애플리케이션과 호환되는 현재 지원 버전을 선택해야 하며, 표기 버전이 최종 업그레이드 대상이라는 뜻은 아닙니다."),
            ("최종 버전", "최종 버전은 동일한 Grype DB로 재검사해 알려진 매치가 없음을 확인한 후보 중 선택한 버전입니다. DB 기준일에 대한 증거이며 애플리케이션 호환성이나 이후 공개될 취약점까지 보장하지 않습니다."),
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


def help_html(language: ReportLanguage, element_id: str = "report-help") -> str:
    title, introduction, items = _HELP[language]
    details = "".join(f"<dt>{heading}</dt><dd>{description}</dd>" for heading, description in items)
    return f"<details id=\"{element_id}\" open><summary>{title}</summary><p>{introduction}</p><dl>{details}</dl></details>"
