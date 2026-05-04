from __future__ import annotations

from dataclasses import dataclass

from .models import CATEGORIES, Finding


DEFAULT_STANDARD = "local"
DEFAULT_STANDARD_CATEGORY = "all"


SECRET_RULE_IDS = (
    "secret.private-key",
    "secret.aws-access-key",
    "secret.github-token",
    "secret.openai-key",
    "secret.slack-token",
    "secret.generic-assignment",
)

DEPENDENCY_RULE_IDS = (
    "dependency.package-json-invalid",
    "dependency.node-missing-lockfile",
    "dependency.node-unbounded-version",
    "dependency.node-insecure-url",
    "dependency.remote-shell-script",
    "dependency.python-insecure-url",
    "dependency.python-unpinned-requirement",
    "dependency.python-wildcard-version",
    "dependency.docker-unpinned-base",
    "dependency.docker-remote-shell",
)

CONFIGURATION_RULE_IDS = (
    "config.env-file-present",
    "config.private-key-like-file",
    "config.debug-enabled",
    "config.development-environment",
    "config.docker-root-user",
    "config.docker-add-http",
    "config.docker-no-user",
    "config.compose-privileged",
    "config.compose-host-network",
    "config.compose-docker-sock",
)

SENSITIVE_DATA_RULE_IDS = SECRET_RULE_IDS + (
    "config.env-file-present",
    "config.private-key-like-file",
)

INSECURE_TRANSPORT_RULE_IDS = (
    "dependency.node-insecure-url",
    "dependency.python-insecure-url",
    "config.docker-add-http",
)

REMOTE_EXECUTION_RULE_IDS = (
    "dependency.remote-shell-script",
    "dependency.docker-remote-shell",
    "config.docker-add-http",
)

SUPPLY_CHAIN_RULE_IDS = DEPENDENCY_RULE_IDS

INTEGRITY_RULE_IDS = (
    "dependency.node-missing-lockfile",
    "dependency.node-insecure-url",
    "dependency.remote-shell-script",
    "dependency.python-insecure-url",
    "dependency.docker-remote-shell",
    "config.docker-add-http",
)

ERROR_HANDLING_RULE_IDS = (
    "config.debug-enabled",
    "config.development-environment",
)


@dataclass(frozen=True)
class StandardCategory:
    id: str
    labels: dict[str, str]
    scanner_categories: tuple[str, ...] = ()
    rule_ids: tuple[str, ...] = ()

    @property
    def supported(self) -> bool:
        return bool(self.scanner_categories)


@dataclass(frozen=True)
class SecurityStandard:
    id: str
    labels: dict[str, str]
    categories: tuple[StandardCategory, ...]


@dataclass(frozen=True)
class StandardSelection:
    standard: str
    category: str
    scanner_categories: tuple[str, ...]
    rule_ids: frozenset[str] | None = None


def _all_category(categories: tuple[StandardCategory, ...], labels: dict[str, str]) -> StandardCategory:
    scanner_categories: list[str] = []
    rule_ids: list[str] = []
    for category in categories:
        for scanner_category in category.scanner_categories:
            if scanner_category not in scanner_categories:
                scanner_categories.append(scanner_category)
        for rule_id in category.rule_ids:
            if rule_id not in rule_ids:
                rule_ids.append(rule_id)
    return StandardCategory(
        DEFAULT_STANDARD_CATEGORY,
        labels,
        scanner_categories=tuple(scanner_categories),
        rule_ids=tuple(rule_ids),
    )


LOCAL_STANDARD = SecurityStandard(
    DEFAULT_STANDARD,
    {"en": "Local Rule Categories", "ko": "로컬 룰 종류"},
    (
        StandardCategory(
            DEFAULT_STANDARD_CATEGORY,
            {"en": "All local checks", "ko": "모든 로컬 점검"},
            scanner_categories=CATEGORIES,
        ),
        StandardCategory(
            "secrets",
            {"en": "Secrets", "ko": "비밀값"},
            scanner_categories=("secrets",),
        ),
        StandardCategory(
            "dependencies",
            {"en": "Dependencies", "ko": "의존성"},
            scanner_categories=("dependencies",),
        ),
        StandardCategory(
            "configuration",
            {"en": "Configuration", "ko": "설정"},
            scanner_categories=("configuration",),
        ),
    ),
)


_OWASP_TOP_10_CATEGORIES = (
    StandardCategory("a01-broken-access-control", {"en": "A01 Broken Access Control", "ko": "A01 접근권한 취약"}),
    StandardCategory(
        "a02-cryptographic-failures",
        {"en": "A02 Cryptographic Failures", "ko": "A02 암호화 오류"},
        scanner_categories=("secrets", "configuration", "dependencies"),
        rule_ids=SECRET_RULE_IDS
        + (
            "config.env-file-present",
            "config.private-key-like-file",
            "dependency.node-insecure-url",
            "dependency.python-insecure-url",
            "config.docker-add-http",
        ),
    ),
    StandardCategory("a03-injection", {"en": "A03 Injection", "ko": "A03 인젝션"}),
    StandardCategory("a04-insecure-design", {"en": "A04 Insecure Design", "ko": "A04 안전하지 않은 설계"}),
    StandardCategory(
        "a05-security-misconfiguration",
        {"en": "A05 Security Misconfiguration", "ko": "A05 보안 설정 오류"},
        scanner_categories=("configuration",),
        rule_ids=CONFIGURATION_RULE_IDS,
    ),
    StandardCategory(
        "a06-vulnerable-outdated-components",
        {"en": "A06 Vulnerable and Outdated Components", "ko": "A06 취약하고 오래된 구성요소"},
        scanner_categories=("dependencies",),
        rule_ids=(
            "dependency.package-json-invalid",
            "dependency.node-missing-lockfile",
            "dependency.node-unbounded-version",
            "dependency.python-unpinned-requirement",
            "dependency.python-wildcard-version",
            "dependency.docker-unpinned-base",
        ),
    ),
    StandardCategory(
        "a07-identification-authentication-failures",
        {"en": "A07 Identification and Authentication Failures", "ko": "A07 식별 및 인증 실패"},
    ),
    StandardCategory(
        "a08-software-data-integrity-failures",
        {"en": "A08 Software and Data Integrity Failures", "ko": "A08 소프트웨어 및 데이터 무결성 실패"},
        scanner_categories=("dependencies", "configuration"),
        rule_ids=(
            "dependency.node-missing-lockfile",
            "dependency.node-insecure-url",
            "dependency.remote-shell-script",
            "dependency.python-insecure-url",
            "dependency.docker-remote-shell",
            "config.docker-add-http",
        ),
    ),
    StandardCategory(
        "a09-security-logging-monitoring-failures",
        {"en": "A09 Security Logging and Monitoring Failures", "ko": "A09 보안 로깅 및 모니터링 실패"},
    ),
    StandardCategory(
        "a10-server-side-request-forgery",
        {"en": "A10 Server-Side Request Forgery", "ko": "A10 서버사이드 요청 위조"},
    ),
)

OWASP_TOP_10_2021 = SecurityStandard(
    "owasp-top-10-2021",
    {"en": "OWASP Top 10:2021", "ko": "OWASP Top 10:2021"},
    (
        _all_category(
            _OWASP_TOP_10_CATEGORIES,
            {"en": "All mapped OWASP checks", "ko": "매핑된 OWASP 항목 전체"},
        ),
        *_OWASP_TOP_10_CATEGORIES,
    ),
)


_SW_DEV_SECURITY_CATEGORIES = (
    StandardCategory(
        "input-validation-expression",
        {"en": "Input Data Validation and Representation", "ko": "입력데이터 검증 및 표현"},
    ),
    StandardCategory(
        "security-features",
        {"en": "Security Features", "ko": "보안기능"},
        scanner_categories=("secrets", "configuration", "dependencies"),
        rule_ids=SECRET_RULE_IDS
        + (
            "config.env-file-present",
            "config.private-key-like-file",
            "dependency.node-insecure-url",
            "dependency.python-insecure-url",
            "config.docker-add-http",
        ),
    ),
    StandardCategory("time-state", {"en": "Time and State", "ko": "시간 및 상태"}),
    StandardCategory(
        "error-handling",
        {"en": "Error Handling", "ko": "에러처리"},
        scanner_categories=("configuration",),
        rule_ids=("config.debug-enabled", "config.development-environment"),
    ),
    StandardCategory("code-error", {"en": "Code Error", "ko": "코드오류"}),
    StandardCategory("encapsulation", {"en": "Encapsulation", "ko": "캡슐화"}),
    StandardCategory(
        "api-misuse",
        {"en": "API Misuse", "ko": "API 오용"},
        scanner_categories=("dependencies", "configuration"),
        rule_ids=(
            "dependency.remote-shell-script",
            "dependency.docker-remote-shell",
            "config.docker-add-http",
        ),
    ),
)

SW_DEV_SECURITY_49 = SecurityStandard(
    "sw-dev-security-49",
    {"en": "Korea SW Development Security 49", "ko": "소프트웨어 개발보안 49"},
    (
        _all_category(
            _SW_DEV_SECURITY_CATEGORIES,
            {"en": "All mapped SW security checks", "ko": "매핑된 SW 개발보안 항목 전체"},
        ),
        *_SW_DEV_SECURITY_CATEGORIES,
    ),
)


_OWASP_TOP_10_2025_CATEGORIES = (
    StandardCategory("a01-broken-access-control", {"en": "A01 Broken Access Control", "ko": "A01 접근권한 취약"}),
    StandardCategory(
        "a02-security-misconfiguration",
        {"en": "A02 Security Misconfiguration", "ko": "A02 보안 설정 오류"},
        scanner_categories=("configuration",),
        rule_ids=CONFIGURATION_RULE_IDS,
    ),
    StandardCategory(
        "a03-software-supply-chain-failures",
        {"en": "A03 Software Supply Chain Failures", "ko": "A03 소프트웨어 공급망 실패"},
        scanner_categories=("dependencies",),
        rule_ids=SUPPLY_CHAIN_RULE_IDS,
    ),
    StandardCategory(
        "a04-cryptographic-failures",
        {"en": "A04 Cryptographic Failures", "ko": "A04 암호화 오류"},
        scanner_categories=("secrets", "configuration", "dependencies"),
        rule_ids=SENSITIVE_DATA_RULE_IDS + INSECURE_TRANSPORT_RULE_IDS,
    ),
    StandardCategory("a05-injection", {"en": "A05 Injection", "ko": "A05 인젝션"}),
    StandardCategory("a06-insecure-design", {"en": "A06 Insecure Design", "ko": "A06 안전하지 않은 설계"}),
    StandardCategory("a07-authentication-failures", {"en": "A07 Authentication Failures", "ko": "A07 인증 실패"}),
    StandardCategory(
        "a08-software-data-integrity-failures",
        {"en": "A08 Software or Data Integrity Failures", "ko": "A08 소프트웨어 또는 데이터 무결성 실패"},
        scanner_categories=("dependencies", "configuration"),
        rule_ids=INTEGRITY_RULE_IDS,
    ),
    StandardCategory(
        "a09-security-logging-alerting-failures",
        {"en": "A09 Security Logging and Alerting Failures", "ko": "A09 보안 로깅 및 알림 실패"},
    ),
    StandardCategory(
        "a10-mishandling-exceptional-conditions",
        {"en": "A10 Mishandling of Exceptional Conditions", "ko": "A10 예외 상황 처리 부적절"},
        scanner_categories=("configuration",),
        rule_ids=ERROR_HANDLING_RULE_IDS,
    ),
)

OWASP_TOP_10_2025 = SecurityStandard(
    "owasp-top-10-2025",
    {"en": "OWASP Top 10:2025", "ko": "OWASP Top 10:2025"},
    (
        _all_category(
            _OWASP_TOP_10_2025_CATEGORIES,
            {"en": "All mapped OWASP 2025 checks", "ko": "매핑된 OWASP 2025 항목 전체"},
        ),
        *_OWASP_TOP_10_2025_CATEGORIES,
    ),
)


_OWASP_API_2023_CATEGORIES = (
    StandardCategory(
        "api1-broken-object-level-authorization",
        {"en": "API1 Broken Object Level Authorization", "ko": "API1 객체 수준 권한 부여 취약"},
    ),
    StandardCategory("api2-broken-authentication", {"en": "API2 Broken Authentication", "ko": "API2 인증 취약"}),
    StandardCategory(
        "api3-broken-object-property-level-authorization",
        {"en": "API3 Broken Object Property Level Authorization", "ko": "API3 객체 속성 수준 권한 부여 취약"},
    ),
    StandardCategory(
        "api4-unrestricted-resource-consumption",
        {"en": "API4 Unrestricted Resource Consumption", "ko": "API4 제한 없는 리소스 사용"},
    ),
    StandardCategory(
        "api5-broken-function-level-authorization",
        {"en": "API5 Broken Function Level Authorization", "ko": "API5 기능 수준 권한 부여 취약"},
    ),
    StandardCategory(
        "api6-unrestricted-access-sensitive-business-flows",
        {"en": "API6 Unrestricted Access to Sensitive Business Flows", "ko": "API6 민감 비즈니스 흐름 접근 제한 미흡"},
    ),
    StandardCategory("api7-server-side-request-forgery", {"en": "API7 Server Side Request Forgery", "ko": "API7 서버사이드 요청 위조"}),
    StandardCategory(
        "api8-security-misconfiguration",
        {"en": "API8 Security Misconfiguration", "ko": "API8 보안 설정 오류"},
        scanner_categories=("configuration",),
        rule_ids=CONFIGURATION_RULE_IDS,
    ),
    StandardCategory(
        "api9-improper-inventory-management",
        {"en": "API9 Improper Inventory Management", "ko": "API9 부적절한 인벤토리 관리"},
    ),
    StandardCategory(
        "api10-unsafe-consumption-of-apis",
        {"en": "API10 Unsafe Consumption of APIs", "ko": "API10 안전하지 않은 API 사용"},
        scanner_categories=("dependencies", "configuration"),
        rule_ids=INSECURE_TRANSPORT_RULE_IDS + REMOTE_EXECUTION_RULE_IDS,
    ),
)

OWASP_API_SECURITY_2023 = SecurityStandard(
    "owasp-api-security-2023",
    {"en": "OWASP API Security Top 10:2023", "ko": "OWASP API Security Top 10:2023"},
    (
        _all_category(
            _OWASP_API_2023_CATEGORIES,
            {"en": "All mapped API Security checks", "ko": "매핑된 API Security 항목 전체"},
        ),
        *_OWASP_API_2023_CATEGORIES,
    ),
)


_OWASP_MOBILE_2024_CATEGORIES = (
    StandardCategory(
        "m1-improper-credential-usage",
        {"en": "M1 Improper Credential Usage", "ko": "M1 부적절한 자격증명 사용"},
        scanner_categories=("secrets", "configuration"),
        rule_ids=SENSITIVE_DATA_RULE_IDS,
    ),
    StandardCategory(
        "m2-inadequate-supply-chain-security",
        {"en": "M2 Inadequate Supply Chain Security", "ko": "M2 부적절한 공급망 보안"},
        scanner_categories=("dependencies",),
        rule_ids=SUPPLY_CHAIN_RULE_IDS,
    ),
    StandardCategory(
        "m3-insecure-authentication-authorization",
        {"en": "M3 Insecure Authentication/Authorization", "ko": "M3 안전하지 않은 인증/인가"},
    ),
    StandardCategory(
        "m4-insufficient-input-output-validation",
        {"en": "M4 Insufficient Input/Output Validation", "ko": "M4 입출력 검증 부족"},
    ),
    StandardCategory(
        "m5-insecure-communication",
        {"en": "M5 Insecure Communication", "ko": "M5 안전하지 않은 통신"},
        scanner_categories=("dependencies", "configuration"),
        rule_ids=INSECURE_TRANSPORT_RULE_IDS,
    ),
    StandardCategory("m6-inadequate-privacy-controls", {"en": "M6 Inadequate Privacy Controls", "ko": "M6 부적절한 개인정보 보호 통제"}),
    StandardCategory("m7-insufficient-binary-protections", {"en": "M7 Insufficient Binary Protections", "ko": "M7 바이너리 보호 부족"}),
    StandardCategory(
        "m8-security-misconfiguration",
        {"en": "M8 Security Misconfiguration", "ko": "M8 보안 설정 오류"},
        scanner_categories=("configuration",),
        rule_ids=CONFIGURATION_RULE_IDS,
    ),
    StandardCategory(
        "m9-insecure-data-storage",
        {"en": "M9 Insecure Data Storage", "ko": "M9 안전하지 않은 데이터 저장"},
        scanner_categories=("secrets", "configuration"),
        rule_ids=SENSITIVE_DATA_RULE_IDS,
    ),
    StandardCategory(
        "m10-insufficient-cryptography",
        {"en": "M10 Insufficient Cryptography", "ko": "M10 암호화 부족"},
        scanner_categories=("secrets", "configuration", "dependencies"),
        rule_ids=SENSITIVE_DATA_RULE_IDS + INSECURE_TRANSPORT_RULE_IDS,
    ),
)

OWASP_MOBILE_TOP_10_2024 = SecurityStandard(
    "owasp-mobile-top-10-2024",
    {"en": "OWASP Mobile Top 10:2024", "ko": "OWASP Mobile Top 10:2024"},
    (
        _all_category(
            _OWASP_MOBILE_2024_CATEGORIES,
            {"en": "All mapped Mobile Top 10 checks", "ko": "매핑된 Mobile Top 10 항목 전체"},
        ),
        *_OWASP_MOBILE_2024_CATEGORIES,
    ),
)


SECURITY_STANDARDS = (
    LOCAL_STANDARD,
    OWASP_TOP_10_2025,
    OWASP_TOP_10_2021,
    OWASP_API_SECURITY_2023,
    OWASP_MOBILE_TOP_10_2024,
    SW_DEV_SECURITY_49,
)
SECURITY_STANDARD_IDS = tuple(standard.id for standard in SECURITY_STANDARDS)


def standards_payload() -> list[dict[str, object]]:
    return [
        {
            "id": standard.id,
            "labels": standard.labels,
            "categories": [
                {
                    "id": category.id,
                    "labels": category.labels,
                    "supported": category.supported,
                }
                for category in standard.categories
            ],
        }
        for standard in SECURITY_STANDARDS
    ]


def resolve_standard_selection(
    standard_id: str = DEFAULT_STANDARD,
    category_id: str = DEFAULT_STANDARD_CATEGORY,
    explicit_categories: tuple[str, ...] | None = None,
) -> StandardSelection:
    if explicit_categories is not None and standard_id == DEFAULT_STANDARD and category_id == DEFAULT_STANDARD_CATEGORY:
        return StandardSelection(
            standard=standard_id,
            category=category_id,
            scanner_categories=explicit_categories,
            rule_ids=None,
        )

    standard = _find_standard(standard_id)
    category = _find_category(standard, category_id)
    if not category.supported:
        raise ValueError(f"Selected standard category has no local checks yet: {standard_id}/{category_id}")
    rule_ids = frozenset(category.rule_ids) if category.rule_ids else None
    return StandardSelection(
        standard=standard.id,
        category=category.id,
        scanner_categories=category.scanner_categories,
        rule_ids=rule_ids,
    )


def filter_findings_by_standard(findings: list[Finding], selection: StandardSelection) -> list[Finding]:
    if selection.rule_ids is None:
        return findings
    return [finding for finding in findings if finding.rule_id in selection.rule_ids]


def _find_standard(standard_id: str) -> SecurityStandard:
    for standard in SECURITY_STANDARDS:
        if standard.id == standard_id:
            return standard
    raise ValueError(f"Unsupported standard: {standard_id}")


def _find_category(standard: SecurityStandard, category_id: str) -> StandardCategory:
    for category in standard.categories:
        if category.id == category_id:
            return category
    raise ValueError(f"Unsupported standard category: {standard.id}/{category_id}")
