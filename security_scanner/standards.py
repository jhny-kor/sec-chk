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


_CWE_TOP_25_2025_CATEGORIES = (
    StandardCategory(
        "cwe-79-cross-site-scripting",
        {"en": "CWE-79 Cross-site Scripting", "ko": "CWE-79 크로스사이트 스크립팅"},
    ),
    StandardCategory(
        "cwe-89-sql-injection",
        {"en": "CWE-89 SQL Injection", "ko": "CWE-89 SQL 삽입"},
    ),
    StandardCategory(
        "cwe-352-cross-site-request-forgery",
        {"en": "CWE-352 Cross-Site Request Forgery", "ko": "CWE-352 크로스사이트 요청 위조"},
    ),
    StandardCategory(
        "cwe-862-missing-authorization",
        {"en": "CWE-862 Missing Authorization", "ko": "CWE-862 인가 누락"},
    ),
    StandardCategory(
        "cwe-787-out-of-bounds-write",
        {"en": "CWE-787 Out-of-bounds Write", "ko": "CWE-787 범위 밖 쓰기"},
    ),
    StandardCategory(
        "cwe-22-path-traversal",
        {"en": "CWE-22 Path Traversal", "ko": "CWE-22 경로 조작"},
    ),
    StandardCategory(
        "cwe-416-use-after-free",
        {"en": "CWE-416 Use After Free", "ko": "CWE-416 해제 후 사용"},
    ),
    StandardCategory(
        "cwe-125-out-of-bounds-read",
        {"en": "CWE-125 Out-of-bounds Read", "ko": "CWE-125 범위 밖 읽기"},
    ),
    StandardCategory(
        "cwe-78-os-command-injection",
        {"en": "CWE-78 OS Command Injection", "ko": "CWE-78 운영체제 명령어 삽입"},
    ),
    StandardCategory(
        "cwe-94-code-injection",
        {"en": "CWE-94 Code Injection", "ko": "CWE-94 코드 삽입"},
    ),
    StandardCategory(
        "cwe-120-classic-buffer-overflow",
        {"en": "CWE-120 Classic Buffer Overflow", "ko": "CWE-120 크기 검증 없는 버퍼 복사"},
    ),
    StandardCategory(
        "cwe-434-dangerous-file-upload",
        {"en": "CWE-434 Unrestricted Upload of File with Dangerous Type", "ko": "CWE-434 위험한 형식의 파일 업로드 제한 미흡"},
    ),
    StandardCategory(
        "cwe-476-null-pointer-dereference",
        {"en": "CWE-476 NULL Pointer Dereference", "ko": "CWE-476 NULL 포인터 역참조"},
    ),
    StandardCategory(
        "cwe-121-stack-buffer-overflow",
        {"en": "CWE-121 Stack-based Buffer Overflow", "ko": "CWE-121 스택 기반 버퍼 오버플로우"},
    ),
    StandardCategory(
        "cwe-502-unsafe-deserialization",
        {"en": "CWE-502 Deserialization of Untrusted Data", "ko": "CWE-502 신뢰할 수 없는 데이터 역직렬화"},
    ),
    StandardCategory(
        "cwe-122-heap-buffer-overflow",
        {"en": "CWE-122 Heap-based Buffer Overflow", "ko": "CWE-122 힙 기반 버퍼 오버플로우"},
    ),
    StandardCategory(
        "cwe-863-incorrect-authorization",
        {"en": "CWE-863 Incorrect Authorization", "ko": "CWE-863 잘못된 인가"},
    ),
    StandardCategory(
        "cwe-20-improper-input-validation",
        {"en": "CWE-20 Improper Input Validation", "ko": "CWE-20 부적절한 입력값 검증"},
    ),
    StandardCategory(
        "cwe-284-improper-access-control",
        {"en": "CWE-284 Improper Access Control", "ko": "CWE-284 부적절한 접근통제"},
    ),
    StandardCategory(
        "cwe-200-sensitive-information-exposure",
        {"en": "CWE-200 Exposure of Sensitive Information to an Unauthorized Actor", "ko": "CWE-200 비인가자에 대한 민감정보 노출"},
        scanner_categories=("secrets", "configuration"),
        rule_ids=SENSITIVE_DATA_RULE_IDS,
    ),
    StandardCategory(
        "cwe-306-missing-authentication-critical-function",
        {"en": "CWE-306 Missing Authentication for Critical Function", "ko": "CWE-306 중요 기능 인증 누락"},
    ),
    StandardCategory(
        "cwe-918-server-side-request-forgery",
        {"en": "CWE-918 Server-Side Request Forgery", "ko": "CWE-918 서버사이드 요청 위조"},
    ),
    StandardCategory(
        "cwe-77-command-injection",
        {"en": "CWE-77 Command Injection", "ko": "CWE-77 명령어 삽입"},
    ),
    StandardCategory(
        "cwe-639-authorization-bypass-user-controlled-key",
        {"en": "CWE-639 Authorization Bypass Through User-Controlled Key", "ko": "CWE-639 사용자 제어 키를 통한 인가 우회"},
    ),
    StandardCategory(
        "cwe-770-resource-allocation-without-limits",
        {"en": "CWE-770 Allocation of Resources Without Limits or Throttling", "ko": "CWE-770 제한 또는 조절 없는 자원 할당"},
    ),
)

CWE_TOP_25_2025 = SecurityStandard(
    "cwe-top-25-2025",
    {"en": "CWE Top 25:2025", "ko": "CWE Top 25:2025"},
    (
        _all_category(
            _CWE_TOP_25_2025_CATEGORIES,
            {"en": "All mapped CWE Top 25 checks", "ko": "매핑된 CWE Top 25 항목 전체"},
        ),
        *_CWE_TOP_25_2025_CATEGORIES,
    ),
)


_ISMS_P_28_CATEGORIES = (
    StandardCategory(
        "2.8.1-security-requirements-definition",
        {"en": "2.8.1 Security Requirements Definition", "ko": "2.8.1 보안 요구사항 정의"},
        scanner_categories=CATEGORIES,
        rule_ids=SECRET_RULE_IDS + DEPENDENCY_RULE_IDS + CONFIGURATION_RULE_IDS,
    ),
    StandardCategory(
        "2.8.2-security-requirements-review-testing",
        {"en": "2.8.2 Security Requirements Review and Testing", "ko": "2.8.2 보안 요구사항 검토 및 시험"},
        scanner_categories=CATEGORIES,
        rule_ids=SECRET_RULE_IDS + DEPENDENCY_RULE_IDS + CONFIGURATION_RULE_IDS,
    ),
    StandardCategory(
        "2.8.3-test-production-separation",
        {"en": "2.8.3 Test and Production Environment Separation", "ko": "2.8.3 시험과 운영 환경 분리"},
        scanner_categories=("configuration",),
        rule_ids=ERROR_HANDLING_RULE_IDS,
    ),
    StandardCategory(
        "2.8.4-test-data-security",
        {"en": "2.8.4 Test Data Security", "ko": "2.8.4 시험 데이터 보안"},
        scanner_categories=("secrets", "configuration"),
        rule_ids=SENSITIVE_DATA_RULE_IDS,
    ),
    StandardCategory(
        "2.8.5-source-program-management",
        {"en": "2.8.5 Source Program Management", "ko": "2.8.5 소스 프로그램 관리"},
        scanner_categories=("secrets", "dependencies", "configuration"),
        rule_ids=SECRET_RULE_IDS
        + (
            "config.env-file-present",
            "config.private-key-like-file",
            "dependency.node-missing-lockfile",
        ),
    ),
    StandardCategory(
        "2.8.6-production-migration",
        {"en": "2.8.6 Production Migration", "ko": "2.8.6 운영환경 이관"},
        scanner_categories=("configuration",),
        rule_ids=CONFIGURATION_RULE_IDS,
    ),
)

ISMS_P_DEVELOPMENT_SECURITY = SecurityStandard(
    "isms-p-development-security",
    {"en": "ISMS-P 2.8 Development Security", "ko": "ISMS-P 2.8 개발보안"},
    (
        _all_category(
            _ISMS_P_28_CATEGORIES,
            {"en": "All mapped ISMS-P 2.8 checks", "ko": "매핑된 ISMS-P 2.8 항목 전체"},
        ),
        *_ISMS_P_28_CATEGORIES,
    ),
)


SECURITY_STANDARDS = (
    LOCAL_STANDARD,
    OWASP_TOP_10_2025,
    OWASP_TOP_10_2021,
    CWE_TOP_25_2025,
    OWASP_API_SECURITY_2023,
    OWASP_MOBILE_TOP_10_2024,
    SW_DEV_SECURITY_49,
    ISMS_P_DEVELOPMENT_SECURITY,
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
