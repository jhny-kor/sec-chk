from __future__ import annotations

from dataclasses import dataclass, field

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
    "dependency.osv-known-vulnerability",
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

CODE_PATTERN_RULE_IDS = (
    "code.xss-dom-sink",
    "code.sql-dynamic-query",
    "code.command-injection",
    "code.path-traversal",
    "code.csrf-disabled",
    "code.auth-disabled-endpoint",
    "code.eval-user-input",
    "code.unsafe-deserialization",
    "code.ssrf-user-url",
    "code.unrestricted-file-upload",
    "code.dangerous-c-buffer-api",
    "code.unbounded-request-body",
    "code.logging-sensitive-data",
    "code.empty-exception-handler",
    "code.stack-trace-exposure",
    "code.unversioned-api-route",
    "code.insecure-temp-file",
    "code.wildcard-cors",
    "code.public-bind-all-interfaces",
    "code.insecure-cookie-settings",
    "code.directory-listing-enabled",
    "code.webdav-enabled",
    "code.legacy-board-software",
    "code.weak-hash",
    "code.xml-external-entity",
)

ACCESS_CONTROL_RULE_IDS = (
    "code.auth-disabled-endpoint",
)

AUTHENTICATION_RULE_IDS = (
    "code.auth-disabled-endpoint",
)

INJECTION_RULE_IDS = (
    "code.xss-dom-sink",
    "code.sql-dynamic-query",
    "code.command-injection",
    "code.eval-user-input",
)

INPUT_VALIDATION_RULE_IDS = (
    "code.xss-dom-sink",
    "code.sql-dynamic-query",
    "code.command-injection",
    "code.path-traversal",
    "code.eval-user-input",
    "code.ssrf-user-url",
    "code.unrestricted-file-upload",
    "code.xml-external-entity",
)

INSECURE_DESIGN_RULE_IDS = (
    "code.csrf-disabled",
    "code.auth-disabled-endpoint",
    "code.unbounded-request-body",
)

MEMORY_SAFETY_RULE_IDS = (
    "code.dangerous-c-buffer-api",
)

SENSITIVE_DATA_RULE_IDS = SECRET_RULE_IDS + (
    "config.env-file-present",
    "config.private-key-like-file",
    "code.logging-sensitive-data",
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
    "code.empty-exception-handler",
    "code.stack-trace-exposure",
)

LOGGING_MONITORING_RULE_IDS = (
    "code.logging-sensitive-data",
    "code.empty-exception-handler",
    "code.stack-trace-exposure",
)

API_INVENTORY_RULE_IDS = (
    "code.unversioned-api-route",
)

TIME_STATE_RULE_IDS = (
    "code.insecure-temp-file",
)

ENCAPSULATION_RULE_IDS = (
    "code.wildcard-cors",
    "code.public-bind-all-interfaces",
)

MISCONFIGURATION_RULE_IDS = CONFIGURATION_RULE_IDS + (
    "code.wildcard-cors",
    "code.public-bind-all-interfaces",
    "code.directory-listing-enabled",
    "code.webdav-enabled",
)

SESSION_MANAGEMENT_RULE_IDS = (
    "code.insecure-cookie-settings",
    "code.csrf-disabled",
)

CRYPTOGRAPHY_RULE_IDS = SENSITIVE_DATA_RULE_IDS + INSECURE_TRANSPORT_RULE_IDS + (
    "code.weak-hash",
)

WEB_FILE_HANDLING_RULE_IDS = (
    "code.path-traversal",
    "code.unrestricted-file-upload",
)

LEGACY_WEB_RULE_IDS = (
    "code.legacy-board-software",
)


@dataclass(frozen=True)
class StandardReference:
    labels: dict[str, str]
    url: str


@dataclass(frozen=True)
class StandardCategory:
    id: str
    labels: dict[str, str]
    scanner_categories: tuple[str, ...] = ()
    rule_ids: tuple[str, ...] = ()
    description: dict[str, str] = field(default_factory=dict)

    @property
    def supported(self) -> bool:
        return bool(self.scanner_categories)


@dataclass(frozen=True)
class SecurityStandard:
    id: str
    labels: dict[str, str]
    categories: tuple[StandardCategory, ...]
    description: dict[str, str] = field(default_factory=dict)
    coverage: dict[str, str] = field(default_factory=dict)
    references: tuple[StandardReference, ...] = ()
    coverage_level: str = "partial"


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


def _reference(en: str, ko: str, url: str) -> StandardReference:
    return StandardReference({"en": en, "ko": ko}, url)


def _text(en: str, ko: str) -> dict[str, str]:
    return {"en": en, "ko": ko}


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
        StandardCategory(
            "code",
            {"en": "Code Patterns", "ko": "코드 패턴"},
            scanner_categories=("code",),
        ),
    ),
    description=_text(
        "SecChk native rule categories for local file, dependency, configuration, and code-pattern checks.",
        "로컬 파일, 의존성, 설정, 코드 패턴을 점검하는 SecChk 기본 룰 묶음입니다.",
    ),
    coverage=_text(
        "Runs the local heuristic rules directly. It is not a replacement for full SAST, DAST, or CVE intelligence.",
        "로컬 휴리스틱 룰을 직접 실행합니다. 전체 SAST, DAST, CVE 인텔리전스를 대체하지는 않습니다.",
    ),
    references=(
        _reference("SecChk GitHub", "SecChk GitHub", "https://github.com/jhny-kor/sec-chk"),
    ),
    coverage_level="local",
)


_OWASP_TOP_10_CATEGORIES = (
    StandardCategory(
        "a01-broken-access-control",
        {"en": "A01 Broken Access Control", "ko": "A01 접근권한 취약"},
        scanner_categories=("code",),
        rule_ids=ACCESS_CONTROL_RULE_IDS,
    ),
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
    StandardCategory(
        "a03-injection",
        {"en": "A03 Injection", "ko": "A03 인젝션"},
        scanner_categories=("code",),
        rule_ids=INJECTION_RULE_IDS,
    ),
    StandardCategory(
        "a04-insecure-design",
        {"en": "A04 Insecure Design", "ko": "A04 안전하지 않은 설계"},
        scanner_categories=("code",),
        rule_ids=INSECURE_DESIGN_RULE_IDS,
    ),
    StandardCategory(
        "a05-security-misconfiguration",
        {"en": "A05 Security Misconfiguration", "ko": "A05 보안 설정 오류"},
        scanner_categories=("configuration", "code"),
        rule_ids=MISCONFIGURATION_RULE_IDS,
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
        scanner_categories=("code",),
        rule_ids=AUTHENTICATION_RULE_IDS,
    ),
    StandardCategory(
        "a08-software-data-integrity-failures",
        {"en": "A08 Software and Data Integrity Failures", "ko": "A08 소프트웨어 및 데이터 무결성 실패"},
        scanner_categories=("dependencies", "configuration", "code"),
        rule_ids=(
            "dependency.node-missing-lockfile",
            "dependency.node-insecure-url",
            "dependency.remote-shell-script",
            "dependency.python-insecure-url",
            "dependency.docker-remote-shell",
            "config.docker-add-http",
            "code.unsafe-deserialization",
        ),
    ),
    StandardCategory(
        "a09-security-logging-monitoring-failures",
        {"en": "A09 Security Logging and Monitoring Failures", "ko": "A09 보안 로깅 및 모니터링 실패"},
        scanner_categories=("code",),
        rule_ids=LOGGING_MONITORING_RULE_IDS,
    ),
    StandardCategory(
        "a10-server-side-request-forgery",
        {"en": "A10 Server-Side Request Forgery", "ko": "A10 서버사이드 요청 위조"},
        scanner_categories=("code",),
        rule_ids=("code.ssrf-user-url",),
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
    description=_text(
        "OWASP's broad web application risk categories mapped to the local rules that can produce file-based evidence.",
        "OWASP의 웹 애플리케이션 주요 위험 범주를 로컬 파일 기반 근거를 만들 수 있는 룰에 매핑한 프로파일입니다.",
    ),
    coverage=_text(
        "Partial automatic coverage. Business-logic and runtime-only risks still require review or dynamic testing.",
        "부분 자동 지원입니다. 비즈니스 로직과 실행 시점 위험은 별도 검토 또는 동적 점검이 필요합니다.",
    ),
    references=(
        _reference("OWASP Top Ten Project", "OWASP Top Ten 프로젝트", "https://owasp.org/www-project-top-ten/"),
    ),
)


_SW_DEV_SECURITY_CATEGORIES = (
    StandardCategory(
        "input-validation-expression",
        {"en": "Input Data Validation and Representation", "ko": "입력데이터 검증 및 표현"},
        scanner_categories=("code",),
        rule_ids=INPUT_VALIDATION_RULE_IDS,
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
    StandardCategory(
        "time-state",
        {"en": "Time and State", "ko": "시간 및 상태"},
        scanner_categories=("code",),
        rule_ids=TIME_STATE_RULE_IDS,
    ),
    StandardCategory(
        "error-handling",
        {"en": "Error Handling", "ko": "에러처리"},
        scanner_categories=("configuration", "code"),
        rule_ids=ERROR_HANDLING_RULE_IDS,
    ),
    StandardCategory(
        "code-error",
        {"en": "Code Error", "ko": "코드오류"},
        scanner_categories=("code",),
        rule_ids=MEMORY_SAFETY_RULE_IDS,
    ),
    StandardCategory(
        "encapsulation",
        {"en": "Encapsulation", "ko": "캡슐화"},
        scanner_categories=("code",),
        rule_ids=ENCAPSULATION_RULE_IDS,
    ),
    StandardCategory(
        "api-misuse",
        {"en": "API Misuse", "ko": "API 오용"},
        scanner_categories=("dependencies", "configuration", "code"),
        rule_ids=(
            "dependency.remote-shell-script",
            "dependency.docker-remote-shell",
            "config.docker-add-http",
            "code.unsafe-deserialization",
            "code.eval-user-input",
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
    description=_text(
        "Korean software development security weakness areas grouped into the seven secure-coding types.",
        "국내 소프트웨어 개발보안 보안약점을 7가지 시큐어코딩 유형으로 묶은 프로파일입니다.",
    ),
    coverage=_text(
        "Partial automatic coverage through local source, configuration, secret, and dependency checks.",
        "소스, 설정, 비밀값, 의존성 로컬 점검으로 부분 자동 지원합니다.",
    ),
    references=(
        _reference("KISA Software Development Security", "KISA 소프트웨어 개발보안", "https://www.kisa.or.kr/1051202"),
    ),
)


_OWASP_TOP_10_2025_CATEGORIES = (
    StandardCategory(
        "a01-broken-access-control",
        {"en": "A01 Broken Access Control", "ko": "A01 접근권한 취약"},
        scanner_categories=("code",),
        rule_ids=ACCESS_CONTROL_RULE_IDS,
    ),
    StandardCategory(
        "a02-security-misconfiguration",
        {"en": "A02 Security Misconfiguration", "ko": "A02 보안 설정 오류"},
        scanner_categories=("configuration", "code"),
        rule_ids=MISCONFIGURATION_RULE_IDS,
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
    StandardCategory(
        "a05-injection",
        {"en": "A05 Injection", "ko": "A05 인젝션"},
        scanner_categories=("code",),
        rule_ids=INJECTION_RULE_IDS,
    ),
    StandardCategory(
        "a06-insecure-design",
        {"en": "A06 Insecure Design", "ko": "A06 안전하지 않은 설계"},
        scanner_categories=("code",),
        rule_ids=INSECURE_DESIGN_RULE_IDS,
    ),
    StandardCategory(
        "a07-authentication-failures",
        {"en": "A07 Authentication Failures", "ko": "A07 인증 실패"},
        scanner_categories=("code",),
        rule_ids=AUTHENTICATION_RULE_IDS,
    ),
    StandardCategory(
        "a08-software-data-integrity-failures",
        {"en": "A08 Software or Data Integrity Failures", "ko": "A08 소프트웨어 또는 데이터 무결성 실패"},
        scanner_categories=("dependencies", "configuration", "code"),
        rule_ids=INTEGRITY_RULE_IDS + ("code.unsafe-deserialization",),
    ),
    StandardCategory(
        "a09-security-logging-alerting-failures",
        {"en": "A09 Security Logging and Alerting Failures", "ko": "A09 보안 로깅 및 알림 실패"},
        scanner_categories=("code",),
        rule_ids=LOGGING_MONITORING_RULE_IDS,
    ),
    StandardCategory(
        "a10-mishandling-exceptional-conditions",
        {"en": "A10 Mishandling of Exceptional Conditions", "ko": "A10 예외 상황 처리 부적절"},
        scanner_categories=("configuration", "code"),
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
    description=_text(
        "A local profile for the project's OWASP Top 10:2025 category set.",
        "프로젝트에 포함된 OWASP Top 10:2025 카테고리 집합을 로컬 룰에 매핑한 프로파일입니다.",
    ),
    coverage=_text(
        "Partial automatic coverage. Validate against the official OWASP project before using it as formal evidence.",
        "부분 자동 지원입니다. 공식 증적으로 쓰기 전 OWASP 공식 프로젝트 기준과 대조가 필요합니다.",
    ),
    references=(
        _reference("OWASP Top Ten Project", "OWASP Top Ten 프로젝트", "https://owasp.org/www-project-top-ten/"),
    ),
)


_OWASP_API_2023_CATEGORIES = (
    StandardCategory(
        "api1-broken-object-level-authorization",
        {"en": "API1 Broken Object Level Authorization", "ko": "API1 객체 수준 권한 부여 취약"},
        scanner_categories=("code",),
        rule_ids=ACCESS_CONTROL_RULE_IDS,
    ),
    StandardCategory(
        "api2-broken-authentication",
        {"en": "API2 Broken Authentication", "ko": "API2 인증 취약"},
        scanner_categories=("code",),
        rule_ids=AUTHENTICATION_RULE_IDS,
    ),
    StandardCategory(
        "api3-broken-object-property-level-authorization",
        {"en": "API3 Broken Object Property Level Authorization", "ko": "API3 객체 속성 수준 권한 부여 취약"},
        scanner_categories=("code",),
        rule_ids=ACCESS_CONTROL_RULE_IDS,
    ),
    StandardCategory(
        "api4-unrestricted-resource-consumption",
        {"en": "API4 Unrestricted Resource Consumption", "ko": "API4 제한 없는 리소스 사용"},
        scanner_categories=("code",),
        rule_ids=("code.unbounded-request-body",),
    ),
    StandardCategory(
        "api5-broken-function-level-authorization",
        {"en": "API5 Broken Function Level Authorization", "ko": "API5 기능 수준 권한 부여 취약"},
        scanner_categories=("code",),
        rule_ids=ACCESS_CONTROL_RULE_IDS,
    ),
    StandardCategory(
        "api6-unrestricted-access-sensitive-business-flows",
        {"en": "API6 Unrestricted Access to Sensitive Business Flows", "ko": "API6 민감 비즈니스 흐름 접근 제한 미흡"},
        scanner_categories=("code",),
        rule_ids=ACCESS_CONTROL_RULE_IDS + ("code.unbounded-request-body",),
    ),
    StandardCategory(
        "api7-server-side-request-forgery",
        {"en": "API7 Server Side Request Forgery", "ko": "API7 서버사이드 요청 위조"},
        scanner_categories=("code",),
        rule_ids=("code.ssrf-user-url",),
    ),
    StandardCategory(
        "api8-security-misconfiguration",
        {"en": "API8 Security Misconfiguration", "ko": "API8 보안 설정 오류"},
        scanner_categories=("configuration", "code"),
        rule_ids=MISCONFIGURATION_RULE_IDS,
    ),
    StandardCategory(
        "api9-improper-inventory-management",
        {"en": "API9 Improper Inventory Management", "ko": "API9 부적절한 인벤토리 관리"},
        scanner_categories=("code",),
        rule_ids=API_INVENTORY_RULE_IDS,
    ),
    StandardCategory(
        "api10-unsafe-consumption-of-apis",
        {"en": "API10 Unsafe Consumption of APIs", "ko": "API10 안전하지 않은 API 사용"},
        scanner_categories=("dependencies", "configuration", "code"),
        rule_ids=INSECURE_TRANSPORT_RULE_IDS + REMOTE_EXECUTION_RULE_IDS + ("code.ssrf-user-url",),
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
    description=_text(
        "OWASP API Security Top 10:2023 risks mapped to local API route, authorization, SSRF, resource, and configuration checks.",
        "OWASP API Security Top 10:2023 위험을 API 라우트, 인가, SSRF, 리소스, 설정 로컬 점검에 매핑한 프로파일입니다.",
    ),
    coverage=_text(
        "Partial automatic coverage. Object-level authorization and business-flow abuse require design and runtime testing.",
        "부분 자동 지원입니다. 객체 수준 인가와 비즈니스 흐름 남용은 설계 검토와 실행 점검이 필요합니다.",
    ),
    references=(
        _reference("OWASP API Security Project", "OWASP API Security 프로젝트", "https://owasp.org/API-Security/"),
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
        scanner_categories=("code",),
        rule_ids=AUTHENTICATION_RULE_IDS,
    ),
    StandardCategory(
        "m4-insufficient-input-output-validation",
        {"en": "M4 Insufficient Input/Output Validation", "ko": "M4 입출력 검증 부족"},
        scanner_categories=("code",),
        rule_ids=INPUT_VALIDATION_RULE_IDS,
    ),
    StandardCategory(
        "m5-insecure-communication",
        {"en": "M5 Insecure Communication", "ko": "M5 안전하지 않은 통신"},
        scanner_categories=("dependencies", "configuration"),
        rule_ids=INSECURE_TRANSPORT_RULE_IDS,
    ),
    StandardCategory(
        "m6-inadequate-privacy-controls",
        {"en": "M6 Inadequate Privacy Controls", "ko": "M6 부적절한 개인정보 보호 통제"},
        scanner_categories=("secrets", "configuration"),
        rule_ids=SENSITIVE_DATA_RULE_IDS,
    ),
    StandardCategory("m7-insufficient-binary-protections", {"en": "M7 Insufficient Binary Protections", "ko": "M7 바이너리 보호 부족"}),
    StandardCategory(
        "m8-security-misconfiguration",
        {"en": "M8 Security Misconfiguration", "ko": "M8 보안 설정 오류"},
        scanner_categories=("configuration", "code"),
        rule_ids=MISCONFIGURATION_RULE_IDS,
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
    description=_text(
        "OWASP mobile application risk categories mapped where source and configuration evidence is available.",
        "모바일 앱 위험 범주 중 소스와 설정 근거가 있는 항목을 로컬 룰에 매핑한 프로파일입니다.",
    ),
    coverage=_text(
        "Partial automatic coverage. Binary protection, platform behavior, and device-state checks need mobile-specific tooling.",
        "부분 자동 지원입니다. 바이너리 보호, 플랫폼 동작, 기기 상태 점검은 모바일 전용 도구가 필요합니다.",
    ),
    references=(
        _reference("OWASP Mobile Application Security", "OWASP Mobile Application Security", "https://owasp.org/www-project-mobile-top-10/"),
    ),
)


_CWE_TOP_25_2025_CATEGORIES = (
    StandardCategory(
        "cwe-79-cross-site-scripting",
        {"en": "CWE-79 Cross-site Scripting", "ko": "CWE-79 크로스사이트 스크립팅"},
        scanner_categories=("code",),
        rule_ids=("code.xss-dom-sink",),
    ),
    StandardCategory(
        "cwe-89-sql-injection",
        {"en": "CWE-89 SQL Injection", "ko": "CWE-89 SQL 삽입"},
        scanner_categories=("code",),
        rule_ids=("code.sql-dynamic-query",),
    ),
    StandardCategory(
        "cwe-352-cross-site-request-forgery",
        {"en": "CWE-352 Cross-Site Request Forgery", "ko": "CWE-352 크로스사이트 요청 위조"},
        scanner_categories=("code",),
        rule_ids=("code.csrf-disabled",),
    ),
    StandardCategory(
        "cwe-862-missing-authorization",
        {"en": "CWE-862 Missing Authorization", "ko": "CWE-862 인가 누락"},
        scanner_categories=("code",),
        rule_ids=ACCESS_CONTROL_RULE_IDS,
    ),
    StandardCategory(
        "cwe-787-out-of-bounds-write",
        {"en": "CWE-787 Out-of-bounds Write", "ko": "CWE-787 범위 밖 쓰기"},
        scanner_categories=("code",),
        rule_ids=MEMORY_SAFETY_RULE_IDS,
    ),
    StandardCategory(
        "cwe-22-path-traversal",
        {"en": "CWE-22 Path Traversal", "ko": "CWE-22 경로 조작"},
        scanner_categories=("code",),
        rule_ids=("code.path-traversal",),
    ),
    StandardCategory(
        "cwe-416-use-after-free",
        {"en": "CWE-416 Use After Free", "ko": "CWE-416 해제 후 사용"},
    ),
    StandardCategory(
        "cwe-125-out-of-bounds-read",
        {"en": "CWE-125 Out-of-bounds Read", "ko": "CWE-125 범위 밖 읽기"},
        scanner_categories=("code",),
        rule_ids=MEMORY_SAFETY_RULE_IDS,
    ),
    StandardCategory(
        "cwe-78-os-command-injection",
        {"en": "CWE-78 OS Command Injection", "ko": "CWE-78 운영체제 명령어 삽입"},
        scanner_categories=("code",),
        rule_ids=("code.command-injection",),
    ),
    StandardCategory(
        "cwe-94-code-injection",
        {"en": "CWE-94 Code Injection", "ko": "CWE-94 코드 삽입"},
        scanner_categories=("code",),
        rule_ids=("code.eval-user-input",),
    ),
    StandardCategory(
        "cwe-120-classic-buffer-overflow",
        {"en": "CWE-120 Classic Buffer Overflow", "ko": "CWE-120 크기 검증 없는 버퍼 복사"},
        scanner_categories=("code",),
        rule_ids=MEMORY_SAFETY_RULE_IDS,
    ),
    StandardCategory(
        "cwe-434-dangerous-file-upload",
        {"en": "CWE-434 Unrestricted Upload of File with Dangerous Type", "ko": "CWE-434 위험한 형식의 파일 업로드 제한 미흡"},
        scanner_categories=("code",),
        rule_ids=("code.unrestricted-file-upload",),
    ),
    StandardCategory(
        "cwe-476-null-pointer-dereference",
        {"en": "CWE-476 NULL Pointer Dereference", "ko": "CWE-476 NULL 포인터 역참조"},
    ),
    StandardCategory(
        "cwe-121-stack-buffer-overflow",
        {"en": "CWE-121 Stack-based Buffer Overflow", "ko": "CWE-121 스택 기반 버퍼 오버플로우"},
        scanner_categories=("code",),
        rule_ids=MEMORY_SAFETY_RULE_IDS,
    ),
    StandardCategory(
        "cwe-502-unsafe-deserialization",
        {"en": "CWE-502 Deserialization of Untrusted Data", "ko": "CWE-502 신뢰할 수 없는 데이터 역직렬화"},
        scanner_categories=("code",),
        rule_ids=("code.unsafe-deserialization",),
    ),
    StandardCategory(
        "cwe-122-heap-buffer-overflow",
        {"en": "CWE-122 Heap-based Buffer Overflow", "ko": "CWE-122 힙 기반 버퍼 오버플로우"},
        scanner_categories=("code",),
        rule_ids=MEMORY_SAFETY_RULE_IDS,
    ),
    StandardCategory(
        "cwe-863-incorrect-authorization",
        {"en": "CWE-863 Incorrect Authorization", "ko": "CWE-863 잘못된 인가"},
        scanner_categories=("code",),
        rule_ids=ACCESS_CONTROL_RULE_IDS,
    ),
    StandardCategory(
        "cwe-20-improper-input-validation",
        {"en": "CWE-20 Improper Input Validation", "ko": "CWE-20 부적절한 입력값 검증"},
        scanner_categories=("code",),
        rule_ids=INPUT_VALIDATION_RULE_IDS,
    ),
    StandardCategory(
        "cwe-284-improper-access-control",
        {"en": "CWE-284 Improper Access Control", "ko": "CWE-284 부적절한 접근통제"},
        scanner_categories=("code",),
        rule_ids=ACCESS_CONTROL_RULE_IDS,
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
        scanner_categories=("code",),
        rule_ids=AUTHENTICATION_RULE_IDS,
    ),
    StandardCategory(
        "cwe-918-server-side-request-forgery",
        {"en": "CWE-918 Server-Side Request Forgery", "ko": "CWE-918 서버사이드 요청 위조"},
        scanner_categories=("code",),
        rule_ids=("code.ssrf-user-url",),
    ),
    StandardCategory(
        "cwe-77-command-injection",
        {"en": "CWE-77 Command Injection", "ko": "CWE-77 명령어 삽입"},
        scanner_categories=("code",),
        rule_ids=("code.command-injection",),
    ),
    StandardCategory(
        "cwe-639-authorization-bypass-user-controlled-key",
        {"en": "CWE-639 Authorization Bypass Through User-Controlled Key", "ko": "CWE-639 사용자 제어 키를 통한 인가 우회"},
        scanner_categories=("code",),
        rule_ids=ACCESS_CONTROL_RULE_IDS,
    ),
    StandardCategory(
        "cwe-770-resource-allocation-without-limits",
        {"en": "CWE-770 Allocation of Resources Without Limits or Throttling", "ko": "CWE-770 제한 또는 조절 없는 자원 할당"},
        scanner_categories=("code",),
        rule_ids=("code.unbounded-request-body",),
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
    description=_text(
        "MITRE CWE Top 25:2025 weaknesses mapped to the local rules where lightweight evidence is possible.",
        "MITRE CWE Top 25:2025 약점 중 경량 로컬 근거를 만들 수 있는 항목을 매핑한 프로파일입니다.",
    ),
    coverage=_text(
        "Partial automatic coverage. Deep memory lifetime and null-dereference analysis remains unsupported.",
        "부분 자동 지원입니다. 메모리 수명과 NULL 역참조의 깊은 분석은 아직 지원하지 않습니다.",
    ),
    references=(
        _reference("MITRE CWE Top 25:2025", "MITRE CWE Top 25:2025", "https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html"),
    ),
)


_ISMS_P_28_CATEGORIES = (
    StandardCategory(
        "2.8.1-security-requirements-definition",
        {"en": "2.8.1 Security Requirements Definition", "ko": "2.8.1 보안 요구사항 정의"},
        scanner_categories=CATEGORIES,
        rule_ids=SECRET_RULE_IDS + DEPENDENCY_RULE_IDS + CONFIGURATION_RULE_IDS + CODE_PATTERN_RULE_IDS,
    ),
    StandardCategory(
        "2.8.2-security-requirements-review-testing",
        {"en": "2.8.2 Security Requirements Review and Testing", "ko": "2.8.2 보안 요구사항 검토 및 시험"},
        scanner_categories=CATEGORIES,
        rule_ids=SECRET_RULE_IDS + DEPENDENCY_RULE_IDS + CONFIGURATION_RULE_IDS + CODE_PATTERN_RULE_IDS,
    ),
    StandardCategory(
        "2.8.3-test-production-separation",
        {"en": "2.8.3 Test and Production Environment Separation", "ko": "2.8.3 시험과 운영 환경 분리"},
        scanner_categories=("configuration", "code"),
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
        scanner_categories=("secrets", "dependencies", "configuration", "code"),
        rule_ids=SECRET_RULE_IDS
        + (
            "config.env-file-present",
            "config.private-key-like-file",
            "dependency.node-missing-lockfile",
        )
        + CODE_PATTERN_RULE_IDS,
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
    description=_text(
        "ISMS-P development-security control area mapped to local evidence for secure requirements, testing, test data, source management, and migration hygiene.",
        "ISMS-P 개발보안 통제 영역을 보안 요구사항, 시험, 시험 데이터, 소스 관리, 운영 이관 위생의 로컬 근거에 매핑한 프로파일입니다.",
    ),
    coverage=_text(
        "Partial automatic coverage. Certification evidence also requires process documents, approvals, and operating records.",
        "부분 자동 지원입니다. 인증 증적에는 프로세스 문서, 승인, 운영 기록도 필요합니다.",
    ),
    references=(
        _reference("KISA ISMS-P", "KISA ISMS-P", "https://isms.kisa.or.kr/"),
    ),
)


CWE_SANS_TOP_25_2025 = SecurityStandard(
    "cwe-sans-top-25-2025",
    {"en": "CWE/SANS Top 25:2025", "ko": "CWE/SANS Top 25:2025"},
    (
        _all_category(
            _CWE_TOP_25_2025_CATEGORIES,
            {"en": "All mapped CWE/SANS Top 25 checks", "ko": "매핑된 CWE/SANS Top 25 항목 전체"},
        ),
        *_CWE_TOP_25_2025_CATEGORIES,
    ),
    description=_text(
        "The SANS-facing Top 25 software error view backed by MITRE CWE Top 25 data.",
        "MITRE CWE Top 25 데이터를 기반으로 SANS에서 소개하는 위험한 소프트웨어 오류 Top 25 프로파일입니다.",
    ),
    coverage=CWE_TOP_25_2025.coverage,
    references=(
        _reference("MITRE CWE Top 25:2025", "MITRE CWE Top 25:2025", "https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html"),
        _reference("SANS Top 25 Software Errors", "SANS Top 25 Software Errors", "https://www.sans.org/top25-software-errors/"),
    ),
)


_CWE_GENERAL_CATEGORIES = (
    StandardCategory(
        "injection",
        {"en": "Injection Weaknesses", "ko": "인젝션 약점"},
        scanner_categories=("code",),
        rule_ids=INJECTION_RULE_IDS + ("code.xml-external-entity",),
    ),
    StandardCategory(
        "auth-access-control",
        {"en": "Authentication and Access Control", "ko": "인증 및 접근통제"},
        scanner_categories=("code",),
        rule_ids=AUTHENTICATION_RULE_IDS + ACCESS_CONTROL_RULE_IDS + SESSION_MANAGEMENT_RULE_IDS,
    ),
    StandardCategory(
        "file-resource-handling",
        {"en": "File and Resource Handling", "ko": "파일 및 리소스 처리"},
        scanner_categories=("code",),
        rule_ids=WEB_FILE_HANDLING_RULE_IDS + ("code.insecure-temp-file", "code.unbounded-request-body"),
    ),
    StandardCategory(
        "crypto-sensitive-data",
        {"en": "Cryptography and Sensitive Data", "ko": "암호 및 민감정보"},
        scanner_categories=("secrets", "configuration", "dependencies", "code"),
        rule_ids=CRYPTOGRAPHY_RULE_IDS,
    ),
    StandardCategory(
        "memory-safety",
        {"en": "Memory Safety", "ko": "메모리 안전"},
        scanner_categories=("code",),
        rule_ids=MEMORY_SAFETY_RULE_IDS,
    ),
    StandardCategory(
        "deserialization-ssrf",
        {"en": "Deserialization and SSRF", "ko": "역직렬화 및 SSRF"},
        scanner_categories=("code",),
        rule_ids=("code.unsafe-deserialization", "code.ssrf-user-url"),
    ),
    StandardCategory(
        "configuration",
        {"en": "Configuration Weaknesses", "ko": "설정 약점"},
        scanner_categories=("configuration", "code"),
        rule_ids=MISCONFIGURATION_RULE_IDS,
    ),
)

CWE_GENERAL = SecurityStandard(
    "cwe",
    {"en": "CWE Mapped Weaknesses", "ko": "CWE 매핑 약점"},
    (
        _all_category(
            _CWE_GENERAL_CATEGORIES,
            {"en": "All mapped CWE checks", "ko": "매핑된 CWE 항목 전체"},
        ),
        *_CWE_GENERAL_CATEGORIES,
    ),
    description=_text(
        "A broad CWE-oriented grouping of local weakness checks beyond the annual Top 25 list.",
        "연간 Top 25를 넘어 로컬 약점 점검을 CWE 관점으로 묶은 범용 프로파일입니다.",
    ),
    coverage=_text(
        "Partial automatic coverage based on local rules; it does not enumerate every CWE entry.",
        "로컬 룰 기반 부분 자동 지원입니다. 모든 CWE 항목을 열거하지는 않습니다.",
    ),
    references=(
        _reference("MITRE CWE", "MITRE CWE", "https://cwe.mitre.org/"),
    ),
)


KISA_SECURE_CODING_GUIDE = SecurityStandard(
    "kisa-secure-coding-guide",
    {"en": "KISA Secure Coding Guide", "ko": "KISA 시큐어코딩 가이드"},
    (
        _all_category(
            _SW_DEV_SECURITY_CATEGORIES,
            {"en": "All mapped secure-coding guide checks", "ko": "매핑된 시큐어코딩 가이드 항목 전체"},
        ),
        *_SW_DEV_SECURITY_CATEGORIES,
    ),
    description=_text(
        "KISA secure-coding guidance mapped to the seven local software development security categories.",
        "KISA 시큐어코딩 가이드를 7가지 소프트웨어 개발보안 유형의 로컬 점검에 매핑한 프로파일입니다.",
    ),
    coverage=SW_DEV_SECURITY_49.coverage,
    references=(
        _reference("KISA Secure Coding Guides", "KISA 시큐어코딩 가이드", "https://search.kisa.or.kr/search/search.jsp?keyword=%EC%8B%9C%ED%81%90%EC%96%B4%EC%BD%94%EB%94%A9"),
        _reference("KISA Python Secure Coding Guide", "KISA Python 시큐어코딩 가이드", "https://www.kisa.or.kr/2060204/form?postSeq=13"),
    ),
)

SW_DEV_SECURITY_7_TYPES = SecurityStandard(
    "sw-dev-security-7-types",
    {"en": "Korea SW Development Security 7 Types", "ko": "소프트웨어 개발보안 7가지 유형"},
    (
        _all_category(
            _SW_DEV_SECURITY_CATEGORIES,
            {"en": "All mapped SW development security type checks", "ko": "매핑된 SW 개발보안 유형 전체"},
        ),
        *_SW_DEV_SECURITY_CATEGORIES,
    ),
    description=_text(
        "The seven secure-coding type taxonomy: input validation, security features, time/state, error handling, code error, encapsulation, and API misuse.",
        "입력데이터 검증, 보안기능, 시간 및 상태, 에러처리, 코드오류, 캡슐화, API 오용의 7가지 유형 프로파일입니다.",
    ),
    coverage=SW_DEV_SECURITY_49.coverage,
    references=SW_DEV_SECURITY_49.references,
)


_NCSC_WEB_8_CATEGORIES = (
    StandardCategory(
        "directory-listing",
        {"en": "Directory Listing", "ko": "디렉터리 리스팅"},
        scanner_categories=("code",),
        rule_ids=("code.directory-listing-enabled",),
    ),
    StandardCategory(
        "file-download",
        {"en": "File Download", "ko": "파일 다운로드"},
        scanner_categories=("code",),
        rule_ids=("code.path-traversal",),
    ),
    StandardCategory(
        "xss",
        {"en": "Cross-site Scripting", "ko": "크로스사이트 스크립팅"},
        scanner_categories=("code",),
        rule_ids=("code.xss-dom-sink",),
    ),
    StandardCategory(
        "file-upload",
        {"en": "File Upload", "ko": "파일 업로드"},
        scanner_categories=("code",),
        rule_ids=("code.unrestricted-file-upload",),
    ),
    StandardCategory(
        "webdav",
        {"en": "WebDAV", "ko": "WebDAV"},
        scanner_categories=("code",),
        rule_ids=("code.webdav-enabled",),
    ),
    StandardCategory(
        "technote",
        {"en": "Technote", "ko": "테크노트"},
        scanner_categories=("code",),
        rule_ids=LEGACY_WEB_RULE_IDS,
    ),
    StandardCategory(
        "zeroboard",
        {"en": "Zeroboard", "ko": "제로보드"},
        scanner_categories=("code",),
        rule_ids=LEGACY_WEB_RULE_IDS,
    ),
    StandardCategory(
        "sql-injection",
        {"en": "SQL Injection", "ko": "SQL 삽입"},
        scanner_categories=("code",),
        rule_ids=("code.sql-dynamic-query",),
    ),
)

NCSC_WEB_8 = SecurityStandard(
    "ncsc-web-8",
    {"en": "NCSC Web 8 Vulnerabilities", "ko": "국정원 웹 8대 보안취약점"},
    (
        _all_category(
            _NCSC_WEB_8_CATEGORIES,
            {"en": "All mapped NCSC Web 8 checks", "ko": "매핑된 국정원 웹 8대 항목 전체"},
        ),
        *_NCSC_WEB_8_CATEGORIES,
    ),
    description=_text(
        "Legacy Korean NCSC website vulnerability categories frequently referenced in public-sector web checks.",
        "공공 웹 점검에서 자주 참조되는 국가사이버안전센터 홈페이지 8대 취약점 프로파일입니다.",
    ),
    coverage=_text(
        "Partial automatic coverage. Active web probing and legacy product version validation still require DAST or manual testing.",
        "부분 자동 지원입니다. 실제 웹 요청 기반 점검과 레거시 제품 버전 확인은 DAST 또는 수동 점검이 필요합니다.",
    ),
    references=(
        _reference("NCSC", "국가사이버안보센터", "https://www.ncsc.go.kr/"),
    ),
)


_E_FINANCE_WEB_8_CATEGORIES = (
    StandardCategory(
        "sql-injection",
        {"en": "SQL Injection", "ko": "SQL 삽입"},
        scanner_categories=("code",),
        rule_ids=("code.sql-dynamic-query",),
    ),
    StandardCategory(
        "upload",
        {"en": "Upload Vulnerability", "ko": "업로드 취약점"},
        scanner_categories=("code",),
        rule_ids=("code.unrestricted-file-upload",),
    ),
    StandardCategory(
        "cookie-session",
        {"en": "Cookie and Session Management", "ko": "쿠키 및 세션 관리"},
        scanner_categories=("code",),
        rule_ids=SESSION_MANAGEMENT_RULE_IDS,
    ),
    StandardCategory(
        "xss",
        {"en": "Cross-site Scripting", "ko": "크로스사이트 스크립팅"},
        scanner_categories=("code",),
        rule_ids=("code.xss-dom-sink",),
    ),
    StandardCategory(
        "buffer-overflow",
        {"en": "Buffer Overflow", "ko": "버퍼 오버플로우"},
        scanner_categories=("code",),
        rule_ids=MEMORY_SAFETY_RULE_IDS,
    ),
    StandardCategory(
        "parameter",
        {"en": "Improper Parameters", "ko": "부적절한 파라미터"},
        scanner_categories=("code",),
        rule_ids=INPUT_VALIDATION_RULE_IDS,
    ),
    StandardCategory(
        "access-control",
        {"en": "Access Control", "ko": "접근통제"},
        scanner_categories=("code",),
        rule_ids=ACCESS_CONTROL_RULE_IDS,
    ),
    StandardCategory(
        "server-configuration",
        {"en": "Server Configuration", "ko": "서버 환경설정"},
        scanner_categories=("configuration", "code"),
        rule_ids=MISCONFIGURATION_RULE_IDS,
    ),
)

ELECTRONIC_FINANCIAL_SUPERVISION_8 = SecurityStandard(
    "electronic-financial-supervision-8",
    {"en": "Electronic Financial Supervision 8 Web Vulnerabilities", "ko": "전자금융감독규정 8대 취약점"},
    (
        _all_category(
            _E_FINANCE_WEB_8_CATEGORIES,
            {"en": "All mapped electronic-finance web checks", "ko": "매핑된 전자금융 8대 항목 전체"},
        ),
        *_E_FINANCE_WEB_8_CATEGORIES,
    ),
    description=_text(
        "Public web-server vulnerability categories referenced by Korean electronic financial supervision rules and related guidance.",
        "전자금융감독규정 및 관련 세칙에서 언급되는 공개용 웹서버 해킹 대응 항목을 매핑한 프로파일입니다.",
    ),
    coverage=_text(
        "Partial automatic coverage. Formal compliance requires infrastructure, web runtime, and operational evidence beyond source files.",
        "부분 자동 지원입니다. 공식 준수에는 소스 파일 외 인프라, 웹 런타임, 운영 증적이 필요합니다.",
    ),
    references=(
        _reference("Korean Law Information Center", "국가법령정보센터", "https://www.law.go.kr/LSW/admRulInfoP.do?admRulSeq=2100000274812&chrClsCd=010201"),
    ),
)


_OWASP_ASVS_5_CATEGORIES = (
    StandardCategory("encoding-sanitization", {"en": "Encoding and Sanitization", "ko": "인코딩 및 정제"}, scanner_categories=("code",), rule_ids=INJECTION_RULE_IDS + ("code.xml-external-entity",)),
    StandardCategory("validation", {"en": "Validation", "ko": "검증"}, scanner_categories=("code",), rule_ids=INPUT_VALIDATION_RULE_IDS),
    StandardCategory("auth-session", {"en": "Authentication and Session", "ko": "인증 및 세션"}, scanner_categories=("code",), rule_ids=AUTHENTICATION_RULE_IDS + SESSION_MANAGEMENT_RULE_IDS),
    StandardCategory("access-control", {"en": "Access Control", "ko": "접근통제"}, scanner_categories=("code",), rule_ids=ACCESS_CONTROL_RULE_IDS),
    StandardCategory("data-protection", {"en": "Data Protection and Cryptography", "ko": "데이터 보호 및 암호"}, scanner_categories=("secrets", "configuration", "dependencies", "code"), rule_ids=CRYPTOGRAPHY_RULE_IDS),
    StandardCategory("configuration", {"en": "Configuration", "ko": "설정"}, scanner_categories=("configuration", "code"), rule_ids=MISCONFIGURATION_RULE_IDS),
    StandardCategory("api-web-service", {"en": "API and Web Service", "ko": "API 및 웹 서비스"}, scanner_categories=("code",), rule_ids=API_INVENTORY_RULE_IDS + ("code.ssrf-user-url", "code.wildcard-cors")),
    StandardCategory("error-logging", {"en": "Error Handling and Logging", "ko": "에러 처리 및 로깅"}, scanner_categories=("configuration", "code"), rule_ids=ERROR_HANDLING_RULE_IDS + LOGGING_MONITORING_RULE_IDS),
    StandardCategory("supply-chain", {"en": "Supply Chain", "ko": "공급망"}, scanner_categories=("dependencies", "configuration"), rule_ids=SUPPLY_CHAIN_RULE_IDS + INTEGRITY_RULE_IDS),
)

OWASP_ASVS_5 = SecurityStandard(
    "owasp-asvs-5",
    {"en": "OWASP ASVS 5.0", "ko": "OWASP ASVS 5.0"},
    (
        _all_category(_OWASP_ASVS_5_CATEGORIES, {"en": "All mapped ASVS checks", "ko": "매핑된 ASVS 항목 전체"}),
        *_OWASP_ASVS_5_CATEGORIES,
    ),
    description=_text(
        "OWASP Application Security Verification Standard requirements grouped into locally checkable control areas.",
        "OWASP Application Security Verification Standard 요구사항 중 로컬로 점검 가능한 통제 영역을 묶은 프로파일입니다.",
    ),
    coverage=_text(
        "Partial automatic coverage. ASVS is a verification standard and many requirements need design review, tests, and runtime evidence.",
        "부분 자동 지원입니다. ASVS는 검증 표준이므로 다수 요구사항은 설계 검토, 테스트, 런타임 증적이 필요합니다.",
    ),
    references=(
        _reference("OWASP ASVS", "OWASP ASVS", "https://owasp.org/www-project-application-security-verification-standard/"),
    ),
)


_OWASP_WSTG_CATEGORIES = (
    StandardCategory("config-deployment", {"en": "Configuration and Deployment", "ko": "설정 및 배포"}, scanner_categories=("configuration", "code"), rule_ids=MISCONFIGURATION_RULE_IDS),
    StandardCategory("authentication", {"en": "Authentication", "ko": "인증"}, scanner_categories=("code",), rule_ids=AUTHENTICATION_RULE_IDS),
    StandardCategory("authorization", {"en": "Authorization", "ko": "인가"}, scanner_categories=("code",), rule_ids=ACCESS_CONTROL_RULE_IDS),
    StandardCategory("session-management", {"en": "Session Management", "ko": "세션 관리"}, scanner_categories=("code",), rule_ids=SESSION_MANAGEMENT_RULE_IDS),
    StandardCategory("input-validation", {"en": "Input Validation", "ko": "입력값 검증"}, scanner_categories=("code",), rule_ids=INPUT_VALIDATION_RULE_IDS + ("code.xml-external-entity",)),
    StandardCategory("error-handling", {"en": "Error Handling", "ko": "에러 처리"}, scanner_categories=("configuration", "code"), rule_ids=ERROR_HANDLING_RULE_IDS),
    StandardCategory("weak-cryptography", {"en": "Weak Cryptography", "ko": "약한 암호"}, scanner_categories=("secrets", "configuration", "dependencies", "code"), rule_ids=CRYPTOGRAPHY_RULE_IDS),
    StandardCategory("api-testing", {"en": "API Testing", "ko": "API 테스트"}, scanner_categories=("code",), rule_ids=API_INVENTORY_RULE_IDS + ("code.ssrf-user-url", "code.unbounded-request-body")),
)

OWASP_WSTG = SecurityStandard(
    "owasp-wstg",
    {"en": "OWASP WSTG", "ko": "OWASP WSTG"},
    (
        _all_category(_OWASP_WSTG_CATEGORIES, {"en": "All mapped WSTG checks", "ko": "매핑된 WSTG 항목 전체"}),
        *_OWASP_WSTG_CATEGORIES,
    ),
    description=_text(
        "OWASP Web Security Testing Guide areas mapped to the local evidence that static scanning can collect.",
        "OWASP Web Security Testing Guide 영역 중 정적 로컬 스캔으로 근거를 수집할 수 있는 항목을 매핑한 프로파일입니다.",
    ),
    coverage=_text(
        "Partial automatic coverage. WSTG is primarily a web testing methodology and needs live-target testing for full coverage.",
        "부분 자동 지원입니다. WSTG는 웹 테스트 방법론이므로 전체 지원에는 실제 대상 웹 점검이 필요합니다.",
    ),
    references=(
        _reference("OWASP WSTG", "OWASP WSTG", "https://owasp.org/www-project-web-security-testing-guide/"),
    ),
)


_NIST_SSDF_CATEGORIES = (
    StandardCategory("protect-software", {"en": "Protect the Software", "ko": "소프트웨어 보호"}, scanner_categories=("secrets", "dependencies", "configuration"), rule_ids=SENSITIVE_DATA_RULE_IDS + INTEGRITY_RULE_IDS),
    StandardCategory("produce-well-secured-software", {"en": "Produce Well-Secured Software", "ko": "안전한 소프트웨어 생산"}, scanner_categories=("configuration", "code"), rule_ids=CONFIGURATION_RULE_IDS + CODE_PATTERN_RULE_IDS),
    StandardCategory("verify-security", {"en": "Verify Security", "ko": "보안 검증"}, scanner_categories=CATEGORIES, rule_ids=SECRET_RULE_IDS + DEPENDENCY_RULE_IDS + CONFIGURATION_RULE_IDS + CODE_PATTERN_RULE_IDS),
    StandardCategory("respond-vulnerabilities", {"en": "Respond to Vulnerabilities", "ko": "취약점 대응"}, scanner_categories=("dependencies",), rule_ids=DEPENDENCY_RULE_IDS),
)

NIST_SSDF = SecurityStandard(
    "nist-ssdf-sp800-218",
    {"en": "NIST SSDF SP 800-218", "ko": "NIST SSDF SP 800-218"},
    (
        _all_category(_NIST_SSDF_CATEGORIES, {"en": "All mapped SSDF checks", "ko": "매핑된 SSDF 항목 전체"}),
        *_NIST_SSDF_CATEGORIES,
    ),
    description=_text(
        "NIST Secure Software Development Framework practices mapped to local evidence for secure development and vulnerability response.",
        "NIST Secure Software Development Framework 실천항목을 안전한 개발과 취약점 대응의 로컬 근거에 매핑한 프로파일입니다.",
    ),
    coverage=_text(
        "Partial automatic coverage. SSDF also needs organizational process evidence, attestations, and supplier management records.",
        "부분 자동 지원입니다. SSDF는 조직 프로세스 증적, 증명, 공급자 관리 기록도 필요합니다.",
    ),
    references=(
        _reference("NIST SP 800-218", "NIST SP 800-218", "https://csrc.nist.gov/pubs/sp/800/218/final"),
    ),
)


_OWASP_SAMM_CATEGORIES = (
    StandardCategory(
        "design-security-requirements",
        {"en": "Design: Security Requirements", "ko": "설계: 보안 요구사항"},
        scanner_categories=CATEGORIES,
        rule_ids=SECRET_RULE_IDS + DEPENDENCY_RULE_IDS + CONFIGURATION_RULE_IDS + CODE_PATTERN_RULE_IDS,
    ),
    StandardCategory(
        "implementation-secure-build",
        {"en": "Implementation: Secure Build", "ko": "구현: 안전한 빌드"},
        scanner_categories=("dependencies", "configuration", "code"),
        rule_ids=SUPPLY_CHAIN_RULE_IDS + INTEGRITY_RULE_IDS + MISCONFIGURATION_RULE_IDS + CODE_PATTERN_RULE_IDS,
    ),
    StandardCategory(
        "implementation-defect-management",
        {"en": "Implementation: Defect Management", "ko": "구현: 결함 관리"},
        scanner_categories=("dependencies", "code"),
        rule_ids=DEPENDENCY_RULE_IDS + CODE_PATTERN_RULE_IDS,
    ),
    StandardCategory(
        "verification-security-testing",
        {"en": "Verification: Security Testing", "ko": "검증: 보안 테스트"},
        scanner_categories=CATEGORIES,
        rule_ids=SECRET_RULE_IDS + DEPENDENCY_RULE_IDS + CONFIGURATION_RULE_IDS + CODE_PATTERN_RULE_IDS,
    ),
    StandardCategory(
        "operations-environment-management",
        {"en": "Operations: Environment Management", "ko": "운영: 환경 관리"},
        scanner_categories=("configuration", "dependencies", "code"),
        rule_ids=MISCONFIGURATION_RULE_IDS + INTEGRITY_RULE_IDS + ERROR_HANDLING_RULE_IDS,
    ),
)

OWASP_SAMM_2 = SecurityStandard(
    "owasp-samm-2",
    {"en": "OWASP SAMM 2", "ko": "OWASP SAMM 2"},
    (
        _all_category(_OWASP_SAMM_CATEGORIES, {"en": "All mapped SAMM checks", "ko": "매핑된 SAMM 항목 전체"}),
        *_OWASP_SAMM_CATEGORIES,
    ),
    description=_text(
        "OWASP Software Assurance Maturity Model practices mapped to local evidence for secure design, implementation, verification, and operations.",
        "OWASP Software Assurance Maturity Model 실천항목을 보안 설계, 구현, 검증, 운영의 로컬 근거에 매핑한 프로파일입니다.",
    ),
    coverage=_text(
        "Partial automatic coverage. SAMM maturity assessment also requires process, people, governance, and program evidence.",
        "부분 자동 지원입니다. SAMM 성숙도 평가는 프로세스, 인력, 거버넌스, 프로그램 증적도 필요합니다.",
    ),
    references=(
        _reference("OWASP SAMM", "OWASP SAMM", "https://owasp.org/www-project-samm/"),
        _reference("OWASP SAMM Model", "OWASP SAMM 모델", "https://owaspsamm.org/model/"),
    ),
)


_OWASP_DEPENDENCY_CHECK_CATEGORIES = (
    StandardCategory("manifest-health", {"en": "Manifest and Lockfile Health", "ko": "매니페스트 및 락파일 위생"}, scanner_categories=("dependencies",), rule_ids=("dependency.package-json-invalid", "dependency.node-missing-lockfile")),
    StandardCategory("version-hygiene", {"en": "Version Pinning Hygiene", "ko": "버전 고정 위생"}, scanner_categories=("dependencies",), rule_ids=("dependency.node-unbounded-version", "dependency.python-unpinned-requirement", "dependency.python-wildcard-version", "dependency.docker-unpinned-base")),
    StandardCategory("insecure-sources", {"en": "Insecure Dependency Sources", "ko": "안전하지 않은 의존성 소스"}, scanner_categories=("dependencies", "configuration"), rule_ids=INSECURE_TRANSPORT_RULE_IDS + REMOTE_EXECUTION_RULE_IDS),
)

OWASP_DEPENDENCY_CHECK_BASELINE = SecurityStandard(
    "owasp-dependency-check-baseline",
    {"en": "OWASP Dependency-Check Baseline", "ko": "OWASP Dependency-Check 기준"},
    (
        _all_category(_OWASP_DEPENDENCY_CHECK_CATEGORIES, {"en": "All mapped Dependency-Check baseline checks", "ko": "매핑된 Dependency-Check 기준 전체"}),
        *_OWASP_DEPENDENCY_CHECK_CATEGORIES,
    ),
    description=_text(
        "A local dependency hygiene profile aligned with OWASP Dependency-Check's known-vulnerable-component purpose.",
        "알려진 취약 컴포넌트 식별이라는 OWASP Dependency-Check 목적에 맞춘 로컬 의존성 위생 프로파일입니다.",
    ),
    coverage=_text(
        "Partial automatic coverage only. Actual CVE matching requires Dependency-Check, OSV, NVD, or another vulnerability feed.",
        "부분 자동 지원입니다. 실제 CVE 대조에는 Dependency-Check, OSV, NVD 같은 취약점 피드 연동이 필요합니다.",
    ),
    references=(
        _reference("OWASP Dependency-Check", "OWASP Dependency-Check", "https://owasp.org/www-project-dependency-check/"),
    ),
)


OWASP_DEPENDENCY_TRACK_BASELINE = SecurityStandard(
    "owasp-dependency-track-baseline",
    {"en": "OWASP Dependency-Track / SBOM Baseline", "ko": "OWASP Dependency-Track / SBOM 기준"},
    (
        _all_category(_OWASP_DEPENDENCY_CHECK_CATEGORIES, {"en": "All mapped SBOM readiness checks", "ko": "매핑된 SBOM 준비성 항목 전체"}),
        *_OWASP_DEPENDENCY_CHECK_CATEGORIES,
    ),
    description=_text(
        "A local supply-chain readiness profile for projects that may later publish SBOMs to Dependency-Track.",
        "향후 Dependency-Track에 SBOM을 연동할 프로젝트를 위한 로컬 공급망 준비성 프로파일입니다.",
    ),
    coverage=_text(
        "Partial automatic coverage only. Portfolio tracking, SBOM ingestion, VEX, EPSS, and policy workflows require Dependency-Track integration.",
        "부분 자동 지원입니다. 포트폴리오 추적, SBOM 수집, VEX, EPSS, 정책 워크플로는 Dependency-Track 연동이 필요합니다.",
    ),
    references=(
        _reference("OWASP Dependency-Track", "OWASP Dependency-Track", "https://owasp.org/www-project-dependency-track/"),
        _reference("CycloneDX", "CycloneDX", "https://cyclonedx.org/"),
    ),
)


SECURITY_STANDARDS = (
    LOCAL_STANDARD,
    OWASP_TOP_10_2025,
    OWASP_TOP_10_2021,
    CWE_TOP_25_2025,
    CWE_SANS_TOP_25_2025,
    CWE_GENERAL,
    OWASP_API_SECURITY_2023,
    OWASP_MOBILE_TOP_10_2024,
    SW_DEV_SECURITY_49,
    SW_DEV_SECURITY_7_TYPES,
    KISA_SECURE_CODING_GUIDE,
    NCSC_WEB_8,
    ELECTRONIC_FINANCIAL_SUPERVISION_8,
    ISMS_P_DEVELOPMENT_SECURITY,
    OWASP_ASVS_5,
    OWASP_WSTG,
    NIST_SSDF,
    OWASP_SAMM_2,
    OWASP_DEPENDENCY_CHECK_BASELINE,
    OWASP_DEPENDENCY_TRACK_BASELINE,
)
SECURITY_STANDARD_IDS = tuple(standard.id for standard in SECURITY_STANDARDS)


def standards_payload() -> list[dict[str, object]]:
    return [
        {
            "id": standard.id,
            "labels": standard.labels,
            "description": standard.description,
            "coverage": standard.coverage,
            "coverage_level": standard.coverage_level,
            "references": [
                {
                    "labels": reference.labels,
                    "url": reference.url,
                }
                for reference in standard.references
            ],
            "categories": [
                {
                    "id": category.id,
                    "labels": category.labels,
                    "description": category.description,
                    "supported": category.supported,
                }
                for category in standard.categories
            ],
        }
        for standard in SECURITY_STANDARDS
    ]


def rule_standard_mappings_payload() -> dict[str, list[dict[str, object]]]:
    mappings: dict[str, list[dict[str, object]]] = {}
    for standard in SECURITY_STANDARDS:
        for category in standard.categories:
            if category.id == DEFAULT_STANDARD_CATEGORY:
                continue
            for rule_id in category.rule_ids:
                mappings.setdefault(rule_id, []).append(
                    {
                        "standard_id": standard.id,
                        "standard_labels": standard.labels,
                        "category_id": category.id,
                        "category_labels": category.labels,
                    }
                )
    return mappings


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
