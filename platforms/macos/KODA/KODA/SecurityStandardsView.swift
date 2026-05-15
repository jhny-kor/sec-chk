import SwiftUI

enum AppLanguage: String, Hashable {
    case ko
    case en

    var backTitle: String {
        switch self {
        case .ko: return "목록"
        case .en: return "Back"
        }
    }

    var helpTitle: String {
        switch self {
        case .ko: return "도움말"
        case .en: return "Help"
        }
    }

    var findingsTitle: String {
        switch self {
        case .ko: return "발견 항목"
        case .en: return "Findings"
        }
    }

    var riskScoreTitle: String {
        switch self {
        case .ko: return "위험 점수"
        case .en: return "Risk Score"
        }
    }

    var scopeTitle: String {
        switch self {
        case .ko: return "점검 범위"
        case .en: return "Scope"
        }
    }

    var automationTitle: String {
        switch self {
        case .ko: return "자동화 수준"
        case .en: return "Automation"
        }
    }

    var criteriaTitle: String {
        switch self {
        case .ko: return "점검 기준"
        case .en: return "Criteria"
        }
    }

    var referenceTitle: String {
        switch self {
        case .ko: return "공식 웹사이트"
        case .en: return "Official Sites"
        }
    }

    var riskFormulaTitle: String {
        switch self {
        case .ko: return "위험점수 계산"
        case .en: return "Risk Score Formula"
        }
    }

    var riskFormulaDescription: String {
        switch self {
        case .ko: return "위험 점수는 치명 100점, 높음 40점, 중간 10점, 낮음 3점, 정보 1점을 발견 항목별로 더한 값입니다."
        case .en: return "Risk score is the sum of each finding: critical 100, high 40, medium 10, low 3, and info 1."
        }
    }

    var severityDistributionTitle: String {
        switch self {
        case .ko: return "위험군별 분포"
        case .en: return "Severity Distribution"
        }
    }

    var checkedItemsTitle: String {
        switch self {
        case .ko: return "이 기준에서 확인하는 항목"
        case .en: return "Checks Covered By This Standard"
        }
    }

    var checkMethodTitle: String {
        switch self {
        case .ko: return "점검 방식"
        case .en: return "Check Method"
        }
    }

    var detailedChecksTitle: String {
        switch self {
        case .ko: return "세부 확인 항목"
        case .en: return "Detailed Checks"
        }
    }

    var evidenceSourceTitle: String {
        switch self {
        case .ko: return "확인 근거"
        case .en: return "Evidence Used"
        }
    }

    var noCheckedItemsTitle: String {
        switch self {
        case .ko: return "표시할 점검 항목이 없습니다."
        case .en: return "No check items to display."
        }
    }

    var localCheckBadge: String {
        switch self {
        case .ko: return "로컬 점검"
        case .en: return "Local"
        }
    }

    var partialCheckBadge: String {
        switch self {
        case .ko: return "부분 자동"
        case .en: return "Partial"
        }
    }

    func severityLabel(_ severity: String) -> String {
        switch (self, severity) {
        case (.ko, "critical"): return "치명"
        case (.ko, "high"): return "높음"
        case (.ko, "medium"): return "중간"
        case (.ko, "low"): return "낮음"
        case (.ko, _): return "정보"
        case (.en, "critical"): return "Critical"
        case (.en, "high"): return "High"
        case (.en, "medium"): return "Medium"
        case (.en, "low"): return "Low"
        case (.en, _): return "Info"
        }
    }

    var helpGuideTitle: String {
        switch self {
        case .ko: return "점검 가이드"
        case .en: return "Check Guide"
        }
    }

    var guideSummaryTitle: String {
        switch self {
        case .ko: return "가이드 요약"
        case .en: return "Guide Summary"
        }
    }

    var guideUsageTitle: String {
        switch self {
        case .ko: return "결과 해석"
        case .en: return "How To Read Results"
        }
    }

    var guideUsageDescription: String {
        switch self {
        case .ko: return "로컬 정적 점검으로 확인 가능한 항목은 자동으로 표시됩니다. 런타임 테스트, 조직 정책, 운영 증적이 필요한 항목은 부분 자동 항목으로 분류되며 별도 검토가 필요합니다."
        case .en: return "Locally mappable static checks are shown automatically. Runtime tests, organizational policy checks, and operational evidence are marked as partial and require separate review."
        }
    }

    var appSubtitle: String {
        switch self {
        case .ko: return "로컬 프로젝트 보안 점검"
        case .en: return "Local Project Security Scan"
        }
    }

    var openInBrowserTitle: String {
        switch self {
        case .ko: return "외부 브라우저로 열기"
        case .en: return "Open in Browser"
        }
    }

    var targetsTitle: String {
        switch self {
        case .ko: return "점검 대상"
        case .en: return "Scan Targets"
        }
    }

    var chooseFolderTitle: String {
        switch self {
        case .ko: return "폴더 선택"
        case .en: return "Choose Folder"
        }
    }

    var uploadFilesTitle: String {
        switch self {
        case .ko: return "파일 업로드"
        case .en: return "Upload Files"
        }
    }

    var clearSelectionTitle: String {
        switch self {
        case .ko: return "선택 초기화"
        case .en: return "Clear Selection"
        }
    }

    var runScanTitle: String {
        switch self {
        case .ko: return "보안 점검 실행"
        case .en: return "Run Security Scan"
        }
    }

    var runningTitle: String {
        switch self {
        case .ko: return "점검 중"
        case .en: return "Scanning"
        }
    }

    var noTargetsTitle: String {
        switch self {
        case .ko: return "선택된 항목 없음"
        case .en: return "No targets selected"
        }
    }

    var removeTargetHelp: String {
        switch self {
        case .ko: return "점검 대상 삭제"
        case .en: return "Remove scan target"
        }
    }

    var resultsTitle: String {
        switch self {
        case .ko: return "점검 결과 조회"
        case .en: return "Scan Results"
        }
    }

    var overallResultsTitle: String {
        switch self {
        case .ko: return "전체 조회"
        case .en: return "Overall Results"
        }
    }

    var overallResultsSubtitle: String {
        switch self {
        case .ko: return "스캔 결과 전체를 한 화면에서 확인합니다."
        case .en: return "View all scan results in one screen."
        }
    }

    var standardsResultsTitle: String {
        switch self {
        case .ko: return "보안기준별 점검결과"
        case .en: return "Results by Security Standard"
        }
    }

    var standardsResultsSubtitle: String {
        switch self {
        case .ko: return "전체 화면에서 기준별 설명, 도움말, KO/EN 토글과 함께 결과를 확인합니다."
        case .en: return "Open a full-screen view with standard details, help, and the KO/EN toggle."
        }
    }

    var resultCardsEnabledTitle: String {
        switch self {
        case .ko: return "점검을 실행하면 결과 조회 카드가 활성화됩니다."
        case .en: return "Run a scan to activate result cards."
        }
    }

    var resultCardsEnabledSubtitle: String {
        switch self {
        case .ko: return "점검 전에는 보안기준 카드를 눌러 기준 설명 화면을 먼저 볼 수 있습니다."
        case .en: return "Before scanning, open a security-standard card to review its criteria."
        }
    }

    var exportTitle: String {
        switch self {
        case .ko: return "다운로드"
        case .en: return "Download"
        }
    }

    func findingCountText(_ count: Int) -> String {
        switch self {
        case .ko: return "\(count)건"
        case .en: return "\(count) finding\(count == 1 ? "" : "s")"
        }
    }

    func riskScoreText(_ score: Int) -> String {
        switch self {
        case .ko: return "\(score)점"
        case .en: return "\(score) pts"
        }
    }

    func mappedItemsText(mapped: Int, total: Int) -> String {
        switch self {
        case .ko: return "매핑 항목 \(mapped)/\(total)"
        case .en: return "Mapped checks \(mapped)/\(total)"
        }
    }
}

struct HelpGuideRoute: Identifiable, Hashable {
    let id: String
    let title: String
    let standard: AppSecurityStandard?

    private init(id: String, title: String, standard: AppSecurityStandard?) {
        self.id = id
        self.title = title
        self.standard = standard
    }

    init(report: ScanReportItem) {
        if let standard = report.standard {
            self.init(standard: standard)
        } else {
            self.init(id: "overall", title: "전체 조회", standard: nil)
        }
    }

    init(standard: AppSecurityStandard) {
        self.init(id: standard.id, title: standard.title, standard: standard)
    }
}

struct LanguageToggle: View {
    @Binding var language: AppLanguage

    var body: some View {
        HStack(spacing: 0) {
            languageButton(.ko)
            languageButton(.en)
        }
        .padding(3)
        .background(Color(red: 0.04, green: 0.07, blue: 0.13))
        .clipShape(RoundedRectangle(cornerRadius: 8))
        .overlay {
            RoundedRectangle(cornerRadius: 8)
                .stroke(Color.white.opacity(0.28), lineWidth: 1)
        }
        .accessibilityLabel("Language")
    }

    private func languageButton(_ value: AppLanguage) -> some View {
        Button {
            language = value
        } label: {
            Text(value.rawValue.uppercased())
                .font(.caption.weight(.bold))
                .foregroundStyle(.white)
                .frame(width: 44, height: 26)
                .background(language == value ? Color.white.opacity(0.26) : Color.clear)
                .clipShape(RoundedRectangle(cornerRadius: 6))
        }
        .buttonStyle(.plain)
        .help(value == .ko ? "한국어" : "English")
    }
}

struct AppSecurityStandard: Identifiable, Hashable {
    let id: String
    let title: String
    let subtitle: String
    let scope: String
    let coverage: String
    let badge: String
    let icon: String
    let accent: StandardAccent
    let categories: [AppStandardCategory]
    let references: [AppStandardReference]

    var supportedCategoryCount: Int {
        categories.filter(\.isMapped).count
    }

    func title(language: AppLanguage) -> String {
        guard language == .en else { return title }
        return SecurityStandardLocalization.standardText[id]?.title ?? title
    }

    func subtitle(language: AppLanguage) -> String {
        guard language == .en else { return subtitle }
        return SecurityStandardLocalization.standardText[id]?.subtitle ?? subtitle
    }

    func scope(language: AppLanguage) -> String {
        guard language == .en else { return scope }
        return SecurityStandardLocalization.standardText[id]?.scope ?? scope
    }

    func coverage(language: AppLanguage) -> String {
        guard language == .en else { return coverage }
        return SecurityStandardLocalization.standardText[id]?.coverage ?? coverage
    }

    func badge(language: AppLanguage) -> String {
        guard language == .en else { return badge }
        return SecurityStandardLocalization.badgeText[badge] ?? badge
    }
}

struct AppStandardCategory: Identifiable, Hashable {
    let id: String
    let title: String
    let coverage: String
    let isMapped: Bool

    func title(language: AppLanguage) -> String {
        guard language == .en else { return title }
        return SecurityStandardLocalization.categoryTitleText[title] ?? title
    }

    func coverage(language: AppLanguage) -> String {
        guard language == .en else { return coverage }
        if !isMapped {
            return "Partially supported. This area needs manual review, runtime testing, or external evidence."
        }
        return SecurityStandardLocalization.categoryCoverageText[coverage]
            ?? "Checks this area using locally available source, configuration, secret, and dependency evidence."
    }

    func detailItems(language: AppLanguage) -> [String] {
        let key = "\(id) \(title) \(coverage)".lowercased()
        let koItems: [String]
        let enItems: [String]

        if key.contains("xss") || key.contains("script") || key.contains("스크립") {
            koItems = [
                "HTML 출력, 템플릿 렌더링, DOM sink에 사용자 입력이 직접 연결되는지 확인합니다.",
                "innerHTML, dangerouslySetInnerHTML, document.write 등 브라우저 실행 경로를 찾습니다.",
                "이스케이프, 인코딩, 콘텐츠 보안 정책으로 보완이 필요한 지점을 표시합니다.",
            ]
            enItems = [
                "Checks whether user input reaches HTML output, template rendering, or DOM sinks.",
                "Finds browser execution paths such as innerHTML, dangerouslySetInnerHTML, and document.write.",
                "Highlights places that need escaping, encoding, or Content Security Policy controls.",
            ]
        } else if key.contains("sql") || key.contains("injection") || key.contains("인젝션") || key.contains("입력") {
            koItems = [
                "SQL 문자열 조합, 명령 실행, 템플릿 인젝션처럼 입력값이 실행 구문에 섞이는 패턴을 확인합니다.",
                "exec, system, subprocess, child_process, eval 계열 호출과 사용자 입력 흐름을 찾습니다.",
                "쿼리 파라미터화, 허용목록 검증, 명령 인자 분리로 고쳐야 할 지점을 표시합니다.",
            ]
            enItems = [
                "Checks patterns where input is mixed into SQL strings, command execution, or template execution.",
                "Finds exec, system, subprocess, child_process, eval, and similar calls tied to input flow.",
                "Highlights places that should use parameterized queries, allowlists, or separated command arguments.",
            ]
        } else if key.contains("path") || key.contains("file") || key.contains("download") || key.contains("upload") || key.contains("파일") || key.contains("다운로드") {
            koItems = [
                "다운로드/업로드 핸들러, 경로 조합, ../ 사용처럼 파일 접근 범위가 넓어지는 패턴을 확인합니다.",
                "정적 파일 공개, 임시 파일, 오래된 업로드/게시판 디렉터리 흔적을 찾습니다.",
                "기준 디렉터리 제한, 확장자 허용목록, 파일명 정규화가 필요한 위치를 표시합니다.",
            ]
            enItems = [
                "Checks download/upload handlers, path joins, and ../ patterns that can widen file access.",
                "Finds static file exposure, temporary-file use, and legacy upload or board-directory traces.",
                "Highlights where base-directory constraints, extension allowlists, and filename normalization are needed.",
            ]
        } else if key.contains("directory") || key.contains("listing") || key.contains("webdav") || key.contains("cors") || key.contains("debug") || key.contains("설정") || key.contains("배포") || key.contains("server") {
            koItems = [
                "debug 플래그, CORS 전체 허용, directory listing, WebDAV 활성화 설정을 확인합니다.",
                "nginx, Apache, IIS, Docker, compose, framework 설정 파일에서 운영 노출 위험을 찾습니다.",
                "운영 배포 전 끄거나 제한해야 할 서버 옵션과 오류 노출 설정을 표시합니다.",
            ]
            enItems = [
                "Checks debug flags, overly permissive CORS, directory listing, and enabled WebDAV settings.",
                "Finds exposure risks in nginx, Apache, IIS, Docker, compose, and framework configuration files.",
                "Highlights server options and error-disclosure settings that should be disabled or restricted before release.",
            ]
        } else if key.contains("session") || key.contains("cookie") || key.contains("auth") || key.contains("인증") || key.contains("인가") || key.contains("세션") || key.contains("접근") {
            koItems = [
                "쿠키 Secure, HttpOnly, SameSite 누락과 세션 설정 약화를 확인합니다.",
                "인가 우회, 라우트 보호 누락, 파일/관리자 경로 접근 패턴을 찾습니다.",
                "인증 우회 조건, 기본 계정, 테스트용 권한 설정이 남은 위치를 표시합니다.",
            ]
            enItems = [
                "Checks missing cookie Secure, HttpOnly, SameSite flags and weak session settings.",
                "Finds authorization bypass patterns, unprotected routes, and file or admin path access risks.",
                "Highlights leftover auth bypass conditions, default accounts, and test-only authorization settings.",
            ]
        } else if key.contains("secret") || key.contains("credential") || key.contains("crypto") || key.contains("hash") || key.contains("암호") || key.contains("비밀") || key.contains("중요정보") {
            koItems = [
                "API 키, 토큰, 개인키, DB 비밀번호처럼 저장소에 남은 비밀값을 확인합니다.",
                "MD5, SHA1, DES, ECB 등 약한 해시/암호와 평문 전송 흔적을 찾습니다.",
                "환경변수 분리, 키 순환, 강한 KDF/암호화 알고리즘으로 바꿔야 할 위치를 표시합니다.",
            ]
            enItems = [
                "Checks repository remnants such as API keys, tokens, private keys, and database passwords.",
                "Finds weak hashes or crypto such as MD5, SHA1, DES, ECB, plus cleartext transport traces.",
                "Highlights where to move secrets to environment storage, rotate keys, or use stronger KDF and crypto algorithms.",
            ]
        } else if key.contains("dependency") || key.contains("sbom") || key.contains("manifest") || key.contains("version") || key.contains("supply") || key.contains("의존") || key.contains("공급망") || key.contains("매니페스트") {
            koItems = [
                "package.json, requirements, Gemfile, lockfile 등 의존성 매니페스트와 잠금 파일 상태를 확인합니다.",
                "고정되지 않은 버전, wildcard, latest, HTTP 소스, 원격 스크립트 즉시 실행 패턴을 찾습니다.",
                "SBOM 생성 준비성, 무결성 검증, OSV/Dependency-Check 연동 대상 파일을 표시합니다.",
            ]
            enItems = [
                "Checks dependency manifests and lockfiles such as package.json, requirements, Gemfile, and lock files.",
                "Finds unpinned versions, wildcards, latest, HTTP sources, and remote script execution patterns.",
                "Highlights SBOM readiness, integrity checks, and files suitable for OSV or Dependency-Check integration.",
            ]
        } else {
            koItems = [
                "소스코드, 설정 파일, 의존성 파일에서 이 기준과 연결되는 정적 근거를 수집합니다.",
                "런타임 호출 없이 확인 가능한 위험 패턴과 운영 전 제거해야 할 흔적을 찾습니다.",
                "조직 정책이나 운영 증적이 필요한 항목은 부분 자동 점검으로 구분해 표시합니다.",
            ]
            enItems = [
                "Collects static evidence from source code, configuration, and dependency files mapped to this standard.",
                "Finds risky patterns and release-time leftovers that can be checked without runtime execution.",
                "Marks items that need organizational policy or operational evidence as partial automation.",
            ]
        }

        return language == .ko ? koItems : enItems
    }

    func evidenceSummary(language: AppLanguage) -> String {
        if isMapped {
            switch language {
            case .ko:
                return "선택한 폴더/파일의 소스 라인, 설정 파일, 의존성 매니페스트, 압축 해제 파일에서 발견된 로컬 증거를 사용합니다."
            case .en:
                return "Uses local evidence from source lines, configuration files, dependency manifests, and extracted archives in the selected targets."
            }
        }

        switch language {
        case .ko:
            return "로컬 파일로 일부 단서만 확인하며, 실제 취약 여부는 런타임 테스트, 운영 설정, 정책 증적으로 추가 검토해야 합니다."
        case .en:
            return "Uses local files for partial signals only; runtime testing, deployed configuration, and policy evidence are still needed for final validation."
        }
    }
}

struct AppStandardReference: Identifiable, Hashable {
    let title: String
    let url: String

    var id: String { url }
}

enum StandardAccent: String, Hashable {
    case blue
    case cyan
    case green
    case indigo
    case orange
    case red
    case slate
    case teal

    var color: Color {
        switch self {
        case .blue: return .blue
        case .cyan: return .cyan
        case .green: return .green
        case .indigo: return .indigo
        case .orange: return .orange
        case .red: return .red
        case .slate: return .secondary
        case .teal: return .teal
        }
    }
}

enum KODATheme {
    static var cardBackground: Color {
        Color(nsColor: .controlBackgroundColor)
    }

    static var insetBackground: Color {
        Color(nsColor: .windowBackgroundColor)
    }
}

private enum SecurityStandardLocalization {
    struct StandardText {
        let title: String
        let subtitle: String
        let scope: String
        let coverage: String
    }

    static let badgeText: [String: String] = [
        "기본": "Default",
        "국제 기준": "International",
        "국내 기준": "Korean Standard",
        "국내 인증": "Korean Certification",
        "국제 검증표준": "International Verification",
        "국제 테스트가이드": "International Testing Guide",
        "국제 프레임워크": "International Framework",
        "국제 성숙도모델": "International Maturity Model",
        "공급망": "Supply Chain",
    ]

    static let standardText: [String: StandardText] = [
        "local": StandardText(
            title: "Local Security Scan",
            subtitle: "Default profile for quickly checking secrets, dependencies, configuration, and risky code patterns.",
            scope: "File-based static checks",
            coverage: "Fully automated local checks"
        ),
        "owasp-top-10-2025": StandardText(
            title: "OWASP Top 10:2025",
            subtitle: "Maps major web application risk categories to local rules.",
            scope: "Web application code and configuration",
            coverage: "Partially automated checks"
        ),
        "owasp-top-10-2021": StandardText(
            title: "OWASP Top 10:2021",
            subtitle: "Checks widely used OWASP Top 10 categories with local evidence.",
            scope: "Web application code and configuration",
            coverage: "Partially automated checks"
        ),
        "cwe-sans-top-25-2025": StandardText(
            title: "CWE/SANS Top 25:2025",
            subtitle: "Risk profile that groups MITRE CWE Top 25 data from the SANS software-error perspective.",
            scope: "Code weaknesses and security hygiene",
            coverage: "Partially automated checks"
        ),
        "cwe-top-25-2025": StandardText(
            title: "CWE Top 25:2025",
            subtitle: "Checks the most dangerous CWE weaknesses with file-based static analysis.",
            scope: "Code weaknesses and dependency hygiene",
            coverage: "Partially automated checks"
        ),
        "cwe-general": StandardText(
            title: "General CWE Weaknesses",
            subtitle: "Classifies common code and configuration weaknesses beyond the Top 25 from the CWE perspective.",
            scope: "Code, configuration, and dependencies",
            coverage: "Partially automated checks"
        ),
        "owasp-api-security-2023": StandardText(
            title: "OWASP API Security Top 10:2023",
            subtitle: "Checks API route, authorization, resource, SSRF, and configuration risks.",
            scope: "API code and configuration",
            coverage: "Partially automated checks"
        ),
        "owasp-mobile-top-10-2024": StandardText(
            title: "OWASP Mobile Top 10:2024",
            subtitle: "Checks security risks visible in mobile app source and configuration.",
            scope: "Mobile source and configuration files",
            coverage: "Partially automated checks"
        ),
        "sw-dev-security-49": StandardText(
            title: "Korean Software Development Security 49",
            subtitle: "Maps the 49 Korean software-development-security guide criteria to local rules.",
            scope: "Korean secure-coding criteria",
            coverage: "Partially automated checks"
        ),
        "sw-dev-security-7-types": StandardText(
            title: "Korean Software Development Security 7 Types",
            subtitle: "Groups development-security weaknesses into seven broad Korean guide types.",
            scope: "Korean secure-coding types",
            coverage: "Partially automated checks"
        ),
        "kisa-secure-coding": StandardText(
            title: "KISA Secure Coding Guide",
            subtitle: "Checks Korean secure-coding recommendations using local code evidence.",
            scope: "Source code and configuration",
            coverage: "Partially automated checks"
        ),
        "ncsc-web-8": StandardText(
            title: "NCSC Web 8 Security Vulnerabilities",
            subtitle: "Checks eight common public web-service vulnerability families used in Korean security reviews.",
            scope: "Web code and server configuration",
            coverage: "Partially automated checks"
        ),
        "electronic-financial-8": StandardText(
            title: "Electronic Financial Supervision 8 Vulnerabilities",
            subtitle: "Maps Korean electronic-finance public web-server review items to local rules.",
            scope: "Financial web-service code and configuration",
            coverage: "Partially automated checks"
        ),
        "isms-p-28": StandardText(
            title: "ISMS-P 2.8 Development Security",
            subtitle: "Maps development-security controls to items that can be checked with local evidence.",
            scope: "Development, testing, and production handoff security",
            coverage: "Partially automated checks"
        ),
        "owasp-asvs-5": StandardText(
            title: "OWASP ASVS 5.0",
            subtitle: "Groups static-checkable areas from application security verification requirements.",
            scope: "Application security verification",
            coverage: "Partially automated checks"
        ),
        "owasp-wstg": StandardText(
            title: "OWASP WSTG",
            subtitle: "Shows web security testing guide areas where file-based evidence is available.",
            scope: "Web security testing methodology",
            coverage: "Partially automated checks"
        ),
        "nist-ssdf": StandardText(
            title: "NIST SSDF SP 800-218",
            subtitle: "Checks secure software development practices with local evidence.",
            scope: "Secure development process",
            coverage: "Partially automated checks"
        ),
        "owasp-samm-2": StandardText(
            title: "OWASP SAMM 2",
            subtitle: "Checks design, implementation, verification, and operations practices in the software assurance maturity model.",
            scope: "Software assurance maturity",
            coverage: "Partially automated checks"
        ),
        "owasp-dependency-check": StandardText(
            title: "OWASP Dependency-Check Baseline",
            subtitle: "Dependency hygiene baseline for identifying known vulnerable components.",
            scope: "Dependency manifests and lockfiles",
            coverage: "Partially automated checks"
        ),
        "owasp-dependency-track": StandardText(
            title: "OWASP Dependency-Track / SBOM Baseline",
            subtitle: "Checks local evidence for SBOM readiness and dependency tracking.",
            scope: "SBOM and supply-chain management",
            coverage: "Partially automated checks"
        ),
    ]

    static let categoryTitleText: [String: String] = [
        "비밀값": "Secrets",
        "의존성": "Dependencies",
        "설정": "Configuration",
        "코드 패턴": "Code Patterns",
        "인가 취약점": "Authorization Weaknesses",
        "리소스 제한": "Resource Limits",
        "API 설정": "API Configuration",
        "자격증명 저장": "Credential Storage",
        "통신 보안": "Communication Security",
        "앱 설정": "App Configuration",
        "모바일 의존성": "Mobile Dependencies",
        "입력 데이터 검증 및 표현": "Input Validation and Representation",
        "보안 기능": "Security Functions",
        "시간 및 상태": "Time and State",
        "에러 처리 및 코드 품질": "Error Handling and Code Quality",
        "캡슐화 및 API 오용": "Encapsulation and API Misuse",
        "에러 처리": "Error Handling",
        "코드 오류": "Code Errors",
        "인젝션": "Injection",
        "크로스사이트 스크립팅": "Cross-Site Scripting",
        "파일 처리": "File Handling",
        "중요정보 보호": "Sensitive Information Protection",
        "파일 다운로드": "File Download",
        "디렉터리 리스팅": "Directory Listing",
        "레거시 게시판": "Legacy Bulletin Board",
        "서버 설정": "Server Configuration",
        "세션 관리": "Session Management",
        "보안 요구사항": "Security Requirements",
        "시큐어코딩": "Secure Coding",
        "시험 데이터 보호": "Test Data Protection",
        "소스 프로그램 관리": "Source Program Management",
        "운영 이관": "Production Handoff",
        "입력 검증": "Input Validation",
        "인증 및 세션": "Authentication and Session",
        "접근통제": "Access Control",
        "데이터 보호 및 암호": "Data Protection and Cryptography",
        "공급망": "Supply Chain",
        "설정 및 배포": "Configuration and Deployment",
        "인증": "Authentication",
        "인가": "Authorization",
        "입력값 검증": "Input Validation",
        "약한 암호": "Weak Cryptography",
        "Protect the Software": "Protect the Software",
        "Produce Well-Secured Software": "Produce Well-Secured Software",
        "Verify Security": "Verify Security",
        "Respond to Vulnerabilities": "Respond to Vulnerabilities",
        "Design": "Design",
        "Implementation": "Implementation",
        "Verification": "Verification",
        "Operations": "Operations",
        "매니페스트 위생": "Manifest Hygiene",
        "버전 고정": "Version Pinning",
        "의존성 소스": "Dependency Sources",
        "SBOM 준비성": "SBOM Readiness",
        "버전 위생": "Version Hygiene",
        "CWE-79 XSS": "CWE-79 XSS",
        "CWE-89 SQL Injection": "CWE-89 SQL Injection",
        "CWE-78 OS Command Injection": "CWE-78 OS Command Injection",
        "CWE-22 Path Traversal": "CWE-22 Path Traversal",
        "CWE-352 CSRF": "CWE-352 CSRF",
        "CWE-798 Hard-coded Credentials": "CWE-798 Hard-coded Credentials",
        "인증 및 접근통제": "Authentication and Access Control",
        "암호 및 비밀정보": "Cryptography and Secrets",
        "보안 설정": "Security Configuration",
    ]

    static let categoryCoverageText: [String: String] = [
        "API 키, 토큰, 개인키로 보이는 값을 탐지합니다.": "Detects possible API keys, tokens, and private keys.",
        "고정되지 않은 버전, 락파일 누락, 안전하지 않은 소스를 확인합니다.": "Checks unpinned versions, missing lockfiles, and unsafe dependency sources.",
        ".env, debug, 권한 상승 컨테이너 설정을 확인합니다.": "Checks .env files, debug flags, and privileged container settings.",
        "XSS, SQL injection, command injection, path traversal 등을 확인합니다.": "Checks XSS, SQL injection, command injection, path traversal, and related patterns.",
        "인가 우회, 파일 다운로드, 경로 접근 패턴을 확인합니다.": "Checks authorization bypass, file download, and path access patterns.",
        "비밀값, 약한 해시, 평문 전송 흔적을 확인합니다.": "Checks secrets, weak hashes, and cleartext transport traces.",
        "SQL, command, template, path traversal 입력 흐름을 확인합니다.": "Checks SQL, command, template, and path traversal input flows.",
        "debug, CORS, directory listing, WebDAV 설정을 확인합니다.": "Checks debug, CORS, directory listing, and WebDAV settings.",
        "의존성 위생과 OSV 확장 대상 매니페스트를 확인합니다.": "Checks dependency hygiene and manifests suitable for OSV extension.",
        "동적 SQL 조합과 입력 흐름을 확인합니다.": "Checks dynamic SQL construction and input flow.",
        "shell 명령 조합과 실행 패턴을 확인합니다.": "Checks shell command construction and execution patterns.",
        "경로 조작 및 파일 다운로드 위험을 확인합니다.": "Checks path manipulation and file download risks.",
        "하드코딩된 비밀값과 토큰을 확인합니다.": "Checks hard-coded secrets and tokens.",
        "키, 토큰, 비밀값 노출을 확인합니다.": "Checks exposed keys, tokens, and secrets.",
        "SQL, XSS, command, path traversal 패턴을 확인합니다.": "Checks SQL, XSS, command, and path traversal patterns.",
        "인증, 세션, 암호, 권한 흐름을 확인합니다.": "Checks authentication, session, cryptography, and authorization flows.",
        "임시 파일, 경쟁 상태 가능 패턴을 확인합니다.": "Checks temporary-file and possible race-condition patterns.",
        "오류 노출, 위험 API 사용 흔적을 확인합니다.": "Checks error disclosure and risky API usage traces.",
        "파일·명령·직렬화 API 오용을 확인합니다.": "Checks file, command, and serialization API misuse.",
        "입력값 기반 공격 패턴을 확인합니다.": "Checks attack patterns driven by user input.",
        "인증, 세션, 암호 사용 위험을 확인합니다.": "Checks authentication, session, and cryptography risks.",
        "임시 파일 및 상태 처리 위험을 확인합니다.": "Checks temporary-file and state-handling risks.",
        "디버그와 오류 노출 설정을 확인합니다.": "Checks debug and error-disclosure settings.",
        "위험 API와 오용 패턴을 확인합니다.": "Checks risky APIs and misuse patterns.",
        "SQL, command, template injection 패턴을 확인합니다.": "Checks SQL, command, and template injection patterns.",
        "DOM sink와 HTML 렌더링 위험을 확인합니다.": "Checks DOM sinks and HTML rendering risks.",
        "다운로드, 경로 조작, directory listing 위험을 확인합니다.": "Checks download, path manipulation, and directory listing risks.",
        "비밀값과 약한 암호 사용을 확인합니다.": "Checks secrets and weak cryptography use.",
        "동적 SQL 조합과 쿼리 입력 흐름을 확인합니다.": "Checks dynamic SQL construction and query input flow.",
        "DOM XSS와 HTML 출력 위험을 확인합니다.": "Checks DOM XSS and HTML output risks.",
        "경로 조작과 다운로드 핸들러 위험을 확인합니다.": "Checks path manipulation and download-handler risks.",
        "index 옵션과 listing 설정을 확인합니다.": "Checks index options and listing settings.",
        "WebDAV 활성화 설정을 확인합니다.": "Checks WebDAV enablement settings.",
        "오래된 게시판·업로드 흔적을 확인합니다.": "Checks traces of legacy bulletin-board and upload components.",
        "SQL과 명령 실행 위험을 확인합니다.": "Checks SQL and command-execution risks.",
        "브라우저 실행 스크립트 주입 위험을 확인합니다.": "Checks browser-side script injection risks.",
        "다운로드, 업로드, 경로 조작 위험을 확인합니다.": "Checks download, upload, and path manipulation risks.",
        "디렉터리 리스팅, WebDAV, debug 설정을 확인합니다.": "Checks directory listing, WebDAV, and debug settings.",
        "쿠키와 세션 설정 위험을 확인합니다.": "Checks cookie and session setting risks.",
        "비밀값, 설정, 의존성 관리 근거를 확인합니다.": "Checks evidence for secrets, configuration, and dependency management.",
        "코드 약점과 위험 API 사용을 확인합니다.": "Checks code weaknesses and risky API usage.",
        ".env, 샘플 비밀값, 테스트 credential을 확인합니다.": "Checks .env files, sample secrets, and test credentials.",
        "락파일, 의존성, 설정 위생을 확인합니다.": "Checks lockfile, dependency, and configuration hygiene.",
        "debug와 위험 설정 잔존 여부를 확인합니다.": "Checks whether debug and risky settings remain.",
        "입력값 검증과 인코딩 위험을 확인합니다.": "Checks input validation and encoding risks.",
        "쿠키, 세션, 인증 처리 위험을 확인합니다.": "Checks cookie, session, and authentication handling risks.",
        "파일·라우트 접근통제 위험을 확인합니다.": "Checks file and route access-control risks.",
        "의존성 및 무결성 설정을 확인합니다.": "Checks dependency and integrity settings.",
        "CORS, debug, directory listing, WebDAV를 확인합니다.": "Checks CORS, debug, directory listing, and WebDAV.",
        "인증·세션 관련 코드 패턴을 확인합니다.": "Checks authentication and session code patterns.",
        "파일 접근과 라우트 접근 위험을 확인합니다.": "Checks file and route access risks.",
        "XSS, SQL, command, traversal 패턴을 확인합니다.": "Checks XSS, SQL, command, and traversal patterns.",
        "약한 해시와 비밀값 노출을 확인합니다.": "Checks weak hashes and exposed secrets.",
        "보안 요구와 위험 설정 흔적을 확인합니다.": "Checks traces of security requirements and risky settings.",
        "시큐어코딩과 의존성 위생을 확인합니다.": "Checks secure-coding and dependency hygiene.",
        "정적 점검 근거를 수집합니다.": "Collects local static-check evidence.",
        "운영 이관 전 debug와 비밀값 잔존을 확인합니다.": "Checks debug and secret remnants before production handoff.",
        "package.json, requirements, lockfile 상태를 확인합니다.": "Checks package.json, requirements, and lockfile status.",
        "고정되지 않은 버전과 wildcard를 확인합니다.": "Checks unpinned versions and wildcards.",
        "평문 또는 원격 실행 의존성 소스를 확인합니다.": "Checks cleartext or remote-execution dependency sources.",
        "매니페스트와 락파일 상태를 확인합니다.": "Checks manifests and lockfile status.",
        "고정되지 않은 의존성과 wildcard를 확인합니다.": "Checks unpinned dependencies and wildcards.",
        "안전하지 않은 다운로드와 원격 실행 패턴을 확인합니다.": "Checks unsafe download and remote-execution patterns.",
    ]
}

struct SecurityStandardsGridView: View {
    let standards: [AppSecurityStandard]
    let minimumCardWidth: CGFloat
    let language: AppLanguage
    let onSelect: (AppSecurityStandard) -> Void

    var body: some View {
        ScrollView {
            LazyVGrid(
                columns: [GridItem(.adaptive(minimum: minimumCardWidth, maximum: 420), spacing: 14)],
                alignment: .leading,
                spacing: 14
            ) {
                ForEach(standards) { standard in
                    Button {
                        onSelect(standard)
                    } label: {
                        SecurityStandardCard(standard: standard, language: language)
                    }
                    .buttonStyle(.plain)
                }
            }
            .padding(22)
        }
        .background(Color(nsColor: .windowBackgroundColor))
    }
}

struct ScanResultsGroupedView: View {
    let reports: [ScanReportItem]
    let standards: [AppSecurityStandard]
    let minimumCardWidth: CGFloat
    let language: AppLanguage
    let onSelectReport: (ScanReportItem) -> Void
    let onSelectStandard: (AppSecurityStandard) -> Void

    private var overallReport: ScanReportItem? {
        reports.first(where: \.isOverall)
    }

    private var standardReports: [ScanReportItem] {
        reports.filter { !$0.isOverall }
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 22) {
                if reports.isEmpty {
                    emptyState
                }

                groupedSection(title: language.overallResultsTitle, subtitle: language.overallResultsSubtitle) {
                    if let overallReport {
                        Button {
                            onSelectReport(overallReport)
                        } label: {
                            ScanReportNavigationCard(report: overallReport, language: language)
                        }
                        .buttonStyle(.plain)
                    } else {
                        DisabledResultCard(
                            title: language.overallResultsTitle,
                            subtitle: language == .ko
                                ? "점검 실행 후 전체 결과 화면으로 이동할 수 있습니다."
                                : "Run a scan to open the overall results screen.",
                            icon: "rectangle.stack"
                        )
                    }
                }

                groupedSection(title: language.standardsResultsTitle, subtitle: language.standardsResultsSubtitle) {
                    if standardReports.isEmpty {
                        LazyVGrid(columns: gridColumns, alignment: .leading, spacing: 14) {
                            ForEach(standards) { standard in
                                Button {
                                    onSelectStandard(standard)
                                } label: {
                                    SecurityStandardCard(standard: standard, language: language)
                                }
                                .buttonStyle(.plain)
                            }
                        }
                    } else {
                        LazyVGrid(columns: gridColumns, alignment: .leading, spacing: 14) {
                            ForEach(standardReports) { report in
                                Button {
                                    onSelectReport(report)
                                } label: {
                                    ScanReportNavigationCard(report: report, language: language)
                                }
                                .buttonStyle(.plain)
                            }
                        }
                    }
                }
            }
            .padding(22)
        }
        .background(Color(nsColor: .windowBackgroundColor))
    }

    private var gridColumns: [GridItem] {
        [GridItem(.adaptive(minimum: minimumCardWidth, maximum: 420), spacing: 14)]
    }

    private var emptyState: some View {
        HStack(spacing: 12) {
            Image(systemName: "play.circle")
                .font(.title2.weight(.semibold))
                .foregroundStyle(.secondary)

            VStack(alignment: .leading, spacing: 4) {
                Text(language.resultCardsEnabledTitle)
                    .font(.headline)
                Text(language.resultCardsEnabledSubtitle)
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(KODATheme.cardBackground)
        .clipShape(RoundedRectangle(cornerRadius: 8))
        .overlay {
            RoundedRectangle(cornerRadius: 8)
                .stroke(Color(nsColor: .separatorColor), lineWidth: 1)
        }
    }

    private func groupedSection<Content: View>(
        title: String,
        subtitle: String,
        @ViewBuilder content: () -> Content
    ) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            VStack(alignment: .leading, spacing: 4) {
                Text(title)
                    .font(.title3.weight(.bold))
                Text(subtitle)
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
            content()
        }
    }
}

private struct ScanReportNavigationCard: View {
    let report: ScanReportItem
    let language: AppLanguage

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .top, spacing: 12) {
                Image(systemName: report.icon)
                    .font(.system(size: 24, weight: .semibold))
                    .foregroundStyle(report.accent.color)
                    .frame(width: 34, height: 34)

                VStack(alignment: .leading, spacing: 5) {
                    Text(report.title(language: language))
                        .font(.headline)
                        .foregroundStyle(.primary)
                        .lineLimit(2)
                        .fixedSize(horizontal: false, vertical: true)

                    Text(report.badge(language: language))
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(report.accent.color)
                }

                Spacer(minLength: 8)

                Image(systemName: "arrow.up.right.square")
                    .foregroundStyle(.secondary)
            }

            Text(report.subtitle(language: language))
                .font(.callout)
                .foregroundStyle(.secondary)
                .lineLimit(2)
                .fixedSize(horizontal: false, vertical: true)

            HStack(spacing: 12) {
                Label(language.findingCountText(report.findingCount), systemImage: "list.bullet.rectangle")
                Label(language.riskScoreText(report.riskScore), systemImage: "gauge.with.dots.needle.50percent")
            }
            .font(.caption)
            .foregroundStyle(.secondary)
        }
        .padding(16)
        .frame(maxWidth: .infinity, minHeight: 156, alignment: .topLeading)
        .background(KODATheme.cardBackground)
        .overlay(alignment: .leading) {
            Rectangle()
                .fill(report.accent.color)
                .frame(width: 4)
        }
        .clipShape(RoundedRectangle(cornerRadius: 8))
        .overlay {
            RoundedRectangle(cornerRadius: 8)
                .stroke(Color(nsColor: .separatorColor), lineWidth: 1)
        }
    }
}

private struct DisabledResultCard: View {
    let title: String
    let subtitle: String
    let icon: String

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: icon)
                .font(.title2.weight(.semibold))
                .foregroundStyle(.secondary)
                .frame(width: 34, height: 34)

            VStack(alignment: .leading, spacing: 5) {
                Text(title)
                    .font(.headline)
                Text(subtitle)
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }

            Spacer()
        }
        .padding(16)
        .frame(maxWidth: .infinity, minHeight: 96, alignment: .leading)
        .background(KODATheme.cardBackground.opacity(0.65))
        .clipShape(RoundedRectangle(cornerRadius: 8))
        .overlay {
            RoundedRectangle(cornerRadius: 8)
                .stroke(Color(nsColor: .separatorColor), lineWidth: 1)
        }
    }
}

private struct SecurityStandardCard: View {
    let standard: AppSecurityStandard
    let language: AppLanguage

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .top, spacing: 12) {
                Image(systemName: standard.icon)
                    .font(.system(size: 24, weight: .semibold))
                    .foregroundStyle(standard.accent.color)
                    .frame(width: 34, height: 34)

                VStack(alignment: .leading, spacing: 5) {
                    Text(standard.title(language: language))
                        .font(.headline)
                        .foregroundStyle(.primary)
                        .lineLimit(2)
                        .fixedSize(horizontal: false, vertical: true)

                    Text(standard.badge(language: language))
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(standard.accent.color)
                }

                Spacer(minLength: 8)

                Image(systemName: "chevron.right")
                    .foregroundStyle(.secondary)
            }

            Text(standard.subtitle(language: language))
                .font(.callout)
                .foregroundStyle(.secondary)
                .lineLimit(3)
                .fixedSize(horizontal: false, vertical: true)

            HStack(spacing: 8) {
                Label("\(standard.supportedCategoryCount)/\(standard.categories.count)", systemImage: "checklist")
                Text(standard.coverage(language: language))
            }
            .font(.caption)
            .foregroundStyle(.secondary)
        }
        .padding(16)
        .frame(maxWidth: .infinity, minHeight: 168, alignment: .topLeading)
        .background(KODATheme.cardBackground)
        .overlay(alignment: .leading) {
            Rectangle()
                .fill(standard.accent.color)
                .frame(width: 4)
        }
        .clipShape(RoundedRectangle(cornerRadius: 8))
        .overlay {
            RoundedRectangle(cornerRadius: 8)
                .stroke(Color(nsColor: .separatorColor), lineWidth: 1)
        }
    }
}

struct SecurityStandardDetailScreen: View {
    let standard: AppSecurityStandard
    @Binding var language: AppLanguage
    let onBack: () -> Void
    let onHelp: () -> Void

    var body: some View {
        GeometryReader { proxy in
            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    header(width: proxy.size.width)
                    content(width: proxy.size.width)
                }
            }
            .background(Color(nsColor: .windowBackgroundColor))
        }
    }

    private func header(width: CGFloat) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 14) {
                Button {
                    onBack()
                } label: {
                    Label(language.backTitle, systemImage: "chevron.left")
                }
                .buttonStyle(.borderless)
                .foregroundStyle(.white)

                Spacer()

                Button {
                    onHelp()
                } label: {
                    Label(language.helpTitle, systemImage: "questionmark.circle")
                }
                .buttonStyle(.borderless)
                .foregroundStyle(.white)

                LanguageToggle(language: $language)
            }

            HStack(alignment: .top, spacing: 16) {
                Image(systemName: standard.icon)
                    .font(.system(size: scaledIconSize(width), weight: .bold))
                    .foregroundStyle(standard.accent.color)
                    .frame(width: scaledIconSize(width) + 12, height: scaledIconSize(width) + 12)

                VStack(alignment: .leading, spacing: 8) {
                    Text(standard.title(language: language))
                        .font(.system(size: scaledTitleSize(width), weight: .bold))
                        .foregroundStyle(.white)
                        .lineLimit(2)
                        .fixedSize(horizontal: false, vertical: true)

                    Text(standard.subtitle(language: language))
                        .font(.title3)
                        .foregroundStyle(.white.opacity(0.75))
                        .fixedSize(horizontal: false, vertical: true)
                }

                Spacer()
            }

            Text("\(standard.badge(language: language)) | \(language.mappedItemsText(mapped: standard.supportedCategoryCount, total: standard.categories.count))")
                .font(.callout.weight(.semibold))
                .foregroundStyle(.white.opacity(0.8))
        }
        .padding(.horizontal, horizontalPadding(width))
        .padding(.vertical, max(28, width * 0.035))
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(red: 0.04, green: 0.07, blue: 0.13))
    }

    private func content(width: CGFloat) -> some View {
        VStack(alignment: .leading, spacing: 20) {
            LazyVGrid(columns: detailColumns(width), spacing: 14) {
                DetailSummaryTile(title: language.scopeTitle, value: standard.scope(language: language))
                DetailSummaryTile(title: language.automationTitle, value: standard.coverage(language: language))
            }

            section(title: language.criteriaTitle) {
                LazyVGrid(columns: detailColumns(width), spacing: 12) {
                    ForEach(standard.categories) { category in
                        StandardCategoryRow(category: category, language: language)
                    }
                }
            }

            section(title: language.referenceTitle) {
                VStack(alignment: .leading, spacing: 10) {
                    ForEach(standard.references) { reference in
                        Link(destination: URL(string: reference.url)!) {
                            HStack {
                                Image(systemName: "link")
                                Text(reference.title)
                                Spacer()
                                Text(reference.url)
                                    .foregroundStyle(.secondary)
                                    .lineLimit(1)
                                    .truncationMode(.middle)
                            }
                            .padding(.horizontal, 14)
                            .padding(.vertical, 11)
                            .background(KODATheme.cardBackground)
                            .clipShape(RoundedRectangle(cornerRadius: 8))
                            .overlay {
                                RoundedRectangle(cornerRadius: 8)
                                    .stroke(Color(nsColor: .separatorColor), lineWidth: 1)
                            }
                        }
                        .buttonStyle(.plain)
                    }
                }
            }
        }
        .padding(.horizontal, horizontalPadding(width))
        .padding(.vertical, 24)
    }

    private func section<Content: View>(title: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(title)
                .font(.title2.weight(.bold))
            content()
        }
    }

    private func detailColumns(_ width: CGFloat) -> [GridItem] {
        let minimum = width > 1120 ? CGFloat(330) : CGFloat(280)
        return [GridItem(.adaptive(minimum: minimum), spacing: 12)]
    }

    private func horizontalPadding(_ width: CGFloat) -> CGFloat {
        min(46, max(20, width * 0.04))
    }

    private func scaledTitleSize(_ width: CGFloat) -> CGFloat {
        min(42, max(28, width * 0.038))
    }

    private func scaledIconSize(_ width: CGFloat) -> CGFloat {
        min(48, max(34, width * 0.04))
    }
}

private struct DetailSummaryTile: View {
    let title: String
    let value: String

    var body: some View {
        VStack(alignment: .leading, spacing: 9) {
            Text(title)
                .font(.caption.weight(.bold))
                .foregroundStyle(.secondary)
            Text(value)
                .font(.body)
                .foregroundStyle(.primary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(16)
        .frame(maxWidth: .infinity, minHeight: 112, alignment: .topLeading)
        .background(KODATheme.cardBackground)
        .clipShape(RoundedRectangle(cornerRadius: 8))
        .overlay {
            RoundedRectangle(cornerRadius: 8)
                .stroke(Color(nsColor: .separatorColor), lineWidth: 1)
        }
    }
}

struct HelpGuideScreen: View {
    let route: HelpGuideRoute
    @Binding var language: AppLanguage
    let onBack: () -> Void

    private var guideStandard: AppSecurityStandard? {
        route.standard ?? SecurityStandardCatalog.all.first { $0.id == "local" }
    }

    var body: some View {
        GeometryReader { proxy in
            VStack(spacing: 0) {
                header(width: proxy.size.width)

                ScrollView {
                    VStack(alignment: .leading, spacing: 22) {
                        LazyVGrid(columns: detailColumns(proxy.size.width), spacing: 14) {
                            DetailSummaryTile(title: language.scopeTitle, value: route.standard?.scope(language: language) ?? overallScope)
                            DetailSummaryTile(title: language.automationTitle, value: route.standard?.coverage(language: language) ?? overallCoverage)
                            DetailSummaryTile(title: language.riskFormulaTitle, value: language.riskFormulaDescription)
                        }

                        section(title: language.guideSummaryTitle) {
                            Text(message)
                                .font(.callout)
                                .foregroundStyle(.secondary)
                                .fixedSize(horizontal: false, vertical: true)
                                .padding(16)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .background(KODATheme.cardBackground)
                                .clipShape(RoundedRectangle(cornerRadius: 8))
                                .overlay {
                                    RoundedRectangle(cornerRadius: 8)
                                        .stroke(Color(nsColor: .separatorColor), lineWidth: 1)
                                }
                        }

                        section(title: language.checkedItemsTitle) {
                            if checkedCategories.isEmpty {
                                Text(language.noCheckedItemsTitle)
                                    .font(.callout)
                                    .foregroundStyle(.secondary)
                            } else {
                                LazyVGrid(columns: detailColumns(proxy.size.width), spacing: 12) {
                                    ForEach(checkedCategories) { category in
                                        HelpCriteriaCard(category: category, language: language)
                                    }
                                }
                            }
                        }

                        section(title: language.guideUsageTitle) {
                            Text(language.guideUsageDescription)
                                .font(.callout)
                                .foregroundStyle(.secondary)
                                .fixedSize(horizontal: false, vertical: true)
                                .padding(16)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .background(KODATheme.cardBackground)
                                .clipShape(RoundedRectangle(cornerRadius: 8))
                                .overlay {
                                    RoundedRectangle(cornerRadius: 8)
                                        .stroke(Color(nsColor: .separatorColor), lineWidth: 1)
                                }
                        }

                        if let standard = guideStandard {
                            section(title: language.referenceTitle) {
                                VStack(alignment: .leading, spacing: 10) {
                                    ForEach(standard.references) { reference in
                                        Link(destination: URL(string: reference.url)!) {
                                            HStack {
                                                Image(systemName: "link")
                                                Text(reference.title)
                                                Spacer()
                                                Text(reference.url)
                                                    .foregroundStyle(.secondary)
                                                    .lineLimit(1)
                                                    .truncationMode(.middle)
                                            }
                                            .padding(.horizontal, 14)
                                            .padding(.vertical, 11)
                                            .background(KODATheme.cardBackground)
                                            .clipShape(RoundedRectangle(cornerRadius: 8))
                                            .overlay {
                                                RoundedRectangle(cornerRadius: 8)
                                                    .stroke(Color(nsColor: .separatorColor), lineWidth: 1)
                                            }
                                        }
                                        .buttonStyle(.plain)
                                    }
                                }
                            }
                        }
                    }
                    .padding(.horizontal, horizontalPadding(proxy.size.width))
                    .padding(.vertical, 24)
                }
            }
            .background(Color(nsColor: .windowBackgroundColor))
        }
    }

    private func header(width: CGFloat) -> some View {
        VStack(alignment: .leading, spacing: 18) {
            HStack(spacing: 14) {
                Button {
                    onBack()
                } label: {
                    Label(language.backTitle, systemImage: "chevron.left")
                }
                .buttonStyle(.borderless)
                .foregroundStyle(.white)

                Spacer()

                LanguageToggle(language: $language)
            }
            .padding(.horizontal, 22)
            .padding(.vertical, 14)

            HStack(alignment: .top, spacing: 16) {
                Image(systemName: guideStandard?.icon ?? "questionmark.circle")
                    .font(.system(size: min(48, max(34, width * 0.04)), weight: .bold))
                    .foregroundStyle(guideStandard?.accent.color ?? .blue)
                    .frame(width: 60, height: 60)

                VStack(alignment: .leading, spacing: 8) {
                    Text(language.helpGuideTitle)
                        .font(.system(size: min(42, max(28, width * 0.038)), weight: .bold))
                        .foregroundStyle(.white)

                    Text(displayTitle)
                        .font(.title3)
                        .foregroundStyle(.white.opacity(0.78))
                        .fixedSize(horizontal: false, vertical: true)
                }

                Spacer()
            }
            .padding(.horizontal, horizontalPadding(width))
            .padding(.top, 12)
            .padding(.bottom, max(28, width * 0.035))
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(red: 0.04, green: 0.07, blue: 0.13))
    }

    private var message: String {
        let standardName = displayTitle

        switch language {
        case .ko:
            return "\(standardName) 기준의 점검 가이드입니다. 아래 항목은 KODA가 로컬 파일과 설정에서 확인하는 범위이며, 자동 탐지 가능한 항목과 별도 검토가 필요한 부분을 함께 보여줍니다."
        case .en:
            return "This guide explains what KODA checks for \(standardName). The items below show what can be inspected from local files and configuration, including locally automated and separately reviewed areas."
        }
    }

    private var checkedCategories: [AppStandardCategory] {
        guideStandard?.categories ?? []
    }

    private var displayTitle: String {
        if let standard = route.standard {
            return standard.title(language: language)
        }
        switch language {
        case .ko: return "전체 조회"
        case .en: return "Overall Results"
        }
    }

    private var overallScope: String {
        switch language {
        case .ko: return "전체 로컬 보안 점검 결과"
        case .en: return "All local security scan results"
        }
    }

    private var overallCoverage: String {
        switch language {
        case .ko: return "기준 제한 없이 전체 자동 점검"
        case .en: return "All automated checks without standard filtering"
        }
    }

    private func section<Content: View>(title: String, @ViewBuilder content: () -> Content) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(title)
                .font(.title2.weight(.bold))
            content()
        }
    }

    private func detailColumns(_ width: CGFloat) -> [GridItem] {
        let minimum = width > 1120 ? CGFloat(330) : CGFloat(280)
        return [GridItem(.adaptive(minimum: minimum), spacing: 12)]
    }

    private func horizontalPadding(_ width: CGFloat) -> CGFloat {
        min(46, max(20, width * 0.04))
    }
}

private struct HelpCriteriaCard: View {
    let category: AppStandardCategory
    let language: AppLanguage

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Text(category.title(language: language))
                    .font(.callout.weight(.semibold))
                    .lineLimit(2)
                    .fixedSize(horizontal: false, vertical: true)

                Spacer(minLength: 8)

                Text(category.isMapped ? language.localCheckBadge : language.partialCheckBadge)
                    .font(.caption.weight(.bold))
                    .foregroundStyle(category.isMapped ? .green : .orange)
            }

            HelpInfoBlock(title: language.checkMethodTitle, text: category.coverage(language: language))

            VStack(alignment: .leading, spacing: 6) {
                Text(language.detailedChecksTitle)
                    .font(.caption.weight(.bold))
                    .foregroundStyle(.secondary)

                ForEach(category.detailItems(language: language), id: \.self) { item in
                    HStack(alignment: .top, spacing: 7) {
                        Image(systemName: "checkmark.circle.fill")
                            .font(.caption2.weight(.bold))
                            .foregroundStyle(category.isMapped ? .green : .orange)
                            .padding(.top, 2)
                        Text(item)
                            .font(.caption)
                            .foregroundStyle(.primary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            }

            HelpInfoBlock(title: language.evidenceSourceTitle, text: category.evidenceSummary(language: language))
        }
        .padding(14)
        .frame(maxWidth: .infinity, minHeight: 220, alignment: .topLeading)
        .background(KODATheme.cardBackground)
        .clipShape(RoundedRectangle(cornerRadius: 8))
        .overlay {
            RoundedRectangle(cornerRadius: 8)
                .stroke(Color(nsColor: .separatorColor), lineWidth: 1)
        }
    }
}

private struct HelpInfoBlock: View {
    let title: String
    let text: String

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title)
                .font(.caption.weight(.bold))
                .foregroundStyle(.secondary)
            Text(text)
                .font(.caption)
                .foregroundStyle(.primary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}

private struct StandardCategoryRow: View {
    let category: AppStandardCategory
    let language: AppLanguage

    var body: some View {
        VStack(alignment: .leading, spacing: 9) {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Text(category.title(language: language))
                    .font(.headline)
                    .lineLimit(2)
                    .fixedSize(horizontal: false, vertical: true)

                Spacer()

                Text(category.isMapped ? language.localCheckBadge : language.partialCheckBadge)
                    .font(.caption.weight(.bold))
                    .foregroundStyle(category.isMapped ? .green : .orange)
            }

            Text(category.coverage(language: language))
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(14)
        .frame(maxWidth: .infinity, minHeight: 108, alignment: .topLeading)
        .background(KODATheme.cardBackground)
        .clipShape(RoundedRectangle(cornerRadius: 8))
        .overlay {
            RoundedRectangle(cornerRadius: 8)
                .stroke(Color(nsColor: .separatorColor), lineWidth: 1)
        }
    }
}

enum SecurityStandardCatalog {
    static let all: [AppSecurityStandard] = [
        AppSecurityStandard(
            id: "local",
            title: "로컬 보안 점검",
            subtitle: "비밀값, 의존성, 설정, 코드 패턴을 빠르게 확인하는 기본 프로파일입니다.",
            scope: "파일 기반 정적 점검",
            coverage: "전체 자동 점검",
            badge: "기본",
            icon: "magnifyingglass",
            accent: .blue,
            categories: [
                category("secrets", "비밀값", "API 키, 토큰, 개인키로 보이는 값을 탐지합니다."),
                category("dependencies", "의존성", "고정되지 않은 버전, 락파일 누락, 안전하지 않은 소스를 확인합니다."),
                category("configuration", "설정", ".env, debug, 권한 상승 컨테이너 설정을 확인합니다."),
                category("code", "코드 패턴", "XSS, SQL injection, command injection, path traversal 등을 확인합니다.")
            ],
            references: [
                reference("KODA GitHub", "https://github.com/jhny-kor/sec-chk")
            ]
        ),
        AppSecurityStandard(
            id: "owasp-top-10-2025",
            title: "OWASP Top 10:2025",
            subtitle: "웹 애플리케이션 주요 위험 범주를 로컬 룰에 매핑한 프로파일입니다.",
            scope: "웹 애플리케이션 코드 및 설정",
            coverage: "부분 자동 점검",
            badge: "국제 기준",
            icon: "shield.lefthalf.filled",
            accent: .cyan,
            categories: [
                category("broken-access-control", "Broken Access Control", "인가 우회, 파일 다운로드, 경로 접근 패턴을 확인합니다."),
                category("cryptographic-failures", "Cryptographic Failures", "비밀값, 약한 해시, 평문 전송 흔적을 확인합니다."),
                category("injection", "Injection", "SQL, command, template, path traversal 입력 흐름을 확인합니다."),
                category("security-misconfiguration", "Security Misconfiguration", "debug, CORS, directory listing, WebDAV 설정을 확인합니다."),
                category("vulnerable-components", "Vulnerable Components", "의존성 위생과 OSV 확장 대상 매니페스트를 확인합니다.")
            ],
            references: [
                reference("OWASP Top Ten Project", "https://owasp.org/www-project-top-ten/")
            ]
        ),
        AppSecurityStandard(
            id: "owasp-top-10-2021",
            title: "OWASP Top 10:2021",
            subtitle: "현재 널리 쓰이는 OWASP Top 10 범주를 로컬 증거 중심으로 점검합니다.",
            scope: "웹 애플리케이션 코드 및 설정",
            coverage: "부분 자동 점검",
            badge: "국제 기준",
            icon: "shield",
            accent: .cyan,
            categories: [
                category("a01", "A01 Broken Access Control", "인가 우회와 파일 경로 취급 위험을 확인합니다."),
                category("a02", "A02 Cryptographic Failures", "비밀값, 약한 암호, 평문 전송 흔적을 확인합니다."),
                category("a03", "A03 Injection", "SQL, command, DOM XSS, path traversal 패턴을 확인합니다."),
                category("a05", "A05 Security Misconfiguration", "debug, CORS, directory listing, WebDAV 흔적을 확인합니다."),
                category("a06", "A06 Vulnerable Components", "고정되지 않은 의존성과 락파일 누락을 확인합니다.")
            ],
            references: [
                reference("OWASP Top Ten Project", "https://owasp.org/www-project-top-ten/")
            ]
        ),
        AppSecurityStandard(
            id: "cwe-sans-top-25-2025",
            title: "CWE/SANS Top 25:2025",
            subtitle: "MITRE CWE Top 25 데이터를 SANS 관점으로 묶은 위험 소프트웨어 오류 프로파일입니다.",
            scope: "코드 약점 및 보안 위생",
            coverage: "부분 자동 점검",
            badge: "국제 기준",
            icon: "exclamationmark.shield",
            accent: .orange,
            categories: cweCategories(),
            references: [
                reference("MITRE CWE Top 25:2025", "https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html"),
                reference("SANS Top 25 Software Errors", "https://www.sans.org/top25-software-errors/")
            ]
        ),
        AppSecurityStandard(
            id: "cwe-top-25-2025",
            title: "CWE Top 25:2025",
            subtitle: "가장 위험한 CWE 약점을 파일 기반 정적 점검으로 확인합니다.",
            scope: "코드 약점 및 의존성 위생",
            coverage: "부분 자동 점검",
            badge: "국제 기준",
            icon: "list.number",
            accent: .orange,
            categories: cweCategories(),
            references: [
                reference("MITRE CWE Top 25:2025", "https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html")
            ]
        ),
        AppSecurityStandard(
            id: "cwe-general",
            title: "CWE 일반 약점",
            subtitle: "Top 25 외의 일반적인 코드·설정 약점을 CWE 관점으로 분류합니다.",
            scope: "코드, 설정, 의존성",
            coverage: "부분 자동 점검",
            badge: "국제 기준",
            icon: "square.grid.2x2",
            accent: .indigo,
            categories: [
                category("input-validation", "입력값 검증", "XSS, injection, traversal, SSRF 계열 패턴을 확인합니다."),
                category("auth-access", "인증 및 접근통제", "약한 세션, 파일 접근, 인증 우회 흔적을 확인합니다."),
                category("crypto", "암호 및 비밀정보", "약한 해시와 비밀값 노출을 확인합니다."),
                category("configuration", "보안 설정", "CORS, debug, directory listing, WebDAV 설정을 확인합니다.")
            ],
            references: [
                reference("MITRE CWE", "https://cwe.mitre.org/")
            ]
        ),
        AppSecurityStandard(
            id: "owasp-api-security-2023",
            title: "OWASP API Security Top 10:2023",
            subtitle: "API 라우트, 인가, 리소스, SSRF, 설정 위험을 확인합니다.",
            scope: "API 코드 및 설정",
            coverage: "부분 자동 점검",
            badge: "국제 기준",
            icon: "point.3.connected.trianglepath.dotted",
            accent: .teal,
            categories: [
                category("authorization", "인가 취약점", "객체·기능 수준 접근통제 누락 위험을 확인합니다."),
                category("resource", "리소스 제한", "요청 크기, 반복 처리, 외부 요청 위험을 확인합니다."),
                category("ssrf", "SSRF", "사용자 입력 URL 요청 패턴을 확인합니다."),
                category("misconfiguration", "API 설정", "CORS, debug, 오류 노출 설정을 확인합니다.")
            ],
            references: [
                reference("OWASP API Security Project", "https://owasp.org/API-Security/")
            ]
        ),
        AppSecurityStandard(
            id: "owasp-mobile-top-10-2024",
            title: "OWASP Mobile Top 10:2024",
            subtitle: "모바일 앱 소스와 설정에서 확인 가능한 보안 위험을 점검합니다.",
            scope: "모바일 소스 및 설정 파일",
            coverage: "부분 자동 점검",
            badge: "국제 기준",
            icon: "iphone.gen3",
            accent: .green,
            categories: [
                category("credentials", "자격증명 저장", "키, 토큰, 비밀값 노출을 확인합니다."),
                category("communication", "통신 보안", "평문 URL, 약한 TLS 설정 흔적을 확인합니다."),
                category("configuration", "앱 설정", "debug, backup, 권한 관련 설정을 확인합니다."),
                category("dependencies", "모바일 의존성", "매니페스트와 의존성 위생을 확인합니다.")
            ],
            references: [
                reference("OWASP Mobile Top 10", "https://owasp.org/www-project-mobile-top-10/")
            ]
        ),
        AppSecurityStandard(
            id: "sw-dev-security-49",
            title: "소프트웨어 개발보안 49",
            subtitle: "국내 소프트웨어 개발보안 가이드 49개 기준을 로컬 룰에 매핑합니다.",
            scope: "국내 시큐어코딩 기준",
            coverage: "부분 자동 점검",
            badge: "국내 기준",
            icon: "doc.text.magnifyingglass",
            accent: .blue,
            categories: [
                category("input-data", "입력 데이터 검증 및 표현", "SQL, XSS, command, path traversal 패턴을 확인합니다."),
                category("security-function", "보안 기능", "인증, 세션, 암호, 권한 흐름을 확인합니다."),
                category("time-state", "시간 및 상태", "임시 파일, 경쟁 상태 가능 패턴을 확인합니다."),
                category("error-code", "에러 처리 및 코드 품질", "오류 노출, 위험 API 사용 흔적을 확인합니다."),
                category("encapsulation", "캡슐화 및 API 오용", "파일·명령·직렬화 API 오용을 확인합니다.")
            ],
            references: [
                reference("KISA 보호나라", "https://www.boho.or.kr/")
            ]
        ),
        AppSecurityStandard(
            id: "sw-dev-security-7-types",
            title: "소프트웨어 개발보안 7대 유형",
            subtitle: "개발보안 약점을 7가지 큰 유형으로 묶어 점검합니다.",
            scope: "국내 시큐어코딩 유형",
            coverage: "부분 자동 점검",
            badge: "국내 기준",
            icon: "7.circle",
            accent: .blue,
            categories: [
                category("input", "입력 데이터 검증 및 표현", "입력값 기반 공격 패턴을 확인합니다."),
                category("security", "보안 기능", "인증, 세션, 암호 사용 위험을 확인합니다."),
                category("time-state", "시간 및 상태", "임시 파일 및 상태 처리 위험을 확인합니다."),
                category("error", "에러 처리", "디버그와 오류 노출 설정을 확인합니다."),
                category("code-quality", "코드 오류", "위험 API와 오용 패턴을 확인합니다.")
            ],
            references: [
                reference("KISA 보호나라", "https://www.boho.or.kr/")
            ]
        ),
        AppSecurityStandard(
            id: "kisa-secure-coding",
            title: "KISA 시큐어코딩 가이드",
            subtitle: "국내 시큐어코딩 권고를 로컬 코드 증거 중심으로 확인합니다.",
            scope: "소스코드 및 설정",
            coverage: "부분 자동 점검",
            badge: "국내 기준",
            icon: "checkmark.shield",
            accent: .green,
            categories: [
                category("injection", "인젝션", "SQL, command, template injection 패턴을 확인합니다."),
                category("xss", "크로스사이트 스크립팅", "DOM sink와 HTML 렌더링 위험을 확인합니다."),
                category("file", "파일 처리", "다운로드, 경로 조작, directory listing 위험을 확인합니다."),
                category("secret", "중요정보 보호", "비밀값과 약한 암호 사용을 확인합니다.")
            ],
            references: [
                reference("KISA 보호나라", "https://www.boho.or.kr/")
            ]
        ),
        AppSecurityStandard(
            id: "ncsc-web-8",
            title: "국정원 웹 8대 보안취약점",
            subtitle: "공개 웹서비스에서 자주 확인하는 8대 취약점 계열을 점검합니다.",
            scope: "웹 코드 및 서버 설정",
            coverage: "부분 자동 점검",
            badge: "국내 기준",
            icon: "building.columns",
            accent: .red,
            categories: [
                category("sql-injection", "SQL Injection", "동적 SQL 조합과 쿼리 입력 흐름을 확인합니다."),
                category("xss", "Cross-Site Scripting", "DOM XSS와 HTML 출력 위험을 확인합니다."),
                category("file-download", "파일 다운로드", "경로 조작과 다운로드 핸들러 위험을 확인합니다."),
                category("directory-listing", "디렉터리 리스팅", "index 옵션과 listing 설정을 확인합니다."),
                category("webdav", "WebDAV", "WebDAV 활성화 설정을 확인합니다."),
                category("legacy-board", "레거시 게시판", "오래된 게시판·업로드 흔적을 확인합니다.")
            ],
            references: [
                reference("국가사이버안보센터", "https://www.ncsc.go.kr/")
            ]
        ),
        AppSecurityStandard(
            id: "electronic-financial-8",
            title: "전자금융감독규정 8대 취약점",
            subtitle: "전자금융 공개 웹서버 점검 항목을 로컬 룰에 매핑합니다.",
            scope: "금융권 웹서비스 코드 및 설정",
            coverage: "부분 자동 점검",
            badge: "국내 기준",
            icon: "banknote",
            accent: .red,
            categories: [
                category("injection", "인젝션", "SQL과 명령 실행 위험을 확인합니다."),
                category("xss", "XSS", "브라우저 실행 스크립트 주입 위험을 확인합니다."),
                category("file", "파일 처리", "다운로드, 업로드, 경로 조작 위험을 확인합니다."),
                category("config", "서버 설정", "디렉터리 리스팅, WebDAV, debug 설정을 확인합니다."),
                category("session", "세션 관리", "쿠키와 세션 설정 위험을 확인합니다.")
            ],
            references: [
                reference("금융감독원", "https://www.fss.or.kr/")
            ]
        ),
        AppSecurityStandard(
            id: "isms-p-28",
            title: "ISMS-P 2.8 개발보안",
            subtitle: "개발보안 통제 영역을 로컬 증거로 확인 가능한 항목에 매핑합니다.",
            scope: "개발·시험·운영 이관 보안",
            coverage: "부분 자동 점검",
            badge: "국내 인증",
            icon: "checkmark.seal",
            accent: .green,
            categories: [
                category("requirements", "보안 요구사항", "비밀값, 설정, 의존성 관리 근거를 확인합니다."),
                category("secure-coding", "시큐어코딩", "코드 약점과 위험 API 사용을 확인합니다."),
                category("test-data", "시험 데이터 보호", ".env, 샘플 비밀값, 테스트 credential을 확인합니다."),
                category("source-management", "소스 프로그램 관리", "락파일, 의존성, 설정 위생을 확인합니다."),
                category("migration", "운영 이관", "debug와 위험 설정 잔존 여부를 확인합니다.")
            ],
            references: [
                reference("KISA ISMS-P", "https://isms.kisa.or.kr/")
            ]
        ),
        AppSecurityStandard(
            id: "owasp-asvs-5",
            title: "OWASP ASVS 5.0",
            subtitle: "애플리케이션 보안 검증 요구사항 중 정적 점검 가능한 영역을 묶습니다.",
            scope: "애플리케이션 보안 검증",
            coverage: "부분 자동 점검",
            badge: "국제 검증표준",
            icon: "doc.badge.gearshape",
            accent: .indigo,
            categories: [
                category("validation", "입력 검증", "입력값 검증과 인코딩 위험을 확인합니다."),
                category("auth-session", "인증 및 세션", "쿠키, 세션, 인증 처리 위험을 확인합니다."),
                category("access-control", "접근통제", "파일·라우트 접근통제 위험을 확인합니다."),
                category("data-protection", "데이터 보호 및 암호", "비밀값과 약한 암호 사용을 확인합니다."),
                category("supply-chain", "공급망", "의존성 및 무결성 설정을 확인합니다.")
            ],
            references: [
                reference("OWASP ASVS", "https://owasp.org/www-project-application-security-verification-standard/")
            ]
        ),
        AppSecurityStandard(
            id: "owasp-wstg",
            title: "OWASP WSTG",
            subtitle: "웹 보안 테스트 가이드 중 파일 기반 증거가 가능한 항목을 표시합니다.",
            scope: "웹 보안 테스트 방법론",
            coverage: "부분 자동 점검",
            badge: "국제 테스트가이드",
            icon: "network",
            accent: .indigo,
            categories: [
                category("config", "설정 및 배포", "CORS, debug, directory listing, WebDAV를 확인합니다."),
                category("authentication", "인증", "인증·세션 관련 코드 패턴을 확인합니다."),
                category("authorization", "인가", "파일 접근과 라우트 접근 위험을 확인합니다."),
                category("input-validation", "입력값 검증", "XSS, SQL, command, traversal 패턴을 확인합니다."),
                category("weak-cryptography", "약한 암호", "약한 해시와 비밀값 노출을 확인합니다.")
            ],
            references: [
                reference("OWASP WSTG", "https://owasp.org/www-project-web-security-testing-guide/")
            ]
        ),
        AppSecurityStandard(
            id: "nist-ssdf",
            title: "NIST SSDF SP 800-218",
            subtitle: "보안 소프트웨어 개발 프레임워크의 실천 항목을 로컬 증거로 확인합니다.",
            scope: "보안 개발 프로세스",
            coverage: "부분 자동 점검",
            badge: "국제 프레임워크",
            icon: "gearshape.2",
            accent: .slate,
            categories: [
                category("protect", "Protect the Software", "비밀값과 의존성 위생을 확인합니다."),
                category("produce", "Produce Well-Secured Software", "보안 설정과 코드 약점을 확인합니다."),
                category("verify", "Verify Security", "로컬 룰 기반 검증 증거를 수집합니다."),
                category("respond", "Respond to Vulnerabilities", "취약 의존성 대응을 위한 매니페스트를 확인합니다.")
            ],
            references: [
                reference("NIST SSDF SP 800-218", "https://csrc.nist.gov/publications/detail/sp/800-218/final")
            ]
        ),
        AppSecurityStandard(
            id: "owasp-samm-2",
            title: "OWASP SAMM 2",
            subtitle: "보안 성숙도 모델의 설계·구현·검증·운영 실천 항목을 확인합니다.",
            scope: "소프트웨어 보증 성숙도",
            coverage: "부분 자동 점검",
            badge: "국제 성숙도모델",
            icon: "chart.line.uptrend.xyaxis",
            accent: .teal,
            categories: [
                category("design", "Design", "보안 요구와 위험 설정 흔적을 확인합니다."),
                category("implementation", "Implementation", "시큐어코딩과 의존성 위생을 확인합니다."),
                category("verification", "Verification", "정적 점검 근거를 수집합니다."),
                category("operations", "Operations", "운영 이관 전 debug와 비밀값 잔존을 확인합니다.")
            ],
            references: [
                reference("OWASP SAMM", "https://owasp.org/www-project-samm/"),
                reference("OWASP SAMM Model", "https://owaspsamm.org/model/")
            ]
        ),
        AppSecurityStandard(
            id: "owasp-dependency-check",
            title: "OWASP Dependency-Check 기준",
            subtitle: "알려진 취약 컴포넌트 식별을 위한 의존성 위생 기준입니다.",
            scope: "의존성 매니페스트 및 락파일",
            coverage: "부분 자동 점검",
            badge: "공급망",
            icon: "shippingbox",
            accent: .orange,
            categories: [
                category("manifest", "매니페스트 위생", "package.json, requirements, lockfile 상태를 확인합니다."),
                category("version", "버전 고정", "고정되지 않은 버전과 wildcard를 확인합니다."),
                category("sources", "의존성 소스", "평문 또는 원격 실행 의존성 소스를 확인합니다.")
            ],
            references: [
                reference("OWASP Dependency-Check", "https://owasp.org/www-project-dependency-check/")
            ]
        ),
        AppSecurityStandard(
            id: "owasp-dependency-track",
            title: "OWASP Dependency-Track / SBOM 기준",
            subtitle: "SBOM 준비성과 의존성 추적을 위한 로컬 증거를 확인합니다.",
            scope: "SBOM 및 공급망 관리",
            coverage: "부분 자동 점검",
            badge: "공급망",
            icon: "doc.zipper",
            accent: .orange,
            categories: [
                category("sbom-readiness", "SBOM 준비성", "매니페스트와 락파일 상태를 확인합니다."),
                category("version-hygiene", "버전 위생", "고정되지 않은 의존성과 wildcard를 확인합니다."),
                category("dependency-source", "의존성 소스", "안전하지 않은 다운로드와 원격 실행 패턴을 확인합니다.")
            ],
            references: [
                reference("OWASP Dependency-Track", "https://owasp.org/www-project-dependency-track/")
            ]
        )
    ]

    private static func cweCategories() -> [AppStandardCategory] {
        [
            category("cwe-79", "CWE-79 XSS", "DOM XSS와 출력 인코딩 위험을 확인합니다."),
            category("cwe-89", "CWE-89 SQL Injection", "동적 SQL 조합과 입력 흐름을 확인합니다."),
            category("cwe-78", "CWE-78 OS Command Injection", "shell 명령 조합과 실행 패턴을 확인합니다."),
            category("cwe-22", "CWE-22 Path Traversal", "경로 조작 및 파일 다운로드 위험을 확인합니다."),
            category("cwe-352", "CWE-352 CSRF", "부분 지원입니다. 정적 코드 근거가 있는 경우만 확인합니다.", isMapped: false),
            category("cwe-798", "CWE-798 Hard-coded Credentials", "하드코딩된 비밀값과 토큰을 확인합니다.")
        ]
    }

    private static func category(
        _ id: String,
        _ title: String,
        _ coverage: String,
        isMapped: Bool = true
    ) -> AppStandardCategory {
        AppStandardCategory(id: id, title: title, coverage: coverage, isMapped: isMapped)
    }

    private static func reference(_ title: String, _ url: String) -> AppStandardReference {
        AppStandardReference(title: title, url: url)
    }
}
