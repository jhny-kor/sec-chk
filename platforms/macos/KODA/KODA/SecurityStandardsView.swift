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
}

struct LanguageToggle: View {
    @Binding var language: AppLanguage

    var body: some View {
        HStack(spacing: 0) {
            languageButton(.ko)
            languageButton(.en)
        }
        .padding(3)
        .background(Color.white.opacity(0.14))
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
}

struct AppStandardCategory: Identifiable, Hashable {
    let id: String
    let title: String
    let coverage: String
    let isMapped: Bool
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

struct SecurityStandardsGridView: View {
    let standards: [AppSecurityStandard]
    let minimumCardWidth: CGFloat
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
                        SecurityStandardCard(standard: standard)
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

                groupedSection(title: "전체 조회", subtitle: "스캔 결과 전체를 한 화면에서 확인합니다.") {
                    if let overallReport {
                        Button {
                            onSelectReport(overallReport)
                        } label: {
                            ScanReportNavigationCard(report: overallReport)
                        }
                        .buttonStyle(.plain)
                    } else {
                        DisabledResultCard(
                            title: "전체 조회",
                            subtitle: "점검 실행 후 전체 결과 화면으로 이동할 수 있습니다.",
                            icon: "rectangle.stack"
                        )
                    }
                }

                groupedSection(title: "보안기준별 점검결과", subtitle: "전체 화면에서 기준별 설명, 도움말, KO/EN 토글과 함께 결과를 확인합니다.") {
                    if standardReports.isEmpty {
                        LazyVGrid(columns: gridColumns, alignment: .leading, spacing: 14) {
                            ForEach(standards) { standard in
                                Button {
                                    onSelectStandard(standard)
                                } label: {
                                    SecurityStandardCard(standard: standard)
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
                                    ScanReportNavigationCard(report: report)
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
                Text("점검을 실행하면 결과 조회 카드가 활성화됩니다.")
                    .font(.headline)
                Text("점검 전에는 보안기준 카드를 눌러 기준 설명 화면을 먼저 볼 수 있습니다.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(nsColor: .textBackgroundColor))
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

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .top, spacing: 12) {
                Image(systemName: report.icon)
                    .font(.system(size: 24, weight: .semibold))
                    .foregroundStyle(report.accent.color)
                    .frame(width: 34, height: 34)

                VStack(alignment: .leading, spacing: 5) {
                    Text(report.title)
                        .font(.headline)
                        .foregroundStyle(.primary)
                        .lineLimit(2)
                        .fixedSize(horizontal: false, vertical: true)

                    Text(report.badge)
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(report.accent.color)
                }

                Spacer(minLength: 8)

                Image(systemName: "arrow.up.right.square")
                    .foregroundStyle(.secondary)
            }

            Text(report.subtitle)
                .font(.callout)
                .foregroundStyle(.secondary)
                .lineLimit(2)
                .fixedSize(horizontal: false, vertical: true)

            HStack(spacing: 12) {
                Label("\(report.findingCount)건", systemImage: "list.bullet.rectangle")
                Label("\(report.riskScore)점", systemImage: "gauge.with.dots.needle.50percent")
            }
            .font(.caption)
            .foregroundStyle(.secondary)
        }
        .padding(16)
        .frame(maxWidth: .infinity, minHeight: 156, alignment: .topLeading)
        .background(Color(nsColor: .textBackgroundColor))
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
        .background(Color(nsColor: .textBackgroundColor).opacity(0.65))
        .clipShape(RoundedRectangle(cornerRadius: 8))
        .overlay {
            RoundedRectangle(cornerRadius: 8)
                .stroke(Color(nsColor: .separatorColor), lineWidth: 1)
        }
    }
}

private struct SecurityStandardCard: View {
    let standard: AppSecurityStandard

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .top, spacing: 12) {
                Image(systemName: standard.icon)
                    .font(.system(size: 24, weight: .semibold))
                    .foregroundStyle(standard.accent.color)
                    .frame(width: 34, height: 34)

                VStack(alignment: .leading, spacing: 5) {
                    Text(standard.title)
                        .font(.headline)
                        .foregroundStyle(.primary)
                        .lineLimit(2)
                        .fixedSize(horizontal: false, vertical: true)

                    Text(standard.badge)
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(standard.accent.color)
                }

                Spacer(minLength: 8)

                Image(systemName: "chevron.right")
                    .foregroundStyle(.secondary)
            }

            Text(standard.subtitle)
                .font(.callout)
                .foregroundStyle(.secondary)
                .lineLimit(3)
                .fixedSize(horizontal: false, vertical: true)

            HStack(spacing: 8) {
                Label("\(standard.supportedCategoryCount)/\(standard.categories.count)", systemImage: "checklist")
                Text(standard.coverage)
            }
            .font(.caption)
            .foregroundStyle(.secondary)
        }
        .padding(16)
        .frame(maxWidth: .infinity, minHeight: 168, alignment: .topLeading)
        .background(Color(nsColor: .textBackgroundColor))
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
    @Binding var isHelpVisible: Bool
    let onBack: () -> Void

    var body: some View {
        GeometryReader { proxy in
            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    header(width: proxy.size.width)
                    if isHelpVisible {
                        DetailHelpPanel(language: language, standard: standard)
                    }
                    content(width: proxy.size.width)
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

                Button {
                    isHelpVisible.toggle()
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
                    Text(standard.title)
                        .font(.system(size: scaledTitleSize(width), weight: .bold))
                        .foregroundStyle(.white)
                        .lineLimit(2)
                        .fixedSize(horizontal: false, vertical: true)

                    Text(standard.subtitle)
                        .font(.title3)
                        .foregroundStyle(.white.opacity(0.75))
                        .fixedSize(horizontal: false, vertical: true)
                }

                Spacer()
            }

            Text("\(standard.badge) | 매핑 항목 \(standard.supportedCategoryCount)/\(standard.categories.count)")
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
                DetailSummaryTile(title: language.scopeTitle, value: standard.scope)
                DetailSummaryTile(title: language.automationTitle, value: standard.coverage)
            }

            section(title: language.criteriaTitle) {
                LazyVGrid(columns: detailColumns(width), spacing: 12) {
                    ForEach(standard.categories) { category in
                        StandardCategoryRow(category: category)
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
                            .background(Color(nsColor: .textBackgroundColor))
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
        .background(Color(nsColor: .textBackgroundColor))
        .clipShape(RoundedRectangle(cornerRadius: 8))
        .overlay {
            RoundedRectangle(cornerRadius: 8)
                .stroke(Color(nsColor: .separatorColor), lineWidth: 1)
        }
    }
}

struct DetailHelpPanel: View {
    let language: AppLanguage
    let standard: AppSecurityStandard?

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 10) {
                Image(systemName: "questionmark.circle")
                    .foregroundStyle(.blue)
                Text(title)
                    .font(.headline)
            }

            Text(message)
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            VStack(alignment: .leading, spacing: 8) {
                Text(language.checkedItemsTitle)
                    .font(.subheadline.weight(.bold))
                    .foregroundStyle(.primary)

                if checkedCategories.isEmpty {
                    Text(language.noCheckedItemsTitle)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                } else {
                    LazyVGrid(columns: [GridItem(.adaptive(minimum: 240), spacing: 10)], spacing: 10) {
                        ForEach(checkedCategories) { category in
                            HelpCriteriaCard(category: category, language: language)
                        }
                    }
                }
            }
            .padding(.top, 4)
        }
        .padding(.horizontal, 22)
        .padding(.vertical, 14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(Color(nsColor: .textBackgroundColor))
        .overlay(alignment: .bottom) {
            Rectangle()
                .fill(Color(nsColor: .separatorColor))
                .frame(height: 1)
        }
    }

    private var title: String {
        switch language {
        case .ko: return "도움말"
        case .en: return "Help"
        }
    }

    private var message: String {
        let standardName = standard?.title ?? {
            switch language {
            case .ko: return "전체 조회"
            case .en: return "Overall Results"
            }
        }()

        switch language {
        case .ko:
            return "\(standardName) 화면입니다. 위험 점수는 치명 100점, 높음 40점, 중간 10점, 낮음 3점, 정보 1점을 더해 계산합니다. 기준별 결과는 로컬 정적 점검으로 매핑 가능한 항목만 포함하며, 런타임 점검이나 조직 증적이 필요한 항목은 별도 확인이 필요합니다."
        case .en:
            return "This is the \(standardName) view. Risk score is calculated as critical 100, high 40, medium 10, low 3, and info 1. Standard-specific results include locally mappable static checks only; runtime validation and organizational evidence still require separate review."
        }
    }

    private var checkedCategories: [AppStandardCategory] {
        if let standard {
            return standard.categories
        }
        return SecurityStandardCatalog.all.first { $0.id == "local" }?.categories ?? []
    }
}

private struct HelpCriteriaCard: View {
    let category: AppStandardCategory
    let language: AppLanguage

    var body: some View {
        VStack(alignment: .leading, spacing: 7) {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Text(category.title)
                    .font(.callout.weight(.semibold))
                    .lineLimit(2)
                    .fixedSize(horizontal: false, vertical: true)

                Spacer(minLength: 8)

                Text(category.isMapped ? language.localCheckBadge : language.partialCheckBadge)
                    .font(.caption.weight(.bold))
                    .foregroundStyle(category.isMapped ? .green : .orange)
            }

            Text(category.coverage)
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(12)
        .frame(maxWidth: .infinity, minHeight: 88, alignment: .topLeading)
        .background(Color(nsColor: .windowBackgroundColor))
        .clipShape(RoundedRectangle(cornerRadius: 8))
        .overlay {
            RoundedRectangle(cornerRadius: 8)
                .stroke(Color(nsColor: .separatorColor), lineWidth: 1)
        }
    }
}

private struct StandardCategoryRow: View {
    let category: AppStandardCategory

    var body: some View {
        VStack(alignment: .leading, spacing: 9) {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Text(category.title)
                    .font(.headline)
                    .lineLimit(2)
                    .fixedSize(horizontal: false, vertical: true)

                Spacer()

                Text(category.isMapped ? "로컬 점검" : "부분 지원")
                    .font(.caption.weight(.bold))
                    .foregroundStyle(category.isMapped ? .green : .orange)
            }

            Text(category.coverage)
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(14)
        .frame(maxWidth: .infinity, minHeight: 108, alignment: .topLeading)
        .background(Color(nsColor: .textBackgroundColor))
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
