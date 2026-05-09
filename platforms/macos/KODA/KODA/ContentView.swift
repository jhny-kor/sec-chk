import SwiftUI
import WebKit

struct ContentView: View {
    @StateObject private var scanner = ScannerBridge()
    @State private var activeStandard: AppSecurityStandard?
    @State private var activeReport: ScanReportItem?
    @State private var language: AppLanguage = .ko
    @State private var isHelpVisible = false

    var body: some View {
        GeometryReader { proxy in
            if let activeReport {
                ScanReportDetailScreen(
                    report: activeReport,
                    language: $language,
                    isHelpVisible: $isHelpVisible
                ) {
                    self.activeReport = nil
                }
            } else if let activeStandard {
                SecurityStandardDetailScreen(
                    standard: activeStandard,
                    language: $language,
                    isHelpVisible: $isHelpVisible
                ) {
                    self.activeStandard = nil
                }
            } else {
                homeView(size: proxy.size)
            }
        }
        .frame(minWidth: 860, minHeight: 640)
    }

    private func homeView(size: CGSize) -> some View {
        let metrics = layoutMetrics(for: size)

        return VStack(spacing: 0) {
            VStack(alignment: .leading, spacing: metrics.verticalSpacing) {
                header
                targetPicker(maxHeight: metrics.targetListHeight)
                statusBar
            }
            .padding(metrics.outerPadding)

            Divider()

            lowerPane(minimumCardWidth: metrics.minimumCardWidth)
        }
    }

    private var header: some View {
        HStack(alignment: .center, spacing: 16) {
            Image(nsImage: NSApp.applicationIconImage)
                .resizable()
                .frame(width: 64, height: 64)
                .clipShape(RoundedRectangle(cornerRadius: 14))

            VStack(alignment: .leading, spacing: 6) {
                Text("KODA")
                    .font(.system(size: 34, weight: .bold))
                Text("로컬 프로젝트 보안 점검")
                    .font(.title3)
                    .foregroundStyle(.secondary)
            }

            Spacer()

            Button("외부 브라우저로 열기") {
                scanner.openReport()
            }
            .disabled(scanner.reportURL == nil)
        }
    }

    private func targetPicker(maxHeight: CGFloat) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Text("점검 대상")
                    .font(.headline)

                Spacer()

                Button("폴더 선택") {
                    scanner.chooseFolder()
                }

                Button("파일 업로드") {
                    scanner.chooseFiles()
                }

                Button("선택 초기화") {
                    scanner.clearSelection()
                }
                .disabled(!scanner.hasSelection || scanner.isRunning)

                Button(scanner.isRunning ? "점검 중" : "보안 점검 실행") {
                    scanner.runScan()
                }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.borderedProminent)
                .disabled(!scanner.hasSelection || scanner.isRunning)
            }

            ScrollView {
                VStack(alignment: .leading, spacing: 8) {
                    if scanner.selectedTargets.isEmpty {
                        Text("선택된 항목 없음")
                            .foregroundStyle(.secondary)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(.horizontal, 12)
                            .padding(.vertical, 10)
                    } else {
                        ForEach(scanner.selectedTargets, id: \.path) { target in
                            HStack(spacing: 8) {
                                Image(systemName: target.hasDirectoryPath ? "folder" : "doc")
                                    .foregroundStyle(.secondary)
                                Text(target.path)
                                    .lineLimit(1)
                                    .truncationMode(.middle)

                                Spacer(minLength: 8)

                                Button {
                                    scanner.removeTarget(target)
                                } label: {
                                    Image(systemName: "xmark.circle.fill")
                                        .foregroundStyle(.secondary)
                                }
                                .buttonStyle(.plain)
                                .help("점검 대상 삭제")
                                .disabled(scanner.isRunning)
                            }
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(.horizontal, 12)
                            .padding(.vertical, 8)
                        }
                    }
                }
            }
            .frame(maxHeight: maxHeight)
            .background(Color(nsColor: .textBackgroundColor))
            .clipShape(RoundedRectangle(cornerRadius: 8))
        }
    }

    private var statusBar: some View {
        HStack(spacing: 14) {
            Circle()
                .fill(scanner.statusColor)
                .frame(width: 8, height: 8)

            Text(scanner.statusMessage)
                .foregroundStyle(scanner.statusColor)
                .lineLimit(1)
                .truncationMode(.middle)
                .textSelection(.enabled)

            if !scanner.detailMessage.isEmpty {
                Text(scanner.detailMessage)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .truncationMode(.tail)
                    .textSelection(.enabled)
            }

            Spacer()
        }
        .font(.callout)
    }

    private func lowerPane(minimumCardWidth: CGFloat) -> some View {
        VStack(spacing: 0) {
            HStack(spacing: 12) {
                Text("점검 결과 조회")
                    .font(.title3.weight(.bold))

                Spacer()
            }
            .padding(.horizontal, 22)
            .padding(.vertical, 14)

            Divider()

            ScanResultsGroupedView(
                reports: scanner.reportItems,
                standards: SecurityStandardCatalog.all,
                minimumCardWidth: minimumCardWidth
            ) { report in
                activeReport = report
                isHelpVisible = false
            } onSelectStandard: { standard in
                activeStandard = standard
                isHelpVisible = false
            }
        }
    }

    private func layoutMetrics(for size: CGSize) -> DashboardLayoutMetrics {
        DashboardLayoutMetrics(
            outerPadding: min(28, max(16, size.width * 0.025)),
            verticalSpacing: min(18, max(12, size.height * 0.02)),
            targetListHeight: min(150, max(82, size.height * 0.17)),
            minimumCardWidth: min(340, max(250, size.width * 0.28))
        )
    }
}

private struct DashboardLayoutMetrics {
    let outerPadding: CGFloat
    let verticalSpacing: CGFloat
    let targetListHeight: CGFloat
    let minimumCardWidth: CGFloat
}

private struct ScanReportDetailScreen: View {
    let report: ScanReportItem
    @Binding var language: AppLanguage
    @Binding var isHelpVisible: Bool
    let onBack: () -> Void

    var body: some View {
        VStack(spacing: 0) {
            detailTopBar

            if isHelpVisible {
                DetailHelpPanel(language: language, standard: report.standard)
            }

            RiskScoreOverviewPanel(report: report, language: language)

            ReportWebView(url: report.reportURL)
                .id(report.reportURL)
        }
        .background(Color(nsColor: .windowBackgroundColor))
    }

    private var detailTopBar: some View {
        HStack(spacing: 14) {
            Button {
                onBack()
            } label: {
                Label(language.backTitle, systemImage: "chevron.left")
            }
            .buttonStyle(.borderless)
            .foregroundStyle(.white)

            VStack(alignment: .leading, spacing: 4) {
                Text(report.title)
                    .font(.title2.weight(.bold))
                    .foregroundStyle(.white)
                    .lineLimit(1)
                Text("\(language.findingsTitle): \(report.findingCount) | \(language.riskScoreTitle): \(report.riskScore)")
                    .font(.caption)
                    .foregroundStyle(.white.opacity(0.75))
            }

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
        .padding(.horizontal, 22)
        .padding(.vertical, 14)
        .background(Color(red: 0.04, green: 0.07, blue: 0.13))
    }
}

private struct RiskScoreOverviewPanel: View {
    let report: ScanReportItem
    let language: AppLanguage

    var body: some View {
        LazyVGrid(columns: [GridItem(.adaptive(minimum: 280), spacing: 14)], alignment: .leading, spacing: 14) {
            VStack(alignment: .leading, spacing: 9) {
                HStack(spacing: 8) {
                    Image(systemName: "function")
                        .foregroundStyle(report.accent.color)
                    Text(language.riskFormulaTitle)
                        .font(.headline)
                }

                Text(language.riskFormulaDescription)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)

                Text("\(language.riskScoreTitle): \(report.riskScore)")
                    .font(.title3.weight(.bold))
                    .foregroundStyle(report.accent.color)
            }
            .padding(16)
            .frame(maxWidth: .infinity, minHeight: 150, alignment: .topLeading)
            .background(Color(nsColor: .textBackgroundColor))
            .clipShape(RoundedRectangle(cornerRadius: 8))
            .overlay {
                RoundedRectangle(cornerRadius: 8)
                    .stroke(Color(nsColor: .separatorColor), lineWidth: 1)
            }

            SeverityDistributionChart(
                distribution: report.severityDistribution,
                language: language
            )
            .padding(16)
            .frame(maxWidth: .infinity, minHeight: 150, alignment: .topLeading)
            .background(Color(nsColor: .textBackgroundColor))
            .clipShape(RoundedRectangle(cornerRadius: 8))
            .overlay {
                RoundedRectangle(cornerRadius: 8)
                    .stroke(Color(nsColor: .separatorColor), lineWidth: 1)
            }
        }
        .padding(.horizontal, 22)
        .padding(.vertical, 14)
        .background(Color(nsColor: .windowBackgroundColor))
        .overlay(alignment: .bottom) {
            Rectangle()
                .fill(Color(nsColor: .separatorColor))
                .frame(height: 1)
        }
    }
}

private struct SeverityDistributionChart: View {
    let distribution: SeverityDistribution
    let language: AppLanguage

    private var buckets: [SeverityBucket] {
        SeverityBucket.all(language: language, distribution: distribution)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 8) {
                Image(systemName: "chart.bar.xaxis")
                    .foregroundStyle(.blue)
                Text(language.severityDistributionTitle)
                    .font(.headline)
            }

            VStack(alignment: .leading, spacing: 9) {
                ForEach(buckets) { bucket in
                    SeverityBarRow(bucket: bucket, maximum: distribution.maximum)
                }
            }
        }
    }
}

private struct SeverityBucket: Identifiable {
    let id: String
    let label: String
    let count: Int
    let color: Color

    static func all(language: AppLanguage, distribution: SeverityDistribution) -> [SeverityBucket] {
        [
            SeverityBucket(id: "critical", label: language.severityLabel("critical"), count: distribution.critical, color: Color(red: 0.50, green: 0.11, blue: 0.11)),
            SeverityBucket(id: "high", label: language.severityLabel("high"), count: distribution.high, color: Color(red: 0.70, green: 0.13, blue: 0.09)),
            SeverityBucket(id: "medium", label: language.severityLabel("medium"), count: distribution.medium, color: Color(red: 0.72, green: 0.48, blue: 0.12)),
            SeverityBucket(id: "low", label: language.severityLabel("low"), count: distribution.low, color: .blue),
            SeverityBucket(id: "info", label: language.severityLabel("info"), count: distribution.info, color: .secondary)
        ]
    }
}

private struct SeverityBarRow: View {
    let bucket: SeverityBucket
    let maximum: Int

    var body: some View {
        HStack(spacing: 10) {
            Text(bucket.label)
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
                .frame(width: 58, alignment: .leading)

            GeometryReader { proxy in
                ZStack(alignment: .leading) {
                    Capsule()
                        .fill(Color(nsColor: .controlBackgroundColor))

                    Capsule()
                        .fill(bucket.color)
                        .frame(width: barWidth(in: proxy.size.width))
                }
            }
            .frame(height: 9)

            Text("\(bucket.count)")
                .font(.caption.monospacedDigit().weight(.semibold))
                .frame(width: 32, alignment: .trailing)
        }
    }

    private func barWidth(in width: CGFloat) -> CGFloat {
        guard bucket.count > 0 else {
            return 0
        }
        return max(6, width * CGFloat(bucket.count) / CGFloat(maximum))
    }
}

struct ReportWebView: NSViewRepresentable {
    let url: URL

    func makeCoordinator() -> Coordinator {
        Coordinator()
    }

    func makeNSView(context: Context) -> WKWebView {
        let configuration = WKWebViewConfiguration()
        let webView = WKWebView(frame: .zero, configuration: configuration)
        webView.allowsMagnification = true
        return webView
    }

    func updateNSView(_ webView: WKWebView, context: Context) {
        guard context.coordinator.loadedURL != url else {
            return
        }

        context.coordinator.loadedURL = url
        webView.loadFileURL(url, allowingReadAccessTo: url.deletingLastPathComponent())
    }

    final class Coordinator {
        var loadedURL: URL?
    }
}
