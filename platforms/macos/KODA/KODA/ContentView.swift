import SwiftUI
import WebKit

struct ContentView: View {
    @StateObject private var scanner = ScannerBridge()
    @State private var activeStandard: AppSecurityStandard?
    @State private var activeReport: ScanReportItem?
    @State private var activeHelpGuide: HelpGuideRoute?
    @State private var language: AppLanguage = .ko

    var body: some View {
        GeometryReader { proxy in
            if let activeHelpGuide {
                HelpGuideScreen(
                    route: activeHelpGuide,
                    language: $language
                ) {
                    self.activeHelpGuide = nil
                }
            } else if let activeReport {
                ScanReportDetailScreen(
                    report: activeReport,
                    language: $language
                ) {
                    self.activeReport = nil
                } onHelp: {
                    self.activeHelpGuide = HelpGuideRoute(report: activeReport)
                } onExport: { format in
                    scanner.export(activeReport, as: format, language: language)
                }
            } else if let activeStandard {
                SecurityStandardDetailScreen(
                    standard: activeStandard,
                    language: $language
                ) {
                    self.activeStandard = nil
                } onHelp: {
                    self.activeHelpGuide = HelpGuideRoute(standard: activeStandard)
                }
            } else {
                homeView(size: proxy.size)
            }
        }
        .frame(minWidth: 860, minHeight: 640)
    }

    private func homeView(size: CGSize) -> some View {
        let metrics = layoutMetrics(for: size)

        return VSplitView {
            GeometryReader { topProxy in
                VStack(alignment: .leading, spacing: metrics.verticalSpacing) {
                    header
                    targetPicker(maxHeight: targetListHeight(for: topProxy.size, metrics: metrics))
                }
                .padding(metrics.outerPadding)
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
            }
            .frame(minHeight: 145, idealHeight: max(180, size.height * 0.24))

            lowerPane(minimumCardWidth: metrics.minimumCardWidth)
                .frame(minHeight: 260)
        }
    }

    private var header: some View {
        HStack(alignment: .center, spacing: 16) {
            Image(nsImage: NSApp.applicationIconImage)
                .resizable()
                .frame(width: 56, height: 56)
                .clipShape(RoundedRectangle(cornerRadius: 12))

            VStack(alignment: .leading, spacing: 6) {
                Text("KODA")
                    .font(.system(size: 31, weight: .bold))
                Text(language.appSubtitle)
                    .font(.title3)
                    .foregroundStyle(.secondary)
            }

            Spacer()

            LanguageToggle(language: $language)
        }
    }

    private func targetPicker(maxHeight: CGFloat) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text(language.targetsTitle)
                    .font(.headline)

                Spacer()

                Button(language.chooseFolderTitle) {
                    scanner.chooseFolder(language: language)
                }

                Button(language.uploadFilesTitle) {
                    scanner.chooseFiles(language: language)
                }

                Button(language.clearSelectionTitle) {
                    scanner.clearSelection()
                }
                .disabled(!scanner.hasSelection || scanner.isRunning)

                Button(scanner.isRunning ? language.runningTitle : language.runScanTitle) {
                    scanner.runScan()
                }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.borderedProminent)
                .disabled(!scanner.hasSelection || scanner.isRunning)
            }

            ScrollView {
                VStack(alignment: .leading, spacing: 8) {
                    if scanner.selectedTargets.isEmpty {
                        Text(language.noTargetsTitle)
                            .foregroundStyle(.secondary)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(.horizontal, 12)
                            .padding(.vertical, 10)
                            .background(KODATheme.insetBackground.opacity(0.65))
                            .clipShape(RoundedRectangle(cornerRadius: 7))
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
                                .help(language.removeTargetHelp)
                                .disabled(scanner.isRunning)
                            }
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(.horizontal, 12)
                            .padding(.vertical, 8)
                            .background(KODATheme.insetBackground.opacity(0.78))
                            .clipShape(RoundedRectangle(cornerRadius: 7))
                        }
                    }
                }
                .padding(8)
            }
            .frame(maxHeight: maxHeight)
            .background(KODATheme.cardBackground)
            .clipShape(RoundedRectangle(cornerRadius: 8))
        }
    }

    private var statusBar: some View {
        HStack(spacing: 14) {
            Circle()
                .fill(scanner.statusColor)
                .frame(width: 8, height: 8)

            Text(scanner.statusMessage(language: language))
                .foregroundStyle(scanner.statusColor)
                .lineLimit(1)
                .truncationMode(.middle)
                .textSelection(.enabled)

            if !scanner.detailMessage(language: language).isEmpty {
                Text(scanner.detailMessage(language: language))
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
            VStack(alignment: .leading, spacing: 8) {
                HStack(spacing: 12) {
                    Text(language.resultsTitle)
                        .font(.title3.weight(.bold))

                    Spacer()
                }

                statusBar
            }
            .padding(.horizontal, 22)
            .padding(.top, 14)
            .padding(.bottom, 12)

            Divider()

            ScanResultsGroupedView(
                reports: scanner.reportItems,
                standards: SecurityStandardCatalog.all,
                minimumCardWidth: minimumCardWidth,
                language: language
            ) { report in
                activeReport = report
                activeHelpGuide = nil
            } onSelectStandard: { standard in
                activeStandard = standard
                activeHelpGuide = nil
            }
        }
    }

    private func layoutMetrics(for size: CGSize) -> DashboardLayoutMetrics {
        DashboardLayoutMetrics(
            outerPadding: min(22, max(14, size.width * 0.02)),
            verticalSpacing: min(14, max(8, size.height * 0.014)),
            minimumCardWidth: min(340, max(250, size.width * 0.28))
        )
    }

    private func targetListHeight(for size: CGSize, metrics: DashboardLayoutMetrics) -> CGFloat {
        let reservedHeaderAndActions = CGFloat(140)
        return min(96, max(44, size.height - reservedHeaderAndActions - metrics.outerPadding))
    }
}

private struct DashboardLayoutMetrics {
    let outerPadding: CGFloat
    let verticalSpacing: CGFloat
    let minimumCardWidth: CGFloat
}

private struct ScanReportDetailScreen: View {
    let report: ScanReportItem
    @Binding var language: AppLanguage
    let onBack: () -> Void
    let onHelp: () -> Void
    let onExport: (ReportExportFormat) -> Void
    @Environment(\.colorScheme) private var colorScheme

    var body: some View {
        VStack(spacing: 0) {
            detailTopBar

            ReportWebView(url: report.htmlURL(language: language), colorScheme: colorScheme)
                .id(report.htmlURL(language: language))
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
                Text(report.title(language: language))
                    .font(.title2.weight(.bold))
                    .foregroundStyle(.white)
                    .lineLimit(1)
                Text("\(language.findingsTitle): \(report.findingCount) | \(language.riskScoreTitle): \(report.riskScore)")
                    .font(.caption)
                    .foregroundStyle(.white.opacity(0.75))
            }

            Spacer()

            Menu {
                ForEach(ReportExportFormat.allCases, id: \.self) { format in
                    Button(format.title(language: language)) {
                        onExport(format)
                    }
                }
            } label: {
                Label(language.exportTitle, systemImage: "square.and.arrow.down")
                    .font(.callout.weight(.bold))
                    .padding(.horizontal, 12)
                    .padding(.vertical, 7)
                    .foregroundStyle(.white)
                    .background(Color(red: 0.04, green: 0.47, blue: 0.72))
                    .clipShape(RoundedRectangle(cornerRadius: 8))
                    .overlay {
                        RoundedRectangle(cornerRadius: 8)
                            .stroke(Color.white.opacity(0.28), lineWidth: 1)
                    }
            }
            .menuStyle(.borderlessButton)

            Button {
                onHelp()
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

struct ReportWebView: NSViewRepresentable {
    let url: URL
    let colorScheme: ColorScheme

    func makeCoordinator() -> Coordinator {
        Coordinator()
    }

    func makeNSView(context: Context) -> WKWebView {
        let configuration = WKWebViewConfiguration()
        let webView = WKWebView(frame: .zero, configuration: configuration)
        webView.allowsMagnification = true
        webView.setValue(false, forKey: "drawsBackground")
        return webView
    }

    func updateNSView(_ webView: WKWebView, context: Context) {
        let appearanceName: NSAppearance.Name = colorScheme == .dark ? .darkAqua : .aqua
        webView.appearance = NSAppearance(named: appearanceName)

        guard context.coordinator.loadedURL != url || context.coordinator.loadedColorScheme != colorScheme else {
            return
        }

        context.coordinator.loadedURL = url
        context.coordinator.loadedColorScheme = colorScheme
        webView.loadFileURL(url, allowingReadAccessTo: url.deletingLastPathComponent())
    }

    final class Coordinator {
        var loadedURL: URL?
        var loadedColorScheme: ColorScheme?
    }
}
