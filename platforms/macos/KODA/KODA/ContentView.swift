import SwiftUI
import WebKit

struct ContentView: View {
    @StateObject private var scanner = ScannerBridge()
    @State private var activeStandard: AppSecurityStandard?
    @State private var homePane: HomePane = .standards

    var body: some View {
        GeometryReader { proxy in
            if let activeStandard {
                SecurityStandardDetailScreen(standard: activeStandard) {
                    self.activeStandard = nil
                }
            } else {
                homeView(size: proxy.size)
            }
        }
        .frame(minWidth: 860, minHeight: 640)
        .onChange(of: scanner.reportURL) { reportURL in
            if reportURL != nil {
                homePane = .report
            } else if homePane == .report {
                homePane = .standards
            }
        }
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

            lowerPane(size: size, minimumCardWidth: metrics.minimumCardWidth)
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

    private func lowerPane(size: CGSize, minimumCardWidth: CGFloat) -> some View {
        VStack(spacing: 0) {
            HStack(spacing: 12) {
                Text(homePane == .report ? "점검 결과" : "보안 점검 기준")
                    .font(.title3.weight(.bold))

                Spacer()

                if scanner.reportURL != nil {
                    Picker("하단 화면", selection: $homePane) {
                        Text("보안 기준").tag(HomePane.standards)
                        Text("점검 결과").tag(HomePane.report)
                    }
                    .pickerStyle(.segmented)
                    .frame(width: min(240, max(190, size.width * 0.24)))
                }
            }
            .padding(.horizontal, min(28, max(18, size.width * 0.025)))
            .padding(.vertical, 14)

            Divider()

            if homePane == .report, let reportURL = scanner.reportURL {
                ReportWebView(url: reportURL)
                    .id(reportURL)
            } else {
                SecurityStandardsGridView(
                    standards: SecurityStandardCatalog.all,
                    minimumCardWidth: minimumCardWidth
                ) { standard in
                    activeStandard = standard
                }
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

private enum HomePane: String {
    case standards
    case report
}

private struct DashboardLayoutMetrics {
    let outerPadding: CGFloat
    let verticalSpacing: CGFloat
    let targetListHeight: CGFloat
    let minimumCardWidth: CGFloat
}

private struct ReportWebView: NSViewRepresentable {
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
