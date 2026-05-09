import AppKit
import Foundation
import SwiftUI

@MainActor
final class ScannerBridge: ObservableObject {
    @Published var selectedTargets: [URL] = []
    @Published var reportURL: URL?
    @Published var isRunning = false
    @Published var statusMessage = "점검할 폴더나 파일을 선택하세요."
    @Published var detailMessage = ""
    @Published var statusColor: Color = .secondary

    var hasSelection: Bool {
        !selectedTargets.isEmpty
    }

    func chooseFolder() {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = true
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.prompt = "선택"
        panel.message = "보안취약점을 점검할 폴더를 선택하세요."

        if panel.runModal() == .OK {
            appendTargets(panel.urls)
        }
    }

    func chooseFiles() {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = true
        panel.canChooseDirectories = false
        panel.canChooseFiles = true
        panel.prompt = "업로드"
        panel.message = "점검할 파일을 선택하세요. zip, jar, war, tar, tar.gz, tgz, gz 압축파일도 선택할 수 있습니다."

        if panel.runModal() == .OK {
            appendTargets(panel.urls)
        }
    }

    func clearSelection() {
        selectedTargets = []
        reportURL = nil
        detailMessage = ""
        statusMessage = "점검할 폴더나 파일을 선택하세요."
        statusColor = .secondary
    }

    func removeTarget(_ url: URL) {
        selectedTargets.removeAll { $0.path == url.path }
        reportURL = nil
        detailMessage = ""

        if selectedTargets.isEmpty {
            statusMessage = "점검할 폴더나 파일을 선택하세요."
        } else {
            statusMessage = "\(selectedTargets.count)개 항목 선택됨"
        }
        statusColor = .secondary
    }

    func runScan() {
        let targets = selectedTargets
        guard !targets.isEmpty else {
            statusMessage = "먼저 점검할 폴더나 파일을 선택하세요."
            statusColor = .red
            return
        }

        isRunning = true
        reportURL = nil
        detailMessage = ""
        statusMessage = "보안 점검을 실행하고 있습니다."
        statusColor = .secondary

        Task {
            let result = await Task.detached(priority: .userInitiated) {
                Self.runScanCommand(targets: targets)
            }.value
            isRunning = false
            detailMessage = result.detail
            if result.exitCode == 0, let output = result.reportURL {
                reportURL = output
                statusMessage = "점검 완료: \(output.path)"
                statusColor = .green
            } else {
                statusMessage = result.message
                statusColor = .red
            }
        }
    }

    func openReport() {
        guard let reportURL else { return }
        NSWorkspace.shared.open(reportURL)
    }

    private func appendTargets(_ urls: [URL]) {
        var seen = Set(selectedTargets.map(\.path))
        let additions = urls.filter { seen.insert($0.path).inserted }
        selectedTargets.append(contentsOf: additions)
        reportURL = nil
        detailMessage = ""
        statusMessage = "\(selectedTargets.count)개 항목 선택됨"
        statusColor = .secondary
    }

    private nonisolated static func runScanCommand(targets: [URL]) -> ScanResult {
        let scanner = NativeSecurityScanner()
        let fileManager = FileManager.default
        let output = fileManager.temporaryDirectory.appendingPathComponent("KODA-security-dashboard-\(UUID().uuidString).html")
        let accessedTargets = targets.filter { $0.startAccessingSecurityScopedResource() }
        defer {
            accessedTargets.forEach { $0.stopAccessingSecurityScopedResource() }
        }

        do {
            let result = try scanner.scan(targets: targets)
            try scanner.writeHTMLReport(result, to: output)
            let warningText = result.warnings.isEmpty ? "" : "\n경고:\n" + result.warnings.joined(separator: "\n")
            return ScanResult(
                exitCode: 0,
                reportURL: output,
                message: "점검 완료",
                detail: "스캔 파일 \(result.scannedFileCount)개, 발견 항목 \(result.findings.count)건\(warningText)"
            )
        } catch {
            return ScanResult(
                exitCode: 2,
                reportURL: nil,
                message: "스캐너 실행에 실패했습니다.",
                detail: error.localizedDescription
            )
        }
    }
}

private struct ScanResult {
    let exitCode: Int32
    let reportURL: URL?
    let message: String
    let detail: String
}
