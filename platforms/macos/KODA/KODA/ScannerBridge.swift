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
        let fileManager = FileManager.default
        guard let scannerRoot = locateScannerRoot(fileManager: fileManager) else {
            return ScanResult(
                exitCode: 2,
                reportURL: nil,
                message: "스캐너 리소스를 찾지 못했습니다.",
                detail: "앱 번들 리소스 또는 KODA_SCANNER_ROOT에서 security_scanner 패키지를 찾지 못했습니다."
            )
        }

        let output = fileManager.temporaryDirectory.appendingPathComponent("KODA-security-dashboard-\(UUID().uuidString).html")
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        var arguments = [
            "python3",
            "-m",
            "security_scanner",
            "scan",
            "--format",
            "html",
            "--language",
            "ko",
            "--output",
            output.path,
            "--discover-projects",
            "--discovery-depth",
            "20",
        ]
        for target in targets {
            arguments.append(contentsOf: ["--target", target.path])
        }
        process.arguments = arguments

        var environment = ProcessInfo.processInfo.environment
        environment["PYTHONPATH"] = scannerRoot.path
        process.environment = environment
        process.currentDirectoryURL = scannerRoot

        let outputPipe = Pipe()
        let errorPipe = Pipe()
        process.standardOutput = outputPipe
        process.standardError = errorPipe

        do {
            try process.run()
            process.waitUntilExit()
        } catch {
            return ScanResult(
                exitCode: 2,
                reportURL: nil,
                message: "스캐너 실행에 실패했습니다.",
                detail: "\(error.localizedDescription)\npython3 런타임을 실행할 수 있는지 확인하세요."
            )
        }

        let stdout = String(data: outputPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        let stderr = String(data: errorPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        let detail = [stdout, stderr].filter { !$0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }.joined(separator: "\n")

        return ScanResult(
            exitCode: process.terminationStatus,
            reportURL: process.terminationStatus == 0 ? output : nil,
            message: process.terminationStatus == 0 ? "점검 완료" : "점검 실패",
            detail: detail
        )
    }

    private nonisolated static func locateScannerRoot(fileManager: FileManager) -> URL? {
        if let configuredRoot = ProcessInfo.processInfo.environment["KODA_SCANNER_ROOT"], !configuredRoot.isEmpty {
            let url = URL(fileURLWithPath: configuredRoot)
            if hasScannerPackage(at: url, fileManager: fileManager) {
                return url
            }
        }

        if let resourceURL = Bundle.main.resourceURL, hasScannerPackage(at: resourceURL, fileManager: fileManager) {
            return resourceURL
        }

        var current = URL(fileURLWithPath: fileManager.currentDirectoryPath)
        for _ in 0..<10 {
            if hasScannerPackage(at: current, fileManager: fileManager) {
                return current
            }
            current.deleteLastPathComponent()
        }

        return nil
    }

    private nonisolated static func hasScannerPackage(at root: URL, fileManager: FileManager) -> Bool {
        let marker = root.appendingPathComponent("security_scanner/__main__.py").path
        return fileManager.fileExists(atPath: marker)
    }
}

private struct ScanResult {
    let exitCode: Int32
    let reportURL: URL?
    let message: String
    let detail: String
}
