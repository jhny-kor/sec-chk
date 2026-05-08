import AppKit
import Foundation
import SwiftUI

@MainActor
final class ScannerBridge: ObservableObject {
    @Published var selectedFolder: URL?
    @Published var reportURL: URL?
    @Published var isRunning = false
    @Published var statusMessage = "점검할 폴더를 선택하세요."
    @Published var detailMessage = ""
    @Published var statusColor: Color = .secondary

    func chooseFolder() {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.prompt = "선택"
        panel.message = "보안취약점을 점검할 폴더를 선택하세요."

        if panel.runModal() == .OK {
            selectedFolder = panel.url
            reportURL = nil
            detailMessage = ""
            statusMessage = "선택됨: \(panel.url?.path ?? "")"
            statusColor = .secondary
        }
    }

    func runScan() {
        guard let selectedFolder else {
            statusMessage = "먼저 점검할 폴더를 선택하세요."
            statusColor = .red
            return
        }

        isRunning = true
        reportURL = nil
        detailMessage = ""
        statusMessage = "보안 점검을 실행하고 있습니다."
        statusColor = .secondary

        Task {
            let result = await Self.runScanCommand(folder: selectedFolder)
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

    private static func runScanCommand(folder: URL) async -> ScanResult {
        let fileManager = FileManager.default
        guard let scannerRoot = locateScannerRoot(fileManager: fileManager) else {
            return ScanResult(
                exitCode: 2,
                reportURL: nil,
                message: "스캐너 리소스를 찾지 못했습니다.",
                detail: "개발 실행은 KODA_SCANNER_ROOT 환경변수 또는 저장소 루트에서 실행해야 합니다. App Store 빌드는 security_scanner 패키지를 앱 리소스로 포함해야 합니다."
            )
        }

        let output = fileManager.temporaryDirectory.appendingPathComponent("KODA-security-dashboard.html")
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = [
            "python3",
            "-m",
            "security_scanner",
            "scan",
            "--target",
            folder.path,
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
                detail: error.localizedDescription
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

    private static func locateScannerRoot(fileManager: FileManager) -> URL? {
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

    private static func hasScannerPackage(at root: URL, fileManager: FileManager) -> Bool {
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
