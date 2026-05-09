import AppKit
import Foundation
import SwiftUI

@MainActor
final class ScannerBridge: ObservableObject {
    @Published var selectedTargets: [URL] = []
    @Published var reportURL: URL?
    @Published var reportItems: [ScanReportItem] = []
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
        reportItems = []
        detailMessage = ""
        statusMessage = "점검할 폴더나 파일을 선택하세요."
        statusColor = .secondary
    }

    func removeTarget(_ url: URL) {
        selectedTargets.removeAll { $0.path == url.path }
        reportURL = nil
        reportItems = []
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
        reportItems = []
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
                reportItems = result.reportItems
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
            let reportItems = try buildReportItems(result: result, scanner: scanner, overallURL: output)
            let warningText = result.warnings.isEmpty ? "" : "\n경고:\n" + result.warnings.joined(separator: "\n")
            return ScanResult(
                exitCode: 0,
                reportURL: output,
                message: "점검 완료",
                detail: "스캔 파일 \(result.scannedFileCount)개, 발견 항목 \(result.findings.count)건\(warningText)",
                reportItems: reportItems
            )
        } catch {
            return ScanResult(
                exitCode: 2,
                reportURL: nil,
                message: "스캐너 실행에 실패했습니다.",
                detail: error.localizedDescription,
                reportItems: []
            )
        }
    }

    private nonisolated static func buildReportItems(
        result: NativeScanResult,
        scanner: NativeSecurityScanner,
        overallURL: URL
    ) throws -> [ScanReportItem] {
        var items = [
            ScanReportItem(
                id: "overall",
                title: "전체 조회",
                subtitle: "모든 로컬 점검 결과를 기준 제한 없이 확인합니다.",
                badge: "전체",
                icon: "rectangle.stack",
                accent: .blue,
                reportURL: overallURL,
                findingCount: result.findings.count,
                riskScore: result.riskScore,
                severityDistribution: SeverityDistribution(findings: result.findings),
                standard: nil
            )
        ]

        for standard in SecurityStandardCatalog.all {
            let findings = result.findings.filter { findingMatches($0, standard: standard) }
            let standardResult = NativeScanResult(
                findings: findings,
                warnings: result.warnings,
                targetCount: result.targetCount,
                scannedFileCount: result.scannedFileCount,
                generatedAt: result.generatedAt
            )
            let fileName = "KODA-\(standard.id)-security-dashboard-\(UUID().uuidString).html"
            let output = FileManager.default.temporaryDirectory.appendingPathComponent(fileName)
            try scanner.writeHTMLReport(standardResult, to: output)
            items.append(
                ScanReportItem(
                    id: standard.id,
                    title: standard.title,
                    subtitle: standard.scope,
                    badge: standard.badge,
                    icon: standard.icon,
                    accent: standard.accent,
                    reportURL: output,
                    findingCount: findings.count,
                    riskScore: standardResult.riskScore,
                    severityDistribution: SeverityDistribution(findings: findings),
                    standard: standard
                )
            )
        }

        return items
    }

    private nonisolated static func findingMatches(_ finding: NativeFinding, standard: AppSecurityStandard) -> Bool {
        switch standard.id {
        case "local", "isms-p-28", "nist-ssdf", "owasp-samm-2":
            return true
        case "owasp-dependency-check", "owasp-dependency-track":
            return finding.category == "dependencies" || finding.ruleID.contains("dependency")
        case "owasp-api-security-2023":
            return finding.ruleID.contains("api")
                || finding.ruleID.contains("ssrf")
                || finding.ruleID.contains("cors")
                || finding.ruleID.contains("auth")
                || finding.category == "configuration"
        case "owasp-mobile-top-10-2024":
            return finding.category == "secrets"
                || finding.category == "configuration"
                || finding.category == "dependencies"
        case "ncsc-web-8", "electronic-financial-8":
            return finding.category == "code" || finding.category == "configuration"
        case "sw-dev-security-49", "sw-dev-security-7-types", "kisa-secure-coding":
            return finding.category == "code"
                || finding.category == "secrets"
                || finding.category == "configuration"
        default:
            return true
        }
    }
}

struct ScanReportItem: Identifiable, Hashable {
    let id: String
    let title: String
    let subtitle: String
    let badge: String
    let icon: String
    let accent: StandardAccent
    let reportURL: URL
    let findingCount: Int
    let riskScore: Int
    let severityDistribution: SeverityDistribution
    let standard: AppSecurityStandard?

    var isOverall: Bool {
        standard == nil
    }
}

struct SeverityDistribution: Hashable {
    let critical: Int
    let high: Int
    let medium: Int
    let low: Int
    let info: Int

    init(critical: Int = 0, high: Int = 0, medium: Int = 0, low: Int = 0, info: Int = 0) {
        self.critical = critical
        self.high = high
        self.medium = medium
        self.low = low
        self.info = info
    }

    init(findings: [NativeFinding]) {
        let counts = Dictionary(grouping: findings, by: \.severity).mapValues(\.count)
        self.init(
            critical: counts["critical"] ?? 0,
            high: counts["high"] ?? 0,
            medium: counts["medium"] ?? 0,
            low: counts["low"] ?? 0,
            info: counts["info"] ?? 0
        )
    }

    var maximum: Int {
        max(critical, high, medium, low, info, 1)
    }
}

private struct ScanResult {
    let exitCode: Int32
    let reportURL: URL?
    let message: String
    let detail: String
    let reportItems: [ScanReportItem]
}
