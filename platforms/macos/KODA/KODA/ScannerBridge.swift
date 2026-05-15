import AppKit
import Foundation
import SwiftUI
import UniformTypeIdentifiers

enum ReportExportFormat: String, CaseIterable, Hashable {
    case html
    case markdown
    case pdf

    var fileExtension: String {
        switch self {
        case .html: return "html"
        case .markdown: return "md"
        case .pdf: return "pdf"
        }
    }

    var contentType: UTType {
        switch self {
        case .html:
            return .html
        case .markdown:
            return UTType(filenameExtension: "md") ?? .plainText
        case .pdf:
            return .pdf
        }
    }

    func title(language: AppLanguage) -> String {
        switch (language, self) {
        case (.ko, .html): return "HTML 다운로드"
        case (.ko, .markdown): return "MD 다운로드"
        case (.ko, .pdf): return "PDF 다운로드"
        case (.en, .html): return "Download HTML"
        case (.en, .markdown): return "Download MD"
        case (.en, .pdf): return "Download PDF"
        }
    }
}

@MainActor
final class ScannerBridge: ObservableObject {
    @Published var selectedTargets: [URL] = []
    @Published var reportURL: URL?
    @Published var reportItems: [ScanReportItem] = []
    @Published var isRunning = false
    @Published private var statusMessageKO = "점검할 폴더나 파일을 선택하세요."
    @Published private var statusMessageEN = "Choose folders or files to scan."
    @Published private var detailMessageKO = ""
    @Published private var detailMessageEN = ""
    @Published var statusColor: Color = .secondary

    var hasSelection: Bool {
        !selectedTargets.isEmpty
    }

    var statusMessage: String {
        statusMessageKO
    }

    var detailMessage: String {
        detailMessageKO
    }

    func statusMessage(language: AppLanguage) -> String {
        language == .ko ? statusMessageKO : statusMessageEN
    }

    func detailMessage(language: AppLanguage) -> String {
        language == .ko ? detailMessageKO : detailMessageEN
    }

    func chooseFolder(language: AppLanguage = .ko) {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = true
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.prompt = language == .ko ? "선택" : "Choose"
        panel.message = language == .ko
            ? "보안취약점을 점검할 폴더를 선택하세요."
            : "Choose folders to scan for security issues."

        if panel.runModal() == .OK {
            appendTargets(panel.urls)
        }
    }

    func chooseFiles(language: AppLanguage = .ko) {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = true
        panel.canChooseDirectories = false
        panel.canChooseFiles = true
        panel.prompt = language == .ko ? "업로드" : "Upload"
        panel.message = language == .ko
            ? "점검할 파일을 선택하세요. zip, jar, war, tar, tar.gz, tgz, gz 압축파일도 선택할 수 있습니다."
            : "Choose files to scan. zip, jar, war, tar, tar.gz, tgz, and gz archives are supported."

        if panel.runModal() == .OK {
            appendTargets(panel.urls)
        }
    }

    func clearSelection() {
        selectedTargets = []
        reportURL = nil
        reportItems = []
        setDetail(ko: "", en: "")
        setStatus(ko: "점검할 폴더나 파일을 선택하세요.", en: "Choose folders or files to scan.")
        statusColor = .secondary
    }

    func removeTarget(_ url: URL) {
        selectedTargets.removeAll { $0.path == url.path }
        reportURL = nil
        reportItems = []
        setDetail(ko: "", en: "")

        if selectedTargets.isEmpty {
            setStatus(ko: "점검할 폴더나 파일을 선택하세요.", en: "Choose folders or files to scan.")
        } else {
            setStatus(ko: "\(selectedTargets.count)개 항목 선택됨", en: "\(selectedTargets.count) item(s) selected")
        }
        statusColor = .secondary
    }

    func runScan() {
        let targets = selectedTargets
        guard !targets.isEmpty else {
            setStatus(ko: "먼저 점검할 폴더나 파일을 선택하세요.", en: "Choose folders or files before scanning.")
            statusColor = .red
            return
        }

        isRunning = true
        reportURL = nil
        reportItems = []
        setDetail(ko: "", en: "")
        setStatus(ko: "보안 점검을 실행하고 있습니다.", en: "Running security scan.")
        statusColor = .secondary

        Task {
            let result = await Task.detached(priority: .userInitiated) {
                Self.runScanCommand(targets: targets)
            }.value
            isRunning = false
            setDetail(ko: result.detailKO, en: result.detailEN)
            if result.exitCode == 0, let output = result.reportURL {
                reportURL = output
                reportItems = result.reportItems
                setStatus(ko: "점검 완료: \(output.path)", en: "Scan complete: \(output.path)")
                statusColor = .green
            } else {
                setStatus(ko: result.messageKO, en: result.messageEN)
                statusColor = .red
            }
        }
    }

    func openReport(language: AppLanguage = .ko) {
        guard let reportURL else { return }
        if let report = reportItems.first(where: \.isOverall) {
            NSWorkspace.shared.open(report.htmlURL(language: language))
        } else {
            NSWorkspace.shared.open(reportURL)
        }
    }

    func export(_ report: ScanReportItem, as format: ReportExportFormat, language: AppLanguage) {
        let source = report.url(format: format, language: language)
        let panel = NSSavePanel()
        panel.allowedContentTypes = [format.contentType]
        panel.canCreateDirectories = true
        panel.nameFieldStringValue = report.exportFileName(format: format, language: language)
        panel.message = language == .ko
            ? "점검결과를 저장할 위치를 선택하세요."
            : "Choose where to save the scan result."

        guard panel.runModal() == .OK, let destination = panel.url else {
            return
        }

        do {
            if FileManager.default.fileExists(atPath: destination.path) {
                try FileManager.default.removeItem(at: destination)
            }
            try FileManager.default.copyItem(at: source, to: destination)
            setStatus(
                ko: "\(format.fileExtension.uppercased()) 저장 완료: \(destination.path)",
                en: "\(format.fileExtension.uppercased()) saved: \(destination.path)"
            )
            statusColor = .green
        } catch {
            setStatus(
                ko: "다운로드 실패: \(error.localizedDescription)",
                en: "Download failed: \(error.localizedDescription)"
            )
            statusColor = .red
        }
    }

    private func appendTargets(_ urls: [URL]) {
        var seen = Set(selectedTargets.map(\.path))
        let additions = urls.filter { seen.insert($0.path).inserted }
        selectedTargets.append(contentsOf: additions)
        reportURL = nil
        setDetail(ko: "", en: "")
        setStatus(ko: "\(selectedTargets.count)개 항목 선택됨", en: "\(selectedTargets.count) item(s) selected")
        statusColor = .secondary
    }

    private func setStatus(ko: String, en: String) {
        statusMessageKO = ko
        statusMessageEN = en
    }

    private func setDetail(ko: String, en: String) {
        detailMessageKO = ko
        detailMessageEN = en
    }

    private nonisolated static func runScanCommand(targets: [URL]) -> ScanResult {
        let scanner = NativeSecurityScanner()
        let accessedTargets = targets.filter { $0.startAccessingSecurityScopedResource() }
        defer {
            accessedTargets.forEach { $0.stopAccessingSecurityScopedResource() }
        }

        do {
            let result = try scanner.scan(targets: targets)
            let overallFiles = try writeReportFiles(result: result, scanner: scanner, prefix: "KODA-security-dashboard")
            let reportItems = try buildReportItems(result: result, scanner: scanner, overallFiles: overallFiles)
            let warningTextKO = result.warnings.isEmpty ? "" : "\n경고:\n" + result.warnings.joined(separator: "\n")
            let warningTextEN = result.warnings.isEmpty ? "" : "\nWarnings:\n" + result.warnings.joined(separator: "\n")
            return ScanResult(
                exitCode: 0,
                reportURL: overallFiles.koHTMLURL,
                messageKO: "점검 완료",
                messageEN: "Scan complete",
                detailKO: "스캔 파일 \(result.scannedFileCount)개, 발견 항목 \(result.findings.count)건\(warningTextKO)",
                detailEN: "Scanned files \(result.scannedFileCount), findings \(result.findings.count)\(warningTextEN)",
                reportItems: reportItems
            )
        } catch {
            return ScanResult(
                exitCode: 2,
                reportURL: nil,
                messageKO: "스캐너 실행에 실패했습니다.",
                messageEN: "Scanner failed.",
                detailKO: error.localizedDescription,
                detailEN: error.localizedDescription,
                reportItems: []
            )
        }
    }

    private nonisolated static func writeReportFiles(
        result: NativeScanResult,
        scanner: NativeSecurityScanner,
        prefix: String
    ) throws -> GeneratedReportFiles {
        let token = UUID().uuidString
        let directory = FileManager.default.temporaryDirectory
        let koHTML = directory.appendingPathComponent("\(prefix)-ko-\(token).html")
        let enHTML = directory.appendingPathComponent("\(prefix)-en-\(token).html")
        let koMarkdown = directory.appendingPathComponent("\(prefix)-ko-\(token).md")
        let enMarkdown = directory.appendingPathComponent("\(prefix)-en-\(token).md")
        let koPDF = directory.appendingPathComponent("\(prefix)-ko-\(token).pdf")
        let enPDF = directory.appendingPathComponent("\(prefix)-en-\(token).pdf")

        try scanner.writeHTMLReport(result, to: koHTML, language: .ko)
        try scanner.writeHTMLReport(result, to: enHTML, language: .en)
        try scanner.writeMarkdownReport(result, to: koMarkdown, language: .ko)
        try scanner.writeMarkdownReport(result, to: enMarkdown, language: .en)
        try scanner.writePDFReport(result, to: koPDF, language: .ko)
        try scanner.writePDFReport(result, to: enPDF, language: .en)

        return GeneratedReportFiles(
            koHTMLURL: koHTML,
            enHTMLURL: enHTML,
            koMarkdownURL: koMarkdown,
            enMarkdownURL: enMarkdown,
            koPDFURL: koPDF,
            enPDFURL: enPDF
        )
    }

    private nonisolated static func buildReportItems(
        result: NativeScanResult,
        scanner: NativeSecurityScanner,
        overallFiles: GeneratedReportFiles
    ) throws -> [ScanReportItem] {
        var items = [
            ScanReportItem(
                id: "overall",
                icon: "rectangle.stack",
                accent: .blue,
                files: overallFiles,
                findingCount: result.findings.count,
                riskScore: result.riskScore,
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
            let files = try writeReportFiles(
                result: standardResult,
                scanner: scanner,
                prefix: "KODA-\(standard.id)-security-dashboard"
            )
            items.append(
                ScanReportItem(
                    id: standard.id,
                    icon: standard.icon,
                    accent: standard.accent,
                    files: files,
                    findingCount: findings.count,
                    riskScore: standardResult.riskScore,
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
    let icon: String
    let accent: StandardAccent
    let files: GeneratedReportFiles
    let findingCount: Int
    let riskScore: Int
    let standard: AppSecurityStandard?

    var isOverall: Bool {
        standard == nil
    }

    var reportURL: URL {
        files.koHTMLURL
    }

    func htmlURL(language: AppLanguage) -> URL {
        language == .ko ? files.koHTMLURL : files.enHTMLURL
    }

    func url(format: ReportExportFormat, language: AppLanguage) -> URL {
        switch (language, format) {
        case (.ko, .html): return files.koHTMLURL
        case (.ko, .markdown): return files.koMarkdownURL
        case (.ko, .pdf): return files.koPDFURL
        case (.en, .html): return files.enHTMLURL
        case (.en, .markdown): return files.enMarkdownURL
        case (.en, .pdf): return files.enPDFURL
        }
    }

    func title(language: AppLanguage) -> String {
        if let standard {
            return standard.title(language: language)
        }
        switch language {
        case .ko: return "전체 조회"
        case .en: return "Overall Results"
        }
    }

    func subtitle(language: AppLanguage) -> String {
        if let standard {
            return standard.scope(language: language)
        }
        switch language {
        case .ko: return "모든 로컬 점검 결과를 기준 제한 없이 확인합니다."
        case .en: return "Review all local scan results without limiting by standard."
        }
    }

    func badge(language: AppLanguage) -> String {
        if let standard {
            return standard.badge(language: language)
        }
        switch language {
        case .ko: return "전체"
        case .en: return "All"
        }
    }

    func exportFileName(format: ReportExportFormat, language: AppLanguage) -> String {
        let slug = id.replacingOccurrences(of: "[^A-Za-z0-9_-]", with: "-", options: .regularExpression)
        return "KODA-\(slug)-\(language.rawValue).\(format.fileExtension)"
    }
}

struct GeneratedReportFiles: Hashable {
    let koHTMLURL: URL
    let enHTMLURL: URL
    let koMarkdownURL: URL
    let enMarkdownURL: URL
    let koPDFURL: URL
    let enPDFURL: URL
}

private struct ScanResult {
    let exitCode: Int32
    let reportURL: URL?
    let messageKO: String
    let messageEN: String
    let detailKO: String
    let detailEN: String
    let reportItems: [ScanReportItem]
}
