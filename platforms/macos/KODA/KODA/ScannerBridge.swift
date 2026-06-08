import AppKit
import CryptoKit
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
    @Published var scoreHistory: [SecurityScoreSnapshot] = []
    @Published var projectProfiles: [ProjectProfile] = []
    @Published var maskReportExports = true

    init() {
        scoreHistory = SecurityScoreStore.load()
        projectProfiles = ProjectProfileStore.load()
    }

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
                if let snapshot = result.scoreSnapshot {
                    recordScoreSnapshot(snapshot)
                }
                setStatus(ko: "점검 완료: \(output.path)", en: "Scan complete: \(output.path)")
                statusColor = .green
            } else {
                setStatus(ko: result.messageKO, en: result.messageEN)
                statusColor = .red
            }
        }
    }

    func runHostScan(language: AppLanguage) {
        isRunning = true
        reportURL = nil
        reportItems = []
        setDetail(ko: "", en: "")
        setStatus(ko: "이 컴퓨터의 보안 상태를 점검하고 있습니다.", en: "Checking this computer's security posture.")
        statusColor = .secondary

        Task {
            let result = await Task.detached(priority: .userInitiated) {
                Self.runHostScanCommand()
            }.value
            isRunning = false
            setDetail(ko: result.detailKO, en: result.detailEN)
            if result.exitCode == 0, let output = result.reportURL {
                reportURL = output
                reportItems = result.reportItems
                if let snapshot = result.scoreSnapshot {
                    recordScoreSnapshot(snapshot)
                }
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
        let masked = maskReportExports
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
            if masked {
                try Self.writeSanitizedReport(report, as: format, language: language, to: destination)
            } else {
                try FileManager.default.copyItem(at: source, to: destination)
            }
            setStatus(
                ko: "\(masked ? "마스킹된 " : "")\(format.fileExtension.uppercased()) 저장 완료: \(destination.path)",
                en: "\(masked ? "Masked " : "")\(format.fileExtension.uppercased()) saved: \(destination.path)"
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

    func exportSecurityToolkit(language: AppLanguage) {
        let projectName = selectedTargets.first?.lastPathComponent ?? "KODA Project"
        let panel = NSSavePanel()
        panel.allowedContentTypes = [UTType(filenameExtension: "md") ?? .plainText]
        panel.canCreateDirectories = true
        panel.nameFieldStringValue = "KODA-security-prevention-kit.md"
        panel.message = language == .ko
            ? "보안 정책, Dependabot, CI 보안 점검, ZAP, Dependency-Track 템플릿을 저장할 위치를 선택하세요."
            : "Choose where to save SECURITY.md, Dependabot, CI security, ZAP, and Dependency-Track templates."

        guard panel.runModal() == .OK, let destination = panel.url else {
            return
        }

        do {
            try SecurityPreventionToolkit.markdown(projectName: projectName, language: language).write(to: destination, atomically: true, encoding: .utf8)
            setStatus(
                ko: "보안 예방 키트 저장 완료: \(destination.path)",
                en: "Security prevention kit saved: \(destination.path)"
            )
            statusColor = .green
        } catch {
            setStatus(
                ko: "보안 예방 키트 저장 실패: \(error.localizedDescription)",
                en: "Security prevention kit save failed: \(error.localizedDescription)"
            )
            statusColor = .red
        }
    }

    func buildSecurityFixPlans(language: AppLanguage) -> [SecurityFixPlan] {
        let targets = selectedTargets.filter { Self.isDirectoryURL($0) }
        guard !targets.isEmpty else {
            setStatus(
                ko: "자동 수정 마법사를 열려면 먼저 프로젝트 폴더를 선택하세요.",
                en: "Choose project folders before opening the auto-fix wizard."
            )
            statusColor = .red
            return []
        }

        let plans = targets.flatMap { SecurityAutoFixer.plans(for: $0) }
        if plans.isEmpty {
            setStatus(
                ko: "적용할 자동 수정 항목이 없습니다.",
                en: "No auto-fix items are available."
            )
            statusColor = .secondary
        }
        return plans
    }

    func applySecurityFixPlans(_ plans: [SecurityFixPlan], language: AppLanguage) {
        guard !plans.isEmpty else {
            return
        }

        isRunning = true
        setDetail(ko: "", en: "")
        setStatus(ko: "선택한 자동 수정 항목을 적용하고 있습니다.", en: "Applying selected auto-fix items.")
        statusColor = .secondary

        Task {
            let result = await Task.detached(priority: .userInitiated) {
                SecurityAutoFixer.apply(plans: plans)
            }.value

            isRunning = false
            let failureSuffixKO = result.failures.isEmpty ? "" : " | 실패 \(result.failures.count)건"
            let failureSuffixEN = result.failures.isEmpty ? "" : " | failed \(result.failures.count)"
            setStatus(
                ko: "자동 수정 완료: 적용 \(result.writtenCount)개\(failureSuffixKO)",
                en: "Auto-fix complete: applied \(result.writtenCount)\(failureSuffixEN)"
            )
            setDetail(ko: result.detailKO, en: result.detailEN)
            statusColor = result.failures.isEmpty ? .green : (result.writtenCount > 0 ? .orange : .red)
        }
    }

    func exportSBOM(language: AppLanguage) {
        let targets = selectedTargets
        guard !targets.isEmpty else {
            setStatus(ko: "SBOM을 생성할 폴더나 파일을 선택하세요.", en: "Choose folders or files before generating an SBOM.")
            statusColor = .red
            return
        }

        let panel = NSSavePanel()
        panel.allowedContentTypes = [UTType.json]
        panel.canCreateDirectories = true
        panel.nameFieldStringValue = "koda-sbom.cdx.json"
        panel.message = language == .ko
            ? "CycloneDX SBOM을 저장할 위치를 선택하세요."
            : "Choose where to save the CycloneDX SBOM."

        guard panel.runModal() == .OK, let destination = panel.url else {
            return
        }

        isRunning = true
        setStatus(ko: "SBOM을 생성하고 있습니다.", en: "Generating SBOM.")
        statusColor = .secondary

        Task {
            let result = await Task.detached(priority: .userInitiated) {
                Self.writeSBOMCommand(targets: targets, destination: destination)
            }.value

            isRunning = false
            if result.exitCode == 0 {
                setStatus(ko: result.messageKO, en: result.messageEN)
                setDetail(ko: result.detailKO, en: result.detailEN)
                statusColor = .green
            } else {
                setStatus(ko: result.messageKO, en: result.messageEN)
                setDetail(ko: result.detailKO, en: result.detailEN)
                statusColor = .red
            }
        }
    }

    func exportVEX(language: AppLanguage) {
        let targets = selectedTargets
        guard !targets.isEmpty else {
            setStatus(ko: "VEX를 생성할 폴더나 파일을 선택하세요.", en: "Choose folders or files before generating VEX.")
            statusColor = .red
            return
        }

        let panel = NSSavePanel()
        panel.allowedContentTypes = [UTType.json]
        panel.canCreateDirectories = true
        panel.nameFieldStringValue = "koda-vex.cdx.json"
        panel.message = language == .ko
            ? "CycloneDX VEX 문서를 저장할 위치를 선택하세요."
            : "Choose where to save the CycloneDX VEX document."

        guard panel.runModal() == .OK, let destination = panel.url else {
            return
        }

        isRunning = true
        setStatus(ko: "OSV/CVE와 KEV/EPSS를 조회해 VEX 초안을 생성하고 있습니다.", en: "Querying OSV/CVE and KEV/EPSS to generate a VEX draft.")
        statusColor = .secondary

        Task {
            let result = await Self.writeVEXCommand(targets: targets, destination: destination)

            isRunning = false
            setStatus(ko: result.messageKO, en: result.messageEN)
            setDetail(ko: result.detailKO, en: result.detailEN)
            statusColor = result.exitCode == 0 ? .green : .red
        }
    }

    func exportZAPBaselinePlan(language: AppLanguage) {
        let alert = NSAlert()
        alert.messageText = language == .ko ? "ZAP DAST 계획 생성" : "Create ZAP DAST Plan"
        alert.informativeText = language == .ko
            ? "권한이 있는 staging 또는 로컬 URL만 입력하세요. KODA는 실행 명령과 점검 계획 파일을 생성합니다."
            : "Enter only an authorized staging or local URL. KODA will generate a plan and command file."
        alert.addButton(withTitle: language == .ko ? "다음" : "Next")
        alert.addButton(withTitle: language.cancelTitle)
        let input = NSTextField(frame: NSRect(x: 0, y: 0, width: 420, height: 24))
        input.placeholderString = "https://staging.example.com"
        alert.accessoryView = input

        guard alert.runModal() == .alertFirstButtonReturn else {
            return
        }
        let targetURL = input.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        guard Self.isHTTPURL(targetURL) else {
            setStatus(ko: "ZAP 계획 생성 실패: http(s) URL만 입력할 수 있습니다.", en: "ZAP plan failed: enter an http(s) URL.")
            statusColor = .red
            return
        }

        let panel = NSSavePanel()
        panel.allowedContentTypes = [UTType(filenameExtension: "md") ?? .plainText]
        panel.canCreateDirectories = true
        panel.nameFieldStringValue = "KODA-zap-baseline-plan.md"
        panel.message = language == .ko
            ? "ZAP baseline 점검 계획을 저장할 위치를 선택하세요."
            : "Choose where to save the ZAP baseline plan."

        guard panel.runModal() == .OK, let destination = panel.url else {
            return
        }

        do {
            try Self.zapBaselinePlan(targetURL: targetURL, language: language).write(to: destination, atomically: true, encoding: .utf8)
            setStatus(ko: "ZAP DAST 계획 저장 완료: \(destination.path)", en: "ZAP DAST plan saved: \(destination.path)")
            setDetail(ko: "실행 전 대상 소유권과 테스트 권한을 다시 확인하세요.", en: "Confirm target ownership and authorization before running it.")
            statusColor = .green
        } catch {
            setStatus(ko: "ZAP 계획 저장 실패: \(error.localizedDescription)", en: "ZAP plan save failed: \(error.localizedDescription)")
            statusColor = .red
        }
    }

    func runZAPBaseline(language: AppLanguage) {
        let alert = NSAlert()
        alert.messageText = language == .ko ? "ZAP DAST 실행" : "Run ZAP DAST"
        alert.informativeText = language == .ko
            ? "권한이 있는 staging 또는 로컬 URL만 입력하세요. Docker가 설치되어 있어야 하며 대상 서비스로 실제 HTTP 요청을 보냅니다."
            : "Enter only an authorized staging or local URL. Docker must be installed and the scan sends real HTTP requests."
        alert.addButton(withTitle: language == .ko ? "실행" : "Run")
        alert.addButton(withTitle: language.cancelTitle)
        let input = NSTextField(frame: NSRect(x: 0, y: 0, width: 420, height: 24))
        input.placeholderString = "https://staging.example.com"
        alert.accessoryView = input

        guard alert.runModal() == .alertFirstButtonReturn else {
            return
        }
        let targetURL = input.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
        guard Self.isHTTPURL(targetURL) else {
            setStatus(ko: "ZAP 실행 실패: http(s) URL만 입력할 수 있습니다.", en: "ZAP run failed: enter an http(s) URL.")
            statusColor = .red
            return
        }

        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.canCreateDirectories = true
        panel.allowsMultipleSelection = false
        panel.prompt = language == .ko ? "저장 위치 선택" : "Choose Output"
        panel.message = language == .ko
            ? "ZAP 리포트를 저장할 폴더를 선택하세요."
            : "Choose a folder where ZAP reports should be saved."

        guard panel.runModal() == .OK, let outputRoot = panel.url else {
            return
        }
        let outputDir = outputRoot.appendingPathComponent("KODA-zap-baseline-\(Self.timestampToken())", isDirectory: true)

        isRunning = true
        setStatus(ko: "ZAP DAST를 실행하고 있습니다.", en: "Running ZAP DAST.")
        setDetail(ko: "대상: \(targetURL)", en: "Target: \(targetURL)")
        statusColor = .secondary

        Task {
            let result = await Task.detached(priority: .userInitiated) {
                Self.runZAPBaselineCommand(targetURL: targetURL, outputDir: outputDir)
            }.value
            isRunning = false
            setStatus(ko: result.messageKO, en: result.messageEN)
            setDetail(ko: result.detailKO, en: result.detailEN)
            statusColor = result.exitCode == 0 ? .green : (result.writtenCount > 0 ? .orange : .red)
        }
    }

    func exportEvidenceChecklist(language: AppLanguage) {
        let panel = NSSavePanel()
        panel.allowedContentTypes = [UTType(filenameExtension: "md") ?? .plainText]
        panel.canCreateDirectories = true
        panel.nameFieldStringValue = "KODA-manual-evidence-checklist.md"
        panel.message = language == .ko
            ? "수동 증적 체크리스트를 저장할 위치를 선택하세요."
            : "Choose where to save the manual evidence checklist."

        guard panel.runModal() == .OK, let destination = panel.url else {
            return
        }

        do {
            let projectName = selectedTargets.first?.lastPathComponent ?? "KODA Project"
            try Self.manualEvidenceChecklist(projectName: projectName, language: language).write(to: destination, atomically: true, encoding: .utf8)
            setStatus(ko: "수동 증적 체크리스트 저장 완료: \(destination.path)", en: "Manual evidence checklist saved: \(destination.path)")
            setDetail(ko: "증적 확인 필요 기준의 운영 증적을 추적할 수 있습니다.", en: "Use it to track evidence for evidence review standards.")
            statusColor = .green
        } catch {
            setStatus(ko: "체크리스트 저장 실패: \(error.localizedDescription)", en: "Checklist save failed: \(error.localizedDescription)")
            statusColor = .red
        }
    }

    func exportScoreDiff(language: AppLanguage) {
        guard scoreHistory.count >= 2 else {
            setStatus(ko: "비교할 점검 기록이 2개 이상 필요합니다.", en: "At least two score history entries are required for comparison.")
            statusColor = .red
            return
        }

        let panel = NSSavePanel()
        panel.allowedContentTypes = [UTType(filenameExtension: "md") ?? .plainText]
        panel.canCreateDirectories = true
        panel.nameFieldStringValue = "KODA-score-diff.md"
        panel.message = language == .ko
            ? "점검 변경 리포트를 저장할 위치를 선택하세요."
            : "Choose where to save the score diff report."

        guard panel.runModal() == .OK, let destination = panel.url else {
            return
        }

        do {
            try Self.scoreDiffMarkdown(current: scoreHistory[0], baseline: scoreHistory[1], language: language).write(to: destination, atomically: true, encoding: .utf8)
            setStatus(ko: "점검 변경 리포트 저장 완료: \(destination.path)", en: "Score diff report saved: \(destination.path)")
            statusColor = .green
        } catch {
            setStatus(ko: "변경 리포트 저장 실패: \(error.localizedDescription)", en: "Diff report save failed: \(error.localizedDescription)")
            statusColor = .red
        }
    }

    func exportReleaseSecurityPackage(language: AppLanguage) {
        let targets = selectedTargets
        guard !targets.isEmpty else {
            setStatus(ko: "릴리스 보안 패키지를 만들 폴더나 파일을 선택하세요.", en: "Choose folders or files before creating a release security package.")
            statusColor = .red
            return
        }

        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.canCreateDirectories = true
        panel.allowsMultipleSelection = false
        panel.prompt = language == .ko ? "저장 위치 선택" : "Choose Output"
        panel.message = language == .ko
            ? "릴리스 보안 패키지를 생성할 상위 폴더를 선택하세요."
            : "Choose a parent folder for the release security package."

        guard panel.runModal() == .OK, let outputRoot = panel.url else {
            return
        }
        let outputDir = outputRoot.appendingPathComponent("KODA-release-security-package-\(Self.timestampToken())", isDirectory: true)

        isRunning = true
        setStatus(ko: "릴리스 보안 패키지를 생성하고 있습니다.", en: "Creating release security package.")
        setDetail(ko: "", en: "")
        statusColor = .secondary

        Task {
            let result = await Self.writeReleaseSecurityPackage(targets: targets, outputDir: outputDir, language: language)
            isRunning = false
            setStatus(ko: result.messageKO, en: result.messageEN)
            setDetail(ko: result.detailKO, en: result.detailEN)
            statusColor = result.exitCode == 0 ? .green : .red
        }
    }

    func runOSVLookup(language: AppLanguage) {
        let targets = selectedTargets
        guard !targets.isEmpty else {
            setStatus(ko: "OSV 조회를 실행할 폴더나 파일을 선택하세요.", en: "Choose folders or files before running OSV lookup.")
            statusColor = .red
            return
        }

        isRunning = true
        reportURL = nil
        reportItems = []
        setDetail(ko: "OSV.dev에 정확한 버전의 의존성 정보를 조회합니다.", en: "Querying exact dependency versions through OSV.dev.")
        setStatus(ko: "OSV/CVE와 KEV/EPSS 조회를 실행하고 있습니다.", en: "Running OSV/CVE and KEV/EPSS lookup.")
        statusColor = .secondary

        Task {
            let result = await Self.runOSVLookupCommand(targets: targets)

            isRunning = false
            setDetail(ko: result.detailKO, en: result.detailEN)
            if result.exitCode == 0, let output = result.reportURL {
                reportURL = output
                reportItems = result.reportItems
                if let snapshot = result.scoreSnapshot {
                    recordScoreSnapshot(snapshot)
                }
                setStatus(ko: result.messageKO, en: result.messageEN)
                statusColor = .green
            } else {
                setStatus(ko: result.messageKO, en: result.messageEN)
                statusColor = .red
            }
        }
    }

    func createIgnoreTemplate(language: AppLanguage) {
        let targets = selectedTargets.filter { Self.isDirectoryURL($0) }
        guard !targets.isEmpty else {
            setStatus(ko: "예외 파일을 생성할 프로젝트 폴더를 선택하세요.", en: "Choose project folders before creating an ignore file.")
            statusColor = .red
            return
        }

        isRunning = true
        setDetail(ko: "", en: "")
        setStatus(ko: "예외 파일을 생성하고 있습니다.", en: "Creating ignore files.")
        statusColor = .secondary

        Task {
            let result = await Task.detached(priority: .userInitiated) {
                KODAIgnoreTemplateWriter.write(to: targets)
            }.value

            isRunning = false
            setStatus(ko: result.messageKO, en: result.messageEN)
            setDetail(ko: result.detailKO, en: result.detailEN)
            statusColor = result.failures.isEmpty ? .green : (result.writtenCount + result.skippedCount > 0 ? .orange : .red)
        }
    }

    func clearScoreHistory(language: AppLanguage) {
        scoreHistory = []
        SecurityScoreStore.save([])
        setStatus(ko: "보안 점수 기록을 지웠습니다.", en: "Security score history cleared.")
        statusColor = .secondary
    }

    func saveProjectProfile(language: AppLanguage) {
        guard !selectedTargets.isEmpty else {
            setStatus(ko: "저장할 점검 대상이 없습니다.", en: "No scan targets to save.")
            statusColor = .red
            return
        }

        let targets = selectedTargets.map { Self.projectProfileTarget(from: $0) }
        let profile = ProjectProfile(
            id: UUID(),
            name: Self.projectProfileName(for: selectedTargets, language: language),
            createdAt: Date(),
            targets: targets
        )
        var profiles = projectProfiles.filter { $0.targetPaths != profile.targetPaths }
        profiles.insert(profile, at: 0)
        profiles = Array(profiles.prefix(30))
        projectProfiles = profiles
        ProjectProfileStore.save(profiles)
        setStatus(ko: "프로젝트 프로파일 저장 완료: \(profile.name)", en: "Project profile saved: \(profile.name)")
        statusColor = .green
    }

    func loadProjectProfile(_ profile: ProjectProfile, language: AppLanguage) {
        let resolvedTargets = profile.targets.compactMap(Self.resolvedURL)
        let existingTargets = resolvedTargets.filter { FileManager.default.fileExists(atPath: $0.path) }

        guard !existingTargets.isEmpty else {
            setStatus(ko: "프로파일의 대상 경로를 찾을 수 없습니다.", en: "No target paths in this profile could be found.")
            statusColor = .red
            return
        }

        selectedTargets = Self.deduplicatedURLs(existingTargets)
        reportURL = nil
        reportItems = []
        let missingCount = max(0, profile.targets.count - selectedTargets.count)
        let detailKO = missingCount > 0 ? "존재하지 않는 경로 \(missingCount)개는 제외했습니다." : ""
        let detailEN = missingCount > 0 ? "Skipped \(missingCount) missing path(s)." : ""
        setDetail(ko: detailKO, en: detailEN)
        setStatus(ko: "\(profile.name) 프로파일 불러오기 완료", en: "Loaded profile: \(profile.name)")
        statusColor = .green
    }

    func deleteProjectProfile(_ profile: ProjectProfile, language: AppLanguage) {
        projectProfiles.removeAll { $0.id == profile.id }
        ProjectProfileStore.save(projectProfiles)
        setStatus(ko: "프로젝트 프로파일 삭제 완료", en: "Project profile deleted.")
        statusColor = .secondary
    }

    func installPreCommitHook(language: AppLanguage) {
        let targets = selectedTargets.filter { Self.isDirectoryURL($0) }
        guard !targets.isEmpty else {
            setStatus(ko: "pre-commit 훅을 설치할 Git 프로젝트 폴더를 선택하세요.", en: "Choose Git project folders before installing pre-commit hooks.")
            statusColor = .red
            return
        }

        isRunning = true
        setDetail(ko: "", en: "")
        setStatus(ko: "KODA pre-commit 훅을 설치하고 있습니다.", en: "Installing KODA pre-commit hooks.")
        statusColor = .secondary

        Task {
            let result = await Task.detached(priority: .userInitiated) {
                Self.installPreCommitHookCommand(targets: targets)
            }.value

            isRunning = false
            setStatus(ko: result.messageKO, en: result.messageEN)
            setDetail(ko: result.detailKO, en: result.detailEN)
            statusColor = result.failures.isEmpty ? .green : (result.writtenCount > 0 || result.skippedCount > 0 ? .orange : .red)
        }
    }

    func exportRepositorySecurityChecklist(language: AppLanguage) {
        exportGeneratedMarkdown(
            defaultFileName: "KODA-github-repository-security.md",
            panelMessageKO: "GitHub 저장소 보안 설정 체크리스트를 저장할 위치를 선택하세요.",
            panelMessageEN: "Choose where to save the GitHub repository security checklist.",
            successKO: "저장소 보안 체크리스트 저장 완료",
            successEN: "Repository security checklist saved",
            content: Self.repositorySecurityChecklist(projectName: selectedTargets.first?.lastPathComponent ?? "KODA Project", language: language),
            language: language
        )
    }

    func exportReleaseSigningPlan(language: AppLanguage) {
        exportGeneratedMarkdown(
            defaultFileName: "KODA-release-signing-plan.md",
            panelMessageKO: "SLSA/Sigstore 릴리스 서명 계획을 저장할 위치를 선택하세요.",
            panelMessageEN: "Choose where to save the SLSA/Sigstore release signing plan.",
            successKO: "릴리스 서명 계획 저장 완료",
            successEN: "Release signing plan saved",
            content: Self.releaseSigningPlan(projectName: selectedTargets.first?.lastPathComponent ?? "KODA Project", language: language),
            language: language
        )
    }

    func exportSSDFWorkflowPlan(language: AppLanguage) {
        exportGeneratedMarkdown(
            defaultFileName: "KODA-nist-ssdf-workflow.md",
            panelMessageKO: "NIST SSDF 워크플로 계획을 저장할 위치를 선택하세요.",
            panelMessageEN: "Choose where to save the NIST SSDF workflow plan.",
            successKO: "NIST SSDF 계획 저장 완료",
            successEN: "NIST SSDF plan saved",
            content: Self.ssdfWorkflowPlan(projectName: selectedTargets.first?.lastPathComponent ?? "KODA Project", language: language),
            language: language
        )
    }

    func exportSecureByDesignPlan(language: AppLanguage) {
        exportGeneratedMarkdown(
            defaultFileName: "KODA-secure-by-design-plan.md",
            panelMessageKO: "Secure by Design 예방 계획을 저장할 위치를 선택하세요.",
            panelMessageEN: "Choose where to save the Secure by Design prevention plan.",
            successKO: "Secure by Design 계획 저장 완료",
            successEN: "Secure by Design plan saved",
            content: Self.secureByDesignPlan(projectName: selectedTargets.first?.lastPathComponent ?? "KODA Project", language: language),
            language: language
        )
    }

    func exportSecretResponseChecklist(language: AppLanguage) {
        exportGeneratedMarkdown(
            defaultFileName: "KODA-secret-rotation-runbook.md",
            panelMessageKO: "비밀값 회전 절차를 저장할 위치를 선택하세요.",
            panelMessageEN: "Choose where to save the secret rotation runbook.",
            successKO: "비밀값 회전 절차 저장 완료",
            successEN: "Secret rotation runbook saved",
            content: Self.secretRotationRunbook(projectName: selectedTargets.first?.lastPathComponent ?? "KODA Project", language: language),
            language: language
        )
    }

    func exportThreatModelTemplate(language: AppLanguage) {
        exportGeneratedMarkdown(
            defaultFileName: "KODA-threat-model.md",
            panelMessageKO: "위협 모델 템플릿을 저장할 위치를 선택하세요.",
            panelMessageEN: "Choose where to save the threat model template.",
            successKO: "위협 모델 템플릿 저장 완료",
            successEN: "Threat model template saved",
            content: Self.threatModelTemplate(projectName: selectedTargets.first?.lastPathComponent ?? "KODA Project", language: language),
            language: language
        )
    }

    func exportThreatModelTemplate(markdown: String, language: AppLanguage) {
        exportGeneratedMarkdown(
            defaultFileName: "KODA-threat-model.md",
            panelMessageKO: "위협 모델 템플릿을 저장할 위치를 선택하세요.",
            panelMessageEN: "Choose where to save the threat model template.",
            successKO: "위협 모델 템플릿 저장 완료",
            successEN: "Threat model template saved",
            content: markdown,
            language: language
        )
    }

    func exportAILLMSecurityPlan(language: AppLanguage) {
        exportGeneratedMarkdown(
            defaultFileName: "KODA-ai-llm-security-plan.md",
            panelMessageKO: "AI/LLM 보안 계획을 저장할 위치를 선택하세요.",
            panelMessageEN: "Choose where to save the AI/LLM security plan.",
            successKO: "AI/LLM 보안 계획 저장 완료",
            successEN: "AI/LLM security plan saved",
            content: Self.aiLLMSecurityPlan(projectName: selectedTargets.first?.lastPathComponent ?? "KODA Project", language: language),
            language: language
        )
    }

    func exportMobileSecurityPlan(language: AppLanguage) {
        exportGeneratedMarkdown(
            defaultFileName: "KODA-mobile-security-plan.md",
            panelMessageKO: "모바일 보안 계획을 저장할 위치를 선택하세요.",
            panelMessageEN: "Choose where to save the mobile security plan.",
            successKO: "모바일 보안 계획 저장 완료",
            successEN: "Mobile security plan saved",
            content: Self.mobileSecurityPlan(projectName: selectedTargets.first?.lastPathComponent ?? "KODA Project", language: language),
            language: language
        )
    }

    func exportNISTCSFProfile(language: AppLanguage) {
        exportGeneratedMarkdown(
            defaultFileName: "KODA-nist-csf-2-profile.md",
            panelMessageKO: "NIST CSF 2.0 프로파일을 저장할 위치를 선택하세요.",
            panelMessageEN: "Choose where to save the NIST CSF 2.0 profile.",
            successKO: "NIST CSF 2.0 프로파일 저장 완료",
            successEN: "NIST CSF 2.0 profile saved",
            content: Self.nistCSFProfile(projectName: selectedTargets.first?.lastPathComponent ?? "KODA Project", language: language),
            language: language
        )
    }

    func exportCISAAttestationChecklist(language: AppLanguage) {
        exportGeneratedMarkdown(
            defaultFileName: "KODA-cisa-secure-software-attestation.md",
            panelMessageKO: "CISA 보안 소프트웨어 개발 확인서 체크리스트를 저장할 위치를 선택하세요.",
            panelMessageEN: "Choose where to save the CISA secure software attestation checklist.",
            successKO: "CISA 확인서 체크리스트 저장 완료",
            successEN: "CISA attestation checklist saved",
            content: Self.cisaAttestationChecklist(projectName: selectedTargets.first?.lastPathComponent ?? "KODA Project", language: language),
            language: language
        )
    }

    func exportAPISecurityPlan(language: AppLanguage) {
        exportGeneratedMarkdown(
            defaultFileName: "KODA-api-security-plan.md",
            panelMessageKO: "API 보안 계획을 저장할 위치를 선택하세요.",
            panelMessageEN: "Choose where to save the API security plan.",
            successKO: "API 보안 계획 저장 완료",
            successEN: "API security plan saved",
            content: SecurityPreventionToolkit.apiSecurityPlan(projectName: selectedTargets.first?.lastPathComponent ?? "KODA Project"),
            language: language
        )
    }

    func exportSCVSPlan(language: AppLanguage) {
        exportGeneratedMarkdown(
            defaultFileName: "KODA-owasp-scvs-plan.md",
            panelMessageKO: "OWASP SCVS 계획을 저장할 위치를 선택하세요.",
            panelMessageEN: "Choose where to save the OWASP SCVS plan.",
            successKO: "OWASP SCVS 계획 저장 완료",
            successEN: "OWASP SCVS plan saved",
            content: SecurityPreventionToolkit.scvsPlan(projectName: selectedTargets.first?.lastPathComponent ?? "KODA Project"),
            language: language
        )
    }

    func exportPrivacyDataMap(language: AppLanguage) {
        exportGeneratedMarkdown(
            defaultFileName: "KODA-privacy-data-map.md",
            panelMessageKO: "개인정보 데이터 맵을 저장할 위치를 선택하세요.",
            panelMessageEN: "Choose where to save the privacy data map.",
            successKO: "개인정보 데이터 맵 저장 완료",
            successEN: "Privacy data map saved",
            content: SecurityPreventionToolkit.privacyDataMap(projectName: selectedTargets.first?.lastPathComponent ?? "KODA Project"),
            language: language
        )
    }

    func exportSecurityRoadmap(language: AppLanguage) {
        exportGeneratedMarkdown(
            defaultFileName: "KODA-security-roadmap.md",
            panelMessageKO: "보안 로드맵을 저장할 위치를 선택하세요.",
            panelMessageEN: "Choose where to save the security roadmap.",
            successKO: "보안 로드맵 저장 완료",
            successEN: "Security roadmap saved",
            content: SecurityPreventionToolkit.securityRoadmap(projectName: selectedTargets.first?.lastPathComponent ?? "KODA Project"),
            language: language
        )
    }

    func exportEvidenceRegister(language: AppLanguage) {
        exportGeneratedMarkdown(
            defaultFileName: "KODA-evidence-register.md",
            panelMessageKO: "보안 증적 보관대장을 저장할 위치를 선택하세요.",
            panelMessageEN: "Choose where to save the security evidence register.",
            successKO: "보안 증적 보관대장 저장 완료",
            successEN: "Security evidence register saved",
            content: SecurityPreventionToolkit.evidenceRegister(projectName: selectedTargets.first?.lastPathComponent ?? "KODA Project"),
            language: language
        )
    }

    func exportSecurityHeadersBaseline(language: AppLanguage) {
        exportGeneratedMarkdown(
            defaultFileName: "KODA-security-headers.md",
            panelMessageKO: "보안 헤더 기준을 저장할 위치를 선택하세요.",
            panelMessageEN: "Choose where to save the security headers baseline.",
            successKO: "보안 헤더 기준 저장 완료",
            successEN: "Security headers baseline saved",
            content: SecurityPreventionToolkit.securityHeadersBaseline(projectName: selectedTargets.first?.lastPathComponent ?? "KODA Project"),
            language: language
        )
    }

    func exportContainerHardeningBaseline(language: AppLanguage) {
        exportGeneratedMarkdown(
            defaultFileName: "KODA-container-hardening.md",
            panelMessageKO: "컨테이너 하드닝 기준을 저장할 위치를 선택하세요.",
            panelMessageEN: "Choose where to save the container hardening baseline.",
            successKO: "컨테이너 하드닝 기준 저장 완료",
            successEN: "Container hardening baseline saved",
            content: SecurityPreventionToolkit.containerHardeningBaseline(projectName: selectedTargets.first?.lastPathComponent ?? "KODA Project"),
            language: language
        )
    }

    func exportCloudIACSecurityPlan(language: AppLanguage) {
        exportGeneratedMarkdown(
            defaultFileName: "KODA-cloud-iac-security.md",
            panelMessageKO: "Cloud/IaC 보안 계획을 저장할 위치를 선택하세요.",
            panelMessageEN: "Choose where to save the Cloud/IaC security plan.",
            successKO: "Cloud/IaC 보안 계획 저장 완료",
            successEN: "Cloud/IaC security plan saved",
            content: SecurityPreventionToolkit.cloudIACSecurityPlan(projectName: selectedTargets.first?.lastPathComponent ?? "KODA Project"),
            language: language
        )
    }

    func applySecurityToolkit(language: AppLanguage) {
        var targets = selectedTargets.filter { Self.isDirectoryURL($0) }

        if targets.isEmpty {
            let panel = NSOpenPanel()
            panel.allowsMultipleSelection = true
            panel.canChooseDirectories = true
            panel.canChooseFiles = false
            panel.prompt = language == .ko ? "적용" : "Apply"
            panel.message = language == .ko
                ? "보안 예방 설정을 생성할 프로젝트 폴더를 선택하세요. 기존 파일은 덮어쓰지 않습니다."
                : "Choose project folders where KODA should create prevention guardrails. Existing files will not be overwritten."

            guard panel.runModal() == .OK else {
                return
            }
            targets = panel.urls
        }

        guard !targets.isEmpty else {
            return
        }

        isRunning = true
        setDetail(ko: "", en: "")
        setStatus(
            ko: "보안 예방 설정을 적용하고 있습니다.",
            en: "Applying security prevention guardrails."
        )
        statusColor = .secondary

        Task {
            let result = await Task.detached(priority: .userInitiated) {
                Self.applySecurityToolkitCommand(targets: targets)
            }.value

            isRunning = false
            let failureSuffixKO = result.failures.isEmpty ? "" : " | 실패 \(result.failures.count)건"
            let failureSuffixEN = result.failures.isEmpty ? "" : " | failed \(result.failures.count)"
            setStatus(
                ko: "예방 설정 적용 완료: 생성 \(result.writtenCount)개, 기존 유지 \(result.skippedCount)개\(failureSuffixKO)",
                en: "Prevention guardrails applied: written \(result.writtenCount), kept existing \(result.skippedCount)\(failureSuffixEN)"
            )
            setDetail(
                ko: result.detail(language: .ko),
                en: result.detail(language: .en)
            )
            statusColor = result.failures.isEmpty ? .green : (result.writtenCount + result.skippedCount > 0 ? .orange : .red)
        }
    }

    private func exportGeneratedMarkdown(
        defaultFileName: String,
        panelMessageKO: String,
        panelMessageEN: String,
        successKO: String,
        successEN: String,
        content: String,
        language: AppLanguage
    ) {
        let panel = NSSavePanel()
        // Offer Markdown (default), HTML, and PDF so documentation guardrails can be
        // shared or printed, not just kept as raw Markdown.
        panel.allowedContentTypes = [
            UTType(filenameExtension: "md") ?? .plainText,
            .html,
            .pdf,
        ]
        panel.canCreateDirectories = true
        panel.nameFieldStringValue = defaultFileName
        panel.message = language == .ko ? panelMessageKO : panelMessageEN

        guard panel.runModal() == .OK, let destination = panel.url else {
            return
        }

        let docTitle = destination.deletingPathExtension().lastPathComponent
        do {
            switch destination.pathExtension.lowercased() {
            case "html", "htm":
                try MarkdownDocumentExporter.html(from: content, title: docTitle)
                    .write(to: destination, atomically: true, encoding: .utf8)
            case "pdf":
                try MarkdownDocumentExporter.writePDF(from: content, title: docTitle, to: destination)
            default:
                try content.write(to: destination, atomically: true, encoding: .utf8)
            }
            setStatus(ko: "\(successKO): \(destination.path)", en: "\(successEN): \(destination.path)")
            statusColor = .green
        } catch {
            setStatus(ko: "저장 실패: \(error.localizedDescription)", en: "Save failed: \(error.localizedDescription)")
            statusColor = .red
        }
    }

    private nonisolated static func isDirectoryURL(_ url: URL) -> Bool {
        if let isDirectory = try? url.resourceValues(forKeys: [.isDirectoryKey]).isDirectory {
            return isDirectory == true
        }
        return url.hasDirectoryPath
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

    private func recordScoreSnapshot(_ snapshot: SecurityScoreSnapshot) {
        var snapshots = scoreHistory
        snapshots.insert(snapshot, at: 0)
        snapshots = Array(snapshots.prefix(100))
        scoreHistory = snapshots
        SecurityScoreStore.save(snapshots)
    }

    private static func projectProfileName(for targets: [URL], language: AppLanguage) -> String {
        let firstTarget = targets.first
        let firstName = firstTarget?.lastPathComponent.isEmpty == false ? firstTarget?.lastPathComponent : firstTarget?.path
        let baseName = firstName?.isEmpty == false ? firstName! : (language == .ko ? "프로젝트" : "Project")
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd HH:mm"
        return "\(baseName) · \(formatter.string(from: Date()))"
    }

    private static func projectProfileTarget(from url: URL) -> ProjectProfileTarget {
        let bookmark = try? url.bookmarkData(
            options: [.withSecurityScope],
            includingResourceValuesForKeys: nil,
            relativeTo: nil
        )
        return ProjectProfileTarget(path: url.path, bookmarkData: bookmark)
    }

    private static func resolvedURL(for target: ProjectProfileTarget) -> URL? {
        if let bookmarkData = target.bookmarkData {
            var isStale = false
            if let url = try? URL(
                resolvingBookmarkData: bookmarkData,
                options: [.withSecurityScope, .withoutUI],
                relativeTo: nil,
                bookmarkDataIsStale: &isStale
            ) {
                return url
            }
        }
        return URL(fileURLWithPath: target.path)
    }

    private static func deduplicatedURLs(_ urls: [URL]) -> [URL] {
        var seen = Set<String>()
        return urls.filter { seen.insert($0.path).inserted }
    }

    private nonisolated static func installPreCommitHookCommand(targets: [URL]) -> OperationResult {
        var written = 0
        var skipped = 0
        var failures: [String] = []

        for target in targets {
            let accessed = target.startAccessingSecurityScopedResource()
            defer {
                if accessed { target.stopAccessingSecurityScopedResource() }
            }

            do {
                let gitDir = target.appendingPathComponent(".git", isDirectory: true)
                guard FileManager.default.fileExists(atPath: gitDir.path) else {
                    failures.append("\(target.path): Git 저장소가 아닙니다.")
                    continue
                }
                let hook = gitDir.appendingPathComponent("hooks/pre-commit")
                try FileManager.default.createDirectory(at: hook.deletingLastPathComponent(), withIntermediateDirectories: true)
                if FileManager.default.fileExists(atPath: hook.path) {
                    let existing = (try? String(contentsOf: hook, encoding: .utf8)) ?? ""
                    if existing.contains("KODA pre-commit security gate") {
                        skipped += 1
                        continue
                    }
                }
                try preCommitHook(kodaExecutable: Bundle.main.executableURL?.path).write(to: hook, atomically: true, encoding: .utf8)
                try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: hook.path)
                written += 1
            } catch {
                failures.append("\(target.path): \(error.localizedDescription)")
            }
        }

        return OperationResult(
            exitCode: failures.isEmpty ? 0 : 2,
            messageKO: "pre-commit 훅 설치 완료: 설치 \(written)개, 기존 유지 \(skipped)개",
            messageEN: "Pre-commit hook setup complete: installed \(written), kept existing \(skipped)",
            detailKO: failures.prefix(3).joined(separator: "\n"),
            detailEN: failures.prefix(3).joined(separator: "\n"),
            writtenCount: written,
            skippedCount: skipped,
            failures: failures
        )
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
                reportItems: reportItems,
                scoreSnapshot: SecurityScoreSnapshot(result: result, targets: targets)
            )
        } catch {
            return ScanResult(
                exitCode: 2,
                reportURL: nil,
                messageKO: "스캐너 실행에 실패했습니다.",
                messageEN: "Scanner failed.",
                detailKO: error.localizedDescription,
                detailEN: error.localizedDescription,
                reportItems: [],
                scoreSnapshot: nil
            )
        }
    }

    private nonisolated static func runHostScanCommand() -> ScanResult {
        let scanner = NativeSecurityScanner()
        let result = scanner.scanHost()
        do {
            let overallFiles = try writeReportFiles(result: result, scanner: scanner, prefix: "KODA-host-posture")
            let reportItems = try buildReportItems(result: result, scanner: scanner, overallFiles: overallFiles)
            let warningTextKO = result.warnings.isEmpty ? "" : "\n경고:\n" + result.warnings.joined(separator: "\n")
            let warningTextEN = result.warnings.isEmpty ? "" : "\nWarnings:\n" + result.warnings.joined(separator: "\n")
            return ScanResult(
                exitCode: 0,
                reportURL: overallFiles.koHTMLURL,
                messageKO: "호스트 점검 완료",
                messageEN: "Host scan complete",
                detailKO: "호스트 보안 항목 \(result.findings.count)건\(warningTextKO)",
                detailEN: "host posture findings \(result.findings.count)\(warningTextEN)",
                reportItems: reportItems,
                scoreSnapshot: SecurityScoreSnapshot(result: result, targets: [])
            )
        } catch {
            return ScanResult(
                exitCode: 2,
                reportURL: nil,
                messageKO: "호스트 점검에 실패했습니다.",
                messageEN: "Host scan failed.",
                detailKO: error.localizedDescription,
                detailEN: error.localizedDescription,
                reportItems: [],
                scoreSnapshot: nil
            )
        }
    }

    private nonisolated static func writeSBOMCommand(targets: [URL], destination: URL) -> OperationResult {
        let accessedTargets = targets.filter { $0.startAccessingSecurityScopedResource() }
        defer {
            accessedTargets.forEach { $0.stopAccessingSecurityScopedResource() }
        }

        do {
            let components = try NativeDependencyInventory.components(from: targets)
            let payload = try NativeDependencyInventory.cycloneDXJSON(components: components)
            if FileManager.default.fileExists(atPath: destination.path) {
                try FileManager.default.removeItem(at: destination)
            }
            try payload.write(to: destination, atomically: true, encoding: .utf8)
            return OperationResult(
                exitCode: 0,
                messageKO: "SBOM 저장 완료: \(destination.path)",
                messageEN: "SBOM saved: \(destination.path)",
                detailKO: "의존성 컴포넌트 \(components.count)개를 CycloneDX 형식으로 저장했습니다.",
                detailEN: "Saved \(components.count) dependency component(s) as CycloneDX.",
                writtenCount: 1,
                skippedCount: 0,
                failures: []
            )
        } catch {
            return OperationResult(
                exitCode: 2,
                messageKO: "SBOM 생성 실패",
                messageEN: "SBOM generation failed",
                detailKO: error.localizedDescription,
                detailEN: error.localizedDescription,
                writtenCount: 0,
                skippedCount: 0,
                failures: [error.localizedDescription]
            )
        }
    }

    private nonisolated static func writeVEXCommand(targets: [URL], destination: URL) async -> OperationResult {
        let accessedTargets = targets.filter { $0.startAccessingSecurityScopedResource() }
        defer {
            accessedTargets.forEach { $0.stopAccessingSecurityScopedResource() }
        }

        do {
            let components = try NativeDependencyInventory.queryableOSVComponents(from: targets)
            guard !components.isEmpty else {
                return OperationResult(
                    exitCode: 2,
                    messageKO: "VEX 생성 실패",
                    messageEN: "VEX generation failed",
                    detailKO: "VEX 초안은 OSV 조회 가능한 고정 버전 의존성이 있을 때 생성할 수 있습니다.",
                    detailEN: "A VEX draft requires pinned dependency versions that can be queried through OSV.",
                    writtenCount: 0,
                    skippedCount: 0,
                    failures: ["No queryable OSV components"]
                )
            }
            let findings = try await NativeOSVClient.queryFindings(components: components)
            let payload = try NativeVEXDocument.render(findings: findings)
            if FileManager.default.fileExists(atPath: destination.path) {
                try FileManager.default.removeItem(at: destination)
            }
            try payload.write(to: destination, atomically: true, encoding: .utf8)
            return OperationResult(
                exitCode: 0,
                messageKO: "VEX 저장 완료: \(destination.path)",
                messageEN: "VEX saved: \(destination.path)",
                detailKO: "OSV 취약점 \(findings.count)건을 in_triage 상태의 CycloneDX VEX 초안으로 저장했습니다.",
                detailEN: "Saved \(findings.count) OSV vulnerability finding(s) as an in-triage CycloneDX VEX draft.",
                writtenCount: 1,
                skippedCount: 0,
                failures: []
            )
        } catch {
            return OperationResult(
                exitCode: 2,
                messageKO: "VEX 생성 실패",
                messageEN: "VEX generation failed",
                detailKO: error.localizedDescription,
                detailEN: error.localizedDescription,
                writtenCount: 0,
                skippedCount: 0,
                failures: [error.localizedDescription]
            )
        }
    }

    private nonisolated static func isHTTPURL(_ value: String) -> Bool {
        guard let url = URL(string: value), let scheme = url.scheme?.lowercased(), ["http", "https"].contains(scheme) else {
            return false
        }
        return url.host != nil
    }

    private nonisolated static func timestampToken() -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyyMMdd-HHmmss"
        return formatter.string(from: Date())
    }

    private nonisolated static func runZAPBaselineCommand(targetURL: String, outputDir: URL) -> OperationResult {
        do {
            try FileManager.default.createDirectory(at: outputDir, withIntermediateDirectories: true)
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
            process.arguments = [
                "docker", "run", "--rm", "-t",
                "-v", "\(outputDir.path):/zap/wrk:rw",
                "ghcr.io/zaproxy/zaproxy:stable",
                "zap-baseline.py",
                "-t", targetURL,
                "-m", "1",
                "-r", "zap-baseline.html",
                "-w", "zap-baseline.md",
                "-J", "zap-baseline.json",
            ]
            let stdout = Pipe()
            let stderr = Pipe()
            process.standardOutput = stdout
            process.standardError = stderr
            try process.run()
            process.waitUntilExit()
            let output = String(data: stdout.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
            let errorOutput = String(data: stderr.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
            let alertCount = countZAPAlerts(in: outputDir.appendingPathComponent("zap-baseline.json"))
            let acceptedExit = [0, 1, 2].contains(Int(process.terminationStatus))
            return OperationResult(
                exitCode: acceptedExit ? 0 : process.terminationStatus,
                messageKO: acceptedExit ? "ZAP DAST 실행 완료: \(outputDir.path)" : "ZAP DAST 실행 실패",
                messageEN: acceptedExit ? "ZAP DAST complete: \(outputDir.path)" : "ZAP DAST failed",
                detailKO: "ZAP 경고 \(alertCount)건. \(errorOutput.isEmpty ? output : errorOutput)",
                detailEN: "ZAP alert(s) \(alertCount). \(errorOutput.isEmpty ? output : errorOutput)",
                writtenCount: acceptedExit ? 1 : 0,
                skippedCount: 0,
                failures: acceptedExit ? [] : [errorOutput]
            )
        } catch {
            return OperationResult(
                exitCode: 2,
                messageKO: "ZAP DAST 실행 실패",
                messageEN: "ZAP DAST failed",
                detailKO: error.localizedDescription,
                detailEN: error.localizedDescription,
                writtenCount: 0,
                skippedCount: 0,
                failures: [error.localizedDescription]
            )
        }
    }

    private nonisolated static func countZAPAlerts(in jsonURL: URL) -> Int {
        guard let data = try? Data(contentsOf: jsonURL),
              let payload = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return 0
        }
        if let alerts = payload["alerts"] as? [[String: Any]] {
            return alerts.count
        }
        if let sites = payload["site"] as? [[String: Any]] {
            return sites.reduce(0) { total, site in
                total + ((site["alerts"] as? [[String: Any]])?.count ?? 0)
            }
        }
        return 0
    }

    private nonisolated static func manualEvidenceChecklist(projectName: String, language: AppLanguage) -> String {
        let generated = ISO8601DateFormatter().string(from: Date())
        let items: [(String, String, String, String, String)] = [
            ("OWASP ASVS", "V1 Architecture", "보안 아키텍처와 신뢰 경계가 문서화되어 있나요?", "Are security architecture and trust boundaries documented?", "Architecture diagrams, data-flow diagrams, threat models"),
            ("OWASP ASVS", "V2 Authentication", "인증 정책, MFA, 계정 복구 흐름을 검토했나요?", "Have authentication, MFA, and account recovery flows been reviewed?", "Auth design notes, test evidence, policy screenshots"),
            ("OWASP WSTG", "Runtime Testing", "권한 있는 URL에 대해 동적 점검 또는 침투테스트를 수행했나요?", "Has dynamic testing or penetration testing been performed against an authorized URL?", "ZAP/Burp reports, authorization record, scope"),
            ("ISMS-P", "Policy & Operation", "개발보안 정책, 담당자, 예외 승인 절차가 운영 중인가요?", "Are secure-development policy, owners, and exception approval processes operating?", "Policy docs, R&R, approval tickets"),
            ("NIST SSDF", "Protect Software", "소스/빌드/릴리스 산출물 보호 통제가 있나요?", "Are source, build, and release artifacts protected?", "Branch protection, signing, provenance, access controls"),
            ("OWASP SAMM", "Governance", "보안 활동의 성숙도와 개선 계획을 추적하고 있나요?", "Is security maturity and improvement planning tracked?", "SAMM scorecards, roadmap, risk acceptance records"),
            ("SLSA/Sigstore", "Release Provenance", "릴리스 산출물에 서명과 출처 증명을 붙이나요?", "Are release artifacts signed and accompanied by provenance?", "cosign signatures, SLSA provenance, checksums"),
        ]
        var lines = [
            language == .ko ? "# KODA 수동 증적 체크리스트" : "# KODA Manual Evidence Checklist",
            "",
            "- Project: \(projectName)",
            "- Generated: \(generated)",
            "",
        ]
        for item in items {
            lines.append("## \(item.0) - \(item.1)")
            lines.append("")
            lines.append("- [ ] \(language == .ko ? item.2 : item.3)")
            lines.append("- Evidence: \(item.4)")
            lines.append("- Owner:")
            lines.append("- Link/File:")
            lines.append("- Review date:")
            lines.append("- Notes:")
            lines.append("")
        }
        return lines.joined(separator: "\n")
    }

    private nonisolated static func preCommitHook(kodaExecutable: String?) -> String {
        let executableAssignment = kodaExecutable.map { "KODA_EXECUTABLE=${KODA_EXECUTABLE:-\(shellQuote($0))}" } ?? "KODA_EXECUTABLE=${KODA_EXECUTABLE:-KODA}"
        return """
        #!/bin/sh
        # KODA pre-commit security gate.
        set -eu

        \(executableAssignment)
        FAIL_ON="${KODA_PRE_COMMIT_FAIL_ON:-high}"
        TARGET="${KODA_PRE_COMMIT_TARGET:-.}"
        REPORT="${TMPDIR:-/tmp}/koda-pre-commit-report.md"
        HTML_REPORT="${TMPDIR:-/tmp}/koda-pre-commit-dashboard.html"

        if [ ! -x "$KODA_EXECUTABLE" ]; then
          echo "KODA executable not found: $KODA_EXECUTABLE" >&2
          echo "Set KODA_EXECUTABLE to the KODA app executable path." >&2
          exit 2
        fi

        KODA_SCAN_TARGETS="$TARGET" \\
        KODA_SCAN_OUTPUT="$HTML_REPORT" \\
        KODA_SCAN_OUTPUT_MARKDOWN="$REPORT" \\
        KODA_SCAN_FAIL_ON="$FAIL_ON" \\
        "$KODA_EXECUTABLE" >/dev/null

        echo "KODA pre-commit scan passed. Report: $REPORT"
        """
    }

    private nonisolated static func shellQuote(_ value: String) -> String {
        "'\(value.replacingOccurrences(of: "'", with: "'\\''"))'"
    }

    private nonisolated static func repositorySecurityChecklist(projectName: String, language: AppLanguage) -> String {
        switch language {
        case .ko:
            return """
            # GitHub 저장소 보안 설정 체크리스트

            프로젝트: \(projectName)

            ## 브랜치 및 리뷰 보호

            - [ ] 기본 브랜치 보호를 켭니다.
            - [ ] 병합 전 pull request를 요구합니다.
            - [ ] 최소 1명 이상의 승인 리뷰를 요구합니다.
            - [ ] KODA/SAST 상태 점검 통과를 병합 조건으로 둡니다.
            - [ ] 보안 민감 경로는 CODEOWNERS 리뷰를 요구합니다.

            ## 비밀값 및 의존성 보호

            - [ ] secret scanning과 push protection을 켭니다.
            - [ ] Dependabot alerts와 security updates를 켭니다.
            - [ ] KODA, CodeQL, Semgrep 등 SARIF 결과를 업로드합니다.
            - [ ] GitHub Actions token 권한은 기본 읽기 전용으로 둡니다.
            """
        case .en:
            return SecurityPreventionToolkit.repositorySecurityChecklist(projectName: projectName)
        }
    }

    private nonisolated static func releaseSigningPlan(projectName: String, language: AppLanguage) -> String {
        switch language {
        case .ko:
            return """
            # SLSA / Sigstore 릴리스 서명 계획

            프로젝트: \(projectName)

            ## 목표

            릴리스 산출물을 CI에서 빌드하고, provenance를 생성하며, Sigstore/cosign 또는 조직 서명 체계로 산출물을 서명한 뒤 체크섬과 함께 게시합니다.

            ## 로컬 dry run 명령

            ```bash
            sha256sum "dist/app.tar.gz" > "dist/app.tar.gz.sha256"
            cosign sign-blob "dist/app.tar.gz" --bundle "dist/app.tar.gz.sigstore.json" --yes
            cosign verify-blob "dist/app.tar.gz" --bundle "dist/app.tar.gz.sigstore.json" --certificate-identity-regexp ".*" --certificate-oidc-issuer-regexp ".*"
            ```

            ## CI 요구사항

            - [ ] 릴리스 태그에서 CI가 산출물을 빌드합니다.
            - [ ] SLSA provenance 또는 동등한 attestation을 생성합니다.
            - [ ] 산출물 또는 컨테이너 digest에 서명합니다.
            - [ ] checksum, signature bundle, provenance를 릴리스에 첨부합니다.
            """
        case .en:
            return SecurityPreventionToolkit.releaseSigningPlan(projectName: projectName)
        }
    }

    private nonisolated static func ssdfWorkflowPlan(projectName: String, language: AppLanguage) -> String {
        switch language {
        case .ko:
            return """
            # NIST SSDF 워크플로

            프로젝트: \(projectName)

            ## Prepare The Organization

            - [ ] 보안 개발 역할과 책임자를 지정합니다.
            - [ ] SECURITY.md, CODEOWNERS, 예외 정책을 최신으로 유지합니다.
            - [ ] 비밀값, 의존성 위생, 안전한 기본값을 contributor에게 안내합니다.

            ## Protect The Software

            - [ ] 소스 접근 권한은 최소 권한으로 둡니다.
            - [ ] 커밋 전 비밀값과 고위험 항목을 차단합니다.
            - [ ] 릴리스 빌드마다 SBOM을 생성합니다.
            - [ ] 릴리스 산출물을 서명하고 provenance를 보관합니다.

            ## Produce Well-Secured Software

            - [ ] Pull request에서 KODA, SAST, 의존성 점검을 실행합니다.
            - [ ] 설정, 쿠키, CORS, 컨테이너, CI token은 안전한 기본값을 사용합니다.
            - [ ] 의존성 업데이트 자동화를 유지합니다.

            ## Respond To Vulnerabilities

            - [ ] OSV/CVE 발견 항목을 KEV/EPSS 맥락으로 우선순위화합니다.
            - [ ] 검토된 의존성 취약점은 VEX로 기록합니다.
            - [ ] 조치 후 KODA를 다시 실행하고 점수 추이를 비교합니다.
            """
        case .en:
            return SecurityPreventionToolkit.ssdfWorkflowPlan(projectName: projectName)
        }
    }

    private nonisolated static func secureByDesignPlan(projectName: String, language: AppLanguage) -> String {
        switch language {
        case .ko:
            return """
            # CISA Secure by Design 예방 계획

            프로젝트: \(projectName)

            ## 고객 보안 결과 책임

            - [ ] 비밀값 노출, 안전하지 않은 기본값, 실제 악용 취약점을 고객 영향 결함으로 취급합니다.
            - [ ] 인증, 세션, 로깅, CORS, 배포 설정에 안전한 기본값을 제공합니다.
            - [ ] 보안 연락처와 취약점 처리 절차를 공개합니다.

            ## 투명성 및 책임성

            - [ ] 보안 정책, 지원 버전, 조치 기대사항을 게시합니다.
            - [ ] 릴리스마다 SBOM과 VEX 산출물을 유지합니다.
            - [ ] 알려진 제한, 수용 위험, 예외 만료일을 기록합니다.
            - [ ] 릴리스마다 점수 추적과 위험군 변화를 확인합니다.

            ## 경영진 주도

            - [ ] 제품 보안 결과 책임자를 지정합니다.
            - [ ] 고위험 항목, 조치 시간, 차단된 비밀값, 취약 의존성 지표를 주기적으로 검토합니다.
            - [ ] 병합과 릴리스 전 보안 게이트를 요구합니다.
            """
        case .en:
            return SecurityPreventionToolkit.secureByDesignPlan(projectName: projectName)
        }
    }

    private nonisolated static func threatModelTemplate(projectName: String, language: AppLanguage) -> String {
        switch language {
        case .ko:
            return """
            # 위협 모델

            프로젝트: \(projectName)

            ## 범위

            - [ ] 제품/서비스 경계:
            - [ ] 포함되는 앱, API, worker, 관리자 도구:
            - [ ] 제외 범위:

            ## 주요 자산과 신뢰 경계

            - [ ] 고객 데이터, 비밀값, 빌드 산출물, 관리자 권한의 소유자와 저장 위치를 기록합니다.
            - [ ] 클라이언트-API, API-DB, CI-레지스트리, 운영자-프로덕션, AI/LLM 제공자 경계를 기록합니다.
            - [ ] 인증 우회, 비밀값 노출, 공급망 변조, 파일 처리, 프롬프트 인젝션 악용 시나리오를 검토합니다.
            """
        case .en:
            return SecurityPreventionToolkit.threatModelTemplate(projectName: projectName)
        }
    }

    private nonisolated static func secretRotationRunbook(projectName: String, language: AppLanguage) -> String {
        switch language {
        case .ko:
            return """
            # 비밀값 회전 절차

            프로젝트: \(projectName)

            ## 즉시 조치

            - [ ] 비밀값 소유자와 영향을 받는 서비스를 식별합니다.
            - [ ] 노출된 값을 폐기하거나 비활성화합니다.
            - [ ] 승인된 비밀 관리 도구에서 대체 값을 발급합니다.
            - [ ] 새 값을 배포하고 KODA와 provider secret scanning을 다시 실행합니다.

            ## 감사

            - [ ] provider 로그, CI 로그, 이슈 첨부, 릴리스 산출물, 채팅 복사본을 확인합니다.
            - [ ] 접근, 권한 상승, 데이터 조회 여부를 기록하고 incident ticket에 최종 판단을 남깁니다.
            """
        case .en:
            return SecurityPreventionToolkit.secretRotationRunbook(projectName: projectName)
        }
    }

    private nonisolated static func aiLLMSecurityPlan(projectName: String, language: AppLanguage) -> String {
        switch language {
        case .ko:
            return """
            # AI / LLM 보안 계획

            프로젝트: \(projectName)

            - [ ] 모델/제공자, 전달 데이터, 사용 도구, 소유자를 목록화합니다.
            - [ ] 사용자 입력과 검색 콘텐츠를 system/developer instruction과 분리합니다.
            - [ ] 프롬프트와 로그에서 credential, token, PII, 고객 비밀값을 제거합니다.
            - [ ] 도구 호출은 allowlist, 인자 검증, 부작용 확인, 감사 로그를 적용합니다.
            - [ ] 프롬프트 인젝션, 민감정보 누출, 과도한 tool 실행 테스트 케이스를 유지합니다.
            """
        case .en:
            return SecurityPreventionToolkit.aiLLMSecurityPlan(projectName: projectName)
        }
    }

    private nonisolated static func mobileSecurityPlan(projectName: String, language: AppLanguage) -> String {
        switch language {
        case .ko:
            return """
            # 모바일 보안 계획

            프로젝트: \(projectName)

            - [ ] MASVS-STORAGE: 로컬 저장소, backup, keychain/keystore, cache 파일을 검토합니다.
            - [ ] MASVS-NETWORK: ATS/network security config와 cleartext traffic 예외를 검토합니다.
            - [ ] MASVS-PLATFORM: Android exported component와 iOS 파일 공유 설정을 검토합니다.
            - [ ] MASVS-CODE: debug flag, logging, injection, 파일 처리, 의존성 위생을 확인합니다.
            - [ ] 릴리스 서명, device/runtime 테스트, 개인정보 처리 항목을 릴리스 기준에 포함합니다.
            """
        case .en:
            return SecurityPreventionToolkit.mobileSecurityPlan(projectName: projectName)
        }
    }

    private nonisolated static func nistCSFProfile(projectName: String, language: AppLanguage) -> String {
        switch language {
        case .ko:
            return """
            # NIST CSF 2.0 프로파일

            프로젝트: \(projectName)

            - [ ] Govern: 보안 위험 소유자, 정책, 예외 처리, 검토 주기를 기록합니다.
            - [ ] Identify: 저장소, 서비스, SBOM, 데이터 저장소, 중요 자산을 목록화합니다.
            - [ ] Protect: 비밀값, 인증, 세션, 컨테이너, 모바일, AI, CI 설정의 안전한 기본값을 확인합니다.
            - [ ] Detect: KODA/SAST/의존성 점검이 pull request 또는 릴리스 브랜치에서 실행됩니다.
            - [ ] Respond: 취약점 신고, OSV/CVE, 비밀값 노출, DAST 발견 항목의 담당자와 기한을 기록합니다.
            - [ ] Recover: checksum, SBOM, VEX, 점검 리포트, 서명/provenance 증적을 릴리스 패키지에 포함합니다.
            """
        case .en:
            return SecurityPreventionToolkit.nistCSFProfile(projectName: projectName)
        }
    }

    private nonisolated static func cisaAttestationChecklist(projectName: String, language: AppLanguage) -> String {
        switch language {
        case .ko:
            return """
            # CISA 보안 소프트웨어 개발 확인서 체크리스트

            프로젝트: \(projectName)

            - [ ] 개발 환경: 소스 접근 최소 권한, 브랜치 보호, 리뷰, CODEOWNERS, CI 게이트를 확인합니다.
            - [ ] 개발 실천: 위협 모델, 시큐어코딩 점검, 예외 owner/reason/until 기록을 확인합니다.
            - [ ] 제3자 구성요소: SBOM, 버전 고정, 알려진 취약점 triage, VEX 결정을 확인합니다.
            - [ ] 검증 및 대응: SAST, 의존성, 비밀값, 설정 점검과 취약점 보고/조치 프로세스를 확인합니다.
            - [ ] 확인서 제출 전 실제 조직 실천 여부와 증적 위치를 책임자가 승인합니다.
            """
        case .en:
            return SecurityPreventionToolkit.cisaAttestationChecklist(projectName: projectName)
        }
    }

    private nonisolated static func scoreDiffMarkdown(current: SecurityScoreSnapshot, baseline: SecurityScoreSnapshot, language: AppLanguage) -> String {
        let scoreDelta = current.riskScore - baseline.riskScore
        let findingDelta = current.findingCount - baseline.findingCount
        let title = language == .ko ? "KODA 점검 변경 리포트" : "KODA Scan Change Report"
        return """
        # \(title)

        - Baseline: \(baseline.formattedDate)
        - Current: \(current.formattedDate)
        - Risk score delta: \(scoreDelta)
        - Finding count delta: \(findingDelta)

        ## Severity Delta

        - critical: \((current.severityCounts["critical"] ?? 0) - (baseline.severityCounts["critical"] ?? 0))
        - high: \((current.severityCounts["high"] ?? 0) - (baseline.severityCounts["high"] ?? 0))
        - medium: \((current.severityCounts["medium"] ?? 0) - (baseline.severityCounts["medium"] ?? 0))
        - low: \((current.severityCounts["low"] ?? 0) - (baseline.severityCounts["low"] ?? 0))
        - info: \((current.severityCounts["info"] ?? 0) - (baseline.severityCounts["info"] ?? 0))
        """
    }

    private nonisolated static func writeReleaseSecurityPackage(targets: [URL], outputDir: URL, language: AppLanguage) async -> OperationResult {
        let accessedTargets = targets.filter { $0.startAccessingSecurityScopedResource() }
        defer {
            accessedTargets.forEach { $0.stopAccessingSecurityScopedResource() }
        }

        do {
            try FileManager.default.createDirectory(at: outputDir, withIntermediateDirectories: true)
            let scanner = NativeSecurityScanner()
            let scan = try scanner.scan(targets: targets)
            let components = try NativeDependencyInventory.components(from: targets)
            let sbom = try NativeDependencyInventory.cycloneDXJSON(components: components)
            try sbom.write(to: outputDir.appendingPathComponent("koda-sbom.cdx.json"), atomically: true, encoding: .utf8)
            let queryable = try NativeDependencyInventory.queryableOSVComponents(from: targets)
            let osvFindings = (try? await NativeOSVClient.queryFindings(components: queryable)) ?? []
            let vex = try NativeVEXDocument.render(findings: osvFindings)
            try vex.write(to: outputDir.appendingPathComponent("koda-vex.cdx.json"), atomically: true, encoding: .utf8)
            try manualEvidenceChecklist(projectName: targets.first?.lastPathComponent ?? "KODA Project", language: language)
                .write(to: outputDir.appendingPathComponent("manual-evidence-checklist.md"), atomically: true, encoding: .utf8)
            try scanner.markdownReport(scan, language: language)
                .write(to: outputDir.appendingPathComponent("scan-findings.md"), atomically: true, encoding: .utf8)
            let readme = language == .ko
                ? "# KODA 릴리스 보안 패키지\n\nSBOM, VEX, 점검결과, 수동 증적 체크리스트, 체크섬을 포함합니다.\n"
                : "# KODA Release Security Package\n\nIncludes SBOM, VEX, scan findings, manual evidence checklist, and checksums.\n"
            try readme.write(to: outputDir.appendingPathComponent("README.md"), atomically: true, encoding: .utf8)
            let checksums = try checksumsText(for: outputDir)
            try checksums.write(to: outputDir.appendingPathComponent("checksums.txt"), atomically: true, encoding: .utf8)
            let manifest = """
            {
              "generated_at": "\(ISO8601DateFormatter().string(from: Date()))",
              "target_count": \(targets.count),
              "finding_count": \(scan.findings.count),
              "component_count": \(components.count),
              "osv_finding_count": \(osvFindings.count)
            }
            """
            try manifest.write(to: outputDir.appendingPathComponent("release-security-manifest.json"), atomically: true, encoding: .utf8)
            return OperationResult(
                exitCode: 0,
                messageKO: "릴리스 보안 패키지 생성 완료: \(outputDir.path)",
                messageEN: "Release security package created: \(outputDir.path)",
                detailKO: "컴포넌트 \(components.count)개, 발견 항목 \(scan.findings.count)건, OSV \(osvFindings.count)건",
                detailEN: "Components \(components.count), findings \(scan.findings.count), OSV \(osvFindings.count)",
                writtenCount: 1,
                skippedCount: 0,
                failures: []
            )
        } catch {
            return OperationResult(
                exitCode: 2,
                messageKO: "릴리스 보안 패키지 생성 실패",
                messageEN: "Release security package failed",
                detailKO: error.localizedDescription,
                detailEN: error.localizedDescription,
                writtenCount: 0,
                skippedCount: 0,
                failures: [error.localizedDescription]
            )
        }
    }

    private nonisolated static func checksumsText(for directory: URL) throws -> String {
        let urls = try FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)
            .filter { !$0.hasDirectoryPath && $0.lastPathComponent != "checksums.txt" }
            .sorted { $0.lastPathComponent < $1.lastPathComponent }
        return try urls.map { url in
            let data = try Data(contentsOf: url)
            let digest = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
            return "\(digest)  \(url.lastPathComponent)"
        }.joined(separator: "\n") + "\n"
    }

    private nonisolated static func zapBaselinePlan(targetURL: String, language: AppLanguage) -> String {
        let command = """
        mkdir -p reports/zap && docker run --rm -t -v "$PWD/reports/zap:/zap/wrk:rw" ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t \(targetURL) -m 1 -r zap-baseline.html -w zap-baseline.md -J zap-baseline.json
        """
        switch language {
        case .ko:
            return """
            # KODA ZAP DAST 계획

            대상 URL: \(targetURL)

            이 파일은 권한이 있는 URL에 대해서만 사용하세요. ZAP baseline은 passive 중심 점검이지만 실행 중 대상 서비스에 요청을 보냅니다.

            ## 실행 명령

            ```bash
            \(command)
            ```

            ## 확인 항목

            - 보안 헤더, 쿠키, 캐시, 혼합 콘텐츠 같은 passive finding
            - 인증이 필요한 화면은 별도 authenticated scan 계획 필요
            - 운영 시스템은 변경 승인과 점검 창을 확보한 뒤 실행
            """
        case .en:
            return """
            # KODA ZAP DAST Plan

            Target URL: \(targetURL)

            Use this only for systems you own or are authorized to test. ZAP baseline is mostly passive, but it still sends requests to the target.

            ## Command

            ```bash
            \(command)
            ```

            ## Checks

            - Passive findings such as security headers, cookies, cache, and mixed content
            - Authenticated areas require a separate authenticated scan plan
            - Production systems need approval and a testing window before execution
            """
        }
    }

    private static func runOSVLookupCommand(targets: [URL]) async -> ScanResult {
        let accessedTargets = targets.filter { $0.startAccessingSecurityScopedResource() }
        defer {
            accessedTargets.forEach { $0.stopAccessingSecurityScopedResource() }
        }

        do {
            let components = try NativeDependencyInventory.queryableOSVComponents(from: targets)
            guard !components.isEmpty else {
                return ScanResult(
                    exitCode: 2,
                    reportURL: nil,
                    messageKO: "OSV 조회 가능한 고정 버전 의존성이 없습니다.",
                    messageEN: "No pinned dependency versions are available for OSV lookup.",
                    detailKO: "requirements.txt, pyproject.toml, poetry.lock, Pipfile.lock, package-lock, yarn.lock, pnpm-lock.yaml의 정확한 버전을 확인하세요.",
                    detailEN: "Check exact versions in requirements.txt, pyproject.toml, poetry.lock, Pipfile.lock, package-lock, yarn.lock, or pnpm-lock.yaml.",
                    reportItems: [],
                    scoreSnapshot: nil
                )
            }

            let findings = try await NativeOSVClient.queryFindings(components: components)
            let result = NativeScanResult(
                findings: findings,
                warnings: [],
                targetCount: targets.count,
                scannedFileCount: components.count,
                generatedAt: Date()
            )
            let scanner = NativeSecurityScanner()
            let overallFiles = try writeReportFiles(result: result, scanner: scanner, prefix: "KODA-osv-dashboard")
            let reportItems = try buildReportItems(result: result, scanner: scanner, overallFiles: overallFiles)
            return ScanResult(
                exitCode: 0,
                reportURL: overallFiles.koHTMLURL,
                messageKO: "OSV/CVE + KEV/EPSS 조회 완료: 발견 \(findings.count)건",
                messageEN: "OSV/CVE + KEV/EPSS lookup complete: \(findings.count) finding(s)",
                detailKO: "조회 컴포넌트 \(components.count)개, OSV 취약점 \(findings.count)건",
                detailEN: "Queried \(components.count) component(s), OSV vulnerabilities \(findings.count)",
                reportItems: reportItems,
                scoreSnapshot: SecurityScoreSnapshot(result: result, targets: targets)
            )
        } catch {
            return ScanResult(
                exitCode: 2,
                reportURL: nil,
                messageKO: "OSV/CVE + KEV/EPSS 조회 실패",
                messageEN: "OSV/CVE + KEV/EPSS lookup failed",
                detailKO: error.localizedDescription,
                detailEN: error.localizedDescription,
                reportItems: [],
                scoreSnapshot: nil
            )
        }
    }

    private nonisolated static func applySecurityToolkitCommand(targets: [URL]) -> ToolkitApplyResult {
        let accessedTargets = targets.filter { $0.startAccessingSecurityScopedResource() }
        defer {
            accessedTargets.forEach { $0.stopAccessingSecurityScopedResource() }
        }

        var writtenCount = 0
        var skippedCount = 0
        var failures: [String] = []

        for target in targets {
            do {
                let writes = try SecurityPreventionToolkit.write(to: target)
                writtenCount += writes.filter { $0.status == .written }.count
                skippedCount += writes.filter { $0.status == .skipped }.count
            } catch {
                failures.append("\(target.path): \(error.localizedDescription)")
            }
        }

        return ToolkitApplyResult(
            targetCount: targets.count,
            writtenCount: writtenCount,
            skippedCount: skippedCount,
            failures: failures
        )
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

    private nonisolated static func writeSanitizedReport(
        _ report: ScanReportItem,
        as format: ReportExportFormat,
        language: AppLanguage,
        to destination: URL
    ) throws {
        let scanner = NativeSecurityScanner()
        let sanitized = NativeReportSanitizer.sanitizedResult(for: report)
        switch format {
        case .html:
            try scanner.writeHTMLReport(sanitized, to: destination, language: language)
        case .markdown:
            try scanner.writeMarkdownReport(sanitized, to: destination, language: language)
        case .pdf:
            try scanner.writePDFReport(sanitized, to: destination, language: language)
        }
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
                findings: result.findings,
                warnings: result.warnings,
                targetCount: result.targetCount,
                scannedFileCount: result.scannedFileCount,
                generatedAt: result.generatedAt,
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
                    findings: findings,
                    warnings: standardResult.warnings,
                    targetCount: standardResult.targetCount,
                    scannedFileCount: standardResult.scannedFileCount,
                    generatedAt: standardResult.generatedAt,
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
        case "cis-macos-benchmark":
            // Map host posture problems (not the info-level "pass" findings) so the
            // compliance card reflects actual endpoint issues.
            return finding.category == "host" && finding.severity != "info"
        case "owasp-dependency-check", "owasp-dependency-track":
            return finding.category == "dependencies"
                || finding.ruleID.contains("dependency")
                || finding.ruleID == "prevention.sbom-missing"
                || finding.ruleID == "prevention.dependency-update-automation-missing"
                || finding.ruleID == "prevention.ci-security-scan-missing"
                || finding.ruleID == "prevention.vex-missing"
                || finding.ruleID == "prevention.dependency-track-integration-missing"
        case "owasp-scvs":
            return finding.category == "dependencies"
                || finding.ruleID.contains("dependency")
                || finding.ruleID == "prevention.scvs-plan-missing"
                || finding.ruleID == "prevention.sbom-missing"
                || finding.ruleID == "prevention.vex-missing"
                || finding.ruleID == "prevention.dependency-update-automation-missing"
                || finding.ruleID == "prevention.dependency-track-integration-missing"
                || finding.ruleID == "prevention.slsa-sigstore-missing"
                || finding.ruleID == "prevention.release-provenance-automation-missing"
                || finding.ruleID == "prevention.github-actions-unpinned"
                || finding.ruleID == "prevention.github-token-permissions-not-readonly"
                || finding.ruleID == "prevention.binary-artifact-committed"
        case "openssf-scorecard-baseline":
            return finding.category == "prevention"
                || finding.ruleID.contains("dependency")
                || finding.ruleID == "dependency.osv-known-vulnerability"
        case "cisa-kev-epss-priority":
            return finding.ruleID == "dependency.osv-known-vulnerability"
                || finding.ruleID == "prevention.vex-missing"
                || finding.ruleID == "prevention.sbom-missing"
                || finding.ruleID == "prevention.dependency-track-integration-missing"
        case "slsa-sigstore-baseline":
            return finding.ruleID == "prevention.slsa-sigstore-missing"
                || finding.ruleID == "prevention.github-actions-unpinned"
                || finding.ruleID == "prevention.github-token-permissions-not-readonly"
                || finding.ruleID == "prevention.binary-artifact-committed"
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
        case "owasp-masvs":
            return finding.ruleID.contains("android")
                || finding.ruleID.contains("ios")
                || finding.category == "secrets"
                || finding.category == "dependencies"
                || finding.ruleID == "prevention.mobile-security-plan-missing"
                || finding.ruleID == "prevention.slsa-sigstore-missing"
                || finding.ruleID == "prevention.release-provenance-automation-missing"
        case "owasp-llm-top-10-2025":
            return finding.ruleID.contains("llm")
                || finding.ruleID == "code.logging-sensitive-data"
                || finding.ruleID == "code.unbounded-request-body"
                || finding.ruleID == "code.eval-user-input"
                || finding.ruleID == "code.command-injection"
                || finding.ruleID == "code.unsafe-deserialization"
                || finding.category == "secrets"
                || finding.ruleID == "prevention.ai-llm-security-plan-missing"
                || finding.ruleID == "prevention.threat-model-missing"
                || finding.ruleID == "prevention.sbom-missing"
                || finding.ruleID == "prevention.vex-missing"
        case "nist-csf-2", "cisa-secure-software-attestation":
            return finding.category == "prevention"
                || finding.category == "dependencies"
                || finding.category == "secrets"
                || finding.category == "configuration"
                || finding.ruleID == "code.logging-sensitive-data"
                || finding.ruleID == "code.insecure-cookie-settings"
                || finding.ruleID == "code.csrf-disabled"
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

private enum NativeReportSanitizer {
    static func sanitizedResult(for report: ScanReportItem) -> NativeScanResult {
        NativeScanResult(
            findings: report.findings.map(sanitizedFinding),
            warnings: report.warnings.map(maskText),
            targetCount: report.targetCount,
            scannedFileCount: report.scannedFileCount,
            generatedAt: report.generatedAt
        )
    }

    private static func sanitizedFinding(_ finding: NativeFinding) -> NativeFinding {
        NativeFinding(
            ruleID: finding.ruleID,
            severity: finding.severity,
            category: finding.category,
            title: maskText(finding.title),
            path: maskPath(finding.path),
            line: finding.line,
            evidence: maskText(finding.evidence),
            recommendation: maskText(finding.recommendation)
        )
    }

    private static func maskPath(_ value: String) -> String {
        let absoluteMasked = maskAbsolutePaths(value)
        guard absoluteMasked != "." else {
            return absoluteMasked
        }
        if absoluteMasked.contains("[local-path]") {
            return absoluteMasked
        }
        let parts = absoluteMasked.split(separator: "/", omittingEmptySubsequences: true).map(String.init)
        if parts.isEmpty {
            return "[target]"
        }
        if parts.count == 1 {
            return "[target]/\(parts[0])"
        }
        return "[target]/" + parts.dropFirst().joined(separator: "/")
    }

    private static func maskText(_ value: String) -> String {
        var output = maskAbsolutePaths(value)
        let replacements: [(String, String)] = [
            (#"AKIA[0-9A-Z]{16}"#, "[redacted-aws-key]"),
            (#"gh[pousr]_[A-Za-z0-9_]{20,}"#, "[redacted-github-token]"),
            (#"sk-[A-Za-z0-9_-]{20,}"#, "[redacted-api-key]"),
            (#"xox[baprs]-[A-Za-z0-9-]{20,}"#, "[redacted-slack-token]"),
            (#"(?i)\b(password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key)(\s*[:=]\s*['"]?)[^'"\s#;,]{6,}"#, "$1$2[redacted]"),
        ]
        for (pattern, replacement) in replacements {
            output = regexReplace(output, pattern: pattern, replacement: replacement)
        }
        return output
    }

    private static func maskAbsolutePaths(_ value: String) -> String {
        regexReplace(
            value,
            pattern: #"(/Users/[^"' <>\n\r]+|/private/var/[^"' <>\n\r]+|[A-Za-z]:\\[^"' <>\n\r]+)"#,
            replacement: "[local-path]"
        )
    }

    private static func regexReplace(_ value: String, pattern: String, replacement: String) -> String {
        guard let regex = try? NSRegularExpression(pattern: pattern) else {
            return value
        }
        let range = NSRange(value.startIndex..<value.endIndex, in: value)
        return regex.stringByReplacingMatches(in: value, range: range, withTemplate: replacement)
    }
}

struct ScanReportItem: Identifiable, Hashable {
    let id: String
    let icon: String
    let accent: StandardAccent
    let files: GeneratedReportFiles
    let findingCount: Int
    let riskScore: Int
    let findings: [NativeFinding]
    let warnings: [String]
    let targetCount: Int
    let scannedFileCount: Int
    let generatedAt: Date
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
        case .ko: return "모든 파일 기반 점검 결과를 기준 제한 없이 확인합니다."
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
    let scoreSnapshot: SecurityScoreSnapshot?
}

private struct OperationResult {
    let exitCode: Int32
    let messageKO: String
    let messageEN: String
    let detailKO: String
    let detailEN: String
    let writtenCount: Int
    let skippedCount: Int
    let failures: [String]
}

struct SecurityScoreSnapshot: Identifiable, Codable, Hashable {
    let id: UUID
    let generatedAt: Date
    let targets: [String]
    let riskScore: Int
    let findingCount: Int
    let severityCounts: [String: Int]

    init(result: NativeScanResult, targets: [URL]) {
        self.id = UUID()
        self.generatedAt = result.generatedAt
        self.targets = targets.map { $0.lastPathComponent.isEmpty ? $0.path : $0.lastPathComponent }
        self.riskScore = result.riskScore
        self.findingCount = result.findings.count
        self.severityCounts = Dictionary(grouping: result.findings, by: \.severity).mapValues(\.count)
    }

    var formattedDate: String {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
        return formatter.string(from: generatedAt)
    }
}

private enum SecurityScoreStore {
    private static var storeURL: URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? FileManager.default.homeDirectoryForCurrentUser
        return base.appendingPathComponent("KODA", isDirectory: true).appendingPathComponent("score-history.json")
    }

    static func load() -> [SecurityScoreSnapshot] {
        guard let data = try? Data(contentsOf: storeURL) else {
            return []
        }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return (try? decoder.decode([SecurityScoreSnapshot].self, from: data)) ?? []
    }

    static func save(_ snapshots: [SecurityScoreSnapshot]) {
        do {
            let url = storeURL
            try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            encoder.dateEncodingStrategy = .iso8601
            let data = try encoder.encode(snapshots)
            try data.write(to: url, options: .atomic)
        } catch {
            // Score history must not block scanning.
        }
    }
}

struct ProjectProfile: Identifiable, Codable, Hashable {
    let id: UUID
    let name: String
    let createdAt: Date
    let targets: [ProjectProfileTarget]

    var targetPaths: [String] {
        targets.map(\.path)
    }

    var formattedDate: String {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd HH:mm"
        return formatter.string(from: createdAt)
    }
}

struct ProjectProfileTarget: Identifiable, Codable, Hashable {
    let id: UUID
    let path: String
    let bookmarkData: Data?

    init(id: UUID = UUID(), path: String, bookmarkData: Data?) {
        self.id = id
        self.path = path
        self.bookmarkData = bookmarkData
    }
}

private enum ProjectProfileStore {
    private static var storeURL: URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? FileManager.default.homeDirectoryForCurrentUser
        return base.appendingPathComponent("KODA", isDirectory: true).appendingPathComponent("project-profiles.json")
    }

    static func load() -> [ProjectProfile] {
        guard let data = try? Data(contentsOf: storeURL) else {
            return []
        }
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return (try? decoder.decode([ProjectProfile].self, from: data)) ?? []
    }

    static func save(_ profiles: [ProjectProfile]) {
        do {
            let url = storeURL
            try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            encoder.dateEncodingStrategy = .iso8601
            let data = try encoder.encode(profiles)
            try data.write(to: url, options: .atomic)
        } catch {
            // Project profiles must not block scanning or the main UI.
        }
    }
}

struct SecurityFixPlan: Identifiable, Hashable {
    enum Action: Hashable {
        case writeFile(String)
        case appendLines([String])
    }

    let id: String
    let targetURL: URL
    let relativePath: String
    let titleKO: String
    let titleEN: String
    let detailKO: String
    let detailEN: String
    let action: Action

    func title(language: AppLanguage) -> String {
        language == .ko ? titleKO : titleEN
    }

    func detail(language: AppLanguage) -> String {
        language == .ko ? detailKO : detailEN
    }
}

private enum SecurityAutoFixer {
    static func plans(for root: URL) -> [SecurityFixPlan] {
        let accessed = root.startAccessingSecurityScopedResource()
        defer {
            if accessed { root.stopAccessingSecurityScopedResource() }
        }

        let fileManager = FileManager.default
        var isDirectory = ObjCBool(false)
        guard fileManager.fileExists(atPath: root.path, isDirectory: &isDirectory), isDirectory.boolValue else {
            return []
        }

        let projectName = root.lastPathComponent.isEmpty ? "KODA Project" : root.lastPathComponent
        var plans: [SecurityFixPlan] = []

        for template in SecurityPreventionToolkit.templateFiles(projectName: projectName) {
            let destination = root.appendingPathComponent(template.relativePath)
            if !fileManager.fileExists(atPath: destination.path) {
                plans.append(
                    SecurityFixPlan(
                        id: "\(root.path)::write::\(template.relativePath)",
                        targetURL: root,
                        relativePath: template.relativePath,
                        titleKO: "\(template.relativePath) 생성",
                        titleEN: "Create \(template.relativePath)",
                        detailKO: "\(projectName)에 기본 보안 예방 파일을 생성합니다.",
                        detailEN: "Create a baseline security guardrail file in \(projectName).",
                        action: .writeFile(template.content)
                    )
                )
            }
        }

        let gitignoreLines = [".env", ".env.*", "*.pem", "*.key", "*.p12", "*.pfx"]
        appendMergePlan(
            root: root,
            relativePath: ".gitignore",
            lines: gitignoreLines,
            titleKO: ".gitignore 보안 패턴 추가",
            titleEN: "Add security patterns to .gitignore",
            detailKO: ".env와 개인 키 형식 파일이 저장소에 들어가지 않도록 누락된 줄만 추가합니다.",
            detailEN: "Append only missing lines so .env and private-key files stay out of the repository.",
            plans: &plans
        )

        let dockerfileExists = fileManager.fileExists(atPath: root.appendingPathComponent("Dockerfile").path)
        let dockerignoreExists = fileManager.fileExists(atPath: root.appendingPathComponent(".dockerignore").path)
        if dockerfileExists || dockerignoreExists {
            let dockerignoreLines = [".git", ".env", ".env.*", "*.pem", "*.key", "node_modules", "dist", "build", "coverage", "reports"]
            appendMergePlan(
                root: root,
                relativePath: ".dockerignore",
                lines: dockerignoreLines,
                titleKO: ".dockerignore 보안 패턴 병합",
                titleEN: "Merge security patterns into .dockerignore",
                detailKO: "Docker 빌드 컨텍스트에 비밀값과 빌드 산출물이 포함되지 않도록 누락된 줄만 추가합니다.",
                detailEN: "Append missing lines to keep secrets and build artifacts out of Docker build contexts.",
                plans: &plans
            )
        }

        return plans
    }

    static func apply(plans: [SecurityFixPlan]) -> OperationResult {
        var applied = 0
        var skipped = 0
        var failures: [String] = []

        for plan in plans {
            let accessed = plan.targetURL.startAccessingSecurityScopedResource()
            defer {
                if accessed { plan.targetURL.stopAccessingSecurityScopedResource() }
            }

            do {
                let destination = plan.targetURL.appendingPathComponent(plan.relativePath)
                try FileManager.default.createDirectory(at: destination.deletingLastPathComponent(), withIntermediateDirectories: true)
                switch plan.action {
                case .writeFile(let content):
                    if FileManager.default.fileExists(atPath: destination.path) {
                        skipped += 1
                    } else {
                        try content.write(to: destination, atomically: true, encoding: .utf8)
                        applied += 1
                    }
                case .appendLines(let lines):
                    var existing = ""
                    if FileManager.default.fileExists(atPath: destination.path) {
                        existing = try String(contentsOf: destination, encoding: .utf8)
                    }
                    var output = existing
                    if !output.isEmpty, !output.hasSuffix("\n") {
                        output += "\n"
                    }
                    let existingLines = Set(existing.components(separatedBy: .newlines).map { $0.trimmingCharacters(in: .whitespaces) })
                    let missing = lines.filter { !existingLines.contains($0) }
                    if missing.isEmpty {
                        skipped += 1
                    } else {
                        output += missing.joined(separator: "\n") + "\n"
                        try output.write(to: destination, atomically: true, encoding: .utf8)
                        applied += 1
                    }
                }
            } catch {
                failures.append("\(plan.relativePath): \(error.localizedDescription)")
            }
        }

        return OperationResult(
            exitCode: failures.isEmpty ? 0 : 2,
            messageKO: "자동 수정 완료",
            messageEN: "Auto-fix complete",
            detailKO: "적용 \(applied)개, 기존 유지 \(skipped)개",
            detailEN: "Applied \(applied), kept existing \(skipped)",
            writtenCount: applied,
            skippedCount: skipped,
            failures: failures
        )
    }

    private static func appendMergePlan(
        root: URL,
        relativePath: String,
        lines: [String],
        titleKO: String,
        titleEN: String,
        detailKO: String,
        detailEN: String,
        plans: inout [SecurityFixPlan]
    ) {
        let destination = root.appendingPathComponent(relativePath)
        let existing = (try? String(contentsOf: destination, encoding: .utf8)) ?? ""
        let existingLines = Set(existing.components(separatedBy: .newlines).map { $0.trimmingCharacters(in: .whitespaces) })
        let missing = lines.filter { !existingLines.contains($0) }
        guard !missing.isEmpty else {
            return
        }
        plans.append(
            SecurityFixPlan(
                id: "\(root.path)::append::\(relativePath)",
                targetURL: root,
                relativePath: relativePath,
                titleKO: titleKO,
                titleEN: titleEN,
                detailKO: "\(detailKO) 추가 줄: \(missing.joined(separator: ", "))",
                detailEN: "\(detailEN) Lines: \(missing.joined(separator: ", "))",
                action: .appendLines(missing)
            )
        )
    }
}

private enum KODAIgnoreTemplateWriter {
    static func write(to targets: [URL]) -> OperationResult {
        var written = 0
        var skipped = 0
        var failures: [String] = []

        for target in targets {
            let accessed = target.startAccessingSecurityScopedResource()
            defer {
                if accessed { target.stopAccessingSecurityScopedResource() }
            }

            do {
                let destination = target.appendingPathComponent("koda-ignore.yml")
                if FileManager.default.fileExists(atPath: destination.path) {
                    skipped += 1
                    continue
                }
                try template.write(to: destination, atomically: true, encoding: .utf8)
                written += 1
            } catch {
                failures.append("\(target.path): \(error.localizedDescription)")
            }
        }

        return OperationResult(
            exitCode: failures.isEmpty ? 0 : 2,
            messageKO: "예외 파일 생성 완료: 생성 \(written)개, 기존 유지 \(skipped)개",
            messageEN: "Ignore file setup complete: written \(written), kept existing \(skipped)",
            detailKO: "koda-ignore.yml에서 rule/path/reason/until 값을 조정하면 다음 스캔부터 해당 항목이 제외됩니다.",
            detailEN: "Edit rule/path/reason/until in koda-ignore.yml to suppress matching findings in future scans.",
            writtenCount: written,
            skippedCount: skipped,
            failures: failures
        )
    }

    private static let template = """
    # KODA finding exceptions. Existing scans ignore matching entries until the date expires.
    # Keep reasons specific and review every exception before extending it.
    ignore:
      - rule: secret.generic-assignment
        path: "tests/**"
        reason: "example test fixture only"
        until: "2099-12-31"
    """
}

private struct NativeDependencyComponent: Hashable {
    let name: String
    let ecosystem: String
    let version: String
    let path: String
    let target: String
    let line: Int?
    let scope: String

    var purl: String {
        let encodedName = name.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? name
        let encodedVersion = version.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? version
        switch ecosystem {
        case "npm": return "pkg:npm/\(encodedName)@\(encodedVersion)"
        case "PyPI": return "pkg:pypi/\(encodedName.lowercased())@\(encodedVersion)"
        case "Maven":
            let parts = name.split(separator: ":", maxSplits: 1).map(String.init)
            if parts.count == 2 {
                let group = parts[0].addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? parts[0]
                let artifact = parts[1].addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? parts[1]
                return "pkg:maven/\(group)/\(artifact)@\(encodedVersion)"
            }
            return "pkg:maven/\(encodedName)@\(encodedVersion)"
        case "Go": return "pkg:golang/\(encodedName)@\(encodedVersion)"
        case "crates.io": return "pkg:cargo/\(encodedName)@\(encodedVersion)"
        case "RubyGems": return "pkg:gem/\(encodedName)@\(encodedVersion)"
        case "Packagist": return "pkg:composer/\(encodedName)@\(encodedVersion)"
        case "NuGet": return "pkg:nuget/\(encodedName)@\(encodedVersion)"
        default: return "pkg:generic/\(encodedName)@\(encodedVersion)"
        }
    }
}

private enum NativeDependencyInventory {
    private static let supportedOSVEcosystems: Set<String> = ["npm", "PyPI", "Maven", "Go", "crates.io", "RubyGems", "Packagist", "NuGet"]
    private static let excludedDirectoryNames: Set<String> = [
        ".git", ".hg", ".svn", ".cache", ".next", ".venv", "venv", "node_modules", "dist", "build", "coverage", "reports", "target"
    ]

    static func components(from targets: [URL]) throws -> [NativeDependencyComponent] {
        var components: [NativeDependencyComponent] = []
        for target in targets {
            if isDirectory(target) {
                components.append(contentsOf: componentsFromDirectory(target))
            } else {
                components.append(contentsOf: componentsFromFile(target, root: target.deletingLastPathComponent(), targetName: target.lastPathComponent))
            }
        }
        return unique(components)
    }

    static func queryableOSVComponents(from targets: [URL]) throws -> [NativeDependencyComponent] {
        try components(from: targets).filter { component in
            supportedOSVEcosystems.contains(component.ecosystem) && isExactVersion(component.version)
        }
    }

    static func cycloneDXJSON(components: [NativeDependencyComponent]) throws -> String {
        let payload: [String: Any] = [
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "version": 1,
            "metadata": [
                "timestamp": ISO8601DateFormatter().string(from: Date()),
                "tools": [
                    [
                        "vendor": "KODA",
                        "name": "KODA",
                        "version": "0.1.0",
                    ],
                ],
            ],
            "components": components.map { component in
                [
                    "type": "library",
                    "name": component.name,
                    "version": component.version,
                    "purl": component.purl,
                    "scope": component.scope,
                    "properties": [
                        ["name": "koda:ecosystem", "value": component.ecosystem],
                        ["name": "koda:path", "value": component.path],
                        ["name": "koda:target", "value": component.target],
                    ],
                ] as [String: Any]
            },
        ]
        let data = try JSONSerialization.data(withJSONObject: payload, options: [.prettyPrinted, .sortedKeys])
        return String(decoding: data, as: UTF8.self)
    }

    private static func componentsFromDirectory(_ root: URL) -> [NativeDependencyComponent] {
        guard let enumerator = FileManager.default.enumerator(
            at: root,
            includingPropertiesForKeys: [.isDirectoryKey],
            options: [.skipsPackageDescendants]
        ) else {
            return []
        }

        let targetName = root.lastPathComponent.isEmpty ? root.path : root.lastPathComponent
        var components: [NativeDependencyComponent] = []
        while let item = enumerator.nextObject() as? URL {
            if isDirectory(item) {
                if excludedDirectoryNames.contains(item.lastPathComponent) {
                    enumerator.skipDescendants()
                }
                continue
            }
            components.append(contentsOf: componentsFromFile(item, root: root, targetName: targetName))
        }
        return components
    }

    private static func componentsFromFile(_ file: URL, root: URL, targetName: String) -> [NativeDependencyComponent] {
        switch file.lastPathComponent {
        case "requirements.txt", "requirements.in":
            return requirementsComponents(file, root: root, targetName: targetName)
        case "package.json":
            return packageJSONComponents(file, root: root, targetName: targetName)
        case "package-lock.json", "npm-shrinkwrap.json":
            return packageLockComponents(file, root: root, targetName: targetName)
        case "yarn.lock":
            return yarnLockComponents(file, root: root, targetName: targetName)
        case "pnpm-lock.yaml":
            return pnpmLockComponents(file, root: root, targetName: targetName)
        case "pyproject.toml":
            return pyprojectComponents(file, root: root, targetName: targetName)
        case "poetry.lock":
            return poetryLockComponents(file, root: root, targetName: targetName)
        case "Pipfile.lock":
            return pipfileLockComponents(file, root: root, targetName: targetName)
        case "go.mod", "go.sum":
            return goModuleComponents(file, root: root, targetName: targetName)
        case "Cargo.lock":
            return cargoLockComponents(file, root: root, targetName: targetName)
        case "Gemfile.lock":
            return gemfileLockComponents(file, root: root, targetName: targetName)
        case "composer.lock":
            return composerLockComponents(file, root: root, targetName: targetName)
        case "pom.xml":
            return pomComponents(file, root: root, targetName: targetName)
        case "packages.config":
            return nugetComponents(file, root: root, targetName: targetName)
        default:
            if ["csproj", "fsproj", "vbproj"].contains(file.pathExtension.lowercased()) {
                return nugetComponents(file, root: root, targetName: targetName)
            }
            return []
        }
    }

    private static func requirementsComponents(_ file: URL, root: URL, targetName: String) -> [NativeDependencyComponent] {
        guard let lines = try? String(contentsOf: file, encoding: .utf8).components(separatedBy: .newlines) else {
            return []
        }
        return lines.enumerated().compactMap { index, rawLine in
            pythonRequirementComponent(
                rawLine,
                file: file,
                root: root,
                targetName: targetName,
                line: index + 1,
                source: file.lastPathComponent
            )
        }
    }

    private static func packageJSONComponents(_ file: URL, root: URL, targetName: String) -> [NativeDependencyComponent] {
        guard let data = try? Data(contentsOf: file),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return []
        }
        var components: [NativeDependencyComponent] = []
        for section in ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"] {
            guard let dependencies = object[section] as? [String: Any] else { continue }
            for (name, rawVersion) in dependencies {
                guard let version = rawVersion as? String else { continue }
                components.append(
                    NativeDependencyComponent(
                        name: name,
                        ecosystem: "npm",
                        version: version.trimmingCharacters(in: .whitespacesAndNewlines),
                        path: displayPath(file, root: root, targetName: targetName),
                        target: targetName,
                        line: nil,
                        scope: section == "devDependencies" ? "excluded" : "required"
                    )
                )
            }
        }
        return components
    }

    private static func packageLockComponents(_ file: URL, root: URL, targetName: String) -> [NativeDependencyComponent] {
        guard let data = try? Data(contentsOf: file),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return []
        }
        var components: [NativeDependencyComponent] = []
        if let packages = object["packages"] as? [String: Any] {
            for (packagePath, rawPackage) in packages {
                guard !packagePath.isEmpty,
                      let package = rawPackage as? [String: Any],
                      let version = package["version"] as? String else {
                    continue
                }
                let name = (package["name"] as? String) ?? packagePath.components(separatedBy: "node_modules/").last ?? ""
                guard !name.isEmpty else { continue }
                components.append(
                    NativeDependencyComponent(
                        name: name,
                        ecosystem: "npm",
                        version: version,
                        path: displayPath(file, root: root, targetName: targetName),
                        target: targetName,
                        line: nil,
                        scope: "required"
                    )
                )
            }
        }
        return components
    }

    private static func yarnLockComponents(_ file: URL, root: URL, targetName: String) -> [NativeDependencyComponent] {
        guard let lines = try? String(contentsOf: file, encoding: .utf8).components(separatedBy: .newlines) else {
            return []
        }

        var pendingNames: [String] = []
        var pendingLine: Int?
        var components: [NativeDependencyComponent] = []
        for (index, rawLine) in lines.enumerated() {
            let stripped = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
            if stripped.isEmpty || stripped.hasPrefix("#") {
                continue
            }
            if !rawLine.hasPrefix(" ") && !rawLine.hasPrefix("\t") && stripped.hasSuffix(":") {
                pendingNames = yarnDescriptorNames(String(stripped.dropLast()))
                pendingLine = index + 1
                continue
            }
            guard !pendingNames.isEmpty, let version = yarnVersion(from: stripped), !version.isEmpty else {
                continue
            }
            for name in pendingNames {
                components.append(
                    NativeDependencyComponent(
                        name: name,
                        ecosystem: "npm",
                        version: version,
                        path: displayPath(file, root: root, targetName: targetName),
                        target: targetName,
                        line: pendingLine,
                        scope: "required"
                    )
                )
            }
            pendingNames = []
            pendingLine = nil
        }
        return components
    }

    private static func pnpmLockComponents(_ file: URL, root: URL, targetName: String) -> [NativeDependencyComponent] {
        guard let lines = try? String(contentsOf: file, encoding: .utf8).components(separatedBy: .newlines) else {
            return []
        }

        var inPackages = false
        var components: [NativeDependencyComponent] = []
        for (index, rawLine) in lines.enumerated() {
            let stripped = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
            if stripped == "packages:" {
                inPackages = true
                continue
            }
            if inPackages && !rawLine.hasPrefix(" ") && !rawLine.hasPrefix("\t") {
                inPackages = false
            }
            guard inPackages else {
                continue
            }
            let key = stripQuotes(stripped)
            guard key.hasPrefix("/"), key.hasSuffix(":"),
                  let parsed = pnpmNameVersion(from: String(key.dropFirst().dropLast())) else {
                continue
            }
            components.append(
                NativeDependencyComponent(
                    name: parsed.name,
                    ecosystem: "npm",
                    version: parsed.version,
                    path: displayPath(file, root: root, targetName: targetName),
                    target: targetName,
                    line: index + 1,
                    scope: "required"
                )
            )
        }
        return components
    }

    private static func pyprojectComponents(_ file: URL, root: URL, targetName: String) -> [NativeDependencyComponent] {
        guard let lines = try? String(contentsOf: file, encoding: .utf8).components(separatedBy: .newlines) else {
            return []
        }

        var section = ""
        var components: [NativeDependencyComponent] = []
        for (index, rawLine) in lines.enumerated() {
            let lineNumber = index + 1
            let stripped = stripInlineComment(rawLine).trimmingCharacters(in: .whitespacesAndNewlines)
            if stripped.hasPrefix("[") && stripped.hasSuffix("]") {
                section = stripped.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
                continue
            }
            let scope = section.contains("optional-dependencies") ? "excluded" : "required"
            for requirement in quotedPythonRequirements(in: stripped) {
                if let component = pythonRequirementComponent(
                    requirement,
                    file: file,
                    root: root,
                    targetName: targetName,
                    line: lineNumber,
                    scope: scope,
                    source: section.isEmpty ? "pyproject.toml" : section
                ) {
                    components.append(component)
                }
            }
            if section == "tool.poetry.dependencies",
               let pair = keyValue(stripped),
               pair.key.lowercased() != "python",
               let version = firstQuotedString(in: pair.value) {
                components.append(
                    NativeDependencyComponent(
                        name: normalizePythonName(pair.key),
                        ecosystem: "PyPI",
                        version: version,
                        path: displayPath(file, root: root, targetName: targetName),
                        target: targetName,
                        line: lineNumber,
                        scope: "required"
                    )
                )
            }
        }
        return components
    }

    private static func poetryLockComponents(_ file: URL, root: URL, targetName: String) -> [NativeDependencyComponent] {
        guard let lines = try? String(contentsOf: file, encoding: .utf8).components(separatedBy: .newlines) else {
            return []
        }

        var current: [String: String] = [:]
        var currentLine: Int?
        var components: [NativeDependencyComponent] = []

        func flushPackage() {
            guard let name = current["name"], let version = current["version"], !name.isEmpty, !version.isEmpty else {
                return
            }
            let groups = current["groups"]?.lowercased() ?? ""
            let category = current["category"]?.lowercased() ?? ""
            let scope = groups.contains("dev") || category == "dev" ? "excluded" : "required"
            components.append(
                NativeDependencyComponent(
                    name: normalizePythonName(name),
                    ecosystem: "PyPI",
                    version: version,
                    path: displayPath(file, root: root, targetName: targetName),
                    target: targetName,
                    line: currentLine,
                    scope: scope
                )
            )
        }

        for (index, rawLine) in lines.enumerated() {
            let stripped = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
            if stripped == "[[package]]" {
                flushPackage()
                current = [:]
                currentLine = index + 1
                continue
            }
            guard currentLine != nil, let pair = keyValue(stripped), ["name", "version", "category", "groups"].contains(pair.key) else {
                continue
            }
            current[pair.key] = tomlValue(pair.value)
        }
        flushPackage()
        return components
    }

    private static func pipfileLockComponents(_ file: URL, root: URL, targetName: String) -> [NativeDependencyComponent] {
        guard let data = try? Data(contentsOf: file),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return []
        }

        var components: [NativeDependencyComponent] = []
        for (section, scope) in [("default", "required"), ("develop", "excluded")] {
            guard let dependencies = object[section] as? [String: Any] else { continue }
            for (name, payload) in dependencies {
                guard let dependency = payload as? [String: Any],
                      let rawVersion = dependency["version"] as? String else {
                    continue
                }
                let version = rawVersion.hasPrefix("==")
                    ? String(rawVersion.dropFirst(2)).trimmingCharacters(in: .whitespacesAndNewlines)
                    : rawVersion.trimmingCharacters(in: .whitespacesAndNewlines)
                guard !version.isEmpty else { continue }
                components.append(
                    NativeDependencyComponent(
                        name: normalizePythonName(name),
                        ecosystem: "PyPI",
                        version: version,
                        path: displayPath(file, root: root, targetName: targetName),
                        target: targetName,
                        line: nil,
                        scope: scope
                    )
                )
            }
        }
        return components
    }

    private static func goModuleComponents(_ file: URL, root: URL, targetName: String) -> [NativeDependencyComponent] {
        guard let lines = try? String(contentsOf: file, encoding: .utf8).components(separatedBy: .newlines) else {
            return []
        }

        var inRequireBlock = false
        var components: [NativeDependencyComponent] = []
        for (index, rawLine) in lines.enumerated() {
            var line = rawLine
                .split(separator: "//", maxSplits: 1, omittingEmptySubsequences: false)
                .first
                .map(String.init)?
                .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            guard !line.isEmpty else { continue }
            if file.lastPathComponent == "go.mod" {
                if line == "require (" {
                    inRequireBlock = true
                    continue
                }
                if inRequireBlock && line == ")" {
                    inRequireBlock = false
                    continue
                }
                if line.hasPrefix("require ") {
                    line = String(line.dropFirst("require ".count)).trimmingCharacters(in: .whitespacesAndNewlines)
                } else if !inRequireBlock {
                    continue
                }
            }
            let pattern = file.lastPathComponent == "go.sum"
                ? #"^\s*([A-Za-z0-9_.\-~/]+(?:/[A-Za-z0-9_.\-~]+)+)\s+(v?[0-9][^\s/]+)(?:/go\.mod)?\s+"#
                : #"^\s*([A-Za-z0-9_.\-~/]+(?:/[A-Za-z0-9_.\-~]+)+)\s+(v?[0-9][^\s]+)"#
            guard let groups = firstRegexGroups(pattern, in: line), groups.count >= 2 else {
                continue
            }
            components.append(
                NativeDependencyComponent(
                    name: groups[0],
                    ecosystem: "Go",
                    version: groups[1],
                    path: displayPath(file, root: root, targetName: targetName),
                    target: targetName,
                    line: index + 1,
                    scope: "required"
                )
            )
        }
        return components
    }

    private static func cargoLockComponents(_ file: URL, root: URL, targetName: String) -> [NativeDependencyComponent] {
        guard let lines = try? String(contentsOf: file, encoding: .utf8).components(separatedBy: .newlines) else {
            return []
        }

        var current: [String: String] = [:]
        var currentLine: Int?
        var components: [NativeDependencyComponent] = []

        func flushPackage() {
            guard let name = current["name"], let version = current["version"], !name.isEmpty, !version.isEmpty else {
                return
            }
            components.append(
                NativeDependencyComponent(
                    name: name,
                    ecosystem: "crates.io",
                    version: version,
                    path: displayPath(file, root: root, targetName: targetName),
                    target: targetName,
                    line: currentLine,
                    scope: "required"
                )
            )
        }

        for (index, rawLine) in lines.enumerated() {
            let stripped = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
            if stripped == "[[package]]" {
                flushPackage()
                current = [:]
                currentLine = index + 1
                continue
            }
            guard currentLine != nil, let pair = keyValue(stripped), ["name", "version"].contains(pair.key) else {
                continue
            }
            current[pair.key] = tomlValue(pair.value)
        }
        flushPackage()
        return components
    }

    private static func gemfileLockComponents(_ file: URL, root: URL, targetName: String) -> [NativeDependencyComponent] {
        guard let lines = try? String(contentsOf: file, encoding: .utf8).components(separatedBy: .newlines) else {
            return []
        }

        var inSpecs = false
        var components: [NativeDependencyComponent] = []
        for (index, rawLine) in lines.enumerated() {
            let stripped = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
            if stripped == "GEM" {
                inSpecs = false
                continue
            }
            if stripped == "specs:" {
                inSpecs = true
                continue
            }
            if inSpecs && !rawLine.isEmpty && !rawLine.hasPrefix(" ") && !rawLine.hasPrefix("\t") {
                inSpecs = false
            }
            guard inSpecs,
                  let groups = firstRegexGroups(#"^\s{4}([A-Za-z0-9_.\-]+)\s+\(([^()\s]+)\)"#, in: rawLine),
                  groups.count >= 2 else {
                continue
            }
            components.append(
                NativeDependencyComponent(
                    name: groups[0],
                    ecosystem: "RubyGems",
                    version: groups[1],
                    path: displayPath(file, root: root, targetName: targetName),
                    target: targetName,
                    line: index + 1,
                    scope: "required"
                )
            )
        }
        return components
    }

    private static func composerLockComponents(_ file: URL, root: URL, targetName: String) -> [NativeDependencyComponent] {
        guard let data = try? Data(contentsOf: file),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return []
        }

        var components: [NativeDependencyComponent] = []
        for (section, scope) in [("packages", "required"), ("packages-dev", "excluded")] {
            guard let packages = object[section] as? [[String: Any]] else { continue }
            for package in packages {
                guard let name = package["name"] as? String,
                      let rawVersion = package["version"] as? String else {
                    continue
                }
                components.append(
                    NativeDependencyComponent(
                        name: name,
                        ecosystem: "Packagist",
                        version: rawVersion.hasPrefix("v") ? String(rawVersion.dropFirst()) : rawVersion,
                        path: displayPath(file, root: root, targetName: targetName),
                        target: targetName,
                        line: nil,
                        scope: scope
                    )
                )
            }
        }
        return components
    }

    private static func pomComponents(_ file: URL, root: URL, targetName: String) -> [NativeDependencyComponent] {
        guard let text = try? String(contentsOf: file, encoding: .utf8) else {
            return []
        }

        var components: [NativeDependencyComponent] = []
        for block in regexMatches(#"<dependency\b[^>]*>(.*?)</dependency>"#, in: text) {
            let groupID = firstXMLTagValue("groupId", in: block)
            let artifactID = firstXMLTagValue("artifactId", in: block)
            let version = firstXMLTagValue("version", in: block)
            guard !groupID.isEmpty, !artifactID.isEmpty, !version.isEmpty, !version.hasPrefix("${") else {
                continue
            }
            let scope = firstXMLTagValue("scope", in: block).lowercased() == "test" ? "excluded" : "required"
            components.append(
                NativeDependencyComponent(
                    name: "\(groupID):\(artifactID)",
                    ecosystem: "Maven",
                    version: version,
                    path: displayPath(file, root: root, targetName: targetName),
                    target: targetName,
                    line: lineNumber(of: "<artifactId>\(artifactID)</artifactId>", in: text),
                    scope: scope
                )
            )
        }
        return components
    }

    private static func nugetComponents(_ file: URL, root: URL, targetName: String) -> [NativeDependencyComponent] {
        guard let text = try? String(contentsOf: file, encoding: .utf8) else {
            return []
        }

        var components: [NativeDependencyComponent] = []
        if file.lastPathComponent == "packages.config" {
            for match in regexMatches(#"<package\b[^>]*\bid=["']([^"']+)["'][^>]*\bversion=["']([^"']+)["'][^>]*/?>"#, in: text, includeFullMatch: false) {
                let parts = match.components(separatedBy: "\u{1f}")
                guard parts.count == 2 else { continue }
                components.append(
                    NativeDependencyComponent(
                        name: parts[0],
                        ecosystem: "NuGet",
                        version: parts[1],
                        path: displayPath(file, root: root, targetName: targetName),
                        target: targetName,
                        line: lineNumber(of: parts[0], in: text),
                        scope: "required"
                    )
                )
            }
            return components
        }

        for block in regexMatches(#"<PackageReference\b([^>]*)>(.*?)</PackageReference>|<PackageReference\b([^>]*)/?>"#, in: text) {
            let attributes = xmlAttributes(block)
            let name = attributes["Include"] ?? attributes["Update"] ?? ""
            let version = attributes["Version"] ?? firstXMLTagValue("Version", in: block)
            guard !name.isEmpty, !version.isEmpty else { continue }
            components.append(
                NativeDependencyComponent(
                    name: name,
                    ecosystem: "NuGet",
                    version: version,
                    path: displayPath(file, root: root, targetName: targetName),
                    target: targetName,
                    line: lineNumber(of: name, in: text),
                    scope: "required"
                )
            )
        }
        return components
    }

    private static func unique(_ components: [NativeDependencyComponent]) -> [NativeDependencyComponent] {
        var seen: Set<String> = []
        var output: [NativeDependencyComponent] = []
        for component in components.sorted(by: { "\($0.ecosystem)\($0.name)\($0.version)" < "\($1.ecosystem)\($1.name)\($1.version)" }) {
            let key = "\(component.ecosystem.lowercased())|\(component.name.lowercased())|\(component.version)|\(component.target)"
            if seen.insert(key).inserted {
                output.append(component)
            }
        }
        return output
    }

    private static func isExactVersion(_ version: String) -> Bool {
        var trimmed = version.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.hasPrefix("v"), trimmed.dropFirst().first?.isNumber == true {
            trimmed = String(trimmed.dropFirst())
        }
        guard !trimmed.isEmpty else { return false }
        if trimmed.range(of: #"[<>=~^*xX\[\]]|\$\{"#, options: .regularExpression) != nil {
            return false
        }
        return trimmed.first?.isNumber == true
    }

    private static func isDirectory(_ url: URL) -> Bool {
        (try? url.resourceValues(forKeys: [.isDirectoryKey]).isDirectory) == true
    }

    private static func pythonRequirementComponent(
        _ value: String,
        file: URL,
        root: URL,
        targetName: String,
        line: Int?,
        scope: String = "required",
        source: String = ""
    ) -> NativeDependencyComponent? {
        let stripped = stripInlineComment(value).trimmingCharacters(in: .whitespacesAndNewlines)
        guard !stripped.isEmpty, !stripped.hasPrefix("-"), let range = stripped.range(of: "==") else {
            return nil
        }
        let name = stripped[..<range.lowerBound].trimmingCharacters(in: .whitespacesAndNewlines)
        let version = stripped[range.upperBound...]
            .split(separator: ";", maxSplits: 1)
            .first
            .map(String.init)?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        guard !name.isEmpty, !version.isEmpty else {
            return nil
        }
        return NativeDependencyComponent(
            name: normalizePythonName(String(name)),
            ecosystem: "PyPI",
            version: version,
            path: displayPath(file, root: root, targetName: targetName),
            target: targetName,
            line: line,
            scope: scope
        )
    }

    private static func quotedPythonRequirements(in value: String) -> [String] {
        let pattern = #""([^"]+==[^"]+)"|'([^']+==[^']+)'"#
        guard let regex = try? NSRegularExpression(pattern: pattern) else {
            return []
        }
        let range = NSRange(value.startIndex..<value.endIndex, in: value)
        return regex.matches(in: value, range: range).compactMap { match in
            for index in 1..<match.numberOfRanges {
                let capture = match.range(at: index)
                if capture.location != NSNotFound, let swiftRange = Range(capture, in: value) {
                    return String(value[swiftRange])
                }
            }
            return nil
        }
    }

    private static func yarnVersion(from value: String) -> String? {
        if value.hasPrefix("version ") {
            return stripQuotes(String(value.dropFirst("version ".count)).trimmingCharacters(in: .whitespacesAndNewlines))
        }
        if value.hasPrefix("version:") {
            return stripQuotes(String(value.dropFirst("version:".count)).trimmingCharacters(in: .whitespacesAndNewlines))
        }
        return nil
    }

    private static func yarnDescriptorNames(_ value: String) -> [String] {
        var names: [String] = []
        for rawDescriptor in value.components(separatedBy: ",") {
            let descriptor = stripQuotes(rawDescriptor.trimmingCharacters(in: .whitespacesAndNewlines))
            guard !descriptor.isEmpty, descriptor != "__metadata" else { continue }
            let name = yarnName(from: descriptor)
            if !name.isEmpty, !names.contains(name) {
                names.append(name)
            }
        }
        return names
    }

    private static func yarnName(from descriptor: String) -> String {
        if descriptor.hasPrefix("@") {
            guard let slash = descriptor.firstIndex(of: "/") else {
                return ""
            }
            let afterSlash = descriptor.index(after: slash)
            if let marker = descriptor[afterSlash...].firstIndex(of: "@") {
                return String(descriptor[..<marker])
            }
            return descriptor
        }
        if let marker = descriptor.firstIndex(of: "@") {
            return String(descriptor[..<marker])
        }
        return descriptor
    }

    private static func pnpmNameVersion(from value: String) -> (name: String, version: String)? {
        let cleaned = value
            .split(separator: "(", maxSplits: 1)
            .first
            .map(String.init)?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        let name: String
        let rawVersion: String
        if cleaned.contains("/") && !cleaned.contains("@") {
            let parts = cleaned.split(separator: "/", maxSplits: 1).map(String.init)
            guard parts.count == 2 else { return nil }
            name = parts[0]
            rawVersion = parts[1]
        } else if let marker = cleaned.lastIndex(of: "@"), marker != cleaned.startIndex {
            name = String(cleaned[..<marker])
            rawVersion = String(cleaned[cleaned.index(after: marker)...])
        } else {
            return nil
        }
        let version = rawVersion
            .split(separator: "_", maxSplits: 1)
            .first
            .map(String.init)?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        guard !name.isEmpty, !version.isEmpty else {
            return nil
        }
        return (name, version)
    }

    private static func firstRegexGroups(_ pattern: String, in value: String) -> [String]? {
        guard let regex = try? NSRegularExpression(pattern: pattern) else {
            return nil
        }
        let range = NSRange(value.startIndex..<value.endIndex, in: value)
        guard let match = regex.firstMatch(in: value, range: range) else {
            return nil
        }
        var groups: [String] = []
        for index in 1..<match.numberOfRanges {
            let capture = match.range(at: index)
            if capture.location != NSNotFound, let swiftRange = Range(capture, in: value) {
                groups.append(String(value[swiftRange]))
            }
        }
        return groups
    }

    private static func regexMatches(_ pattern: String, in value: String, includeFullMatch: Bool = true) -> [String] {
        guard let regex = try? NSRegularExpression(pattern: pattern, options: [.dotMatchesLineSeparators, .caseInsensitive]) else {
            return []
        }
        let range = NSRange(value.startIndex..<value.endIndex, in: value)
        return regex.matches(in: value, range: range).compactMap { match in
            if includeFullMatch, let swiftRange = Range(match.range, in: value) {
                return String(value[swiftRange])
            }
            var captures: [String] = []
            for index in 1..<match.numberOfRanges {
                let capture = match.range(at: index)
                if capture.location != NSNotFound, let swiftRange = Range(capture, in: value) {
                    captures.append(String(value[swiftRange]))
                }
            }
            return captures.isEmpty ? nil : captures.joined(separator: "\u{1f}")
        }
    }

    private static func firstXMLTagValue(_ tag: String, in value: String) -> String {
        let escaped = NSRegularExpression.escapedPattern(for: tag)
        let pattern = #"<(?:[A-Za-z0-9_.-]+:)?"# + escaped + #">\s*([^<\s][^<]*)\s*</(?:[A-Za-z0-9_.-]+:)?"# + escaped + #">"#
        return firstRegexGroups(pattern, in: value)?.first?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    }

    private static func xmlAttributes(_ value: String) -> [String: String] {
        guard let regex = try? NSRegularExpression(pattern: #"([A-Za-z_:][A-Za-z0-9_.:-]*)=["']([^"']+)["']"#) else {
            return [:]
        }
        let range = NSRange(value.startIndex..<value.endIndex, in: value)
        var attributes: [String: String] = [:]
        for match in regex.matches(in: value, range: range) {
            guard let keyRange = Range(match.range(at: 1), in: value),
                  let valueRange = Range(match.range(at: 2), in: value) else {
                continue
            }
            attributes[String(value[keyRange])] = String(value[valueRange])
        }
        return attributes
    }

    private static func lineNumber(of needle: String, in value: String) -> Int? {
        guard let range = value.range(of: needle) else {
            return nil
        }
        return value[..<range.lowerBound].filter { $0 == "\n" }.count + 1
    }

    private static func keyValue(_ value: String) -> (key: String, value: String)? {
        let parts = value.split(separator: "=", maxSplits: 1).map(String.init)
        guard parts.count == 2 else {
            return nil
        }
        return (
            parts[0].trimmingCharacters(in: .whitespacesAndNewlines),
            parts[1].trimmingCharacters(in: .whitespacesAndNewlines)
        )
    }

    private static func tomlValue(_ value: String) -> String {
        let stripped = stripInlineComment(value).trimmingCharacters(in: .whitespacesAndNewlines)
        if stripped.hasPrefix("["), stripped.hasSuffix("]") {
            return stripped.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        }
        return firstQuotedString(in: stripped) ?? stripQuotes(stripped)
    }

    private static func firstQuotedString(in value: String) -> String? {
        for quote in ["\"", "'"] {
            guard let start = value.firstIndex(of: Character(quote)) else {
                continue
            }
            let afterStart = value.index(after: start)
            guard let end = value[afterStart...].firstIndex(of: Character(quote)) else {
                continue
            }
            return String(value[afterStart..<end])
        }
        return nil
    }

    private static func stripQuotes(_ value: String) -> String {
        value.trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
    }

    private static func stripInlineComment(_ value: String) -> String {
        value.split(separator: "#", maxSplits: 1, omittingEmptySubsequences: false).first.map(String.init) ?? ""
    }

    private static func normalizePythonName(_ value: String) -> String {
        value
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
            .replacingOccurrences(of: #"[-_.]+"#, with: "-", options: .regularExpression)
    }

    private static func displayPath(_ file: URL, root: URL, targetName: String) -> String {
        let rootPath = root.standardizedFileURL.path
        let filePath = file.standardizedFileURL.path
        if filePath.hasPrefix(rootPath) {
            let rel = filePath.dropFirst(rootPath.count).trimmingCharacters(in: CharacterSet(charactersIn: "/"))
            return "\(targetName)/\(rel)"
        }
        return file.lastPathComponent
    }
}

private enum NativeOSVClient {
    static func queryFindings(components: [NativeDependencyComponent]) async throws -> [NativeFinding] {
        let queries = components.map { component in
            [
                "package": [
                    "name": component.name,
                    "ecosystem": component.ecosystem,
                ],
                "version": component.version,
            ] as [String: Any]
        }
        let body = try JSONSerialization.data(withJSONObject: ["queries": queries])
        var request = URLRequest(url: URL(string: "https://api.osv.dev/v1/querybatch")!)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = body

        let (data, response) = try await URLSession.shared.data(for: request)
        if let http = response as? HTTPURLResponse, http.statusCode >= 400 {
            throw NSError(domain: "KODA.OSV", code: http.statusCode, userInfo: [NSLocalizedDescriptionKey: "OSV returned HTTP \(http.statusCode)"])
        }
        guard let payload = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let results = payload["results"] as? [[String: Any]] else {
            return []
        }

        var pending: [(NativeDependencyComponent, [String: Any], [String])] = []
        var discoveredCVEIDs = Set<String>()
        for (index, result) in results.enumerated() {
            guard index < components.count,
                  let vulns = result["vulns"] as? [[String: Any]] else {
                continue
            }
            let component = components[index]
            for vuln in vulns {
                let vulnCVEs = cveIDs(from: vuln)
                discoveredCVEIDs.formUnion(vulnCVEs)
                pending.append((component, vuln, vulnCVEs))
            }
        }
        let intel = (try? await NativeVulnerabilityIntelClient.query(cveIDs: Array(discoveredCVEIDs))) ?? [:]
        return pending.map { item in
            finding(component: item.0, vulnerability: item.1, cveIDs: item.2, intel: intel)
        }
    }

    private static func finding(
        component: NativeDependencyComponent,
        vulnerability: [String: Any],
        cveIDs: [String],
        intel: [String: NativeVulnerabilityIntel]
    ) -> NativeFinding {
        let id = vulnerability["id"] as? String ?? "OSV"
        let summary = vulnerability["summary"] as? String
        let aliases = (vulnerability["aliases"] as? [String] ?? []).prefix(4).joined(separator: ", ")
        let severity = prioritizedSeverity(base: severityLabel(vulnerability), cveIDs: cveIDs, intel: intel)
        let intelSummary = NativeVulnerabilityIntelClient.summary(cveIDs: cveIDs, intel: intel)
        let evidence = "\(component.ecosystem) \(component.name)@\(component.version): \(id)\(aliases.isEmpty ? "" : " | \(aliases)")\(intelSummary.isEmpty ? "" : " | \(intelSummary)")"
        return NativeFinding(
            ruleID: "dependency.osv-known-vulnerability",
            severity: severity,
            category: "dependencies",
            title: summary?.prefix(120).description ?? "OSV에 보고된 알려진 취약 의존성",
            path: component.path,
            line: component.line,
            evidence: evidence,
            recommendation: recommendation(id: id, cveIDs: cveIDs, intel: intel)
        )
    }

    private static func cveIDs(from vulnerability: [String: Any]) -> [String] {
        var values = [vulnerability["id"] as? String ?? ""]
        values.append(contentsOf: vulnerability["aliases"] as? [String] ?? [])
        return NativeVulnerabilityIntelClient.extractCVEIDs(from: values.joined(separator: " "))
    }

    private static func prioritizedSeverity(base: String, cveIDs: [String], intel: [String: NativeVulnerabilityIntel]) -> String {
        if cveIDs.contains(where: { intel[$0]?.isKEV == true }) {
            return "critical"
        }
        if cveIDs.contains(where: { item in
            guard let intel = intel[item] else { return false }
            return (intel.epss ?? 0) >= 0.5 || (intel.percentile ?? 0) >= 0.95
        }) {
            return maxSeverity(base, "high")
        }
        return base
    }

    private static func recommendation(id: String, cveIDs: [String], intel: [String: NativeVulnerabilityIntel]) -> String {
        let prioritized = cveIDs.compactMap { intel[$0] }.filter { !$0.priorityLabel.isEmpty }
        let url = "https://osv.dev/vulnerability/\(id)"
        if prioritized.isEmpty {
            return "OSV 상세 페이지를 확인한 뒤 업그레이드, 패치, 대체, 또는 보완 통제를 문서화하세요."
        }
        let labels = prioritized.prefix(3).map { "\($0.cve) \($0.priorityLabel)" }.joined(separator: ", ")
        return "\(labels) 항목이므로 우선 조치하세요. \(url)을 확인한 뒤 업그레이드, 패치, 대체 또는 보완 통제를 문서화하세요."
    }

    private static func maxSeverity(_ left: String, _ right: String) -> String {
        let rank = ["info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4]
        return (rank[left] ?? 0) >= (rank[right] ?? 0) ? left : right
    }

    private static func severityLabel(_ vulnerability: [String: Any]) -> String {
        if let database = vulnerability["database_specific"] as? [String: Any],
           let severity = database["severity"] as? String {
            return normalizeSeverity(severity)
        }
        if let severityItems = vulnerability["severity"] as? [[String: Any]] {
            for item in severityItems {
                if let score = item["score"] as? String, let label = cvssSeverity(score) {
                    return label
                }
            }
        }
        return "high"
    }

    private static func normalizeSeverity(_ severity: String) -> String {
        switch severity.lowercased() {
        case "critical": return "critical"
        case "high": return "high"
        case "medium", "moderate": return "medium"
        case "low": return "low"
        default: return "high"
        }
    }

    private static func cvssSeverity(_ scoreText: String) -> String? {
        for token in scoreText.replacingOccurrences(of: "/", with: " ").split(separator: " ") {
            if let score = Double(token) {
                if score >= 9 { return "critical" }
                if score >= 7 { return "high" }
                if score >= 4 { return "medium" }
                if score > 0 { return "low" }
            }
        }
        return nil
    }
}

private struct NativeVulnerabilityIntel {
    let cve: String
    var isKEV: Bool = false
    var dueDate: String = ""
    var ransomware: String = ""
    var epss: Double?
    var percentile: Double?
    var epssDate: String = ""

    var priorityLabel: String {
        if isKEV { return "CISA KEV" }
        if let epss, epss >= 0.5 { return "high EPSS" }
        if let percentile, percentile >= 0.95 { return "top EPSS percentile" }
        return ""
    }
}

private enum NativeVulnerabilityIntelClient {
    private static let cisaKEVURL = URL(string: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")!
    private static let epssBaseURL = "https://api.first.org/data/v1/epss"

    static func query(cveIDs: [String]) async throws -> [String: NativeVulnerabilityIntel] {
        let cves = Array(Set(cveIDs.filter { !$0.isEmpty })).sorted()
        guard !cves.isEmpty else { return [:] }

        var output = Dictionary(uniqueKeysWithValues: cves.map { ($0, NativeVulnerabilityIntel(cve: $0)) })
        if let kev = try? await fetchKEV() {
            for cve in cves {
                guard let entry = kev[cve] else { continue }
                var item = output[cve] ?? NativeVulnerabilityIntel(cve: cve)
                item.isKEV = true
                item.dueDate = entry["dueDate"] as? String ?? ""
                item.ransomware = entry["knownRansomwareCampaignUse"] as? String ?? ""
                output[cve] = item
            }
        }
        if let epss = try? await fetchEPSS(cveIDs: cves) {
            for cve in cves {
                guard let entry = epss[cve] else { continue }
                var item = output[cve] ?? NativeVulnerabilityIntel(cve: cve)
                item.epss = doubleValue(entry["epss"])
                item.percentile = doubleValue(entry["percentile"])
                item.epssDate = entry["date"] as? String ?? ""
                output[cve] = item
            }
        }
        return output
    }

    static func extractCVEIDs(from text: String) -> [String] {
        guard let regex = try? NSRegularExpression(pattern: #"CVE-\d{4}-\d{4,}"#, options: [.caseInsensitive]) else {
            return []
        }
        let range = NSRange(text.startIndex..<text.endIndex, in: text)
        let values = regex.matches(in: text, range: range).compactMap { match -> String? in
            guard let swiftRange = Range(match.range, in: text) else { return nil }
            return text[swiftRange].uppercased()
        }
        return Array(Set(values)).sorted()
    }

    static func summary(cveIDs: [String], intel: [String: NativeVulnerabilityIntel]) -> String {
        cveIDs.compactMap { cve in
            guard let item = intel[cve] else { return nil }
            if item.isKEV {
                let due = item.dueDate.isEmpty ? "" : ", due \(item.dueDate)"
                let ransomware = item.ransomware.isEmpty ? "" : ", ransomware \(item.ransomware)"
                return "\(item.cve): CISA KEV\(due)\(ransomware)"
            }
            if let epss = item.epss {
                let percentile = item.percentile.map { ", percentile \(percent($0))" } ?? ""
                let date = item.epssDate.isEmpty ? "" : ", \(item.epssDate)"
                return "\(item.cve): EPSS \(percent(epss))\(percentile)\(date)"
            }
            return nil
        }
        .joined(separator: "; ")
    }

    private static func fetchKEV() async throws -> [String: [String: Any]] {
        let (data, response) = try await URLSession.shared.data(from: cisaKEVURL)
        if let http = response as? HTTPURLResponse, http.statusCode >= 400 {
            throw NSError(domain: "KODA.KEV", code: http.statusCode, userInfo: [NSLocalizedDescriptionKey: "CISA KEV returned HTTP \(http.statusCode)"])
        }
        guard let payload = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let vulnerabilities = payload["vulnerabilities"] as? [[String: Any]] else {
            return [:]
        }
        var output: [String: [String: Any]] = [:]
        for item in vulnerabilities {
            guard let cve = item["cveID"] as? String else { continue }
            output[cve.uppercased()] = item
        }
        return output
    }

    private static func fetchEPSS(cveIDs: [String]) async throws -> [String: [String: Any]] {
        var output: [String: [String: Any]] = [:]
        for chunk in chunks(cveIDs, maxCharacters: 1800) {
            var components = URLComponents(string: epssBaseURL)!
            components.queryItems = [URLQueryItem(name: "cve", value: chunk.joined(separator: ","))]
            guard let url = components.url else { continue }
            let (data, response) = try await URLSession.shared.data(from: url)
            if let http = response as? HTTPURLResponse, http.statusCode >= 400 {
                throw NSError(domain: "KODA.EPSS", code: http.statusCode, userInfo: [NSLocalizedDescriptionKey: "FIRST EPSS returned HTTP \(http.statusCode)"])
            }
            guard let payload = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let rows = payload["data"] as? [[String: Any]] else {
                continue
            }
            for item in rows {
                guard let cve = item["cve"] as? String else { continue }
                output[cve.uppercased()] = item
            }
        }
        return output
    }

    private static func chunks(_ cves: [String], maxCharacters: Int) -> [[String]] {
        var chunks: [[String]] = []
        var current: [String] = []
        var length = 0
        for cve in cves {
            let addition = cve.count + (current.isEmpty ? 0 : 1)
            if !current.isEmpty && length + addition > maxCharacters {
                chunks.append(current)
                current = []
                length = 0
            }
            current.append(cve)
            length += addition
        }
        if !current.isEmpty {
            chunks.append(current)
        }
        return chunks
    }

    private static func doubleValue(_ value: Any?) -> Double? {
        if let number = value as? Double { return number }
        if let string = value as? String { return Double(string) }
        return nil
    }

    private static func percent(_ value: Double) -> String {
        String(format: "%.1f%%", value * 100)
    }
}

private enum NativeVEXDocument {
    static func render(findings: [NativeFinding]) throws -> String {
        let vulnerabilities = findings.compactMap(vulnerabilityPayload)
        let payload: [String: Any] = [
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": "urn:uuid:\(UUID().uuidString)",
            "version": 1,
            "metadata": [
                "timestamp": ISO8601DateFormatter().string(from: Date()),
                "tools": [
                    "components": [
                        [
                            "type": "application",
                            "name": "KODA",
                            "version": "0.1.0",
                        ],
                    ],
                ],
            ],
            "vulnerabilities": vulnerabilities,
        ]
        let data = try JSONSerialization.data(withJSONObject: payload, options: [.prettyPrinted, .sortedKeys])
        return String(decoding: data, as: UTF8.self)
    }

    private static func vulnerabilityPayload(_ finding: NativeFinding) -> [String: Any]? {
        guard finding.ruleID == "dependency.osv-known-vulnerability" else {
            return nil
        }
        let ids = NativeVulnerabilityIntelClient.extractCVEIDs(from: "\(finding.title) \(finding.evidence)")
        let vulnerabilityID = ids.first ?? osvID(from: finding.evidence)
        guard !vulnerabilityID.isEmpty else {
            return nil
        }
        return [
            "id": vulnerabilityID,
            "source": ["name": "KODA OSV lookup"],
            "ratings": [["severity": finding.severity]],
            "analysis": [
                "state": "in_triage",
                "detail": "KODA generated this VEX entry as a review placeholder. Confirm exploitability before marking affected, not_affected, or resolved.",
            ],
            "affects": [
                [
                    "ref": componentRef(from: finding),
                ],
            ],
            "properties": [
                ["name": "koda:rule_id", "value": finding.ruleID],
                ["name": "koda:path", "value": finding.path],
            ],
        ]
    }

    private static func osvID(from evidence: String) -> String {
        guard let colon = evidence.firstIndex(of: ":") else {
            return ""
        }
        return evidence[evidence.index(after: colon)...]
            .split(separator: " ")
            .first
            .map { String($0).trimmingCharacters(in: CharacterSet(charactersIn: "(),;")) } ?? ""
    }

    private static func componentRef(from finding: NativeFinding) -> String {
        let prefix = finding.evidence.split(separator: ":", maxSplits: 1).first.map(String.init) ?? ""
        let parts = prefix.split(separator: " ", maxSplits: 1).map(String.init)
        guard parts.count == 2, let marker = parts[1].lastIndex(of: "@") else {
            return finding.path
        }
        let ecosystem = parts[0]
        let name = String(parts[1][..<marker])
        let version = String(parts[1][parts[1].index(after: marker)...])
        if ecosystem == "npm" {
            return "pkg:npm/\(name)@\(version)"
        }
        if ecosystem == "PyPI" {
            return "pkg:pypi/\(name.lowercased())@\(version)"
        }
        return "\(ecosystem):\(name)@\(version)"
    }
}

private struct ToolkitApplyResult {
    let targetCount: Int
    let writtenCount: Int
    let skippedCount: Int
    let failures: [String]

    func detail(language: AppLanguage) -> String {
        let base: String
        switch language {
        case .ko:
            base = "적용 폴더 \(targetCount)개, 새로 생성 \(writtenCount)개, 기존 파일 유지 \(skippedCount)개"
        case .en:
            base = "Folders \(targetCount), newly written \(writtenCount), existing files kept \(skippedCount)"
        }

        guard !failures.isEmpty else {
            return base
        }

        let limitedFailures = failures.prefix(3).joined(separator: "\n")
        let moreCount = failures.count - min(failures.count, 3)
        let suffix: String
        if moreCount > 0 {
            suffix = language == .ko ? "\n외 \(moreCount)건" : "\nAnd \(moreCount) more"
        } else {
            suffix = ""
        }
        return "\(base)\n\(limitedFailures)\(suffix)"
    }
}

private struct SecurityPreventionTemplateWrite {
    enum Status {
        case written
        case skipped
    }

    let relativePath: String
    let status: Status
}

private enum SecurityPreventionToolkitError: LocalizedError {
    case targetIsNotDirectory(String)

    var errorDescription: String? {
        switch self {
        case .targetIsNotDirectory(let path):
            return "Target is not a directory: \(path)"
        }
    }
}

private enum SecurityPreventionToolkit {
    static func write(to root: URL, force: Bool = false) throws -> [SecurityPreventionTemplateWrite] {
        let fileManager = FileManager.default
        var isDirectory = ObjCBool(false)
        guard fileManager.fileExists(atPath: root.path, isDirectory: &isDirectory), isDirectory.boolValue else {
            throw SecurityPreventionToolkitError.targetIsNotDirectory(root.path)
        }

        var results: [SecurityPreventionTemplateWrite] = []
        let projectName = root.lastPathComponent.isEmpty ? "KODA Project" : root.lastPathComponent
        for template in templateFiles(projectName: projectName) {
            let destination = root.appendingPathComponent(template.relativePath)
            if fileManager.fileExists(atPath: destination.path), !force {
                results.append(SecurityPreventionTemplateWrite(relativePath: template.relativePath, status: .skipped))
                continue
            }

            let parent = destination.deletingLastPathComponent()
            try fileManager.createDirectory(at: parent, withIntermediateDirectories: true)
            try template.content.write(to: destination, atomically: true, encoding: .utf8)
            results.append(SecurityPreventionTemplateWrite(relativePath: template.relativePath, status: .written))
        }
        return results
    }

    static func markdown(projectName: String, language: AppLanguage) -> String {
        switch language {
        case .ko:
            return korean(projectName: projectName)
        case .en:
            return english(projectName: projectName)
        }
    }

    fileprivate static func templateFiles(projectName: String) -> [(relativePath: String, content: String)] {
        [
            ("SECURITY.md", securityPolicy(projectName: projectName)),
            (".github/dependabot.yml", dependabotConfig()),
            (".github/workflows/koda-security.yml", githubSecurityWorkflow()),
            (".github/workflows/koda-release-provenance.yml", releaseProvenanceWorkflow()),
            (".github/CODEOWNERS", codeowners()),
            (".dockerignore", dockerignore()),
            (".env.example", envExample()),
            ("docs/security/PRE_COMMIT.md", preCommitGuide()),
            ("docs/security/GITHUB_REPOSITORY_SECURITY.md", repositorySecurityChecklist(projectName: projectName)),
            ("docs/security/ZAP_BASELINE.md", zapBaselineGuide()),
            ("docs/security/DEPENDENCY_TRACK.md", dependencyTrackGuide(projectName: projectName)),
            ("docs/security/VEX.md", vexGuide()),
            ("docs/security/SLSA_SIGSTORE.md", slsaSigstoreGuide()),
            ("docs/security/NIST_SSDF_WORKFLOW.md", ssdfWorkflowPlan(projectName: projectName)),
            ("docs/security/SECURE_BY_DESIGN.md", secureByDesignPlan(projectName: projectName)),
            ("docs/security/THREAT_MODEL.md", threatModelTemplate(projectName: projectName)),
            ("docs/security/SECRET_ROTATION.md", secretRotationRunbook(projectName: projectName)),
            ("docs/security/AI_LLM_SECURITY.md", aiLLMSecurityPlan(projectName: projectName)),
            ("docs/security/MOBILE_SECURITY.md", mobileSecurityPlan(projectName: projectName)),
            ("docs/security/NIST_CSF_2_PROFILE.md", nistCSFProfile(projectName: projectName)),
            ("docs/security/CISA_SECURE_SOFTWARE_ATTESTATION.md", cisaAttestationChecklist(projectName: projectName)),
            ("docs/security/API_SECURITY.md", apiSecurityPlan(projectName: projectName)),
            ("docs/security/SCVS_PLAN.md", scvsPlan(projectName: projectName)),
            ("docs/security/PRIVACY_DATA_MAP.md", privacyDataMap(projectName: projectName)),
            ("docs/security/SECURITY_ROADMAP.md", securityRoadmap(projectName: projectName)),
            ("docs/security/EVIDENCE_REGISTER.md", evidenceRegister(projectName: projectName)),
            ("docs/security/SECURITY_HEADERS.md", securityHeadersBaseline(projectName: projectName)),
            ("docs/security/CONTAINER_HARDENING.md", containerHardeningBaseline(projectName: projectName)),
            ("docs/security/CLOUD_IAC_SECURITY.md", cloudIACSecurityPlan(projectName: projectName)),
        ]
    }

    private static func securityPolicy(projectName: String) -> String {
        """
        # Security Policy

        ## Supported Versions

        | Version | Supported |
        | --- | --- |
        | main / latest | yes |

        ## Reporting a Vulnerability

        Please report suspected vulnerabilities privately before opening a public issue.

        - Project: \(projectName)
        - Contact: security@example.com
        - Expected first response: 3 business days
        - Expected status update: 7 business days

        ## Handling

        1. Confirm the report and assign an owner.
        2. Reproduce the issue in a private branch or isolated environment.
        3. Patch, test, and release the fix.
        4. Rotate exposed credentials when secrets are involved.
        5. Publish an advisory or release note after users have a remediation path.
        """
    }

    private static func dependabotConfig() -> String {
        """
        version: 2
        updates:
          - package-ecosystem: "npm"
            directory: "/"
            schedule:
              interval: "weekly"
          - package-ecosystem: "pip"
            directory: "/"
            schedule:
              interval: "weekly"
          - package-ecosystem: "github-actions"
            directory: "/"
            schedule:
              interval: "weekly"
        """
    }

    private static func githubSecurityWorkflow() -> String {
        """
        name: KODA Security

        on:
          pull_request:
          push:
            branches: [main]
          schedule:
            - cron: "0 18 * * 1"

        permissions:
          contents: read

        jobs:
          local-security-scan:
            runs-on: ubuntu-latest
            permissions:
              contents: read
              security-events: write
            steps:
              - uses: actions/checkout@v4
              - uses: actions/setup-python@v5
                with:
                  python-version: "3.12"
              - name: Install KODA scanner
                run: python -m pip install "git+https://github.com/jhny-kor/sec-chk.git"
              - name: Run KODA local scan
                run: |
                  python -m security_scanner scan --target . --format sarif --output koda-results.sarif --enable-osv --enable-vuln-intel
                  python -m security_scanner scan --target . --format cyclonedx --output koda-sbom.cdx.json
              - name: Upload SARIF
                uses: github/codeql-action/upload-sarif@v3
                with:
                  sarif_file: koda-results.sarif
              - name: Upload SBOM artifact
                uses: actions/upload-artifact@v4
                with:
                  name: koda-sbom
                  path: koda-sbom.cdx.json

          openssf-scorecard:
            runs-on: ubuntu-latest
            permissions:
              contents: read
              security-events: write
              id-token: write
            steps:
              - uses: actions/checkout@v4
              - uses: ossf/scorecard-action@v2.4.0
                with:
                  results_file: scorecard-results.sarif
                  results_format: sarif
                  publish_results: true
              - uses: github/codeql-action/upload-sarif@v3
                with:
                  sarif_file: scorecard-results.sarif
        """
    }

    private static func releaseProvenanceWorkflow() -> String {
        """
        name: KODA Release Provenance

        on:
          workflow_dispatch:
          release:
            types: [published]

        permissions:
          contents: read
          id-token: write

        jobs:
          release-provenance:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
              - name: Build release artifacts
                run: |
                  mkdir -p dist
                  tar --exclude .git --exclude dist -czf dist/source-release.tar.gz .
              - name: Generate checksums
                run: sha256sum dist/* > dist/checksums.txt
              - name: Install cosign
                uses: sigstore/cosign-installer@v3
              - name: Sign artifacts with Sigstore
                run: |
                  for artifact in dist/*; do
                    [ -f "$artifact" ] || continue
                    cosign sign-blob "$artifact" --bundle "$artifact.sigstore.json" --yes
                  done
        """
    }

    private static func codeowners() -> String {
        """
        # Adjust owners before committing.
        * @security-team
        /.github/ @security-team
        /security_scanner/ @security-team
        /docs/security/ @security-team
        /SECURITY.md @security-team
        """
    }

    private static func dockerignore() -> String {
        """
        .git
        .github
        .env
        .env.*
        !.env.example
        node_modules
        dist
        build
        coverage
        reports
        *.pem
        *.key
        *.p12
        *.pfx
        """
    }

    private static func envExample() -> String {
        """
        # Copy to .env locally and fill real values outside the repository.
        APP_ENV=development
        LOG_LEVEL=info
        """
    }

    private static func preCommitGuide() -> String {
        """
        # KODA Pre-Commit Security Gate

        Install the KODA pre-commit hook from the app or CLI to stop high-risk findings before they enter Git history.

        ```bash
        python -m security_scanner install-hook --target . --fail-on high
        ```

        Environment variables:

        - KODA_PRE_COMMIT_FAIL_ON: critical, high, medium, low, or info
        - KODA_PRE_COMMIT_TARGET: target path, default `.`
        """
    }

    fileprivate static func repositorySecurityChecklist(projectName: String) -> String {
        """
        # GitHub Repository Security Checklist

        Project: \(projectName)

        ## Branch And Review Protection

        - [ ] Protect the default branch.
        - [ ] Require pull requests before merge.
        - [ ] Require at least one approving review.
        - [ ] Require KODA/SAST status checks before merge.
        - [ ] Require CODEOWNERS review for security-sensitive paths.

        ## Secret And Dependency Protection

        - [ ] Enable secret scanning and push protection.
        - [ ] Enable Dependabot alerts and security updates.
        - [ ] Upload SARIF from KODA, CodeQL, Semgrep, or equivalent tools.
        - [ ] Keep Actions token permissions read-only by default.
        """
    }

    private static func zapBaselineGuide() -> String {
        """
        # ZAP Baseline

        Use this only against systems you own or are authorized to test.

        The KODA app can prepare local prevention files. ZAP itself runs against a live URL through the official ZAP Docker image, so run it only after confirming the target is authorized.

        ```bash
        python -m security_scanner zap-command --url https://example.com --output-dir reports/zap
        ```
        """
    }

    private static func dependencyTrackGuide(projectName: String) -> String {
        """
        # Dependency-Track SBOM Upload

        Generate a CycloneDX SBOM from KODA, then upload it to your Dependency-Track server.

        ```bash
        python -m security_scanner scan --target . --format cyclonedx --output reports/sbom.cdx.json
        python -m security_scanner upload-sbom \\
          --server-url https://dependency-track.example.com \\
          --api-key-env DEPENDENCY_TRACK_API_KEY \\
          --project-name "\(projectName)" \\
          --project-version main \\
          --sbom reports/sbom.cdx.json \\
          --auto-create
        ```
        """
    }

    private static func vexGuide() -> String {
        """
        # VEX Tracking

        Use VEX to record reviewed dependency vulnerabilities after OSV, Dependency-Track, or another advisory source reports a CVE.

        Create docs/security/vex.cdx.json or another CycloneDX/OpenVEX document with the component, vulnerability ID, status, impact statement, and review date.

        KODA treats VEX as a prevention artifact. It does not automatically mark a vulnerability as safe.
        """
    }

    private static func slsaSigstoreGuide() -> String {
        """
        # SLSA and Sigstore Release Guardrails

        For release builds, generate provenance and sign artifacts before publishing:

        1. Build release artifacts in CI.
        2. Generate SLSA provenance or an equivalent attestation.
        3. Sign artifacts with Sigstore/cosign or your signing system.
        4. Publish checksums, signatures, and provenance next to the release.
        5. Keep GitHub Actions permissions read-only by default.
        """
    }

    fileprivate static func releaseSigningPlan(projectName: String) -> String {
        """
        # SLSA / Sigstore Release Signing Plan

        Project: \(projectName)

        ## Goal

        Build release artifacts in CI, generate provenance, sign artifacts with Sigstore/cosign or your signing system, and publish verification material next to the release.

        ## Local Commands For Dry Run

        ```bash
        sha256sum "dist/app.tar.gz" > "dist/app.tar.gz.sha256"
        cosign sign-blob "dist/app.tar.gz" --bundle "dist/app.tar.gz.sigstore.json" --yes
        cosign verify-blob "dist/app.tar.gz" --bundle "dist/app.tar.gz.sigstore.json" --certificate-identity-regexp ".*" --certificate-oidc-issuer-regexp ".*"
        ```

        ## CI Requirements

        - [ ] Build artifacts in CI from the release tag.
        - [ ] Generate SLSA provenance or an equivalent attestation.
        - [ ] Sign the artifact or container digest.
        - [ ] Publish checksum, signature bundle, and provenance.
        - [ ] Verify the published artifact from a clean environment before release announcement.
        """
    }

    fileprivate static func ssdfWorkflowPlan(projectName: String) -> String {
        """
        # NIST SSDF Workflow

        Project: \(projectName)

        ## Prepare The Organization

        - [ ] Define secure-development roles and owners.
        - [ ] Keep SECURITY.md, CODEOWNERS, and exception policy current.
        - [ ] Train contributors on secrets, dependency hygiene, and secure defaults.

        ## Protect The Software

        - [ ] Keep source access least-privilege.
        - [ ] Block secrets and high-risk findings before commit.
        - [ ] Generate SBOMs for release builds.
        - [ ] Sign release artifacts and preserve provenance.

        ## Produce Well-Secured Software

        - [ ] Run KODA, SAST, and dependency checks on pull requests.
        - [ ] Use secure defaults for configuration, cookies, CORS, containers, and CI tokens.
        - [ ] Keep dependency update automation enabled.

        ## Respond To Vulnerabilities

        - [ ] Triage OSV/CVE findings with KEV/EPSS context.
        - [ ] Record reviewed dependency findings in VEX.
        - [ ] Re-run KODA and compare score history after remediation.
        """
    }

    fileprivate static func secureByDesignPlan(projectName: String) -> String {
        """
        # CISA Secure by Design Plan

        Project: \(projectName)

        ## Take Ownership Of Customer Security Outcomes

        - [ ] Treat exposed secrets, unsafe defaults, and known exploited vulnerabilities as customer-impacting defects.
        - [ ] Provide secure defaults for auth, sessions, logging, CORS, and deployment configuration.
        - [ ] Keep a security contact and vulnerability handling process visible.

        ## Embrace Radical Transparency And Accountability

        - [ ] Publish security policy, supported versions, and remediation expectations.
        - [ ] Keep SBOM and VEX artifacts for releases.
        - [ ] Record known limitations, accepted risks, and exception expiry dates.
        - [ ] Track score history and severity deltas after each release.

        ## Lead From The Top

        - [ ] Assign owners for product security outcomes.
        - [ ] Review Secure by Design metrics regularly.
        - [ ] Require security gates before merge and release.
        """
    }

    fileprivate static func threatModelTemplate(projectName: String) -> String {
        """
        # Threat Model

        Project: \(projectName)

        ## Scope

        - [ ] Product or service boundary:
        - [ ] In-scope repositories, apps, APIs, workers, and admin tools:
        - [ ] Out-of-scope systems:

        ## Assets

        | Asset | Sensitivity | Owner | Storage/Transit |
        | --- | --- | --- | --- |
        | Customer data | high | TBD | TBD |
        | Secrets and tokens | critical | TBD | secret manager / environment |
        | Build and release artifacts | high | TBD | CI/release storage |

        ## Trust Boundaries

        - [ ] Browser/mobile client to backend API
        - [ ] Backend to database/cache/object storage
        - [ ] CI runner to package registries and release storage
        - [ ] Admin/operator access to production systems
        - [ ] AI/LLM provider, tool, or retrieval boundary when used

        ## Abuse Cases

        - [ ] Unauthorized access to user/admin function
        - [ ] Secret leak through repository, logs, prompt, or artifact
        - [ ] Dependency or CI supply-chain compromise
        - [ ] File upload/download path manipulation
        - [ ] Prompt injection or over-privileged agent action when AI is used
        """
    }

    fileprivate static func secretRotationRunbook(projectName: String) -> String {
        """
        # Secret Rotation Runbook

        Project: \(projectName)

        ## Immediate Response

        - [ ] Identify the secret owner and affected service.
        - [ ] Revoke or disable the exposed value.
        - [ ] Issue a replacement secret through the approved secret manager.
        - [ ] Deploy the replacement without writing it to source control.
        - [ ] Re-run KODA and provider-side secret scanning.

        ## Audit

        - [ ] Review provider logs from the first possible exposure time.
        - [ ] Check CI logs, issue attachments, release artifacts, and chat copies.
        - [ ] Record owner, incident ticket, timeline, and final disposition.
        """
    }

    fileprivate static func aiLLMSecurityPlan(projectName: String) -> String {
        """
        # AI / LLM Security Plan

        Project: \(projectName)

        ## Inventory

        | Use case | Model/provider | Data sent | Tools/actions | Owner |
        | --- | --- | --- | --- | --- |
        | TBD | TBD | TBD | TBD | TBD |

        ## OWASP LLM Top 10 Controls

        - [ ] LLM01 Prompt Injection: user and retrieved content are separated from system/developer instructions.
        - [ ] LLM02 Sensitive Information Disclosure: prompts and logs redact credentials, tokens, PII, and customer secrets.
        - [ ] LLM03 Supply Chain: model, SDK, plugin, and retrieval dependencies are inventoried and reviewed.
        - [ ] LLM05 Improper Output Handling: model output is validated before HTML, shell, SQL, file, or API use.
        - [ ] LLM06 Excessive Agency: tools are allowlisted, scoped, logged, and require confirmation for side effects.
        - [ ] LLM08 Vector and Embedding Weaknesses: retrieval sources are trusted, access-controlled, and poison-resistant.

        ## Tests

        - [ ] Prompt injection fixtures cover direct and indirect input.
        - [ ] Tool calls reject path traversal, network abuse, and unauthorized destructive actions.
        - [ ] Sensitive data canary values are not returned by the model or stored in logs.
        """
    }

    fileprivate static func mobileSecurityPlan(projectName: String) -> String {
        """
        # Mobile Security Plan

        Project: \(projectName)

        ## OWASP MASVS Coverage

        - [ ] MASVS-STORAGE: local storage, backups, keychain/keystore, and cached files reviewed.
        - [ ] MASVS-CRYPTO: approved crypto and key handling used.
        - [ ] MASVS-AUTH: authentication, session, biometric, and authorization flows tested.
        - [ ] MASVS-NETWORK: TLS/ATS/network security config reviewed; cleartext traffic disabled.
        - [ ] MASVS-PLATFORM: exported Android components and iOS document sharing reviewed.
        - [ ] MASVS-CODE: debug flags, logging, injection, file handling, and dependency hygiene checked.
        - [ ] MASVS-RESILIENCE: release signing, debug builds, and tamper expectations documented.
        - [ ] MASVS-PRIVACY: personal data collection, retention, prompts, analytics, and logs reviewed.
        """
    }

    fileprivate static func nistCSFProfile(projectName: String) -> String {
        """
        # NIST CSF 2.0 Profile

        Project: \(projectName)

        - [ ] Govern: risk owners, policy, exception handling, and review cadence are documented.
        - [ ] Identify: repositories, services, dependency manifests, SBOM, data stores, and critical assets are inventoried.
        - [ ] Protect: secrets, authentication, session, container, mobile, AI, and CI settings have secure defaults.
        - [ ] Detect: KODA/SAST/dependency scans run on pull requests or release branches.
        - [ ] Respond: vulnerability reports, OSV/CVE findings, secret leaks, and DAST findings have owners and due dates.
        - [ ] Recover: release packages include checksums, SBOM, VEX, scan reports, and signing/provenance evidence.
        """
    }

    fileprivate static func cisaAttestationChecklist(projectName: String) -> String {
        """
        # CISA Secure Software Development Attestation Checklist

        Project: \(projectName)

        ## Secure Development Environment

        - [ ] Source access is least-privilege and reviewed.
        - [ ] Branch protection, required review, CODEOWNERS, and CI gates are configured.
        - [ ] Secrets are not stored in source and have rotation procedures.

        ## Secure Development Practices

        - [ ] Threat modeling is performed for significant features.
        - [ ] Secure coding checks run locally or in CI.
        - [ ] Security-relevant exceptions have owner, reason, and expiry.

        ## Third-Party Components

        - [ ] Dependencies are inventoried with SBOM.
        - [ ] Versions are pinned where practical.
        - [ ] Known vulnerabilities are triaged and VEX decisions are recorded.

        ## Verification And Response

        - [ ] SAST, dependency, secret, and configuration checks are run before release.
        - [ ] DAST or penetration testing is scheduled when runtime behavior matters.
        - [ ] Vulnerability reporting, remediation, and release-note/advisory processes are documented.
        """
    }

    fileprivate static func apiSecurityPlan(projectName: String) -> String {
        """
        # API Security Plan

        Project: \(projectName)

        ## Inventory

        | API | Version | Auth Required | Data Class | Owner |
        | --- | --- | --- | --- | --- |
        | TBD | /api/v1 | yes | TBD | TBD |

        ## Controls

        - [ ] Object-level authorization is checked for every user-controlled object ID.
        - [ ] Function-level authorization is explicit for admin, payment, account, and profile routes.
        - [ ] Request body schemas reject unknown properties to prevent mass assignment.
        - [ ] Rate limits and quotas cover login, signup, password reset, search, export, and high-cost APIs.
        - [ ] Outbound API calls use allowlisted destinations, timeouts, retry limits, and SSRF protections.
        - [ ] API versions, deprecation dates, and owners are documented.
        """
    }

    fileprivate static func scvsPlan(projectName: String) -> String {
        """
        # OWASP SCVS Plan

        Project: \(projectName)

        - [ ] V1 Inventory: source, package, container, plugin, model, and generated components are inventoried.
        - [ ] V2 SBOM: CycloneDX or SPDX SBOM is generated and retained for release builds.
        - [ ] V3 Build Environment: CI runners are least-privilege and build from protected refs.
        - [ ] V4 Package Management: lockfiles are committed and approved registries are used.
        - [ ] V5 Component Analysis: OSV/CVE, KEV/EPSS, and dependency scan results are triaged.
        - [ ] V6 Pedigree and Provenance: release artifacts are built in CI, checksummed, signed, and linked to provenance.
        """
    }

    fileprivate static func privacyDataMap(projectName: String) -> String {
        """
        # Privacy Data Map

        Project: \(projectName)

        | Field | Category | Purpose | Storage | Retention | Sharing | Owner |
        | --- | --- | --- | --- | --- | --- | --- |
        | email | personal data | account/contact | TBD | TBD | TBD | TBD |

        - [ ] Personal data is not logged in raw form.
        - [ ] Test fixtures and demo data avoid real personal data.
        - [ ] Retention and deletion behavior is documented.
        - [ ] Analytics, AI/LLM prompts, crash reports, and support exports are reviewed for personal data.
        """
    }

    fileprivate static func securityRoadmap(projectName: String) -> String {
        """
        # Security Roadmap

        Project: \(projectName)

        | Priority | Work Item | Standard | Owner | Due Date | Status | Evidence |
        | --- | --- | --- | --- | --- | --- | --- |
        | P1 | Remove critical/high KODA findings | Local / OWASP | TBD | TBD | planned | reports/ |
        | P1 | Complete threat model and API inventory | OWASP API / ASVS | TBD | TBD | planned | docs/security/ |
        | P2 | Complete SCVS supply-chain evidence | OWASP SCVS | TBD | TBD | planned | release package |
        """
    }

    fileprivate static func evidenceRegister(projectName: String) -> String {
        """
        # Security Evidence Register

        Project: \(projectName)

        | Evidence | Standard | Location | Owner | Review Date | Notes |
        | --- | --- | --- | --- | --- | --- |
        | KODA scan report | Local / OWASP / CWE | reports/security-dashboard.html | TBD | TBD | TBD |
        | SBOM | SCVS / SSDF | reports/sbom.cdx.json | TBD | TBD | TBD |
        | VEX | SCVS / vulnerability response | reports/vex.cdx.json | TBD | TBD | TBD |
        | Threat model | ASVS / API / Secure by Design | docs/security/THREAT_MODEL.md | TBD | TBD | TBD |
        """
    }

    fileprivate static func securityHeadersBaseline(projectName: String) -> String {
        """
        # Security Headers Baseline

        Project: \(projectName)

        | Header | Baseline |
        | --- | --- |
        | Content-Security-Policy | default-src 'self'; frame-ancestors 'none'; object-src 'none' |
        | Strict-Transport-Security | max-age=31536000; includeSubDomains |
        | X-Content-Type-Options | nosniff |
        | Referrer-Policy | strict-origin-when-cross-origin |
        | Permissions-Policy | disable unused browser capabilities |
        | Cache-Control | no-store for sensitive authenticated responses |
        """
    }

    fileprivate static func containerHardeningBaseline(projectName: String) -> String {
        """
        # Container Hardening Baseline

        Project: \(projectName)

        - [ ] Runtime image uses a non-root user.
        - [ ] Images are pinned to reviewed tags or digests.
        - [ ] Docker socket is not mounted into application containers.
        - [ ] Secrets are injected at runtime and not committed in compose files.
        - [ ] Kubernetes uses runAsNonRoot, allowPrivilegeEscalation: false, RuntimeDefault seccomp, dropped capabilities, resource limits, and NetworkPolicies.
        """
    }

    fileprivate static func cloudIACSecurityPlan(projectName: String) -> String {
        """
        # Cloud and IaC Security Plan

        Project: \(projectName)

        - [ ] Public ingress is limited to intended ports and source ranges.
        - [ ] Admin access uses VPN, bastion, or an approved management plane.
        - [ ] Storage buckets, databases, and queues are private and encrypted by default.
        - [ ] IAM policies avoid wildcard actions and principals.
        - [ ] Terraform outputs avoid raw secrets and use sensitive = true when needed.
        - [ ] State files are encrypted, access-controlled, and excluded from source control.
        """
    }

    private static func korean(projectName: String) -> String {
        """
        # KODA 보안 예방 키트

        프로젝트: \(projectName)

        이 파일은 취약점이 들어오기 전에 막기 위한 기본 템플릿 묶음입니다. 저장소에 그대로 넣기 전에 담당자, 브랜치, 패키지 생태계, 운영 URL을 프로젝트에 맞게 수정하세요.

        ## SECURITY.md

        ```markdown
        # Security Policy

        ## Supported Versions

        | Version | Supported |
        | --- | --- |
        | main / latest | yes |

        ## Reporting a Vulnerability

        취약점은 공개 이슈가 아니라 보안 담당자에게 비공개로 먼저 제보해주세요.

        - Project: \(projectName)
        - Contact: security@example.com
        - First response: 3 business days
        - Status update: 7 business days

        ## Handling

        1. 제보를 접수하고 담당자를 지정합니다.
        2. 격리된 환경에서 재현합니다.
        3. 패치, 테스트, 릴리스를 진행합니다.
        4. 비밀값 노출이면 키를 즉시 교체합니다.
        5. 사용자 조치 경로가 준비된 뒤 공지합니다.
        ```

        ## .github/dependabot.yml

        ```yaml
        version: 2
        updates:
          - package-ecosystem: "npm"
            directory: "/"
            schedule:
              interval: "weekly"
          - package-ecosystem: "pip"
            directory: "/"
            schedule:
              interval: "weekly"
          - package-ecosystem: "github-actions"
            directory: "/"
            schedule:
              interval: "weekly"
        ```

        ## .github/workflows/koda-security.yml

        ```yaml
        name: KODA Security

        on:
          pull_request:
          push:
            branches: [main]
          schedule:
            - cron: "0 18 * * 1"

        permissions:
          contents: read
          security-events: write

        jobs:
          local-security-scan:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v4
              - uses: actions/setup-python@v5
                with:
                  python-version: "3.12"
              - name: Run KODA local scan
                run: |
                  python -m security_scanner scan --target . --format sarif --output koda-results.sarif --enable-osv
              - name: Upload SARIF
                uses: github/codeql-action/upload-sarif@v3
                with:
                  sarif_file: koda-results.sarif
        ```

        ## ZAP Baseline

        ```bash
        python -m security_scanner zap-command --url https://example.com --output-dir reports/zap
        ```

        ## Dependency-Track SBOM 업로드

        ```bash
        python -m security_scanner scan --target . --format cyclonedx --output reports/sbom.cdx.json
        python -m security_scanner upload-sbom --server-url https://dependency-track.example.com --api-key-env DEPENDENCY_TRACK_API_KEY --project-name "\(projectName)" --project-version main --sbom reports/sbom.cdx.json --auto-create
        ```
        """
    }

    private static func english(projectName: String) -> String {
        """
        # KODA Security Prevention Kit

        Project: \(projectName)

        This file contains baseline guardrail templates for preventing vulnerabilities before they enter the project. Adjust owners, branches, ecosystems, and production URLs before committing.

        ## SECURITY.md

        ```markdown
        # Security Policy

        ## Supported Versions

        | Version | Supported |
        | --- | --- |
        | main / latest | yes |

        ## Reporting a Vulnerability

        Please report suspected vulnerabilities privately before opening a public issue.

        - Project: \(projectName)
        - Contact: security@example.com
        - First response: 3 business days
        - Status update: 7 business days
        ```

        ## Dependabot, CI Security, ZAP, and Dependency-Track

        Use the same commands and YAML blocks from the Korean section if this file is shared bilingually, or generate the full project templates from the CLI:

        ```bash
        python -m security_scanner init-security --target . --project-name "\(projectName)"
        python -m security_scanner zap-command --url https://example.com --output-dir reports/zap
        python -m security_scanner scan --target . --format cyclonedx --output reports/sbom.cdx.json
        python -m security_scanner upload-sbom --server-url https://dependency-track.example.com --api-key-env DEPENDENCY_TRACK_API_KEY --project-name "\(projectName)" --project-version main --sbom reports/sbom.cdx.json --auto-create
        ```
        """
    }
}

/// Converts KODA's Markdown guardrail/plan documents into shareable HTML and
/// printable PDF, so the prevention tool is not limited to raw `.md` output.
/// Handles the controlled Markdown subset KODA templates emit: headings, bullet
/// and numbered lists, tables, fenced/inline code, bold, and links.
enum MarkdownDocumentExporter {
    static func html(from markdown: String, title: String) -> String {
        let body = renderBody(markdown)
        return """
        <!doctype html>
        <html lang="ko">
        <head>
        <meta charset="utf-8">
        <title>\(escape(title))</title>
        <style>
          body { font: 15px/1.65 -apple-system, "Helvetica Neue", "Apple SD Gothic Neo", sans-serif; color: #1b2330; max-width: 820px; margin: 40px auto; padding: 0 24px; }
          h1 { font-size: 26px; border-bottom: 2px solid #e2e8f0; padding-bottom: 8px; }
          h2 { font-size: 21px; margin-top: 28px; }
          h3 { font-size: 17px; margin-top: 22px; }
          h4 { font-size: 15px; margin-top: 18px; color: #475069; }
          code { background: #f1f5f9; padding: 1px 5px; border-radius: 4px; font-family: "SF Mono", Menlo, monospace; font-size: 0.9em; }
          pre { background: #0f172a; color: #e2e8f0; padding: 14px 16px; border-radius: 8px; overflow-x: auto; }
          pre code { background: transparent; padding: 0; color: inherit; }
          table { border-collapse: collapse; width: 100%; margin: 14px 0; }
          th, td { border: 1px solid #d8dee9; padding: 7px 10px; text-align: left; font-size: 0.95em; }
          th { background: #f1f5f9; }
          ul, ol { padding-left: 22px; }
          li { margin: 4px 0; }
          a { color: #2563eb; }
        </style>
        </head>
        <body>
        \(body)
        </body>
        </html>
        """
    }

    @MainActor
    static func writePDF(from markdown: String, title: String, to destination: URL) throws {
        let htmlString = html(from: markdown, title: title)
        guard let data = htmlString.data(using: .utf8),
              let attributed = try? NSAttributedString(
                  data: data,
                  options: [
                      .documentType: NSAttributedString.DocumentType.html,
                      .characterEncoding: String.Encoding.utf8.rawValue,
                  ],
                  documentAttributes: nil
              )
        else {
            throw CocoaError(.fileWriteUnknown)
        }

        let pageSize = NSSize(width: 595, height: 842) // A4 at 72 dpi
        let margin: CGFloat = 48
        let textView = NSTextView(frame: NSRect(x: 0, y: 0, width: pageSize.width - margin * 2, height: pageSize.height - margin * 2))
        textView.isVerticallyResizable = true
        textView.isHorizontallyResizable = false
        textView.textStorage?.setAttributedString(attributed)

        let printInfo = NSPrintInfo()
        printInfo.paperSize = pageSize
        printInfo.topMargin = margin
        printInfo.bottomMargin = margin
        printInfo.leftMargin = margin
        printInfo.rightMargin = margin
        printInfo.horizontalPagination = .fit
        printInfo.verticalPagination = .automatic
        printInfo.isHorizontallyCentered = false
        printInfo.isVerticallyCentered = false
        printInfo.jobDisposition = .save
        printInfo.dictionary()[NSPrintInfo.AttributeKey.jobSavingURL.rawValue] = destination

        let operation = NSPrintOperation(view: textView, printInfo: printInfo)
        operation.showsPrintPanel = false
        operation.showsProgressPanel = false
        if !operation.run() {
            throw CocoaError(.fileWriteUnknown)
        }
    }

    // MARK: - Markdown -> HTML body

    private static func renderBody(_ markdown: String) -> String {
        var html = ""
        var listKind: String? // "ul" or "ol"
        var inCodeFence = false
        var tableRows: [String] = []

        func closeList() {
            if let kind = listKind { html += "</\(kind)>\n"; listKind = nil }
        }
        func flushTable() {
            guard !tableRows.isEmpty else { return }
            html += renderTable(tableRows)
            tableRows = []
        }

        for rawLine in markdown.components(separatedBy: "\n") {
            let line = rawLine
            let trimmed = line.trimmingCharacters(in: .whitespaces)

            if trimmed.hasPrefix("```") {
                if inCodeFence { html += "</code></pre>\n"; inCodeFence = false }
                else { closeList(); flushTable(); html += "<pre><code>"; inCodeFence = true }
                continue
            }
            if inCodeFence { html += escape(line) + "\n"; continue }

            if trimmed.hasPrefix("|") && trimmed.hasSuffix("|") {
                closeList()
                tableRows.append(trimmed)
                continue
            } else {
                flushTable()
            }

            if trimmed.isEmpty { closeList(); continue }

            if let heading = headingLevel(trimmed) {
                closeList()
                let text = inline(String(trimmed.dropFirst(heading + 1)).trimmingCharacters(in: .whitespaces))
                html += "<h\(heading)>\(text)</h\(heading)>\n"
                continue
            }

            if trimmed.hasPrefix("- ") || trimmed.hasPrefix("* ") {
                if listKind != "ul" { closeList(); html += "<ul>\n"; listKind = "ul" }
                html += "<li>\(inline(String(trimmed.dropFirst(2))))</li>\n"
                continue
            }
            if let ordered = orderedItem(trimmed) {
                if listKind != "ol" { closeList(); html += "<ol>\n"; listKind = "ol" }
                html += "<li>\(inline(ordered))</li>\n"
                continue
            }

            closeList()
            html += "<p>\(inline(trimmed))</p>\n"
        }
        if inCodeFence { html += "</code></pre>\n" }
        closeList()
        flushTable()
        return html
    }

    private static func headingLevel(_ line: String) -> Int? {
        var count = 0
        for char in line {
            if char == "#" { count += 1 } else { break }
        }
        if count >= 1, count <= 6, line.dropFirst(count).first == " " { return count }
        return nil
    }

    private static func orderedItem(_ line: String) -> String? {
        guard let dotIndex = line.firstIndex(of: ".") else { return nil }
        let prefix = line[line.startIndex..<dotIndex]
        guard !prefix.isEmpty, prefix.allSatisfy(\.isNumber) else { return nil }
        let after = line.index(after: dotIndex)
        guard after < line.endIndex, line[after] == " " else { return nil }
        return String(line[line.index(after: after)...])
    }

    private static func renderTable(_ rows: [String]) -> String {
        func cells(_ row: String) -> [String] {
            var trimmed = row
            if trimmed.hasPrefix("|") { trimmed.removeFirst() }
            if trimmed.hasSuffix("|") { trimmed.removeLast() }
            return trimmed.components(separatedBy: "|").map { $0.trimmingCharacters(in: .whitespaces) }
        }
        func isSeparator(_ row: String) -> Bool {
            cells(row).allSatisfy { cell in
                !cell.isEmpty && cell.allSatisfy { $0 == "-" || $0 == ":" || $0 == " " }
            }
        }
        var out = "<table>\n"
        var wroteHeader = false
        for (index, row) in rows.enumerated() {
            if index == 1 && isSeparator(row) { continue }
            let tag = (index == 0) ? "th" : "td"
            if index == 0 { out += "<thead>" }
            if index == 1 && !wroteHeader { out += "<tbody>" }
            let cellHTML = cells(row).map { "<\(tag)>\(inline($0))</\(tag)>" }.joined()
            out += "<tr>\(cellHTML)</tr>\n"
            if index == 0 { out += "</thead>"; wroteHeader = true }
        }
        out += "</tbody></table>\n"
        return out
    }

    // MARK: - Inline

    private static func inline(_ text: String) -> String {
        var result = escape(text)
        result = replace(result, pattern: "`([^`]+)`", template: "<code>$1</code>")
        result = replace(result, pattern: "\\*\\*([^*]+)\\*\\*", template: "<strong>$1</strong>")
        result = replace(result, pattern: "\\[([^\\]]+)\\]\\(([^)]+)\\)", template: "<a href=\"$2\">$1</a>")
        return result
    }

    private static func replace(_ text: String, pattern: String, template: String) -> String {
        guard let regex = try? NSRegularExpression(pattern: pattern) else { return text }
        let range = NSRange(text.startIndex..., in: text)
        return regex.stringByReplacingMatches(in: text, range: range, withTemplate: template)
    }

    private static func escape(_ text: String) -> String {
        text.replacingOccurrences(of: "&", with: "&amp;")
            .replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;")
    }
}
