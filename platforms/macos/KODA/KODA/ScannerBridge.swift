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
            return finding.category == "dependencies"
                || finding.ruleID.contains("dependency")
                || finding.ruleID == "prevention.sbom-missing"
                || finding.ruleID == "prevention.dependency-update-automation-missing"
                || finding.ruleID == "prevention.ci-security-scan-missing"
                || finding.ruleID == "prevention.vex-missing"
                || finding.ruleID == "prevention.dependency-track-integration-missing"
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
    let findings: [NativeFinding]
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
        default: return "pkg:generic/\(encodedName)@\(encodedVersion)"
        }
    }
}

private enum NativeDependencyInventory {
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
            ["npm", "PyPI"].contains(component.ecosystem) && isExactVersion(component.version)
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
        default:
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
        let trimmed = version.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return false }
        if trimmed.range(of: #"[<>=~^*xX]"#, options: .regularExpression) != nil {
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
            (".dockerignore", dockerignore()),
            (".env.example", envExample()),
            ("docs/security/ZAP_BASELINE.md", zapBaselineGuide()),
            ("docs/security/DEPENDENCY_TRACK.md", dependencyTrackGuide(projectName: projectName)),
            ("docs/security/VEX.md", vexGuide()),
            ("docs/security/SLSA_SIGSTORE.md", slsaSigstoreGuide()),
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
