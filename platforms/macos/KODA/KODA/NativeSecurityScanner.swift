import Compression
import AppKit
import CoreText
import Foundation

struct NativeFinding {
    let ruleID: String
    let severity: String
    let category: String
    let title: String
    let path: String
    let line: Int?
    let evidence: String
    let recommendation: String
}

struct NativeScanResult {
    let findings: [NativeFinding]
    let warnings: [String]
    let targetCount: Int
    let scannedFileCount: Int
    let generatedAt: Date

    var riskScore: Int {
        findings.reduce(0) { total, finding in
            total + Self.score(for: finding.severity)
        }
    }

    static func score(for severity: String) -> Int {
        switch severity {
        case "critical": return 100
        case "high": return 40
        case "medium": return 10
        case "low": return 3
        default: return 1
        }
    }
}

enum NativeScanError: Error, LocalizedError {
    case unsafeArchivePath(String)
    case unsupportedArchive(String)
    case corruptArchive(String)
    case compressionFailed(String)

    var errorDescription: String? {
        switch self {
        case .unsafeArchivePath(let path):
            return "압축파일에 안전하지 않은 경로가 있습니다: \(path)"
        case .unsupportedArchive(let path):
            return "지원하지 않는 압축 형식입니다: \(path)"
        case .corruptArchive(let path):
            return "압축파일을 읽을 수 없습니다: \(path)"
        case .compressionFailed(let path):
            return "압축 해제에 실패했습니다: \(path)"
        }
    }
}

final class NativeSecurityScanner {
    private let fileManager: FileManager
    private let maxFileSize = 524_288
    private let excludedDirectoryNames: Set<String> = [
        ".git",
        ".hg",
        ".svn",
        ".cache",
        ".mypy_cache",
        ".next",
        ".omx",
        ".playwright-cli",
        ".pytest_cache",
        ".terraform",
        ".venv",
        "DerivedData",
        "__pycache__",
        "build",
        "coverage",
        "dist",
        "node_modules",
        "output",
        "reports",
        "target",
        "venv",
    ]

    init(fileManager: FileManager = .default) {
        self.fileManager = fileManager
    }

    func scan(targets: [URL]) throws -> NativeScanResult {
        let temporaryRoot = fileManager.temporaryDirectory.appendingPathComponent("KODA-native-scan-\(UUID().uuidString)")
        try fileManager.createDirectory(at: temporaryRoot, withIntermediateDirectories: true)
        defer {
            try? fileManager.removeItem(at: temporaryRoot)
        }

        var findings: [NativeFinding] = []
        var warnings: [String] = []
        var scannedFileCount = 0

        for target in targets {
            let resolvedTarget = target.standardizedFileURL
            guard fileManager.fileExists(atPath: resolvedTarget.path) else {
                warnings.append("대상이 존재하지 않습니다: \(resolvedTarget.path)")
                continue
            }

            let targetName = resolvedTarget.lastPathComponent.isEmpty ? resolvedTarget.path : resolvedTarget.lastPathComponent
            if isArchive(resolvedTarget) {
                do {
                    let extractedRoot = try extractArchive(resolvedTarget, under: temporaryRoot)
                    scanDirectory(
                        extractedRoot,
                        targetName: targetName,
                        originalRoot: extractedRoot,
                        findings: &findings,
                        warnings: &warnings,
                        scannedFileCount: &scannedFileCount
                    )
                } catch {
                    warnings.append(error.localizedDescription)
                }
                continue
            }

            if isDirectory(resolvedTarget) {
                scanDirectory(
                    resolvedTarget,
                    targetName: targetName,
                    originalRoot: resolvedTarget,
                    findings: &findings,
                    warnings: &warnings,
                    scannedFileCount: &scannedFileCount
                )
            } else {
                scanFile(
                    resolvedTarget,
                    targetName: targetName,
                    root: resolvedTarget.deletingLastPathComponent(),
                    findings: &findings,
                    scannedFileCount: &scannedFileCount
                )
            }
        }

        return NativeScanResult(
            findings: findings.sorted { left, right in
                let leftRank = severityRank(left.severity)
                let rightRank = severityRank(right.severity)
                if leftRank != rightRank { return leftRank > rightRank }
                if left.path != right.path { return left.path < right.path }
                return (left.line ?? 0) < (right.line ?? 0)
            },
            warnings: warnings,
            targetCount: targets.count,
            scannedFileCount: scannedFileCount,
            generatedAt: Date()
        )
    }

    func writeHTMLReport(_ result: NativeScanResult, to output: URL, language: AppLanguage = .ko) throws {
        try renderHTML(result, language: language).write(to: output, atomically: true, encoding: .utf8)
    }

    func writeMarkdownReport(_ result: NativeScanResult, to output: URL, language: AppLanguage = .ko) throws {
        try renderMarkdown(result, language: language).write(to: output, atomically: true, encoding: .utf8)
    }

    func writePDFReport(_ result: NativeScanResult, to output: URL, language: AppLanguage = .ko) throws {
        let pageRect = CGRect(x: 0, y: 0, width: 595, height: 842)
        let data = NSMutableData()
        var mediaBox = pageRect
        guard let consumer = CGDataConsumer(data: data as CFMutableData),
              let context = CGContext(consumer: consumer, mediaBox: &mediaBox, nil) else {
            throw CocoaError(.fileWriteUnknown)
        }

        context.beginPDFPage(nil)
        drawPDFSummaryPage(result, language: language, context: context, pageRect: pageRect)
        context.endPDFPage()
        drawPDFFindingPages(
            renderPlainText(result, language: language),
            title: reportLabel("findings", language: language),
            context: context,
            pageRect: pageRect
        )

        context.closePDF()
        try data.write(to: output, options: .atomic)
    }

    private func drawPDFSummaryPage(
        _ result: NativeScanResult,
        language: AppLanguage,
        context: CGContext,
        pageRect: CGRect
    ) {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
        let generated = formatter.string(from: result.generatedAt)
        let severityCounts = Dictionary(grouping: result.findings, by: \.severity).mapValues(\.count)

        context.setFillColor(pdfColor(245, 247, 251).cgColor)
        context.fill(pageRect)

        let headerRect = topRect(x: 0, y: 0, width: pageRect.width, height: 112, pageRect: pageRect)
        context.setFillColor(pdfColor(11, 18, 32).cgColor)
        context.fill(headerRect)

        drawPDFText(
            reportLabel("pageTitle", language: language),
            in: topRect(x: 42, y: 28, width: pageRect.width - 84, height: 34, pageRect: pageRect),
            context: context,
            font: .systemFont(ofSize: 24, weight: .bold),
            color: .white
        )
        drawPDFText(
            "\(reportLabel("generatedAt", language: language)) \(generated) | \(reportLabel("targets", language: language)) \(result.targetCount) | \(reportLabel("scannedFiles", language: language)) \(result.scannedFileCount)",
            in: topRect(x: 42, y: 67, width: pageRect.width - 84, height: 22, pageRect: pageRect),
            context: context,
            font: .systemFont(ofSize: 10.5, weight: .regular),
            color: pdfColor(203, 213, 225)
        )

        let cardTop = CGFloat(138)
        let cardGap = CGFloat(12)
        let cardWidth = (pageRect.width - 84 - cardGap * 3) / 4
        let cards: [(String, String, NSColor)] = [
            (reportLabel("riskScore", language: language), "\(result.riskScore)", pdfColor(194, 65, 12)),
            (reportLabel("criticalHigh", language: language), "\((severityCounts["critical"] ?? 0) + (severityCounts["high"] ?? 0))", pdfColor(153, 27, 27)),
            (severityLabel("medium", language: language), "\(severityCounts["medium"] ?? 0)", pdfColor(180, 83, 9)),
            (reportLabel("lowInfo", language: language), "\((severityCounts["low"] ?? 0) + (severityCounts["info"] ?? 0))", pdfColor(37, 99, 235)),
        ]

        for (index, card) in cards.enumerated() {
            let x = CGFloat(42) + CGFloat(index) * (cardWidth + cardGap)
            let rect = topRect(x: x, y: cardTop, width: cardWidth, height: 88, pageRect: pageRect)
            drawPDFRoundedRect(rect, fill: .white, stroke: pdfColor(216, 222, 233), context: context)
            drawPDFText(
                card.0,
                in: topRect(x: x + 14, y: cardTop + 13, width: cardWidth - 28, height: 18, pageRect: pageRect),
                context: context,
                font: .systemFont(ofSize: 9.5, weight: .bold),
                color: pdfColor(102, 112, 133)
            )
            drawPDFText(
                card.1,
                in: topRect(x: x + 14, y: cardTop + 38, width: cardWidth - 28, height: 36, pageRect: pageRect),
                context: context,
                font: .systemFont(ofSize: 26, weight: .heavy),
                color: card.2
            )
        }

        let formulaRect = topRect(x: 42, y: 252, width: pageRect.width - 84, height: 82, pageRect: pageRect)
        drawPDFRoundedRect(formulaRect, fill: .white, stroke: pdfColor(216, 222, 233), context: context)
        drawPDFText(
            reportLabel("riskFormula", language: language),
            in: topRect(x: 58, y: 267, width: pageRect.width - 116, height: 18, pageRect: pageRect),
            context: context,
            font: .systemFont(ofSize: 11, weight: .bold),
            color: pdfColor(102, 112, 133)
        )
        drawPDFText(
            riskFormula(language: language),
            in: topRect(x: 58, y: 292, width: pageRect.width - 116, height: 28, pageRect: pageRect),
            context: context,
            font: .systemFont(ofSize: 10.5, weight: .regular),
            color: pdfColor(17, 24, 39),
            lineSpacing: 3
        )

        let chartTop = CGFloat(360)
        let chartRect = topRect(x: 42, y: chartTop, width: pageRect.width - 84, height: 210, pageRect: pageRect)
        drawPDFRoundedRect(chartRect, fill: .white, stroke: pdfColor(216, 222, 233), context: context)
        drawPDFText(
            reportLabel("severityDistribution", language: language),
            in: topRect(x: 58, y: chartTop + 16, width: pageRect.width - 116, height: 20, pageRect: pageRect),
            context: context,
            font: .systemFont(ofSize: 12, weight: .bold),
            color: pdfColor(17, 24, 39)
        )
        drawPDFSeverityBars(severityCounts, language: language, top: chartTop + 48, context: context, pageRect: pageRect)

        if !result.warnings.isEmpty {
            let warningSummary = result.warnings.prefix(4).map { "- \(warningText($0, language: language))" }.joined(separator: "\n")
            let warningRect = topRect(x: 42, y: 596, width: pageRect.width - 84, height: 96, pageRect: pageRect)
            drawPDFRoundedRect(warningRect, fill: pdfColor(255, 251, 235), stroke: pdfColor(251, 191, 36), context: context)
            drawPDFText(
                reportLabel("warnings", language: language),
                in: topRect(x: 58, y: 612, width: pageRect.width - 116, height: 18, pageRect: pageRect),
                context: context,
                font: .systemFont(ofSize: 11, weight: .bold),
                color: pdfColor(146, 64, 14)
            )
            drawPDFText(
                warningSummary,
                in: topRect(x: 58, y: 637, width: pageRect.width - 116, height: 42, pageRect: pageRect),
                context: context,
                font: .systemFont(ofSize: 9.5, weight: .regular),
                color: pdfColor(120, 53, 15),
                lineSpacing: 3
            )
        }
    }

    private func drawPDFFindingPages(
        _ text: String,
        title: String,
        context: CGContext,
        pageRect: CGRect
    ) {
        let paragraph = NSMutableParagraphStyle()
        paragraph.lineSpacing = 4
        paragraph.lineBreakMode = .byWordWrapping
        let attributed = NSAttributedString(
            string: text,
            attributes: [
                .font: NSFont.systemFont(ofSize: 10, weight: .regular),
                .foregroundColor: pdfColor(17, 24, 39),
                .paragraphStyle: paragraph,
            ]
        )
        let framesetter = CTFramesetterCreateWithAttributedString(attributed)
        var range = CFRange(location: 0, length: 0)

        repeat {
            context.beginPDFPage(nil)
            context.setFillColor(pdfColor(255, 255, 255).cgColor)
            context.fill(pageRect)
            drawPDFText(
                title,
                in: topRect(x: 42, y: 34, width: pageRect.width - 84, height: 24, pageRect: pageRect),
                context: context,
                font: .systemFont(ofSize: 16, weight: .bold),
                color: pdfColor(17, 24, 39)
            )
            let textRect = pageRect.insetBy(dx: 42, dy: 74)
            let path = CGPath(rect: textRect, transform: nil)
            let frame = CTFramesetterCreateFrame(framesetter, range, path, nil)
            context.saveGState()
            context.textMatrix = .identity
            CTFrameDraw(frame, context)
            context.restoreGState()
            let visible = CTFrameGetVisibleStringRange(frame)
            range.location += max(visible.length, 1)
            context.endPDFPage()
        } while range.location < max(attributed.length, 1)
    }

    private func renderPDFFindingText(_ result: NativeScanResult, language: AppLanguage) -> String {
        let warnings = result.warnings.isEmpty
            ? ""
            : "\n\(reportLabel("warnings", language: language))\n"
                + result.warnings.map { "- \(warningText($0, language: language))" }.joined(separator: "\n")
                + "\n\n"
        let findings = result.findings.isEmpty
            ? reportLabel("noFindings", language: language)
            : result.findings.enumerated().map { index, finding in
                """
                \(index + 1). [\(severityLabel(finding.severity, language: language))] \(findingTitle(finding, language: language))
                   Rule: \(finding.ruleID)
                   \(reportLabel("category", language: language)): \(categoryLabel(finding.category, language: language))
                   \(reportLabel("path", language: language)): \(finding.path)\(finding.line.map { ":\($0)" } ?? "")
                   \(reportLabel("evidence", language: language)): \(finding.evidence)
                   \(reportLabel("recommendation", language: language)): \(findingRecommendation(finding, language: language))
                """
            }.joined(separator: "\n\n")

        return "\(warnings)\(findings)"
    }

    private func drawPDFSeverityBars(
        _ counts: [String: Int],
        language: AppLanguage,
        top: CGFloat,
        context: CGContext,
        pageRect: CGRect
    ) {
        let entries = ["critical", "high", "medium", "low", "info"]
        let maximum = max(entries.map { counts[$0] ?? 0 }.max() ?? 0, 1)

        for (index, severity) in entries.enumerated() {
            let y = top + CGFloat(index) * 31
            let count = counts[severity] ?? 0
            let ratio = CGFloat(count) / CGFloat(maximum)

            drawPDFText(
                severityLabel(severity, language: language),
                in: topRect(x: 58, y: y, width: 76, height: 18, pageRect: pageRect),
                context: context,
                font: .systemFont(ofSize: 10, weight: .bold),
                color: pdfColor(102, 112, 133)
            )

            let trackRect = topRect(x: 136, y: y + 4, width: pageRect.width - 236, height: 11, pageRect: pageRect)
            drawPDFRoundedRect(trackRect, fill: pdfColor(233, 238, 245), stroke: pdfColor(233, 238, 245), context: context, cornerRadius: 5.5)
            if count > 0 {
                let fillRect = CGRect(x: trackRect.minX, y: trackRect.minY, width: max(8, trackRect.width * ratio), height: trackRect.height)
                drawPDFRoundedRect(fillRect, fill: pdfSeverityColor(severity), stroke: pdfSeverityColor(severity), context: context, cornerRadius: 5.5)
            }

            drawPDFText(
                "\(count)",
                in: topRect(x: pageRect.width - 86, y: y, width: 44, height: 18, pageRect: pageRect),
                context: context,
                font: .systemFont(ofSize: 10, weight: .heavy),
                color: pdfColor(17, 24, 39)
            )
        }
    }

    private func drawPDFText(
        _ text: String,
        in rect: CGRect,
        context: CGContext,
        font: NSFont,
        color: NSColor,
        lineSpacing: CGFloat = 2
    ) {
        let paragraph = NSMutableParagraphStyle()
        paragraph.lineSpacing = lineSpacing
        paragraph.lineBreakMode = .byWordWrapping
        let attributed = NSAttributedString(
            string: text,
            attributes: [
                .font: font,
                .foregroundColor: color,
                .paragraphStyle: paragraph,
            ]
        )
        let framesetter = CTFramesetterCreateWithAttributedString(attributed)
        let path = CGPath(rect: rect, transform: nil)
        let frame = CTFramesetterCreateFrame(framesetter, CFRange(location: 0, length: attributed.length), path, nil)
        context.saveGState()
        context.textMatrix = .identity
        CTFrameDraw(frame, context)
        context.restoreGState()
    }

    private func drawPDFRoundedRect(
        _ rect: CGRect,
        fill: NSColor,
        stroke: NSColor,
        context: CGContext,
        cornerRadius: CGFloat = 9
    ) {
        let path = CGPath(roundedRect: rect, cornerWidth: cornerRadius, cornerHeight: cornerRadius, transform: nil)
        context.setFillColor(fill.cgColor)
        context.addPath(path)
        context.fillPath()
        context.setStrokeColor(stroke.cgColor)
        context.setLineWidth(1)
        context.addPath(path)
        context.strokePath()
    }

    private func topRect(x: CGFloat, y: CGFloat, width: CGFloat, height: CGFloat, pageRect: CGRect) -> CGRect {
        CGRect(x: x, y: pageRect.height - y - height, width: width, height: height)
    }

    private func pdfColor(_ red: CGFloat, _ green: CGFloat, _ blue: CGFloat, _ alpha: CGFloat = 1) -> NSColor {
        NSColor(calibratedRed: red / 255, green: green / 255, blue: blue / 255, alpha: alpha)
    }

    private func pdfSeverityColor(_ severity: String) -> NSColor {
        switch severity {
        case "critical": return pdfColor(127, 29, 29)
        case "high": return pdfColor(180, 35, 24)
        case "medium": return pdfColor(183, 121, 31)
        case "low": return pdfColor(37, 99, 235)
        default: return pdfColor(71, 84, 103)
        }
    }

    private func scanDirectory(
        _ root: URL,
        targetName: String,
        originalRoot: URL,
        findings: inout [NativeFinding],
        warnings: inout [String],
        scannedFileCount: inout Int
    ) {
        guard let enumerator = fileManager.enumerator(
            at: root,
            includingPropertiesForKeys: [.isDirectoryKey, .fileSizeKey],
            options: [.skipsPackageDescendants]
        ) else {
            warnings.append("디렉터리를 열 수 없습니다: \(root.path)")
            return
        }

        while let item = enumerator.nextObject() as? URL {
            if isDirectory(item) {
                if excludedDirectoryNames.contains(item.lastPathComponent) {
                    enumerator.skipDescendants()
                }
                continue
            }

            if isArchive(item) {
                do {
                    let extractedRoot = try extractArchive(item, under: fileManager.temporaryDirectory)
                    scanDirectory(
                        extractedRoot,
                        targetName: targetName,
                        originalRoot: extractedRoot,
                        findings: &findings,
                        warnings: &warnings,
                        scannedFileCount: &scannedFileCount
                    )
                    try? fileManager.removeItem(at: extractedRoot)
                } catch {
                    warnings.append(error.localizedDescription)
                }
                continue
            }

            scanFile(
                item,
                targetName: targetName,
                root: originalRoot,
                findings: &findings,
                scannedFileCount: &scannedFileCount
            )
        }
    }

    private func scanFile(
        _ file: URL,
        targetName: String,
        root: URL,
        findings: inout [NativeFinding],
        scannedFileCount: inout Int
    ) {
        guard let lines = readTextLines(file) else { return }
        scannedFileCount += 1
        let displayPath = relativePath(file, root: root)
        let localFindings =
            checkSecrets(lines: lines, file: file, displayPath: displayPath)
            + checkDependencies(lines: lines, file: file, root: root, displayPath: displayPath)
            + checkConfiguration(lines: lines, file: file, displayPath: displayPath)
            + checkCode(lines: lines, file: file, displayPath: displayPath)

        findings.append(contentsOf: localFindings.map { finding in
            NativeFinding(
                ruleID: finding.ruleID,
                severity: finding.severity,
                category: finding.category,
                title: finding.title,
                path: "\(targetName)/\(finding.path)",
                line: finding.line,
                evidence: finding.evidence,
                recommendation: finding.recommendation
            )
        })
    }

    private func checkSecrets(lines: [String], file: URL, displayPath: String) -> [NativeFinding] {
        var findings: [NativeFinding] = []
        for (index, line) in lines.enumerated() {
            let lineNumber = index + 1
            if line.contains("-----BEGIN") && line.contains("PRIVATE KEY-----") {
                findings.append(finding("secret.private-key", "critical", "secrets", "개인 키가 파일에 포함됨", displayPath, lineNumber, line, "개인 키를 즉시 폐기하고 안전한 비밀 관리 저장소로 이동하세요."))
            }
            if matches(#"sk-[A-Za-z0-9_\-]{20,}"#, line) {
                findings.append(finding("secret.openai-key", "high", "secrets", "API 키로 보이는 값 발견", displayPath, lineNumber, redact(line), "키를 폐기하고 환경변수 또는 비밀 관리 저장소를 사용하세요."))
            }
            if matches(#"(?i)\b(api[_-]?key|secret|token|password|passwd|pwd)\b\s*[:=]\s*['\"]?[A-Za-z0-9_\-./+=]{12,}"#, line),
               !matches(#"(?i)(getenv|process\.env|os\.environ|config\.get|placeholder|example)"#, line) {
                findings.append(finding("secret.generic-assignment", "medium", "secrets", "하드코딩된 비밀값 의심 대입", displayPath, lineNumber, redact(line), "코드에 값을 직접 두지 말고 런타임 비밀 주입을 사용하세요."))
            }
        }
        return findings
    }

    private func checkDependencies(lines: [String], file: URL, root: URL, displayPath: String) -> [NativeFinding] {
        var findings: [NativeFinding] = []
        let name = file.lastPathComponent
        if name == "requirements.txt" {
            for (index, rawLine) in lines.enumerated() {
                let line = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
                if line.isEmpty || line.hasPrefix("#") || line.contains("==") || line.contains("@") {
                    continue
                }
                if matches(#"^[A-Za-z0-9_.\-]+([<>=!~]=?)?.*"#, line) {
                    findings.append(finding("dependency.python-unpinned-requirement", "low", "dependencies", "고정되지 않은 Python 의존성", displayPath, index + 1, line, "정확한 버전을 고정하고 정기적으로 취약점 조회를 수행하세요."))
                }
            }
        }

        if name == "package.json" {
            let lockfiles = ["package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"]
            if !lockfiles.contains(where: { fileManager.fileExists(atPath: file.deletingLastPathComponent().appendingPathComponent($0).path) }) {
                findings.append(finding("dependency.node-missing-lockfile", "medium", "dependencies", "Node lockfile 누락", displayPath, nil, "package.json", "lockfile을 커밋해 재현 가능한 설치를 보장하세요."))
            }
            for (index, line) in lines.enumerated() {
                if matches(#"(?i)\"[^\"]+\"\s*:\s*\"(\*|latest|x|>=)"#, line) {
                    findings.append(finding("dependency.node-unbounded-version", "medium", "dependencies", "제한 없는 Node 의존성 버전", displayPath, index + 1, line, "검증된 버전 범위나 lockfile을 사용하세요."))
                }
            }
        }

        if name == "Dockerfile" {
            for (index, line) in lines.enumerated() {
                if matches(#"(?i)(curl|wget).*\|\s*(sh|bash)"#, line) {
                    findings.append(finding("dependency.remote-shell-install", "high", "dependencies", "원격 스크립트 즉시 실행", displayPath, index + 1, line, "다운로드 검증과 체크섬 확인 후 실행하세요."))
                }
                if matches(#"(?i)FROM\s+\S+:latest\b"#, line) {
                    findings.append(finding("dependency.container-latest-tag", "medium", "dependencies", "latest 컨테이너 태그 사용", displayPath, index + 1, line, "불변 태그나 digest를 사용하세요."))
                }
            }
        }

        _ = root
        return findings
    }

    private func checkConfiguration(lines: [String], file: URL, displayPath: String) -> [NativeFinding] {
        var findings: [NativeFinding] = []
        let name = file.lastPathComponent
        if name == ".env" || name.hasPrefix(".env.") {
            findings.append(finding("config.env-file-present", "medium", "configuration", "환경 파일이 프로젝트에 포함됨", displayPath, nil, name, "비밀값 포함 여부를 확인하고 저장소에서 제외하세요."))
        }

        for (index, line) in lines.enumerated() {
            if matches(#"(?i)\bDEBUG\s*[:=]\s*(true|1|yes)\b"#, line) {
                findings.append(finding("config.debug-enabled", "medium", "configuration", "디버그 설정 활성화", displayPath, index + 1, line, "운영 빌드에서 디버그 설정을 비활성화하세요."))
            }
            if matches(#"(?i)\bprivileged\s*:\s*true\b"#, line) {
                findings.append(finding("config.compose-privileged", "high", "configuration", "권한 상승 컨테이너 설정", displayPath, index + 1, line, "컨테이너 privileged 모드를 제거하고 필요한 capability만 부여하세요."))
            }
        }
        return findings
    }

    private func checkCode(lines: [String], file: URL, displayPath: String) -> [NativeFinding] {
        var findings: [NativeFinding] = []
        for (index, line) in lines.enumerated() {
            let lineNumber = index + 1
            if matches(#"(?i)\.innerHTML\s*=.*(location|document\.URL|request|params)"#, line) {
                findings.append(finding("code.xss-dom-sink", "medium", "code", "DOM XSS 위험 sink", displayPath, lineNumber, line, "신뢰할 수 없는 입력을 HTML로 직접 삽입하지 말고 escaping 또는 textContent를 사용하세요."))
            }
            if matches(#"(?i)(execute|query)\s*\(.*(SELECT|INSERT|UPDATE|DELETE).*(\+|f"|%\s)"#, line) {
                findings.append(finding("code.sql-dynamic-query", "high", "code", "동적 SQL 쿼리 구성", displayPath, lineNumber, line, "파라미터 바인딩 또는 ORM 안전 API를 사용하세요."))
            }
            if matches(#"(?i)(os\.system|subprocess\.[A-Za-z_]+|exec\().*(shell\s*=\s*True|\+|request|params)"#, line) {
                findings.append(finding("code.command-injection", "high", "code", "명령어 삽입 위험", displayPath, lineNumber, line, "쉘 실행을 피하고 인자를 배열로 전달하며 입력을 allowlist로 검증하세요."))
            }
            if matches(#"(?i)(send_file|sendfile|readFile|createReadStream).*(request|req\.|params|query)"#, line) {
                findings.append(finding("code.path-traversal", "high", "code", "경로 조작 위험", displayPath, lineNumber, line, "사용자 입력 경로를 정규화하고 허용된 루트 내부인지 검증하세요."))
            }
            if matches(#"(?i)(pickle\.loads|yaml\.load|ObjectInputStream|unserialize\()"#, line) {
                findings.append(finding("code.unsafe-deserialization", "high", "code", "위험한 역직렬화 사용", displayPath, lineNumber, line, "신뢰할 수 없는 입력의 역직렬화를 금지하고 안전 로더를 사용하세요."))
            }
            if matches(#"(?i)mktemp\s*\("#, line) {
                findings.append(finding("code.insecure-temp-file", "medium", "code", "불안전한 임시 파일 생성", displayPath, lineNumber, line, "경쟁 조건을 피하기 위해 안전한 임시 파일 API를 사용하세요."))
            }
            if matches(#"(?i)(CORS|Access-Control-Allow-Origin).*(\*|origins\s*=\s*['\"]\*)"#, line) {
                findings.append(finding("code.wildcard-cors", "medium", "code", "와일드카드 CORS 설정", displayPath, lineNumber, line, "허용 origin을 명시적으로 제한하세요."))
            }
            if matches(#"(?i)(host\s*=\s*['\"]0\.0\.0\.0|listen\([^)]*0\.0\.0\.0)"#, line) {
                findings.append(finding("code.public-bind-all-interfaces", "low", "code", "전체 인터페이스 바인딩", displayPath, lineNumber, line, "개발 서버는 localhost에만 바인딩하세요."))
            }
            if matches(#"(?i)(md5|sha1)\s*\("#, line) {
                findings.append(finding("code.weak-hash", "medium", "code", "약한 해시 알고리즘 사용", displayPath, lineNumber, line, "SHA-256 이상 또는 비밀번호에는 bcrypt/argon2를 사용하세요."))
            }
            if matches(#"(?i)(secure\s*:\s*false|httpOnly\s*:\s*false|SameSite\s*=\s*None)"#, line) {
                findings.append(finding("code.insecure-cookie-settings", "medium", "code", "쿠키/세션 보안 설정 약화", displayPath, lineNumber, line, "Secure, HttpOnly, SameSite 속성을 적절히 설정하세요."))
            }
            if matches(#"(?i)Options\s+Indexes"#, line) {
                findings.append(finding("code.directory-listing-enabled", "medium", "code", "디렉터리 리스팅 활성화", displayPath, lineNumber, line, "디렉터리 인덱싱을 비활성화하세요."))
            }
            if matches(#"(?i)WebDAV(Module| enabled| true)"#, line) {
                findings.append(finding("code.webdav-enabled", "medium", "code", "WebDAV 활성화 흔적", displayPath, lineNumber, line, "필요하지 않은 WebDAV 기능을 비활성화하세요."))
            }
        }
        return findings
    }

    private func readTextLines(_ file: URL) -> [String]? {
        guard isTextCandidate(file) else { return nil }
        guard let values = try? file.resourceValues(forKeys: [.fileSizeKey]),
              let size = values.fileSize,
              size <= maxFileSize else {
            return nil
        }
        guard let data = try? Data(contentsOf: file, options: [.mappedIfSafe]) else {
            return nil
        }
        if data.prefix(4096).contains(0) {
            return nil
        }
        return String(decoding: data, as: UTF8.self).components(separatedBy: .newlines)
    }

    private func isTextCandidate(_ file: URL) -> Bool {
        let name = file.lastPathComponent
        let textNames: Set<String> = [
            ".env",
            ".env.local",
            ".env.production",
            ".env.development",
            ".htaccess",
            ".npmrc",
            "Dockerfile",
            "Makefile",
            "requirements.txt",
        ]
        if textNames.contains(name) || name.hasPrefix(".env.") {
            return true
        }
        let textExtensions: Set<String> = [
            "bash", "c", "cc", "cfg", "conf", "config", "cpp", "cs", "css", "cxx", "env", "go",
            "h", "hpp", "html", "ini", "java", "js", "json", "jsx", "kt", "m", "md", "php",
            "plist", "properties", "py", "rb", "rs", "sh", "sql", "swift", "toml", "ts", "tsx",
            "txt", "vue", "xml", "yaml", "yml", "zsh",
        ]
        return textExtensions.contains(file.pathExtension.lowercased())
    }

    private func extractArchive(_ archive: URL, under root: URL) throws -> URL {
        let output = root.appendingPathComponent("\(archive.lastPathComponent)-\(UUID().uuidString)")
        try fileManager.createDirectory(at: output, withIntermediateDirectories: true)
        let lowerName = archive.lastPathComponent.lowercased()
        let data = try Data(contentsOf: archive)

        if lowerName.hasSuffix(".zip") || lowerName.hasSuffix(".jar") || lowerName.hasSuffix(".war") || lowerName.hasSuffix(".ear") {
            try extractZip(data, to: output)
            return output
        }

        if lowerName.hasSuffix(".tar") {
            try extractTar(data, to: output)
            return output
        }

        if lowerName.hasSuffix(".tar.gz") || lowerName.hasSuffix(".tgz") {
            try extractTar(try gunzip(data, sourceName: archive.lastPathComponent), to: output)
            return output
        }

        if lowerName.hasSuffix(".gz") {
            let decompressed = try gunzip(data, sourceName: archive.lastPathComponent)
            let fileName = String(archive.deletingPathExtension().lastPathComponent.prefix(120))
            try decompressed.write(to: safeDestination(root: output, memberName: fileName))
            return output
        }

        throw NativeScanError.unsupportedArchive(archive.lastPathComponent)
    }

    private func extractZip(_ data: Data, to output: URL) throws {
        var offset = 0
        while offset + 30 <= data.count {
            let signature = data.u32(offset)
            if signature == 0x0201_4B50 || signature == 0x0605_4B50 {
                break
            }
            guard signature == 0x0403_4B50 else {
                throw NativeScanError.corruptArchive("zip")
            }

            let flags = data.u16(offset + 6)
            let method = data.u16(offset + 8)
            let compressedSize = Int(data.u32(offset + 18))
            let uncompressedSize = Int(data.u32(offset + 22))
            let nameLength = Int(data.u16(offset + 26))
            let extraLength = Int(data.u16(offset + 28))
            let nameStart = offset + 30
            let dataStart = nameStart + nameLength + extraLength
            guard nameStart + nameLength <= data.count, dataStart + compressedSize <= data.count else {
                throw NativeScanError.corruptArchive("zip")
            }
            guard flags & 0x0008 == 0 else {
                throw NativeScanError.unsupportedArchive("zip data descriptor")
            }

            let nameData = data[nameStart..<nameStart + nameLength]
            guard let memberName = String(data: nameData, encoding: .utf8), !memberName.isEmpty else {
                throw NativeScanError.corruptArchive("zip filename")
            }
            let destination = try safeDestination(root: output, memberName: memberName)
            if memberName.hasSuffix("/") {
                try fileManager.createDirectory(at: destination, withIntermediateDirectories: true)
            } else {
                try fileManager.createDirectory(at: destination.deletingLastPathComponent(), withIntermediateDirectories: true)
                let compressed = Data(data[dataStart..<dataStart + compressedSize])
                switch method {
                case 0:
                    try compressed.write(to: destination)
                case 8:
                    try inflate(compressed, expectedSize: uncompressedSize, label: memberName).write(to: destination)
                default:
                    throw NativeScanError.unsupportedArchive("zip method \(method)")
                }
            }
            offset = dataStart + compressedSize
        }
    }

    private func extractTar(_ data: Data, to output: URL) throws {
        var offset = 0
        while offset + 512 <= data.count {
            let block = data[offset..<offset + 512]
            if block.allSatisfy({ $0 == 0 }) {
                break
            }
            let name = tarString(data, offset: offset, length: 100)
            if name.isEmpty {
                break
            }
            let sizeText = tarString(data, offset: offset + 124, length: 12)
            let size = Int(sizeText.trimmingCharacters(in: .whitespacesAndNewlines), radix: 8) ?? 0
            let typeFlag = data[offset + 156]
            let dataStart = offset + 512
            guard dataStart + size <= data.count else {
                throw NativeScanError.corruptArchive("tar")
            }
            let destination = try safeDestination(root: output, memberName: name)
            if typeFlag == 53 || name.hasSuffix("/") {
                try fileManager.createDirectory(at: destination, withIntermediateDirectories: true)
            } else if typeFlag == 0 || typeFlag == 48 {
                try fileManager.createDirectory(at: destination.deletingLastPathComponent(), withIntermediateDirectories: true)
                try Data(data[dataStart..<dataStart + size]).write(to: destination)
            }
            offset = dataStart + ((size + 511) / 512) * 512
        }
    }

    private func gunzip(_ data: Data, sourceName: String) throws -> Data {
        guard data.count > 18, data[0] == 0x1F, data[1] == 0x8B, data[2] == 8 else {
            throw NativeScanError.corruptArchive(sourceName)
        }
        let flags = data[3]
        var offset = 10
        if flags & 0x04 != 0 {
            guard offset + 2 <= data.count else { throw NativeScanError.corruptArchive(sourceName) }
            let extraLength = Int(data.u16(offset))
            offset += 2 + extraLength
        }
        if flags & 0x08 != 0 {
            while offset < data.count, data[offset] != 0 { offset += 1 }
            offset += 1
        }
        if flags & 0x10 != 0 {
            while offset < data.count, data[offset] != 0 { offset += 1 }
            offset += 1
        }
        if flags & 0x02 != 0 {
            offset += 2
        }
        guard offset < data.count - 8 else {
            throw NativeScanError.corruptArchive(sourceName)
        }
        let expectedSize = Int(data.u32(data.count - 4))
        return try inflate(Data(data[offset..<data.count - 8]), expectedSize: expectedSize, label: sourceName)
    }

    private func inflate(_ data: Data, expectedSize: Int, label: String) throws -> Data {
        if data.isEmpty {
            return Data()
        }
        var outputSize = max(expectedSize, data.count * 4, 1024)
        for _ in 0..<8 {
            var output = [UInt8](repeating: 0, count: outputSize)
            let written = data.withUnsafeBytes { source in
                compression_decode_buffer(
                    &output,
                    output.count,
                    source.bindMemory(to: UInt8.self).baseAddress!,
                    data.count,
                    nil,
                    COMPRESSION_ZLIB
                )
            }
            if written > 0 {
                return Data(output.prefix(written))
            }
            outputSize *= 2
        }
        throw NativeScanError.compressionFailed(label)
    }

    private func safeDestination(root: URL, memberName: String) throws -> URL {
        let parts = memberName.split(separator: "/").map(String.init).filter { !$0.isEmpty && $0 != "." }
        if parts.contains("..") {
            throw NativeScanError.unsafeArchivePath(memberName)
        }
        var destination = root
        for part in parts {
            destination.appendPathComponent(part)
        }
        let rootPath = root.standardizedFileURL.path
        let destinationPath = destination.standardizedFileURL.path
        guard destinationPath == rootPath || destinationPath.hasPrefix(rootPath + "/") else {
            throw NativeScanError.unsafeArchivePath(memberName)
        }
        return destination
    }

    private func isArchive(_ url: URL) -> Bool {
        let name = url.lastPathComponent.lowercased()
        return [".zip", ".jar", ".war", ".ear", ".tar", ".tar.gz", ".tgz", ".gz"].contains { name.hasSuffix($0) }
    }

    private func isDirectory(_ url: URL) -> Bool {
        (try? url.resourceValues(forKeys: [.isDirectoryKey]).isDirectory) == true
    }

    private func relativePath(_ url: URL, root: URL) -> String {
        let rootPath = root.standardizedFileURL.path
        let path = url.standardizedFileURL.path
        if path.hasPrefix(rootPath + "/") {
            return String(path.dropFirst(rootPath.count + 1))
        }
        return url.lastPathComponent
    }

    private func finding(
        _ ruleID: String,
        _ severity: String,
        _ category: String,
        _ title: String,
        _ path: String,
        _ line: Int?,
        _ evidence: String,
        _ recommendation: String
    ) -> NativeFinding {
        NativeFinding(
            ruleID: ruleID,
            severity: severity,
            category: category,
            title: title,
            path: path,
            line: line,
            evidence: String(evidence.trimmingCharacters(in: .whitespacesAndNewlines).prefix(220)),
            recommendation: recommendation
        )
    }

    private func severityRank(_ severity: String) -> Int {
        switch severity {
        case "critical": return 5
        case "high": return 4
        case "medium": return 3
        case "low": return 2
        default: return 1
        }
    }
}

private func matches(_ pattern: String, _ text: String) -> Bool {
    guard let regex = try? NSRegularExpression(pattern: pattern) else { return false }
    let range = NSRange(text.startIndex..<text.endIndex, in: text)
    return regex.firstMatch(in: text, range: range) != nil
}

private func redact(_ line: String) -> String {
    line.replacingOccurrences(of: #"sk-[A-Za-z0-9_\-]{8,}"#, with: "sk-[redacted]", options: .regularExpression)
}

private func tarString(_ data: Data, offset: Int, length: Int) -> String {
    guard offset < data.count else { return "" }
    let end = min(offset + length, data.count)
    let bytes = data[offset..<end].prefix { $0 != 0 }
    return String(data: Data(bytes), encoding: .utf8) ?? ""
}

private extension Data {
    func u16(_ offset: Int) -> UInt16 {
        UInt16(self[offset]) | UInt16(self[offset + 1]) << 8
    }

    func u32(_ offset: Int) -> UInt32 {
        UInt32(self[offset])
            | UInt32(self[offset + 1]) << 8
            | UInt32(self[offset + 2]) << 16
            | UInt32(self[offset + 3]) << 24
    }
}

private extension NativeSecurityScanner {
    func renderHTML(_ result: NativeScanResult, language: AppLanguage) -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
        let generated = formatter.string(from: result.generatedAt)
        let severityCounts = Dictionary(grouping: result.findings, by: \.severity).mapValues(\.count)
        let severityBars = renderSeverityBars(severityCounts, language: language)
        let rows = result.findings.map { finding in
            """
            <tr>
              <td><span class="badge \(finding.severity.htmlEscaped)">\(severityLabel(finding.severity, language: language))</span></td>
              <td><strong>\(findingTitle(finding, language: language).htmlEscaped)</strong><br><code>\(finding.ruleID.htmlEscaped)</code> | \(categoryLabel(finding.category, language: language).htmlEscaped)</td>
              <td>\(finding.path.htmlEscaped)\(finding.line.map { ":\($0)" } ?? "")</td>
              <td><code>\(finding.evidence.htmlEscaped)</code><br><span>\(findingRecommendation(finding, language: language).htmlEscaped)</span></td>
            </tr>
            """
        }.joined(separator: "\n")
        let warnings = result.warnings.map { "<li>\(warningText($0, language: language).htmlEscaped)</li>" }.joined(separator: "\n")
        let pageTitle = reportLabel("pageTitle", language: language)

        return """
        <!doctype html>
        <html lang="\(language.rawValue)">
        <head>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width, initial-scale=1">
          <title>\(pageTitle.htmlEscaped)</title>
          <style>
            :root { color-scheme: light dark; --ink:#111827; --muted:#667085; --line:#d8dee9; --bg:#f5f7fb; --card:#ffffff; --thead:#f8fafc; --code:#475467; --track:#e9eef5; --warning:#92400e; }
            @media (prefers-color-scheme: dark) {
              :root { --ink:#f8fafc; --muted:#a8b3c7; --line:#334155; --bg:#0f172a; --card:#111827; --thead:#172033; --code:#cbd5e1; --track:#263244; --warning:#fbbf24; }
            }
            html { background:var(--bg); }
            body { margin:0; font-family:-apple-system,BlinkMacSystemFont,"Apple SD Gothic Neo",sans-serif; background:var(--bg); color:var(--ink); }
            header { background:#0b1220; color:white; padding:28px 36px; }
            main { padding:28px 36px 44px; }
            h1 { margin:0 0 8px; font-size:34px; }
            .meta { color:#cbd5e1; }
            .grid { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:14px; margin:22px 0; }
            .card { background:var(--card); border:1px solid var(--line); border-radius:8px; padding:18px; }
            .label { color:var(--muted); font-weight:700; }
            .value { font-size:34px; font-weight:800; margin-top:8px; }
            .risk-panel { display:grid; grid-template-columns:1fr 1.2fr; gap:14px; margin:0 0 22px; }
            .risk-copy { color:var(--muted); line-height:1.55; margin:8px 0 0; }
            .bars { display:grid; gap:10px; }
            .bar-row { display:grid; grid-template-columns:72px 1fr 42px; align-items:center; gap:10px; }
            .bar-label { color:var(--muted); font-weight:700; }
            .bar-track { height:11px; border-radius:999px; background:var(--track); overflow:hidden; }
            .bar-fill { height:100%; border-radius:999px; min-width:0; }
            .bar-count { text-align:right; font-variant-numeric:tabular-nums; font-weight:800; }
            table { width:100%; border-collapse:collapse; background:var(--card); border:1px solid var(--line); border-radius:8px; overflow:hidden; }
            th,td { text-align:left; vertical-align:top; border-bottom:1px solid var(--line); padding:13px 14px; }
            th { color:var(--muted); background:var(--thead); font-size:13px; }
            code { color:var(--code); white-space:pre-wrap; word-break:break-word; }
            .badge { display:inline-block; min-width:68px; text-align:center; border-radius:999px; padding:7px 10px; font-weight:800; }
            .critical { background:#7f1d1d; color:white; }
            .high { background:#b42318; color:white; }
            .medium { background:#b7791f; color:white; }
            .low { background:#2563eb; color:white; }
            .info { background:#475467; color:white; }
            .warnings { margin:18px 0; color:var(--warning); }
            @media (max-width: 900px) { .grid,.risk-panel { grid-template-columns:1fr; } table { font-size:14px; } }
          </style>
        </head>
        <body>
          <header>
            <h1>\(pageTitle.htmlEscaped)</h1>
            <div class="meta">\(reportLabel("generatedAt", language: language).htmlEscaped) \(generated.htmlEscaped) | \(reportLabel("targets", language: language).htmlEscaped) \(result.targetCount) | \(reportLabel("scannedFiles", language: language).htmlEscaped) \(result.scannedFileCount)</div>
          </header>
          <main>
            <section class="grid">
              <div class="card"><div class="label">\(reportLabel("riskScore", language: language).htmlEscaped)</div><div class="value">\(result.riskScore)</div></div>
              <div class="card"><div class="label">\(reportLabel("criticalHigh", language: language).htmlEscaped)</div><div class="value">\((severityCounts["critical"] ?? 0) + (severityCounts["high"] ?? 0))</div></div>
              <div class="card"><div class="label">\(severityLabel("medium", language: language).htmlEscaped)</div><div class="value">\(severityCounts["medium"] ?? 0)</div></div>
              <div class="card"><div class="label">\(reportLabel("lowInfo", language: language).htmlEscaped)</div><div class="value">\((severityCounts["low"] ?? 0) + (severityCounts["info"] ?? 0))</div></div>
            </section>
            <section class="risk-panel">
              <div class="card">
                <div class="label">\(reportLabel("riskFormula", language: language).htmlEscaped)</div>
                <p class="risk-copy">\(riskFormula(language: language).htmlEscaped)</p>
              </div>
              <div class="card">
                <div class="label">\(reportLabel("severityDistribution", language: language).htmlEscaped)</div>
                <div class="bars">\(severityBars)</div>
              </div>
            </section>
            \(warnings.isEmpty ? "" : "<section class=\"warnings\"><strong>\(reportLabel("warnings", language: language).htmlEscaped)</strong><ul>\(warnings)</ul></section>")
            <table>
              <thead><tr><th>\(reportLabel("severity", language: language).htmlEscaped)</th><th>\(reportLabel("finding", language: language).htmlEscaped)</th><th>\(reportLabel("path", language: language).htmlEscaped)</th><th>\(reportLabel("evidenceAction", language: language).htmlEscaped)</th></tr></thead>
              <tbody>\(rows.isEmpty ? "<tr><td colspan=\"4\">\(reportLabel("noFindings", language: language).htmlEscaped)</td></tr>" : rows)</tbody>
            </table>
          </main>
        </body>
        </html>
        """
    }

    func renderMarkdown(_ result: NativeScanResult, language: AppLanguage) -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
        let generated = formatter.string(from: result.generatedAt)
        let severityCounts = Dictionary(grouping: result.findings, by: \.severity).mapValues(\.count)
        let warningBlock = result.warnings.isEmpty
            ? ""
            : "\n## \(reportLabel("warnings", language: language))\n\n"
                + result.warnings.map { "- \(warningText($0, language: language))" }.joined(separator: "\n")
                + "\n"
        let rows = result.findings.map { finding in
            let columns = [
                severityLabel(finding.severity, language: language),
                findingTitle(finding, language: language),
                finding.ruleID,
                categoryLabel(finding.category, language: language),
                "\(finding.path)\(finding.line.map { ":\($0)" } ?? "")",
                finding.evidence,
                findingRecommendation(finding, language: language),
            ].map(\.markdownCellEscaped).joined(separator: " | ")
            return "| \(columns) |"
        }.joined(separator: "\n")
        let findingRows = rows.isEmpty
            ? "| \(reportLabel("noFindings", language: language).markdownCellEscaped) |  |  |  |  |  |  |"
            : rows

        return """
        # \(reportLabel("pageTitle", language: language))

        - \(reportLabel("generatedAt", language: language)): \(generated)
        - \(reportLabel("targets", language: language)): \(result.targetCount)
        - \(reportLabel("scannedFiles", language: language)): \(result.scannedFileCount)
        - \(reportLabel("riskScore", language: language)): \(result.riskScore)

        ## \(reportLabel("riskFormula", language: language))

        \(riskFormula(language: language))

        ## \(reportLabel("severityDistribution", language: language))

        - \(severityLabel("critical", language: language)): \(severityCounts["critical"] ?? 0)
        - \(severityLabel("high", language: language)): \(severityCounts["high"] ?? 0)
        - \(severityLabel("medium", language: language)): \(severityCounts["medium"] ?? 0)
        - \(severityLabel("low", language: language)): \(severityCounts["low"] ?? 0)
        - \(severityLabel("info", language: language)): \(severityCounts["info"] ?? 0)
        \(warningBlock)
        ## \(reportLabel("findings", language: language))

        | \(reportLabel("severity", language: language)) | \(reportLabel("finding", language: language)) | Rule | \(reportLabel("category", language: language)) | \(reportLabel("path", language: language)) | \(reportLabel("evidence", language: language)) | \(reportLabel("recommendation", language: language)) |
        | --- | --- | --- | --- | --- | --- | --- |
        \(findingRows)
        """
    }

    func renderPlainText(_ result: NativeScanResult, language: AppLanguage) -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
        let generated = formatter.string(from: result.generatedAt)
        let severityCounts = Dictionary(grouping: result.findings, by: \.severity).mapValues(\.count)
        let warnings = result.warnings.isEmpty
            ? ""
            : "\n\(reportLabel("warnings", language: language))\n"
                + result.warnings.map { "- \(warningText($0, language: language))" }.joined(separator: "\n")
                + "\n"
        let findings = result.findings.isEmpty
            ? reportLabel("noFindings", language: language)
            : result.findings.enumerated().map { index, finding in
                """
                \(index + 1). [\(severityLabel(finding.severity, language: language))] \(findingTitle(finding, language: language))
                   Rule: \(finding.ruleID)
                   \(reportLabel("category", language: language)): \(categoryLabel(finding.category, language: language))
                   \(reportLabel("path", language: language)): \(finding.path)\(finding.line.map { ":\($0)" } ?? "")
                   \(reportLabel("evidence", language: language)): \(finding.evidence)
                   \(reportLabel("recommendation", language: language)): \(findingRecommendation(finding, language: language))
                """
            }.joined(separator: "\n\n")

        return """
        \(reportLabel("pageTitle", language: language))

        \(reportLabel("generatedAt", language: language)): \(generated)
        \(reportLabel("targets", language: language)): \(result.targetCount)
        \(reportLabel("scannedFiles", language: language)): \(result.scannedFileCount)
        \(reportLabel("riskScore", language: language)): \(result.riskScore)

        \(reportLabel("riskFormula", language: language))
        \(riskFormula(language: language))

        \(reportLabel("severityDistribution", language: language))
        \(severityLabel("critical", language: language)): \(severityCounts["critical"] ?? 0)
        \(severityLabel("high", language: language)): \(severityCounts["high"] ?? 0)
        \(severityLabel("medium", language: language)): \(severityCounts["medium"] ?? 0)
        \(severityLabel("low", language: language)): \(severityCounts["low"] ?? 0)
        \(severityLabel("info", language: language)): \(severityCounts["info"] ?? 0)
        \(warnings)
        \(reportLabel("findings", language: language))
        \(findings)
        """
    }

    func severityLabel(_ severity: String, language: AppLanguage) -> String {
        switch (language, severity) {
        case (.ko, "critical"): return "치명"
        case (.ko, "high"): return "높음"
        case (.ko, "medium"): return "중간"
        case (.ko, "low"): return "낮음"
        case (.ko, _): return "정보"
        case (.en, "critical"): return "Critical"
        case (.en, "high"): return "High"
        case (.en, "medium"): return "Medium"
        case (.en, "low"): return "Low"
        case (.en, _): return "Info"
        }
    }

    func renderSeverityBars(_ counts: [String: Int], language: AppLanguage) -> String {
        let entries = [
            ("critical", severityLabel("critical", language: language), "#7f1d1d"),
            ("high", severityLabel("high", language: language), "#b42318"),
            ("medium", severityLabel("medium", language: language), "#b7791f"),
            ("low", severityLabel("low", language: language), "#2563eb"),
            ("info", severityLabel("info", language: language), "#475467"),
        ]
        let maximum = max(entries.map { counts[$0.0] ?? 0 }.max() ?? 0, 1)
        return entries.map { severity, label, color in
            let count = counts[severity] ?? 0
            let width = count == 0 ? 0 : max(3, Int((Double(count) / Double(maximum)) * 100))
            return """
            <div class="bar-row">
              <div class="bar-label">\(label)</div>
              <div class="bar-track"><div class="bar-fill" style="width:\(width)%; background:\(color);"></div></div>
              <div class="bar-count">\(count)</div>
            </div>
            """
        }.joined(separator: "\n")
    }

    func reportLabel(_ key: String, language: AppLanguage) -> String {
        let ko = [
            "pageTitle": "KODA 보안 점검 리포트",
            "generatedAt": "생성 시각",
            "targets": "점검 대상",
            "scannedFiles": "스캔 파일",
            "riskScore": "위험 점수",
            "criticalHigh": "치명/높음",
            "lowInfo": "낮음/정보",
            "riskFormula": "위험점수 계산",
            "severityDistribution": "위험군별 분포",
            "warnings": "경고",
            "severity": "심각도",
            "finding": "발견 항목",
            "findings": "발견 항목",
            "path": "경로",
            "category": "분류",
            "evidence": "근거",
            "recommendation": "조치",
            "evidenceAction": "근거 / 조치",
            "noFindings": "발견 항목이 없습니다.",
        ]
        let en = [
            "pageTitle": "KODA Security Scan Report",
            "generatedAt": "Generated",
            "targets": "Targets",
            "scannedFiles": "Scanned Files",
            "riskScore": "Risk Score",
            "criticalHigh": "Critical/High",
            "lowInfo": "Low/Info",
            "riskFormula": "Risk Score Formula",
            "severityDistribution": "Severity Distribution",
            "warnings": "Warnings",
            "severity": "Severity",
            "finding": "Finding",
            "findings": "Findings",
            "path": "Path",
            "category": "Category",
            "evidence": "Evidence",
            "recommendation": "Recommendation",
            "evidenceAction": "Evidence / Action",
            "noFindings": "No findings.",
        ]
        return (language == .ko ? ko : en)[key] ?? key
    }

    func riskFormula(language: AppLanguage) -> String {
        switch language {
        case .ko:
            return "위험 점수는 치명 100점, 높음 40점, 중간 10점, 낮음 3점, 정보 1점을 발견 항목별로 더한 값입니다."
        case .en:
            return "Risk score is the sum of each finding: critical 100, high 40, medium 10, low 3, and info 1."
        }
    }

    func categoryLabel(_ category: String, language: AppLanguage) -> String {
        guard language == .en else { return category }
        switch category {
        case "secrets": return "Secrets"
        case "dependencies": return "Dependencies"
        case "configuration": return "Configuration"
        case "code": return "Code Pattern"
        default: return category
        }
    }

    func findingTitle(_ finding: NativeFinding, language: AppLanguage) -> String {
        guard language == .en else { return finding.title }
        switch finding.ruleID {
        case "secret.private-key": return "Private key embedded in a file"
        case "secret.openai-key": return "Possible API key found"
        case "secret.generic-assignment": return "Possible hard-coded secret assignment"
        case "dependency.python-unpinned-requirement": return "Unpinned Python dependency"
        case "dependency.node-missing-lockfile": return "Node lockfile missing"
        case "dependency.node-unbounded-version": return "Unbounded Node dependency version"
        case "dependency.remote-shell-install": return "Remote install script executed immediately"
        case "dependency.container-latest-tag": return "Container image uses latest tag"
        case "config.env-file-present": return "Environment file present in project"
        case "config.debug-enabled": return "Debug setting enabled"
        case "config.compose-privileged": return "Privileged container configuration"
        case "code.xss-dom-sink": return "DOM XSS sink risk"
        case "code.sql-dynamic-query": return "Dynamic SQL query construction"
        case "code.command-injection": return "Command injection risk"
        case "code.path-traversal": return "Path traversal risk"
        case "code.unsafe-deserialization": return "Unsafe deserialization"
        case "code.insecure-temp-file": return "Insecure temporary file creation"
        case "code.wildcard-cors": return "Wildcard CORS configuration"
        case "code.public-bind-all-interfaces": return "Binds to all network interfaces"
        case "code.weak-hash": return "Weak hash algorithm"
        case "code.insecure-cookie-settings": return "Weak cookie/session security settings"
        case "code.directory-listing-enabled": return "Directory listing enabled"
        case "code.webdav-enabled": return "WebDAV enabled"
        default: return finding.title
        }
    }

    func findingRecommendation(_ finding: NativeFinding, language: AppLanguage) -> String {
        guard language == .en else { return finding.recommendation }
        switch finding.ruleID {
        case "secret.private-key":
            return "Revoke the private key immediately and move it to a secure secrets manager."
        case "secret.openai-key":
            return "Revoke the key and use environment variables or a secrets manager."
        case "secret.generic-assignment":
            return "Do not keep secret values in source code; inject them at runtime."
        case "dependency.python-unpinned-requirement":
            return "Pin exact versions and run dependency vulnerability checks regularly."
        case "dependency.node-missing-lockfile":
            return "Commit a lockfile to keep dependency installation reproducible."
        case "dependency.node-unbounded-version":
            return "Use verified version ranges or a lockfile."
        case "dependency.remote-shell-install":
            return "Verify downloads and checksums before execution."
        case "dependency.container-latest-tag":
            return "Use immutable image tags or digests."
        case "config.env-file-present":
            return "Check for secrets and exclude this file from the repository."
        case "config.debug-enabled":
            return "Disable debug settings for production builds."
        case "config.compose-privileged":
            return "Remove privileged mode and grant only required capabilities."
        case "code.xss-dom-sink":
            return "Do not inject untrusted input as HTML; escape it or use textContent."
        case "code.sql-dynamic-query":
            return "Use parameter binding or safe ORM APIs."
        case "code.command-injection":
            return "Avoid shell execution, pass arguments as arrays, and validate input with allowlists."
        case "code.path-traversal":
            return "Normalize user paths and verify they stay inside an allowed root."
        case "code.unsafe-deserialization":
            return "Do not deserialize untrusted input; use safe loaders."
        case "code.insecure-temp-file":
            return "Use safe temporary-file APIs to avoid race conditions."
        case "code.wildcard-cors":
            return "Restrict allowed origins explicitly."
        case "code.public-bind-all-interfaces":
            return "Bind development servers to localhost only."
        case "code.weak-hash":
            return "Use SHA-256 or stronger; for passwords use bcrypt or argon2."
        case "code.insecure-cookie-settings":
            return "Set Secure, HttpOnly, and SameSite attributes appropriately."
        case "code.directory-listing-enabled":
            return "Disable directory indexing."
        case "code.webdav-enabled":
            return "Disable WebDAV unless it is explicitly required."
        default:
            return finding.recommendation
        }
    }

    func warningText(_ warning: String, language: AppLanguage) -> String {
        guard language == .en else { return warning }
        if warning.hasPrefix("대상이 존재하지 않습니다:") {
            return warning.replacingOccurrences(of: "대상이 존재하지 않습니다:", with: "Target does not exist:")
        }
        if warning.hasPrefix("디렉터리를 열 수 없습니다:") {
            return warning.replacingOccurrences(of: "디렉터리를 열 수 없습니다:", with: "Cannot open directory:")
        }
        if warning.hasPrefix("압축파일에 안전하지 않은 경로가 있습니다:") {
            return warning.replacingOccurrences(of: "압축파일에 안전하지 않은 경로가 있습니다:", with: "Archive contains an unsafe path:")
        }
        if warning.hasPrefix("지원하지 않는 압축 형식입니다:") {
            return warning.replacingOccurrences(of: "지원하지 않는 압축 형식입니다:", with: "Unsupported archive format:")
        }
        if warning.hasPrefix("압축파일을 읽을 수 없습니다:") {
            return warning.replacingOccurrences(of: "압축파일을 읽을 수 없습니다:", with: "Cannot read archive:")
        }
        if warning.hasPrefix("압축 해제에 실패했습니다:") {
            return warning.replacingOccurrences(of: "압축 해제에 실패했습니다:", with: "Archive extraction failed:")
        }
        return warning
    }
}

private extension String {
    var htmlEscaped: String {
        replacingOccurrences(of: "&", with: "&amp;")
            .replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;")
            .replacingOccurrences(of: "\"", with: "&quot;")
            .replacingOccurrences(of: "'", with: "&#39;")
    }

    var markdownCellEscaped: String {
        replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "|", with: "\\|")
            .replacingOccurrences(of: "\n", with: " ")
            .replacingOccurrences(of: "\r", with: " ")
    }
}
