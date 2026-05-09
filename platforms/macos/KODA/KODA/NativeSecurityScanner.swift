import Compression
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

    func writeHTMLReport(_ result: NativeScanResult, to output: URL) throws {
        try renderHTML(result).write(to: output, atomically: true, encoding: .utf8)
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
    func renderHTML(_ result: NativeScanResult) -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
        let generated = formatter.string(from: result.generatedAt)
        let severityCounts = Dictionary(grouping: result.findings, by: \.severity).mapValues(\.count)
        let severityBars = renderSeverityBars(severityCounts)
        let rows = result.findings.map { finding in
            """
            <tr>
              <td><span class="badge \(finding.severity.htmlEscaped)">\(severityLabel(finding.severity))</span></td>
              <td><strong>\(finding.title.htmlEscaped)</strong><br><code>\(finding.ruleID.htmlEscaped)</code> | \(finding.category.htmlEscaped)</td>
              <td>\(finding.path.htmlEscaped)\(finding.line.map { ":\($0)" } ?? "")</td>
              <td><code>\(finding.evidence.htmlEscaped)</code><br><span>\(finding.recommendation.htmlEscaped)</span></td>
            </tr>
            """
        }.joined(separator: "\n")
        let warnings = result.warnings.map { "<li>\($0.htmlEscaped)</li>" }.joined(separator: "\n")

        return """
        <!doctype html>
        <html lang="ko">
        <head>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width, initial-scale=1">
          <title>KODA 보안 점검 리포트</title>
          <style>
            :root { color-scheme: light; --ink:#111827; --muted:#667085; --line:#d8dee9; --bg:#f5f7fb; --card:#ffffff; }
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
            .bar-track { height:11px; border-radius:999px; background:#e9eef5; overflow:hidden; }
            .bar-fill { height:100%; border-radius:999px; min-width:0; }
            .bar-count { text-align:right; font-variant-numeric:tabular-nums; font-weight:800; }
            table { width:100%; border-collapse:collapse; background:var(--card); border:1px solid var(--line); border-radius:8px; overflow:hidden; }
            th,td { text-align:left; vertical-align:top; border-bottom:1px solid var(--line); padding:13px 14px; }
            th { color:var(--muted); background:#f8fafc; font-size:13px; }
            code { color:#475467; white-space:pre-wrap; word-break:break-word; }
            .badge { display:inline-block; min-width:68px; text-align:center; border-radius:999px; padding:7px 10px; font-weight:800; }
            .critical { background:#7f1d1d; color:white; }
            .high { background:#b42318; color:white; }
            .medium { background:#b7791f; color:white; }
            .low { background:#2563eb; color:white; }
            .info { background:#475467; color:white; }
            .warnings { margin:18px 0; color:#92400e; }
            @media (max-width: 900px) { .grid,.risk-panel { grid-template-columns:1fr; } table { font-size:14px; } }
          </style>
        </head>
        <body>
          <header>
            <h1>KODA 보안 점검 리포트</h1>
            <div class="meta">생성 시각 \(generated.htmlEscaped) | 점검 대상 \(result.targetCount) | 스캔 파일 \(result.scannedFileCount)</div>
          </header>
          <main>
            <section class="grid">
              <div class="card"><div class="label">위험 점수</div><div class="value">\(result.riskScore)</div></div>
              <div class="card"><div class="label">치명/높음</div><div class="value">\((severityCounts["critical"] ?? 0) + (severityCounts["high"] ?? 0))</div></div>
              <div class="card"><div class="label">중간</div><div class="value">\(severityCounts["medium"] ?? 0)</div></div>
              <div class="card"><div class="label">낮음/정보</div><div class="value">\((severityCounts["low"] ?? 0) + (severityCounts["info"] ?? 0))</div></div>
            </section>
            <section class="risk-panel">
              <div class="card">
                <div class="label">위험점수 계산</div>
                <p class="risk-copy">위험 점수는 치명 100점, 높음 40점, 중간 10점, 낮음 3점, 정보 1점을 발견 항목별로 더한 값입니다.</p>
              </div>
              <div class="card">
                <div class="label">위험군별 분포</div>
                <div class="bars">\(severityBars)</div>
              </div>
            </section>
            \(warnings.isEmpty ? "" : "<section class=\"warnings\"><strong>경고</strong><ul>\(warnings)</ul></section>")
            <table>
              <thead><tr><th>심각도</th><th>발견 항목</th><th>경로</th><th>근거 / 조치</th></tr></thead>
              <tbody>\(rows.isEmpty ? "<tr><td colspan=\"4\">발견 항목이 없습니다.</td></tr>" : rows)</tbody>
            </table>
          </main>
        </body>
        </html>
        """
    }

    func severityLabel(_ severity: String) -> String {
        switch severity {
        case "critical": return "치명"
        case "high": return "높음"
        case "medium": return "중간"
        case "low": return "낮음"
        default: return "정보"
        }
    }

    func renderSeverityBars(_ counts: [String: Int]) -> String {
        let entries = [
            ("critical", "치명", "#7f1d1d"),
            ("high", "높음", "#b42318"),
            ("medium", "중간", "#b7791f"),
            ("low", "낮음", "#2563eb"),
            ("info", "정보", "#475467"),
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
}

private extension String {
    var htmlEscaped: String {
        replacingOccurrences(of: "&", with: "&amp;")
            .replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;")
            .replacingOccurrences(of: "\"", with: "&quot;")
            .replacingOccurrences(of: "'", with: "&#39;")
    }
}
