import Foundation

struct BundledJavaScanOutcome {
    let exitCode: Int32
    let sbomURL: URL
    let componentCount: Int
    let vulnerabilityCount: Int
    let detail: String
}

enum BundledJavaArchiveScanner {
    private static let archiveExtensions = Set(["jar", "war", "ear"])

    static func scan(targets: [URL], outputDirectory: URL) throws -> BundledJavaScanOutcome {
        guard !targets.isEmpty else {
            throw JavaScanError.noTargets
        }

        let assets = try paths()
        try FileManager.default.createDirectory(at: outputDirectory, withIntermediateDirectories: true)
        let stagingDirectory = try stagingDirectory()
        defer { try? FileManager.default.removeItem(at: stagingDirectory) }

        let accessedTargets = targets.filter { $0.startAccessingSecurityScopedResource() }
        defer { accessedTargets.forEach { $0.stopAccessingSecurityScopedResource() } }
        try stage(targets: targets, in: stagingDirectory)

        let databaseCache = try databaseCacheDirectory()
        try importDatabaseIfNeeded(grype: assets.grype, archive: assets.databaseArchive, cache: databaseCache)

        let result = try run(
            executable: assets.scanner,
            arguments: ["jar-scan", "--target", stagingDirectory.path, "--output-dir", outputDirectory.path],
            environment: [
                "KODA_SYFT_BIN": assets.syft.path,
                "KODA_GRYPE_BIN": assets.grype.path,
                "KODA_NVD_DATA": assets.nvdDirectory.path,
                "KODA_CISA_KEV": assets.cisaKEV.path,
                "GRYPE_DB_CACHE_DIR": databaseCache.path,
                "GRYPE_DB_AUTO_UPDATE": "false",
                "GRYPE_DB_VALIDATE_AGE": "false",
            ]
        )
        let sbomURL = outputDirectory.appendingPathComponent("server-sbom.cdx.json")
        guard FileManager.default.fileExists(atPath: sbomURL.path) else {
            throw JavaScanError.missingSBOM(result.stderr)
        }
        return BundledJavaScanOutcome(
            exitCode: result.exitCode,
            sbomURL: sbomURL,
            componentCount: componentCount(in: sbomURL),
            vulnerabilityCount: vulnerabilityCount(in: outputDirectory.appendingPathComponent("server-vulnerabilities.json")),
            detail: [result.stdout, result.stderr].filter { !$0.isEmpty }.joined(separator: "\n")
        )
    }

    private static func paths() throws -> AssetPaths {
        let contents = Bundle.main.bundleURL.appendingPathComponent("Contents", isDirectory: true)
        let resources = contents.appendingPathComponent("Resources/java-scan", isDirectory: true)
        let helpers = contents.appendingPathComponent("Helpers", isDirectory: true)
        let tools = helpers.appendingPathComponent("java-scan-tools/\(architecture)", isDirectory: true)
        let databaseDirectory = resources.appendingPathComponent("grype-db/incoming", isDirectory: true)
        guard let databaseArchive = try FileManager.default.contentsOfDirectory(at: databaseDirectory, includingPropertiesForKeys: nil).first(where: { $0.pathExtension == "zst" }) else {
            throw JavaScanError.missingAsset(databaseDirectory.path)
        }
        let paths = AssetPaths(
            scanner: helpers.appendingPathComponent("koda-java-scan-\(architecture).app/Contents/MacOS/koda-java-scan"),
            syft: tools.appendingPathComponent("syft"),
            grype: tools.appendingPathComponent("grype"),
            databaseArchive: databaseArchive,
            nvdDirectory: resources.appendingPathComponent("vuln-data/nvd", isDirectory: true),
            cisaKEV: resources.appendingPathComponent("vuln-data/known_exploited_vulnerabilities.json")
        )
        for path in [paths.scanner, paths.syft, paths.grype, paths.nvdDirectory, paths.cisaKEV] where !FileManager.default.fileExists(atPath: path.path) {
            throw JavaScanError.missingAsset(path.path)
        }
        return paths
    }

    private static func stagingDirectory() throws -> URL {
        let cache = try FileManager.default.url(for: .cachesDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
        let directory = cache.appendingPathComponent("java-scan/\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        return directory
    }

    private static func databaseCacheDirectory() throws -> URL {
        let support = try FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true)
        let directory = support.appendingPathComponent("com.jhnykor.koda/java-scan/grype-db", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        return directory
    }

    private static func stage(targets: [URL], in directory: URL) throws {
        for (index, target) in targets.enumerated() {
            let destination = directory.appendingPathComponent("\(index)-\(target.lastPathComponent)")
            try FileManager.default.copyItem(at: target, to: destination)
        }
    }

    private static func importDatabaseIfNeeded(grype: URL, archive: URL, cache: URL) throws {
        let marker = cache.appendingPathComponent(".koda-imported-\(archive.lastPathComponent)")
        guard !FileManager.default.fileExists(atPath: marker.path) else {
            return
        }
        let result = try run(
            executable: grype,
            arguments: ["db", "import", archive.path],
            environment: [
                "GRYPE_DB_CACHE_DIR": cache.path,
                "GRYPE_DB_AUTO_UPDATE": "false",
                "GRYPE_DB_VALIDATE_AGE": "false",
            ]
        )
        guard result.exitCode == 0 else {
            throw JavaScanError.databaseImport(result.stderr)
        }
        try Data().write(to: marker, options: .atomic)
    }

    private static func run(executable: URL, arguments: [String], environment: [String: String]) throws -> ProcessResult {
        let process = Process()
        let stdout = Pipe()
        let stderr = Pipe()
        process.executableURL = executable
        process.arguments = arguments
        process.environment = ProcessInfo.processInfo.environment.merging(environment) { _, replacement in replacement }
        process.standardOutput = stdout
        process.standardError = stderr
        try process.run()
        process.waitUntilExit()
        return ProcessResult(
            exitCode: process.terminationStatus,
            stdout: String(decoding: stdout.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self),
            stderr: String(decoding: stderr.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        )
    }

    private static func componentCount(in sbom: URL) -> Int {
        jsonArrayCount(in: sbom, key: "components")
    }

    private static func vulnerabilityCount(in report: URL) -> Int {
        jsonArrayCount(in: report, key: "vulnerabilities")
    }

    private static func jsonArrayCount(in file: URL, key: String) -> Int {
        guard let data = try? Data(contentsOf: file),
              let payload = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let values = payload[key] as? [Any] else {
            return 0
        }
        return values.count
    }

    private static var architecture: String {
        #if arch(arm64)
        return "arm64"
        #elseif arch(x86_64)
        return "amd64"
        #else
        return "unsupported"
        #endif
    }
}

private struct AssetPaths {
    let scanner: URL
    let syft: URL
    let grype: URL
    let databaseArchive: URL
    let nvdDirectory: URL
    let cisaKEV: URL
}

private struct ProcessResult {
    let exitCode: Int32
    let stdout: String
    let stderr: String
}

private enum JavaScanError: LocalizedError {
    case noTargets
    case missingAsset(String)
    case databaseImport(String)
    case missingSBOM(String)

    var errorDescription: String? {
        switch self {
        case .noTargets:
            return "No JAR, WAR, or EAR target was selected."
        case .missingAsset(let path):
            return "Bundled Java scanner asset is missing: \(path)"
        case .databaseImport(let detail):
            return "Bundled Grype database import failed: \(detail)"
        case .missingSBOM(let detail):
            return "Bundled Java scanner did not generate an SBOM: \(detail)"
        }
    }
}
