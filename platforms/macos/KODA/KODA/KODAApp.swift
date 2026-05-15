import Darwin
import Foundation
import SwiftUI

@main
struct KODAApp: App {
    init() {
        runHeadlessScanIfRequested()
    }

    var body: some Scene {
        WindowGroup {
            ContentView()
                .frame(minWidth: 760, minHeight: 520)
        }
        .commands {
            CommandGroup(replacing: .newItem) {}
        }
    }

    private func runHeadlessScanIfRequested() {
        let environment = ProcessInfo.processInfo.environment
        guard let targetValue = environment["KODA_SCAN_TARGETS"], !targetValue.isEmpty else {
            return
        }

        let targets = targetValue
            .split(separator: "\n")
            .map { URL(fileURLWithPath: String($0)) }
        let output: URL
        if let outputValue = environment["KODA_SCAN_OUTPUT"], !outputValue.isEmpty {
            output = URL(fileURLWithPath: outputValue)
        } else {
            output = URL(fileURLWithPath: NSTemporaryDirectory())
                .appendingPathComponent("KODA-headless-security-dashboard.html")
        }

        do {
            let scanner = NativeSecurityScanner()
            let result = try scanner.scan(targets: targets)
            let language: AppLanguage = environment["KODA_SCAN_LANGUAGE"] == "en" ? .en : .ko
            try scanner.writeHTMLReport(result, to: output, language: language)
            if let markdownOutput = environment["KODA_SCAN_OUTPUT_MARKDOWN"], !markdownOutput.isEmpty {
                try scanner.writeMarkdownReport(result, to: URL(fileURLWithPath: markdownOutput), language: language)
            }
            if let pdfOutput = environment["KODA_SCAN_OUTPUT_PDF"], !pdfOutput.isEmpty {
                try scanner.writePDFReport(result, to: URL(fileURLWithPath: pdfOutput), language: language)
            }
            print(output.path)
            exit(0)
        } catch {
            fputs("\(error.localizedDescription)\n", stderr)
            exit(2)
        }
    }
}
