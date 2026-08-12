import Darwin
import Foundation

@main
struct KODAHostPostureSelfCheck {
    static func main() {
        if ProcessInfo.processInfo.environment["KODA_LIVE_HOST_CHECK"] == "1" {
            let result = NativeSecurityScanner().scanHost()
            result.findings.forEach { print("\($0.ruleID)\t\($0.evidence)") }
            result.warnings.forEach { print("warning\t\($0)") }
            return
        }

        precondition(
            NativeSecurityScanner.acceptedCommandOutput(
                stdout: "",
                stderr: "Automatic login is disabled.",
                terminationStatus: 0
            ) == "Automatic login is disabled."
        )
        precondition(
            NativeSecurityScanner.acceptedCommandOutput(
                stdout: "",
                stderr: "The domain/default pair does not exist",
                terminationStatus: 1
            ) == nil
        )
        precondition(
            NativeSecurityScanner.acceptedCommandOutput(
                stdout: "Automatic login is enabled.",
                stderr: "",
                terminationStatus: 1
            ) == nil
        )

        setenv("APP_SANDBOX_CONTAINER_ID", "koda-self-check", 1)
        let scanner = NativeSecurityScanner()
        let result = scanner.scanHost()
        let ids = Set(result.findings.map(\.ruleID))

        precondition(!ids.contains("host.macos.filevault-off"))
        precondition(!ids.contains("host.macos.auto-login-enabled"))
        precondition(!ids.contains("host.macos.screen-lock-disabled"))
        precondition(ids.contains("host.macos.filevault-unverified"))
        precondition(ids.contains("host.macos.auto-login-unverified"))
        precondition(ids.contains("host.macos.screen-lock-unverified"))
        precondition(result.findings.filter { $0.verificationStatus == "unverified" }.count == 9)
        precondition(scanner.markdownReport(result, language: .ko).contains("미확인"))
        precondition(scanner.markdownReport(result, language: .en).contains("Unverified"))

        print("KODA macOS host posture self-check passed")
    }
}
