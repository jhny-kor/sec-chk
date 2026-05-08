import SwiftUI

struct ContentView: View {
    @StateObject private var scanner = ScannerBridge()

    var body: some View {
        VStack(alignment: .leading, spacing: 24) {
            header

            VStack(alignment: .leading, spacing: 14) {
                Text("점검 대상")
                    .font(.headline)

                HStack(spacing: 12) {
                    Text(scanner.selectedFolder?.path ?? "선택된 폴더 없음")
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.horizontal, 12)
                        .padding(.vertical, 10)
                        .background(Color(nsColor: .textBackgroundColor))
                        .clipShape(RoundedRectangle(cornerRadius: 8))

                    Button("폴더 선택") {
                        scanner.chooseFolder()
                    }
                }

                HStack(spacing: 12) {
                    Button(scanner.isRunning ? "점검 중" : "보안 점검 실행") {
                        scanner.runScan()
                    }
                    .keyboardShortcut(.defaultAction)
                    .disabled(scanner.selectedFolder == nil || scanner.isRunning)

                    Button("리포트 열기") {
                        scanner.openReport()
                    }
                    .disabled(scanner.reportURL == nil)
                }
            }

            VStack(alignment: .leading, spacing: 8) {
                Text("상태")
                    .font(.headline)
                Text(scanner.statusMessage)
                    .foregroundStyle(scanner.statusColor)
                    .textSelection(.enabled)
            }

            if !scanner.detailMessage.isEmpty {
                ScrollView {
                    Text(scanner.detailMessage)
                        .font(.system(.body, design: .monospaced))
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .textSelection(.enabled)
                }
                .frame(maxHeight: 180)
                .padding(12)
                .background(Color(nsColor: .textBackgroundColor))
                .clipShape(RoundedRectangle(cornerRadius: 8))
            }

            Spacer()
        }
        .padding(28)
    }

    private var header: some View {
        HStack(alignment: .center, spacing: 16) {
            Image(nsImage: NSApp.applicationIconImage)
                .resizable()
                .frame(width: 64, height: 64)
                .clipShape(RoundedRectangle(cornerRadius: 14))

            VStack(alignment: .leading, spacing: 6) {
                Text("KODA")
                    .font(.system(size: 34, weight: .bold))
                Text("로컬 프로젝트 보안 점검")
                    .font(.title3)
                    .foregroundStyle(.secondary)
            }
        }
    }
}
