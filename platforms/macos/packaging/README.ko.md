# KODA macOS App Store 패키징

이 폴더는 KODA 네이티브 SwiftUI 앱의 App Store 패키징 경로를 담습니다.

## 포함 항목

- App Store 아이콘·샌드박스 entitlements
- `platforms/macos/app/KODA/KODA.xcodeproj` 네이티브 프로젝트
- 오프라인 Java 스캐너 자산을 포함하는 Xcode 빌드 스크립트
- App Store 아카이브 및 서명 검증 스크립트

## 로컬 빌드

```zsh
platforms/macos/scripts/build-koda-xcode-app.command
```

결과는 `dist/macos/KODA.app`에 생성됩니다. Java 메뉴는 내장 Python helper,
Syft, Grype, Grype DB, NVD, CISA KEV를 사용하며 앱 실행 중 다운로드하지
않습니다. Intel 빌드는 Intel Mac에서 별도로 만들고
`KODA_MACOS_ARCHS=x86_64`를 지정해야 합니다.

App Store용 Java helper에는 명령줄 스캔 경로만 포함하며 대시보드 서버와
Tk 폴더 선택기 모듈은 제외합니다. 이 제외 설정은 공유 Python, Windows,
Linux 및 레거시 macOS 앱 빌드에는 적용되지 않습니다.

App Store 제출은 다음 경로를 사용합니다.

```zsh
platforms/macos/scripts/archive-koda-app-store.command
```

서명된 앱의 App Sandbox와 오프라인 JAR 스모크 테스트를 제출 전에 확인하세요.

- [한국어 문서 인덱스](../../../docs/README.md)
- [English macOS packaging guide](README.md)
