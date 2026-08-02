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

App Store 아카이브는 `KODA_APP_STORE` Swift 조건으로 빌드됩니다. 네이티브 웹
점검은 GET/HEAD 기반 read-only만 허용하고, 로그인 POST·능동 probe·ZAP·상태 변경
시나리오는 실행하지 않습니다. 전체 21개 프로필 점검은 공유 Python CLI 또는
직접배포판에서 실행해야 하며, App Store판의 미지원 항목은 PASS가 아닌
`UNSUPPORTED`/검토 상태로 남깁니다.

배포 경계는 다음과 같습니다.

| 배포판 | 웹 21개 항목 | 실행 경계 |
| --- | --- | --- |
| macOS 직접배포판/공유 Python | 지원 | `web-audit`의 profile·approval·nonce 게이트 적용 |
| App Store판 | 부분 지원 | GET/HEAD native read-only만 허용; POST·능동 probe·ZAP·상태 변경은 실행하지 않음 |

직접배포판에서 점검할 때는 저장소 루트에서 `PYTHONPATH`를 지정하고 먼저
`web-audit run --dry-run`을 실행하세요. ZAP/Playwright/BOAST는 앱이 자동으로
내려받지 않으며 사전 설치·digest·manifest가 없으면 PASS 대신 capability 상태가
반환됩니다. App Store판에서 `state_change` 또는 GET/HEAD 이외 메서드를 프로필에
선언하면 프로필 검증 단계에서 거부됩니다.

서명된 앱의 App Sandbox와 오프라인 JAR 스모크 테스트를 제출 전에 확인하세요.

- [한국어 문서 인덱스](../../../docs/README.md)
- [English macOS packaging guide](README.md)
