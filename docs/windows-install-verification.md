# Windows 설치 가능 여부 로컬 검증 메모

검증 일시: 2026-05-21

## 결론

- 이 저장소는 Windows 설치 파일 빌드를 지원합니다.
- App Store 브랜드명에 맞춘 직접 배포용 설치파일 진입점은 `scripts/build-koda-windows-installer.ps1`입니다.
- 빌드 산출물은 `dist\KODA\KODA.exe`와 `dist\Windows\KODASetup.exe`입니다.
- 설치 대상은 `%LOCALAPPDATA%\KODA`이고, Start Menu `KODA` 바로가기를 생성하도록 구현되어 있습니다.
- 기존 개발자용 소스 설치 진입점은 `archive/windows/legacy-secchk/`로 이동했습니다. 이 경로는 레거시 `SecChk` 런처용이며 현재 KODA 설치 경로에서는 사용하지 않습니다.

## 근거

1. README에 Windows 빌드 절차(Python 3.10+, Inno Setup 6, `build-koda-windows-installer.ps1`)와 KODA 설치 산출물이 문서화되어 있습니다.
2. `build-koda-windows-installer.ps1`는 Windows에서 PyInstaller로 `KODA.exe`를 만들고 Inno Setup으로 `KODASetup.exe`를 생성합니다.
3. `packaging/windows/KODA.iss`는 `%LOCALAPPDATA%\KODA` 설치 경로와 Start Menu/Desktop 바로가기를 정의합니다.

## 이번 로컬(macOS)에서 실제 확인한 항목

- ✅ 테스트 스위트: `python3 -m unittest discover -s tests` (64 tests passed)
- ✅ Python 진입점 구문 확인: `python3 -m compileall scripts/koda-app.py security_scanner/app.py`
- ✅ diff whitespace 검사: `git diff --check`
- ⚠️ PowerShell 구문 파서 실행: `pwsh` 바이너리 부재로 미실행

## 한계

- 현재 환경은 macOS이므로 PyInstaller Windows `.exe`, Inno Setup 컴파일, Windows Start Menu 바로가기 생성 동작은 실제 OS 수준으로 실행 검증할 수 없습니다.
- Windows 설치파일의 최종 실기 검증은 Windows 10/11 + Python 3.10+ + Inno Setup 6 환경에서 `scripts\build-koda-windows-installer.ps1` 실행으로 확인해야 합니다.
