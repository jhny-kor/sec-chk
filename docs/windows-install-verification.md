# Windows 설치 가능 여부 로컬 검증 메모

검증 일시(UTC): 2026-05-08

## 결론

- 이 저장소는 Windows 설치를 공식 지원합니다.
- 설치 진입점은 `scripts/install-windows.bat`이며 내부에서 `scripts/install-windows.ps1`을 호출합니다.
- 설치 대상은 `%LOCALAPPDATA%\SecChk`이고, Start Menu 바로가기를 생성하도록 구현되어 있습니다.

## 근거

1. README에 Windows 설치 절차(파이썬 3.10+, `install-windows.bat` 더블클릭)와 설치/제거 경로가 문서화되어 있습니다.
2. `install-windows.bat`는 PowerShell 설치 스크립트로 위임합니다.
3. `install-windows.ps1`는 Python 3.10+ 검사, venv 생성, 앱 복사, 런처(`SecChk.bat`, `SecChk-CLI.bat`) 작성, Start Menu 단축아이콘 생성을 수행합니다.

## 이번 로컬(리눅스 컨테이너)에서 실제 확인한 항목

- ✅ 테스트 스위트: `python3 -m pytest -q` (38 passed)
- ⚠️ PowerShell 구문 파서 실행: `pwsh` 바이너리 부재로 미실행 (`pwsh: command not found`)

## 한계

- 현재 환경은 Linux 컨테이너이므로 `*.bat`/Windows Start Menu/COM shortcut 생성 동작을 실제 OS 수준으로 실행 검증할 수 없습니다.
- Windows 설치 동작의 최종 실기 검증은 Windows 환경(예: Windows 10/11 + Python 3.10+)에서 `scripts/install-windows.bat` 실행으로 확인해야 합니다.
