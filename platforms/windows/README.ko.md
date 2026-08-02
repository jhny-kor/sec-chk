# KODA Windows EXE 설치본 빌드

이 폴더는 Windows 직접 배포용 Inno Setup 설치본을 만드는 경로입니다.
실제 `.exe`는 Windows PC에서 PyInstaller와 Inno Setup으로 빌드해야 합니다.

## 결과물과 요구사항

결과물은 `dist\\KODA\\KODA.exe`와 `dist\\Windows\\KODASetup.exe`입니다.
빌드 PC에는 Windows, Python 3.10 이상, Inno Setup 6이 필요합니다. 사용자는
저장소를 복제하지 않고 `KODASetup.exe`만 설치하면 됩니다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\scripts\build-koda-windows-installer.ps1
```

버전은 `-Version 0.1.1`, Inno Setup 경로는
`-InnoCompilerPath "C:\\Path\\To\\ISCC.exe"`로 지정할 수 있습니다.

소스코드 SW49 기능만 빠르게 반복 점검할 때는 다음과 같이 빌드합니다.
최초 1회는 `-SkipDependencyInstall`을 빼서 PyInstaller를 설치하고, 이후
반복 빌드부터 아래처럼 사용합니다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\scripts\build-koda-windows-installer.ps1 `
  -SourceOnly -SkipDependencyInstall
```

이 프로파일은 같은 `KODASetup.exe`를 만들지만 Java/라이브러리·실시간 웹
점검, Playwright/Chromium, Syft·Grype·Grype DB를 포함하지 않습니다. 대시보드,
`koda scan --standard sw-dev-security-49`, 소스 HTML/JSON/Markdown 리포트와
패키지 SW49 스모크 테스트는 유지됩니다. `jar-scan` 또는 `web-scan`이 필요할
때는 `-SourceOnly` 없이 정식 설치본을 다시 빌드해야 합니다.
`web-audit`의 21개 항목은 SourceOnly에서 자동 실행하지 않고
`UNSUPPORTED(package_capability_missing)`으로 보고합니다.

Microsoft Store 배포에는 Inno 설치본이 아니라 MSIX 또는 `.msixupload`를
사용해야 합니다.

설치 후 `koda scan --target C:\src\project --format html --output reports\source.html`을
실행하면 소스 메인 리포트와 `source-detail.html` 상세 리포트가 함께 생성됩니다.
Java 아카이브는 `koda jar-scan --target C:\deploy\apps --format html`을 사용하며,
`server-library-report.html`과 `server-library-report-detail.html`을 생성합니다.
Windows 프로그램에서는 **보고서 → HTML (메인 + 상세)**를 선택하면 소스 두 파일이
상대 링크를 유지한 ZIP으로 저장됩니다.

여러 배포 폴더를 하나의 라이브러리 리포트로 합치려면 `--target`을 반복 지정합니다.
모든 폴더의 아카이브·컴포넌트·취약점·SBOM이 중복 제거되어 하나의 메인/상세 리포트로
생성됩니다.

```bat
koda jar-scan ^
  --target C:\deploy\api ^
  --target C:\deploy\worker ^
  --output-dir reports\java-scan
```

- [한국어 문서 인덱스](../../docs/README.md)
- [English Windows installer guide](README.md)
