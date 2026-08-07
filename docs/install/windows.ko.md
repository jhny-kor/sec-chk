# KODA Windows 설치

Windows 설치본은 공통 Python 엔진과 Inno Setup 패키지를 사용합니다. 실제
설치본과 취약점 데이터 zip은 Windows 빌드 환경에서 생성해야 합니다.

설치 후 `koda-vuln-data-<date>.zip`을 별도로 반입해 NVD·CISA KEV 자료를
현행화할 수 있습니다. 애플리케이션을 다시 빌드하지 않고 데이터 패키지만
교체할 수 있습니다.

```powershell
python -m security_scanner jar-scan `
  --target C:\deploy\apps `
  --target C:\deploy\worker-apps `
  --output-dir reports\java-scan `
  --fail-on high --fail-on-kev
```

JAR 보고서는 현재 HTML과 Markdown 모두 한국어로 생성되며 `--language`는
`ko`만 지원합니다.
`--target`은 반복 지정할 수 있으며, 지정한 폴더들을 하나의 라이브러리
메인/상세 리포트와 SBOM으로 통합합니다.

설치기는 `%LOCALAPPDATA%\KODA`를 사용자 `PATH`에 추가하고 `koda.cmd`를
설치합니다. 설치 후 새 명령 프롬프트를 열어 `koda --help`로 실행하세요.
기존 `KODA-CLI.cmd`도 호환성을 위해 유지됩니다.

소스코드 분석은 기준을 명시해서 실행할 수 있습니다. HTML은 메인 요약과
`-detail.html` 상세 파일로 나뉩니다.

```bat
koda scan --target C:\src\project --standard sw-dev-security-49 ^
  --format html --output reports\source.html
```

`owasp-asvs-5`, `owasp-proactive-controls`, `sw-dev-security-49`,
`sw-dev-security-7-types` 등을 선택할 수 있고 `--standard-category`로 범주를
좁힐 수 있습니다. 프로파일은 KODA 정적 룰의 매핑 범위이며 전체 SAST나 공식
준수 판정을 의미하지 않습니다.

- [한국어 문서 인덱스](../README.md)
- [English Windows install](windows.md)
