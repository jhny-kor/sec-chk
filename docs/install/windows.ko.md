# KODA Windows 설치

Windows 설치본은 공통 Python 엔진과 Inno Setup 패키지를 사용합니다. 실제
설치본과 취약점 데이터 zip은 Windows 빌드 환경에서 생성해야 합니다.

설치 후 `koda-vuln-data-<date>.zip`을 별도로 반입해 NVD·CISA KEV 자료를
현행화할 수 있습니다. 애플리케이션을 다시 빌드하지 않고 데이터 패키지만
교체할 수 있습니다.

```powershell
python -m security_scanner jar-scan `
  --target C:\deploy\apps `
  --output-dir reports\java-scan `
  --fail-on high --fail-on-kev
```

`--language ko|en`은 HTML과 Markdown을 고정합니다. 생략하면 HTML은 한국어로
열리고 `한국어`/`English` 전환 버튼을 표시하며 Markdown은 한국어입니다.

- [한국어 문서 인덱스](../README.md)
- [English Windows install](windows.md)
