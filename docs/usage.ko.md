# KODA CLI 및 로컬 사용법

이 문서는 Linux·Windows·CI·서버에서 사용하는 공통 Python 엔진의 한국어
사용 안내입니다. 모든 명령은 저장소 루트에서 실행하고 `PYTHONPATH`에
`platforms/shared/python`을 추가합니다.

## 시작

```bash
export PYTHONPATH="$PWD/platforms/shared/python"
python3 -m security_scanner app
```

대시보드는 기본적으로 `127.0.0.1:8765`에만 바인딩됩니다. 명령별 전체 옵션은
`python3 -m security_scanner <command> --help`로 확인하세요.

## 주요 명령

```bash
python3 -m security_scanner scan --target /path/to/project --format html
python3 -m security_scanner scan --target /path/to/project --format sarif --fail-on high
python3 -m security_scanner jar-scan --target /deploy/apps --fail-on high --fail-on-kev
python3 -m security_scanner sbom-verify --target /deploy/apps --sbom approved.cdx.json
```

JAR 보고서는 `--language ko` 또는 `--language en`으로 고정할 수 있습니다.
옵션을 생략하면 HTML은 한국어로 열리고 `한국어`/`English` 전환 버튼을
표시하며 Markdown은 한국어로 생성됩니다. 취약점은 라이브러리·설치 버전별로
통합되고 `Fixed`와 Grype DB 재검증 결과인 `Final`이 함께 표시됩니다.

## 안전 경계

일반 스캔과 `sbom-verify`는 읽기 전용입니다. `fix --apply`, 템플릿 생성,
`web-scan`, `zap-run`, `upload-sbom`은 파일을 변경하거나 외부 시스템에
접근할 수 있으므로 승인된 대상에서만 사용하세요.

## 승인된 웹 점검

`web-scan`은 기본적으로 제한된 posture 점검만 수행합니다. `--active`나
`zap-run --mode full`처럼 요청 범위를 넓히는 옵션은 소유하거나 명시적 권한을
받은 대상에서만 사용하고, ZAP 활성 모드에는 `--authorize-active`를 지정하세요.

- [한국어 문서 인덱스](README.md)
- [English CLI and local usage](usage.md)
