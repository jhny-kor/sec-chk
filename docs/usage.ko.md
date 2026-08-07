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
python3 -m security_scanner scan --target /path/to/project --standard owasp-asvs-5 --format html --output reports/source.html
python3 -m security_scanner scan --target /path/to/project --standard sw-dev-security-49 --standard-category input-validation-expression --format html --output reports/sw49-input.html
python3 -m security_scanner scan --target /path/to/project --format sarif --fail-on high
python3 -m security_scanner jar-scan --target /deploy/apps --target /deploy/worker-apps --fail-on high --fail-on-kev
python3 -m security_scanner sbom-verify --target /deploy/apps --sbom approved.cdx.json
```

`jar-scan`의 `--target`은 반복 지정할 수 있습니다. 여러 폴더를 지정하면 모든
아카이브·컴포넌트·취약점·SBOM을 중복 제거하여 하나의 라이브러리 메인/상세 리포트로
생성합니다.

JAR 보고서는 현재 HTML과 Markdown 모두 한국어로 생성되며 `--language`는
`ko`만 지원합니다. 취약점은 라이브러리·설치 버전별로
통합되고 `Fixed`와 Grype DB 재검증 결과인 `Final`이 함께 표시됩니다.

소스코드 분석은 `--standard`로 등록된 기준을 하나 선택해야 합니다. 예를 들어
`owasp-asvs-5`, `owasp-proactive-controls`, `sw-dev-security-49`,
`sw-dev-security-7-types`를 사용할 수 있으며, `--standard-category`로 해당
기준의 지원 범주를 더 좁힐 수 있습니다. HTML은 지정한 경로를 요약(메인)으로
생성하고 같은 폴더에 `-detail.html` 상세 보고서를 함께 생성합니다. 기준 프로파일은
KODA가 구현한 정적 룰 매핑 범위이며 전체 SAST 또는 공식 준수 판정을 의미하지 않습니다.

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
