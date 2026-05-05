# Local Security Scanner

Read-only security scanner for local project folders. It scans configured paths, can auto-discover project roots under a parent folder, and runs selected vulnerability categories without installing dependencies or calling the network.

Korean guide: [한국어 안내](#한국어-안내)

## What It Checks

- `secrets`: likely API keys, private keys, access tokens, and hard-coded secret assignments.
- `dependencies`: risky dependency manifests, missing lockfiles, unpinned Python requirements, remote shell install scripts, and unsafe image tags.
- `configuration`: committed environment files, private-key-like files, debug flags, and risky Docker/Compose settings.

## Quick Start

```bash
python3 -m security_scanner serve
```

Open `http://127.0.0.1:8765/security-dashboard.html`, choose a folder to scan, select a security standard/category such as OWASP Top 10:2025, CWE Top 25:2025, ISMS-P 2.8, or Korea SW Development Security 49, and run the check from the dashboard.

To generate a static dashboard file instead:

```bash
python3 -m security_scanner scan --config scanner_config.example.json
```

Use a narrower target before scanning a large folder. The scanner is designed to be read-only, but broad scans can produce noisy reports.

For a portfolio-style scan of a folder that contains multiple projects:

```bash
python3 -m security_scanner discover --target /path/to/projects --depth 2
SEC_CHK_TARGET=/path/to/projects python3 -m security_scanner scan --config scanner_config.documents.example.json
```

## Configuration

Copy `scanner_config.example.json` and edit the `targets` list:

```json
{
  "targets": [
    {
      "name": "security-workspace",
      "path": ".",
      "discover_projects": false,
      "discovery_depth": 2,
      "categories": ["secrets", "dependencies", "configuration"],
      "exclude_globs": ["**/.git/**", "**/node_modules/**"],
      "max_file_size_bytes": 524288
    }
  ],
  "report": {
    "format": "html",
    "output": "reports/security-dashboard.html",
    "min_severity": "low",
    "language": "ko"
  }
}
```

## CLI

```bash
python3 -m security_scanner list-categories
python3 -m security_scanner serve
python3 -m security_scanner discover --target /path/to/projects --depth 2
python3 -m security_scanner scan --target /path/to/project --category secrets --format json
python3 -m security_scanner scan --config scanner_config.example.json --fail-on high
python3 -m security_scanner scan --target . --format sarif --output reports/results.sarif
SEC_CHK_TARGET=/path/to/projects python3 -m security_scanner scan --config scanner_config.documents.example.json --language ko
```

`--fail-on` returns a non-zero exit code when findings at or above that severity are present, which is useful for CI or scheduled jobs.

Report formats:

- `html`: static dashboard with severity metrics, project comparison, filters, KO/EN toggle, and a finding table.
- `markdown`: readable text report.
- `json`: scanner-native structured output.
- `sarif`: SARIF 2.1.0 style output for downstream static-analysis consumers.

## Dashboard Design

The HTML dashboard follows common vulnerability-management patterns seen in GitLab Security Dashboard, DefectDojo, OWASP Dependency-Track, SARIF consumers, and CVSS-based triage workflows. See `docs/security-dashboard-research.md` for source notes and implementation limits.

## Notes

This tool is a local static checker, not a replacement for full SAST, dependency advisory databases, container scanners, SBOM analysis, CVSS scoring, or manual security review. It is intended to inventory obvious local risks consistently across project folders.

Security-standard selections are mapping profiles over the local rules. Categories with no mapped local checks are shown as unsupported instead of pretending full standard coverage. CWE Top 25 and ISMS-P are included as partial profiles; NIST SSDF and OWASP ASVS remain expansion candidates because they need broader rule coverage or checklist-style workflows.

## 한국어 안내

로컬 프로젝트 폴더를 읽기 전용으로 점검하는 보안 스캐너입니다. 네트워크 호출이나 추가 의존성 설치 없이 설정한 경로를 스캔하고, 하위 프로젝트 자동 탐색과 한국어/영어 토글 대시보드를 제공합니다.

### 점검 항목

- `secrets`: API 키, 개인 키, 액세스 토큰, 하드코딩된 비밀값 의심 대입
- `dependencies`: 위험한 의존성 매니페스트, lockfile 누락, 고정되지 않은 Python requirements, 원격 셸 설치 스크립트, 안전하지 않은 이미지 태그
- `configuration`: 커밋된 환경 파일, 개인 키처럼 보이는 파일, 디버그 플래그, 위험한 Docker/Compose 설정

### 빠른 시작

```bash
python3 -m security_scanner serve
```

브라우저에서 `http://127.0.0.1:8765/security-dashboard.html`을 열고, 대시보드 상단의 `폴더 선택`으로 검사할 폴더를 고른 뒤 OWASP Top 10:2025, CWE Top 25:2025, ISMS-P 2.8, 소프트웨어 개발보안 49 같은 보안 기준과 카테고리를 선택하고 `점검 실행`을 누르면 됩니다.

정적 HTML 대시보드를 파일로 생성하려면 다음 명령을 사용합니다.

```bash
python3 -m security_scanner scan --config scanner_config.example.json
```

여러 프로젝트가 들어 있는 폴더를 한 번에 점검하려면:

```bash
python3 -m security_scanner discover --target /path/to/projects --depth 2
SEC_CHK_TARGET=/path/to/projects python3 -m security_scanner scan --config scanner_config.documents.example.json
```

### 설정

`scanner_config.example.json`을 복사한 뒤 `targets`의 `path`를 점검할 폴더로 바꾸면 됩니다.

```json
{
  "targets": [
    {
      "name": "security-workspace",
      "path": ".",
      "discover_projects": false,
      "discovery_depth": 2,
      "categories": ["secrets", "dependencies", "configuration"],
      "exclude_globs": ["**/.git/**", "**/node_modules/**"],
      "max_file_size_bytes": 524288
    }
  ],
  "report": {
    "format": "html",
    "output": "reports/security-dashboard.html",
    "min_severity": "low",
    "language": "ko"
  }
}
```

### 주요 명령

```bash
python3 -m security_scanner list-categories
python3 -m security_scanner serve
python3 -m security_scanner discover --target /path/to/projects --depth 2
python3 -m security_scanner scan --target /path/to/project --category secrets --format json
python3 -m security_scanner scan --config scanner_config.example.json --fail-on high
python3 -m security_scanner scan --target . --format sarif --output reports/results.sarif
SEC_CHK_TARGET=/path/to/projects python3 -m security_scanner scan --config scanner_config.documents.example.json --language ko
```

`--fail-on`은 지정한 심각도 이상의 발견 항목이 있을 때 0이 아닌 종료 코드를 반환하므로 CI나 예약 작업에 사용할 수 있습니다.

### 리포트 형식

- `html`: 심각도 지표, 프로젝트 비교, 필터, KO/EN 토글, 발견 항목 테이블을 포함한 정적 대시보드
- `markdown`: 사람이 읽기 쉬운 텍스트 리포트
- `json`: 스캐너 자체 구조화 출력
- `sarif`: 외부 정적 분석 도구와 연동하기 위한 SARIF 2.1.0 형식 출력

### 참고

이 도구는 로컬 정적 점검기입니다. 전문 SAST, 의존성 취약점 데이터베이스, 컨테이너 스캐너, SBOM 분석, CVSS 산정, 수동 보안 리뷰를 대체하지 않습니다. 여러 로컬 프로젝트 폴더에서 명확한 위험 신호를 일관되게 수집하는 용도입니다.

보안 기준 선택은 현재 로컬 룰을 기준 카테고리에 매핑한 프로파일입니다. 매핑된 로컬 점검이 없는 카테고리는 전체 지원인 것처럼 표시하지 않고 미지원으로 표시합니다. CWE Top 25와 ISMS-P는 부분 프로파일로 포함했으며, NIST SSDF와 OWASP ASVS는 더 많은 룰이나 체크리스트형 워크플로가 필요해서 확장 후보로 남겼습니다.
