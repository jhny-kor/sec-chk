# Local Security Scanner

Read-only security scanner for local project folders. It scans configured paths, can auto-discover project roots under a parent folder, and runs selected vulnerability categories without installing dependencies. The default scan is offline; OSV/CVE dependency lookup is opt-in because it queries OSV.dev.

Korean guide: [한국어 안내](#한국어-안내)

## What It Checks

- `secrets`: likely API keys, private keys, access tokens, and hard-coded secret assignments.
- `dependencies`: risky dependency manifests, missing lockfiles, unpinned Python requirements, remote shell install scripts, and unsafe image tags.
- `configuration`: committed environment files, private-key-like files, debug flags, and risky Docker/Compose settings.
- `code`: heuristic code patterns for XSS, SQL injection, command injection, path traversal, SSRF, unsafe deserialization, disabled CSRF/auth checks, risky uploads, cookie/session weakness, weak hashes, XML parser risk, risky web-server settings, and C/C++ buffer APIs.

## Quick Start

Run it like a local app:

```bash
python3 -m security_scanner app
```

This opens `security-dashboard.html` in the default browser and keeps a local server running until you press `Ctrl+C`. On macOS, you can double-click `scripts/sec-chk.command` from Finder. On Windows, double-click `scripts/sec-chk.bat`.

Server-only mode is still available:

```bash
python3 -m security_scanner serve
```

Open `http://127.0.0.1:8765/security-dashboard.html`, choose a folder to scan, select a security standard/category such as OWASP Top 10:2025, CWE/SANS Top 25:2025, CWE, ISMS-P 2.8, Korea SW Development Security 49, KISA Secure Coding Guide, NCSC Web 8, Electronic Financial Supervision 8, OWASP ASVS, OWASP WSTG, NIST SSDF, OWASP SAMM, or OWASP dependency/SBOM baselines, and run the check from the dashboard. Turn on `OSV/CVE lookup` when you want exact-version dependency advisories from OSV.dev.

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
      "categories": ["secrets", "dependencies", "configuration", "code"],
      "exclude_globs": ["**/.git/**", "**/node_modules/**"],
      "max_file_size_bytes": 524288
    }
  ],
  "enable_osv": false,
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
python3 -m security_scanner app
python3 -m security_scanner list-categories
python3 -m security_scanner serve
python3 -m security_scanner discover --target /path/to/projects --depth 2
python3 -m security_scanner scan --target /path/to/project --category secrets --format json
python3 -m security_scanner scan --config scanner_config.example.json --fail-on high
python3 -m security_scanner scan --target . --format sarif --output reports/results.sarif
python3 -m security_scanner scan --target . --format cyclonedx --output reports/sbom.cdx.json
python3 -m security_scanner scan --target . --enable-osv --format html
SEC_CHK_TARGET=/path/to/projects python3 -m security_scanner scan --config scanner_config.documents.example.json --language ko
```

`--fail-on` returns a non-zero exit code when findings at or above that severity are present, which is useful for CI or scheduled jobs.

`--enable-osv` sends exact package names and pinned versions from supported manifests to OSV.dev. It is disabled by default so normal local scans remain offline.

Report formats:

- `html`: static dashboard with severity metrics, project comparison, filters, KO/EN toggle, Help view, coverage matrix, rule details, SBOM download, optional OSV/CVE lookup, official standard links, and a finding table.
- `markdown`: readable text report.
- `json`: scanner-native structured output.
- `sarif`: SARIF 2.1.0 style output for downstream static-analysis consumers.
- `cyclonedx`: CycloneDX JSON SBOM generated from supported dependency manifests.

## Dashboard Design

The HTML dashboard follows common vulnerability-management patterns seen in GitLab Security Dashboard, DefectDojo, OWASP Dependency-Track, SARIF consumers, and CVSS-based triage workflows. See `docs/security-dashboard-research.md` for source notes and implementation limits.

## Notes

This tool is a local static checker, not a replacement for full SAST, dependency advisory databases, container scanners, SBOM analysis, CVSS scoring, or manual security review. It is intended to inventory obvious local risks consistently across project folders.

Security-standard selections are mapping profiles over the local rules. The dashboard Help button explains each standard, mapped check criteria, coverage limits, official links, and whether the profile is covered by local rules or only partially automated. Finding remediation cards also show related standards for each local rule. Profiles include OWASP Top 10, CWE/SANS Top 25, CWE, KISA secure-coding and software-development-security guides, NCSC Web 8, Electronic Financial Supervision 8, ISMS-P 2.8, OWASP ASVS, OWASP WSTG, NIST SSDF, OWASP SAMM, and OWASP dependency/SBOM baselines. Coverage is still partial where a standard requires runtime testing, organizational evidence, or external vulnerability intelligence.

## 한국어 안내

로컬 프로젝트 폴더를 읽기 전용으로 점검하는 보안 스캐너입니다. 추가 의존성 설치 없이 설정한 경로를 스캔하고, 하위 프로젝트 자동 탐색과 한국어/영어 토글 대시보드를 제공합니다. 기본 스캔은 오프라인이며, OSV/CVE 의존성 조회는 OSV.dev를 호출하므로 사용자가 켰을 때만 실행됩니다.

### 점검 항목

- `secrets`: API 키, 개인 키, 액세스 토큰, 하드코딩된 비밀값 의심 대입
- `dependencies`: 위험한 의존성 매니페스트, lockfile 누락, 고정되지 않은 Python requirements, 원격 셸 설치 스크립트, 안전하지 않은 이미지 태그
- `configuration`: 커밋된 환경 파일, 개인 키처럼 보이는 파일, 디버그 플래그, 위험한 Docker/Compose 설정
- `code`: XSS, SQL 삽입, 명령어 삽입, 경로 조작, SSRF, 위험한 역직렬화, CSRF/인증 우회 설정, 위험한 업로드, 쿠키/세션 약화, 약한 해시, XML 파서 위험, 웹 서버 위험 설정, C/C++ 버퍼 API 휴리스틱 패턴

### 빠른 시작

로컬 프로그램처럼 실행하려면:

```bash
python3 -m security_scanner app
```

기본 브라우저에 `security-dashboard.html`을 자동으로 열고, 터미널에서 `Ctrl+C`를 누를 때까지 로컬 서버를 유지합니다. macOS에서는 Finder에서 `scripts/sec-chk.command`, Windows에서는 `scripts/sec-chk.bat`를 더블클릭하면 됩니다.

서버만 직접 띄우려면:

```bash
python3 -m security_scanner serve
```

브라우저에서 `http://127.0.0.1:8765/security-dashboard.html`을 열고, 대시보드 상단의 `폴더 선택`으로 검사할 폴더를 고른 뒤 OWASP Top 10:2025, CWE/SANS Top 25:2025, CWE, ISMS-P 2.8, 소프트웨어 개발보안 49, KISA 시큐어코딩 가이드, 국정원 웹 8대, 전자금융감독규정 8대, OWASP ASVS, OWASP WSTG, NIST SSDF, OWASP SAMM, OWASP 의존성/SBOM 기준 같은 보안 기준과 카테고리를 선택하고 `점검 실행`을 누르면 됩니다. 정확한 버전의 의존성 취약점까지 확인하려면 `OSV/CVE 조회`를 켜세요.

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
      "categories": ["secrets", "dependencies", "configuration", "code"],
      "exclude_globs": ["**/.git/**", "**/node_modules/**"],
      "max_file_size_bytes": 524288
    }
  ],
  "enable_osv": false,
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
python3 -m security_scanner app
python3 -m security_scanner list-categories
python3 -m security_scanner serve
python3 -m security_scanner discover --target /path/to/projects --depth 2
python3 -m security_scanner scan --target /path/to/project --category secrets --format json
python3 -m security_scanner scan --config scanner_config.example.json --fail-on high
python3 -m security_scanner scan --target . --format sarif --output reports/results.sarif
python3 -m security_scanner scan --target . --format cyclonedx --output reports/sbom.cdx.json
python3 -m security_scanner scan --target . --enable-osv --format html
SEC_CHK_TARGET=/path/to/projects python3 -m security_scanner scan --config scanner_config.documents.example.json --language ko
```

`--fail-on`은 지정한 심각도 이상의 발견 항목이 있을 때 0이 아닌 종료 코드를 반환하므로 CI나 예약 작업에 사용할 수 있습니다.

`--enable-osv`는 지원되는 매니페스트에서 정확한 패키지명과 고정 버전을 OSV.dev로 조회합니다. 기본값은 꺼짐이므로 일반 로컬 스캔은 오프라인으로 유지됩니다.

### 리포트 형식

- `html`: 심각도 지표, 프로젝트 비교, 필터, KO/EN 토글, 도움말 화면, 커버리지 매트릭스, 룰 상세, SBOM 다운로드, 선택형 OSV/CVE 조회, 공식 기준 링크, 발견 항목 테이블을 포함한 정적 대시보드
- `markdown`: 사람이 읽기 쉬운 텍스트 리포트
- `json`: 스캐너 자체 구조화 출력
- `sarif`: 외부 정적 분석 도구와 연동하기 위한 SARIF 2.1.0 형식 출력
- `cyclonedx`: 지원되는 의존성 매니페스트에서 생성한 CycloneDX JSON SBOM

### 참고

이 도구는 로컬 정적 점검기입니다. 전문 SAST, 의존성 취약점 데이터베이스, 컨테이너 스캐너, SBOM 분석, CVSS 산정, 수동 보안 리뷰를 대체하지 않습니다. 여러 로컬 프로젝트 폴더에서 명확한 위험 신호를 일관되게 수집하는 용도입니다.

보안 기준 선택은 현재 로컬 룰을 기준 카테고리에 매핑한 프로파일입니다. 대시보드의 `도움말` 버튼에서 각 기준의 설명, 매핑된 점검 기준, 점검 범위 한계, 공식 링크, 로컬 룰 지원 여부와 부분 자동 점검 여부를 확인할 수 있습니다. 각 발견 항목의 조치 상세에는 관련 보안 기준도 함께 표시됩니다. OWASP Top 10, CWE/SANS Top 25, CWE, KISA 시큐어코딩/소프트웨어 개발보안, 국정원 웹 8대, 전자금융감독규정 8대, ISMS-P 2.8, OWASP ASVS, OWASP WSTG, NIST SSDF, OWASP SAMM, OWASP 의존성/SBOM 기준을 포함합니다. 실행 시점 점검, 조직 증적, 외부 취약점 인텔리전스가 필요한 기준은 부분 지원입니다.
