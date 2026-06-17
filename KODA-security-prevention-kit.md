# KODA 보안 예방 키트

프로젝트: security

이 파일은 취약점이 들어오기 전에 막기 위한 기본 템플릿 묶음입니다. 저장소에 그대로 넣기 전에 담당자, 브랜치, 패키지 생태계, 운영 URL을 프로젝트에 맞게 수정하세요.

## SECURITY.md

```markdown
# Security Policy

## Supported Versions

| Version | Supported |
| --- | --- |
| main / latest | yes |

## Reporting a Vulnerability

취약점은 공개 이슈가 아니라 보안 담당자에게 비공개로 먼저 제보해주세요.

- Project: security
- Contact: security@example.com
- First response: 3 business days
- Status update: 7 business days

## Handling

1. 제보를 접수하고 담당자를 지정합니다.
2. 격리된 환경에서 재현합니다.
3. 패치, 테스트, 릴리스를 진행합니다.
4. 비밀값 노출이면 키를 즉시 교체합니다.
5. 사용자 조치 경로가 준비된 뒤 공지합니다.
```

## .github/dependabot.yml

```yaml
version: 2
updates:
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "weekly"
  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "weekly"
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
```

## .github/workflows/koda-security.yml

```yaml
name: KODA Security

on:
  pull_request:
  push:
    branches: [main]
  schedule:
    - cron: "0 18 * * 1"

permissions:
  contents: read
  security-events: write

jobs:
  local-security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: Run KODA local scan
        run: |
          python -m security_scanner scan --target . --format sarif --output koda-results.sarif --enable-osv
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: koda-results.sarif
```

## ZAP Baseline

```bash
python -m security_scanner zap-command --url https://example.com --output-dir reports/zap
```

## Dependency-Track SBOM 업로드

```bash
python -m security_scanner scan --target . --format cyclonedx --output reports/sbom.cdx.json
python -m security_scanner upload-sbom --server-url https://dependency-track.example.com --api-key-env DEPENDENCY_TRACK_API_KEY --project-name "security" --project-version main --sbom reports/sbom.cdx.json --auto-create
```