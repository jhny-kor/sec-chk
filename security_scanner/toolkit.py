from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class TemplateWriteResult:
    path: Path
    status: str


def security_template_files(project_name: str = "KODA Project") -> dict[str, str]:
    clean_name = project_name.strip() or "KODA Project"
    return {
        "SECURITY.md": _security_policy(clean_name),
        ".github/dependabot.yml": _dependabot_config(),
        ".github/workflows/koda-security.yml": _github_security_workflow(),
        ".dockerignore": _dockerignore(),
        ".env.example": _env_example(),
        "docs/security/ZAP_BASELINE.md": _zap_baseline_guide(),
        "docs/security/DEPENDENCY_TRACK.md": _dependency_track_guide(clean_name),
        "docs/security/VEX.md": _vex_guide(),
        "docs/security/SLSA_SIGSTORE.md": _slsa_sigstore_guide(),
    }


def write_security_template_files(root: Path, *, project_name: str = "", force: bool = False) -> list[TemplateWriteResult]:
    root = root.expanduser().resolve()
    if not root.exists() or not root.is_dir():
        raise ValueError(f"Target directory does not exist: {root}")

    results: list[TemplateWriteResult] = []
    for relative_path, content in security_template_files(project_name or root.name).items():
        destination = root / relative_path
        if destination.exists() and not force:
            results.append(TemplateWriteResult(destination, "skipped"))
            continue
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(content, encoding="utf-8")
        results.append(TemplateWriteResult(destination, "written"))
    return results


def render_security_toolkit_markdown(project_name: str = "KODA Project") -> str:
    files = security_template_files(project_name)
    sections = [
        "# KODA Security Prevention Kit",
        "",
        "이 문서는 KODA가 생성한 보안 예방 가드레일 템플릿입니다.",
        "프로젝트에 맞게 담당자, 브랜치, 패키지 생태계, 운영 URL을 수정한 뒤 저장소에 반영하세요.",
        "",
    ]
    for path, content in files.items():
        fence = "yaml" if path.endswith((".yml", ".yaml")) else "markdown"
        if path == ".dockerignore" or path == ".env.example":
            fence = "text"
        sections.extend([f"## {path}", "", f"```{fence}", content.rstrip(), "```", ""])
    return "\n".join(sections)


def _security_policy(project_name: str) -> str:
    return f"""# Security Policy

## Supported Versions

| Version | Supported |
| --- | --- |
| main / latest | yes |

## Reporting a Vulnerability

Please report suspected vulnerabilities privately before opening a public issue.

- Project: {project_name}
- Contact: security@example.com
- Expected first response: 3 business days
- Expected status update: 7 business days

## Handling

1. Confirm the report and assign an owner.
2. Reproduce the issue in a private branch or isolated environment.
3. Patch, test, and release the fix.
4. Rotate exposed credentials when secrets are involved.
5. Publish an advisory or release note after users have a remediation path.
"""


def _dependabot_config() -> str:
    return """version: 2
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
"""


def _github_security_workflow() -> str:
    return """name: KODA Security

on:
  pull_request:
  push:
    branches: [main]
  schedule:
    - cron: "0 18 * * 1"

permissions:
  contents: read

jobs:
  local-security-scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: Install KODA scanner
        run: python -m pip install "git+https://github.com/jhny-kor/sec-chk.git"
      - name: Run KODA local scan
        run: |
          python -m security_scanner scan --target . --format sarif --output koda-results.sarif --enable-osv --enable-vuln-intel
          python -m security_scanner scan --target . --format cyclonedx --output koda-sbom.cdx.json
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: koda-results.sarif
      - name: Upload SBOM artifact
        uses: actions/upload-artifact@v4
        with:
          name: koda-sbom
          path: koda-sbom.cdx.json

  openssf-scorecard:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
      id-token: write
    steps:
      - uses: actions/checkout@v4
      - uses: ossf/scorecard-action@v2.4.0
        with:
          results_file: scorecard-results.sarif
          results_format: sarif
          publish_results: true
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: scorecard-results.sarif
"""


def _dockerignore() -> str:
    return """.git
.github
.env
.env.*
!.env.example
node_modules
dist
build
coverage
reports
*.pem
*.key
*.p12
*.pfx
"""


def _env_example() -> str:
    return """# Copy to .env locally and fill real values outside the repository.
APP_ENV=development
LOG_LEVEL=info
"""


def _zap_baseline_guide() -> str:
    return """# ZAP Baseline

Use this only against systems you own or are authorized to test.

```bash
python3 -m security_scanner zap-command --url https://example.com --output-dir reports/zap
```

The generated command uses the official ZAP Docker baseline image and performs passive checks without active attacks.
"""


def _dependency_track_guide(project_name: str) -> str:
    return f"""# Dependency-Track SBOM Upload

Generate a CycloneDX SBOM:

```bash
python3 -m security_scanner scan --target . --format cyclonedx --output reports/sbom.cdx.json
```

Upload it to Dependency-Track:

```bash
python3 -m security_scanner upload-sbom \\
  --server-url https://dependency-track.example.com \\
  --api-key-env DEPENDENCY_TRACK_API_KEY \\
  --project-name "{project_name}" \\
  --project-version main \\
  --sbom reports/sbom.cdx.json \\
  --auto-create
```
"""


def _vex_guide() -> str:
    return """# VEX Tracking

Use VEX to record reviewed dependency vulnerabilities after OSV, Dependency-Track, or another advisory source reports a CVE.

Create `docs/security/vex.cdx.json` or another CycloneDX/OpenVEX document with:

- the affected component and version
- the vulnerability or CVE ID
- status such as `not_affected`, `affected`, `fixed`, or `under_investigation`
- impact statement and expiry/review date

KODA treats VEX as a prevention artifact. It does not claim a vulnerability is safe automatically; it only checks that review decisions can be tracked.
"""


def _slsa_sigstore_guide() -> str:
    return """# SLSA and Sigstore Release Guardrails

For release builds, add provenance and signing controls before publishing artifacts:

1. Build release artifacts in CI, not on a developer laptop.
2. Generate SLSA provenance or an equivalent attestation.
3. Sign artifacts with Sigstore/cosign or your organization's signing system.
4. Publish checksums, signatures, and provenance next to the release.
5. Keep GitHub Actions permissions read-only by default and grant write or OIDC permissions only at job scope.

KODA detects missing signing/provenance preparation from local workflow files, but actual signature verification requires the built artifact and release metadata.
"""
