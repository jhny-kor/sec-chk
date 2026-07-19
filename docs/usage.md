# KODA CLI and local usage

This guide covers the shared Python engine used by Linux, Windows, CI, and server deployments. For platform installation and closed-network bundles, use the [documentation index](README.md).

## Run from a source checkout

```bash
export PYTHONPATH="$PWD/platforms/shared/python"
python3 -m security_scanner app
```

`app` opens the local dashboard in the default browser. `serve` starts the same dashboard without opening a browser:

```bash
python3 -m security_scanner serve
```

The default binding is `127.0.0.1:8765`. Open `http://127.0.0.1:8765/security-dashboard.html`.

## Configure a scan

Copy the example configuration and change its target path:

```json
{
  "targets": [
    {
      "name": "security-workspace",
      "path": ".",
      "discover_projects": false,
      "categories": ["secrets", "dependencies", "configuration", "code", "prevention"],
      "exclude_globs": ["**/.git/**", "**/node_modules/**"],
      "max_file_size_bytes": 524288
    }
  ],
  "enable_osv": false,
  "enable_vuln_intel": false,
  "report": {
    "format": "html",
    "output": "reports/security-dashboard.html",
    "min_severity": "low",
    "language": "ko"
  }
}
```

To suppress a known false positive without changing a scanner rule, add `koda-ignore.yml` or `.koda-ignore.yml` to the scanned-folder root:

```yaml
ignore:
  - rule: secret.openai-key
    path: .env
    reason: local development placeholder
    until: 2099-12-31
```

## Common commands

```bash
# Discover project roots and run local scans
python3 -m security_scanner discover --target /path/to/projects
python3 -m security_scanner scan --target /path/to/project --category secrets --format json
python3 -m security_scanner scan --config scanner_config.example.json --fail-on high
python3 -m security_scanner scan --target . --format sarif --output reports/results.sarif
python3 -m security_scanner scan --target . --format cyclonedx --output reports/sbom.cdx.json

# Optional external dependency intelligence
python3 -m security_scanner scan --target . --enable-osv --format html
python3 -m security_scanner scan --target . --enable-vuln-intel --format html
python3 -m security_scanner scan --target . --enable-osv --reachability --format json

# CI-oriented changed-file scan
python3 -m security_scanner scan --target . --changed-only --base origin/main --format sarif --fail-on high

# Offline Java archive scan and deployed-SBOM verification
python3 -m security_scanner jar-scan --target /deploy/apps --output-dir reports/java-scan --fail-on high --fail-on-kev
python3 -m security_scanner sbom-verify --target /deploy/apps --sbom reports/approved-sbom.cdx.json --output-dir reports/sbom-verification --strict-hash --fail-on-mismatch
```

`--fail-on` exits nonzero when a finding meets the specified severity. `--enable-osv` queries OSV.dev using exact package names and versions. `--enable-vuln-intel` includes OSV and enriches available CVEs with CISA KEV and FIRST EPSS data; both options are off by default so ordinary scans remain offline.

`--reachability` labels dependency findings as `reachable`, `unreachable`, or `unknown` from local Python and JavaScript/TypeScript import analysis. It does not remove a finding. Add `--reachable-only` with `--fail-on` when an unreachable result should not fail a gate.

For a complete command list and current flags, run:

```bash
python3 -m security_scanner --help
python3 -m security_scanner scan --help
```

## Reports

| Format | Use |
| --- | --- |
| `html` | Static dashboard with filtering, severity metrics, coverage, and finding details. |
| `markdown` | Readable text report. |
| `json` | Scanner-native structured report. |
| `sarif` | SARIF 2.1.0 for static-analysis consumers. |
| `cyclonedx` | CycloneDX JSON SBOM from supported dependency manifests. |
| `cyclonedx-vex` | CycloneDX VEX draft; vulnerabilities remain `in_triage` until human review. |

See the [report contract](report-contract.md) for output fields.

## CI

The repository includes a composite action at `.github/actions/koda/`. A consuming repository can scan pull-request changes and upload SARIF:

```yaml
jobs:
  koda-security:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: <owner>/<koda-repo>/.github/actions/koda@main
        with:
          fail-on: high
          changed-only: "true"
```

The action scopes pull-request scans to changed files when history is available. Use `fail-on: none` to report without failing the job.

## Actions that can change state or contact a target

| Command | Behavior |
| --- | --- |
| `fix --target .` | Prints a dry-run diff. Add `--apply` to write deterministic fixes; backups are created unless `--no-backup` is supplied. |
| `init-security` | Creates prevention templates without overwriting existing files by default. |
| `install-hook` | Installs a local KODA pre-commit gate. |
| `web-scan` | Contacts an authorized URL. Crawling, rendering, and path probes widen the request scope. |
| `zap-run` | Runs an authorized OWASP ZAP baseline through Docker. |
| `upload-sbom` | Uploads an SBOM to Dependency-Track; store its API key in an environment variable. |

`web-scan` and `zap-run` must only target systems you own or are explicitly authorized to test. The [ZAP guide](security/ZAP_BASELINE.md), [Dependency-Track guide](security/DEPENDENCY_TRACK.md), and [offline Java runbook](security/java-sbom-vulnerability-scan.md) contain the operating details.

## Limits

KODA provides consistent local evidence and optional intelligence; it is not a replacement for full SAST, authenticated DAST, container scanning, a vulnerability database, CVSS scoring, or manual review. Security-standard selections map local rules to profiles. Requirements that need runtime testing, hosted-service settings, release artifacts, or organizational evidence remain marked as external integration or evidence review.
