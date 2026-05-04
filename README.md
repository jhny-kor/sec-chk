# Local Security Scanner

Read-only security scanner for local project folders. It scans configured paths, can auto-discover project roots under a parent folder, and runs selected vulnerability categories without installing dependencies or calling the network.

## What It Checks

- `secrets`: likely API keys, private keys, access tokens, and hard-coded secret assignments.
- `dependencies`: risky dependency manifests, missing lockfiles, unpinned Python requirements, remote shell install scripts, and unsafe image tags.
- `configuration`: committed environment files, private-key-like files, debug flags, and risky Docker/Compose settings.

## Quick Start

```bash
python3 -m security_scanner serve
```

Open `http://127.0.0.1:8765/security-dashboard.html`, enter the directory to scan, and run the check from the dashboard.

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
