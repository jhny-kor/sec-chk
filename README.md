# KODA

<p align="center">
  <img src="docs/assets/readme/koda-readme-hero.png" alt="KODA local security scanner overview" width="100%">
</p>

<p align="center">
  <strong>Offline-first local security and quality scanner for source code, configuration, dependencies, host posture, and screen quality.</strong>
</p>

<p align="center">
  <a href="https://apps.apple.com/kr/app/koda/id6770264012?mt=12">Download KODA on the Mac App Store</a> ·
  <a href="docs/README.md">🇰🇷 한국어 설치·운영 문서</a>
</p>

KODA keeps scans local by default. The native macOS app has its own Swift scanner; Linux, Windows, CI, and server deployments use the shared Python engine in [`platforms/shared/python/`](platforms/shared/python/).

## Choose your path

| I want to… | Start here |
| --- | --- |
| Install the native macOS app | [Mac App Store](https://apps.apple.com/kr/app/koda/id6770264012?mt=12) or [macOS install guide](docs/install/macos.md) |
| Run KODA on Linux | [Linux install and operation guide](docs/install/linux.md) |
| Build or install the Windows desktop app | [Windows install guide](docs/install/windows.md) |
| Scan JAR/WAR/EAR files on an offline server | [Offline Java SBOM and vulnerability runbook](docs/security/java-sbom-vulnerability-scan.md) |
| Choose an air-gapped delivery method | [Offline delivery overview](docs/install/offline-delivery.md) |
| Run scans, configure reports, or set up CI | [CLI and local usage](docs/usage.md) |
| Integrate with security tooling | [Security integration docs](docs/README.md#보안-점검연동-security) |

## Platform support

| Capability | macOS app | Windows installer | Linux host package | Linux Docker package |
| --- | --- | --- | --- | --- |
| Local source, configuration, dependency, and quality scan | Yes | Yes | Yes | Yes |
| Dashboard | Native app | WebView2 desktop window | `koda serve` | Loopback-bound dashboard |
| Offline JAR/WAR/EAR SBOM and vulnerability scan | Yes | Yes | Yes | Yes |
| Baseline SBOM verification | No | Yes | Yes | Yes |
| Host posture scan | No | Yes | Yes | No |
| Live web scan or ZAP baseline | Yes | Yes | Yes | No, by design |

The Python engine can run from source on any OS. The macOS column above refers only to the native app.

## Quick start

Requires Python 3.10 or later — the engine uses only the standard library, so there is no `pip install` step.

```bash
git clone https://github.com/jhny-kor/sec-chk.git
cd sec-chk
export PYTHONPATH="$PWD/platforms/shared/python"
python3 -m security_scanner app
```

This starts the local dashboard at `http://127.0.0.1:8765` (loopback only; nothing leaves your machine).

To scan your own project, copy the example config, point `targets[].path` at your project folder, and run a scan:

```bash
cp platforms/shared/python/scanner_config.example.json my-config.json
# edit my-config.json: change "path": "." to your project folder
python3 -m security_scanner scan --config my-config.json
```

The HTML report is written to `reports/security-dashboard.html`.

Use a narrow target before scanning large folders. Normal scans are read-only. `fix --apply`, prevention-template generation, and authorized web or ZAP scans can change files or contact a target; see [CLI and local usage](docs/usage.md) before using them.

## What KODA helps you do

| When you need to… | KODA provides | Result |
| --- | --- | --- |
| Find common project risks before review or release | Local source, dependency, configuration, secret, and prevention checks | A prioritized local report and an optional CI gate. |
| Check whether a UI has basic quality issues | `screen_quality` checks for markup accessibility and exposure problems | A focused quality report for HTML/JSP/CLX/JS/Vue/React sources. |
| Prioritize dependency findings | Optional OSV/CVE, CISA KEV, FIRST EPSS, reachability, and AI triage | More context without changing the original finding severity. |
| Audit deployed Java archives offline | JAR/WAR/EAR inventory, CycloneDX SBOM, vulnerability matching, and baseline comparison | Evidence for what is deployed and whether it matches an approved SBOM. |
| Check a workstation or an authorized web target | Optional host posture, web posture, and ZAP workflows | A bounded security posture report; active checks require explicit authorization. |

Security scans run `secrets`, `dependencies`, `configuration`, `code`, and `prevention` by default. `screen_quality` and `host` are separate categories. A zero-finding result is not a security guarantee; coverage depends on selected checks, reachable targets, and available data.

## Documentation

The [documentation index](docs/README.md) is the complete map. Common references:

| Topic | Document |
| --- | --- |
| CLI commands, configuration, reports, CI, and auto-fix | [CLI and local usage](docs/usage.md) |
| Closed-network Docker, Linux, and Windows delivery | [Offline delivery overview](docs/install/offline-delivery.md) |
| macOS, Linux, and Windows installation | [Install guides](docs/README.md#설치와-배포-install) |
| Java SBOM, pre-commit, Dependency-Track, ZAP, VEX, and supply-chain guidance | [Security integration docs](docs/README.md#보안-점검연동-security) |
| Report fields and output contracts | [Report contract](docs/report-contract.md) |
| Dashboard design rationale and limits | [Dashboard research](docs/security-dashboard-research.md) |

## Repository layout

| Path | Purpose |
| --- | --- |
| `platforms/shared/python/` | Shared Python engine for Linux, Windows, CI, and server use. |
| `platforms/macos/` | Native Swift app, packaging, and macOS scripts. |
| `platforms/linux/` | Offline host and Docker distributions. |
| `platforms/windows/` | Windows packaging, scripts, and installer assets. |
| `docs/` | Installation, operating, security-integration, and product documentation. |
| `tests/` | Shared engine, wrapper, and report-contract tests. |

Generated outputs such as `dist/`, `reports/`, and `.build/` are not primary source. Legacy material is retained under `archive/` for reference.

## Scope and safety

KODA is a local scanner and workflow aid. It does not replace full SAST, authenticated DAST, dependency advisory services, container scanning, CVSS scoring, or manual security review. Run live web and ZAP scans only against systems you own or are explicitly authorized to test.
