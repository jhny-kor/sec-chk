# KODA Privacy Policy

Effective date: May 17, 2026

KODA is a macOS app for local project security review. The app is designed to analyze files and folders selected by the user on the user's Mac.

## Data collection

KODA does not require an account and does not collect personal information for advertising, tracking, analytics, or resale.

Security scan results are generated on the user's device from files and folders selected by the user. Reports, snapshots, and exported artifacts are stored locally unless the user chooses to share them outside the app.

## Local file access

KODA reads only user-selected files, folders, or archives for security analysis. The app uses this access to identify possible secrets, dependency risks, configuration issues, code patterns, and release-preparation gaps.

## Optional online vulnerability enrichment

KODA can optionally enrich dependency and vulnerability findings through public security intelligence services such as OSV.dev, CISA Known Exploited Vulnerabilities, and FIRST EPSS. When this feature is used, dependency package names, package versions, or CVE identifiers may be sent to those public endpoints. KODA does not intentionally send source code, local file contents, account credentials, or scan reports to those services.

Network providers may receive standard request metadata such as IP address and user agent as part of normal HTTPS requests.

## Optional AI triage

KODA can optionally use a large language model to label findings as likely true or false positives (`--ai-triage`). This feature is disabled by default. When a **local** backend is used (Ollama, the default), finding context stays on the user's machine and nothing is sent over the network. When the user explicitly selects a **cloud** backend (for example `anthropic/...` or `openai/...`), KODA sends finding metadata and a short surrounding source snippet to that provider in order to obtain the label; KODA surfaces a one-time warning when this external transfer happens. Raw secret values are never included in the data sent for triage: `secrets` findings are triaged from their redacted evidence only, without a source snippet. API keys for cloud backends are read from environment variables and are not stored by KODA.

## Tracking and advertising

KODA does not use third-party advertising SDKs, does not track users across apps or websites, and does not sell user data.

## Contact

For privacy questions or support requests, use the project support page:

https://github.com/jhny-kor/KODA

For the Korean version, see [PRIVACY.ko.md](PRIVACY.ko.md).
