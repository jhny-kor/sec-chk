# GitHub Repository Security Checklist

This checklist records repository-hosted controls that KODA can detect only partially from local files.

## Branch And Review Protection

- [ ] Protect the default branch.
- [ ] Require pull requests before merge.
- [ ] Require at least one approving review.
- [ ] Require KODA, test, and SAST status checks before merge.
- [ ] Require review from CODEOWNERS for security-sensitive paths.
- [ ] Dismiss stale approvals when new commits are pushed.

## Secret And Dependency Protection

- [ ] Enable secret scanning and push protection.
- [ ] Enable Dependabot alerts.
- [ ] Enable Dependabot security updates.
- [ ] Upload SARIF results from KODA, CodeQL, Semgrep, or an equivalent tool.
- [ ] Keep Actions token permissions read-only by default.

## Accountability

- [ ] Keep `SECURITY.md` current.
- [ ] Review `koda-ignore.yml` exceptions on a schedule.
- [ ] Preserve SBOM, VEX, checksums, and signing material for release builds.
- [ ] Review score history and newly introduced findings before release.
