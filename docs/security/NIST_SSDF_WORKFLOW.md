# NIST SSDF Workflow

This file maps KODA prevention work to NIST SP 800-218 SSDF practice groups. It is a local evidence checklist, not a certification statement.

## Prepare The Organization

- [ ] Define owners for secure development decisions.
- [ ] Keep `SECURITY.md`, CODEOWNERS, and exception policy current.
- [ ] Train contributors on secrets, dependency hygiene, secure defaults, and report handling.

## Protect The Software

- [ ] Keep repository access least-privilege.
- [ ] Run the KODA pre-commit gate for local prevention.
- [ ] Generate SBOMs for release builds.
- [ ] Sign release artifacts and preserve provenance.

## Produce Well-Secured Software

- [ ] Run KODA, SAST, dependency, and workflow-hardening checks on pull requests.
- [ ] Use secure defaults for auth, sessions, CORS, containers, CI tokens, and logging.
- [ ] Keep dependency update automation enabled.
- [ ] Review design changes for auth, data protection, and trust boundaries.

## Respond To Vulnerabilities

- [ ] Triage OSV/CVE findings with KEV/EPSS context.
- [ ] Record reviewed dependency decisions in VEX.
- [ ] Track owner, due date, remediation result, and release/advisory notes.
- [ ] Re-run KODA and compare score history after remediation.
