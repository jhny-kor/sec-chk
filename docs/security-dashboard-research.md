# Security Dashboard Research Notes

The current implementation borrows information architecture from established vulnerability-management tools without copying any vendor branding or proprietary layout.

## Sources Checked

- GitLab Security Dashboard: severity panels, risk score, whole-dashboard filters, vulnerability trends, and project/group posture views.
  - https://docs.gitlab.com/user/application_security/security_dashboard/
- DefectDojo Main Dashboard: summary cards, severity history, dashboard tiles, and vulnerability tracking environment overview.
  - https://docs.defectdojo.com/metrics_reports/dashboards/introduction_dashboard/
- OWASP Dependency-Track: portfolio-level supply-chain risk, project metrics, policy/auditing workflow, and SBOM-centric application inventory.
  - https://docs.dependencytrack.org/
- SARIF 2.1.0: OASIS standard interchange format for static analysis results.
  - https://www.oasis-open.org/standard/sarif-v2-1-0/
- GitHub code scanning SARIF support: practical SARIF ingestion expectations for code scanning alerts.
  - https://docs.github.com/github/finding-security-vulnerabilities-and-errors-in-your-code/sarif-support-for-code-scanning
- FIRST CVSS v3.1: qualitative severity bands used by vulnerability management programs.
  - https://www.first.org/cvss/v3-1/specification-document

## Adopted Patterns

- Portfolio view: one dashboard can summarize many local project folders.
- Severity-first triage: critical/high findings are visually prominent.
- Project comparison: targets are listed with finding counts so noisy or risky folders stand out.
- Global filters: severity, category, target, and free-text filtering affect the full dashboard.
- Finding table: remediation guidance stays attached to each finding.
- Interchange output: SARIF is available for downstream static-analysis consumers.

## Deliberate Limits

- The local risk score is a simple weighted backlog score, not a CVSS calculation.
- Trend charts are not included yet because the scanner does not persist historical scan snapshots.
- SBOM, CVE, EPSS, and advisory lookups are deferred because the first version remains offline and dependency-free.
