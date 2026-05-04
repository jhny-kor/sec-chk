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
- OWASP Top 10:2021: web application risk categories used for the dashboard standard/category selector.
  - https://owasp.org/Top10/2021/
- Korea Ministry of the Interior and Safety SW Development Security Guide: source for the software security weakness criteria related to Article 52.
  - https://www.mois.go.kr/frt/bbs/type001/commonSelectBoardArticle.do?bbsId=BBSMSTR_000000000015&nttId=88956
- Korea Law Information Center software security weakness criteria: current official appendix reference for Article 52 category naming.
  - https://www.law.go.kr/

## Adopted Patterns

- Portfolio view: one dashboard can summarize many local project folders.
- Severity-first triage: critical/high findings are visually prominent.
- Project comparison: targets are listed with finding counts so noisy or risky folders stand out.
- Global filters: severity, category, target, and free-text filtering affect the full dashboard.
- Standard selector: scan requests can narrow local checks by mapped security standards while unsupported standard categories remain visibly unavailable.
- Finding table: remediation guidance stays attached to each finding.
- Interchange output: SARIF is available for downstream static-analysis consumers.

## Deliberate Limits

- The local risk score is a simple weighted backlog score, not a CVSS calculation.
- Trend charts are not included yet because the scanner does not persist historical scan snapshots.
- SBOM, CVE, EPSS, and advisory lookups are deferred because the first version remains offline and dependency-free.
- OWASP Top 10 and SW Development Security 49 selections are mapping profiles over the implemented local rules, not a claim of full standard coverage.
