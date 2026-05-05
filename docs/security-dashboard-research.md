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
- OWASP Top 10:2025: updated web application risk categories; added as a mapped profile where current local checks overlap.
  - https://owasp.org/Top10/2025/
- OWASP Top 10:2021: web application risk categories used for the dashboard standard/category selector.
  - https://owasp.org/Top10/2021/
- OWASP API Security Top 10:2023: API-specific risk categories; added as a mapped profile for configuration and unsafe API-consumption overlaps.
  - https://owasp.org/API-Security/editions/2023/en/0x11-t10/
- OWASP Mobile Top 10:2024: mobile risk categories; added as a mapped profile for credential, supply-chain, communication, storage, cryptography, and configuration overlaps.
  - https://owasp.org/www-project-mobile-top-10/
- OWASP ASVS 5.0.0: verification requirements for web application technical controls; tracked as a future checklist/profile candidate.
  - https://owasp.org/www-project-application-security-verification-standard/
- CWE Top 25 2025: current MITRE/CISA weakness prioritization list; added as a partial profile for local sensitive-data checks and heuristic code-pattern checks.
  - https://cwe.mitre.org/top25/
- NIST SSDF SP 800-218: secure software development practice framework; tracked as a future process/checklist candidate rather than a direct static-scan profile.
  - https://csrc.nist.gov/pubs/sp/800/218/final
- Korea Ministry of the Interior and Safety SW Development Security Guide: source for the software security weakness criteria related to Article 52.
  - https://www.mois.go.kr/frt/bbs/type001/commonSelectBoardArticle.do?bbsId=BBSMSTR_000000000015&nttId=88956
- Korea Law Information Center software security weakness criteria: current official appendix reference for Article 52 category naming.
  - https://www.law.go.kr/
- Korea ISMS-P: management-system certification criteria; added as a partial ISMS-P 2.8 development-security profile where local static checks can provide supporting evidence.
  - https://www.isms-p.or.kr/sysm/intro/selectSysmCertDetail.do

## Adopted Patterns

- Portfolio view: one dashboard can summarize many local project folders.
- Severity-first triage: critical/high findings are visually prominent.
- Project comparison: targets are listed with finding counts so noisy or risky folders stand out.
- Global filters: severity, category, target, and free-text filtering affect the full dashboard.
- Standard selector: scan requests can narrow local checks by mapped security standards while unsupported standard categories remain visibly unavailable.
- Finding table: remediation guidance stays attached to each finding.
- Interchange output: SARIF is available for downstream static-analysis consumers.
- Code-pattern heuristics: common risky sinks such as dynamic SQL, unsafe HTML rendering, shell execution, path use, SSRF fetches, disabled CSRF/auth checks, unsafe deserialization, file upload saves, request body parsing, and C/C++ buffer APIs can provide lightweight local evidence for standards categories.

## Deliberate Limits

- The local risk score is a simple weighted backlog score, not a CVSS calculation.
- Trend charts are not included yet because the scanner does not persist historical scan snapshots.
- SBOM, CVE, EPSS, and advisory lookups are deferred because the first version remains offline and dependency-free.
- Standard selections are mapping profiles over the implemented local rules, not a claim of full standard coverage.
- CWE Top 25 coverage is still heuristic; use-after-free and null-pointer dereference remain unsupported because they need deeper language-aware analysis.
- ISMS-P 2.8 is a supporting-evidence profile, not an ISMS-P audit result; full coverage needs checklist/evidence workflows outside static file scanning.
- ASVS and NIST SSDF are better served by additional rule engines or checklist/evidence workflows before they are exposed as first-class scan profiles.
