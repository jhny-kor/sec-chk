# VEX Tracking

Use VEX to record reviewed dependency vulnerabilities after OSV, Dependency-Track, or another advisory source reports a CVE.

Create `docs/security/vex.cdx.json` or another CycloneDX/OpenVEX document with:

- the affected component and version
- the vulnerability or CVE ID
- status such as `not_affected`, `affected`, `fixed`, or `under_investigation`
- impact statement and expiry/review date

KODA treats VEX as a prevention artifact. It does not claim a vulnerability is safe automatically; it only checks that review decisions can be tracked.
