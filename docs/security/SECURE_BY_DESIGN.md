# CISA Secure by Design Plan

This plan turns CISA Secure by Design principles into project-level prevention work KODA can help track.

## Take Ownership Of Customer Security Outcomes

- [ ] Treat exposed secrets, unsafe defaults, and known exploited vulnerabilities as customer-impacting defects.
- [ ] Provide secure defaults for auth, sessions, logging, CORS, and deployment configuration.
- [ ] Ship updates or compensating guidance quickly for exploitable dependency findings.
- [ ] Keep security contact and vulnerability handling process visible.

## Embrace Radical Transparency And Accountability

- [ ] Publish security policy, supported versions, and remediation expectations.
- [ ] Keep SBOM and VEX artifacts for releases.
- [ ] Record accepted risks, known limitations, and exception expiry dates.
- [ ] Track score history and severity deltas after each release.

## Lead From The Top

- [ ] Assign owners for product security outcomes.
- [ ] Review Secure by Design metrics: high findings, time to remediate, secrets blocked, and vulnerable dependencies.
- [ ] Require security gates before merge and release.
- [ ] Invest in prevention automation before post-release response work.
