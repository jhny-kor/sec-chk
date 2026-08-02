# KODA profile-driven 21-control web audit

`web-audit` executes only the origins, resources, strategies, and success/rejection
oracles declared in a strict JSON profile. Use it only against a staging or test
system you own or are explicitly authorized to assess.

```bash
export KODA_APPROVAL_KEY='operator-managed-secret'
export KODA_OAST_SECRET='base64-secret-from-boast' # valid base64, only for OAST profiles
koda web-audit plan --profile profile.json --out approval-request.json
koda web-audit approve --request approval-request.json --approver name --out approval.json
koda web-audit run --profile profile.json --approval approval.json \
  --confirm-origin https://staging.example.com --format json --output reports/web-audit.json
```

`plan` validates the profile and resolves target DNS/IP addresses without target
traffic. `approve` signs the request with HMAC-SHA256. `run` verifies the profile
hash, exact origin, current IP set, scope, limits, signature, and expiry, then
consumes the nonce once from `~/.koda/web-audit-nonces.sqlite3`.

Profiles use `schema_version: 1` and declare `target`, `limits`, `accounts`,
`auth`, `resources`, `scenarios`, `oast`, and `applicability`. Resource paths are
origin-relative and scenario steps can reference only declared resource IDs.
Credentials must be `${ENV:NAME}` or an environment-variable-name reference.
Shell, eval, Python callbacks, arbitrary URLs, raw secrets, and raw request/response
publication are rejected or redacted.

For SSRF/code-injection callback verification, add `oast` to `target.scopes` and
declare `oast.control_plane_origin`, `oast.callback_domain`, and the approved
`oast.allowed_ips` IP/CIDR list. KODA uses the pinned BOAST `GET /events` control plane to
register and poll a test. A new event is `VULNERABLE`; a completed poll with no
event can contribute to `PASS` only when the scenario oracle and cleanup also
complete. The secret is read only from `KODA_OAST_SECRET` and is never stored in
the profile, approval, or report. Use `${CAPTURE:OAST_PAYLOAD}` in the declared
scenario to send the generated callback payload.

Every control is returned with a canonical `web.*` ID, status, execution flag,
reason code, coverage, tested surfaces, strategy results, and evidence IDs. A clean
ZAP or crawl result does not close undeclared controls.

All strategies declared on one scenario execute; the scenario reaches complete
coverage only when every strategy passes. Native scenarios support JSON/form/header
authentication, access matrices, timing/state oracles, bounded multipart uploads,
cleanup, and test-only HTTP verbs through `resource.probe_methods`. JSON auth tokens
and ZAP credentials remain environment references; bounded `delay_seconds` supports
expiry/replay checks without a hidden sleep;
the ZAP Docker invocation forwards only the referenced variable names.

| Status | Meaning |
| --- | --- |
| `VULNERABLE` | Verified exploit, state violation, or callback evidence |
| `PASS` | Required strategies, oracle, and cleanup completed without evidence |
| `NEEDS_REVIEW` | Incomplete oracle, OAST, cleanup, or surface coverage |
| `NOT_APPLICABLE` | Explicit profile exclusion with a reason |
| `UNSUPPORTED` | Required capability is absent from the distribution |
| `NOT_SCANNED` | Approval, profile, credential, or preflight prevented execution |

SourceOnly and macOS App Store distributions keep this boundary fail-closed and
report the web capability as unsupported/review; they must not present a missing
web engine as PASS. See the [Korean runbook](WEB_AUDIT.ko.md) for a complete sample
profile.

ZAP web-audit runs require a preinstalled digest-pinned image and add-on manifest;
the command uses Docker pull-never behavior. Missing ZAP, Playwright browsers, or
BOAST capabilities remain `UNSUPPORTED` or `NOT_SCANNED`.
The ZAP Automation Framework plan carries spider/active-scan limits and an
`exitStatus` outcome check; a clean ZAP exit code alone never closes all 21 controls.
