# KODA Report Contract

KODA can have different scanners per platform, but report consumers should not care which scanner produced the finding. Linux, Windows, CI, and server flows use the shared Python engine. The macOS app uses the native Swift scanner. Both lanes must keep this contract stable.

## Finding Fields

Every JSON finding uses these keys:

| Field | Required | Notes |
| --- | --- | --- |
| `rule_id` | yes | Stable rule identifier such as `secret.openai-key` or `host.linux.ssh-root-login`. |
| `category` | yes | One of the category values below. |
| `severity` | yes | One of `info`, `low`, `medium`, `high`, `critical`. Lowercase only. |
| `title` | yes | Short user-facing finding title. |
| `target` | yes | Logical scan target name. Empty string is allowed when not applicable. |
| `path` | yes | File path when file-backed; host findings may use a relevant system path or an empty path. |
| `line` | yes | 1-based line number or `null`. |
| `evidence` | yes | Redacted evidence. Do not expose raw secrets. |
| `description` | yes | Why this matters. Empty string is allowed. |
| `recommendation` | yes | Remediation guidance. Empty string is allowed. |
| `resource` | yes | Stable host/resource identifier. Empty string for file-backed findings. |
| `reachable` | yes | Empty string, `reachable`, `unreachable`, or `unknown`. |
| `triage_verdict` | yes | Empty string, `likely_true`, `likely_false`, or `uncertain`. |
| `triage_confidence` | yes | Number from 0 to 1, or `null`. |
| `triage_note` | yes | Short triage note. Empty string when not triaged. |

## Categories

Current production categories:

- `secrets`
- `dependencies`
- `configuration`
- `code`
- `prevention`
- `screen_quality`
- `host`

Reserved categories for the next platform work:

- `action_flow`

`web` is used by authorized web posture scans and should keep the same finding field shape.

## Platform Rules

- macOS Swift and shared Python implementations may differ internally.
- `rule_id`, `category`, `severity`, and JSON key names must not differ by platform.
- Severity values are lowercase and ordered as: `info`, `low`, `medium`, `high`, `critical`.
- CI gates must use `severity`, not localized labels or UI text.
- Report additions should be additive. Do not rename or remove existing keys without a migration.

## Verification

The shared Python contract is locked by `tests/test_report_contract.py::ReportContractTests.test_json_report_preserves_platform_contract_fields`.

When changing the macOS Swift scanner output, verify that its exported findings can be mapped to the same fields before changing report consumers.
