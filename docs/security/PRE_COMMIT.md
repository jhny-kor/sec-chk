# KODA Pre-Commit Security Gate

KODA can install a local Git pre-commit hook that runs a fast offline scan before a commit is created.

```bash
python3 -m security_scanner install-hook --target . --fail-on high
```

The hook blocks the commit when findings meet or exceed `KODA_PRE_COMMIT_FAIL_ON`.

Install it only where `python3 -m security_scanner` is available to Git hooks
(for example, the KODA-installed environment or an activated source checkout).
The hook writes its Markdown report under `TMPDIR` (or `/tmp`), so that
location must be writable by the committing user.

Useful environment variables:

- `KODA_PRE_COMMIT_FAIL_ON`: `critical`, `high`, `medium`, `low`, or `info`
- `KODA_PRE_COMMIT_TARGET`: scan target, default `.`

Keep the hook local and fast. Run external OSV/KEV/EPSS lookup, ZAP DAST, SBOM upload, and release signing from the app or CI.
