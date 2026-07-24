# ZAP Baseline

Use this only against systems you own or are authorized to test.

The default `zap-run` mode is ZAP Baseline. It runs against a live URL through
the official ZAP Docker image, so confirm the target is authorized before
running it.

```bash
python -m security_scanner zap-command --url https://example.com --output-dir reports/zap
```

Run the baseline and write reports with:

```bash
python -m security_scanner zap-run --url https://example.com --output-dir reports/zap
```

`--mode full`, `--mode api`, or automation with `--active-scan` sends active
attack traffic. KODA rejects those modes unless `--authorize-active` is given;
use that flag only after explicit authorization. See the [CLI usage guide](../usage.md#authorized-web-scanning) for the full boundary and options.
