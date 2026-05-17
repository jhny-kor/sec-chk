# ZAP Baseline

Use this only against systems you own or are authorized to test.

The KODA app can prepare local prevention files. ZAP itself runs against a live URL through the official ZAP Docker image, so run it only after confirming the target is authorized.

```bash
python -m security_scanner zap-command --url https://example.com --output-dir reports/zap
```