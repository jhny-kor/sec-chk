# KODA Offline Delivery Overview

This guide describes the English-language delivery paths for offline JAR/WAR/EAR
SBOM and vulnerability scans. All paths use the shared engine in
`platforms/shared/python/security_scanner/` and keep Grype database updates
disabled at runtime.

## Delivery choices

| Package | Best for | Runtime requirements |
| --- | --- | --- |
| Linux tarball | A user-owned Linux server installation | Python and the supplied Syft/Grype assets |
| Docker bundle | A Linux x86_64 host with Docker already installed | Docker Engine; no host package installation |
| Windows installer plus data zip | Windows desktop or server workflows | The KODA installer and a separately refreshed vulnerability-data zip |

Every package should carry the scanner, Syft, Grype, the local Grype database,
NVD JSON feeds, and CISA KEV data. Verify checksums before moving a bundle into a
closed network.

## Common scan

```bash
export PYTHONPATH=/opt/koda/platforms/shared/python
python3 -m security_scanner jar-scan \
  --target /jeus/domains/domain1/applications \
  --target /jeus/domains/domain2/applications \
  --output-dir reports/java-scan \
  --syft-bin /opt/koda/tools/syft \
  --grype-bin /opt/koda/tools/grype \
  --nvd-data /opt/koda/vuln-data/nvd \
  --cisa-kev /opt/koda/vuln-data/known_exploited_vulnerabilities.json \
  --fail-on high --fail-on-kev
```

Use `--language en` for a fixed English report. If omitted, HTML opens in Korean
with a Korean/English switch and Markdown is Korean. Findings are grouped by
library and installed version; `Final` is the lowest candidate with no matching
vulnerability in the same Grype database as of its database date.
Repeat `--target` to combine multiple deployment roots into the same archive
inventory, SBOM, and main/detail report pair; duplicate locations are removed.

## Validation

Use `--verify-sbom` to compare the generated SBOM with deployed archives and
`--baseline-sbom` to compare with an approved baseline. Retain the generated
CycloneDX SBOM, vulnerability JSON, HTML/Markdown reports, metadata, warnings,
and SBOM verification output as release evidence.

`--fail-on-kev` returns exit code `2` when KEV data was not loaded, because the
gate cannot be evaluated safely. Grype and Syft never download data during the
scan.

## Language switch

- [English documentation index](../README.en.md)
- [Korean offline delivery overview](offline-delivery.md)
