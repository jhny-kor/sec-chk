# KODA Offline Docker Delivery

This bundle runs the offline Java archive scanner on a Linux x86_64 server. Docker
Engine must already be installed; the bundle does not change Docker or host
configuration.

## Run

```bash
docker load --input koda-java-scanner.tar
docker run --rm \
  --read-only \
  --network none \
  -v /deploy/apps:/scan:ro \
  -v "$PWD/reports:/reports" \
  koda-java-scanner:latest \
  jar-scan --target /scan --output-dir /reports \
  --fail-on high --fail-on-kev
```

Mount the application directory read-only and retain the generated reports. Put
approved Grype, NVD, and KEV data in the bundle's documented data location before
entering the closed network. The scanner does not download updates at runtime.

The HTML report defaults to Korean with a Korean/English switch when no language
is specified. Add `--language en` or `--language ko` for a fixed-language report.

- [English documentation index](../../../docs/README.en.md)
- [Korean Docker delivery guide](README.md)
