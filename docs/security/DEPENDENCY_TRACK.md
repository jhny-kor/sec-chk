# Dependency-Track SBOM Upload

Generate a CycloneDX SBOM from KODA, then upload it to your Dependency-Track server.

```bash
python -m security_scanner scan --target . --format cyclonedx --output reports/sbom.cdx.json
python -m security_scanner upload-sbom \
  --server-url https://dependency-track.example.com \
  --api-key-env DEPENDENCY_TRACK_API_KEY \
  --project-name "security" \
  --project-version main \
  --sbom reports/sbom.cdx.json \
  --auto-create
```