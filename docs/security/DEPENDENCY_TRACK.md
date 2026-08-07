# Dependency-Track SBOM Upload

Generate a CycloneDX SBOM from KODA, then upload it to your Dependency-Track server.

```bash
export PYTHONPATH="$PWD/platforms/shared/python"
export DEPENDENCY_TRACK_API_KEY='operator-managed-secret'
python3 -m security_scanner scan --target . --format cyclonedx --output reports/sbom.cdx.json
python3 -m security_scanner upload-sbom \
  --server-url https://dependency-track.example.com \
  --api-key-env DEPENDENCY_TRACK_API_KEY \
  --project-name "security" \
  --project-version main \
  --sbom reports/sbom.cdx.json \
  --auto-create
```

The upload fails closed when the API-key environment variable is empty, the SBOM
file does not exist, or the project name/version is blank. Do not pass the API
key with `--api-key` because it can remain in shell history.
