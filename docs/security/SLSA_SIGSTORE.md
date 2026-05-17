# SLSA and Sigstore Release Guardrails

For release builds, add provenance and signing controls before publishing artifacts:

1. Build release artifacts in CI, not on a developer laptop.
2. Generate SLSA provenance or an equivalent attestation.
3. Sign artifacts with Sigstore/cosign or your organization's signing system.
4. Publish checksums, signatures, and provenance next to the release.
5. Keep GitHub Actions permissions read-only by default and grant write or OIDC permissions only at job scope.

KODA detects missing signing/provenance preparation from local workflow files, but actual signature verification requires the built artifact and release metadata.
