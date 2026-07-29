# Windows Vulnerability Data Refresh

`koda-vuln-data-<date>.zip` is the separate NVD and CISA KEV data package used by
the Windows installer. Refreshing this package does not require rebuilding or
reinstalling the application.

## Build on a connected Windows host

Run the repository's Windows build script from PowerShell:

```powershell
.\platforms\windows\scripts\build-koda-vuln-data.ps1
```

The script downloads the configured NVD feeds and KEV catalog, writes a dated zip,
and records checksums and source metadata. Review the output before transferring
it into the closed network.

## Install the package

Copy the zip to the Windows KODA data directory and extract it according to the
installer's data-path configuration. Keep the original zip, checksum, and build
log with the change record. Do not replace the application executable when only
the vulnerability data is being refreshed.

## Verify before scanning

Confirm that the extracted directory contains the NVD JSON feeds and
`known_exploited_vulnerabilities.json`. Run a Java scan with `--nvd-data` and
`--cisa-kev` pointing at those paths, then retain `scan-metadata.json` so the
data-as-of date and source hashes are auditable.

- [English documentation index](../README.en.md)
- [Korean vulnerability-data refresh procedure](vuln-data-refresh.md)
