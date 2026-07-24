# KODA Windows Install

Windows uses the shared Python engine from `platforms/shared/python/` and packages it through the Windows scripts under `platforms/windows/`.

## Build Installer

Run on Windows 10/11 with Python 3.10 or newer and Inno Setup 6 installed:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\platforms\windows\scripts\build-koda-windows-installer.ps1
```

The build creates:

- `dist\KODA\KODA.exe`
- `dist\Windows\KODASetup.exe`

Target users install with `KODASetup.exe`. It installs to `%LOCALAPPDATA%\KODA` and creates Start Menu shortcuts for `KODA` and `KODA (Browser Mode)`.

## Vulnerability Data Package

The installer bundles Syft, Grype, and the Grype DB, but not the NVD and CISA
KEV feeds. Those change daily while the application does not, so they ship as a
separate package that is refreshed without rebuilding or redistributing the
installer.

Build it on a connected macOS/Linux host (it reuses the same download cache and
`.meta` verification as the Linux offline bundle):

```bash
bash platforms/linux/package-offline.sh --vuln-data-only
# → dist/Windows/koda-vuln-data-<date>.zip  (about 210 MB, NVD 2002-current + KEV)
```

You can also build the package directly on an internet-connected Windows PC.
This does not require Python, Docker, or the KODA installer build tools; it
uses PowerShell 5.1 or PowerShell 7:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\platforms\windows\scripts\build-koda-vuln-data.ps1
# → dist\Windows\koda-vuln-data-<date>.zip
```

The Windows script caches yearly NVD feeds under
`.build\koda-vuln-data-cache\` and verifies each cached feed against its
downloaded `.meta` SHA-256 before using it. The
`recent` and `modified` NVD feeds and the CISA KEV catalog are downloaded and
verified on every run. Add `-Refresh` to download all yearly feeds again. To
limit the data range, use for example `-StartYear 2025 -EndYear 2026`; the
default is the complete NVD range from 2002 through the current UTC year.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass `
  -File .\platforms\windows\scripts\build-koda-vuln-data.ps1 `
  -Refresh -StartYear 2025 -EndYear 2026
```

The script prints the archive SHA-256; compare it on the target machine with
`Get-FileHash` before extracting. Extract the zip into the install directory so
that the folders line up:

```powershell
Expand-Archive -Path koda-vuln-data-<date>.zip -DestinationPath $env:LOCALAPPDATA\KODA -Force
# → %LOCALAPPDATA%\KODA\vuln-data\nvd\...
#   %LOCALAPPDATA%\KODA\vuln-data\known_exploited_vulnerabilities.json
#   %LOCALAPPDATA%\KODA\vuln-data\versions.txt   (feed 기준일)
```

`KODA.exe` and `KODA-CLI.exe` detect `vuln-data\` on startup and set
`KODA_NVD_DATA` and `KODA_CISA_KEV` automatically, exactly as they already do
for `tools\`. No path arguments are needed:

```bat
koda jar-scan --target D:\apps ^
  --output-dir reports --fail-on high --fail-on-kev
```

The installer keeps `KODA-CLI.cmd` as a compatibility alias and adds
`%LOCALAPPDATA%\KODA` to the per-user `PATH`. Open a new Command Prompt after
installation and type `koda --help` (existing shells must be restarted).

For source-code static analysis, choose one configured standard explicitly. The
HTML output path is the summary page and a `-detail.html` sibling is written for
the complete findings table:

```bat
koda scan --target D:\src\project --standard sw-dev-security-49 ^
  --format html --output reports\source.html
```

The supported profiles include `owasp-asvs-5`, `owasp-proactive-controls`,
`owasp-top-10-2021`, `owasp-top-10-2025`, `sw-dev-security-49`, and
`sw-dev-security-7-types`. Use `koda scan --help` to see the complete list and
`--standard-category` to narrow a profile to one category.

Add `--language ko` or `--language en` to fix the report language. When omitted,
the HTML report opens in Korean and includes a Korean/English toggle; Markdown is
generated in Korean. Findings are grouped by library and installed version, with
`Fixed` advisory candidates and a DB-verified `Final` candidate when available.

Without the data package `jar-scan` still runs on Grype alone, but reports carry
no CVSS or exploited-vulnerability detail, and `--fail-on-kev` exits `2` rather
than passing a gate it cannot evaluate.

Refresh the data by extracting a newer zip over the old one. Upgrading KODA does
not delete `vuln-data\`; uninstalling KODA removes it with the rest of the
install directory.

## Run From Source

```bat
platforms\windows\scripts\sec-chk.bat
```

The source-tree launcher sets `PYTHONPATH` to `platforms\shared\python` before running the scanner.

## Notes

- The macOS Swift app is not cross-compiled to Windows.
- Windows installer metadata lives in `platforms/windows/packaging/KODA.iss`.
- Windows assets live in `platforms/windows/assets/`.
