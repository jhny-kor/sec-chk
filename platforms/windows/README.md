# KODA Windows EXE installer build

This folder contains the Inno Setup script used to build the direct-download
KODA Windows installer.

The native macOS App Store build is SwiftUI and cannot be compiled into a
Windows executable on macOS. Build the Windows installer on a Windows PC so
PyInstaller can produce a real Windows `.exe`.

## Result

The build creates:

```text
dist\KODA\KODA.exe
dist\Windows\KODASetup.exe
```

After installation, the Start Menu shortcut runs `KODA.exe`. The executable
starts the local dashboard server and opens it in one native Edge WebView2
window, with no console window and no separate browser tab.

If a PC does not have a working Edge WebView2 Runtime, KODA automatically opens
the dashboard in the default browser instead. Users can also force this path
from the Start Menu shortcut named `KODA (Browser Mode)`.

## Requirements on the build PC

- Windows
- Python 3.10 or newer
- Inno Setup 6

Target users do **not** need to clone the repository. They only need
`KODASetup.exe`.

The installer places both `koda.cmd` and the legacy `KODA-CLI.cmd` in the
per-user install directory and adds that directory to the user `PATH`. Open a
new Command Prompt after installation and run `koda --help` or, for example:

```bat
koda scan --target C:\src\project --standard owasp-asvs-5 --format html --output reports\source.html
```

The requested HTML path is the source main report. KODA also writes the
standalone `-detail.html` source evidence report beside it. For Java archives,
run `koda jar-scan`; it writes `server-library-report.html` and
`server-library-report-detail.html` in the same output directory. The desktop
program's **Report → HTML (main + detail)** action downloads the source pair as
one ZIP so the relative detail file stays together. `--standard-category` can
narrow the selected OWASP or Korean software-development-security profile.

To combine two or more deployment roots into one library report, repeat
`--target`. Archives, components, vulnerabilities, and SBOM entries from all
roots are deduplicated and written to the same report pair:

```bat
koda jar-scan ^
  --target C:\deploy\api ^
  --target C:\deploy\worker ^
  --output-dir reports\java-scan
```

## Build

Run from the repository root:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build-koda-windows-installer.ps1
```

For a double-clickable wrapper, run `scripts\build-koda-windows-installer.bat`.

Optional version override:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build-koda-windows-installer.ps1 -Version 0.1.1
```

If Inno Setup is installed in a custom path:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build-koda-windows-installer.ps1 -InnoCompilerPath "C:\Path\To\ISCC.exe"
```

For fast SW49 source-code testing, build the same `KODASetup.exe` without
Java/library scanning, live-web scanning, Playwright/Chromium, Syft, Grype, or
the Grype database. On the first build, omit `-SkipDependencyInstall` once to
install PyInstaller; keep it for subsequent source-only rebuilds:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build-koda-windows-installer.ps1 `
  -SourceOnly -SkipDependencyInstall
```

This profile keeps the dashboard, `koda scan --standard sw-dev-security-49`,
HTML/JSON/Markdown source reports, and the packaged SW49 smoke test. It is a
test installer, not a replacement for the full production installer; rebuild
without `-SourceOnly` for `jar-scan`, `web-scan`, or `web-audit`. The 21-control
`web-audit` command reports `UNSUPPORTED(package_capability_missing)` in this
profile instead of making live requests.

The full installer includes the shared web-audit engine, but external capabilities
remain preflight requirements. Playwright/Chromium, Docker with a digest-pinned
ZAP image and add-on manifest, and BOAST must already be installed/configured;
the installer and scanner do not download them automatically. Validate an
approval without target traffic first:

```powershell
$env:KODA_APPROVAL_KEY = "operator-managed-secret"
koda web-audit run `
  --profile .\profile.json `
  --approval .\approval.json `
  --confirm-origin https://staging.example.com `
  --dry-run
```

Only a complete required scenario/oracle/cleanup set produces `PASS`. Keep
`UNSUPPORTED` (package capability missing) separate from `NOT_SCANNED` (approval,
credential, or preflight prevented execution) in release gates.

## Microsoft Store path

`KODASetup.exe` is an Inno Setup desktop installer for direct download.
Microsoft Store distribution should use an MSIX package or `.msixupload` file
through Partner Center, not the Inno installer.

Recommended Store lane:

1. Reserve the app name in Partner Center.
2. Convert or package the desktop app as MSIX.
3. Generate a Store upload package (`.msixupload`) with Visual Studio or MSIX tooling.
4. Validate the package locally where possible.
5. Submit the upload package, screenshots, privacy details, age rating, and notes in Partner Center.

Useful Microsoft references:

- [MSIX documentation](https://learn.microsoft.com/en-us/windows/msix/)
- [Package a desktop or UWP app in Visual Studio](https://learn.microsoft.com/en-us/windows/msix/package/packaging-uwp-apps)
- [Create an app submission for your MSIX app](https://learn.microsoft.com/en-us/windows/apps/publish/publish-your-app/msix/create-app-submission?pivots=store-installer-msix)
