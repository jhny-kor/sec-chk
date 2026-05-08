# SecChk Windows EXE installer build

This folder contains the Inno Setup script used to build `SecChkSetup.exe`.

## Result

The build creates:

```text
dist\SecChk\SecChk.exe
dist\Windows\SecChkSetup.exe
```

After installation, the Start Menu shortcut runs `SecChk.exe`. The executable starts the local dashboard server and opens the default web browser.

## Requirements on the build PC

- Windows
- Python 3.10 or newer
- Inno Setup 6

Target users do **not** need to clone the repository. They only need `SecChkSetup.exe`.

## Build

Run from the repository root:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build-windows-installer.ps1
```

Optional version override:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build-windows-installer.ps1 -Version 0.1.1
```

If Inno Setup is installed in a custom path:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\build-windows-installer.ps1 -InnoCompilerPath "C:\Path\To\ISCC.exe"
```

## Microsoft Store path

The current `SecChkSetup.exe` is an Inno Setup desktop installer for direct download. Microsoft Store distribution should use an MSIX package or `.msixupload` file through Partner Center, not the Inno installer.

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
