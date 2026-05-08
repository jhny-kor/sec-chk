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
