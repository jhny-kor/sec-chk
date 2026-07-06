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

## Run From Source

```bat
platforms\windows\scripts\sec-chk.bat
```

The source-tree launcher sets `PYTHONPATH` to `platforms\shared\python` before running the scanner.

## Notes

- The macOS Swift app is not cross-compiled to Windows.
- Windows installer metadata lives in `platforms/windows/packaging/KODA.iss`.
- Windows assets live in `platforms/windows/assets/`.
