# KODA macOS Install

macOS has two lanes:

- `platforms/macos/app/KODA/`: native Swift app with `NativeSecurityScanner.swift`.
- `platforms/macos/scripts/`: Python dashboard helper scripts for local source-tree use.

The native Swift app does not call the shared Python engine. It should keep the same rule id, severity, category, and report-shape contract as the shared engine.

## Build Native App

```bash
xcodebuild -project platforms/macos/app/KODA/KODA.xcodeproj -scheme KODA -configuration Debug build
```

For the local release helper:

```bash
bash platforms/macos/scripts/build-koda-xcode-app.command
```

## Run Python Dashboard Helper

```bash
bash platforms/macos/scripts/sec-chk.command
```

The helper sets `PYTHONPATH` to `platforms/shared/python` and runs `python3 -m security_scanner app`.

## Install Python Dashboard Helper

```bash
bash platforms/macos/scripts/install-macos.command
```

This installs under `~/Library/Application Support/SecChk` and creates launchers in `~/Applications`. The helper path remains separate from the native Swift app.
