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
CODE_SIGNING_ALLOWED=YES bash platforms/macos/scripts/build-koda-xcode-app.command
codesign --verify --deep --strict --verbose=2 dist/macos/KODA.app
open -n dist/macos/KODA.app
```

The helper prepares the offline Java assets by default and writes the Release
bundle to `dist/macos/KODA.app`. The signed command above requires an installed
Apple Development identity. Copying over a root-owned Mac App Store install in
`/Applications` requires administrator authentication; back up the installed app
first. An Apple Development signature is suitable for local verification but does
not represent App Store distribution or notarization.

## Settings and host posture

The app preloads the rule catalog in the background before the Settings sheet is
opened and reuses the cached catalog. App Sandbox cannot reliably establish the
result of system commands such as `fdesetup`, `csrutil`, and `defaults`. In that
case KODA reports all nine host items, including FileVault, automatic login, and
screen lock, as `Unverified` instead of manufacturing PASS or FAIL results. It
opens the corresponding System Settings pane where supported; SIP uses command
and Recovery guidance instead.

- FileVault: System Settings > Privacy & Security > FileVault
- Automatic login and Guest User: System Settings > Users & Groups
- Screen lock: System Settings > Lock Screen
- Automatic updates: System Settings > General > Software Update
- Firewall: System Settings > Network > Firewall
- Gatekeeper: System Settings > Privacy & Security > Security
- SIP: inspect with `csrutil status`; changes require macOS Recovery

## Native website scan

Select all toggles only the ten website-scan options and leaves ZAP settings
separate. It includes active XSS, SQL injection, and redirect verification, so use
it only against an authorized target. The native crawl defaults to 50 pages and
depth 3, with at most 100 crawl-frontier URL attempts. Active, asset, and host
probe requests are separate from that frontier budget. Native active verification
only covers URL query parameters; it does not submit HTML forms. Budget, asset
read, and WebKit rendering gaps remain explicit warnings. The App Store build
keeps the native scan to its GET/HEAD read-only boundary.

## Run Python Dashboard Helper

```bash
bash platforms/macos/scripts/koda.command
```

The helper sets `PYTHONPATH` to `platforms/shared/python` and runs `python3 -m security_scanner app`.

## Install Python Dashboard Helper

```bash
bash platforms/macos/scripts/install-macos.command
```

This installs under `~/Library/Application Support/KODA` and creates `KODA.command` and `KODA-CLI.command` launchers in `~/Applications`. The helper path remains separate from the native Swift app; existing legacy shortcuts continue to work through a compatibility wrapper.
