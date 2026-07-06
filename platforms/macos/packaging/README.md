# KODA macOS App Store Packaging

This folder contains the first App Store packaging lane for the macOS app named `KODA`.

## What is included

- `assets/KODA.icns`: app icon generated from the supplied KODA image.
- `assets/KODA-AppStore-1024.png`: 1024 px App Store marketing icon source.
- `KODA.entitlements`: App Sandbox entitlements required for Mac App Store distribution.
- `../app/KODA/KODA.xcodeproj`: native SwiftUI macOS project for the App Store lane. The app supports folder selection, multiple file selection, and common archive inputs with a built-in Swift scanner.
- `../scripts/build-koda-xcode-app.command`: builds the native Xcode app to `dist/macos/KODA.app`.
- `../scripts/build-koda-app.command`: legacy PyInstaller-based macOS app and package build script for non-store experiments.

## Requirements

- macOS with Xcode Command Line Tools.
- Apple Developer Program membership.
- A Mac App Store bundle identifier, for example `com.yourcompany.koda`.
- Mac App Distribution and Mac Installer Distribution signing certificates.

## Local build

### Xcode project

Open the native project:

```zsh
open platforms/macos/app/KODA/KODA.xcodeproj
```

For local command-line verification without signing:

```zsh
platforms/macos/scripts/build-koda-xcode-app.command
```

The Xcode app uses the native Swift scanner in the app target. It does not require `python3` to launch or scan from the `.app` bundle. The local build output is:

```text
dist/macos/KODA.app
```

### PyInstaller package lane

```zsh
platforms/macos/scripts/build-koda-app.command
```

The local build creates an unsigned test package at:

```text
dist/macos/KODA.app
dist/macos/KODA-0.1.0-unsigned.pkg
```

## App Store archive

Use the native Xcode project as the App Store lane:

```zsh
/Applications/Xcode.app/Contents/Developer/usr/bin/xcodebuild \
  -project platforms/macos/app/KODA/KODA.xcodeproj \
  -scheme KODA \
  -configuration Release \
  -archivePath build/KODA.xcarchive \
  archive
```

Then upload the archive from Xcode Organizer or export it with an App Store
Connect export profile. Before submission, verify the signed app has the App
Sandbox entitlement:

```zsh
codesign -dvvv --entitlements :- build/KODA.xcarchive/Products/Applications/KODA.app
```

For command-line export, provide an App Store export options plist and run:

```zsh
/Applications/Xcode.app/Contents/Developer/usr/bin/xcodebuild \
  -exportArchive \
  -archivePath build/KODA.xcarchive \
  -exportPath dist/app-store \
  -exportOptionsPlist /path/to/ExportOptions-app-store.plist
```

The legacy `build-koda-app.command` PyInstaller lane is for non-store
experiments. Do not use it for the Mac App Store submission unless the store
lane is intentionally changed back to the Python bundle.

## Current limitation

The Xcode app is now the preferred App Store lane, and it can run scans from selected folders, selected files, and supported archives (`zip`, `jar`, `war`, `tar`, `tar.gz`, `tgz`, `gz`) without an external Python runtime. Before final App Review submission, run a full sandbox QA pass on a clean Mac and verify folder selection, multi-file scanning, archive extraction, and scanner access to user-selected folders.

Apple references:

- [Upload builds to App Store Connect](https://developer.apple.com/help/app-store-connect/manage-builds/upload-builds/)
- [App Sandbox](https://developer.apple.com/documentation/security/app_sandbox)
- [Configuring the macOS App Sandbox](https://developer.apple.com/documentation/xcode/configuring-the-macos-app-sandbox)
