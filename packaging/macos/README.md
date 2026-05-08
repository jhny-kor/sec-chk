# KODA macOS App Store Packaging

This folder contains the first App Store packaging lane for the macOS app named `KODA`.

## What is included

- `assets/KODA.icns`: app icon generated from the supplied KODA image.
- `assets/KODA-AppStore-1024.png`: 1024 px App Store marketing icon source.
- `KODA.entitlements`: App Sandbox entitlements required for Mac App Store distribution.
- `../../platforms/macos/KODA/KODA.xcodeproj`: native SwiftUI macOS project for the App Store lane.
- `build-koda-app.command`: PyInstaller-based macOS app and package build script.

## Requirements

- macOS with Xcode Command Line Tools.
- Python 3.10 or newer.
- Apple Developer Program membership.
- A Mac App Store bundle identifier, for example `com.yourcompany.koda`.
- Mac App Distribution and Mac Installer Distribution signing certificates.

## Local build

### Xcode project

Open the native project:

```zsh
open platforms/macos/KODA/KODA.xcodeproj
```

For local command-line verification without signing:

```zsh
xcodebuild \
  -project platforms/macos/KODA/KODA.xcodeproj \
  -scheme KODA \
  -configuration Debug \
  -derivedDataPath /tmp/koda-derived \
  CODE_SIGNING_ALLOWED=NO \
  build
```

The Xcode scheme sets `KODA_SCANNER_ROOT` to the repository root for development runs. For a final App Store build, package `security_scanner` as an app resource or replace the bridge with a native scanner implementation so the app is self-contained.

### PyInstaller package lane

```zsh
packaging/macos/build-koda-app.command
```

The local build creates an unsigned test package at:

```text
dist/macos/KODA.app
dist/macos/KODA-0.1.0-unsigned.pkg
```

## App Store signed build

Set the signing identities from Keychain before running the build:

```zsh
BUNDLE_ID="com.yourcompany.koda" \
CODE_SIGN_IDENTITY="3rd Party Mac Developer Application: Your Company (TEAMID)" \
INSTALLER_SIGN_IDENTITY="3rd Party Mac Developer Installer: Your Company (TEAMID)" \
packaging/macos/build-koda-app.command
```

The signed package is written to:

```text
dist/macos/KODA-0.1.0.pkg
```

Upload the signed package through Transporter or App Store Connect after creating the app record, privacy answers, export-compliance answers, screenshots, and review notes.

## Current limitation

The Xcode app is now the preferred App Store lane, but its first bridge still calls the existing Python scanner during development. Before final App Review submission, make the scanner runtime self-contained, run a full sandbox QA pass on a clean Mac, and verify folder selection, OSV opt-in networking, and scanner access to user-selected folders.

Apple references:

- [Upload builds to App Store Connect](https://developer.apple.com/help/app-store-connect/manage-builds/upload-builds/)
- [App Sandbox](https://developer.apple.com/documentation/security/app_sandbox)
- [Configuring the macOS App Sandbox](https://developer.apple.com/documentation/xcode/configuring-the-macos-app-sandbox)
