# KODA macOS App Store Packaging

This folder contains the first App Store packaging lane for the macOS app named `KODA`.

## What is included

- `assets/KODA.icns`: app icon generated from the supplied KODA image.
- `assets/KODA-AppStore-1024.png`: 1024 px App Store marketing icon source.
- `KODA.entitlements`: App Sandbox entitlements required for Mac App Store distribution.
- `../../platforms/macos/KODA/KODA.xcodeproj`: native SwiftUI macOS project for the App Store lane. The app supports folder selection, multiple file selection, and common archive inputs with a built-in Swift scanner.
- `build-koda-xcode-app.command`: builds the native Xcode app to `dist/macos/KODA.app`.
- `build-koda-app.command`: legacy PyInstaller-based macOS app and package build script for non-store experiments.

## Requirements

- macOS with Xcode Command Line Tools.
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
packaging/macos/build-koda-xcode-app.command
```

The Xcode app uses the native Swift scanner in the app target. It does not require `python3` to launch or scan from the `.app` bundle. The local build output is:

```text
dist/macos/KODA.app
```

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

The Xcode app is now the preferred App Store lane, and it can run scans from selected folders, selected files, and supported archives (`zip`, `jar`, `war`, `tar`, `tar.gz`, `tgz`, `gz`) without an external Python runtime. Before final App Review submission, run a full sandbox QA pass on a clean Mac and verify folder selection, multi-file scanning, archive extraction, and scanner access to user-selected folders.

Apple references:

- [Upload builds to App Store Connect](https://developer.apple.com/help/app-store-connect/manage-builds/upload-builds/)
- [App Sandbox](https://developer.apple.com/documentation/security/app_sandbox)
- [Configuring the macOS App Sandbox](https://developer.apple.com/documentation/xcode/configuring-the-macos-app-sandbox)
