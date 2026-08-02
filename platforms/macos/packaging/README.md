# KODA macOS App Store Packaging

This folder contains the first App Store packaging lane for the macOS app named `KODA`.

## What is included

- `assets/KODA.icns`: app icon generated from the supplied KODA image.
- `assets/KODA-AppStore-1024.png`: 1024 px App Store marketing icon source.
- `KODA.entitlements`: App Sandbox entitlements required for Mac App Store distribution.
- `../app/KODA/KODA.xcodeproj`: native SwiftUI macOS project for the App Store lane. The app supports folder selection, multiple file selection, and common archive inputs with a built-in Swift scanner.
- `../scripts/build-koda-xcode-app.command`: builds the native Xcode app to `dist/macos/KODA.app`, including the offline Java scanner assets.
- `../scripts/prepare-java-scan-assets.command`: builds the embedded Python scanner, downloads checksum-verified Syft/Grype release binaries, and stages the offline Grype/NVD/CISA data pack.
- `../scripts/archive-koda-app-store.command`: prepares the assets and creates an App Store archive.
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

The Xcode app uses the native Swift scanner for its standard scan. Its Java archive scan menu uses an embedded Python helper plus bundled Syft, Grype, Grype DB, NVD, and CISA KEV data; the shipped app does not download or execute any scanner code at runtime. The local build output is:

```text
dist/macos/KODA.app
```

The App Store Java helper packages only the command-line scan path. Dashboard
server and Tk folder-picker modules are explicitly excluded from this helper so
Tcl/Tk is not shipped in the App Store bundle. This exclusion does not apply to
the shared Python, Windows, Linux, or legacy macOS application lanes.

The release scripts default to `arm64`, matching the bundled scanner helper.
Build an Intel asset pack on an Intel macOS build host and set
`KODA_MACOS_ARCHS=x86_64` before producing an Intel release. The staging phase
fails instead of shipping a universal app when a matching helper, Syft, or
Grype binary is absent.

`prepare-java-scan-assets.command` obtains NVD feeds from 2002 through the
current year by default. The Java scan has no default archive-count, archive
size, entry-count, or nesting-depth limit; any optional traversal limit must
be supplied explicitly through the CLI.

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
platforms/macos/scripts/archive-koda-app-store.command
```

The archive script passes the `KODA_APP_STORE` Swift condition. In that build,
the native web scanner is restricted to GET/HEAD read-only requests; login POSTs,
active probes, ZAP, and state-changing scenarios are disabled. Run the complete
21-control profile-driven audit through the shared Python CLI or the direct
distribution, and keep App Store capability gaps as `UNSUPPORTED`/review rather
than treating them as PASS.

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

The Xcode app is the preferred App Store lane. The Java scan reads selected JAR/WAR/EAR files as data only; it never invokes Java or executes archive content. Before App Review submission, verify the signed archive with `codesign --verify --deep --strict --verbose=2`, inspect each helper entitlement, and run an offline JAR smoke test from the exported app.

Apple references:

- [Upload builds to App Store Connect](https://developer.apple.com/help/app-store-connect/manage-builds/upload-builds/)
- [App Sandbox](https://developer.apple.com/documentation/security/app_sandbox)
- [Configuring the macOS App Sandbox](https://developer.apple.com/documentation/xcode/configuring-the-macos-app-sandbox)
