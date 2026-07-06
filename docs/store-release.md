# Store Release Notes

This project now has separate store-release lanes for macOS and Windows.

## macOS App Store

The App Store app name is `KODA`.

Primary lane:

- Xcode project: `platforms/macos/app/KODA/KODA.xcodeproj`
- Bundle identifier: `com.jhnykor.koda` by default
- App Sandbox entitlements: `platforms/macos/packaging/KODA.entitlements`
- Icon: `platforms/macos/packaging/assets/KODA.icns`
- App Store 1024 px icon source: `platforms/macos/packaging/assets/KODA-AppStore-1024.png`
- Scanner runtime: native Swift scanner in the KODA app target; no external Python runtime required for `.app` scanning.
- Inputs: folder selection, multiple file selection, and supported archives (`zip`, `jar`, `war`, `tar`, `tar.gz`, `tgz`, `gz`).

Local build check:

```zsh
platforms/macos/scripts/build-koda-xcode-app.command
```

Before submission:

- Set the final Apple Developer Team and Bundle ID in Xcode.
- Use App Sandbox and keep folder access behind user selection.
- Run a clean-Mac sandbox QA pass against the signed archive, including selected folder access and archive extraction.
- Archive in Xcode and upload to App Store Connect, or export and upload with Transporter.

Apple references:

- [Upload builds to App Store Connect](https://developer.apple.com/help/app-store-connect/manage-builds/upload-builds/)
- [App Sandbox](https://developer.apple.com/documentation/security/app_sandbox)
- [Configuring the macOS App Sandbox](https://developer.apple.com/documentation/xcode/configuring-the-macos-app-sandbox)

## Microsoft Store

The direct-download Windows installer is:

```text
dist/Windows/KODASetup.exe
```

That installer is useful for website or GitHub release distribution, but
Microsoft Store submission should be packaged as MSIX and uploaded through
Partner Center.

Recommended lane:

1. Reserve the app name in Partner Center.
2. Build the Windows executable with `platforms\windows\scripts\build-koda-windows-installer.ps1` on Windows.
3. Package the executable as MSIX with Visual Studio or MSIX tooling.
4. Generate a Store upload file (`.msixupload`).
5. Submit the upload package and Store listing metadata in Partner Center.

Microsoft references:

- [MSIX documentation](https://learn.microsoft.com/en-us/windows/msix/)
- [Package a desktop or UWP app in Visual Studio](https://learn.microsoft.com/en-us/windows/msix/package/packaging-uwp-apps)
- [Create an app submission for your MSIX app](https://learn.microsoft.com/en-us/windows/apps/publish/publish-your-app/msix/create-app-submission?pivots=store-installer-msix)
