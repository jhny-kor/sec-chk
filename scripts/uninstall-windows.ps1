[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

$InstallRoot = Join-Path $env:LOCALAPPDATA "SecChk"
$StartMenuDir = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\SecChk"
$DesktopShortcut = Join-Path ([Environment]::GetFolderPath("Desktop")) "SecChk.lnk"

Write-Host "Removing SecChk shortcuts and install files."

Remove-Item -Path $StartMenuDir -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path $DesktopShortcut -Force -ErrorAction SilentlyContinue

if (Test-Path $InstallRoot) {
    Set-Location $env:TEMP
    Remove-Item -Path $InstallRoot -Recurse -Force
}

Write-Host "SecChk was removed."
