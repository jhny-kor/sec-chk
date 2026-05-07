[CmdletBinding()]
param(
    [switch]$NoStartMenuShortcut,
    [switch]$DesktopShortcut
)

$ErrorActionPreference = "Stop"

$InstallRoot = Join-Path $env:LOCALAPPDATA "SecChk"
$AppDir = Join-Path $InstallRoot "app"
$VenvDir = Join-Path $InstallRoot ".venv"
$LauncherPath = Join-Path $InstallRoot "SecChk.bat"
$CliLauncherPath = Join-Path $InstallRoot "SecChk-CLI.bat"
$UninstallPath = Join-Path $InstallRoot "Uninstall-SecChk.ps1"
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

function Find-Python {
    $candidates = @(
        @{ Command = "py"; Args = @("-3") },
        @{ Command = "python"; Args = @() },
        @{ Command = "python3"; Args = @() }
    )

    foreach ($candidate in $candidates) {
        $command = $candidate["Command"]
        $prefixArgs = @($candidate["Args"])
        if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {
            continue
        }
        $testArgs = $prefixArgs + @("-c", "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)")
        & $command @testArgs *> $null
        if ($LASTEXITCODE -eq 0) {
            return $candidate
        }
    }

    throw "Python 3.10 or newer was not found. Install Python from https://www.python.org/downloads/windows/ and run this installer again."
}

function New-SecChkShortcut {
    param(
        [Parameter(Mandatory = $true)][string]$ShortcutPath,
        [Parameter(Mandatory = $true)][string]$TargetPath,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory
    )

    $shortcutDir = Split-Path -Parent $ShortcutPath
    New-Item -ItemType Directory -Path $shortcutDir -Force | Out-Null

    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($ShortcutPath)
    $shortcut.TargetPath = $TargetPath
    $shortcut.WorkingDirectory = $WorkingDirectory
    $shortcut.Description = "Run the SecChk local security dashboard"
    $shortcut.Save()
}

Write-Host "Installing SecChk to $InstallRoot"

$python = Find-Python
New-Item -ItemType Directory -Path $InstallRoot -Force | Out-Null

if (-not (Test-Path (Join-Path $VenvDir "Scripts\python.exe"))) {
    $pythonCommand = $python["Command"]
    $venvArgs = @($python["Args"]) + @("-m", "venv", $VenvDir)
    & $pythonCommand @venvArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to create the SecChk Python environment."
    }
}

if (Test-Path $AppDir) {
    Remove-Item -Path $AppDir -Recurse -Force
}
New-Item -ItemType Directory -Path $AppDir -Force | Out-Null

Copy-Item -Path (Join-Path $RepoRoot "security_scanner") -Destination $AppDir -Recurse -Force
foreach ($fileName in @("README.md", "pyproject.toml", "scanner_config.example.json", "scanner_config.documents.example.json")) {
    $source = Join-Path $RepoRoot $fileName
    if (Test-Path $source) {
        Copy-Item -Path $source -Destination $AppDir -Force
    }
}
if (Test-Path (Join-Path $RepoRoot "docs")) {
    Copy-Item -Path (Join-Path $RepoRoot "docs") -Destination $AppDir -Recurse -Force
}
Copy-Item -Path (Join-Path $PSScriptRoot "uninstall-windows.ps1") -Destination $UninstallPath -Force

$venvPython = Join-Path $VenvDir "Scripts\python.exe"

$launcherContent = @"
@echo off
setlocal
set "SEC_CHK_ROOT=$InstallRoot"
set "SEC_CHK_APP=$AppDir"
set "SEC_CHK_PY=$venvPython"

if not exist "%SEC_CHK_PY%" (
  echo SecChk Python environment was not found.
  echo Run install-windows.bat again.
  pause
  exit /b 1
)

set "PYTHONPATH=%SEC_CHK_APP%;%PYTHONPATH%"
cd /d "%USERPROFILE%"
"%SEC_CHK_PY%" -m security_scanner app %*
set "EXIT_CODE=%ERRORLEVEL%"
if not "%EXIT_CODE%"=="0" (
  echo.
  echo SecChk stopped with exit code %EXIT_CODE%.
  pause
)
exit /b %EXIT_CODE%
"@
Set-Content -Path $LauncherPath -Value $launcherContent -Encoding UTF8

$cliLauncherContent = @"
@echo off
setlocal
set "SEC_CHK_APP=$AppDir"
set "SEC_CHK_PY=$venvPython"

if not exist "%SEC_CHK_PY%" (
  echo SecChk Python environment was not found.
  echo Run install-windows.bat again.
  exit /b 1
)

set "PYTHONPATH=%SEC_CHK_APP%;%PYTHONPATH%"
"%SEC_CHK_PY%" -m security_scanner %*
exit /b %ERRORLEVEL%
"@
Set-Content -Path $CliLauncherPath -Value $cliLauncherContent -Encoding UTF8

if (-not $NoStartMenuShortcut) {
    $startMenuDir = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs\SecChk"
    New-SecChkShortcut -ShortcutPath (Join-Path $startMenuDir "SecChk.lnk") -TargetPath $LauncherPath -WorkingDirectory $env:USERPROFILE
}

if ($DesktopShortcut) {
    $desktopPath = [Environment]::GetFolderPath("Desktop")
    New-SecChkShortcut -ShortcutPath (Join-Path $desktopPath "SecChk.lnk") -TargetPath $LauncherPath -WorkingDirectory $env:USERPROFILE
}

Write-Host ""
Write-Host "SecChk was installed successfully."
Write-Host "Run it from the Start Menu shortcut or from:"
Write-Host "  $LauncherPath"
Write-Host ""
Write-Host "CLI launcher:"
Write-Host "  $CliLauncherPath"
Write-Host ""
Write-Host "Uninstall:"
Write-Host "  powershell -NoProfile -ExecutionPolicy Bypass -File `"$UninstallPath`""
