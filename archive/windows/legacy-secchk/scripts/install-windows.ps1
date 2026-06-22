[CmdletBinding()]
param(
    [switch]$NoStartMenuShortcut,
    [switch]$DesktopShortcut,
    [switch]$ForceRecreateVenv
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$InstallRoot = Join-Path $env:LOCALAPPDATA "SecChk"
$AppDir = Join-Path $InstallRoot "app"
$VenvDir = Join-Path $InstallRoot ".venv"
$LauncherPath = Join-Path $InstallRoot "SecChk.bat"
$CliLauncherPath = Join-Path $InstallRoot "SecChk-CLI.bat"
$UninstallPath = Join-Path $InstallRoot "Uninstall-SecChk.ps1"

$ScriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$RepoRoot = (Resolve-Path (Join-Path $ScriptRoot "..")).Path

function Assert-PathExists {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Description,
        [ValidateSet("File", "Directory")][string]$Type = "File"
    )

    $pathType = if ($Type -eq "Directory") { "Container" } else { "Leaf" }
    if (-not (Test-Path -LiteralPath $Path -PathType $pathType)) {
        throw "$Description was not found: $Path. Download or clone the full sec-chk repository, extract the ZIP if needed, then run scripts\install-windows.bat."
    }
}

function Assert-SourceTree {
    Assert-PathExists -Path (Join-Path $RepoRoot "security_scanner") -Description "security_scanner folder" -Type Directory
    Assert-PathExists -Path (Join-Path $RepoRoot "pyproject.toml") -Description "pyproject.toml" -Type File
    Assert-PathExists -Path (Join-Path $ScriptRoot "uninstall-windows.ps1") -Description "uninstall-windows.ps1" -Type File
}

function Test-PythonVersion {
    param(
        [Parameter(Mandatory = $true)][string]$Command,
        [string[]]$Args = @()
    )

    $testArgs = @($Args) + @("-c", "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)")
    & $Command @testArgs *> $null
    return ($LASTEXITCODE -eq 0)
}

function Find-Python {
    $candidates = @(
        [pscustomobject]@{ Command = "py"; Args = @("-3") },
        [pscustomobject]@{ Command = "python"; Args = @() },
        [pscustomobject]@{ Command = "python3"; Args = @() }
    )

    foreach ($candidate in $candidates) {
        if (-not (Get-Command $candidate.Command -ErrorAction SilentlyContinue)) {
            continue
        }
        if (Test-PythonVersion -Command $candidate.Command -Args $candidate.Args) {
            return $candidate
        }
    }

    throw "Python 3.10 or newer was not found. Install Python from https://www.python.org/downloads/windows/ and run this installer again."
}

function Test-VenvPython {
    param([Parameter(Mandatory = $true)][string]$PythonPath)

    if (-not (Test-Path -LiteralPath $PythonPath -PathType Leaf)) {
        return $false
    }

    & $PythonPath -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)" *> $null
    return ($LASTEXITCODE -eq 0)
}

function New-SecChkShortcut {
    param(
        [Parameter(Mandatory = $true)][string]$ShortcutPath,
        [Parameter(Mandatory = $true)][string]$TargetPath,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory
    )

    try {
        $shortcutDir = Split-Path -Parent $ShortcutPath
        New-Item -ItemType Directory -Path $shortcutDir -Force | Out-Null

        $shell = New-Object -ComObject WScript.Shell
        $shortcut = $shell.CreateShortcut($ShortcutPath)
        $shortcut.TargetPath = $TargetPath
        $shortcut.WorkingDirectory = $WorkingDirectory
        $shortcut.Description = "Run the SecChk local security dashboard"
        $shortcut.Save()
    }
    catch {
        Write-Warning "Could not create shortcut '$ShortcutPath': $($_.Exception.Message)"
    }
}

function Write-BatchFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Content
    )

    $normalized = ($Content.TrimStart([char[]]@("`r", "`n")) -replace "`r?`n", "`r`n")
    [System.IO.File]::WriteAllText($Path, $normalized, [System.Text.Encoding]::ASCII)
}

Write-Host "Installing SecChk to $InstallRoot"

Assert-SourceTree

$python = Find-Python
New-Item -ItemType Directory -Path $InstallRoot -Force | Out-Null

$venvPython = Join-Path $VenvDir "Scripts\python.exe"
if ($ForceRecreateVenv -or -not (Test-VenvPython -PythonPath $venvPython)) {
    if (Test-Path -LiteralPath $VenvDir) {
        Remove-Item -LiteralPath $VenvDir -Recurse -Force
    }

    $venvArgs = @($python.Args) + @("-m", "venv", $VenvDir)
    & $python.Command @venvArgs
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to create the SecChk Python environment."
    }
}

if (Test-Path -LiteralPath $AppDir) {
    Remove-Item -LiteralPath $AppDir -Recurse -Force
}
New-Item -ItemType Directory -Path $AppDir -Force | Out-Null

Copy-Item -LiteralPath (Join-Path $RepoRoot "security_scanner") -Destination $AppDir -Recurse -Force
foreach ($fileName in @("README.md", "pyproject.toml", "scanner_config.example.json", "scanner_config.documents.example.json")) {
    $source = Join-Path $RepoRoot $fileName
    if (Test-Path -LiteralPath $source -PathType Leaf) {
        Copy-Item -LiteralPath $source -Destination $AppDir -Force
    }
}
if (Test-Path -LiteralPath (Join-Path $RepoRoot "docs") -PathType Container) {
    Copy-Item -LiteralPath (Join-Path $RepoRoot "docs") -Destination $AppDir -Recurse -Force
}
Copy-Item -LiteralPath (Join-Path $ScriptRoot "uninstall-windows.ps1") -Destination $UninstallPath -Force

$launcherContent = @'
@echo off
setlocal
set "SEC_CHK_ROOT=%LOCALAPPDATA%\SecChk"
set "SEC_CHK_APP=%SEC_CHK_ROOT%\app"
set "SEC_CHK_PY=%SEC_CHK_ROOT%\.venv\Scripts\python.exe"

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
'@
Write-BatchFile -Path $LauncherPath -Content $launcherContent

$cliLauncherContent = @'
@echo off
setlocal
set "SEC_CHK_ROOT=%LOCALAPPDATA%\SecChk"
set "SEC_CHK_APP=%SEC_CHK_ROOT%\app"
set "SEC_CHK_PY=%SEC_CHK_ROOT%\.venv\Scripts\python.exe"

if not exist "%SEC_CHK_PY%" (
  echo SecChk Python environment was not found.
  echo Run install-windows.bat again.
  exit /b 1
)

set "PYTHONPATH=%SEC_CHK_APP%;%PYTHONPATH%"
"%SEC_CHK_PY%" -m security_scanner %*
exit /b %ERRORLEVEL%
'@
Write-BatchFile -Path $CliLauncherPath -Content $cliLauncherContent

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
