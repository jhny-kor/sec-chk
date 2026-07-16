[CmdletBinding()]
param(
    [string]$Version = "0.1.0",
    [switch]$SkipDependencyInstall,
    [string]$InnoCompilerPath
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if ($env:OS -ne "Windows_NT") {
    throw "This build script must be run on Windows. PyInstaller should build Windows executables on Windows."
}

$AppName = "KODA"
$CliAppName = "KODA-CLI"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")).Path
$SharedPythonRoot = Join-Path $RepoRoot "platforms\shared\python"
$BuildRoot = Join-Path $RepoRoot ".build\koda-windows-installer"
$VenvDir = Join-Path $BuildRoot ".venv"

# Chromium for Playwright is downloaded once and bundled into the GUI app.
# The CLI entry point reuses the GUI app's bundled Chromium at runtime.
$BrowsersDir = Join-Path $BuildRoot "ms-playwright"

$VenvPython = Join-Path $VenvDir "Scripts\python.exe"

$GuiEntryPoint = Join-Path $RepoRoot "platforms\windows\scripts\koda-desktop.py"
$CliEntryPoint = Join-Path $BuildRoot "koda-cli-entry.py"

$DistDir = Join-Path $RepoRoot "dist"
$AppDistDir = Join-Path $DistDir $AppName
$CliDistDir = Join-Path $AppDistDir $CliAppName
$CliExecutable = Join-Path $CliDistDir "$CliAppName.exe"

$InstallerOutDir = Join-Path $DistDir "Windows"
$InnoScript = Join-Path $RepoRoot "platforms\windows\packaging\KODA.iss"
$IconPath = Join-Path $RepoRoot "platforms\windows\assets\KODA.ico"

function Find-Python310 {
    $candidates = @(
        [pscustomobject]@{ Command = "py"; Args = @("-3") },
        [pscustomobject]@{ Command = "python"; Args = @() },
        [pscustomobject]@{ Command = "python3"; Args = @() }
    )

    foreach ($candidate in $candidates) {
        $command = $candidate.Command
        $prefixArgs = @($candidate.Args)

        if (-not (Get-Command $command -ErrorAction SilentlyContinue)) {
            continue
        }

        $testArgs = $prefixArgs + @(
            "-c",
            "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)"
        )

        & $command @testArgs *> $null

        if ($LASTEXITCODE -eq 0) {
            return $candidate
        }
    }

    throw "Python 3.10 or newer was not found. Install Python 3.10+ and run this build script again."
}

function Find-InnoCompiler {
    param([string]$RequestedPath)

    if ($RequestedPath) {
        if (Test-Path -LiteralPath $RequestedPath -PathType Leaf) {
            return (Resolve-Path -LiteralPath $RequestedPath).Path
        }

        throw "Inno Setup compiler was not found at: $RequestedPath"
    }

    $candidates = @()

    if (${env:ProgramFiles(x86)}) {
        $candidates += (
            Join-Path ${env:ProgramFiles(x86)} "Inno Setup 6\ISCC.exe"
        )
    }

    if ($env:ProgramFiles) {
        $candidates += (
            Join-Path $env:ProgramFiles "Inno Setup 6\ISCC.exe"
        )
    }

    foreach ($candidate in $candidates) {
        if ($candidate -and (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            return $candidate
        }
    }

    $command = Get-Command "ISCC.exe" -ErrorAction SilentlyContinue

    if ($command) {
        return $command.Source
    }

    throw "Inno Setup 6 compiler was not found. Install Inno Setup 6 or pass -InnoCompilerPath."
}

function Ensure-VenvPip {
    param([string]$PythonPath)

    & $PythonPath -m pip --version *> $null

    if ($LASTEXITCODE -eq 0) {
        return
    }

    Write-Host "pip is missing from the build virtual environment. Running ensurepip."

    & $PythonPath -m ensurepip --upgrade

    if ($LASTEXITCODE -ne 0) {
        throw @"
The virtual environment does not contain pip, and ensurepip failed.
Delete this directory and run the build again:

$VenvDir

If the problem continues, repair or reinstall Python with pip and venv enabled.
"@
    }

    & $PythonPath -m pip --version *> $null

    if ($LASTEXITCODE -ne 0) {
        throw "pip is still unavailable after running ensurepip."
    }
}

function Write-Utf8NoBomFile {
    param(
        [string]$Path,
        [string]$Content
    )

    $encoding = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($Path, $Content, $encoding)
}

Write-Host "Preparing KODA Windows installer build."
Write-Host "Repository: $RepoRoot"

if (-not (Test-Path -LiteralPath $GuiEntryPoint -PathType Leaf)) {
    throw "Missing GUI PyInstaller entry point: $GuiEntryPoint"
}

if (-not (Test-Path -LiteralPath (
    Join-Path $SharedPythonRoot "security_scanner"
) -PathType Container)) {
    throw "security_scanner package was not found. Run this script from the full repository."
}

if (-not (Test-Path -LiteralPath $InnoScript -PathType Leaf)) {
    throw "Missing Inno Setup script: $InnoScript"
}

New-Item -ItemType Directory -Path $BuildRoot -Force | Out-Null
New-Item -ItemType Directory -Path $InstallerOutDir -Force | Out-Null

$python = Find-Python310
$pythonCommand = $python.Command
$pythonArgs = @($python.Args)

if (-not (Test-Path -LiteralPath $VenvPython -PathType Leaf)) {
    Write-Host "Creating build virtual environment."

    & $pythonCommand @(
        $pythonArgs + @(
            "-m",
            "venv",
            $VenvDir
        )
    )

    if ($LASTEXITCODE -ne 0) {
        throw "Failed to create build virtual environment."
    }
}

Ensure-VenvPip -PythonPath $VenvPython

if (-not $SkipDependencyInstall) {
    Write-Host "Upgrading pip."

    & $VenvPython -m pip install --upgrade pip

    if ($LASTEXITCODE -ne 0) {
        throw "Failed to upgrade pip."
    }

    Write-Host "Installing build dependencies."

    # pywebview: Windows GUI window using Edge WebView2
    # playwright: optional SPA rendering during web scans
    & $VenvPython -m pip install --upgrade `
        pyinstaller `
        pywebview `
        "playwright==1.61.0"

    if ($LASTEXITCODE -ne 0) {
        throw "Failed to install PyInstaller, pywebview, and playwright."
    }

    Write-Host "Downloading Playwright Chromium for offline SPA rendering."

    $env:PLAYWRIGHT_BROWSERS_PATH = $BrowsersDir

    & $VenvPython -m playwright install chromium

    if ($LASTEXITCODE -ne 0) {
        throw "Failed to download Playwright Chromium."
    }
}
else {
    Write-Host "Skipping dependency installation."

    & $VenvPython -m PyInstaller --version *> $null

    if ($LASTEXITCODE -ne 0) {
        throw "PyInstaller is not installed in the build virtual environment. Run again without -SkipDependencyInstall."
    }
}

# Generate a small console entry point.
# It imports the same security_scanner.cli.main() used by:
# python -m security_scanner
$cliEntrySource = @'
from __future__ import annotations

import os
import sys
from pathlib import Path


def configure_bundled_chromium() -> None:
    """Reuse Chromium bundled with the adjacent GUI installation."""
    if not getattr(sys, "frozen", False):
        return

    executable_dir = Path(sys.executable).resolve().parent

    # Installed layout:
    # KODA\
    #   KODA.exe
    #   _internal\ms-playwright\
    #   KODA-CLI\KODA-CLI.exe
    install_root = executable_dir.parent

    candidates = (
        install_root / "_internal" / "ms-playwright",
        install_root / "ms-playwright",
    )

    for candidate in candidates:
        if candidate.is_dir():
            os.environ["PLAYWRIGHT_BROWSERS_PATH"] = str(candidate)
            break


def run() -> int:
    configure_bundled_chromium()

    from security_scanner.cli import main

    return main()


if __name__ == "__main__":
    raise SystemExit(run())
'@

Write-Utf8NoBomFile `
    -Path $CliEntryPoint `
    -Content $cliEntrySource

if (Test-Path -LiteralPath $AppDistDir) {
    Write-Host "Removing previous application build: $AppDistDir"
    Remove-Item -LiteralPath $AppDistDir -Recurse -Force
}

# ---------------------------------------------------------------------------
# Build GUI application: dist\KODA\KODA.exe
# ---------------------------------------------------------------------------

$guiWorkPath = Join-Path $BuildRoot "pyinstaller-gui-work"
$guiSpecPath = Join-Path $BuildRoot "pyinstaller-gui-spec"

$guiPyInstallerArgs = @(
    "--noconfirm",
    "--clean",
    "--onedir",

    # GUI application: do not show a console window.
    "--windowed",

    "--name", $AppName,
    "--distpath", $DistDir,
    "--workpath", $guiWorkPath,
    "--specpath", $guiSpecPath,
    "--paths", $SharedPythonRoot,

    # Report template used by HWPX export.
    "--add-data",
    (
        (
            Join-Path $SharedPythonRoot `
                "security_scanner\assets\koda-hwpx-template.hwpx"
        ) + ";security_scanner\assets"
    ),

    # Modules such as host posture, inventory, EOL, CPE and web scanning
    # are imported lazily.
    "--collect-submodules", "security_scanner",
    "--hidden-import", "security_scanner.web",

    # Native Windows GUI backend.
    "--collect-all", "webview",
    "--collect-all", "clr_loader",
    "--collect-all", "pythonnet",

    # Playwright Python driver and package data.
    "--collect-all", "playwright",

    "--hidden-import", "tkinter",
    "--hidden-import", "tkinter.filedialog",
    "--hidden-import", "tkinter.messagebox"
)

# Put Chromium inside the GUI application's _internal\ms-playwright directory.
if (Test-Path -LiteralPath $BrowsersDir -PathType Container) {
    $guiPyInstallerArgs += @(
        "--add-data",
        ($BrowsersDir + ";ms-playwright")
    )
}
else {
    Write-Warning @"
Chromium was not found at:

$BrowsersDir

KODA will still build, but Playwright SPA rendering will not be available.
Run the script again without -SkipDependencyInstall to download Chromium.
"@
}

if (Test-Path -LiteralPath $IconPath -PathType Leaf) {
    $guiPyInstallerArgs += @(
        "--icon",
        $IconPath
    )
}

$guiPyInstallerArgs += $GuiEntryPoint

Write-Host "Building KODA.exe with PyInstaller."

& $VenvPython -m PyInstaller @guiPyInstallerArgs

if ($LASTEXITCODE -ne 0) {
    throw "KODA GUI PyInstaller build failed."
}

$guiExecutable = Join-Path $AppDistDir "KODA.exe"

if (-not (Test-Path -LiteralPath $guiExecutable -PathType Leaf)) {
    throw "KODA.exe was not created: $guiExecutable"
}

# ---------------------------------------------------------------------------
# Build CLI application: dist\KODA\KODA-CLI\KODA-CLI.exe
# ---------------------------------------------------------------------------

$cliWorkPath = Join-Path $BuildRoot "pyinstaller-cli-work"
$cliSpecPath = Join-Path $BuildRoot "pyinstaller-cli-spec"

$cliPyInstallerArgs = @(
    "--noconfirm",
    "--clean",
    "--onedir",

    # CLI application: keep the console attached.
    "--console",

    "--name", $CliAppName,

    # Using AppDistDir creates:
    # dist\KODA\KODA-CLI\KODA-CLI.exe
    "--distpath", $AppDistDir,
    "--workpath", $cliWorkPath,
    "--specpath", $cliSpecPath,
    "--paths", $SharedPythonRoot,

    "--add-data",
    (
        (
            Join-Path $SharedPythonRoot `
                "security_scanner\assets\koda-hwpx-template.hwpx"
        ) + ";security_scanner\assets"
    ),

    "--collect-submodules", "security_scanner",
    "--hidden-import", "security_scanner.web",

    # CLI can use Playwright for web-scan --render.
    # Chromium itself is not duplicated; the generated entry point points
    # PLAYWRIGHT_BROWSERS_PATH to the GUI application's bundled browser.
    "--collect-all", "playwright",

    "--hidden-import", "tkinter",
    "--hidden-import", "tkinter.filedialog",
    "--hidden-import", "tkinter.messagebox"
)

if (Test-Path -LiteralPath $IconPath -PathType Leaf) {
    $cliPyInstallerArgs += @(
        "--icon",
        $IconPath
    )
}

$cliPyInstallerArgs += $CliEntryPoint

Write-Host "Building KODA-CLI.exe with PyInstaller."

& $VenvPython -m PyInstaller @cliPyInstallerArgs

if ($LASTEXITCODE -ne 0) {
    throw "KODA CLI PyInstaller build failed."
}

if (-not (Test-Path -LiteralPath $CliExecutable -PathType Leaf)) {
    throw "KODA-CLI.exe was not created: $CliExecutable"
}

# Root-level launcher:
# %LOCALAPPDATA%\KODA\KODA-CLI.cmd
$cliLauncherPath = Join-Path $AppDistDir "KODA-CLI.cmd"

$cliLauncherSource = @'
@echo off
"%~dp0KODA-CLI\KODA-CLI.exe" %*
exit /b %ERRORLEVEL%
'@

Set-Content `
    -LiteralPath $cliLauncherPath `
    -Value $cliLauncherSource `
    -Encoding ASCII

# Optional Start Menu shell. It keeps a command prompt open and makes
# KODA-CLI.cmd available through the current session's PATH.
$cliShellPath = Join-Path $AppDistDir "KODA-CLI-Shell.cmd"

$cliShellSource = @'
@echo off
title KODA CLI
cd /d "%USERPROFILE%"
set "PATH=%~dp0;%PATH%"
echo.
echo KODA CLI
echo Run: KODA-CLI.cmd --help
echo.
%COMSPEC% /K
'@

Set-Content `
    -LiteralPath $cliShellPath `
    -Value $cliShellSource `
    -Encoding ASCII

# ---------------------------------------------------------------------------
# Copy documentation and example configuration files
# ---------------------------------------------------------------------------

foreach ($fileName in @(
    "README.md",
    "scanner_config.example.json",
    "scanner_config.documents.example.json"
)) {
    $source = Join-Path $SharedPythonRoot $fileName

    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
        $source = Join-Path $RepoRoot $fileName
    }

    if (Test-Path -LiteralPath $source -PathType Leaf) {
        Copy-Item `
            -LiteralPath $source `
            -Destination $AppDistDir `
            -Force
    }
}

$docsPath = Join-Path $RepoRoot "docs"

if (Test-Path -LiteralPath $docsPath -PathType Container) {
    Copy-Item `
        -LiteralPath $docsPath `
        -Destination $AppDistDir `
        -Recurse `
        -Force
}

# ---------------------------------------------------------------------------
# Build KODASetup.exe
# ---------------------------------------------------------------------------

$iscc = Find-InnoCompiler -RequestedPath $InnoCompilerPath

Write-Host "Building KODASetup.exe with Inno Setup."

& $iscc "/DMyAppVersion=$Version" $InnoScript

if ($LASTEXITCODE -ne 0) {
    throw "Inno Setup build failed."
}

$setupPath = Join-Path $InstallerOutDir "KODASetup.exe"

if (-not (Test-Path -LiteralPath $setupPath -PathType Leaf)) {
    throw "Installer was not created: $setupPath"
}

Write-Host ""
Write-Host "Build finished successfully."
Write-Host "GUI executable: $guiExecutable"
Write-Host "CLI executable: $CliExecutable"
Write-Host "CLI launcher: $cliLauncherPath"
Write-Host "Installer: $setupPath"
Write-Host ""
Write-Host "Installed GUI:"
Write-Host "  %LOCALAPPDATA%\KODA\KODA.exe"
Write-Host ""
Write-Host "Installed CLI:"
Write-Host "  %LOCALAPPDATA%\KODA\KODA-CLI.cmd --help"
Write-Host "  %LOCALAPPDATA%\KODA\KODA-CLI\KODA-CLI.exe --help"
