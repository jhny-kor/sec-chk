[CmdletBinding()]
param(
    [string]$Version = "0.1.0",
    [switch]$SkipDependencyInstall,
    [string]$InnoCompilerPath,

    # Pinned security-tool versions. Override these parameters when upgrading.
    [string]$SyftVersion = "1.46.0",
    [string]$GrypeVersion = "0.115.0",

    # Use these only when the build cache already contains the required files.
    [switch]$SkipSecurityToolDownload,
    [switch]$SkipGrypeDatabaseUpdate
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
$VenvPython = Join-Path $VenvDir "Scripts\python.exe"

# Playwright Chromium is downloaded once and bundled into the GUI application.
$BrowsersDir = Join-Path $BuildRoot "ms-playwright"

# Syft, Grype and the Grype vulnerability database are staged here.
$SecurityToolsCacheDir = Join-Path $BuildRoot "security-tools"
$SecurityToolsDownloadDir = Join-Path $BuildRoot "security-tool-downloads"
$SyftExe = Join-Path $SecurityToolsCacheDir "syft.exe"
$GrypeExe = Join-Path $SecurityToolsCacheDir "grype.exe"
$GrypeDbDir = Join-Path $SecurityToolsCacheDir "grype-db"
$SecurityToolLicensesDir = Join-Path $SecurityToolsCacheDir "licenses"

$GuiEntryPoint = Join-Path $RepoRoot "platforms\windows\scripts\koda-desktop.py"
$CliEntryPoint = Join-Path $BuildRoot "koda-cli-entry.py"
$RuntimeHook = Join-Path $BuildRoot "koda-runtime-env.py"

$DistDir = Join-Path $RepoRoot "dist"
$AppDistDir = Join-Path $DistDir $AppName
$CliDistDir = Join-Path $AppDistDir $CliAppName
$GuiExecutable = Join-Path $AppDistDir "KODA.exe"
$CliExecutable = Join-Path $CliDistDir "$CliAppName.exe"
$InstalledToolsDir = Join-Path $AppDistDir "tools"

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

function Invoke-KodaDownload {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri,

        [Parameter(Mandatory = $true)]
        [string]$Destination
    )

    $parent = Split-Path -Parent $Destination
    New-Item -ItemType Directory -Path $parent -Force | Out-Null

    Write-Host "Downloading: $Uri"
    Write-Host "Destination: $Destination"

    # GitHub releases require modern TLS.
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    Invoke-WebRequest `
        -Uri $Uri `
        -OutFile $Destination `
        -UseBasicParsing

    if (-not (Test-Path -LiteralPath $Destination -PathType Leaf)) {
        throw "Download did not create the expected file: $Destination"
    }

    $size = (Get-Item -LiteralPath $Destination).Length
    if ($size -le 0) {
        throw "Downloaded file is empty: $Destination"
    }
}

function Install-ZippedSecurityTool {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ToolName,

        [Parameter(Mandatory = $true)]
        [string]$Version,

        [Parameter(Mandatory = $true)]
        [string]$DownloadUri,

        [Parameter(Mandatory = $true)]
        [string]$ExecutableName,

        [Parameter(Mandatory = $true)]
        [string]$DestinationExecutable
    )

    $toolDownloadDir = Join-Path $SecurityToolsDownloadDir $ToolName
    $archivePath = Join-Path $toolDownloadDir "$ToolName-$Version-windows-amd64.zip"
    $extractDir = Join-Path $toolDownloadDir "extracted"

    if (Test-Path -LiteralPath $toolDownloadDir) {
        Remove-Item -LiteralPath $toolDownloadDir -Recurse -Force
    }

    New-Item -ItemType Directory -Path $toolDownloadDir -Force | Out-Null

    Invoke-KodaDownload -Uri $DownloadUri -Destination $archivePath

    Write-Host "Extracting $ToolName $Version."
    Expand-Archive `
        -LiteralPath $archivePath `
        -DestinationPath $extractDir `
        -Force

    $executable = Get-ChildItem `
        -LiteralPath $extractDir `
        -Filter $ExecutableName `
        -File `
        -Recurse |
        Select-Object -First 1

    if (-not $executable) {
        throw "$ExecutableName was not found in downloaded $ToolName archive."
    }

    New-Item -ItemType Directory -Path $SecurityToolsCacheDir -Force | Out-Null
    Copy-Item `
        -LiteralPath $executable.FullName `
        -Destination $DestinationExecutable `
        -Force

    # Preserve upstream license text when the release archive includes it.
    $license = Get-ChildItem `
        -LiteralPath $extractDir `
        -File `
        -Recurse |
        Where-Object { $_.Name -match '^LICENSE(?:\..*)?$' } |
        Select-Object -First 1

    if ($license) {
        New-Item -ItemType Directory -Path $SecurityToolLicensesDir -Force | Out-Null
        Copy-Item `
            -LiteralPath $license.FullName `
            -Destination (Join-Path $SecurityToolLicensesDir "$ToolName-LICENSE.txt") `
            -Force
    }
}

function Test-SecurityTool {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ToolName,

        [Parameter(Mandatory = $true)]
        [string]$Executable
    )

    if (-not (Test-Path -LiteralPath $Executable -PathType Leaf)) {
        throw "$ToolName executable was not found: $Executable"
    }

    Write-Host "Checking $ToolName executable."
    & $Executable --version

    if ($LASTEXITCODE -ne 0) {
        throw "$ToolName version check failed: $Executable"
    }
}

function Update-GrypeDatabase {
    if (Test-Path -LiteralPath $GrypeDbDir) {
        Remove-Item -LiteralPath $GrypeDbDir -Recurse -Force
    }

    New-Item -ItemType Directory -Path $GrypeDbDir -Force | Out-Null

    $previousCacheDir = $env:GRYPE_DB_CACHE_DIR
    $previousAutoUpdate = $env:GRYPE_DB_AUTO_UPDATE
    $previousValidateAge = $env:GRYPE_DB_VALIDATE_AGE
    $previousCheckForAppUpdate = $env:GRYPE_CHECK_FOR_APP_UPDATE

    try {
        $env:GRYPE_DB_CACHE_DIR = $GrypeDbDir
        $env:GRYPE_DB_AUTO_UPDATE = "true"
        $env:GRYPE_DB_VALIDATE_AGE = "false"
        $env:GRYPE_CHECK_FOR_APP_UPDATE = "false"

        Write-Host "Downloading the Grype vulnerability database."
        & $GrypeExe db update

        if ($LASTEXITCODE -ne 0) {
            throw "Grype vulnerability database update failed."
        }

        Write-Host "Validating the downloaded Grype vulnerability database."
        $statusPath = Join-Path $SecurityToolsCacheDir "grype-db-status.json"
        & $GrypeExe db status -o json |
            Set-Content -LiteralPath $statusPath -Encoding UTF8

        if ($LASTEXITCODE -ne 0) {
            throw "Grype database status check failed."
        }

        $dbFiles = @(
            Get-ChildItem `
                -LiteralPath $GrypeDbDir `
                -File `
                -Recurse `
                -ErrorAction SilentlyContinue
        )

        if ($dbFiles.Count -eq 0) {
            throw "Grype database update completed without creating database files: $GrypeDbDir"
        }
    }
    finally {
        $env:GRYPE_DB_CACHE_DIR = $previousCacheDir
        $env:GRYPE_DB_AUTO_UPDATE = $previousAutoUpdate
        $env:GRYPE_DB_VALIDATE_AGE = $previousValidateAge
        $env:GRYPE_CHECK_FOR_APP_UPDATE = $previousCheckForAppUpdate
    }
}

function Confirm-GrypeDatabaseExists {
    if (-not (Test-Path -LiteralPath $GrypeDbDir -PathType Container)) {
        throw @"
The Grype database cache does not exist:

$GrypeDbDir

Run the build without -SkipGrypeDatabaseUpdate while connected to the internet.
"@
    }

    $dbFiles = @(
        Get-ChildItem `
            -LiteralPath $GrypeDbDir `
            -File `
            -Recurse `
            -ErrorAction SilentlyContinue
    )

    if ($dbFiles.Count -eq 0) {
        throw "The Grype database cache is empty: $GrypeDbDir"
    }
}

function Write-SecurityToolManifest {
    $syftHash = (Get-FileHash -LiteralPath $SyftExe -Algorithm SHA256).Hash
    $grypeHash = (Get-FileHash -LiteralPath $GrypeExe -Algorithm SHA256).Hash
    $generatedAt = [DateTimeOffset]::UtcNow.ToString("o")

    $manifest = @"
KODA bundled security tools
Generated at UTC: $generatedAt

Syft version requested: $SyftVersion
Syft executable: tools\syft.exe
Syft SHA256: $syftHash

Grype version requested: $GrypeVersion
Grype executable: tools\grype.exe
Grype SHA256: $grypeHash

Grype database: tools\grype-db
Grype database auto-update at runtime: disabled
"@

    Write-Utf8NoBomFile `
        -Path (Join-Path $SecurityToolsCacheDir "TOOL-VERSIONS.txt") `
        -Content $manifest
}

Write-Host "Preparing KODA Windows installer build."
Write-Host "Repository: $RepoRoot"
Write-Host "Syft version: $SyftVersion"
Write-Host "Grype version: $GrypeVersion"

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
New-Item -ItemType Directory -Path $SecurityToolsCacheDir -Force | Out-Null

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
    Write-Host "Skipping Python dependency installation."

    & $VenvPython -m PyInstaller --version *> $null

    if ($LASTEXITCODE -ne 0) {
        throw "PyInstaller is not installed in the build virtual environment. Run again without -SkipDependencyInstall."
    }
}

# ---------------------------------------------------------------------------
# Download Syft and Grype for Windows x86_64.
# ---------------------------------------------------------------------------

if (-not $SkipSecurityToolDownload) {
    $syftUri = "https://github.com/anchore/syft/releases/download/v$SyftVersion/syft_${SyftVersion}_windows_amd64.zip"
    $grypeUri = "https://github.com/anchore/grype/releases/download/v$GrypeVersion/grype_${GrypeVersion}_windows_amd64.zip"

    Install-ZippedSecurityTool `
        -ToolName "syft" `
        -Version $SyftVersion `
        -DownloadUri $syftUri `
        -ExecutableName "syft.exe" `
        -DestinationExecutable $SyftExe

    Install-ZippedSecurityTool `
        -ToolName "grype" `
        -Version $GrypeVersion `
        -DownloadUri $grypeUri `
        -ExecutableName "grype.exe" `
        -DestinationExecutable $GrypeExe
}
else {
    Write-Host "Skipping Syft and Grype downloads. Using cached executables."
}

Test-SecurityTool -ToolName "Syft" -Executable $SyftExe
Test-SecurityTool -ToolName "Grype" -Executable $GrypeExe

if (-not $SkipGrypeDatabaseUpdate) {
    Update-GrypeDatabase
}
else {
    Write-Host "Skipping Grype database update. Using cached database."
    Confirm-GrypeDatabaseExists
}

Write-SecurityToolManifest

# ---------------------------------------------------------------------------
# Generate runtime hook shared by GUI and CLI builds.
#
# The hook runs before application imports and points KODA at the bundled tools.
# ---------------------------------------------------------------------------

$runtimeHookSource = @'
from __future__ import annotations

import os
import sys
from pathlib import Path


def _install_root() -> Path:
    executable_dir = Path(sys.executable).resolve().parent

    # GUI:
    #   KODA\KODA.exe
    #
    # CLI:
    #   KODA\KODA-CLI\KODA-CLI.exe
    if executable_dir.name.casefold() == "koda-cli":
        return executable_dir.parent

    return executable_dir


root = _install_root()
tools = root / "tools"
syft = tools / "syft.exe"
grype = tools / "grype.exe"
grype_db = tools / "grype-db"

if syft.is_file():
    os.environ.setdefault("KODA_SYFT_BIN", str(syft))

if grype.is_file():
    os.environ.setdefault("KODA_GRYPE_BIN", str(grype))

if grype_db.is_dir():
    os.environ.setdefault("GRYPE_DB_CACHE_DIR", str(grype_db))

# NVD and CISA KEV ship as a separate data package because they change daily
# while the application does not. Unzip koda-vuln-data-<date>.zip into the
# install directory and jar-scan picks it up here; without it the scan still
# runs on Grype alone.
vuln_data = root / "vuln-data"
nvd_data = vuln_data / "nvd"
cisa_kev = vuln_data / "known_exploited_vulnerabilities.json"

if nvd_data.is_dir():
    os.environ.setdefault("KODA_NVD_DATA", str(nvd_data))

if cisa_kev.is_file():
    os.environ.setdefault("KODA_CISA_KEV", str(cisa_kev))

# The installed product is intended to work without internet access.
os.environ.setdefault("GRYPE_DB_AUTO_UPDATE", "false")
os.environ.setdefault("GRYPE_DB_VALIDATE_AGE", "false")
os.environ.setdefault("GRYPE_CHECK_FOR_APP_UPDATE", "false")

# Reuse Chromium bundled in the GUI application from the CLI build as well.
browser_candidates = (
    root / "_internal" / "ms-playwright",
    root / "ms-playwright",
)

for candidate in browser_candidates:
    if candidate.is_dir():
        os.environ.setdefault("PLAYWRIGHT_BROWSERS_PATH", str(candidate))
        break
'@

Write-Utf8NoBomFile `
    -Path $RuntimeHook `
    -Content $runtimeHookSource

# Console entry point for KODA-CLI.exe.
$cliEntrySource = @'
from __future__ import annotations

from security_scanner.cli import main


if __name__ == "__main__":
    raise SystemExit(main())
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
    "--windowed",

    "--name", $AppName,
    "--distpath", $DistDir,
    "--workpath", $guiWorkPath,
    "--specpath", $guiSpecPath,
    "--paths", $SharedPythonRoot,
    "--runtime-hook", $RuntimeHook,

    "--add-data",
    (
        (
            Join-Path $SharedPythonRoot `
                "security_scanner\assets\koda-hwpx-template.hwpx"
        ) + ";security_scanner\assets"
    ),

    "--collect-submodules", "security_scanner",
    "--hidden-import", "security_scanner.web",

    "--collect-all", "webview",
    "--collect-all", "clr_loader",
    "--collect-all", "pythonnet",
    "--collect-all", "playwright",

    "--hidden-import", "tkinter",
    "--hidden-import", "tkinter.filedialog",
    "--hidden-import", "tkinter.messagebox"
)

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

if (-not (Test-Path -LiteralPath $GuiExecutable -PathType Leaf)) {
    throw "KODA.exe was not created: $GuiExecutable"
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
    "--console",

    "--name", $CliAppName,
    "--distpath", $AppDistDir,
    "--workpath", $cliWorkPath,
    "--specpath", $cliSpecPath,
    "--paths", $SharedPythonRoot,
    "--runtime-hook", $RuntimeHook,

    "--add-data",
    (
        (
            Join-Path $SharedPythonRoot `
                "security_scanner\assets\koda-hwpx-template.hwpx"
        ) + ";security_scanner\assets"
    ),

    "--collect-submodules", "security_scanner",
    "--hidden-import", "security_scanner.web",
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

# ---------------------------------------------------------------------------
# Copy Syft, Grype and the Grype DB into the installation tree.
# ---------------------------------------------------------------------------

if (Test-Path -LiteralPath $InstalledToolsDir) {
    Remove-Item -LiteralPath $InstalledToolsDir -Recurse -Force
}

Copy-Item `
    -LiteralPath $SecurityToolsCacheDir `
    -Destination $InstalledToolsDir `
    -Recurse `
    -Force

if (-not (Test-Path -LiteralPath (
    Join-Path $InstalledToolsDir "syft.exe"
) -PathType Leaf)) {
    throw "Bundled syft.exe was not copied into the installer tree."
}

if (-not (Test-Path -LiteralPath (
    Join-Path $InstalledToolsDir "grype.exe"
) -PathType Leaf)) {
    throw "Bundled grype.exe was not copied into the installer tree."
}

Confirm-GrypeDatabaseExists

# Root-level CLI launcher.
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

# Start Menu shell that remains open.
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
# Copy documentation and example configuration files.
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
# Build KODASetup.exe.
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
Write-Host "GUI executable: $GuiExecutable"
Write-Host "CLI executable: $CliExecutable"
Write-Host "Bundled tools: $InstalledToolsDir"
Write-Host "Installer: $setupPath"
Write-Host ""
Write-Host "Installed CLI example:"
Write-Host '  "%LOCALAPPDATA%\KODA\KODA-CLI.cmd" jar-scan --target . --output-dir output --fail-on high'
Write-Host ""
Write-Host "Syft, Grype and the Grype DB will be detected automatically."
