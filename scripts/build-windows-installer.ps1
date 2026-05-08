[CmdletBinding()]
param(
    [string]$Version = "0.1.0",
    [switch]$SkipDependencyInstall,
    [string]$InnoCompilerPath
)

$ErrorActionPreference = "Stop"

if ($env:OS -ne "Windows_NT") {
    throw "This build script must be run on Windows. PyInstaller should build Windows executables on Windows."
}

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$BuildRoot = Join-Path $RepoRoot ".build\windows-installer"
$VenvDir = Join-Path $BuildRoot ".venv"
$VenvPython = Join-Path $VenvDir "Scripts\python.exe"
$EntryPoint = Join-Path $RepoRoot "scripts\sec-chk-app.py"
$DistDir = Join-Path $RepoRoot "dist"
$AppDistDir = Join-Path $DistDir "SecChk"
$InstallerOutDir = Join-Path $DistDir "Windows"
$InnoScript = Join-Path $RepoRoot "packaging\windows\SecChk.iss"

function Find-Python310 {
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

    $candidates = @(
        (Join-Path ${env:ProgramFiles(x86)} "Inno Setup 6\ISCC.exe"),
        (Join-Path $env:ProgramFiles "Inno Setup 6\ISCC.exe")
    )

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

Write-Host "Preparing Windows installer build."
Write-Host "Repository: $RepoRoot"

if (-not (Test-Path -LiteralPath $EntryPoint -PathType Leaf)) {
    throw "Missing PyInstaller entry point: $EntryPoint"
}

if (-not (Test-Path -LiteralPath (Join-Path $RepoRoot "security_scanner") -PathType Container)) {
    throw "security_scanner package was not found. Run this script from the full sec-chk repository."
}

New-Item -ItemType Directory -Path $BuildRoot -Force | Out-Null
New-Item -ItemType Directory -Path $InstallerOutDir -Force | Out-Null

$python = Find-Python310
$pythonCommand = $python["Command"]
$pythonArgs = @($python["Args"])

if (-not (Test-Path -LiteralPath $VenvPython -PathType Leaf)) {
    Write-Host "Creating build virtual environment."
    & $pythonCommand @($pythonArgs + @("-m", "venv", $VenvDir))
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to create build virtual environment."
    }
}

if (-not $SkipDependencyInstall) {
    Write-Host "Installing build dependencies."
    & $VenvPython -m pip install --upgrade pip pyinstaller
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to install PyInstaller."
    }
}

if (Test-Path -LiteralPath $AppDistDir) {
    Remove-Item -LiteralPath $AppDistDir -Recurse -Force
}

$workPath = Join-Path $BuildRoot "pyinstaller-work"
$specPath = Join-Path $BuildRoot "pyinstaller-spec"

Write-Host "Building SecChk.exe with PyInstaller."
& $VenvPython -m PyInstaller `
    --noconfirm `
    --clean `
    --onedir `
    --console `
    --name "SecChk" `
    --distpath $DistDir `
    --workpath $workPath `
    --specpath $specPath `
    --paths $RepoRoot `
    --hidden-import tkinter `
    --hidden-import tkinter.filedialog `
    --hidden-import tkinter.messagebox `
    $EntryPoint

if ($LASTEXITCODE -ne 0) {
    throw "PyInstaller build failed."
}

if (-not (Test-Path -LiteralPath (Join-Path $AppDistDir "SecChk.exe") -PathType Leaf)) {
    throw "SecChk.exe was not created."
}

# Keep helpful project files beside the executable. They are not required to run,
# but they help users understand the tool after installation.
foreach ($fileName in @("README.md", "scanner_config.example.json", "scanner_config.documents.example.json")) {
    $source = Join-Path $RepoRoot $fileName
    if (Test-Path -LiteralPath $source -PathType Leaf) {
        Copy-Item -LiteralPath $source -Destination $AppDistDir -Force
    }
}

if (Test-Path -LiteralPath (Join-Path $RepoRoot "docs") -PathType Container) {
    Copy-Item -LiteralPath (Join-Path $RepoRoot "docs") -Destination $AppDistDir -Recurse -Force
}

$iscc = Find-InnoCompiler -RequestedPath $InnoCompilerPath

Write-Host "Building SecChkSetup.exe with Inno Setup."
& $iscc "/DMyAppVersion=$Version" $InnoScript
if ($LASTEXITCODE -ne 0) {
    throw "Inno Setup build failed."
}

$setupPath = Join-Path $InstallerOutDir "SecChkSetup.exe"
if (-not (Test-Path -LiteralPath $setupPath -PathType Leaf)) {
    throw "Installer was not created: $setupPath"
}

Write-Host ""
Write-Host "Build finished successfully."
Write-Host "Installer: $setupPath"
Write-Host "Installed users will run SecChk from the Start Menu or desktop shortcut."
Write-Host "Double-clicking SecChk starts the local dashboard and opens the default web browser."
