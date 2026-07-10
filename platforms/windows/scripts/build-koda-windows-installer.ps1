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
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")).Path
$SharedPythonRoot = Join-Path $RepoRoot "platforms\shared\python"
$BuildRoot = Join-Path $RepoRoot ".build\koda-windows-installer"
$VenvDir = Join-Path $BuildRoot ".venv"
# Chromium build for the SPA-render feature is downloaded here, then bundled
# into the app so rendering works offline (no separate 'playwright install').
$BrowsersDir = Join-Path $BuildRoot "ms-playwright"
$VenvPython = Join-Path $VenvDir "Scripts\python.exe"
$EntryPoint = Join-Path $RepoRoot "platforms\windows\scripts\koda-desktop.py"
$DistDir = Join-Path $RepoRoot "dist"
$AppDistDir = Join-Path $DistDir $AppName
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

    $candidates = @()
    if (${env:ProgramFiles(x86)}) {
        $candidates += (Join-Path ${env:ProgramFiles(x86)} "Inno Setup 6\ISCC.exe")
    }
    if ($env:ProgramFiles) {
        $candidates += (Join-Path $env:ProgramFiles "Inno Setup 6\ISCC.exe")
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

Write-Host "Preparing KODA Windows installer build."
Write-Host "Repository: $RepoRoot"

if (-not (Test-Path -LiteralPath $EntryPoint -PathType Leaf)) {
    throw "Missing PyInstaller entry point: $EntryPoint"
}

if (-not (Test-Path -LiteralPath (Join-Path $SharedPythonRoot "security_scanner") -PathType Container)) {
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
    & $pythonCommand @($pythonArgs + @("-m", "venv", $VenvDir))
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to create build virtual environment."
    }
}

if (-not $SkipDependencyInstall) {
    Write-Host "Installing build dependencies."
    # pywebview hosts the dashboard in a single native window (Edge WebView2),
    # so KODA opens like the macOS app instead of a console + browser tab.
    # playwright (pinned) powers the optional SPA-render web crawl.
    & $VenvPython -m pip install --upgrade pip pyinstaller pywebview "playwright==1.61.0"
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to install PyInstaller, pywebview, and playwright."
    }

    Write-Host "Downloading Playwright Chromium to bundle for offline SPA rendering."
    $env:PLAYWRIGHT_BROWSERS_PATH = $BrowsersDir
    & $VenvPython -m playwright install chromium
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to download Playwright Chromium."
    }
}

if (Test-Path -LiteralPath $AppDistDir) {
    Remove-Item -LiteralPath $AppDistDir -Recurse -Force
}

$workPath = Join-Path $BuildRoot "pyinstaller-work"
$specPath = Join-Path $BuildRoot "pyinstaller-spec"

$pyInstallerArgs = @(
    "--noconfirm",
    "--clean",
    "--onedir",
    # --windowed (no console): KODA launches as a single GUI window, with no
    # terminal window behind it -- matching the macOS KODA app.
    "--windowed",
    "--name", $AppName,
    "--distpath", $DistDir,
    "--workpath", $workPath,
    "--specpath", $specPath,
    "--paths", $SharedPythonRoot,
    # Bundle the 한글(HWPX) report template so the /api/export hwpx download works
    # in the frozen app (read at runtime via security_scanner/assets/).
    "--add-data", ((Join-Path $SharedPythonRoot "security_scanner\assets\koda-hwpx-template.hwpx") + ";security_scanner\assets"),
    # Host posture, inventory, EOL, and CPE modules are imported lazily, so they
    # must be force-collected or PyInstaller's static analysis drops them.
    "--collect-submodules", "security_scanner",
    # Live web posture scan (headers/TLS/cookies/CORS) is reached from the
    # dashboard via /api/web-scan and imported lazily; force-include it so the
    # feature ships in KODA.exe even if the collect flag above is narrowed later.
    "--hidden-import", "security_scanner.web",
    # pywebview + its Windows Edge WebView2 backend (pythonnet/clr) must be
    # bundled fully or the native window backend fails to load at runtime.
    "--collect-all", "webview",
    "--collect-all", "clr_loader",
    "--collect-all", "pythonnet",
    # playwright ships a bundled node driver as package data; collect it all so
    # the frozen app can drive the bundled Chromium for SPA rendering.
    "--collect-all", "playwright",
    "--hidden-import", "tkinter",
    "--hidden-import", "tkinter.filedialog",
    "--hidden-import", "tkinter.messagebox"
)

# Bundle the downloaded Chromium under ms-playwright/ so it ships inside the app;
# security_scanner.web points PLAYWRIGHT_BROWSERS_PATH at it at runtime.
if (Test-Path -LiteralPath $BrowsersDir -PathType Container) {
    $pyInstallerArgs += @("--add-data", ($BrowsersDir + ";ms-playwright"))
} else {
    Write-Warning "Chromium browser folder not found at $BrowsersDir; SPA rendering will be unavailable in this build. Re-run without -SkipDependencyInstall."
}

if (Test-Path -LiteralPath $IconPath -PathType Leaf) {
    $pyInstallerArgs += @("--icon", $IconPath)
}

$pyInstallerArgs += $EntryPoint

Write-Host "Building KODA.exe with PyInstaller."
& $VenvPython -m PyInstaller @pyInstallerArgs

if ($LASTEXITCODE -ne 0) {
    throw "PyInstaller build failed."
}

if (-not (Test-Path -LiteralPath (Join-Path $AppDistDir "KODA.exe") -PathType Leaf)) {
    throw "KODA.exe was not created."
}

foreach ($fileName in @("README.md", "scanner_config.example.json", "scanner_config.documents.example.json")) {
    $source = Join-Path $SharedPythonRoot $fileName
    if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
        $source = Join-Path $RepoRoot $fileName
    }
    if (Test-Path -LiteralPath $source -PathType Leaf) {
        Copy-Item -LiteralPath $source -Destination $AppDistDir -Force
    }
}

if (Test-Path -LiteralPath (Join-Path $RepoRoot "docs") -PathType Container) {
    Copy-Item -LiteralPath (Join-Path $RepoRoot "docs") -Destination $AppDistDir -Recurse -Force
}

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
Write-Host "Installer: $setupPath"
Write-Host "Installed users will run KODA from the Start Menu or desktop shortcut."
Write-Host "Double-clicking KODA opens a single native window (no console, no separate browser tab)."
