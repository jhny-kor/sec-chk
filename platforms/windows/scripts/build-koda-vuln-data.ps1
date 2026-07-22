[CmdletBinding()]
param(
    [string]$OutputDirectory,
    [string]$CacheDirectory,
    [int]$StartYear = 2002,
    [int]$EndYear = [DateTime]::UtcNow.Year,
    [switch]$Refresh
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..\..")).Path
if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $RepoRoot "dist\Windows"
}
if (-not $CacheDirectory) {
    $CacheDirectory = Join-Path $RepoRoot ".build\koda-vuln-data-cache"
}

if ($StartYear -lt 2002) {
    throw "StartYear must be 2002 or later."
}
if ($EndYear -lt $StartYear) {
    throw "EndYear must be greater than or equal to StartYear."
}

$NvdCacheDirectory = Join-Path $CacheDirectory "vuln-data\nvd"
$NvdMetaDirectory = Join-Path $CacheDirectory "nvd-meta"
$CisaCacheFile = Join-Path $CacheDirectory "vuln-data\known_exploited_vulnerabilities.json"
$StagingRoot = Join-Path $env:TEMP ("koda-vuln-data-" + [Guid]::NewGuid().ToString("N"))
$StagingVulnData = Join-Path $StagingRoot "vuln-data"
$OutputDate = [DateTime]::UtcNow.ToString("yyyy-MM-dd")
$OutputPath = Join-Path $OutputDirectory "koda-vuln-data-$OutputDate.zip"

function Ensure-Directory {
    param([Parameter(Mandatory = $true)][string]$Path)

    New-Item -ItemType Directory -Path $Path -Force | Out-Null
}

function Download-File {
    param(
        [Parameter(Mandatory = $true)][string]$Uri,
        [Parameter(Mandatory = $true)][string]$Destination
    )

    Ensure-Directory -Path (Split-Path -Parent $Destination)
    $partial = "$Destination.part.$([Guid]::NewGuid().ToString('N'))"
    $lastError = $null
    try {
        for ($attempt = 1; $attempt -le 3; $attempt++) {
            try {
                Write-Host "Downloading $Uri (attempt $attempt/3)"
                Invoke-WebRequest `
                    -Uri $Uri `
                    -OutFile $partial `
                    -UseBasicParsing `
                    -Headers @{ "User-Agent" = "KODA-vulnerability-data-builder" }
                if (-not (Test-Path -LiteralPath $partial -PathType Leaf)) {
                    throw "Download produced no file: $Uri"
                }
                Move-Item -LiteralPath $partial -Destination $Destination -Force
                return
            }
            catch {
                $lastError = $_
                if ($attempt -lt 3) {
                    Write-Warning "Download failed; retrying in $($attempt * 2) seconds. $($_.Exception.Message)"
                    Start-Sleep -Seconds ($attempt * 2)
                }
            }
        }
        throw "Download failed after 3 attempts: $Uri`n$lastError"
    }
    finally {
        if (Test-Path -LiteralPath $partial -PathType Leaf) {
            Remove-Item -LiteralPath $partial -Force
        }
    }
}

function Get-MetaSha256 {
    param([Parameter(Mandatory = $true)][string]$MetaPath)

    $match = Select-String -LiteralPath $MetaPath -Pattern '^\s*sha256\s*:\s*(\S+)\s*$' | Select-Object -First 1
    if (-not $match) {
        throw "NVD metadata has no sha256 entry: $MetaPath"
    }
    return $match.Matches[0].Groups[1].Value.ToLowerInvariant()
}

function Get-UncompressedSha256 {
    param([Parameter(Mandatory = $true)][string]$GzipPath)

    $fileStream = [IO.File]::OpenRead($GzipPath)
    $gzipStream = New-Object System.IO.Compression.GZipStream `
        -ArgumentList $fileStream, ([IO.Compression.CompressionMode]::Decompress)
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha256.ComputeHash($gzipStream))).Replace("-", "").ToLowerInvariant()
    }
    finally {
        $sha256.Dispose()
        $gzipStream.Dispose()
        $fileStream.Dispose()
    }
}

function Assert-NvdFeed {
    param(
        [Parameter(Mandatory = $true)][string]$FeedPath,
        [Parameter(Mandatory = $true)][string]$MetaPath
    )

    $expected = Get-MetaSha256 -MetaPath $MetaPath
    $actual = Get-UncompressedSha256 -GzipPath $FeedPath
    if ($actual -ne $expected) {
        throw "NVD checksum mismatch for $(Split-Path -Leaf $FeedPath): $actual != $expected"
    }
    Write-Host "Verified $(Split-Path -Leaf $FeedPath) against .meta"
}

function Get-CisaMetadata {
    param([Parameter(Mandatory = $true)][string]$Path)

    $payload = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    if (-not $payload.dateReleased -or -not $payload.catalogVersion) {
        throw "CISA KEV data has no dateReleased/catalogVersion: $Path"
    }
    return $payload
}

function Write-Utf8NoBom {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Content
    )

    $encoding = New-Object System.Text.UTF8Encoding($false)
    [IO.File]::WriteAllText($Path, $Content, $encoding)
}

try {
    Ensure-Directory -Path $NvdCacheDirectory
    Ensure-Directory -Path $NvdMetaDirectory
    Ensure-Directory -Path $OutputDirectory
    Ensure-Directory -Path $StagingVulnData
    Ensure-Directory -Path (Join-Path $StagingVulnData "nvd")

    for ($year = $StartYear; $year -le $EndYear; $year++) {
        $feedName = "nvdcve-2.0-$year"
        $feedUri = "https://nvd.nist.gov/feeds/json/cve/2.0/$feedName.json.gz"
        $metaUri = "https://nvd.nist.gov/feeds/json/cve/2.0/$feedName.meta"
        $feedPath = Join-Path $NvdCacheDirectory "$feedName.json.gz"
        $metaPath = Join-Path $NvdMetaDirectory "$feedName.meta"

        # Metadata is small and always refreshed. It lets a cached feed be
        # reused safely while still detecting a changed or corrupted feed.
        Download-File -Uri $metaUri -Destination $metaPath
        $needsDownload = $Refresh -or -not (Test-Path -LiteralPath $feedPath -PathType Leaf)
        if (-not $needsDownload) {
            try {
                Assert-NvdFeed -FeedPath $feedPath -MetaPath $metaPath
            }
            catch {
                Write-Warning "Cached NVD feed is stale or invalid; downloading it again. $($_.Exception.Message)"
                $needsDownload = $true
            }
        }
        if ($needsDownload) {
            Download-File -Uri $feedUri -Destination $feedPath
            Assert-NvdFeed -FeedPath $feedPath -MetaPath $metaPath
        }
        Copy-Item -LiteralPath $feedPath -Destination (Join-Path $StagingVulnData "nvd\$feedName.json.gz") -Force
    }

    foreach ($mutableFeed in @("recent", "modified")) {
        $feedName = "nvdcve-2.0-$mutableFeed"
        $feedUri = "https://nvd.nist.gov/feeds/json/cve/2.0/$feedName.json.gz"
        $metaUri = "https://nvd.nist.gov/feeds/json/cve/2.0/$feedName.meta"
        $feedPath = Join-Path $NvdCacheDirectory "$feedName.json.gz"
        $metaPath = Join-Path $NvdMetaDirectory "$feedName.meta"

        Download-File -Uri $feedUri -Destination $feedPath
        Download-File -Uri $metaUri -Destination $metaPath
        Assert-NvdFeed -FeedPath $feedPath -MetaPath $metaPath
        Copy-Item -LiteralPath $feedPath -Destination (Join-Path $StagingVulnData "nvd\$feedName.json.gz") -Force
    }

    Download-File `
        -Uri "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json" `
        -Destination $CisaCacheFile
    $cisa = Get-CisaMetadata -Path $CisaCacheFile
    Copy-Item -LiteralPath $CisaCacheFile `
        -Destination (Join-Path $StagingVulnData "known_exploited_vulnerabilities.json") -Force

    $versions = @(
        "KODA offline vulnerability data (NVD + CISA KEV)"
        "built_at=$([DateTime]::UtcNow.ToString('o'))"
        "nvd_start_year=$StartYear"
        "nvd_end_year=$EndYear"
        "cisa_kev_date_released=$($cisa.dateReleased)"
        "cisa_kev_catalog_version=$($cisa.catalogVersion)"
    ) -join [Environment]::NewLine
    Write-Utf8NoBom -Path (Join-Path $StagingVulnData "versions.txt") -Content ($versions + [Environment]::NewLine)

    if (Test-Path -LiteralPath $OutputPath -PathType Leaf) {
        Remove-Item -LiteralPath $OutputPath -Force
    }
    Compress-Archive `
        -Path $StagingVulnData `
        -DestinationPath $OutputPath `
        -CompressionLevel Optimal `
        -Force

    $hash = (Get-FileHash -LiteralPath $OutputPath -Algorithm SHA256).Hash.ToLowerInvariant()
    Write-Host "sha256=$hash"
    Write-Host $OutputPath
}
finally {
    if (Test-Path -LiteralPath $StagingRoot) {
        Remove-Item -LiteralPath $StagingRoot -Recurse -Force
    }
}
