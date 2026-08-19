$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$version = $env:DEPSCAN_ACTION_VERSION
if ($version -notmatch '^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$') {
    throw "version must be an exact depscan release tag such as v1.1.0"
}
if ($env:RUNNER_OS -ne "Windows" -or $env:RUNNER_ARCH -ne "X64") {
    throw "Unsupported depscan runner: $($env:RUNNER_OS)/$($env:RUNNER_ARCH)"
}
if ([string]::IsNullOrWhiteSpace($env:RUNNER_TEMP)) {
    throw "RUNNER_TEMP is required"
}
if ([string]::IsNullOrWhiteSpace($env:GITHUB_ENV)) {
    throw "GITHUB_ENV is required"
}

$target = "x86_64-pc-windows-msvc"
$asset = "depscan-cli-$target.zip"
$checksumAsset = "$asset.sha256"
$releaseBase = "https://github.com/gedankrayze/depscan/releases/download/$version"
$downloadDir = Join-Path $env:RUNNER_TEMP ("depscan-action-download-" + [Guid]::NewGuid().ToString("N"))
$installDir = Join-Path $env:RUNNER_TEMP ("depscan-action-bin-" + [Guid]::NewGuid().ToString("N"))

New-Item -ItemType Directory -Path $downloadDir | Out-Null
New-Item -ItemType Directory -Path $installDir | Out-Null
try {
    $archive = Join-Path $downloadDir $asset
    $checksumFile = Join-Path $downloadDir $checksumAsset
    Invoke-WebRequest -Uri "$releaseBase/$asset" -OutFile $archive
    Invoke-WebRequest -Uri "$releaseBase/$checksumAsset" -OutFile $checksumFile

    $checksumLines = @(
        Get-Content -LiteralPath $checksumFile |
            Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    )
    if ($checksumLines.Count -ne 1) {
        throw "Release checksum file must contain exactly one nonblank record"
    }
    $checksumParts = @($checksumLines[0] -split '\s+' | Where-Object { $_ -ne "" })
    if ($checksumParts.Count -ne 2 -or $checksumParts[0] -notmatch '^[0-9a-f]{64}$') {
        throw "Release checksum file has an invalid record"
    }
    $expectedSha256 = $checksumParts[0]
    $checksumName = $checksumParts[1].TrimStart('*')
    if ($checksumName -ne $asset) {
        throw "Release checksum names $checksumName instead of $asset"
    }

    $actualSha256 = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualSha256 -ne $expectedSha256) {
        throw "depscan checksum mismatch for $asset; expected $expectedSha256, got $actualSha256"
    }

    Expand-Archive -LiteralPath $archive -DestinationPath $downloadDir
    $sourceBinary = Join-Path $downloadDir "depscan-cli-$target/depscan.exe"
    if (-not (Test-Path -LiteralPath $sourceBinary -PathType Leaf)) {
        throw "Verified depscan archive did not contain the expected executable"
    }

    $installedBinary = Join-Path $installDir "depscan.exe"
    Copy-Item -LiteralPath $sourceBinary -Destination $installedBinary
    $installedBinary = (Resolve-Path -LiteralPath $installedBinary).Path

    $versionOutput = & $installedBinary --version
    if ($LASTEXITCODE -ne 0) {
        throw "Downloaded depscan executable failed its version check"
    }
    $installedVersion = ($versionOutput -join "`n").Trim()
    if ($installedVersion -ne "depscan $($version.Substring(1))") {
        throw "Downloaded binary does not match release $version`: $installedVersion"
    }
    Add-Content -LiteralPath $env:GITHUB_ENV -Value "DEPSCAN_ACTION_INSTALLED_BINARY=$installedBinary" -Encoding utf8
}
finally {
    Remove-Item -LiteralPath $downloadDir -Recurse -Force -ErrorAction SilentlyContinue
}
