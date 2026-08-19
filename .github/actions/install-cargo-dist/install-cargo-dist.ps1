$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$version = "0.32.0"
if ($env:RUNNER_OS -ne "Windows" -or $env:RUNNER_ARCH -ne "X64") {
    throw "Unsupported cargo-dist runner: $($env:RUNNER_OS)/$($env:RUNNER_ARCH)"
}
if ([string]::IsNullOrWhiteSpace($env:RUNNER_TEMP)) {
    throw "RUNNER_TEMP is required"
}
if ([string]::IsNullOrWhiteSpace($env:GITHUB_PATH)) {
    throw "GITHUB_PATH is required"
}

$asset = "cargo-dist-x86_64-pc-windows-msvc.zip"
$expectedSha256 = "26e845cabff12a92911ce960af73a86c8f9b2b2d9072b01dfe5b662acf044fa3"
$downloadDir = Join-Path $env:RUNNER_TEMP ("depscan-cargo-dist-download-" + [Guid]::NewGuid().ToString("N"))
$installDir = Join-Path $env:RUNNER_TEMP ("depscan-cargo-dist-bin-" + [Guid]::NewGuid().ToString("N"))

New-Item -ItemType Directory -Path $downloadDir | Out-Null
New-Item -ItemType Directory -Path $installDir | Out-Null
try {
    $archive = Join-Path $downloadDir $asset
    $url = "https://github.com/axodotdev/cargo-dist/releases/download/v$version/$asset"
    Invoke-WebRequest -Uri $url -OutFile $archive

    $actualSha256 = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualSha256 -ne $expectedSha256) {
        throw "cargo-dist checksum mismatch for $asset; expected $expectedSha256, got $actualSha256"
    }

    Expand-Archive -LiteralPath $archive -DestinationPath $downloadDir
    $sourceBinary = Join-Path $downloadDir "cargo-dist-x86_64-pc-windows-msvc/dist.exe"
    if (-not (Test-Path -LiteralPath $sourceBinary -PathType Leaf)) {
        throw "Verified cargo-dist archive did not contain the expected executable"
    }

    $installedBinary = Join-Path $installDir "dist.exe"
    Copy-Item -LiteralPath $sourceBinary -Destination $installedBinary

    $versionOutput = & $installedBinary --version
    if ($LASTEXITCODE -ne 0) {
        throw "Downloaded cargo-dist executable failed its version check"
    }
    $installedVersion = ($versionOutput -join "`n").Trim()
    if ($installedVersion -ne "cargo-dist $version") {
        throw "Unexpected cargo-dist version: $installedVersion"
    }
    Add-Content -LiteralPath $env:GITHUB_PATH -Value $installDir -Encoding utf8
}
finally {
    Remove-Item -LiteralPath $downloadDir -Recurse -Force -ErrorAction SilentlyContinue
}
