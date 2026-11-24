param(
    [Parameter(Mandatory=$true)][string]$BinaryDirectory,
    [Parameter(Mandatory=$true)][string]$OutputInstaller,
    [string]$WixDirectory = $env:WIX,
    [string]$Version,
    [switch]$TestRollback
)
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$binary = (Resolve-Path -LiteralPath $BinaryDirectory).Path
$target = $env:CARGO_TARGET_DIR
if (-not $target) { $target = Join-Path $repo 'target' }
$target = [IO.Path]::GetFullPath($target)
if (-not $Version) {
    $manifest = Get-Content -LiteralPath (Join-Path $repo 'Cargo.toml') -Raw
    if ($manifest -notmatch '(?ms)^\[workspace\.package\]\s*\r?\nversion = "([^"]+)"') { throw 'Cannot read workspace version' }
    $Version = $Matches[1]
}
if ($Version -notmatch '^\d+\.\d+\.\d+$') { throw 'MSI version must have three numeric components' }
if (-not $WixDirectory) { throw 'Set WixDirectory or WIX to the WiX 3 toolset directory' }
if (Test-Path -LiteralPath (Join-Path $WixDirectory 'bin/candle.exe')) { $WixDirectory = Join-Path $WixDirectory 'bin' }
$candle = Join-Path $WixDirectory 'candle.exe'
$light = Join-Path $WixDirectory 'light.exe'
if (-not (Test-Path -LiteralPath $candle) -or -not (Test-Path -LiteralPath $light)) { throw 'WiX 3 candle/light tools are required' }
$output = [IO.Path]::GetFullPath($OutputInstaller)
if (Test-Path -LiteralPath $output) { throw 'Output MSI already exists' }
$directory = Split-Path $output
New-Item -ItemType Directory -Path $directory -Force | Out-Null
$source = Join-Path $repo 'crates/depscan-cli/wix/main.wxs'
if ($TestRollback) {
    # A failure fixture only: the shipping MSI has no failure switch/custom action.
    [xml]$xml = Get-Content -LiteralPath $source -Raw
    $namespace = $xml.DocumentElement.NamespaceURI
    $product = $xml.DocumentElement.Product
    $failure = $xml.CreateElement('CustomAction',$namespace)
    $failure.SetAttribute('Id','DepscanTestFailure')
    $failure.SetAttribute('Error','Expected DS-127 rollback regression failure')
    [void]$product.AppendChild($failure)
    $schedule = $xml.CreateElement('Custom',$namespace)
    $schedule.SetAttribute('Action','DepscanTestFailure')
    $schedule.SetAttribute('Before','InstallFinalize')
    $schedule.InnerText = '1'
    [void]$product.InstallExecuteSequence.AppendChild($schedule)
    $source = Join-Path $directory 'rollback-fixture.wxs'
    $xml.Save($source)
}
$object = [IO.Path]::ChangeExtension($output,'.wixobj')
& $candle -nologo -arch x64 "-dVersion=$Version" "-dCargoTargetDir=$target" "-dCargoTargetBinDir=$binary" -out $object $source
if ($LASTEXITCODE -ne 0) { throw 'MSI compilation failed' }
& $light -nologo -wx -ext (Join-Path $WixDirectory 'WixUIExtension.dll') -out $output $object
if ($LASTEXITCODE -ne 0) { throw 'MSI link/validation failed' }
& (Join-Path $PSScriptRoot 'assert-installer.ps1') -Installer $output
