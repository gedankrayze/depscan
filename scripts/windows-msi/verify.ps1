param(
    [Parameter(Mandatory=$true)][string]$BinaryDirectory,
    [Parameter(Mandatory=$true)][string]$EvidenceDirectory,
    [string]$WixDirectory = $env:WIX,
    [switch]$ExercisePathFixtures
)
$ErrorActionPreference = 'Stop'
if (Test-Path -LiteralPath $EvidenceDirectory) { throw 'Evidence directory must be new' }
New-Item -ItemType Directory -Path $EvidenceDirectory | Out-Null
$EvidenceDirectory = (Resolve-Path -LiteralPath $EvidenceDirectory).Path
$binary = (Resolve-Path -LiteralPath $BinaryDirectory).Path
$repo = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$manifest = Get-Content -LiteralPath (Join-Path $repo 'Cargo.toml') -Raw
if ($manifest -notmatch '(?ms)^\[workspace\.package\]\s*\r?\nversion = "(\d+)\.(\d+)\.(\d+)"') { throw 'Cannot read MSI version' }
$version = '{0}.{1}.{2}' -f $Matches[1],$Matches[2],$Matches[3]
$next = '{0}.{1}.{2}' -f $Matches[1],$Matches[2],([int]$Matches[3] + 1)
$target = $env:CARGO_TARGET_DIR
if (-not $target) { $target = Join-Path $repo 'target' }
$target = [IO.Path]::GetFullPath($target)
& (Join-Path $PSScriptRoot 'build-path-helper.ps1') -OutputDirectory (Join-Path $target 'msi-helper')
$build = Join-Path $PSScriptRoot 'build-installer.ps1'
$lifecycle = Join-Path $PSScriptRoot 'test-lifecycle.ps1'
$upgrade = Join-Path $PSScriptRoot 'test-upgrade.ps1'
$normal = Join-Path $EvidenceDirectory 'normal.msi'
$rollback = Join-Path $EvidenceDirectory 'rollback.msi'
$newer = Join-Path $EvidenceDirectory 'newer-fixture.msi'
$failedUpgrade = Join-Path $EvidenceDirectory 'failed-upgrade-fixture.msi'
& $build -BinaryDirectory $binary -OutputInstaller $normal -WixDirectory $WixDirectory -Version $version
& $build -BinaryDirectory $binary -OutputInstaller $rollback -WixDirectory $WixDirectory -Version $version -TestRollback
& $build -BinaryDirectory $binary -OutputInstaller $newer -WixDirectory $WixDirectory -Version $next
& $build -BinaryDirectory $binary -OutputInstaller $failedUpgrade -WixDirectory $WixDirectory -Version $next -TestRollback
$reference = Join-Path $binary 'depscan.exe'
& $lifecycle -Installer $normal -ReferenceBinary $reference -EvidenceDirectory (Join-Path $EvidenceDirectory 'lifecycle')
& $lifecycle -Installer $rollback -ReferenceBinary $reference -EvidenceDirectory (Join-Path $EvidenceDirectory 'rollback') -ExpectRollback
& $upgrade -OldInstaller $normal -UpgradeInstaller $newer -ReferenceBinary $reference -EvidenceDirectory (Join-Path $EvidenceDirectory 'upgrade')
& $upgrade -OldInstaller $normal -UpgradeInstaller $failedUpgrade -ReferenceBinary $reference -EvidenceDirectory (Join-Path $EvidenceDirectory 'failed-upgrade') -ExpectRollback
if ($ExercisePathFixtures) {
    & (Join-Path $PSScriptRoot 'test-path-fixtures.ps1') -Installer $normal -ReferenceBinary $reference -EvidenceDirectory (Join-Path $EvidenceDirectory 'path-fixtures')
}
