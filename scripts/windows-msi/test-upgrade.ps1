param(
    [Parameter(Mandatory=$true)][string]$OldInstaller,
    [Parameter(Mandatory=$true)][string]$UpgradeInstaller,
    [Parameter(Mandatory=$true)][string]$ReferenceBinary,
    [Parameter(Mandatory=$true)][string]$EvidenceDirectory,
    [switch]$ExpectRollback,
    [switch]$LegacyInstaller
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'test-helpers.ps1')
$OldInstaller = (Resolve-Path -LiteralPath $OldInstaller).Path
$UpgradeInstaller = (Resolve-Path -LiteralPath $UpgradeInstaller).Path
if (Test-Path -LiteralPath $EvidenceDirectory) { throw 'Evidence directory must be new' }
New-Item -ItemType Directory -Path $EvidenceDirectory | Out-Null
$EvidenceDirectory = (Resolve-Path -LiteralPath $EvidenceDirectory).Path
$products = @((Read-ProductCode $OldInstaller),(Read-ProductCode $UpgradeInstaller))
if ($products[0] -eq $products[1]) { throw 'Upgrade test requires distinct products' }
$prefix = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\'
$installRoot = Join-Path $env:ProgramFiles 'depscan-cli'
if ((Test-Path -LiteralPath $installRoot) -or (Test-Path -LiteralPath ($prefix + $products[0])) -or (Test-Path -LiteralPath ($prefix + $products[1]))) { throw 'Existing installation prevents an isolated upgrade test' }
$baseline = Read-PathState
[IO.File]::WriteAllText((Join-Path $EvidenceDirectory 'baseline.json'),($baseline | ConvertTo-Json),$utf8)
$expectedHash = (Get-FileHash -LiteralPath $ReferenceBinary -Algorithm SHA256).Hash
$installed = Join-Path $installRoot 'bin/depscan.exe'
$msiexec = Join-Path $env:SystemRoot 'System32/msiexec.exe'
$receipt = [ordered]@{Error=$null; UpgradeRollback=[bool]$ExpectRollback; LegacyFixture=[bool]$LegacyInstaller; Verified=$false; ManualLegacyCleanup=$false}
try {
    $null = Invoke-Native $msiexec @('/i',$OldInstaller,'/qn','/norestart','REBOOT=ReallySuppress','/L*V',(Join-Path $EvidenceDirectory 'old-install.log')) 'old-install'
    $before = Read-PathState
    if ($LegacyInstaller) {
        # Model an installed legacy package whose type has been manually repaired.
        $before.MachineKind = $baseline.MachineKind
        Restore-PathType $before
    } elseif ($before.MachineKind -cne $baseline.MachineKind) { throw 'Old fixture changed PATH type' }
    $expectedExit = $(if ($ExpectRollback) { 1603 } else { 0 })
    $null = Invoke-Native $msiexec @('/i',$UpgradeInstaller,'/qn','/norestart','REBOOT=ReallySuppress','/L*V',(Join-Path $EvidenceDirectory 'upgrade.log')) 'upgrade' $expectedExit
    $after = Read-PathState
    if ($after.MachinePath -cne $before.MachinePath -or $after.MachineKind -cne $before.MachineKind) { throw 'Upgrade or rollback changed PATH text/type' }
    if ((Get-FileHash -LiteralPath $installed -Algorithm SHA256).Hash -ne $expectedHash) { throw 'Upgrade or rollback lost the installed binary' }
    $oldPresent = Test-Path -LiteralPath ($prefix + $products[0])
    $newPresent = Test-Path -LiteralPath ($prefix + $products[1])
    if ($oldPresent -ne [bool]$ExpectRollback -or $newPresent -eq [bool]$ExpectRollback) { throw 'Unexpected product registration after upgrade/rollback' }
    if ($ExpectRollback) {
        $log = Get-Content -LiteralPath (Join-Path $EvidenceDirectory 'upgrade.log') -Raw
        if ($log -notmatch 'Expected DS-127 rollback regression failure') { throw 'Expected upgrade failure was not exercised' }
    }
    $receipt.CliVersion = (Invoke-Native $installed @('--version') 'version').Trim()
    $receipt.KindAfterUpgrade = $after.MachineKind
    $receipt.Verified = $true
} catch { $receipt.Error = $_.Exception.Message }
finally {
    foreach ($product in $products) {
        if (Test-Path -LiteralPath ($prefix + $product)) {
            try { $null = Invoke-Native $msiexec @('/x',$product,'/qn','/norestart','REBOOT=ReallySuppress','/L*V',(Join-Path $EvidenceDirectory ($product + '-uninstall.log'))) ('uninstall-' + $product) }
            catch { $receipt.Error = $_.Exception.Message }
        }
    }
    $after = Read-PathState
    $receipt.MachinePathRestored = $after.MachinePath -ceq $baseline.MachinePath
    $receipt.UserPathUnchanged = ($after.UserPath -ceq $baseline.UserPath) -and ($after.UserKind -ceq $baseline.UserKind) -and ($after.UserPathExists -eq $baseline.UserPathExists)
    if ($receipt.MachinePathRestored -and $after.MachineKind -cne $baseline.MachineKind) {
        Restore-PathType $baseline
        if ($LegacyInstaller -and $ExpectRollback) { $receipt.ManualLegacyCleanup = $true }
        else { $receipt.Error = 'Fixed-package uninstall changed PATH type' }
    }
    $receipt.InstallationAbsent = -not ((Test-Path -LiteralPath $installRoot) -or (Test-Path -LiteralPath ($prefix + $products[0])) -or (Test-Path -LiteralPath ($prefix + $products[1])))
    [IO.File]::WriteAllText((Join-Path $EvidenceDirectory 'result.json'),($receipt | ConvertTo-Json),$utf8)
}
$receipt | ConvertTo-Json -Compress
if ($receipt.Error -or -not $receipt.Verified -or -not $receipt.MachinePathRestored -or -not $receipt.UserPathUnchanged -or -not $receipt.InstallationAbsent) { throw 'MSI upgrade regression failed; inspect result.json' }
