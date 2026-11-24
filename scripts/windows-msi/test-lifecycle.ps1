param(
    [Parameter(Mandatory=$true)][string]$Installer,
    [Parameter(Mandatory=$true)][string]$ReferenceBinary,
    [Parameter(Mandatory=$true)][string]$EvidenceDirectory,
    [switch]$ExpectRollback
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'test-helpers.ps1')

$Installer = (Resolve-Path -LiteralPath $Installer).Path
$ReferenceBinary = (Resolve-Path -LiteralPath $ReferenceBinary).Path
if (Test-Path -LiteralPath $EvidenceDirectory) { throw 'Evidence directory must be new' }
New-Item -ItemType Directory -Path $EvidenceDirectory | Out-Null
$EvidenceDirectory = (Resolve-Path -LiteralPath $EvidenceDirectory).Path
$engine = New-Object -ComObject WindowsInstaller.Installer
$database = $engine.OpenDatabase($Installer,0)
$product = Read-MsiProperty $database 'ProductCode'
$version = Read-MsiProperty $database 'ProductVersion'
if ((Read-MsiProperty $database 'ALLUSERS') -ne '1') { throw 'Expected per-machine MSI' }
[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($database)
[void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($engine)
$registration = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\' + $product
$installRoot = Join-Path $env:ProgramFiles 'depscan-cli'
$installed = Join-Path $installRoot 'bin\depscan.exe'
if ((Test-Path -LiteralPath $installRoot) -or (Test-Path -LiteralPath $registration)) { throw 'Refusing to replace an existing installation' }
$baseline = Read-PathState
[IO.File]::WriteAllText((Join-Path $EvidenceDirectory 'baseline.json'),($baseline | ConvertTo-Json),$utf8)
$expectedHash = (Get-FileHash -LiteralPath $ReferenceBinary -Algorithm SHA256).Hash
$msiexec = Join-Path $env:SystemRoot 'System32\msiexec.exe'
$receipt = [ordered]@{ProductCode=$product; Version=$version; Error=$null; AutomaticPathTypeRestoration=$false; ManualTypeCleanup=$false}
try {
    $expectedInstallExit = $(if ($ExpectRollback) { 1603 } else { 0 })
    $null = Invoke-Native $msiexec @('/i',$Installer,'/qn','/norestart','REBOOT=ReallySuppress','/L*V',(Join-Path $EvidenceDirectory 'install.log')) 'install' $expectedInstallExit
    $receipt.InstallExit = $expectedInstallExit
    if ($ExpectRollback) {
        $log = Get-Content -LiteralPath (Join-Path $EvidenceDirectory 'install.log') -Raw
        if ($log -notmatch 'Expected DS-127 rollback regression failure' -or $log -notmatch 'DepscanRollbackPathType') { throw 'Expected rollback failure/helper was not exercised' }
    } else {
        if ((Get-FileHash -LiteralPath $installed -Algorithm SHA256).Hash -ne $expectedHash) { throw 'Installed binary differs from reference' }
        $afterInstall = Read-PathState
        $receipt.KindAfterInstall = $afterInstall.MachineKind
        if ($afterInstall.MachineKind -cne $baseline.MachineKind) { throw 'Installation changed the machine PATH registry type' }
        $bin = Split-Path $installed
        if (@($afterInstall.MachinePath -split ';' | Where-Object { $_.TrimEnd('\') -ieq $bin.TrimEnd('\') }).Count -ne 1) { throw 'Expected one installed PATH entry' }
        $receipt.CliVersion = (Invoke-Native $installed @('--version') 'version').Trim()
        $null = Invoke-Native $installed @('--help') 'help'
        Move-Item -LiteralPath $installed -Destination (Join-Path $EvidenceDirectory 'before-repair.exe')
        $null = Invoke-Native $msiexec @('/fa',$product,'/qn','/norestart','REBOOT=ReallySuppress','/L*V',(Join-Path $EvidenceDirectory 'repair.log')) 'repair'
        $receipt.RepairExit = 0
        if ((Get-FileHash -LiteralPath $installed -Algorithm SHA256).Hash -ne $expectedHash) { throw 'Repair did not restore the reference binary' }
        $receipt.KindAfterRepair = (Read-PathState).MachineKind
        if ($receipt.KindAfterRepair -cne $baseline.MachineKind) { throw 'Repair changed the machine PATH registry type' }
    }
} catch { $receipt.Error = $_.Exception.Message }
finally {
    if (Test-Path -LiteralPath $registration) {
        try {
            $null = Invoke-Native $msiexec @('/x',$product,'/qn','/norestart','REBOOT=ReallySuppress','/L*V',(Join-Path $EvidenceDirectory 'uninstall.log')) 'uninstall'
            $receipt.UninstallExit = 0
        } catch { $receipt.Error = $_.Exception.Message }
    }
    $after = Read-PathState
    $receipt.KindAfterUninstall = $after.MachineKind
    $receipt.AutomaticPathTypeRestoration = $after.MachineKind -ceq $baseline.MachineKind
    $receipt.RawMachinePathRestored = $after.MachinePath -ceq $baseline.MachinePath
    $receipt.UserPathUnchanged = ($after.UserPath -ceq $baseline.UserPath) -and ($after.UserKind -ceq $baseline.UserKind) -and ($after.UserPathExists -eq $baseline.UserPathExists)
    if ($receipt.RawMachinePathRestored -and -not $receipt.AutomaticPathTypeRestoration) {
        $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($environmentKey,$true)
        try {
            if ($key.GetValue('Path',$null,$options) -cne $baseline.MachinePath) { throw 'Concurrent PATH edit; refusing cleanup overwrite' }
            $key.SetValue('Path',[string]$baseline.MachinePath,[Enum]::Parse([Microsoft.Win32.RegistryValueKind],$baseline.MachineKind))
            $receipt.ManualTypeCleanup = $true
        } finally { $key.Close() }
    }
    $receipt.ProductAbsent = -not (Test-Path -LiteralPath $registration)
    $receipt.DirectoryAbsent = -not (Test-Path -LiteralPath $installRoot)
    $receipt.CompletedUtc = [DateTime]::UtcNow.ToString('o')
    [IO.File]::WriteAllText((Join-Path $EvidenceDirectory 'result.json'),($receipt | ConvertTo-Json),$utf8)
}
$receipt | ConvertTo-Json -Compress
if ($receipt.Error -or -not $receipt.AutomaticPathTypeRestoration -or -not $receipt.RawMachinePathRestored -or -not $receipt.UserPathUnchanged -or -not $receipt.ProductAbsent -or -not $receipt.DirectoryAbsent) { throw 'MSI lifecycle regression failed; inspect result.json' }
