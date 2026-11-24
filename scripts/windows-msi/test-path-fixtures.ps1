param(
    [Parameter(Mandatory=$true)][string]$Installer,
    [Parameter(Mandatory=$true)][string]$ReferenceBinary,
    [Parameter(Mandatory=$true)][string]$EvidenceDirectory
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot 'test-helpers.ps1')
if (Test-Path -LiteralPath $EvidenceDirectory) { throw 'Evidence directory must be new' }
New-Item -ItemType Directory -Path $EvidenceDirectory | Out-Null
$baseline = Read-PathState
$expanded = [Environment]::ExpandEnvironmentVariables($baseline.MachinePath)
if ($expanded.Contains('%')) { throw 'Unresolved expansion references prevent safe PATH fixtures' }
$cases = @(
    @{Name='expand-no-references'; Text=$expanded; Kind='ExpandString'},
    @{Name='string'; Text=$expanded; Kind='String'},
    @{Name='expand-reference'; Text=($expanded + ';%SystemRoot%'); Kind='ExpandString'}
)
[IO.File]::WriteAllText((Join-Path $EvidenceDirectory 'baseline.json'),($baseline | ConvertTo-Json),$utf8)
foreach ($case in $cases) {
    $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($environmentKey,$true)
    try {
        if ($key.GetValue('Path',$null,$options) -cne $baseline.MachinePath -or $key.GetValueKind('Path').ToString() -cne $baseline.MachineKind) { throw 'Concurrent PATH edit; refusing fixture mutation' }
        $key.SetValue('Path',[string]$case.Text,[Enum]::Parse([Microsoft.Win32.RegistryValueKind],$case.Kind))
        try {
            & (Join-Path $PSScriptRoot 'test-lifecycle.ps1') -Installer $Installer -ReferenceBinary $ReferenceBinary -EvidenceDirectory (Join-Path $EvidenceDirectory $case.Name)
        } finally {
            # The lifecycle test owns uninstall. Never overwrite an unrelated PATH edit.
            if ($key.GetValue('Path',$null,$options) -cne $case.Text) { throw 'Fixture PATH differs after uninstall; refusing snapshot overwrite' }
            $key.SetValue('Path',[string]$baseline.MachinePath,[Enum]::Parse([Microsoft.Win32.RegistryValueKind],$baseline.MachineKind))
        }
    } finally { $key.Close() }
}
$after = Read-PathState
if ($after.MachinePath -cne $baseline.MachinePath -or $after.MachineKind -cne $baseline.MachineKind) { throw 'Fixture baseline restoration failed' }
