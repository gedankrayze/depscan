param([Parameter(Mandatory=$true)][string]$Installer)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'test-helpers.ps1')
$engine = New-Object -ComObject WindowsInstaller.Installer
$database = $engine.OpenDatabase((Resolve-Path -LiteralPath $Installer).Path,0)
try {
    if ((Read-MsiProperty $database 'ALLUSERS') -ne '1') { throw 'Expected per-machine MSI' }
    $expected = @{
        DepscanCapturePathType=@(1,'CapturePathType')
        DepscanRestorePathType=@(3073,'RestorePathType')
        DepscanRollbackPathType=@(3329,'RestorePathType')
    }
    $view = $database.OpenView('SELECT `Action`, `Type`, `Source`, `Target` FROM `CustomAction`')
    [void]$view.Execute()
    try {
        while ($record = $view.Fetch()) {
            try {
                $name = $record.StringData(1)
                if ($expected.ContainsKey($name)) {
                    if ($record.IntegerData(2) -ne $expected[$name][0] -or $record.StringData(3) -cne 'DepscanPathType' -or $record.StringData(4) -cne $expected[$name][1]) { throw "Unsafe PATH action contract: $name" }
                    $expected.Remove($name)
                }
            } finally { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($record) }
        }
    } finally { [void]$view.Close(); [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($view) }
    if ($expected.Count) { throw 'Compiled MSI is missing required PATH actions' }
    $sequence = @{}
    $view = $database.OpenView('SELECT `Action`, `Sequence` FROM `InstallExecuteSequence`')
    [void]$view.Execute()
    try {
        while ($record = $view.Fetch()) {
            try { $sequence[$record.StringData(1)] = $record.IntegerData(2) }
            finally { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($record) }
        }
    } finally { [void]$view.Close(); [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($view) }
    $order = @('DepscanCapturePathType','InstallInitialize','DepscanRollbackPathType','RemoveEnvironmentStrings','WriteEnvironmentStrings','InstallExecute','RemoveExistingProducts','DepscanRestorePathType','InstallFinalize')
    for ($i=0; $i -lt $order.Count; $i++) {
        if (-not $sequence.ContainsKey($order[$i])) { throw "Missing MSI sequence action: $($order[$i])" }
        if ($i -gt 0 -and $sequence[$order[$i-1]] -ge $sequence[$order[$i]]) { throw 'Unsafe PATH/upgrade/rollback ordering in compiled MSI' }
    }
} finally {
    [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($database)
    [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($engine)
}
