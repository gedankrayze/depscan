# Dot-sourced by the native installer tests; no product code depends on these helpers.
$utf8 = New-Object Text.UTF8Encoding($false)
$environmentKey = 'SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
$options = [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames

function Read-PathState {
    $machine = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($environmentKey)
    $user = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment')
    try {
        $hasUserPath = @($user.GetValueNames()) -contains 'Path'
        return [pscustomobject]@{
            MachinePath=$machine.GetValue('Path',$null,$options)
            MachineKind=$machine.GetValueKind('Path').ToString()
            UserPathExists=$hasUserPath
            UserPath=$user.GetValue('Path',$null,$options)
            UserKind=$(if ($hasUserPath) { $user.GetValueKind('Path').ToString() } else { $null })
        }
    } finally { $machine.Close(); $user.Close() }
}

function Invoke-Native([string]$Executable,[string[]]$Arguments,[string]$Name,[int]$ExpectedExit=0) {
    foreach ($argument in $Arguments) { if ($argument.Contains('"') -or $argument.EndsWith('\')) { throw 'Unsupported native argument' } }
    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName = $Executable
    $info.Arguments = ($Arguments | ForEach-Object { if ($_ -match '\s') { '"' + $_ + '"' } else { $_ } }) -join ' '
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $info
    try {
        [void]$process.Start()
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(90000)) { $process.Kill(); throw "Timed out: $Name" }
        $process.WaitForExit()
        $code = $process.ExitCode
        [IO.File]::WriteAllText((Join-Path $EvidenceDirectory ($Name + '.stdout')),$stdout.Result,$utf8)
        [IO.File]::WriteAllText((Join-Path $EvidenceDirectory ($Name + '.stderr')),$stderr.Result,$utf8)
        if ($code -ne $ExpectedExit) { throw "$Name exited $code; expected $ExpectedExit" }
        return $stdout.Result
    } finally { $process.Dispose() }
}

function Read-MsiProperty($Database,[string]$Name) {
    $view = $Database.OpenView("SELECT ``Value`` FROM ``Property`` WHERE ``Property`` = '$Name'")
    try {
        [void]$view.Execute()
        $record = $view.Fetch()
        if (-not $record) { throw "Missing MSI property: $Name" }
        try { return $record.StringData(1) }
        finally { [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($record) }
    } finally {
        [void]$view.Close()
        [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($view)
    }
}

function Read-ProductCode([string]$Installer) {
    $engine = New-Object -ComObject WindowsInstaller.Installer
    $database = $engine.OpenDatabase($Installer,0)
    try { return Read-MsiProperty $database 'ProductCode' }
    finally {
        [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($database)
        [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($engine)
    }
}

function Restore-PathType($Baseline) {
    $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($environmentKey,$true)
    try {
        if ($key.GetValue('Path',$null,$options) -cne $Baseline.MachinePath) { throw 'Concurrent PATH edit; refusing cleanup overwrite' }
        $key.SetValue('Path',[string]$Baseline.MachinePath,[Enum]::Parse([Microsoft.Win32.RegistryValueKind],$Baseline.MachineKind))
    } finally { $key.Close() }
}
