param([Parameter(Mandatory=$true)][string]$OutputDirectory)
$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
$sources = Join-Path $repo 'crates/depscan-cli/wix'
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$output = (Resolve-Path -LiteralPath $OutputDirectory).Path
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio/Installer/vswhere.exe'
if (-not (Test-Path -LiteralPath $vswhere)) { throw 'Visual Studio C++ build tools are required' }
$installation = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if ($LASTEXITCODE -ne 0 -or -not $installation) { throw 'Cannot locate the x64 MSVC toolset' }
$vcvars = Join-Path $installation 'VC/Auxiliary/Build/vcvars64.bat'
$flags = '/nologo /W4 /WX /utf-8 /sdl /GS /guard:cf /DUNICODE /D_UNICODE /DWIN32_LEAN_AND_MEAN /MT'
$commands = @(
    '@echo off',
    'chcp 65001 >nul',
    ('call "{0}" >nul' -f $vcvars),
    'if errorlevel 1 exit /b 1',
    ('cl {0} /I"{1}" /Fe:"{2}\path-type-tests.exe" "{3}\path-type-tests.c" "{1}\path-type-value.c" advapi32.lib /link /DYNAMICBASE /NXCOMPAT /guard:cf' -f $flags,$sources,$output,$PSScriptRoot),
    'if errorlevel 1 exit /b 1',
    ('"{0}\path-type-tests.exe"' -f $output),
    'if errorlevel 1 exit /b 1',
    ('cl {0} /LD /I"{1}" /Fe:"{2}\depscan-msi-path.dll" "{1}\path-type.c" "{1}\path-type-value.c" advapi32.lib msi.lib /link /DYNAMICBASE /NXCOMPAT /guard:cf /Brepro' -f $flags,$sources,$output),
    'exit /b %errorlevel%'
)
$batch = Join-Path $output 'build-path-helper.cmd'
[IO.File]::WriteAllLines($batch,$commands,(New-Object Text.UTF8Encoding($false)))
Push-Location $output
try {
    & $env:ComSpec /d /c "`"$batch`""
    if ($LASTEXITCODE -ne 0) { throw 'Native MSI PATH helper build/tests failed' }
} finally { Pop-Location }
