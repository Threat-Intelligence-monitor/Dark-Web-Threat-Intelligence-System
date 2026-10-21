[CmdletBinding()]
param([Parameter(Mandatory = $true)][string]$DataRoot)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$releaseRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..')).TrimEnd('\')
$dataDirectory = [IO.Path]::GetFullPath($DataRoot).TrimEnd('\')
$releasesRoot = Join-Path $dataDirectory 'app\releases'
$stateRoot = if ($env:DARKWEB_UPDATE_STATE_DIR) { $env:DARKWEB_UPDATE_STATE_DIR } else { Join-Path $env:LOCALAPPDATA 'DarkWebThreatIntel' }
$installation = Get-Content -LiteralPath (Join-Path $stateRoot 'installation.json') -Raw -Encoding UTF8 | ConvertFrom-Json
$installedRoot = [IO.Path]::GetFullPath([string]$installation.current_root).TrimEnd('\')
foreach ($root in @($releaseRoot, $installedRoot)) {
    if ((Split-Path -Parent $root) -ine $releasesRoot -or -not (Test-Path -LiteralPath (Join-Path $root 'version.json') -PathType Leaf)) {
        throw 'Both releases must be prepared directories directly below DataRoot\app\releases.'
    }
    $directory = Get-Item -LiteralPath $root -Force
    while ($null -ne $directory) {
        if ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Linked release directories are not allowed.' }
        $directory = $directory.Parent
    }
}
if ([int]$installation.format -ne 1 -or
    [IO.Path]::GetFullPath([string]$installation.data_root).TrimEnd('\') -ine $dataDirectory) {
    throw 'DataRoot does not match the active managed installation.'
}
$version = Get-Content -LiteralPath (Join-Path $installedRoot 'version.json') -Raw -Encoding UTF8 | ConvertFrom-Json
if ($version.version -ne $installation.current_version) { throw 'The active installation version is inconsistent.' }
$env:DARKWEB_DATA_ROOT = $dataDirectory
$env:DARKWEB_APP_ROOT = Join-Path $dataDirectory 'app'
$env:DARKWEB_UPDATE_STATE_DIR = $stateRoot
$powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
& $powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot 'start_all_services_windows.ps1') prepare-update -DataRoot $dataDirectory
if ($LASTEXITCODE -ne 0) { throw 'Preparing the verified update runtime failed; the current services were preserved.' }
$profilePath = Join-Path $releaseRoot 'darkweb_collector\.runtime\windows\python-environment.json'
$profile = Get-Content -LiteralPath $profilePath -Raw -Encoding UTF8 | ConvertFrom-Json
$python = Join-Path ([string]$profile.root) 'Scripts\python.exe'
if (-not (Test-Path -LiteralPath $python -PathType Leaf)) { throw 'The prepared Python runtime is unavailable.' }
& $python -B (Join-Path $PSScriptRoot 'run_self_update.py') --installed-root $installedRoot
if ($LASTEXITCODE -ne 0) { throw 'The verified update did not complete; inspect update-status.json and update.log.' }
Write-Host '[SUCCESS] The verified update completed, including application version and queue health checks.'
