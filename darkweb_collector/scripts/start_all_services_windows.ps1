[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Position = 0)]
    [ValidateSet("start", "stop", "status", "install", "prepare-update", "health", "register", "uninstall")]
    [string]$Action = "start",

    [Parameter(Position = 1)]
    [ValidateSet("keep-data", "purge-data")]
    [string]$UninstallMode = "keep-data",

    [string]$DataRoot = "",

    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
if (-not (Get-Command Get-FileHash -ErrorAction SilentlyContinue)) {
    $utilityModules = @(
        (Join-Path $PSHOME "Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1"),
        (Join-Path $env:SystemRoot "System32\WindowsPowerShell\v1.0\Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1")
    )
    foreach ($module in $utilityModules) {
        if (Test-Path -LiteralPath $module -PathType Leaf) {
            Import-Module -Name $module -ErrorAction SilentlyContinue
        }
        if (Get-Command Get-FileHash -ErrorAction SilentlyContinue) { break }
    }
}
if (-not (Get-Command Get-FileHash -ErrorAction SilentlyContinue)) {
    throw "Get-FileHash is unavailable in the current PowerShell environment."
}
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
}
catch {
}

$SessionName = "bishe-stack-windows"
$ApiHost = "127.0.0.1"
$ApiPort = if ($env:DARKWEB_API_PORT) { [int]$env:DARKWEB_API_PORT } else { 8000 }
$ApiBaseUrl = "http://${ApiHost}:${ApiPort}"
$ApiHealthUrl = "$ApiBaseUrl/api/health"
$ApiJobsUrl = "$ApiBaseUrl/api/jobs"
$FrontendHost = "127.0.0.1"
$FrontendPort = if ($env:DARKWEB_FRONTEND_PORT) { [int]$env:DARKWEB_FRONTEND_PORT } else { 5174 }
$FrontendUrl = "http://${FrontendHost}:${FrontendPort}"
$NewUiMarker = '<meta name="darkweb-ui" content="xuanjian-new-ui"'
$ServiceWaitSeconds = 45
$SchedulerIntervalSeconds = if ($env:SCHEDULER_INTERVAL_SECONDS) { [int]$env:SCHEDULER_INTERVAL_SECONDS } else { 60 }
$VulnSyncIntervalSeconds = if ($env:VULN_SYNC_INTERVAL_SECONDS) { [int]$env:VULN_SYNC_INTERVAL_SECONDS } else { 3600 }
$VulnSyncLimit = if ($env:VULN_SYNC_LIMIT) { [int]$env:VULN_SYNC_LIMIT } else { 300 }
$ConfiguredBrowserConcurrency = 3
if ($env:DARKWEB_BROWSER_CONCURRENCY) {
    try {
        $ConfiguredBrowserConcurrency = [Math]::Max([int]$env:DARKWEB_BROWSER_CONCURRENCY, 3)
    }
    catch {
        $ConfiguredBrowserConcurrency = 3
    }
}
$BrowserPublicConcurrency = if ($env:DARKWEB_BROWSER_PUBLIC_CONCURRENCY) {
    [Math]::Max([int]$env:DARKWEB_BROWSER_PUBLIC_CONCURRENCY, 2)
}
else {
    [Math]::Max([int][Math]::Ceiling($ConfiguredBrowserConcurrency / 2.0), 2)
}
$BrowserOnionConcurrency = if ($env:DARKWEB_BROWSER_ONION_CONCURRENCY) {
    [Math]::Max([int]$env:DARKWEB_BROWSER_ONION_CONCURRENCY, 1)
}
else {
    [Math]::Max($ConfiguredBrowserConcurrency - $BrowserPublicConcurrency, 1)
}
$BrowserConcurrency = $BrowserPublicConcurrency + $BrowserOnionConcurrency

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$CollectorRoot = (Resolve-Path (Join-Path $ScriptDir "..")).Path
$ProjectRoot = (Resolve-Path (Join-Path $CollectorRoot "..")).Path
$DashboardRoot = Join-Path $ProjectRoot "threat-intelligence-dashboard"
$PostgreSqlSetupScript = Join-Path $ScriptDir "setup_postgresql_windows.ps1"
$LocalAppDataRoot = if ($env:LOCALAPPDATA) { $env:LOCALAPPDATA } elseif ($env:USERPROFILE) { Join-Path $env:USERPROFILE "AppData\Local" } else { Join-Path $ProjectRoot ".runtime\user" }
$ControlRoot = [System.IO.Path]::GetFullPath((Join-Path $LocalAppDataRoot "DarkWebThreatIntel"))
$DataRootConfigPath = Join-Path $ControlRoot "data-root.json"
$PostgreSqlTargetConfigPath = Join-Path $ControlRoot "postgresql-target.json"
$dataRootConfig = $null
if (Test-Path -LiteralPath $DataRootConfigPath -PathType Leaf) {
    try {
        $dataRootConfig = Get-Content -LiteralPath $DataRootConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
        if ([int]$dataRootConfig.format -ne 1 -or -not $dataRootConfig.data_root) {
            throw "unsupported configuration"
        }
    }
    catch {
        throw "Data root configuration is invalid: $DataRootConfigPath"
    }
}
$configuredDataRoot = if ($DataRoot) {
    $DataRoot
}
elseif ([Environment]::GetEnvironmentVariable("DARKWEB_DATA_ROOT", "User")) {
    [Environment]::GetEnvironmentVariable("DARKWEB_DATA_ROOT", "User")
}
elseif ($dataRootConfig) {
    [string]$dataRootConfig.data_root
}
elseif ($env:DARKWEB_DATA_ROOT) {
    $env:DARKWEB_DATA_ROOT
}
elseif ($env:DARKWEB_USER_DATA_ROOT) {
    $env:DARKWEB_USER_DATA_ROOT
}
else {
    $ControlRoot
}
if (-not [System.IO.Path]::IsPathRooted($configuredDataRoot)) {
    throw "DataRoot must be an absolute path below a drive root."
}
$DefaultUserDataDir = [System.IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($configuredDataRoot)).TrimEnd("\")
if ($DefaultUserDataDir.StartsWith("\\", [StringComparison]::Ordinal)) {
    throw "DataRoot must be on a local Windows volume; network and WSL UNC paths are not supported."
}
$dataDriveRoot = [System.IO.Path]::GetPathRoot($DefaultUserDataDir).TrimEnd("\")
if ($DefaultUserDataDir -ieq $dataDriveRoot) {
    throw "DataRoot cannot be a drive root; use a dedicated directory such as D:\DarkWebThreatIntel."
}
foreach ($protectedDataRoot in @($env:SystemRoot, $env:ProgramFiles, ${env:ProgramFiles(x86)})) {
    if (-not $protectedDataRoot) { continue }
    $protectedPath = [System.IO.Path]::GetFullPath($protectedDataRoot).TrimEnd("\")
    if ($DefaultUserDataDir -ieq $protectedPath -or
        $DefaultUserDataDir.StartsWith($protectedPath + "\", [StringComparison]::OrdinalIgnoreCase)) {
        throw "DataRoot cannot be under a protected system directory: $protectedPath"
    }
}
$PreviousDataRoot = if ($dataRootConfig -and $dataRootConfig.previous_data_root) {
    [System.IO.Path]::GetFullPath([string]$dataRootConfig.previous_data_root).TrimEnd("\")
}
else {
    ""
}
function Resolve-MigratedDataPath {
    param([string]$Value, [string]$DefaultPath)
    if (-not $Value) { return $DefaultPath }
    $resolvedValue = [System.IO.Path]::GetFullPath($Value).TrimEnd("\")
    if ($PreviousDataRoot -and $PreviousDataRoot -ine $DefaultUserDataDir) {
        if ($resolvedValue -ieq $PreviousDataRoot) { return $DefaultUserDataDir }
        $previousPrefix = $PreviousDataRoot + "\"
        if ($resolvedValue.StartsWith($previousPrefix, [StringComparison]::OrdinalIgnoreCase)) {
            return $DefaultUserDataDir.TrimEnd("\") + $resolvedValue.Substring($PreviousDataRoot.Length)
        }
    }
    return $resolvedValue
}
$MigrationRoot = Resolve-MigratedDataPath $env:DARKWEB_MIGRATION_ROOT (Join-Path $DefaultUserDataDir "migrations")
$AppRoot = Resolve-MigratedDataPath $env:DARKWEB_APP_ROOT (Join-Path $DefaultUserDataDir "app")
if ($AppRoot.StartsWith("\\", [StringComparison]::Ordinal) -or
    $AppRoot.TrimEnd("\") -ieq [System.IO.Path]::GetPathRoot($AppRoot).TrimEnd("\")) {
    throw "DARKWEB_APP_ROOT must be a dedicated directory on a local Windows volume."
}
$PlaywrightBrowsersRoot = Resolve-MigratedDataPath $env:PLAYWRIGHT_BROWSERS_PATH (Join-Path $DefaultUserDataDir "playwright")
$env:DARKWEB_DATA_ROOT = $DefaultUserDataDir
$env:DARKWEB_USER_DATA_ROOT = $DefaultUserDataDir
$env:DARKWEB_MIGRATION_ROOT = $MigrationRoot
$env:DARKWEB_APP_ROOT = $AppRoot
$env:PLAYWRIGHT_BROWSERS_PATH = $PlaywrightBrowsersRoot
$VenvDir = Join-Path $CollectorRoot "venv"
$VenvPython = Join-Path $VenvDir "Scripts\python.exe"
$RuntimeDir = Join-Path $CollectorRoot ".runtime\windows"
$PythonEnvironmentState = Join-Path $RuntimeDir "python-environment.json"
$PythonEnvironmentsRoot = Join-Path $DefaultUserDataDir "runtimes\python-envs"
$DependencyHelper = Join-Path $ScriptDir "runtime_dependencies.py"
$NewCollectorEnvironment = $false
$DashboardNodeModulesDir = Join-Path $DashboardRoot "node_modules"
$DashboardDistDir = Join-Path $DashboardRoot "dist"
$LogDir = Join-Path $RuntimeDir "logs"
$PidFile = Join-Path $RuntimeDir "services.json"
$RuntimePortsFile = Join-Path $RuntimeDir "ports.json"
$CommandBinDir = Join-Path $ControlRoot "bin"
$DarkwebCommandPath = Join-Path $CommandBinDir "darkweb.cmd"
$UpdateStateRoot = if ($env:DARKWEB_UPDATE_STATE_DIR) {
    if (-not [System.IO.Path]::IsPathRooted($env:DARKWEB_UPDATE_STATE_DIR)) {
        throw "DARKWEB_UPDATE_STATE_DIR must be an absolute local path."
    }
    $resolvedUpdateStateRoot = [System.IO.Path]::GetFullPath($env:DARKWEB_UPDATE_STATE_DIR)
    if ($resolvedUpdateStateRoot.StartsWith("\\", [StringComparison]::Ordinal)) {
        throw "DARKWEB_UPDATE_STATE_DIR does not support network or WSL UNC paths."
    }
    $resolvedUpdateStateRoot
}
else {
    $ControlRoot
}
$InstallationStatePath = Join-Path $UpdateStateRoot "installation.json"
$ManagedInstallation = $null
$ManagedInstallationActive = $false
if (Test-Path -LiteralPath $InstallationStatePath -PathType Leaf) {
    try {
        $candidateInstallation = Get-Content -LiteralPath $InstallationStatePath -Raw -Encoding UTF8 | ConvertFrom-Json
        if ([int]$candidateInstallation.format -eq 1 -and $candidateInstallation.current_root) {
            $targetProjectRoot = [System.IO.Path]::GetFullPath([string]$candidateInstallation.current_root).TrimEnd("\")
            $currentProjectRoot = [System.IO.Path]::GetFullPath($ProjectRoot).TrimEnd("\")
            $targetScript = Join-Path $targetProjectRoot "darkweb_collector\scripts\start_all_services_windows.ps1"
            if ($targetProjectRoot.Equals($currentProjectRoot, [StringComparison]::OrdinalIgnoreCase)) {
                $ManagedInstallation = $candidateInstallation
                $ManagedInstallationActive = $true
            }
            elseif ($Action -ne "prepare-update" -and (Test-Path -LiteralPath $targetScript -PathType Leaf)) {
                $forwardArguments = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $targetScript, $Action)
                if ($Action -eq "uninstall") {
                    $forwardArguments += $UninstallMode
                }
                if ($DataRoot) {
                    $forwardArguments += @("-DataRoot", $DataRoot)
                }
                if ($Force) {
                    $forwardArguments += "-Force"
                }
                if ($WhatIfPreference) {
                    $forwardArguments += "-WhatIf"
                }
                & "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" @forwardArguments
                exit $LASTEXITCODE
            }
        }
    }
    catch {
        Write-Host "[WARN] Ignoring invalid managed installation state: $($_.Exception.Message)"
    }
}
$ActiveReleaseFile = Resolve-MigratedDataPath $env:DARKWEB_ACTIVE_RELEASE_FILE (Join-Path $DefaultUserDataDir "active-release.json")
$ActiveRelease = $null
if (Test-Path -LiteralPath $ActiveReleaseFile -PathType Leaf) {
    try {
        $candidateRelease = Get-Content -LiteralPath $ActiveReleaseFile -Raw -Encoding UTF8 | ConvertFrom-Json
        if ([int]$candidateRelease.format -eq 1 -and $candidateRelease.database_engine -eq "postgresql") {
            $ActiveRelease = $candidateRelease
        }
    }
    catch {
        throw "Active data release configuration is invalid: $ActiveReleaseFile"
    }
}
$ActiveReleaseEnabled = $null -ne $ActiveRelease
$DefaultTorExpertRoot = Join-Path $DefaultUserDataDir "tor-expert"
$DefaultTorBridgeRuntimeDir = Join-Path $DefaultUserDataDir "tor_bridge_runtime"
$DefaultTorBridgeAutoRuntimeDir = Join-Path $DefaultUserDataDir "tor_bridge_runtime_auto"
$DefaultNpmCacheDir = Join-Path $DefaultUserDataDir "npm-cache"
$DefaultRuntimeRoot = Join-Path $DefaultUserDataDir "runtimes"
$GarnetVersion = "2.2.1"
$GarnetArchiveUrl = "https://github.com/microsoft/garnet/releases/download/v2.2.1/win-x64-based-readytorun.zip"
$GarnetArchiveSha256 = "93f0026d305585cd249a91dda6fd44c46bcaa56304115b039f74f23fe630c64a"
$GarnetServerSha256 = "4aae95813ff41810d866708d617fd7c2efe8ff631d5c8a25fe743fa08e0f1bac"
$GarnetRuntimeRoot = Join-Path $DefaultRuntimeRoot "garnet\$GarnetVersion"
$GarnetServerExecutable = Join-Path $GarnetRuntimeRoot "net10.0\GarnetServer.exe"
$GarnetDotnetVersion = "10.0.11"
$GarnetDotnetArchiveUrl = "https://builds.dotnet.microsoft.com/dotnet/Runtime/10.0.11/dotnet-runtime-10.0.11-win-x64.zip"
$GarnetDotnetArchiveSha512 = "d9ab9c0d9916b8fa3585b5f403057f594ffffb8364dac09e0007dd8ac671c86754935b980d8fb5da83cb1b82ac3cd57cc407c969e6d837aaa2fae21047cb7448"
$GarnetDotnetExecutableSha256 = "ab1b71fd3dd71062e074c9fab8312081a81b7f2b3e0327c48c4d249c8d1a3135"
$GarnetDotnetRoot = Join-Path $DefaultRuntimeRoot "dotnet\$GarnetDotnetVersion"
$GarnetDotnetExecutable = Join-Path $GarnetDotnetRoot "dotnet.exe"
$DefaultGarnetDataRoot = Join-Path $DefaultUserDataDir "garnet-data"
$GarnetDataRoot = Resolve-MigratedDataPath $env:DARKWEB_GARNET_DATA_ROOT $DefaultGarnetDataRoot
$GarnetCheckpointDir = Join-Path $GarnetDataRoot "checkpoints"
$GarnetCheckpointIntervalSeconds = if ($env:DARKWEB_GARNET_CHECKPOINT_INTERVAL_SECONDS) { [Math]::Max([int]$env:DARKWEB_GARNET_CHECKPOINT_INTERVAL_SECONDS, 300) } else { 21600 }
$GarnetRuntimeManifest = Join-Path $DefaultUserDataDir "garnet-runtime.json"
$ManagedGarnetRedisUrl = "redis://127.0.0.1:6380/0"
$LegacyManagedRedisUrl = "redis://127.0.0.1:6379/0"
$script:RedisProvider = "external"
$LegacyCollectorOutputRoot = Join-Path $DefaultUserDataDir "output"
$ProjectCollectorOutputRoot = Join-Path $CollectorRoot "output"
$ProjectCollectorOutputArchiveRoot = Join-Path $CollectorRoot "output-archive"
$ProjectCollectorDbPath = Join-Path $CollectorRoot "data\collector.db"
$AuthPasswordFile = Resolve-MigratedDataPath $env:DARKWEB_AUTH_PASSWORD_FILE (Join-Path $DefaultUserDataDir "auth-password.txt")
$NodeExePath = ""
$NodeBinDir = ""
$PackageLockStamp = Join-Path $DashboardRoot "node_modules\.package-lock.sha256"
$RedisUrl = if ($env:REDIS_URL) { $env:REDIS_URL } else { $ManagedGarnetRedisUrl }
$CollectorDbPath = Resolve-MigratedDataPath $env:DARKWEB_COLLECTOR_DB_PATH (Join-Path $DefaultUserDataDir "collector.db")
$ManagedCollectorSitesFile = if ($ManagedInstallationActive -and $ManagedInstallation.sites_file) {
    Resolve-MigratedDataPath ([string]$ManagedInstallation.sites_file) ""
}
else {
    ""
}
$ConfiguredCollectorSitesFile = if ($ManagedCollectorSitesFile) {
    $ManagedCollectorSitesFile
}
elseif ($env:DARKWEB_COLLECTOR_SITES_FILE) {
    Resolve-MigratedDataPath $env:DARKWEB_COLLECTOR_SITES_FILE ""
}
else {
    ""
}
$ConfiguredSitesParent = if ($ConfiguredCollectorSitesFile) { Split-Path -Parent $ConfiguredCollectorSitesFile } else { "" }
$SitesFileBelongsToAnotherCheckout = $ConfiguredSitesParent -and (Split-Path -Leaf $ConfiguredSitesParent) -ieq "darkweb_collector" -and $ConfiguredSitesParent -ine $CollectorRoot
$CollectorSitesFile = if ($ManagedCollectorSitesFile) {
    $ManagedCollectorSitesFile
}
elseif ($ConfiguredCollectorSitesFile -and -not $SitesFileBelongsToAnotherCheckout) {
    $ConfiguredCollectorSitesFile
}
else {
    Join-Path $CollectorRoot "sites.yaml"
}
$TorBridgeTorExecutable = Resolve-MigratedDataPath $env:DARKWEB_TOR_EXECUTABLE ""
$TorBridgeTransportExecutable = Resolve-MigratedDataPath $env:DARKWEB_TOR_TRANSPORT_EXECUTABLE ""
$TorExpertRoot = Resolve-MigratedDataPath $env:DARKWEB_TOR_EXPERT_DIR $DefaultTorExpertRoot
$TorBridgePtConfigPath = if ($env:DARKWEB_TOR_PT_CONFIG_PATH -and [System.IO.Path]::GetExtension($env:DARKWEB_TOR_PT_CONFIG_PATH) -ieq ".json") {
    Resolve-MigratedDataPath $env:DARKWEB_TOR_PT_CONFIG_PATH (Join-Path $TorExpertRoot "pt_config.json")
}
else {
    Join-Path $TorExpertRoot "pt_config.json"
}
$TorReleaseMetadataUrl = if ($env:TOR_RELEASE_METADATA_URL) { $env:TOR_RELEASE_METADATA_URL } else { "https://aus1.torproject.org/torbrowser/update_3/release/download-windows-x86_64.json" }
$TorDistBaseUrl = if ($env:TOR_DIST_BASE_URL) { $env:TOR_DIST_BASE_URL.TrimEnd("/") } else { "https://dist.torproject.org/torbrowser" }
$TorBrowserBuildRepo = if ($env:TOR_BROWSER_BUILD_REPO) { $env:TOR_BROWSER_BUILD_REPO } else { "https://gitlab.torproject.org/tpo/applications/tor-browser-build.git" }
$BundledTorPtConfigPath = Join-Path $CollectorRoot "src\darkweb_collector\tor_bridge_control\pt_config.json"
$script:TorReleaseInfo = $null
$ManagedCollectorOutputRoot = if ($ManagedInstallationActive -and $ManagedInstallation.output_root) {
    Resolve-MigratedDataPath ([string]$ManagedInstallation.output_root) ""
}
else {
    ""
}
$ConfiguredCollectorOutputRoot = if ($ManagedCollectorOutputRoot) {
    $ManagedCollectorOutputRoot
}
elseif ($env:DARKWEB_COLLECTOR_OUTPUT_ROOT) {
    Resolve-MigratedDataPath $env:DARKWEB_COLLECTOR_OUTPUT_ROOT ""
}
else {
    ""
}
$ConfiguredOutputParent = if ($ConfiguredCollectorOutputRoot) { Split-Path -Parent $ConfiguredCollectorOutputRoot } else { "" }
$OutputRootBelongsToAnotherCheckout = $ConfiguredOutputParent -and (Split-Path -Leaf $ConfiguredOutputParent) -ieq "darkweb_collector" -and $ConfiguredOutputParent -ine $CollectorRoot
$CollectorOutputRoot = if ($ManagedCollectorOutputRoot) {
    $ManagedCollectorOutputRoot
}
elseif ($ConfiguredCollectorOutputRoot -and -not $OutputRootBelongsToAnotherCheckout) {
    $ConfiguredCollectorOutputRoot
}
else {
    if ($ActiveReleaseEnabled -and $ActiveRelease.output_root) {
        Resolve-MigratedDataPath ([string]$ActiveRelease.output_root) ""
    }
    else {
        $LegacyCollectorOutputRoot
    }
}
$env:DARKWEB_ACTIVE_RELEASE_FILE = $ActiveReleaseFile
$env:DARKWEB_UPDATE_STATE_DIR = $UpdateStateRoot
$env:DARKWEB_COLLECTOR_DB_PATH = $CollectorDbPath
$env:DARKWEB_COLLECTOR_SITES_FILE = $CollectorSitesFile
$env:DARKWEB_COLLECTOR_OUTPUT_ROOT = $CollectorOutputRoot
$env:DARKWEB_GARNET_DATA_ROOT = $GarnetDataRoot
$env:DARKWEB_AUTH_PASSWORD_FILE = $AuthPasswordFile
$env:DARKWEB_TOR_EXPERT_DIR = $TorExpertRoot
if ($TorBridgeTorExecutable) { $env:DARKWEB_TOR_EXECUTABLE = $TorBridgeTorExecutable }
else { Remove-Item Env:DARKWEB_TOR_EXECUTABLE -ErrorAction SilentlyContinue }
if ($TorBridgeTransportExecutable) { $env:DARKWEB_TOR_TRANSPORT_EXECUTABLE = $TorBridgeTransportExecutable }
else { Remove-Item Env:DARKWEB_TOR_TRANSPORT_EXECUTABLE -ErrorAction SilentlyContinue }
$env:DARKWEB_TOR_PT_CONFIG_PATH = $TorBridgePtConfigPath

function Write-Info {
    param([string]$Message)
    Write-Host "[INFO] $Message"
}

function Write-Warn {
    param([string]$Message)
    Write-Host "[WARN] $Message"
}

function Stop-WithError {
    param([string]$Message)
    Write-Error "[ERROR] $Message"
    exit 1
}

function Write-StartupTrace {
    param([string]$Message)
    if ($env:DARKWEB_TRACE_STARTUP -eq "1") {
        Write-Info "[trace] $Message"
    }
}

function Invoke-TimedStep {
    param(
        [string]$Name,
        [scriptblock]$Body
    )
    if ($env:DARKWEB_TRACE_STARTUP -ne "1") {
        & $Body
        return
    }

    $started = Get-Date
    Write-StartupTrace "$Name started"
    try {
        & $Body
    }
    finally {
        $elapsed = ((Get-Date) - $started).TotalSeconds
        Write-StartupTrace ("{0} finished in {1:N2}s" -f $Name, $elapsed)
    }
}

function Resolve-RequiredCommand {
    param(
        [string]$Name,
        [string]$Hint
    )
    $command = Get-Command $Name -ErrorAction SilentlyContinue
    if (-not $command) {
        Stop-WithError "Missing required command '$Name'. $Hint"
    }
    return $command.Source
}

function Resolve-OptionalCommand {
    param([string]$Name)
    $command = Get-Command $Name -ErrorAction SilentlyContinue
    if ($command) {
        return $command.Source
    }
    return $null
}

function Resolve-OptionalCommandPath {
    param([string[]]$Names)
    foreach ($name in $Names) {
        $command = Get-Command $name -ErrorAction SilentlyContinue
        if ($command) {
            return $command.Source
        }
    }
    return $null
}

function Resolve-PowerShellCommand {
    $powerShell = Resolve-OptionalCommandPath @("pwsh.exe", "pwsh", "powershell.exe", "powershell")
    if ($powerShell) {
        return $powerShell
    }
    Stop-WithError "PowerShell is required to start background services."
}

function Quote-PS {
    param([string]$Value)
    return "'" + $Value.Replace("'", "''") + "'"
}

function Ensure-Directory {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path | Out-Null
    }
}

function Get-DataRootDriveInfo {
    $candidate = $DefaultUserDataDir
    while (-not (Test-Path -LiteralPath $candidate) -and $candidate -ne [System.IO.Path]::GetPathRoot($candidate)) {
        $candidate = Split-Path -Parent $candidate
    }
    return [System.IO.DriveInfo]::new([System.IO.Path]::GetPathRoot($candidate))
}

function Assert-DataRootCapacity {
    Ensure-Directory $DefaultUserDataDir
    $drive = Get-DataRootDriveInfo
    if ($drive.AvailableFreeSpace -lt 2GB -and -not $Force) {
        Stop-WithError "Data root $DefaultUserDataDir has less than 2 GiB free. Choose another drive with configure-data-root.cmd or re-run with -Force only after confirming capacity."
    }
    if ($drive.AvailableFreeSpace -lt 20GB) {
        Write-Warn "Data root has only $([Math]::Round($drive.AvailableFreeSpace / 1GB, 2)) GiB free: $DefaultUserDataDir"
    }
}

function New-AuthPassword {
    return "123456"
}

function Ensure-AuthPasswordFile {
    if ($env:DARKWEB_AUTH_PASSWORD) {
        return
    }
    $parent = Split-Path -Parent $AuthPasswordFile
    Ensure-Directory $parent
    if ((Test-Path -LiteralPath $AuthPasswordFile) -and ((Get-Content -LiteralPath $AuthPasswordFile -Raw).Trim())) {
        return
    }
    New-AuthPassword | Set-Content -LiteralPath $AuthPasswordFile -Encoding ASCII -NoNewline
    Write-Info "Initialized local auth password file: $AuthPasswordFile"
}

function Remove-GeneratedDirectory {
    param(
        [string]$Path,
        [string]$AllowedRoot
    )
    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }

    $resolvedPath = (Resolve-Path -LiteralPath $Path).Path
    $resolvedRoot = (Resolve-Path -LiteralPath $AllowedRoot).Path
    $rootPrefix = $resolvedRoot.TrimEnd("\") + "\"
    if (-not ($resolvedPath.Equals($resolvedRoot, [StringComparison]::OrdinalIgnoreCase) -or $resolvedPath.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase))) {
        Stop-WithError "Refusing to remove generated directory outside project root: $resolvedPath"
    }
    Remove-Item -LiteralPath $resolvedPath -Recurse -Force
}

function Update-ProcessPathFromRegistry {
    $machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $parts = New-Object System.Collections.Generic.List[string]
    $seen = New-Object "System.Collections.Generic.HashSet[string]" ([StringComparer]::OrdinalIgnoreCase)
    if ($machinePath) {
        foreach ($entry in $machinePath -split ";") {
            $trimmed = $entry.Trim()
            if ($trimmed -and $seen.Add($trimmed.TrimEnd("\"))) {
                $parts.Add($trimmed) | Out-Null
            }
        }
    }
    if ($userPath) {
        foreach ($entry in $userPath -split ";") {
            $trimmed = $entry.Trim()
            if ($trimmed -and $seen.Add($trimmed.TrimEnd("\"))) {
                $parts.Add($trimmed) | Out-Null
            }
        }
    }
    if ($env:Path) {
        foreach ($entry in $env:Path -split ";") {
            $trimmed = $entry.Trim()
            if ($trimmed -and $seen.Add($trimmed.TrimEnd("\"))) {
                $parts.Add($trimmed) | Out-Null
            }
        }
    }
    $env:Path = ($parts -join ";")
}

function Add-UserPathEntry {
    param([string]$Path)
    Ensure-Directory $Path
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $entries = @()
    if ($userPath) {
        $entries = $userPath -split ";" | Where-Object { $_ -and $_.Trim() }
    }
    $alreadyPresent = $false
    foreach ($entry in $entries) {
        if ($entry.TrimEnd("\") -ieq $Path.TrimEnd("\")) {
            $alreadyPresent = $true
            break
        }
    }
    if (-not $alreadyPresent) {
        $entries += $Path
        [Environment]::SetEnvironmentVariable("Path", ($entries -join ";"), "User")
    }
    if (($env:Path -split ";") -notcontains $Path) {
        $env:Path = "$Path;$env:Path"
    }
}

function Add-ProcessPathEntry {
    param([string]$Path)
    if (-not $Path) {
        return
    }
    $entries = @($env:Path -split ";" | Where-Object { $_ -and $_.Trim() })
    foreach ($entry in $entries) {
        if ($entry.TrimEnd("\") -ieq $Path.TrimEnd("\")) {
            return
        }
    }
    $env:Path = "$Path;$env:Path"
}

function Set-UserEnv {
    param(
        [string]$Name,
        [string]$Value
    )
    $currentUserValue = [Environment]::GetEnvironmentVariable($Name, "User")
    if ($currentUserValue -ne $Value) {
        [Environment]::SetEnvironmentVariable($Name, $Value, "User")
    }
    $currentProcessValue = [Environment]::GetEnvironmentVariable($Name, "Process")
    if ($currentProcessValue -ne $Value) {
        Set-Item -Path "Env:$Name" -Value $Value
    }
}

function Test-SamePath {
    param(
        [string]$Left,
        [string]$Right
    )
    if (-not $Left -or -not $Right) {
        return $false
    }
    $leftPath = [System.IO.Path]::GetFullPath($Left).TrimEnd("\")
    $rightPath = [System.IO.Path]::GetFullPath($Right).TrimEnd("\")
    return $leftPath.Equals($rightPath, [StringComparison]::OrdinalIgnoreCase)
}

function Test-ProjectOwnedRedisEnvironment {
    $registeredProjectRoot = [Environment]::GetEnvironmentVariable("DARKWEB_PROJECT_ROOT", "User")
    $registeredCollectorRoot = [Environment]::GetEnvironmentVariable("DARKWEB_COLLECTOR_ROOT", "User")
    if (-not ((Test-SamePath -Left $registeredProjectRoot -Right $ProjectRoot) -and
        (Test-SamePath -Left $registeredCollectorRoot -Right $CollectorRoot))) {
        return $false
    }
    $registeredRedisUrl = [Environment]::GetEnvironmentVariable("REDIS_URL", "User")
    $provider = [Environment]::GetEnvironmentVariable("DARKWEB_REDIS_PROVIDER", "User")
    if ($provider -eq "garnet" -and $registeredRedisUrl -eq $ManagedGarnetRedisUrl) {
        return $true
    }
    return -not $provider -and $registeredRedisUrl -eq $LegacyManagedRedisUrl
}

function Test-PathUnderRoot {
    param(
        [string]$Path,
        [string]$Root
    )
    if (-not $Path -or -not $Root) {
        return $false
    }
    $fullPath = [System.IO.Path]::GetFullPath($Path).TrimEnd("\")
    $fullRoot = [System.IO.Path]::GetFullPath($Root).TrimEnd("\")
    return $fullPath.StartsWith($fullRoot + "\", [StringComparison]::OrdinalIgnoreCase)
}

function Get-PostgreSqlDataDirectory {
    try {
        $services = @(Get-CimInstance Win32_Service -Filter "Name LIKE 'postgresql%'" -ErrorAction Stop)
        $service = $services | Where-Object { $_.Name -match "-16$" -or [string]$_.PathName -match '(?i)\\16\\' } | Select-Object -First 1
        if (-not $service) { $service = $services | Select-Object -First 1 }
        if ($service -and [string]$service.PathName -match '(?i)(?:^|\s)-D\s+(?:"([^"]+)"|([^\s]+))') {
            $servicePath = if ($matches[1]) { $matches[1] } else { $matches[2] }
            if ($servicePath) {
                return [System.IO.Path]::GetFullPath($servicePath)
            }
        }
    }
    catch {
    }
    if (Test-Path -LiteralPath $PostgreSqlTargetConfigPath -PathType Leaf) {
        try {
            $targetConfig = Get-Content -LiteralPath $PostgreSqlTargetConfigPath -Raw -Encoding UTF8 | ConvertFrom-Json
            if ($targetConfig.data_directory) {
                return [System.IO.Path]::GetFullPath([string]$targetConfig.data_directory)
            }
        }
        catch {
        }
    }
    return ""
}

function Remove-ManagedPath {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "Low")]
    param(
        [string]$Path,
        [string]$ExpectedPath,
        [string]$Label
    )
    if (-not (Test-SamePath -Left $Path -Right $ExpectedPath)) {
        Stop-WithError "Refusing to remove unexpected path for ${Label}: $Path"
    }
    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }
    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $item = Get-Item -LiteralPath $Path -Force
    if ($PSCmdlet.ShouldProcess($fullPath, "Remove $Label")) {
        if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            if ($item.PSIsContainer) {
                [System.IO.Directory]::Delete($Path, $false)
            }
            else {
                [System.IO.File]::Delete($Path)
            }
        }
        else {
            Remove-Item -LiteralPath $Path -Recurse:$item.PSIsContainer -Force
        }
    }
}

function Remove-EmptyManagedDirectory {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "Low")]
    param(
        [string]$Path,
        [string]$ExpectedPath
    )
    if (-not (Test-SamePath -Left $Path -Right $ExpectedPath)) {
        Stop-WithError "Refusing to remove unexpected directory: $Path"
    }
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        return
    }
    if (@(Get-ChildItem -LiteralPath $Path -Force).Count -ne 0) {
        return
    }
    if ($PSCmdlet.ShouldProcess($Path, "Remove empty darkweb directory")) {
        Remove-Item -LiteralPath $Path -Force
    }
}

function Remove-UserPathEntry {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "Low")]
    param([string]$Path)
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if (-not $userPath) {
        return
    }
    $entries = @($userPath -split ";" | Where-Object { $_ -and $_.Trim() })
    $remaining = @($entries | Where-Object { -not (Test-SamePath -Left $_ -Right $Path) })
    if ($remaining.Count -eq $entries.Count) {
        return
    }
    if ($PSCmdlet.ShouldProcess("User PATH", "Remove $Path")) {
        [Environment]::SetEnvironmentVariable("Path", ($remaining -join ";"), "User")
    }
}

function Remove-ManagedUserEnv {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "Low")]
    param(
        [string]$Name,
        [string[]]$ExpectedValues = @(),
        [string]$ExpectedRoot = ""
    )
    $current = [Environment]::GetEnvironmentVariable($Name, "User")
    if ($null -eq $current) {
        return
    }
    $managed = $false
    foreach ($expected in $ExpectedValues) {
        $sameValue = $current -ieq $expected
        $samePath = -not $sameValue -and
            [System.IO.Path]::IsPathRooted($current) -and
            [System.IO.Path]::IsPathRooted($expected) -and
            (Test-SamePath -Left $current -Right $expected)
        if ($sameValue -or $samePath) {
            $managed = $true
            break
        }
    }
    if (-not $managed -and $ExpectedRoot) {
        $managed = (Test-SamePath -Left $current -Right $ExpectedRoot) -or (Test-PathUnderRoot -Path $current -Root $ExpectedRoot)
    }
    if (-not $managed) {
        Write-Warn "Preserving user-managed environment variable $Name"
        return
    }
    if ($PSCmdlet.ShouldProcess("User environment", "Remove $Name")) {
        [Environment]::SetEnvironmentVariable($Name, $null, "User")
    }
}

function Test-CommandWorks {
    param(
        [string]$CommandName,
        [string[]]$Arguments = @("--version")
    )
    $command = Get-Command $CommandName -ErrorAction SilentlyContinue
    if (-not $command) {
        return $false
    }
    $source = $command.Source
    if (-not $source) {
        $source = $command.Name
    }
    try {
        & $source @Arguments *> $null
        return ($LASTEXITCODE -eq 0)
    }
    catch {
        return $false
    }
}

function Resolve-WorkingCommand {
    param(
        [string[]]$Names,
        [string[]]$Arguments = @("--version")
    )
    Update-ProcessPathFromRegistry
    foreach ($name in $Names) {
        if (Test-CommandWorks -CommandName $name -Arguments $Arguments) {
            $command = Get-Command $name -ErrorAction Stop
            if ($command.Source) {
                return $command.Source
            }
            return $command.Name
        }
    }
    return $null
}

function Resolve-ExistingFile {
    param([string[]]$Candidates)
    foreach ($candidate in @($Candidates | Where-Object { $_ -and $_.Trim() } | Select-Object -Unique)) {
        try {
            if (Test-Path -LiteralPath $candidate -PathType Leaf) {
                return (Resolve-Path -LiteralPath $candidate).Path
            }
        }
        catch {
        }
    }
    return $null
}

function Resolve-CommandOrFile {
    param(
        [string[]]$Names,
        [string[]]$Candidates = @()
    )
    Update-ProcessPathFromRegistry
    foreach ($name in $Names) {
        $command = Get-Command $name -ErrorAction SilentlyContinue
        if ($command -and $command.Source -and (Test-Path -LiteralPath $command.Source -PathType Leaf)) {
            return $command.Source
        }
    }
    return Resolve-ExistingFile -Candidates $Candidates
}

function Get-TorBrowserTorCandidates {
    $candidates = @()
    $roots = @(
        $LocalAppDataRoot,
        $env:USERPROFILE,
        ([Environment]::GetEnvironmentVariable("ProgramFiles")),
        ([Environment]::GetEnvironmentVariable("ProgramFiles(x86)"))
    )
    foreach ($root in $roots | Where-Object { $_ }) {
        $candidates += (Join-Path $root "Programs\Tor Browser\Browser\TorBrowser\Tor\tor.exe")
        $candidates += (Join-Path $root "Tor Browser\Browser\TorBrowser\Tor\tor.exe")
        $candidates += (Join-Path $root "Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe")
        $candidates += (Join-Path $root "Downloads\Tor Browser\Browser\TorBrowser\Tor\tor.exe")
        $candidates += (Join-Path $root "Documents\Tor Browser\Browser\TorBrowser\Tor\tor.exe")
        $candidates += (Join-Path $root "Tor\tor.exe")
        $candidates += (Join-Path $root "Tor Expert Bundle\tor\tor.exe")
    }
    return $candidates
}

function Resolve-TorBridgeTorExecutable {
    if ($script:TorBridgeTorExecutable -and (Test-Path -LiteralPath $script:TorBridgeTorExecutable -PathType Leaf)) {
        return (Resolve-Path -LiteralPath $script:TorBridgeTorExecutable).Path
    }
    return Resolve-CommandOrFile -Names @("tor.exe", "tor") -Candidates (Get-TorBrowserTorCandidates)
}

function Resolve-TorBridgeTransportExecutable {
    param([string]$TorExecutable)
    if ($script:TorBridgeTransportExecutable -and (Test-Path -LiteralPath $script:TorBridgeTransportExecutable -PathType Leaf)) {
        return (Resolve-Path -LiteralPath $script:TorBridgeTransportExecutable).Path
    }

    $candidates = @()
    if ($TorExecutable) {
        $torDir = Split-Path -Parent $TorExecutable
        foreach ($name in @("lyrebird.exe", "snowflake-client.exe", "obfs4proxy.exe")) {
            $candidates += (Join-Path $torDir "PluggableTransports\$name")
            $candidates += (Join-Path (Split-Path -Parent $torDir) "PluggableTransports\$name")
        }
    }
    return Resolve-CommandOrFile -Names @("lyrebird.exe", "snowflake-client.exe", "obfs4proxy.exe") -Candidates $candidates
}

function Get-TorReleaseInfo {
    if ($script:TorReleaseInfo) {
        return $script:TorReleaseInfo
    }
    $payload = Invoke-RestMethod -Uri $TorReleaseMetadataUrl -TimeoutSec 30
    $version = [string]$payload.version
    $gitTag = [string]$payload.git_tag
    if ($version -notmatch '^\d+\.\d+\.\d+$' -or $gitTag -notmatch '^tbb-[0-9A-Za-z._-]+$') {
        throw "Tor release metadata is invalid."
    }
    $script:TorReleaseInfo = [PSCustomObject]@{
        Version = $version
        GitTag = $gitTag
    }
    return $script:TorReleaseInfo
}

function Get-InstalledProjectTorRuntime {
    $manifestPath = Join-Path $TorExpertRoot "current.json"
    if (Test-Path -LiteralPath $manifestPath -PathType Leaf) {
        try {
            $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
            if ((Test-Path -LiteralPath $manifest.tor_executable -PathType Leaf) -and
                (Test-Path -LiteralPath $manifest.transport_executable -PathType Leaf)) {
                return [PSCustomObject]@{
                    Version = [string]$manifest.version
                    TorExecutable = (Resolve-Path -LiteralPath $manifest.tor_executable).Path
                    TransportExecutable = (Resolve-Path -LiteralPath $manifest.transport_executable).Path
                    CheckedAt = [string]$manifest.checked_at
                }
            }
        }
        catch {
        }
    }
    foreach ($directory in @(Get-ChildItem -LiteralPath $TorExpertRoot -Directory -ErrorAction SilentlyContinue | Sort-Object LastWriteTimeUtc -Descending)) {
        $tor = Join-Path $directory.FullName "tor\tor.exe"
        $transport = Join-Path $directory.FullName "tor\pluggable_transports\lyrebird.exe"
        if ((Test-Path -LiteralPath $tor -PathType Leaf) -and (Test-Path -LiteralPath $transport -PathType Leaf)) {
            return [PSCustomObject]@{
                Version = $directory.Name
                TorExecutable = (Resolve-Path -LiteralPath $tor).Path
                TransportExecutable = (Resolve-Path -LiteralPath $transport).Path
                CheckedAt = ""
            }
        }
    }
    return $null
}

function Save-ProjectTorRuntimeManifest {
    param([object]$Runtime)
    New-Item -ItemType Directory -Force -Path $TorExpertRoot | Out-Null
    $manifestPath = Join-Path $TorExpertRoot "current.json"
    $json = @{
        version = $Runtime.Version
        tor_executable = $Runtime.TorExecutable
        transport_executable = $Runtime.TransportExecutable
        checked_at = [DateTime]::UtcNow.ToString("o")
    } | ConvertTo-Json
    [System.IO.File]::WriteAllText($manifestPath, $json, (New-Object System.Text.UTF8Encoding($false)))
}

function Install-ProjectTorRuntime {
    param([object]$Release)
    $target = Join-Path $TorExpertRoot $Release.Version
    $tor = Join-Path $target "tor\tor.exe"
    $transport = Join-Path $target "tor\pluggable_transports\lyrebird.exe"
    if (-not ((Test-Path -LiteralPath $tor -PathType Leaf) -and (Test-Path -LiteralPath $transport -PathType Leaf))) {
        $archiveName = "tor-expert-bundle-windows-x86_64-$($Release.Version).tar.gz"
        $versionUrl = "$TorDistBaseUrl/$($Release.Version)"
        $downloadRoot = Join-Path $TorExpertRoot (".download-" + [Guid]::NewGuid().ToString("N"))
        $archivePath = Join-Path $downloadRoot $archiveName
        $unpackRoot = Join-Path $downloadRoot "unpacked"
        New-Item -ItemType Directory -Force -Path $unpackRoot | Out-Null
        try {
            Write-Info "Downloading official Tor Expert Bundle $($Release.Version)..."
            Invoke-WebRequest -Uri "$versionUrl/$archiveName" -OutFile $archivePath -UseBasicParsing -TimeoutSec 180
            $checksumText = (Invoke-WebRequest -Uri "$versionUrl/sha256sums-signed-build.txt" -UseBasicParsing -TimeoutSec 30).Content
            $pattern = "(?im)^([0-9a-f]{{64}})\s+\*?{0}\s*$" -f [Regex]::Escape($archiveName)
            $match = [Regex]::Match($checksumText, $pattern)
            if (-not $match.Success) {
                throw "The official checksum list does not contain $archiveName."
            }
            $actualHash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
            if ($actualHash -ne $match.Groups[1].Value.ToLowerInvariant()) {
                throw "Tor Expert Bundle checksum verification failed."
            }
            $tar = Resolve-OptionalCommand "tar"
            if (-not $tar) {
                throw "Windows tar.exe is unavailable."
            }
            & $tar -xzf $archivePath -C $unpackRoot
            if ($LASTEXITCODE -ne 0) {
                throw "Tor Expert Bundle extraction failed."
            }
            $unpackedTor = Join-Path $unpackRoot "tor\tor.exe"
            $unpackedTransport = Join-Path $unpackRoot "tor\pluggable_transports\lyrebird.exe"
            if (-not ((Test-Path -LiteralPath $unpackedTor -PathType Leaf) -and (Test-Path -LiteralPath $unpackedTransport -PathType Leaf))) {
                throw "Tor Expert Bundle is missing tor.exe or lyrebird.exe."
            }
            if (Test-Path -LiteralPath $target) {
                $invalidTarget = "$target.invalid.$([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())"
                Move-Item -LiteralPath $target -Destination $invalidTarget
            }
            Move-Item -LiteralPath $unpackRoot -Destination $target
        }
        finally {
            if (Test-Path -LiteralPath $downloadRoot) {
                Remove-Item -LiteralPath $downloadRoot -Recurse -Force
            }
        }
    }
    $runtime = [PSCustomObject]@{
        Version = [string]$Release.Version
        TorExecutable = (Resolve-Path -LiteralPath $tor).Path
        TransportExecutable = (Resolve-Path -LiteralPath $transport).Path
        CheckedAt = [DateTime]::UtcNow.ToString("o")
    }
    Save-ProjectTorRuntimeManifest -Runtime $runtime
    return $runtime
}

function Update-ProjectTorBridgeConfig {
    param([object]$Release)
    $managedConfigPath = Join-Path $TorExpertRoot "pt_config.json"
    if ($env:DARKWEB_TOR_PT_CONFIG_PATH -and
        [System.IO.Path]::GetExtension($env:DARKWEB_TOR_PT_CONFIG_PATH) -ieq ".json" -and
        (Test-Path -LiteralPath $env:DARKWEB_TOR_PT_CONFIG_PATH -PathType Leaf) -and
        ([System.IO.Path]::GetFullPath($env:DARKWEB_TOR_PT_CONFIG_PATH) -ine [System.IO.Path]::GetFullPath($managedConfigPath))) {
        return (Resolve-Path -LiteralPath $env:DARKWEB_TOR_PT_CONFIG_PATH).Path
    }
    New-Item -ItemType Directory -Force -Path $TorExpertRoot | Out-Null
    $updated = $false
    $git = Resolve-OptionalCommand "git"
    if ($Release -and $git -and $env:DARKWEB_TOR_BRIDGE_AUTO_UPDATE -ne "0") {
        $sourceCache = Join-Path $TorExpertRoot "bridge-config-source"
        $tempConfig = Join-Path $TorExpertRoot "pt_config.json.tmp"
        try {
            if (-not (Test-Path -LiteralPath (Join-Path $sourceCache ".git"))) {
                New-Item -ItemType Directory -Force -Path $sourceCache | Out-Null
                & $git -C $sourceCache init --quiet
                & $git -C $sourceCache remote add origin $TorBrowserBuildRepo
            }
            & $git -C $sourceCache fetch --quiet --depth 1 --filter=blob:none origin "refs/tags/$($Release.GitTag)"
            if ($LASTEXITCODE -ne 0) {
                throw "Could not fetch Tor Browser build tag $($Release.GitTag)."
            }
            $configText = (& $git -C $sourceCache show "FETCH_HEAD:projects/tor-expert-bundle/pt_config.json") -join "`n"
            if ($LASTEXITCODE -ne 0) {
                throw "Could not read the Tor bridge configuration from $($Release.GitTag)."
            }
            $configPayload = $configText | ConvertFrom-Json
            if (-not $configPayload.bridges) {
                throw "The downloaded Tor bridge configuration is invalid."
            }
            [System.IO.File]::WriteAllText($tempConfig, $configText, (New-Object System.Text.UTF8Encoding($false)))
            Move-Item -LiteralPath $tempConfig -Destination $TorBridgePtConfigPath -Force
            $updated = $true
            Write-Info "Built-in bridge configuration updated from official Tor release $($Release.Version)."
        }
        catch {
            Write-Warn "Built-in bridge configuration update failed: $($_.Exception.Message)"
        }
    }
    if (-not $updated -and -not (Test-Path -LiteralPath $TorBridgePtConfigPath -PathType Leaf)) {
        Copy-Item -LiteralPath $BundledTorPtConfigPath -Destination $TorBridgePtConfigPath
    }
    return (Resolve-Path -LiteralPath $TorBridgePtConfigPath).Path
}

function Ensure-TorBridgeRuntime {
    if ($env:DARKWEB_TOR_BRIDGE_CHECK -eq "0") {
        return
    }

    $release = $null
    $projectRuntime = Get-InstalledProjectTorRuntime
    $needsUpdateCheck = -not $projectRuntime
    if ($projectRuntime -and $projectRuntime.CheckedAt) {
        try {
            $needsUpdateCheck = ([DateTime]::Parse($projectRuntime.CheckedAt).ToUniversalTime() -lt [DateTime]::UtcNow.AddDays(-1))
        }
        catch {
            $needsUpdateCheck = $true
        }
    }
    elseif ($projectRuntime) {
        $needsUpdateCheck = $true
    }
    if ($env:DARKWEB_TOR_BRIDGE_AUTO_INSTALL -ne "0" -and $needsUpdateCheck) {
        try {
            $release = Get-TorReleaseInfo
            $projectRuntime = Install-ProjectTorRuntime -Release $release
        }
        catch {
            Write-Warn "Tor Expert Bundle auto-install/update failed: $($_.Exception.Message)"
            $projectRuntime = Get-InstalledProjectTorRuntime
        }
    }
    if (-not $release -and $env:DARKWEB_TOR_BRIDGE_AUTO_UPDATE -ne "0" -and $needsUpdateCheck) {
        try {
            $release = Get-TorReleaseInfo
        }
        catch {
            Write-Warn "Could not check the current Tor release: $($_.Exception.Message)"
        }
    }
    $bridgeConfig = Update-ProjectTorBridgeConfig -Release $release
    Set-UserEnv -Name "DARKWEB_TOR_PT_CONFIG_PATH" -Value $bridgeConfig

    if ($projectRuntime) {
        $script:TorBridgeTorExecutable = $projectRuntime.TorExecutable
        $script:TorBridgeTransportExecutable = $projectRuntime.TransportExecutable
    }
    $torExecutable = Resolve-TorBridgeTorExecutable
    if (-not $torExecutable) {
        $script:TorBridgeTorExecutable = ""
        $script:TorBridgeTransportExecutable = ""
        Write-Warn "Tor bridge runtime is unavailable. The project could not install or recover its private Tor Expert Bundle."
        return
    }

    $script:TorBridgeTorExecutable = $torExecutable
    Set-Item -Path "Env:DARKWEB_TOR_EXECUTABLE" -Value $torExecutable
    Set-UserEnv -Name "DARKWEB_TOR_EXECUTABLE" -Value $torExecutable
    Add-ProcessPathEntry (Split-Path -Parent $torExecutable)

    $transportExecutable = Resolve-TorBridgeTransportExecutable -TorExecutable $torExecutable
    if (-not $transportExecutable) {
        $script:TorBridgeTransportExecutable = ""
        Write-Warn "Tor was found at $torExecutable, but no pluggable transport was found. Retry the project runtime update or set DARKWEB_TOR_TRANSPORT_EXECUTABLE."
        return
    }

    $script:TorBridgeTransportExecutable = $transportExecutable
    Set-Item -Path "Env:DARKWEB_TOR_TRANSPORT_EXECUTABLE" -Value $transportExecutable
    Set-UserEnv -Name "DARKWEB_TOR_TRANSPORT_EXECUTABLE" -Value $transportExecutable
    Add-ProcessPathEntry (Split-Path -Parent $transportExecutable)
    Write-Info "Tor bridge runtime detected: $torExecutable"
    Write-Info "Tor bridge transport detected: $transportExecutable"
}

function Install-WingetPackage {
    param(
        [string]$PackageId,
        [string]$DisplayName,
        [string]$Override = ""
    )
    $winget = Resolve-OptionalCommand "winget"
    if (-not $winget) {
        Stop-WithError "Missing '$DisplayName' and winget is unavailable. Install App Installer from Microsoft Store, or install $DisplayName manually and run darkweb again."
    }

    Write-Info "Installing $DisplayName with winget"
    $arguments = @(
        "install",
        "--id",
        $PackageId,
        "--exact",
        "--accept-package-agreements",
        "--accept-source-agreements"
    )
    if ($Override) {
        $arguments += @("--override", $Override)
    }
    & $winget @arguments
    if ($LASTEXITCODE -ne 0) {
        Stop-WithError "winget failed to install $DisplayName. Install it manually, reopen the terminal, and run darkweb again."
    }
    Update-ProcessPathFromRegistry
}

function Get-FileHashText {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        return ""
    }
    return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash
}

function Install-VerifiedZipRuntime {
    param(
        [string]$Label,
        [string]$Url,
        [string]$ExpectedHash,
        [ValidateSet("SHA256", "SHA512")]
        [string]$HashAlgorithm,
        [string]$TargetRoot,
        [string]$RequiredRelativePath,
        [string]$SourceArchivePath = "",
        [switch]$ForceRepair
    )

    $requiredPath = Join-Path $TargetRoot $RequiredRelativePath
    if (-not $ForceRepair -and (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
        return (Resolve-Path -LiteralPath $requiredPath).Path
    }
    if (-not [Environment]::Is64BitOperatingSystem) {
        Stop-WithError "$Label requires a 64-bit Windows operating system."
    }

    $stagingRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("darkweb-runtime-" + [Guid]::NewGuid().ToString("N"))
    $archivePath = Join-Path $stagingRoot "runtime.zip"
    $unpackRoot = Join-Path $stagingRoot "unpacked"
    $previousProgressPreference = $ProgressPreference
    try {
        $ProgressPreference = "SilentlyContinue"
        New-Item -ItemType Directory -Force -Path $stagingRoot,$unpackRoot | Out-Null
        if ($SourceArchivePath) {
            $sourcePath = [System.IO.Path]::GetFullPath($SourceArchivePath)
            if (-not (Test-Path -LiteralPath $sourcePath -PathType Leaf)) {
                Stop-WithError "$Label archive was not found: $sourcePath"
            }
            Copy-Item -LiteralPath $sourcePath -Destination $archivePath
        }
        else {
            Write-Info "Downloading $Label"
            Invoke-WebRequest -Uri $Url -OutFile $archivePath -UseBasicParsing -TimeoutSec 300
        }

        $actualHash = (Get-FileHash -LiteralPath $archivePath -Algorithm $HashAlgorithm).Hash.ToLowerInvariant()
        if ($actualHash -ne $ExpectedHash.ToLowerInvariant()) {
            Stop-WithError "$Label checksum verification failed."
        }
        Expand-Archive -LiteralPath $archivePath -DestinationPath $unpackRoot
        $unpackedRequiredPath = Join-Path $unpackRoot $RequiredRelativePath
        if (-not (Test-Path -LiteralPath $unpackedRequiredPath -PathType Leaf)) {
            Stop-WithError "$Label archive is missing $RequiredRelativePath."
        }

        Ensure-Directory (Split-Path -Parent $TargetRoot)
        if (Test-Path -LiteralPath $TargetRoot) {
            $invalidTarget = "$TargetRoot.invalid.$([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())"
            Move-Item -LiteralPath $TargetRoot -Destination $invalidTarget
            Write-Warn "Preserved incomplete $Label runtime at $invalidTarget"
        }
        Move-Item -LiteralPath $unpackRoot -Destination $TargetRoot
    }
    finally {
        $ProgressPreference = $previousProgressPreference
        if (Test-Path -LiteralPath $stagingRoot) {
            Remove-Item -LiteralPath $stagingRoot -Recurse -Force
        }
    }

    if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
        Stop-WithError "$Label installation did not produce $requiredPath."
    }
    return (Resolve-Path -LiteralPath $requiredPath).Path
}

function Save-GarnetRuntimeManifest {
    $payload = [ordered]@{
        provider = "garnet"
        version = $GarnetVersion
        archive_sha256 = $GarnetArchiveSha256
        server_executable_sha256 = $GarnetServerSha256
        dotnet_version = $GarnetDotnetVersion
        dotnet_archive_sha512 = $GarnetDotnetArchiveSha512
        dotnet_executable_sha256 = $GarnetDotnetExecutableSha256
        endpoint = $ManagedGarnetRedisUrl
        runtime_root = $GarnetRuntimeRoot
        dotnet_root = $GarnetDotnetRoot
        checkpoint_root = $GarnetCheckpointDir
        installed_at = [DateTime]::UtcNow.ToString("o")
    }
    Ensure-Directory (Split-Path -Parent $GarnetRuntimeManifest)
    $temporaryPath = "$GarnetRuntimeManifest.tmp"
    [System.IO.File]::WriteAllText(
        $temporaryPath,
        ($payload | ConvertTo-Json -Depth 4),
        (New-Object System.Text.UTF8Encoding($false))
    )
    Move-Item -LiteralPath $temporaryPath -Destination $GarnetRuntimeManifest -Force
}

function Resolve-ManagedGarnetRuntime {
    if (-not ((Test-Path -LiteralPath $GarnetServerExecutable -PathType Leaf) -and
        (Test-Path -LiteralPath $GarnetDotnetExecutable -PathType Leaf) -and
        (Test-Path -LiteralPath $GarnetRuntimeManifest -PathType Leaf))) {
        return $null
    }

    try {
        $manifest = Get-Content -LiteralPath $GarnetRuntimeManifest -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($manifest.provider -ne "garnet" -or
            $manifest.version -ne $GarnetVersion -or
            $manifest.archive_sha256 -ne $GarnetArchiveSha256 -or
            $manifest.server_executable_sha256 -ne $GarnetServerSha256 -or
            $manifest.dotnet_version -ne $GarnetDotnetVersion -or
            $manifest.dotnet_archive_sha512 -ne $GarnetDotnetArchiveSha512 -or
            $manifest.dotnet_executable_sha256 -ne $GarnetDotnetExecutableSha256) {
            return $null
        }
        if ((Get-FileHash -LiteralPath $GarnetServerExecutable -Algorithm SHA256).Hash.ToLowerInvariant() -ne $GarnetServerSha256 -or
            (Get-FileHash -LiteralPath $GarnetDotnetExecutable -Algorithm SHA256).Hash.ToLowerInvariant() -ne $GarnetDotnetExecutableSha256) {
            return $null
        }
    }
    catch {
        return $null
    }

    $previousDotnetRoot = [Environment]::GetEnvironmentVariable("DOTNET_ROOT", "Process")
    $previousDotnetRootX64 = [Environment]::GetEnvironmentVariable("DOTNET_ROOT_X64", "Process")
    $previousPath = $env:Path
    $runtimeValid = $false
    try {
        Set-Item -Path "Env:DOTNET_ROOT" -Value $GarnetDotnetRoot
        Set-Item -Path "Env:DOTNET_ROOT_X64" -Value $GarnetDotnetRoot
        Add-ProcessPathEntry $GarnetDotnetRoot
        & $GarnetServerExecutable --help *> $null
        $runtimeValid = $LASTEXITCODE -eq 0
    }
    catch {
        $runtimeValid = $false
    }
    finally {
        $env:Path = $previousPath
        if ($null -eq $previousDotnetRoot) { Remove-Item Env:DOTNET_ROOT -ErrorAction SilentlyContinue } else { Set-Item Env:DOTNET_ROOT -Value $previousDotnetRoot }
        if ($null -eq $previousDotnetRootX64) { Remove-Item Env:DOTNET_ROOT_X64 -ErrorAction SilentlyContinue } else { Set-Item Env:DOTNET_ROOT_X64 -Value $previousDotnetRootX64 }
    }
    if (-not $runtimeValid) {
        return $null
    }
    return [pscustomobject]@{
        ServerExecutable = (Resolve-Path -LiteralPath $GarnetServerExecutable).Path
        DotnetExecutable = (Resolve-Path -LiteralPath $GarnetDotnetExecutable).Path
        DataRoot = $GarnetDataRoot
        CheckpointDir = $GarnetCheckpointDir
    }
}

function Ensure-ManagedGarnetRuntime {
    $runtime = Resolve-ManagedGarnetRuntime
    if ($runtime) {
        return $runtime
    }
    if ($env:DARKWEB_GARNET_AUTO_INSTALL -eq "0") {
        Stop-WithError "Managed Garnet is missing and DARKWEB_GARNET_AUTO_INSTALL=0. Place the verified runtime under $GarnetRuntimeRoot and .NET under $GarnetDotnetRoot."
    }

    Install-VerifiedZipRuntime `
        -Label "Microsoft .NET Runtime $GarnetDotnetVersion" `
        -Url $GarnetDotnetArchiveUrl `
        -ExpectedHash $GarnetDotnetArchiveSha512 `
        -HashAlgorithm "SHA512" `
        -TargetRoot $GarnetDotnetRoot `
        -RequiredRelativePath "dotnet.exe" `
        -SourceArchivePath ([string]$env:DARKWEB_DOTNET_RUNTIME_ARCHIVE_PATH) `
        -ForceRepair | Out-Null
    Install-VerifiedZipRuntime `
        -Label "Microsoft Garnet $GarnetVersion" `
        -Url $GarnetArchiveUrl `
        -ExpectedHash $GarnetArchiveSha256 `
        -HashAlgorithm "SHA256" `
        -TargetRoot $GarnetRuntimeRoot `
        -RequiredRelativePath "net10.0\GarnetServer.exe" `
        -SourceArchivePath ([string]$env:DARKWEB_GARNET_ARCHIVE_PATH) `
        -ForceRepair | Out-Null

    Save-GarnetRuntimeManifest
    $runtime = Resolve-ManagedGarnetRuntime
    if (-not $runtime) {
        Stop-WithError "Microsoft Garnet was installed but could not run with the project-private .NET runtime."
    }
    Write-Info "Managed Garnet runtime ready: $GarnetServerExecutable"
    return $runtime
}

function Get-RedisEndpoint {
    $endpoint = [pscustomobject]@{
        Host = "127.0.0.1"
        Port = 6380
        IsLocal = $true
    }

    try {
        $uri = [Uri]$RedisUrl
        if ($uri.Host) {
            $endpoint.Host = $uri.Host
        }
        if ($uri.Port -gt 0) {
            $endpoint.Port = $uri.Port
        }
    }
    catch {
    }

    $localHosts = @("localhost", "127.0.0.1", "::1", "[::1]")
    $endpoint.IsLocal = $localHosts -contains $endpoint.Host.ToLowerInvariant()
    return $endpoint
}

function Test-RedisReady {
    $endpoint = Get-RedisEndpoint
    $redisCli = Resolve-OptionalCommandPath @("redis-cli.exe", "redis-cli")
    if ($redisCli) {
        try {
            $output = & $redisCli -u $RedisUrl ping 2>$null
            if ($LASTEXITCODE -eq 0 -and $output -match "PONG") {
                return $true
            }
        }
        catch {
        }
    }

    $client = $null
    try {
        $client = New-Object System.Net.Sockets.TcpClient
        $client.ReceiveTimeout = 1000
        $client.SendTimeout = 1000
        $async = $client.BeginConnect($endpoint.Host, $endpoint.Port, $null, $null)
        $waitHandle = $async.AsyncWaitHandle
        try {
            if (-not $waitHandle.WaitOne(1000, $false)) {
                return $false
            }
        }
        finally {
            $waitHandle.Close()
        }
        $client.EndConnect($async)
        $stream = $client.GetStream()
        $request = [Text.Encoding]::ASCII.GetBytes("*1`r`n`$4`r`nPING`r`n")
        $stream.Write($request, 0, $request.Length)
        $buffer = New-Object byte[] 64
        $responseBuilder = New-Object System.Text.StringBuilder
        while ($responseBuilder.Length -lt 1024) {
            $count = $stream.Read($buffer, 0, $buffer.Length)
            if ($count -le 0) {
                break
            }
            $null = $responseBuilder.Append([Text.Encoding]::ASCII.GetString($buffer, 0, $count))
            if ($responseBuilder.ToString().Contains("`r`n")) {
                break
            }
        }
        return $responseBuilder.ToString().StartsWith("+PONG`r`n", [StringComparison]::Ordinal)
    }
    catch {
        return $false
    }
    finally {
        if ($client) {
            $client.Dispose()
        }
    }
}

function Wait-ForRedis {
    param([int]$TimeoutSeconds)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        if (Test-RedisReady) {
            return $true
        }
        Start-Sleep -Seconds 1
    }
    return $false
}

function Wait-ForHttp {
    param(
        [string]$Url,
        [int]$TimeoutSeconds
    )
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        try {
            Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 2 | Out-Null
            return $true
        }
        catch {
            Start-Sleep -Seconds 1
        }
    }
    return $false
}

function Set-ApiPort {
    param([int]$Port)
    $script:ApiPort = $Port
    $script:ApiBaseUrl = "http://${script:ApiHost}:${script:ApiPort}"
    $script:ApiHealthUrl = "$script:ApiBaseUrl/api/health"
    $script:ApiJobsUrl = "$script:ApiBaseUrl/api/jobs"
}

function Set-FrontendPort {
    param([int]$Port)
    $script:FrontendPort = $Port
    $script:FrontendUrl = "http://${script:FrontendHost}:${script:FrontendPort}"
}

function Save-RuntimePorts {
    Ensure-Directory $RuntimeDir
    $payload = [pscustomobject]@{
        api_port = $ApiPort
        api_base_url = $ApiBaseUrl
        frontend_port = $FrontendPort
        frontend_url = $FrontendUrl
        updated_at = (Get-Date).ToString("s")
    } | ConvertTo-Json -Depth 3
    [IO.File]::WriteAllText($RuntimePortsFile, $payload + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
}

function Load-RuntimePorts {
    if (-not (Test-Path -LiteralPath $RuntimePortsFile)) {
        return
    }
    try {
        $ports = Get-Content -LiteralPath $RuntimePortsFile -Raw | ConvertFrom-Json
        if ($ports.api_port) {
            Set-ApiPort -Port ([int]$ports.api_port)
        }
        if ($ports.frontend_port) {
            Set-FrontendPort -Port ([int]$ports.frontend_port)
        }
    }
    catch {
        Write-Warn "Could not read runtime ports from ${RuntimePortsFile}: $($_.Exception.Message)"
    }
}

function Test-DarkwebApiReady {
    try {
        $payload = Invoke-RestMethod -Uri $ApiHealthUrl -TimeoutSec 3
        return ($payload.status -eq "ok")
    }
    catch {
        return $false
    }
}

function Test-DarkwebFrontendReady {
    try {
        $response = Invoke-WebRequest -Uri $FrontendUrl -UseBasicParsing -TimeoutSec 3
        $developmentEntryReady = $response.Content.Contains('/src/main.js')
        $previewEntryReady = [regex]::IsMatch(
            $response.Content,
            '<script\b[^>]*\bsrc="/assets/[^"]+\.js"'
        )
        $htmlReady = $response.Content.Contains($NewUiMarker) -and (
            $developmentEntryReady -or $previewEntryReady
        )
        if (-not $htmlReady) {
            return $false
        }
        return $true
    }
    catch {
        return $false
    }
}

function Wait-ForDarkwebApi {
    param([int]$TimeoutSeconds)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        if (Test-DarkwebApiReady) {
            return $true
        }
        Start-Sleep -Seconds 1
    }
    return $false
}

function Wait-ForDarkwebFrontend {
    param([int]$TimeoutSeconds)
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        if (Test-DarkwebFrontendReady) {
            return $true
        }
        Start-Sleep -Seconds 1
    }
    return $false
}

function Get-ListeningProcessIds {
    param([int]$Port)
    try {
        return @(Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction Stop |
            Select-Object -ExpandProperty OwningProcess -Unique)
    }
    catch {
        return @()
    }
}

function Test-PortBindable {
    param([int]$Port)
    $listener = $null
    try {
        $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Any, $Port)
        $listener.Server.ExclusiveAddressUse = $true
        $listener.Start()
        return $true
    }
    catch {
        return $false
    }
    finally {
        if ($listener) {
            try {
                $listener.Stop()
            }
            catch {
            }
        }
    }
}

function Test-PortAvailable {
    param([int]$Port)
    if (@(Get-ListeningProcessIds -Port $Port).Count -gt 0) {
        return $false
    }
    return (Test-PortBindable -Port $Port)
}

function Find-AvailablePort {
    param([int[]]$Candidates)
    foreach ($candidate in $Candidates) {
        if (Test-PortAvailable -Port $candidate) {
            return $candidate
        }
    }
    for ($port = 18000; $port -lt 18100; $port++) {
        if (Test-PortAvailable -Port $port) {
            return $port
        }
    }
    Stop-WithError "No available fallback port found in 18000-18099."
}

function Ensure-ApiPort {
    Stop-ProjectListenersOnPort -Port $ApiPort -Reason "required by darkweb collector API"
    Start-Sleep -Milliseconds 500
    if (Test-PortAvailable -Port $ApiPort) {
        return
    }

    $fallback = Find-AvailablePort -Candidates @(18000, 18001, 18002, 18003, 18004, 18005)
    Write-Warn "Port $ApiPort is occupied by a process that could not be stopped; using API port $fallback"
    Set-ApiPort -Port $fallback
}

function Ensure-FrontendPort {
    Stop-ProjectListenersOnPort -Port $FrontendPort -Reason "required by darkweb dashboard"
    Start-Sleep -Milliseconds 500
    if (Test-PortAvailable -Port $FrontendPort) {
        return
    }

    $fallback = Find-AvailablePort -Candidates @(5174, 5175, 5176, 5177, 5178, 5179)
    Write-Warn "Port $FrontendPort is occupied by a process that could not be stopped; using frontend port $fallback"
    Set-FrontendPort -Port $fallback
}

function Get-ServiceRecords {
    if (-not (Test-Path -LiteralPath $PidFile)) {
        return @()
    }
    $content = Get-Content -LiteralPath $PidFile -Raw
    if (-not $content.Trim()) {
        return @()
    }
    $records = $content | ConvertFrom-Json
    if ($records -is [array]) {
        return $records
    }
    return @($records)
}

function Test-ManagedServicesRunning {
    $requiredNames = @("api", "frontend", "worker-seed", "worker-detail", "scheduler", "vuln-sync")
    for ($index = 1; $index -le $BrowserPublicConcurrency; $index++) {
        $requiredNames += "worker-browser-public-$index"
    }
    for ($index = 1; $index -le $BrowserOnionConcurrency; $index++) {
        $requiredNames += "worker-browser-onion-$index"
    }
    $records = @(Get-ServiceRecords)
    if ($records | Where-Object { $_.name -eq "garnet" } | Select-Object -First 1) {
        $requiredNames += @("garnet", "garnet-checkpoint")
    }
    $processRows = @(Get-ProcessRows)
    $processRowMap = New-ProcessRowMap -ProcessRows $processRows
    foreach ($name in $requiredNames) {
        $record = $records | Where-Object { $_.name -eq $name } | Select-Object -First 1
        if (-not $record) {
            return $false
        }
        if (-not (Test-ServiceRecordOwnsProcess -Record $record -ProcessRows $processRows -ProcessRowMap $processRowMap)) {
            return $false
        }
    }
    return $true
}

function Test-DarkwebStackReady {
    Load-RuntimePorts
    if (-not (Test-ManagedServicesRunning)) {
        return $false
    }
    if (-not (Test-RedisReady)) {
        return $false
    }
    if (-not (Test-DarkwebApiReady)) {
        return $false
    }
    if (-not (Test-DarkwebFrontendReady)) {
        return $false
    }
    return $true
}

function Save-ServiceRecords {
    param([array]$Records)
    Ensure-Directory $RuntimeDir
    $Records | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $PidFile -Encoding UTF8
}

function Test-ProcessRunning {
    param([int]$ProcessId)
    return [bool](Get-Process -Id $ProcessId -ErrorAction SilentlyContinue)
}

function Get-ManagedGarnetProcesses {
    $records = @(Get-ServiceRecords | Where-Object { $_.name -eq "garnet" })
    $processRows = @(Get-ProcessRows)
    $processRowMap = New-ProcessRowMap -ProcessRows $processRows
    $managed = @()
    foreach ($process in @(Get-Process -Name "GarnetServer" -ErrorAction SilentlyContinue | Where-Object {
        $_.Path -and $_.Path.Equals($GarnetServerExecutable, [StringComparison]::OrdinalIgnoreCase)
    })) {
        $record = $records | Where-Object { [int]$_.pid -eq $process.Id } | Select-Object -First 1
        if ($record -and (Test-ServiceRecordOwnsProcess -Record $record -ProcessRows $processRows -ProcessRowMap $processRowMap)) {
            $managed += $process
            continue
        }
        if ($processRowMap.ContainsKey($process.Id) -and
            (Test-ProjectManagedCommandLine -CommandLine ([string]$processRowMap[$process.Id].CommandLine))) {
            $managed += $process
        }
    }
    return $managed
}

function Stop-ManagedGarnetProcesses {
    $processRows = @(Get-ProcessRows)
    $processRowMap = New-ProcessRowMap -ProcessRows $processRows
    foreach ($process in @(Get-ManagedGarnetProcesses)) {
        if ($processRowMap.ContainsKey($process.Id)) {
            Stop-ProcessTree -ProcessId $process.Id -ProcessRows $processRows -ProcessRowMap $processRowMap -Label "managed Garnet"
        }
    }
}

function Stop-ManagedProjectPythonProcesses {
    if (-not (Test-Path -LiteralPath $VenvPython -PathType Leaf)) {
        return
    }
    $processRows = @(Get-ProcessRows)
    $processRowMap = New-ProcessRowMap -ProcessRows $processRows
    foreach ($process in @(Get-Process -Name "python" -ErrorAction SilentlyContinue | Where-Object {
        $_.Path -and $_.Path.Equals($VenvPython, [StringComparison]::OrdinalIgnoreCase)
    })) {
        if ($processRowMap.ContainsKey($process.Id) -and
            (Test-ProjectManagedProcess -ProcessRow $processRowMap[$process.Id] -ProcessRowMap $processRowMap)) {
            Stop-ProcessTree -ProcessId $process.Id -ProcessRows $processRows -ProcessRowMap $processRowMap -Label "project Python"
        }
    }
}

function Test-ProcessUsesDashboardRuntime {
    param([object]$Process)
    if ($Process.Path -and (Test-PathUnderRoot -Path $Process.Path -Root $DashboardNodeModulesDir)) {
        return $true
    }
    try {
        foreach ($module in @($Process.Modules)) {
            if ($module.FileName -and (Test-PathUnderRoot -Path $module.FileName -Root $DashboardNodeModulesDir)) {
                return $true
            }
        }
    }
    catch {
    }
    return $false
}

function Stop-ManagedDashboardProcesses {
    $processRows = @(Get-ProcessRows)
    $processRowMap = New-ProcessRowMap -ProcessRows $processRows
    foreach ($process in @(Get-Process -ErrorAction SilentlyContinue | Where-Object {
        Test-ProcessUsesDashboardRuntime -Process $_
    })) {
        if ($processRowMap.ContainsKey($process.Id) -and
            (Test-ProjectManagedProcess -ProcessRow $processRowMap[$process.Id] -ProcessRowMap $processRowMap)) {
            Stop-ProcessTree -ProcessId $process.Id -ProcessRows $processRows -ProcessRowMap $processRowMap -Label "dashboard"
        }
    }
}

function Get-ProcessRows {
    try {
        return @(Get-CimInstance Win32_Process -ErrorAction Stop)
    }
    catch {
        return @(Get-WmiObject Win32_Process -ErrorAction Stop)
    }
}

function New-ProcessRowMap {
    param([object[]]$ProcessRows)
    $map = @{}
    foreach ($row in $ProcessRows) {
        if ($row -and $row.ProcessId) {
            $map[[int]$row.ProcessId] = $row
        }
    }
    return $map
}

function Test-ServiceRecordOwnsProcess {
    param(
        [object]$Record,
        [object[]]$ProcessRows,
        [hashtable]$ProcessRowMap
    )
    $processId = [int]$Record.pid
    $process = Get-Process -Id $processId -ErrorAction SilentlyContinue
    if (-not $process) {
        return $false
    }
    try {
        $recordStartedAt = [DateTime]::Parse([string]$Record.started_at)
        if ([Math]::Abs(($process.StartTime - $recordStartedAt).TotalSeconds) -gt 15) {
            return $false
        }
    }
    catch {
        return $false
    }

    if ($Record.name -eq "garnet") {
        if (-not ($process.Path -and $process.Path.Equals($GarnetServerExecutable, [StringComparison]::OrdinalIgnoreCase))) {
            return $false
        }
        if ($ProcessRowMap.ContainsKey($processId)) {
            return (Test-ProjectManagedCommandLine -CommandLine ([string]$ProcessRowMap[$processId].CommandLine))
        }
        return $true
    }

    if ($Record.name -eq "garnet-checkpoint") {
        if ($ProcessRowMap.ContainsKey($processId) -and $ProcessRowMap[$processId].CommandLine) {
            return (Test-ProjectManagedCommandLine -CommandLine ([string]$ProcessRowMap[$processId].CommandLine))
        }
        return $process.ProcessName -in @("powershell", "pwsh")
    }

    if (-not $ProcessRowMap.ContainsKey($processId)) {
        return $false
    }
    return (Test-ProjectManagedProcess -ProcessRow $ProcessRowMap[$processId] -ProcessRowMap $ProcessRowMap)
}

function Get-ProcessRowCreatedAt {
    param([object]$ProcessRow)
    if ($null -eq $ProcessRow -or -not $ProcessRow.CreationDate) {
        throw "Cannot verify process creation time."
    }
    try {
        if ($ProcessRow.CreationDate -is [DateTime]) {
            return $ProcessRow.CreationDate.ToUniversalTime()
        }
        return [System.Management.ManagementDateTimeConverter]::ToDateTime([string]$ProcessRow.CreationDate).ToUniversalTime()
    }
    catch {
        throw "Cannot verify process creation time for pid $($ProcessRow.ProcessId)."
    }
}

function Get-ProtectedUpdateProcessIds {
    param([object[]]$ProcessRows, [hashtable]$ProcessRowMap)
    $protected = New-Object "System.Collections.Generic.HashSet[int]"
    $null = $protected.Add($PID)
    foreach ($row in $ProcessRows) {
        if ($row.CommandLine -like "*run_self_update.py*") {
            $null = $protected.Add([int]$row.ProcessId)
        }
    }
    if ($env:DARKWEB_UPDATE_CONTROLLER_PID -or $env:DARKWEB_UPDATE_CONTROLLER_CREATE_TIME) {
        $controllerId = 0
        $controllerBirth = 0.0
        if (-not [int]::TryParse($env:DARKWEB_UPDATE_CONTROLLER_PID, [ref]$controllerId) -or
            -not [double]::TryParse($env:DARKWEB_UPDATE_CONTROLLER_CREATE_TIME, [Globalization.NumberStyles]::Float, [Globalization.CultureInfo]::InvariantCulture, [ref]$controllerBirth)) {
            throw "Invalid update controller identity."
        }
        if ($ProcessRowMap.ContainsKey($controllerId)) {
            $epoch = [DateTime]::SpecifyKind([DateTime]'1970-01-01', [DateTimeKind]::Utc)
            $created = Get-ProcessRowCreatedAt -ProcessRow $ProcessRowMap[$controllerId]
            if ([Math]::Abs(($created - $epoch).TotalSeconds - $controllerBirth) -le 0.001) {
                $null = $protected.Add($controllerId)
            }
        }
    }
    # A venv redirector owns its real Python child; preserve both, not worker descendants.
    foreach ($controllerId in @($protected)) {
        if ($controllerId -eq $PID -or -not $ProcessRowMap.ContainsKey($controllerId)) { continue }
        $row = $ProcessRowMap[$controllerId]
        $parentId = [int]$row.ParentProcessId
        if ($ProcessRowMap.ContainsKey($parentId)) {
            $parent = $ProcessRowMap[$parentId]
            if ($parent.ExecutablePath -match '\\Scripts\\pythonw?\.exe$' -and
                (Get-ProcessRowCreatedAt $parent) -le (Get-ProcessRowCreatedAt $row)) {
                $null = $protected.Add($parentId)
            }
        }
        if ($row.ExecutablePath -match '\\Scripts\\pythonw?\.exe$') {
            foreach ($child in $ProcessRows) {
                if ([int]$child.ParentProcessId -eq $controllerId -and $child.ExecutablePath -match '\\pythonw?\.exe$' -and
                    (Get-ProcessRowCreatedAt $child) -ge (Get-ProcessRowCreatedAt $row)) {
                    $null = $protected.Add([int]$child.ProcessId)
                }
            }
        }
    }
    # Keep the calling stop/forwarding chain, stopping before the managed API ancestor.
    $seen = New-Object "System.Collections.Generic.HashSet[int]"
    $caller = if ($ProcessRowMap.ContainsKey($PID)) { $ProcessRowMap[$PID] } else { $null }
    $parentId = if ($caller) { [int]$caller.ParentProcessId } else { 0 }
    while ($parentId -gt 0 -and $seen.Add($parentId) -and $ProcessRowMap.ContainsKey($parentId)) {
        $parent = $ProcessRowMap[$parentId]
        if ((Get-ProcessRowCreatedAt $parent) -gt (Get-ProcessRowCreatedAt $caller)) { break }
        if ((Test-ProjectManagedCommandLine $parent.CommandLine) -and -not $protected.Contains($parentId)) { break }
        $null = $protected.Add($parentId)
        $caller = $parent
        $parentId = [int]$parent.ParentProcessId
    }
    return ,$protected
}

function Get-CurrentProcessForRow {
    param([object]$ProcessRow)
    $created = Get-ProcessRowCreatedAt -ProcessRow $ProcessRow
    try {
        $process = Get-Process -Id ([int]$ProcessRow.ProcessId) -ErrorAction Stop
    }
    catch {
        if ($_.CategoryInfo.Category -eq [Management.Automation.ErrorCategory]::ObjectNotFound) { return $null }
        throw "Cannot inspect process pid $($ProcessRow.ProcessId)."
    }
    try {
        $null = $process.Handle
        if ($process.HasExited -or [Math]::Abs(($process.StartTime.ToUniversalTime() - $created).TotalMilliseconds) -gt 1) {
            $process.Dispose()
            return $null
        }
        return $process
    }
    catch {
        $process.Dispose()
        throw "Cannot verify process identity for pid $($ProcessRow.ProcessId)."
    }
}

function Stop-ProcessTree {
    param(
        [int]$ProcessId,
        [object[]]$ProcessRows = $null,
        [hashtable]$ProcessRowMap = $null,
        [string]$Label = "process",
        [System.Collections.Generic.HashSet[int]]$ProtectedProcessIds = $null
    )
    if (-not $ProcessId -or $ProcessId -eq $PID) {
        return
    }
    if ($null -eq $ProcessRows) {
        $ProcessRows = @(Get-ProcessRows)
    }
    if ($null -eq $ProcessRowMap) {
        $ProcessRowMap = New-ProcessRowMap -ProcessRows $ProcessRows
    }
    if ($null -eq $ProtectedProcessIds) {
        $ProtectedProcessIds = Get-ProtectedUpdateProcessIds -ProcessRows $ProcessRows -ProcessRowMap $ProcessRowMap
    }
    if ($ProtectedProcessIds.Contains($ProcessId)) {
        Write-Info "Preserving active update controller pid $ProcessId"
        return
    }
    if (-not $ProcessRowMap.ContainsKey($ProcessId)) { return }
    $row = $ProcessRowMap[$ProcessId]
    $created = Get-ProcessRowCreatedAt -ProcessRow $row
    $children = @($ProcessRows | Where-Object {
        [int]$_.ParentProcessId -eq $ProcessId -and (Get-ProcessRowCreatedAt $_) -ge $created
    })
    foreach ($child in $children) {
        Stop-ProcessTree -ProcessId ([int]$child.ProcessId) -ProcessRows $ProcessRows -ProcessRowMap $ProcessRowMap -Label "child process" -ProtectedProcessIds $ProtectedProcessIds
    }
    $process = Get-CurrentProcessForRow -ProcessRow $row
    if ($null -eq $process) { return }
    try {
        Write-Info "Stopping $Label pid $ProcessId"
        try { $process.Kill() }
        catch { if (-not $process.HasExited) { throw } }
        if (-not $process.WaitForExit(1000)) {
            throw "Process pid $ProcessId did not exit after targeted stop."
        }
    }
    finally { $process.Dispose() }
}

function Test-ProjectManagedCommandLine {
    param([string]$CommandLine)
    if (-not $CommandLine) {
        return $false
    }

    if ($CommandLine.IndexOf($GarnetServerExecutable, [StringComparison]::OrdinalIgnoreCase) -ge 0 -and
        $CommandLine.IndexOf($GarnetCheckpointDir, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
        return $true
    }

    $projectProcessPattern = [regex]::Escape($ProjectRoot)
    if ($CommandLine -notmatch $projectProcessPattern) {
        return $false
    }

    $markers = @(
        "serve_api.py",
        "crawl.py",
        "darkweb_collector.celery_app",
        "darkweb_collector.worker_supervisor",
        "celery",
        "node_modules\.bin",
        "vite\bin\vite.js",
        "npm-cli.js",
        "npm run dev",
        "DARKWEB_GARNET_CHECKPOINT_LOOP"
    )
    return [bool]($markers | Where-Object { $CommandLine -like "*$_*" } | Select-Object -First 1)
}

function Test-ProjectManagedProcess {
    param(
        [object]$ProcessRow,
        [hashtable]$ProcessRowMap
    )
    if ($null -eq $ProcessRow) {
        return $false
    }
    if ($null -eq $ProcessRowMap) {
        $ProcessRowMap = New-ProcessRowMap -ProcessRows @($ProcessRow)
    }
    $protected = Get-ProtectedUpdateProcessIds -ProcessRows @($ProcessRowMap.Values) -ProcessRowMap $ProcessRowMap
    if ($protected.Contains([int]$ProcessRow.ProcessId)) {
        return $false
    }
    if (Test-ProjectManagedCommandLine -CommandLine $ProcessRow.CommandLine) {
        return $true
    }

    $seen = New-Object "System.Collections.Generic.HashSet[int]"
    $child = $ProcessRow
    $parentId = [int]$ProcessRow.ParentProcessId
    while ($parentId -gt 0 -and $seen.Add($parentId)) {
        if ($null -eq $ProcessRowMap -or -not $ProcessRowMap.ContainsKey($parentId)) {
            break
        }
        $parent = $ProcessRowMap[$parentId]
        if ($null -eq $parent) {
            break
        }
        if ((Get-ProcessRowCreatedAt $parent) -gt (Get-ProcessRowCreatedAt $child)) {
            break
        }
        if (Test-ProjectManagedCommandLine -CommandLine $parent.CommandLine) {
            return $true
        }
        $child = $parent
        $parentId = [int]$parent.ParentProcessId
    }

    return $false
}

function Get-ProjectManagedProcessRows {
    param(
        [object[]]$ProcessRows,
        [hashtable]$ProcessRowMap
    )
    $candidateIds = New-Object "System.Collections.Generic.HashSet[int]"
    $protected = Get-ProtectedUpdateProcessIds -ProcessRows $ProcessRows -ProcessRowMap $ProcessRowMap
    foreach ($row in $ProcessRows) {
        if ($row -and -not $protected.Contains([int]$row.ProcessId) -and (Test-ProjectManagedCommandLine -CommandLine $row.CommandLine)) {
            $null = $candidateIds.Add([int]$row.ProcessId)
            $parentId = [int]$row.ParentProcessId
            if ($parentId -gt 0 -and $ProcessRowMap.ContainsKey($parentId) -and -not $protected.Contains($parentId) -and
                (Get-ProcessRowCreatedAt $ProcessRowMap[$parentId]) -le (Get-ProcessRowCreatedAt $row)) {
                $null = $candidateIds.Add($parentId)
            }
        }
    }

    foreach ($processId in $candidateIds) {
        if ($ProcessRowMap.ContainsKey($processId)) {
            $ProcessRowMap[$processId]
        }
    }
}

function Stop-ProjectListenersOnPort {
    param(
        [int]$Port,
        [string]$Reason
    )
    $processRows = @(Get-ProcessRows)
    $processRowMap = New-ProcessRowMap -ProcessRows $processRows
    foreach ($processId in Get-ListeningProcessIds -Port $Port) {
        if (-not $processId -or $processId -eq $PID) {
            continue
        }
        $processRow = if ($processRowMap.ContainsKey([int]$processId)) { $processRowMap[[int]$processId] } else { $null }
        if (Test-ProjectManagedProcess -ProcessRow $processRow -ProcessRowMap $processRowMap) {
            Write-Warn "Stopping project process $processId listening on port $Port ($Reason)"
            Stop-ProcessTree -ProcessId ([int]$processId) -ProcessRows $processRows -ProcessRowMap $processRowMap -Label "port $Port listener"
        }
    }
}

function New-ServiceCommand {
    param(
        [string]$WorkingDirectory,
        [string]$Body,
        [string]$LogPath
    )

    $quotedWorkDir = Quote-PS $WorkingDirectory
    $quotedLog = Quote-PS $LogPath
    $postgresqlDataDirectory = Get-PostgreSqlDataDirectory
    return @"
`$ErrorActionPreference = 'Continue'
Remove-Item Env:DARKWEB_UPDATE_CONTROLLER_PID, Env:DARKWEB_UPDATE_CONTROLLER_CREATE_TIME -ErrorAction SilentlyContinue
Set-Location -LiteralPath $quotedWorkDir
`$env:Path = $(Quote-PS $env:Path)
`$env:REDIS_URL = $(Quote-PS $RedisUrl)
`$env:DARKWEB_API_HOST = '0.0.0.0'
`$env:DARKWEB_API_PORT = $(Quote-PS ([string]$ApiPort))
`$env:DARKWEB_API_TARGET = $(Quote-PS $ApiBaseUrl)
`$env:VITE_API_TARGET = $(Quote-PS $ApiBaseUrl)
`$env:DARKWEB_FRONTEND_PORT = $(Quote-PS ([string]$FrontendPort))
`$env:DARKWEB_FRONTEND_URL = $(Quote-PS $FrontendUrl)
`$env:VITE_FRONTEND_PORT = $(Quote-PS ([string]$FrontendPort))
`$env:PYTHONPATH = $(Quote-PS (Join-Path $CollectorRoot "src"))
`$env:DARKWEB_DATA_ROOT = $(Quote-PS $DefaultUserDataDir)
`$env:DARKWEB_USER_DATA_ROOT = $(Quote-PS $DefaultUserDataDir)
`$env:DARKWEB_APP_ROOT = $(Quote-PS $AppRoot)
`$env:DARKWEB_UPDATE_STATE_DIR = $(Quote-PS $UpdateStateRoot)
`$env:PLAYWRIGHT_BROWSERS_PATH = $(Quote-PS $PlaywrightBrowsersRoot)
`$env:DARKWEB_MIGRATION_ROOT = $(Quote-PS $MigrationRoot)
`$env:DARKWEB_POSTGRESQL_DATA_DIRECTORY = $(Quote-PS $postgresqlDataDirectory)
`$env:DARKWEB_COLLECTOR_DB_PATH = $(Quote-PS $CollectorDbPath)
`$env:DARKWEB_COLLECTOR_SITES_FILE = $(Quote-PS $CollectorSitesFile)
`$env:DARKWEB_COLLECTOR_OUTPUT_ROOT = $(Quote-PS $CollectorOutputRoot)
`$env:DARKWEB_ACTIVE_RELEASE_FILE = $(Quote-PS $ActiveReleaseFile)
`$env:DARKWEB_AUTH_PASSWORD_FILE = $(Quote-PS $AuthPasswordFile)
`$env:DARKWEB_GARNET_DATA_ROOT = $(Quote-PS $GarnetDataRoot)
`$env:DARKWEB_TOR_EXPERT_DIR = $(Quote-PS $TorExpertRoot)
`$env:DARKWEB_TOR_EXECUTABLE = $(Quote-PS $script:TorBridgeTorExecutable)
`$env:DARKWEB_TOR_TRANSPORT_EXECUTABLE = $(Quote-PS $script:TorBridgeTransportExecutable)
`$env:DARKWEB_BROWSER_CONCURRENCY = $(Quote-PS ([string]$BrowserConcurrency))
`$env:DARKWEB_BROWSER_PUBLIC_CONCURRENCY = $(Quote-PS ([string]$BrowserPublicConcurrency))
`$env:DARKWEB_BROWSER_ONION_CONCURRENCY = $(Quote-PS ([string]$BrowserOnionConcurrency))
`$env:NPM_CONFIG_CACHE = $(Quote-PS (Join-Path $DefaultUserDataDir "npm-cache"))
$Body *>> $quotedLog
"@
}

function Start-ManagedProcess {
    param(
        [string]$Name,
        [string]$WorkingDirectory,
        [string]$Body
    )

    $powerShell = Resolve-PowerShellCommand
    $logPath = Join-Path $LogDir "$Name.log"
    if (Test-Path -LiteralPath $logPath) {
        try {
            Remove-Item -LiteralPath $logPath -Force -ErrorAction Stop
        }
        catch {
            $stamp = Get-Date -Format "yyyyMMdd-HHmmss"
            $logPath = Join-Path $LogDir "$Name-$stamp.log"
            Write-Warn "Log file $Name.log is locked; using $([System.IO.Path]::GetFileName($logPath))"
        }
    }
    $command = New-ServiceCommand -WorkingDirectory $WorkingDirectory -Body $Body -LogPath $logPath
    $process = Start-Process -FilePath $powerShell -ArgumentList @(
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        $command
    ) -WindowStyle Hidden -PassThru

    return [pscustomobject]@{
        name = $Name
        pid = $process.Id
        log = $logPath
        started_at = (Get-Date).ToString("s")
    }
}

function Get-GarnetLimitedCpuMask {
    param([long]$OriginalMask)
    $bits = @()
    for ($index = 0; $index -lt 64; $index++) {
        $bit = [long]1 -shl $index
        if (($OriginalMask -band $bit) -ne 0) { $bits += $bit }
    }
    if ($bits.Count -eq 0) { throw "Garnet has no processors available in its affinity mask." }
    $count = [int][Math]::Max(1, [Math]::Floor($bits.Count / 2.0))
    $mask = [long]0
    foreach ($bit in @($bits | Select-Object -Last $count)) { $mask = $mask -bor $bit }
    return [pscustomobject]@{ Mask = $mask; OriginalCount = $bits.Count; SelectedCount = $count }
}

function Set-ManagedGarnetCpuLimit {
    param([Diagnostics.Process]$Process, [string]$ExpectedExecutable)
    if ([IntPtr]::Size -ne 8) { throw "Garnet CPU scheduling requires 64-bit PowerShell." }
    if (-not ("DarkwebGarnetCpuTopology" -as [type])) {
        Add-Type -TypeDefinition @'
using System.Runtime.InteropServices;
public static class DarkwebGarnetCpuTopology {
    [DllImport("kernel32.dll")] public static extern ushort GetActiveProcessorGroupCount();
}
'@
    }
    $processorGroups = [DarkwebGarnetCpuTopology]::GetActiveProcessorGroupCount()
    if ($processorGroups -eq 0) { throw "Could not determine active processor groups for Garnet CPU scheduling." }
    if ($processorGroups -ne 1) {
        throw "Garnet CPU scheduling supports one active processor group with 1-64 logical processors. Multiple processor groups require an explicit group-aware policy."
    }
    $null = $Process.Handle
    $identityWait = [Diagnostics.Stopwatch]::StartNew()
    do {
        $Process.Refresh()
        if ($Process.HasExited) { throw "Garnet exited before CPU scheduling could be applied." }
        $processPath = [string]$Process.Path
        if ($processPath) { break }
        if ($identityWait.ElapsedMilliseconds -ge 1000) { throw "Could not verify the newly started Garnet executable." }
        Start-Sleep -Milliseconds 10
    } while ($true)
    if (-not $processPath.Equals($ExpectedExecutable, [StringComparison]::OrdinalIgnoreCase)) {
        throw "The process is not the running project-owned Garnet executable."
    }
    $startTicks = $Process.StartTime.ToUniversalTime().Ticks.ToString()
    $previousMask = $Process.ProcessorAffinity.ToInt64()
    $previousPriority = $Process.PriorityClass
    $stateRoot = Join-Path $DefaultUserDataDir "diagnostics\garnet-cpu"
    $statePath = Join-Path $stateRoot "garnet-$($Process.Id)-$startTicks.json"
    if (Test-Path -LiteralPath $statePath -PathType Leaf) {
        $state = Get-Content -LiteralPath $statePath -Raw -Encoding UTF8 | ConvertFrom-Json
        if ([int]$state.process_id -ne $Process.Id -or [string]$state.start_ticks -ne $startTicks -or
            -not ([string]$state.executable_path).Equals($ExpectedExecutable, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Saved CPU settings do not belong to this Garnet process."
        }
    }
    else {
        $state = [pscustomobject]@{
            process_id = $Process.Id; start_ticks = $startTicks; executable_path = $ExpectedExecutable
            original_affinity = $previousMask.ToString(); original_priority = [string]$previousPriority
        }
        Ensure-Directory $stateRoot
        $state | ConvertTo-Json | Set-Content -LiteralPath $statePath -Encoding UTF8 -ErrorAction Stop
    }
    # Reuse the original mask for this process, including settings saved by control-garnet-cpu.ps1.
    $limit = Get-GarnetLimitedCpuMask ([long]$state.original_affinity)
    try {
        $Process.ProcessorAffinity = [IntPtr]$limit.Mask
        $Process.PriorityClass = [Diagnostics.ProcessPriorityClass]::BelowNormal
        $Process.Refresh()
        if ($Process.HasExited -or $Process.StartTime.ToUniversalTime().Ticks.ToString() -ne $startTicks -or
            $Process.ProcessorAffinity.ToInt64() -ne $limit.Mask -or
            $Process.PriorityClass -ne [Diagnostics.ProcessPriorityClass]::BelowNormal) {
            throw "Windows did not apply the requested Garnet CPU settings."
        }
    }
    catch {
        try {
            if (-not $Process.HasExited -and $Process.StartTime.ToUniversalTime().Ticks.ToString() -eq $startTicks) {
                $Process.ProcessorAffinity = [IntPtr]$previousMask
                $Process.PriorityClass = $previousPriority
            }
        }
        catch { Write-Warn "Could not restore Garnet scheduling after a failed CPU limit operation." }
        throw
    }
    Write-Info "Garnet CPU scheduling: $($limit.OriginalCount) -> $($limit.SelectedCount) allowed logical processors; priority BelowNormal."
    if ($limit.OriginalCount -eq 1) { Write-Warn "Only one logical processor is available; affinity cannot reduce CPU capacity further." }
}

function Start-ManagedGarnetProcess {
    param(
        [object]$Runtime,
        [int]$Port
    )

    Ensure-Directory $LogDir
    $logPath = Join-Path $LogDir "garnet.log"
    $errorLogPath = Join-Path $LogDir "garnet-error.log"
    foreach ($path in @($logPath, $errorLogPath)) {
        if (Test-Path -LiteralPath $path) {
            Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
        }
    }

    $arguments = @(
        "--port", [string]$Port,
        "--bind", "127.0.0.1",
        "--memory", "256m",
        "--page", "4m",
        "--segment", "64m",
        "--aof",
        "--aof-commit-wait",
        "--checkpointdir", ('"{0}"' -f [string]$Runtime.CheckpointDir),
        "--recover",
        "--fail-on-recovery-error",
        "--lua",
        "--logger-level", "Information"
    )

    $previousDotnetRoot = [Environment]::GetEnvironmentVariable("DOTNET_ROOT", "Process")
    $previousDotnetRootX64 = [Environment]::GetEnvironmentVariable("DOTNET_ROOT_X64", "Process")
    $previousPath = $env:Path
    $process = $null
    try {
        Set-Item -Path "Env:DOTNET_ROOT" -Value $GarnetDotnetRoot
        Set-Item -Path "Env:DOTNET_ROOT_X64" -Value $GarnetDotnetRoot
        Add-ProcessPathEntry $GarnetDotnetRoot
        $process = Start-Process `
            -FilePath $Runtime.ServerExecutable `
            -ArgumentList $arguments `
            -WorkingDirectory $Runtime.DataRoot `
            -RedirectStandardOutput $logPath `
            -RedirectStandardError $errorLogPath `
            -WindowStyle Hidden `
            -PassThru
        Set-ManagedGarnetCpuLimit -Process $process -ExpectedExecutable $Runtime.ServerExecutable
    }
    catch {
        if ($process -and -not $process.HasExited) {
            $process.Kill()
            if (-not $process.WaitForExit(5000)) { throw "Garnet CPU scheduling failed and its new process did not stop." }
        }
        throw
    }
    finally {
        $env:Path = $previousPath
        if ($null -eq $previousDotnetRoot) { Remove-Item Env:DOTNET_ROOT -ErrorAction SilentlyContinue } else { Set-Item Env:DOTNET_ROOT -Value $previousDotnetRoot }
        if ($null -eq $previousDotnetRootX64) { Remove-Item Env:DOTNET_ROOT_X64 -ErrorAction SilentlyContinue } else { Set-Item Env:DOTNET_ROOT_X64 -Value $previousDotnetRootX64 }
    }

    return [pscustomobject]@{
        name = "garnet"
        pid = $process.Id
        log = $logPath
        error_log = $errorLogPath
        started_at = (Get-Date).ToString("s")
    }
}

function Ensure-PythonRuntime {
    $python = Resolve-PythonExe
    if ($python) {
        return $python
    }

    Install-WingetPackage -PackageId "Python.Python.3.12" -DisplayName "Python 3.12" -Override "InstallAllUsers=0 PrependPath=1 Include_launcher=1 Include_pip=1"
    $python = Resolve-PythonExe
    if (-not $python) {
        Stop-WithError "Python was installed but python.exe is still not available. Reopen the terminal and run darkweb again."
    }
    return $python
}

function Test-PythonExe {
    param([string]$PythonPath)
    if (-not $PythonPath) {
        return $false
    }
    try {
        & $PythonPath -c "import sys, venv, ensurepip; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)" *> $null
        return ($LASTEXITCODE -eq 0)
    }
    catch {
        return $false
    }
}

function Resolve-PythonExe {
    $python = Resolve-WorkingCommand -Names @("python.exe", "python") -Arguments @("-c", "import sys, venv, ensurepip; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)")
    if ($python) {
        return $python
    }

    $candidates = @()
    $roots = @(
        (Join-Path $env:LOCALAPPDATA "Programs\Python"),
        ([Environment]::GetEnvironmentVariable("ProgramFiles")),
        ([Environment]::GetEnvironmentVariable("ProgramFiles(x86)"))
    )
    foreach ($root in $roots) {
        if ($root -and (Test-Path -LiteralPath $root)) {
            $candidates += @(Get-ChildItem -LiteralPath $root -Filter "Python3*" -Directory -ErrorAction SilentlyContinue |
                Sort-Object Name -Descending |
                ForEach-Object { Join-Path $_.FullName "python.exe" })
        }
    }
    foreach ($candidate in $candidates | Select-Object -Unique) {
        if ((Test-Path -LiteralPath $candidate) -and (Test-PythonExe $candidate)) {
            return $candidate
        }
    }

    $pyLauncher = Resolve-OptionalCommandPath @("py.exe", "py")
    if ($pyLauncher) {
        try {
            $resolved = & $pyLauncher -3 -c "import sys, venv, ensurepip; print(sys.executable)" 2>$null
            if ($LASTEXITCODE -eq 0 -and $resolved -and (Test-Path -LiteralPath $resolved.Trim()) -and (Test-PythonExe $resolved.Trim())) {
                return $resolved.Trim()
            }
        }
        catch {
        }
    }
    return $null
}

function Resolve-NodeExe {
    $node = Resolve-WorkingCommand -Names @("node.exe", "node") -Arguments @("--version")
    if ($node) {
        return $node
    }

    $programFiles = [Environment]::GetEnvironmentVariable("ProgramFiles")
    $programFilesX86 = [Environment]::GetEnvironmentVariable("ProgramFiles(x86)")
    $programW6432 = [Environment]::GetEnvironmentVariable("ProgramW6432")
    $candidates = @()
    foreach ($root in @($programFiles, $programW6432, $programFilesX86)) {
        if ($root) {
            $candidates += (Join-Path $root "nodejs\node.exe")
        }
    }
    $localPrograms = Join-Path $LocalAppDataRoot "Programs"
    $candidates += (Join-Path $localPrograms "nodejs\node.exe")

    foreach ($candidate in $candidates | Select-Object -Unique) {
        if ((Test-Path -LiteralPath $candidate)) {
            & $candidate --version *> $null
            if ($LASTEXITCODE -eq 0) {
                return $candidate
            }
        }
    }
    return $null
}

function Ensure-NodeRuntime {
    $script:NodeExePath = ""
    $script:NodeBinDir = ""
    $node = Resolve-NodeExe
    if (-not $node) {
        Install-WingetPackage -PackageId "OpenJS.NodeJS.LTS" -DisplayName "Node.js LTS"
        $node = Resolve-NodeExe
    }
    if (-not $node) {
        Stop-WithError "Node.js was installed but node.exe is still not available. Reopen the terminal and run darkweb again."
    }

    $nodeDir = Split-Path -Parent $node
    $script:NodeExePath = $node
    $script:NodeBinDir = $nodeDir
    Add-ProcessPathEntry $nodeDir
    Add-UserPathEntry $nodeDir

    & $node -e "const major = Number(process.versions.node.split('.')[0]); process.exit(major >= 18 ? 0 : 1)" *> $null
    if ($LASTEXITCODE -ne 0) {
        Stop-WithError "Node.js at $node is too old or cannot run. Install Node.js 18 LTS or newer."
    }

    $npm = Join-Path $nodeDir "npm.cmd"
    if (-not (Test-Path -LiteralPath $npm)) {
        $npm = Resolve-WorkingCommand -Names @("npm.cmd", "npm") -Arguments @("--version")
    }
    if (-not $npm) {
        Stop-WithError "Node.js is available at $node, but npm.cmd was not found. Reinstall Node.js LTS and run darkweb again."
    }
    & $npm --version *> $null
    if ($LASTEXITCODE -ne 0) {
        Stop-WithError "npm.cmd exists at $npm, but it cannot run correctly."
    }
    return $npm
}

function Ensure-RedisRuntime {
    if (Test-RedisReady) {
        if ($RedisUrl -eq $LegacyManagedRedisUrl -and (Test-ProjectOwnedRedisEnvironment)) {
            Write-Info "Migrating the project-owned legacy Redis endpoint to managed Garnet."
            $script:RedisUrl = $ManagedGarnetRedisUrl
            Set-Item -Path "Env:REDIS_URL" -Value $ManagedGarnetRedisUrl
        }
        else {
            if (@((Get-ManagedGarnetProcesses)).Count -gt 0) {
                $script:RedisProvider = "garnet"
            }
            return
        }
    }
    $endpoint = Get-RedisEndpoint
    if (-not $endpoint.IsLocal) {
        Stop-WithError "REDIS_URL points to $RedisUrl, but it is not reachable. Start that Redis instance or change REDIS_URL."
    }
    if ($RedisUrl -eq $LegacyManagedRedisUrl) {
        if (-not (Test-ProjectOwnedRedisEnvironment)) {
            Stop-WithError "Configured REDIS_URL $LegacyManagedRedisUrl is not reachable. It was not marked as project-managed, so it will not be replaced automatically."
        }
        Write-Info "Legacy Redis endpoint $LegacyManagedRedisUrl is unavailable; switching to managed Garnet."
        $script:RedisUrl = $ManagedGarnetRedisUrl
        Set-Item -Path "Env:REDIS_URL" -Value $ManagedGarnetRedisUrl
    }
    elseif ($RedisUrl -ne $ManagedGarnetRedisUrl) {
        Stop-WithError "Configured REDIS_URL $RedisUrl is not reachable. The project only auto-manages Garnet at $ManagedGarnetRedisUrl."
    }

    Ensure-ManagedGarnetRuntime | Out-Null
    $script:RedisProvider = "garnet"
}

function Register-DarkwebCommand {
    if ($Action -eq "register") {
        Load-RuntimePorts
    }
    Ensure-Directory $CommandBinDir
    $commandText = @"
@echo off
set "COLLECTOR_ROOT=%DARKWEB_COLLECTOR_ROOT%"
if "%COLLECTOR_ROOT%"=="" set "COLLECTOR_ROOT=$CollectorRoot"
set "DARKWEB_API_PORT=$ApiPort"
set "DARKWEB_API_TARGET=$ApiBaseUrl"
set "VITE_API_TARGET=$ApiBaseUrl"
set "DARKWEB_FRONTEND_PORT=$FrontendPort"
set "DARKWEB_FRONTEND_URL=$FrontendUrl"
set "VITE_FRONTEND_PORT=$FrontendPort"
if not exist "%COLLECTOR_ROOT%\scripts\start_all_services_windows.ps1" (
  echo [ERROR] DARKWEB_COLLECTOR_ROOT is not valid. Run .\darkweb.cmd register from the project root.
  exit /b 1
)
if "%~1"=="" (
  "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%COLLECTOR_ROOT%\scripts\configure_data_root_windows.ps1" first-run
  if errorlevel 1 exit /b 1
  "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%COLLECTOR_ROOT%\scripts\start_all_services_windows.ps1" start
) else (
  "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%COLLECTOR_ROOT%\scripts\start_all_services_windows.ps1" %*
)
"@
    Set-Content -LiteralPath $DarkwebCommandPath -Value $commandText -Encoding ASCII
    Add-UserPathEntry $CommandBinDir

    Set-UserEnv -Name "DARKWEB_PROJECT_ROOT" -Value $ProjectRoot
    Set-UserEnv -Name "DARKWEB_HOME" -Value $ProjectRoot
    Set-UserEnv -Name "DARKWEB_COLLECTOR_ROOT" -Value $CollectorRoot
    Set-UserEnv -Name "DARKWEB_DASHBOARD_ROOT" -Value $DashboardRoot
    Set-UserEnv -Name "DARKWEB_DATA_ROOT" -Value $DefaultUserDataDir
    Set-UserEnv -Name "DARKWEB_USER_DATA_ROOT" -Value $DefaultUserDataDir
    Set-UserEnv -Name "DARKWEB_APP_ROOT" -Value $AppRoot
    Set-UserEnv -Name "DARKWEB_MIGRATION_ROOT" -Value $MigrationRoot
    Set-UserEnv -Name "DARKWEB_ACTIVE_RELEASE_FILE" -Value $ActiveReleaseFile
    Set-UserEnv -Name "DARKWEB_COLLECTOR_DB_PATH" -Value $CollectorDbPath
    Set-UserEnv -Name "DARKWEB_COLLECTOR_SITES_FILE" -Value $CollectorSitesFile
    Set-UserEnv -Name "DARKWEB_COLLECTOR_OUTPUT_ROOT" -Value $CollectorOutputRoot
    Set-UserEnv -Name "DARKWEB_AUTH_PASSWORD_FILE" -Value $AuthPasswordFile
    Set-UserEnv -Name "DARKWEB_UPDATE_STATE_DIR" -Value $UpdateStateRoot
    Set-UserEnv -Name "PLAYWRIGHT_BROWSERS_PATH" -Value $PlaywrightBrowsersRoot
    Set-UserEnv -Name "DARKWEB_GARNET_DATA_ROOT" -Value $GarnetDataRoot
    Set-UserEnv -Name "DARKWEB_TOR_EXPERT_DIR" -Value $TorExpertRoot
    if ($script:RedisProvider -eq "garnet") {
        Set-UserEnv -Name "REDIS_URL" -Value $RedisUrl
        Set-UserEnv -Name "DARKWEB_REDIS_PROVIDER" -Value "garnet"
    }
    Set-UserEnv -Name "DARKWEB_API_PORT" -Value ([string]$ApiPort)
    Set-UserEnv -Name "DARKWEB_API_TARGET" -Value $ApiBaseUrl
    Set-UserEnv -Name "DARKWEB_FRONTEND_PORT" -Value ([string]$FrontendPort)
    Set-UserEnv -Name "DARKWEB_FRONTEND_URL" -Value $FrontendUrl
    Write-Info "Registered darkweb command: $DarkwebCommandPath"
}

function Test-CollectorVenv {
    param([string]$Python = $VenvPython)
    if (-not (Test-Path -LiteralPath $Python -PathType Leaf)) {
        return $false
    }
    try {
        & $Python -B -c "import sys, pathlib, pip; raise SystemExit(0 if sys.prefix != sys.base_prefix and pathlib.Path(sys.executable).exists() and pathlib.Path(sys.prefix).exists() else 1)" *> $null
        return ($LASTEXITCODE -eq 0)
    }
    catch {
        return $false
    }
}

function Set-CollectorEnvironment {
    param([string]$Root)
    $script:VenvDir = $Root
    $script:VenvPython = Join-Path $Root "Scripts\python.exe"
}

function Test-LocalDependencyPath {
    param([string]$Path)
    if (-not $Path -or $Path -notmatch '^[A-Za-z]:\\') { return $false }
    foreach ($part in $Path.Substring(3).TrimEnd('\').Split('\')) {
        if ($part -in @('.', '..') -or $part.EndsWith('.') -or $part.EndsWith(' ') -or $part.Contains(':')) { return $false }
    }
    $cursor = [IO.Path]::GetFullPath($Path)
    while ($cursor) {
        if ((Test-Path -LiteralPath $cursor) -and ((Get-Item -LiteralPath $cursor -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { return $false }
        $cursor = [IO.Path]::GetDirectoryName($cursor)
    }
    return $true
}

function Test-PythonEnvironmentPath {
    param([string]$Root)
    return (Test-LocalDependencyPath $Root) -and ((Test-SamePath $Root (Join-Path $CollectorRoot "venv")) -or
        (Test-PathUnderRoot $Root $PythonEnvironmentsRoot) -or
        ((Test-PathUnderRoot $Root $AppRoot) -and $Root.EndsWith('\darkweb_collector\venv', [StringComparison]::OrdinalIgnoreCase)))
}

function Read-PythonEnvironmentProfile {
    param([string]$Path)
    try {
        if (-not (Test-LocalDependencyPath $Path) -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
        $profile = Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json
        if ($profile.format -ne 1 -or -not (Test-PythonEnvironmentPath ([string]$profile.root))) { return $null }
        foreach ($name in @("identity", "requirements", "packages", "key")) {
            if ([string]$profile.$name -notmatch '^[a-f0-9]{64}$') { return $null }
        }
        return $profile
    }
    catch { return $null }
}

function Get-PythonDependencyProfile {
    param([string]$Python, [string]$Requirements = (Join-Path $CollectorRoot "requirements.txt"))
    try {
        $output = & $Python -B $DependencyHelper python-profile --requirements $Requirements 2>$null
        if ($LASTEXITCODE -eq 0) { return ($output | ConvertFrom-Json) }
    }
    catch { }
    return $null
}

function Save-PythonEnvironmentProfile {
    $profile = Get-PythonDependencyProfile $VenvPython
    if (-not $profile) { Stop-WithError "Cannot verify the prepared Python environment." }
    $record = [ordered]@{ format = 1; root = $VenvDir; identity = $profile.identity; requirements = $profile.requirements; packages = $profile.packages; key = $profile.key }
    $paths = @($PythonEnvironmentState, (Join-Path $PythonEnvironmentsRoot ($profile.key + ".json")))
    foreach ($path in $paths) {
        if (-not (Test-LocalDependencyPath $path)) { Stop-WithError "Linked or unsafe Python dependency metadata directory." }
    }
    foreach ($path in $paths) {
        Ensure-Directory (Split-Path -Parent $path)
        $temporary = "$path.$PID.tmp"
        $record | ConvertTo-Json | Set-Content -LiteralPath $temporary -Encoding UTF8
        Move-Item -LiteralPath $temporary -Destination $path -Force
    }
}

function Ensure-CollectorVenv {
    if (-not (Test-LocalDependencyPath $PythonEnvironmentsRoot) -or -not (Test-LocalDependencyPath $PythonEnvironmentState)) {
        Stop-WithError "Linked or unsafe Python dependency cache directory."
    }
    $python = Ensure-PythonRuntime
    $expected = Get-PythonDependencyProfile $python
    if (-not $expected) { Stop-WithError "Cannot identify the base Python runtime and requirements." }
    $indexPath = Join-Path $PythonEnvironmentsRoot ($expected.key + ".json")
    if (-not (Test-LocalDependencyPath $indexPath)) { Stop-WithError "Linked or unsafe Python dependency index." }
    $candidates = @((Read-PythonEnvironmentProfile $PythonEnvironmentState),
        (Read-PythonEnvironmentProfile $indexPath))
    $projects = @($ProjectRoot)
    if (Test-Path -LiteralPath $InstallationStatePath -PathType Leaf) {
        try {
            $installation = Get-Content -LiteralPath $InstallationStatePath -Raw -Encoding UTF8 | ConvertFrom-Json
            if ($installation.format -eq 1 -and $installation.current_root) { $projects += [string]$installation.current_root }
        }
        catch { Write-Warn "Ignoring an unreadable dependency source installation." }
    }
    foreach ($project in ($projects | Select-Object -Unique)) {
        $collector = Join-Path $project "darkweb_collector"
        $saved = Read-PythonEnvironmentProfile (Join-Path $collector ".runtime\windows\python-environment.json")
        if ($saved) { $candidates += $saved; continue }
        $legacy = Join-Path $collector "venv"
        if (@($candidates | Where-Object { $_ -and (Test-SamePath $_.root $legacy) }).Count -gt 0) { continue }
        $requirements = Join-Path $collector "requirements.txt"
        $stamp = Join-Path $legacy ".requirements.sha256"
        if ((Test-PythonEnvironmentPath $legacy) -and (Test-Path -LiteralPath $requirements -PathType Leaf) -and
            (Test-Path -LiteralPath $stamp -PathType Leaf) -and (Get-Content -LiteralPath $stamp -Raw).Trim() -eq (Get-FileHashText $requirements)) {
            $profile = Get-PythonDependencyProfile (Join-Path $legacy "Scripts\python.exe") $requirements
            if ($profile) { $profile | Add-Member NoteProperty root $legacy; $candidates += $profile }
        }
    }
    foreach ($candidate in $candidates) {
        if (-not $candidate -or $candidate.key -ne $expected.key -or -not (Test-PythonEnvironmentPath $candidate.root)) { continue }
        $candidatePython = Join-Path $candidate.root "Scripts\python.exe"
        $actual = Get-PythonDependencyProfile $candidatePython
        if ($actual -and $actual.key -eq $expected.key -and $actual.packages -eq $candidate.packages -and
            (Test-CollectorVenv $candidatePython) -and (Test-CollectorDependencies $candidatePython)) {
            Set-CollectorEnvironment $candidate.root
            $script:NewCollectorEnvironment = $false
            Save-PythonEnvironmentProfile
            Write-Info "Reusing verified Python dependencies: $VenvDir"
            return
        }
    }
    $root = Join-Path $PythonEnvironmentsRoot ($expected.key.Substring(0,16) + "-" + [Guid]::NewGuid().ToString("N").Substring(0,8))
    if (-not (Test-PythonEnvironmentPath $root) -or (Test-Path -LiteralPath $root)) { Stop-WithError "Unsafe or already existing Python environment directory." }
    Ensure-Directory $PythonEnvironmentsRoot
    Set-CollectorEnvironment $root
    $script:NewCollectorEnvironment = $true
    Write-Info "Creating isolated Python environment for changed or missing dependencies: $VenvDir"
    & $python -m venv $VenvDir
    if ($LASTEXITCODE -ne 0) { Stop-WithError "Failed to create Python virtual environment." }
}

function Test-CollectorDependencies {
    param([string]$Python = $VenvPython)
    try {
        $code = @"
from importlib.metadata import version
from pathlib import Path
import sys
from pip._vendor.packaging.requirements import Requirement
import celery, redis, playwright, fastapi, uvicorn, pycountry, babel, psutil, psycopg2, jwt, wecom_aibot_sdk
for line in Path(sys.argv[1]).read_text(encoding='utf-8-sig').splitlines():
    if not line.strip() or line.lstrip().startswith('#'):
        continue
    requirement = Requirement(line)
    if requirement.marker is None or requirement.marker.evaluate():
        if not requirement.specifier.contains(version(requirement.name)):
            raise SystemExit(1)
"@
        & $Python -B -c $code (Join-Path $CollectorRoot "requirements.txt") *> $null
        if ($LASTEXITCODE -ne 0) { return $false }
        & $Python -B -m pip check *> $null
        return ($LASTEXITCODE -eq 0)
    }
    catch {
        return $false
    }
}

function Ensure-CollectorDependencies {
    $saved = Read-PythonEnvironmentProfile $PythonEnvironmentState
    $actual = Get-PythonDependencyProfile $VenvPython
    if ($saved -and $actual -and $actual.key -eq $saved.key -and $actual.packages -eq $saved.packages -and
        (Test-SamePath $saved.root $VenvDir) -and (Test-CollectorDependencies)) {
        return
    }
    if (-not $NewCollectorEnvironment -or -not (Test-PathUnderRoot $VenvDir $PythonEnvironmentsRoot)) {
        Stop-WithError "An existing Python environment failed verification; preserving it without modification."
    }
    Write-Info "Installing collector Python dependencies"
    & $VenvPython -m pip install -r (Join-Path $CollectorRoot "requirements.txt")
    if ($LASTEXITCODE -ne 0) {
        Stop-WithError "Failed to install Python requirements."
    }
    if (-not (Test-CollectorDependencies)) { Stop-WithError "Prepared Python dependencies failed validation." }
    Save-PythonEnvironmentProfile
    $script:NewCollectorEnvironment = $false
}

function Test-PlaywrightBrowsers {
    param([switch]$FilesOnly)
    try {
        $code = @"
from pathlib import Path
import sys
from playwright.sync_api import sync_playwright

with sync_playwright() as playwright:
    for browser_type in (playwright.chromium, playwright.firefox):
        if not Path(browser_type.executable_path).exists():
            raise SystemExit(1)
        if sys.argv[1] != 'files':
            browser = browser_type.launch(headless=True)
            browser.close()
"@
        & $VenvPython -B -c $code $(if ($FilesOnly) { "files" } else { "launch" }) *> $null
        return ($LASTEXITCODE -eq 0)
    }
    catch {
        return $false
    }
}

function Ensure-PlaywrightRuntime {
    if (Test-PlaywrightBrowsers) {
        Write-Info "Reusing verified shared Playwright browsers"
        return
    }
    if (Test-PlaywrightBrowsers -FilesOnly) {
        Stop-WithError "Existing Playwright browser files cannot launch; preserving them without downloading replacements."
    }
    Write-Info "Installing Playwright browser runtimes"
    $previousGc = [Environment]::GetEnvironmentVariable("PLAYWRIGHT_SKIP_BROWSER_GC", "Process")
    try {
        $env:PLAYWRIGHT_SKIP_BROWSER_GC = "1"
        & $VenvPython -B -m playwright install chromium firefox
        if ($LASTEXITCODE -ne 0) { Stop-WithError "Failed to install Playwright browser runtimes." }
    }
    finally {
        if ($null -eq $previousGc) { Remove-Item Env:PLAYWRIGHT_SKIP_BROWSER_GC -ErrorAction SilentlyContinue }
        else { $env:PLAYWRIGHT_SKIP_BROWSER_GC = $previousGc }
    }
    if (-not (Test-PlaywrightBrowsers)) {
        Stop-WithError "Playwright browsers were installed but cannot launch. Check the local browser runtime dependencies."
    }
}

function Ensure-DashboardDependencies {
    & $VenvPython -B $DependencyHelper check-node-paths --dashboard $DashboardRoot
    if ($LASTEXITCODE -ne 0) { Stop-WithError "Linked or unsafe dashboard dependency directory; no dependencies were removed or installed." }
    $npm = Ensure-NodeRuntime
    $packageLockPath = Join-Path $DashboardRoot "package-lock.json"
    $expectedHash = Get-FileHashText $packageLockPath
    $expected = Get-DashboardDependencyProfile $DashboardRoot
    $nodeIdentity = & $script:NodeExePath -p "JSON.stringify([process.version,process.versions.modules,process.platform,process.arch])"
    if ($LASTEXITCODE -ne 0 -or -not $expected) { Stop-WithError "Cannot identify the dashboard dependencies and Node runtime." }
    if (Test-DashboardDependencies $DashboardRoot $expected.fingerprint $nodeIdentity) {
        Save-DashboardDependencyProfile $expected.fingerprint $nodeIdentity $expectedHash
        return
    }
    if (Test-Path -LiteralPath $InstallationStatePath -PathType Leaf) {
        try {
            $installation = Get-Content -LiteralPath $InstallationStatePath -Raw -Encoding UTF8 | ConvertFrom-Json
            if ($installation.format -eq 1 -and -not (Test-SamePath ([string]$installation.current_root) $ProjectRoot)) {
                $source = Join-Path ([string]$installation.current_root) "threat-intelligence-dashboard"
                $sourceProfile = Get-DashboardDependencyProfile $source
                if ($sourceProfile -and $sourceProfile.fingerprint -eq $expected.fingerprint -and
                    (Test-DashboardDependencies $source $expected.fingerprint $nodeIdentity)) {
                    if (Test-Path -LiteralPath $DashboardNodeModulesDir) {
                        Remove-GeneratedDirectory -Path $DashboardNodeModulesDir -AllowedRoot $DashboardRoot
                    }
                    & "$env:SystemRoot\System32\robocopy.exe" (Join-Path $source "node_modules") $DashboardNodeModulesDir /E /COPY:DAT /DCOPY:DAT /R:0 /W:0 /XJ /NFL /NDL /NJH /NJS /NP | Out-Null
                    if ($LASTEXITCODE -ge 8) { throw "Dashboard dependency copy failed." }
                    if (-not (Test-DashboardDependencies $DashboardRoot $expected.fingerprint $nodeIdentity)) { throw "Copied dashboard dependencies failed validation." }
                    Save-DashboardDependencyProfile $expected.fingerprint $nodeIdentity $expectedHash
                    Write-Info "Reused verified dashboard dependencies from the previous release"
                    return
                }
            }
        }
        catch {
            Write-Warn "Dashboard dependency reuse failed; installing an isolated local copy."
        }
    }
    Write-Info "Installing dashboard dependencies"
    $npmCache = Join-Path $DefaultUserDataDir "npm-cache"
    Ensure-Directory $npmCache
    $env:NPM_CONFIG_CACHE = $npmCache
    if ($script:NodeBinDir) {
        Add-ProcessPathEntry $script:NodeBinDir
    }
    Push-Location $DashboardRoot
    try {
        & $npm ci --prefer-offline --no-audit --no-fund
        if ($LASTEXITCODE -ne 0) {
            Stop-WithError "Failed to install dashboard dependencies."
        }
    }
    finally {
        Pop-Location
    }
    if (-not (Test-DashboardDependencies $DashboardRoot $expected.fingerprint $nodeIdentity)) {
        Stop-WithError "Installed dashboard dependencies failed validation."
    }
    Save-DashboardDependencyProfile $expected.fingerprint $nodeIdentity $expectedHash
}

function Get-DashboardDependencyProfile {
    param([string]$Root)
    try {
        $output = & $VenvPython -B $DependencyHelper node-profile --dashboard $Root 2>$null
        if ($LASTEXITCODE -eq 0) { return ($output | ConvertFrom-Json) }
    }
    catch { }
    return $null
}

function Test-DashboardDependencies {
    param([string]$Root, [string]$Fingerprint, [string]$NodeIdentity)
    try {
        $modules = Join-Path $Root "node_modules"
        $stamp = Join-Path $modules ".darkweb-runtime.json"
        if (Test-Path -LiteralPath $stamp -PathType Leaf) {
            $saved = Get-Content -LiteralPath $stamp -Raw -Encoding UTF8 | ConvertFrom-Json
            if ($saved.format -ne 1 -or $saved.fingerprint -ne $Fingerprint -or $saved.node -ne $NodeIdentity) { return $false }
        }
        & $VenvPython -B $DependencyHelper check-node --dashboard $Root *> $null
        if ($LASTEXITCODE -ne 0) { return $false }
        & $script:NodeExePath -e "require(require('node:path').join(process.argv[1],'esbuild')).transformSync('let ready = true')" $modules *> $null
        return ($LASTEXITCODE -eq 0)
    }
    catch { return $false }
}

function Save-DashboardDependencyProfile {
    param([string]$Fingerprint, [string]$NodeIdentity, [string]$LockHash)
    @{ format = 1; fingerprint = $Fingerprint; node = $NodeIdentity } | ConvertTo-Json |
        Set-Content -LiteralPath (Join-Path $DashboardNodeModulesDir ".darkweb-runtime.json") -Encoding UTF8
    Set-Content -LiteralPath $PackageLockStamp -Value $LockHash -Encoding ASCII
}

function Build-Dashboard {
    $null = Ensure-NodeRuntime
    $node = $script:NodeExePath
    $viteCli = Join-Path $DashboardRoot "node_modules\vite\bin\vite.js"
    $nodeIdentity = & $node -p "JSON.stringify([process.version,process.versions.modules,process.platform,process.arch])"
    if ($LASTEXITCODE -ne 0) { Stop-WithError "Cannot identify the dashboard build runtime." }
    $buildStamp = Join-Path $RuntimeDir "dashboard-build.json"
    $profile = & $VenvPython -B $DependencyHelper dashboard-profile --dashboard $DashboardRoot --node-identity $nodeIdentity
    if ($LASTEXITCODE -ne 0) { Stop-WithError "Cannot verify dashboard build inputs." }
    $profile = $profile | ConvertFrom-Json
    if (Test-Path -LiteralPath $buildStamp -PathType Leaf) {
        try {
            $saved = Get-Content -LiteralPath $buildStamp -Raw -Encoding UTF8 | ConvertFrom-Json
            if ($saved.fingerprint -eq $profile.fingerprint -and $profile.dist -and $saved.dist -eq $profile.dist) {
                Write-Info "Reusing verified dashboard build for unchanged source and runtime"
                return
            }
        }
        catch { Write-Warn "Ignoring an invalid dashboard build record." }
    }
    Write-Info "Building optimized dashboard assets"
    Push-Location $DashboardRoot
    try {
        & $node $viteCli build
        if ($LASTEXITCODE -ne 0) {
            Stop-WithError "Failed to build optimized dashboard assets."
        }
    }
    finally {
        Pop-Location
    }
    $distIndex = Join-Path $DashboardDistDir "index.html"
    if (-not (Test-Path -LiteralPath $distIndex -PathType Leaf)) {
        Stop-WithError "Dashboard build did not produce dist/index.html."
    }
    $built = & $VenvPython -B $DependencyHelper dashboard-profile --dashboard $DashboardRoot --node-identity $nodeIdentity
    if ($LASTEXITCODE -ne 0) { Stop-WithError "Cannot verify dashboard build output." }
    $built = $built | ConvertFrom-Json
    if ($built.fingerprint -ne $profile.fingerprint -or -not $built.dist) { Stop-WithError "Dashboard build inputs changed or output is incomplete." }
    Ensure-Directory $RuntimeDir
    $built | ConvertTo-Json | Set-Content -LiteralPath "$buildStamp.$PID.tmp" -Encoding UTF8
    Move-Item -LiteralPath "$buildStamp.$PID.tmp" -Destination $buildStamp -Force
}

function Ensure-RuntimeDatabase {
    Ensure-Directory (Split-Path -Parent $CollectorDbPath)
    Ensure-Directory $CollectorOutputRoot
    Copy-MissingOutputArtifacts
    $pythonCode = "from pathlib import Path; import sys; root = Path(sys.argv[1]); target = Path(sys.argv[2]); src = root / 'src'; sys.path.insert(0, str(src)); from darkweb_collector.db import connect; connection = connect(target); connection.commit(); connection.close()"
    & $VenvPython -c $pythonCode $CollectorRoot $CollectorDbPath
    if ($LASTEXITCODE -ne 0) {
        Stop-WithError "Failed to initialize collector database."
    }
}

function Copy-MissingOutputArtifacts {
    if ($ActiveReleaseEnabled) {
        return
    }
    $sourceOutputRoot = Join-Path $CollectorRoot "output"
    if (-not (Test-Path -LiteralPath $sourceOutputRoot)) {
        return
    }

    Ensure-Directory $CollectorOutputRoot
    $resolvedSource = (Resolve-Path -LiteralPath $sourceOutputRoot).Path
    $resolvedTarget = (Resolve-Path -LiteralPath $CollectorOutputRoot).Path
    if ($resolvedSource.TrimEnd("\") -ieq $resolvedTarget.TrimEnd("\")) {
        return
    }

    $copied = 0
    $sourceFiles = @(Get-ChildItem -LiteralPath $resolvedSource -Recurse -File -ErrorAction SilentlyContinue)
    foreach ($file in $sourceFiles) {
        $relativePath = $file.FullName.Substring($resolvedSource.Length).TrimStart([char[]]@("\", "/"))
        if (-not $relativePath) {
            continue
        }
        $targetPath = Join-Path $resolvedTarget $relativePath
        if (Test-Path -LiteralPath $targetPath) {
            continue
        }
        Ensure-Directory (Split-Path -Parent $targetPath)
        Copy-Item -LiteralPath $file.FullName -Destination $targetPath
        $copied += 1
    }
    if ($copied -gt 0) {
        Write-Info "Copied $copied existing collector output artifact(s) into runtime output root"
    }
}

function Ensure-SiteConfigsLoad {
    Ensure-Directory $RuntimeDir
    $checkerPath = Join-Path $RuntimeDir "check_sites.py"
    $pythonCode = @"
from pathlib import Path
import sys
root = Path(sys.argv[1])
sites_file = Path(sys.argv[2])
src = root / "src"
sys.path.insert(0, str(src))
from darkweb_collector.config import load_site_configs
from darkweb_collector.adapters.registry import get_adapter
configs = load_site_configs(sites_file)
if not configs:
    raise SystemExit("no site config found")
missing = []
for config in configs:
    try:
        get_adapter(config.site_name)
    except Exception as exc:
        missing.append(f"{config.site_name}: {exc}")
if missing:
    raise SystemExit("adapter missing for configured sites: " + "; ".join(missing))
print(",".join(config.site_name for config in configs))
"@
    Set-Content -LiteralPath $checkerPath -Value $pythonCode -Encoding UTF8
    $output = & $VenvPython $checkerPath $CollectorRoot $CollectorSitesFile
    if ($LASTEXITCODE -ne 0) {
        Stop-WithError "Failed to load crawler site configuration from $CollectorSitesFile. $output"
    }
    Write-Info "Crawler sites loaded: $output"
}

function Ensure-Redis {
    if (Test-RedisReady) {
        Write-Info "Redis is already running"
        $managedGarnet = @(Get-ManagedGarnetProcesses) | Select-Object -First 1
        if ($managedGarnet) {
            Set-ManagedGarnetCpuLimit -Process $managedGarnet -ExpectedExecutable $GarnetServerExecutable
            $script:RedisProvider = "garnet"
            return [pscustomobject]@{
                name = "garnet"
                pid = $managedGarnet.Id
                log = Join-Path $LogDir "garnet.log"
                error_log = Join-Path $LogDir "garnet-error.log"
                started_at = $managedGarnet.StartTime.ToString("s")
            }
        }
        return $null
    }

    $endpoint = Get-RedisEndpoint
    if (-not $endpoint.IsLocal) {
        Stop-WithError "REDIS_URL points to $RedisUrl, but it is not reachable. Start that Redis instance or change REDIS_URL."
    }

    if ($RedisUrl -ne $ManagedGarnetRedisUrl) {
        Stop-WithError "Redis-compatible endpoint $RedisUrl is not ready and is not managed by this project."
    }
    $runtime = Ensure-ManagedGarnetRuntime
    Ensure-Directory $runtime.DataRoot
    Ensure-Directory $runtime.CheckpointDir

    Write-Info "Starting managed Microsoft Garnet $GarnetVersion"
    $record = Start-ManagedGarnetProcess -Runtime $runtime -Port $endpoint.Port
    if (-not (Wait-ForRedis -TimeoutSeconds $ServiceWaitSeconds)) {
        if (Test-ProcessRunning -ProcessId ([int]$record.pid)) {
            Stop-ProcessTree -ProcessId ([int]$record.pid) -Label "failed Garnet"
        }
        Stop-WithError "Garnet did not become ready. Check $($record.log)."
    }
    return $record
}

function Ensure-RedisCanStart {
    Ensure-RedisRuntime
}

function Test-PostgreSqlDatabaseUrl {
    param([string]$Value)
    if (-not $Value) {
        return $false
    }
    try {
        $uri = [Uri]$Value
        return $uri.Scheme -in @("postgres", "postgresql") -and $uri.Host
    }
    catch {
        return $false
    }
}

function Ensure-PostgreSqlMigrationTarget {
    $targetUrl = if ($env:DARKWEB_MIGRATION_TARGET_DATABASE_URL) {
        [string]$env:DARKWEB_MIGRATION_TARGET_DATABASE_URL
    }
    else {
        [string][Environment]::GetEnvironmentVariable("DARKWEB_MIGRATION_TARGET_DATABASE_URL", "User")
    }
    if ($targetUrl) {
        if (-not (Test-PostgreSqlDatabaseUrl $targetUrl)) {
            Stop-WithError "DARKWEB_MIGRATION_TARGET_DATABASE_URL must be a valid PostgreSQL URL."
        }
        $env:DARKWEB_MIGRATION_TARGET_DATABASE_URL = $targetUrl
        Write-Info "PostgreSQL migration target is already configured"
        return
    }

    $activeDatabaseUrl = ""
    if ($ActiveReleaseEnabled) {
        $activeDatabaseUrlProperty = $ActiveRelease.PSObject.Properties["database_url"]
        if ($activeDatabaseUrlProperty) {
            $activeDatabaseUrl = [string]$activeDatabaseUrlProperty.Value
        }
    }
    if (Test-PostgreSqlDatabaseUrl $activeDatabaseUrl) {
        $env:DARKWEB_MIGRATION_TARGET_DATABASE_URL = $activeDatabaseUrl
        Write-Info "Using the active PostgreSQL database as the migration target"
        return
    }

    if (-not (Test-Path -LiteralPath $PostgreSqlSetupScript -PathType Leaf)) {
        Stop-WithError "Bundled PostgreSQL setup tool was not found: $PostgreSqlSetupScript"
    }
    $powershell = Resolve-PowerShellCommand
    Write-Info "Preparing PostgreSQL 16 as the default migration target"
    & $powershell -NoProfile -ExecutionPolicy Bypass -File $PostgreSqlSetupScript install -ProjectRoot $ProjectRoot -DataRoot $DefaultUserDataDir -NoRestart -OneClick
    if ($LASTEXITCODE -ne 0) {
        $resultPath = Join-Path $ControlRoot "postgresql-setup-result.json"
        $detail = ""
        if (Test-Path -LiteralPath $resultPath -PathType Leaf) {
            try {
                $result = Get-Content -LiteralPath $resultPath -Raw -Encoding UTF8 | ConvertFrom-Json
                if ($result.status -eq "error") {
                    $detail = [string]$result.message
                }
            }
            catch {
                $detail = ""
            }
        }
        Stop-WithError $(if ($detail) { "Failed to prepare PostgreSQL: $detail" } else { "Failed to prepare PostgreSQL." })
    }

    $targetUrl = [string][Environment]::GetEnvironmentVariable("DARKWEB_MIGRATION_TARGET_DATABASE_URL", "User")
    if (-not (Test-PostgreSqlDatabaseUrl $targetUrl)) {
        Stop-WithError "PostgreSQL setup completed without a valid migration target configuration."
    }
    $env:DARKWEB_MIGRATION_TARGET_DATABASE_URL = $targetUrl
    Write-Info "PostgreSQL migration target is ready"
}

function Ensure-Environment {
    Invoke-TimedStep "Assert-DataRootCapacity" { Assert-DataRootCapacity }
    Invoke-TimedStep "Ensure-PythonRuntime" { Ensure-PythonRuntime | Out-Null }
    Invoke-TimedStep "Ensure-NodeRuntime" { Ensure-NodeRuntime | Out-Null }
    Invoke-TimedStep "Ensure-RedisCanStart" { Ensure-RedisCanStart }
    Invoke-TimedStep "Ensure-AuthPasswordFile" { Ensure-AuthPasswordFile }
    Invoke-TimedStep "Ensure-TorBridgeRuntime" { Ensure-TorBridgeRuntime }
    Invoke-TimedStep "Register-DarkwebCommand" { Register-DarkwebCommand }
    if (-not (Test-Path -LiteralPath (Join-Path $CollectorRoot "scripts\serve_api.py"))) {
        Stop-WithError "API launcher not found under collector scripts."
    }
    if (-not (Test-Path -LiteralPath (Join-Path $DashboardRoot "package.json"))) {
        Stop-WithError "Dashboard package.json not found."
    }
    $dashboardIndex = Join-Path $DashboardRoot "index.html"
    if (-not (Test-Path -LiteralPath $dashboardIndex) -or -not (Get-Content -LiteralPath $dashboardIndex -Raw).Contains($NewUiMarker)) {
        Stop-WithError "Xuanjian new UI was not found under $DashboardRoot."
    }

    Ensure-Directory $RuntimeDir
    Ensure-Directory $LogDir
    Invoke-TimedStep "Ensure-CollectorVenv" { Ensure-CollectorVenv }
    Invoke-TimedStep "Ensure-CollectorDependencies" { Ensure-CollectorDependencies }
    Invoke-TimedStep "Ensure-PlaywrightRuntime" { Ensure-PlaywrightRuntime }
    Invoke-TimedStep "Ensure-DashboardDependencies" { Ensure-DashboardDependencies }
    Invoke-TimedStep "Build-Dashboard" { Build-Dashboard }
    Invoke-TimedStep "Ensure-PostgreSqlMigrationTarget" { Ensure-PostgreSqlMigrationTarget }
    Invoke-TimedStep "Ensure-RuntimeDatabase" { Ensure-RuntimeDatabase }
    Invoke-TimedStep "Ensure-SiteConfigsLoad" { Ensure-SiteConfigsLoad }
}

function Prepare-UpdateEnvironment {
    if (-not (Test-Path -LiteralPath (Join-Path $CollectorRoot "scripts\serve_api.py") -PathType Leaf)) {
        Stop-WithError "API launcher not found under collector scripts."
    }
    $dashboardIndex = Join-Path $DashboardRoot "index.html"
    if (-not (Test-Path -LiteralPath (Join-Path $DashboardRoot "package.json") -PathType Leaf) -or
        -not (Test-Path -LiteralPath $dashboardIndex -PathType Leaf) -or
        -not (Get-Content -LiteralPath $dashboardIndex -Raw).Contains($NewUiMarker)) {
        Stop-WithError "Xuanjian new UI was not found under $DashboardRoot."
    }

    Ensure-Directory $RuntimeDir
    Ensure-Directory $LogDir
    Invoke-TimedStep "Ensure-PythonRuntime" { Ensure-PythonRuntime | Out-Null }
    Invoke-TimedStep "Ensure-NodeRuntime" { Ensure-NodeRuntime | Out-Null }
    Invoke-TimedStep "Ensure-RedisCanStart" { Ensure-RedisCanStart }
    Invoke-TimedStep "Ensure-TorBridgeRuntime" { Ensure-TorBridgeRuntime }
    Invoke-TimedStep "Ensure-CollectorVenv" { Ensure-CollectorVenv }
    Invoke-TimedStep "Ensure-CollectorDependencies" { Ensure-CollectorDependencies }
    Invoke-TimedStep "Ensure-PlaywrightRuntime" { Ensure-PlaywrightRuntime }
    Invoke-TimedStep "Ensure-DashboardDependencies" { Ensure-DashboardDependencies }
    Invoke-TimedStep "Build-Dashboard" { Build-Dashboard }
    Write-Info "Update environment is ready"
}

function Assert-DarkwebHealth {
    Load-RuntimePorts
    if (-not (Test-DarkwebStackReady)) {
        Stop-WithError "Darkweb services did not pass the strict health check."
    }
    Write-Info "Darkweb services passed the strict health check"
}

function Start-Services {
    if (Test-DarkwebStackReady) {
        Write-Info "Services already running"
        Write-Info "Frontend: $FrontendUrl"
        Write-Info "API jobs: $ApiJobsUrl"
        return
    }

    Ensure-Environment

    $existingRecords = @(Get-ServiceRecords | Where-Object { Test-ProcessRunning -ProcessId ([int]$_.pid) })
    if ($existingRecords.Count -gt 0) {
        Write-Warn "Existing $SessionName services are running; stopping them first"
        Stop-Services
    }

    # A previous run may have lost its PID file, or another dev server may
    # still occupy the fixed ports used by Vite's proxy. Clear those ports
    # when they are not serving this project's API/frontend.
    $originalApiPort = $ApiPort
    $originalFrontendPort = $FrontendPort
    Ensure-ApiPort
    Ensure-FrontendPort
    Save-RuntimePorts
    if ($ApiPort -ne $originalApiPort -or $FrontendPort -ne $originalFrontendPort) {
        Register-DarkwebCommand
    }

    $records = @()
    $redisRecord = Ensure-Redis
    if ($redisRecord) {
        $records += $redisRecord
        Save-ServiceRecords $records
    }
    $python = Quote-PS $VenvPython
    if ($redisRecord) {
        $checkpointCode = Quote-PS "import os, redis; redis.Redis.from_url(os.environ['REDIS_URL'], socket_connect_timeout=5, socket_timeout=30).bgsave(schedule=True)"
        $checkpointBody = "`$env:DARKWEB_GARNET_CHECKPOINT_LOOP = '1'; while (`$true) { Start-Sleep -Seconds $GarnetCheckpointIntervalSeconds; & $python -c $checkpointCode; if (`$LASTEXITCODE -ne 0) { Write-Warning 'Managed Garnet checkpoint failed' } }"
        $records += Start-ManagedProcess -Name "garnet-checkpoint" -WorkingDirectory $CollectorRoot -Body $checkpointBody
    }
    $null = Ensure-NodeRuntime
    $node = Quote-PS $script:NodeExePath
    $crawler = Quote-PS (Join-Path $CollectorRoot "scripts\crawl.py")
    $apiLauncher = Quote-PS (Join-Path $CollectorRoot "scripts\serve_api.py")
    $viteCli = Quote-PS (Join-Path $DashboardRoot "node_modules\vite\bin\vite.js")

    $records += Start-ManagedProcess -Name "api" -WorkingDirectory $CollectorRoot -Body "& $python $apiLauncher"
    if (-not (Wait-ForDarkwebApi -TimeoutSeconds $ServiceWaitSeconds)) {
        Write-Warn "Darkweb API did not return configured site health within ${ServiceWaitSeconds}s"
    }

    $records += Start-ManagedProcess -Name "frontend" -WorkingDirectory $DashboardRoot -Body "& $node $viteCli preview --host 0.0.0.0 --port $FrontendPort --strictPort"
    $collectorWorkdir = Quote-PS $CollectorRoot
    $records += Start-ManagedProcess -Name "worker-seed" -WorkingDirectory $CollectorRoot -Body "& $python -m darkweb_collector.worker_supervisor --workdir $collectorWorkdir --name worker-seed --queues seed_http --hostname `"seed-http-$PID@%h`""
    $records += Start-ManagedProcess -Name "worker-detail" -WorkingDirectory $CollectorRoot -Body "& $python -m darkweb_collector.worker_supervisor --workdir $collectorWorkdir --name worker-detail --queues detail_http --hostname `"detail-http-$PID@%h`""
    for ($index = 1; $index -le $BrowserPublicConcurrency; $index++) {
        $records += Start-ManagedProcess -Name "worker-browser-public-$index" -WorkingDirectory $CollectorRoot -Body "& $python -m darkweb_collector.worker_supervisor --workdir $collectorWorkdir --name worker-browser-public-$index --queues browser_public,browser_render --hostname `"browser-public-$index-$PID@%h`""
    }
    for ($index = 1; $index -le $BrowserOnionConcurrency; $index++) {
        $records += Start-ManagedProcess -Name "worker-browser-onion-$index" -WorkingDirectory $CollectorRoot -Body "& $python -m darkweb_collector.worker_supervisor --workdir $collectorWorkdir --name worker-browser-onion-$index --queues browser_onion --hostname `"browser-onion-$index-$PID@%h`""
    }
    $records += Start-ManagedProcess -Name "scheduler" -WorkingDirectory $CollectorRoot -Body "while (`$true) { Write-Host `"[`$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] enqueue-due`"; & $python $crawler enqueue-due; Start-Sleep -Seconds $SchedulerIntervalSeconds }"
    $records += Start-ManagedProcess -Name "vuln-sync" -WorkingDirectory $CollectorRoot -Body "while (`$true) { Write-Host `"[`$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] sync-public-vulns --limit $VulnSyncLimit`"; & $python $crawler sync-public-vulns --limit $VulnSyncLimit; Start-Sleep -Seconds $VulnSyncIntervalSeconds }"

    Save-ServiceRecords $records

    if (-not (Wait-ForDarkwebFrontend -TimeoutSeconds $ServiceWaitSeconds)) {
        Write-Warn "Darkweb frontend did not become ready within ${ServiceWaitSeconds}s"
    }

    Write-Info "Services started"
    Write-Info "Frontend: $FrontendUrl"
    Write-Info "API jobs: $ApiJobsUrl"
    Write-Info "Logs: $LogDir"
    Show-Status
}

function Stop-Services {
    $portsToClean = @($ApiPort, $FrontendPort)
    Load-RuntimePorts
    $runtimePortsToClean = @($ApiPort, $FrontendPort)
    $projectPortsToClean = @(8000, 5173, 5174)

    $records = @(Get-ServiceRecords)
    $ownedProcessIds = @()
    $processRows = @(Get-ProcessRows)
    $processRowMap = New-ProcessRowMap -ProcessRows $processRows
    $stopRecords = @($records | Sort-Object @{ Expression = { if ($_.name -eq "garnet") { 1 } else { 0 } } })
    foreach ($record in $stopRecords) {
        $pidValue = [int]$record.pid
        if (Test-ProcessRunning -ProcessId $pidValue) {
            if (Test-ServiceRecordOwnsProcess -Record $record -ProcessRows $processRows -ProcessRowMap $processRowMap) {
                if ($record.name -ne "garnet") {
                    $ownedProcessIds += $pidValue
                }
                Stop-ProcessTree -ProcessId $pidValue -ProcessRows $processRows -ProcessRowMap $processRowMap -Label $record.name
            }
            else {
                Write-Warn "Ignoring stale PID record for $($record.name): $pidValue"
            }
        }
    }

    Start-Sleep -Milliseconds 300
    $processRows = @(Get-ProcessRows)
    $processRowMap = New-ProcessRowMap -ProcessRows $processRows
    Get-ProjectManagedProcessRows -ProcessRows $processRows -ProcessRowMap $processRowMap |
        Sort-Object ProcessId -Descending |
        ForEach-Object {
            Stop-ProcessTree -ProcessId ([int]$_.ProcessId) -ProcessRows $processRows -ProcessRowMap $processRowMap -Label "project process"
        }
    Stop-ManagedDashboardProcesses
    Stop-ManagedProjectPythonProcesses
    Stop-ManagedGarnetProcesses

    foreach ($port in @($runtimePortsToClean | Where-Object { $_ -and [int]$_ -gt 0 } | Sort-Object -Unique)) {
        Stop-ProjectListenersOnPort -Port ([int]$port) -Reason "darkweb runtime port cleanup"
    }
    foreach ($port in @($projectPortsToClean | Where-Object { $_ -and [int]$_ -gt 0 } | Sort-Object -Unique)) {
        Stop-ProjectListenersOnPort -Port ([int]$port) -Reason "darkweb stop cleanup"
    }

    Start-Sleep -Milliseconds 300
    $remainingOwned = @($ownedProcessIds | Where-Object { Test-ProcessRunning -ProcessId ([int]$_) })
    $remainingRows = @(Get-ProcessRows)
    $remainingRowMap = New-ProcessRowMap -ProcessRows $remainingRows
    $remainingManaged = @(Get-ProjectManagedProcessRows -ProcessRows $remainingRows -ProcessRowMap $remainingRowMap |
        Where-Object { [int]$_.ProcessId -ne $PID })
    if ($remainingOwned.Count -gt 0 -or $remainingManaged.Count -gt 0) {
        Stop-WithError "Managed project processes are still running after stop."
    }

    if (Test-Path -LiteralPath $PidFile) {
        Remove-Item -LiteralPath $PidFile -Force
    }
    Write-Info "Services stopped"
}

function Stop-TorBridgeForUninstall {
    if (Test-Path -LiteralPath $VenvPython -PathType Leaf) {
        $pythonCode = "from darkweb_collector.tor_bridge_control import stop_tor_bridge; stop_tor_bridge()"
        try {
            Push-Location $CollectorRoot
            & $VenvPython -c $pythonCode *> $null
            if ($LASTEXITCODE -eq 0) {
                return
            }
        }
        catch {
            Write-Warn "Tor bridge process could not be stopped cleanly: $($_.Exception.Message)"
        }
        finally {
            Pop-Location
        }
    }

    $pidPath = Join-Path $DefaultTorBridgeRuntimeDir "tor.pid"
    if (-not (Test-Path -LiteralPath $pidPath -PathType Leaf)) {
        return
    }
    $pidText = (Get-Content -LiteralPath $pidPath -Raw).Trim()
    $pidValue = 0
    if (-not [int]::TryParse($pidText, [ref]$pidValue) -or $pidValue -le 0) {
        return
    }
    $processRows = @(Get-ProcessRows)
    $process = $processRows | Where-Object { [int]$_.ProcessId -eq $pidValue } | Select-Object -First 1
    $managedTorrc = Join-Path $DefaultTorBridgeRuntimeDir "torrc"
    if ($process -and ([string]$process.CommandLine).IndexOf($managedTorrc, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
        $processRowMap = New-ProcessRowMap -ProcessRows $processRows
        Stop-ProcessTree -ProcessId $pidValue -ProcessRows $processRows -ProcessRowMap $processRowMap -Label "Tor bridge"
    }
    elseif ($process) {
        Write-Warn "Preserving PID $pidValue because it is not the managed Tor bridge process"
    }
}

function Remove-DarkwebRegistration {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "Low")]
    param()

    Remove-UserPathEntry -Path $CommandBinDir -WhatIf:$WhatIfPreference -Confirm:$false
    Remove-ManagedPath -Path $DarkwebCommandPath -ExpectedPath (Join-Path $ControlRoot "bin\darkweb.cmd") -Label "darkweb command" -WhatIf:$WhatIfPreference -Confirm:$false
    Remove-EmptyManagedDirectory -Path $CommandBinDir -ExpectedPath (Join-Path $ControlRoot "bin") -WhatIf:$WhatIfPreference -Confirm:$false

    $projectOwnsRedisEnvironment = Test-ProjectOwnedRedisEnvironment
    $managedVariables = @(
        @{ Name = "DARKWEB_PROJECT_ROOT"; Values = @($ProjectRoot) },
        @{ Name = "DARKWEB_HOME"; Values = @($ProjectRoot) },
        @{ Name = "DARKWEB_COLLECTOR_ROOT"; Values = @($CollectorRoot) },
        @{ Name = "DARKWEB_DASHBOARD_ROOT"; Values = @($DashboardRoot) },
        @{ Name = "DARKWEB_DATA_ROOT"; Values = @($DefaultUserDataDir) },
        @{ Name = "DARKWEB_USER_DATA_ROOT"; Values = @($DefaultUserDataDir) },
        @{ Name = "DARKWEB_APP_ROOT"; Values = @($AppRoot, (Join-Path $DefaultUserDataDir "app")) },
        @{ Name = "DARKWEB_UPDATE_STATE_DIR"; Values = @($UpdateStateRoot, $ControlRoot) },
        @{ Name = "PLAYWRIGHT_BROWSERS_PATH"; Values = @($PlaywrightBrowsersRoot, (Join-Path $DefaultUserDataDir "playwright")) },
        @{ Name = "DARKWEB_MIGRATION_ROOT"; Values = @($MigrationRoot, (Join-Path $DefaultUserDataDir "migrations")) },
        @{ Name = "DARKWEB_ACTIVE_RELEASE_FILE"; Values = @($ActiveReleaseFile, (Join-Path $DefaultUserDataDir "active-release.json")) },
        @{ Name = "DARKWEB_COLLECTOR_DB_PATH"; Values = @($CollectorDbPath, (Join-Path $DefaultUserDataDir "collector.db")) },
        @{ Name = "DARKWEB_COLLECTOR_SITES_FILE"; Values = @($CollectorSitesFile, (Join-Path $CollectorRoot "sites.yaml")) },
        @{ Name = "DARKWEB_COLLECTOR_OUTPUT_ROOT"; Values = @($CollectorOutputRoot, $ProjectCollectorOutputRoot, $LegacyCollectorOutputRoot) },
        @{ Name = "DARKWEB_AUTH_PASSWORD_FILE"; Values = @($AuthPasswordFile, (Join-Path $DefaultUserDataDir "auth-password.txt")) },
        @{ Name = "DARKWEB_GARNET_DATA_ROOT"; Values = @($GarnetDataRoot, $DefaultGarnetDataRoot) },
        @{ Name = "DARKWEB_TOR_EXPERT_DIR"; Values = @($TorExpertRoot, $DefaultTorExpertRoot) },
        @{ Name = "DARKWEB_API_PORT"; Values = @([string]$ApiPort) },
        @{ Name = "DARKWEB_API_TARGET"; Values = @($ApiBaseUrl) },
        @{ Name = "DARKWEB_FRONTEND_PORT"; Values = @([string]$FrontendPort) },
        @{ Name = "DARKWEB_FRONTEND_URL"; Values = @($FrontendUrl) }
    )
    foreach ($variable in $managedVariables) {
        Remove-ManagedUserEnv -Name $variable.Name -ExpectedValues $variable.Values -WhatIf:$WhatIfPreference -Confirm:$false
    }
    if ($projectOwnsRedisEnvironment) {
        Remove-ManagedUserEnv -Name "REDIS_URL" -ExpectedValues @($ManagedGarnetRedisUrl, $LegacyManagedRedisUrl) -WhatIf:$WhatIfPreference -Confirm:$false
        Remove-ManagedUserEnv -Name "DARKWEB_REDIS_PROVIDER" -ExpectedValues @("garnet") -WhatIf:$WhatIfPreference -Confirm:$false
    }
    foreach ($name in @("DARKWEB_TOR_EXECUTABLE", "DARKWEB_TOR_TRANSPORT_EXECUTABLE", "DARKWEB_TOR_PT_CONFIG_PATH")) {
        Remove-ManagedUserEnv -Name $name -ExpectedRoot $DefaultTorExpertRoot -WhatIf:$WhatIfPreference -Confirm:$false
    }
}

function Uninstall-Darkweb {
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "Low")]
    param(
        [ValidateSet("keep-data", "purge-data")]
        [string]$Mode,
        [switch]$ForceDelete
    )

    if ($Mode -eq "purge-data" -and -not $ForceDelete -and -not $WhatIfPreference) {
        $answer = Read-Host "This permanently deletes the darkweb database, collected output, sessions, and local account settings. Type DELETE to continue"
        if ($answer -cne "DELETE") {
            Stop-WithError "Uninstall cancelled; no data was deleted"
        }
    }

    if ($PSCmdlet.ShouldProcess("darkweb managed services", "Stop before uninstall")) {
        Stop-TorBridgeForUninstall
        Stop-Services
    }

    Remove-DarkwebRegistration -WhatIf:$WhatIfPreference -Confirm:$false
    Remove-ManagedPath -Path $InstallationStatePath -ExpectedPath (Join-Path $UpdateStateRoot "installation.json") -Label "managed installation pointer" -WhatIf:$WhatIfPreference -Confirm:$false
    if (Test-SamePath $VenvDir (Join-Path $CollectorRoot "venv")) {
        Remove-ManagedPath -Path $VenvDir -ExpectedPath (Join-Path $CollectorRoot "venv") -Label "Python virtual environment" -WhatIf:$WhatIfPreference -Confirm:$false
    }
    Remove-ManagedPath -Path $DashboardNodeModulesDir -ExpectedPath (Join-Path $DashboardRoot "node_modules") -Label "dashboard dependencies" -WhatIf:$WhatIfPreference -Confirm:$false
    Remove-ManagedPath -Path $DashboardDistDir -ExpectedPath (Join-Path $DashboardRoot "dist") -Label "dashboard build output" -WhatIf:$WhatIfPreference -Confirm:$false
    Remove-ManagedPath -Path $RuntimeDir -ExpectedPath (Join-Path $CollectorRoot ".runtime\windows") -Label "Windows runtime files" -WhatIf:$WhatIfPreference -Confirm:$false
    Remove-ManagedPath -Path $DefaultTorBridgeRuntimeDir -ExpectedPath (Join-Path $DefaultUserDataDir "tor_bridge_runtime") -Label "Tor bridge runtime files" -WhatIf:$WhatIfPreference -Confirm:$false
    Remove-ManagedPath -Path $DefaultTorBridgeAutoRuntimeDir -ExpectedPath (Join-Path $DefaultUserDataDir "tor_bridge_runtime_auto") -Label "Tor bridge probe runtime files" -WhatIf:$WhatIfPreference -Confirm:$false
    Remove-ManagedPath -Path $DefaultTorExpertRoot -ExpectedPath (Join-Path $DefaultUserDataDir "tor-expert") -Label "project Tor Expert Bundle" -WhatIf:$WhatIfPreference -Confirm:$false
    Remove-ManagedPath -Path $DefaultNpmCacheDir -ExpectedPath (Join-Path $DefaultUserDataDir "npm-cache") -Label "project npm cache" -WhatIf:$WhatIfPreference -Confirm:$false
    Remove-ManagedPath -Path $GarnetRuntimeRoot -ExpectedPath (Join-Path $DefaultRuntimeRoot "garnet\$GarnetVersion") -Label "managed Garnet runtime" -WhatIf:$WhatIfPreference -Confirm:$false
    Remove-ManagedPath -Path $GarnetDotnetRoot -ExpectedPath (Join-Path $DefaultRuntimeRoot "dotnet\$GarnetDotnetVersion") -Label "managed Garnet .NET runtime" -WhatIf:$WhatIfPreference -Confirm:$false
    Remove-ManagedPath -Path $GarnetRuntimeManifest -ExpectedPath (Join-Path $DefaultUserDataDir "garnet-runtime.json") -Label "managed Garnet runtime manifest" -WhatIf:$WhatIfPreference -Confirm:$false
    Remove-EmptyManagedDirectory -Path (Join-Path $DefaultRuntimeRoot "garnet") -ExpectedPath (Join-Path $DefaultRuntimeRoot "garnet") -WhatIf:$WhatIfPreference -Confirm:$false
    Remove-EmptyManagedDirectory -Path (Join-Path $DefaultRuntimeRoot "dotnet") -ExpectedPath (Join-Path $DefaultRuntimeRoot "dotnet") -WhatIf:$WhatIfPreference -Confirm:$false
    Remove-EmptyManagedDirectory -Path $DefaultRuntimeRoot -ExpectedPath (Join-Path $DefaultUserDataDir "runtimes") -WhatIf:$WhatIfPreference -Confirm:$false
    Remove-ManagedPath -Path (Join-Path $CollectorRoot "dump.rdb") -ExpectedPath (Join-Path $CollectorRoot "dump.rdb") -Label "project Redis cache" -WhatIf:$WhatIfPreference -Confirm:$false

    if (-not (Test-SamePath -Left $TorExpertRoot -Right $DefaultTorExpertRoot)) {
        Write-Warn "Preserving custom Tor runtime outside the managed data directory: $TorExpertRoot"
    }

    if ($Mode -eq "purge-data") {
        if (-not (Test-SamePath -Left $GarnetDataRoot -Right $DefaultGarnetDataRoot)) {
            Write-Warn "Preserving custom Garnet data outside the managed user data directory: $GarnetDataRoot"
        }
        if (-not (Test-SamePath -Left $CollectorOutputRoot -Right $ProjectCollectorOutputRoot) -and
            -not (Test-SamePath -Left $CollectorOutputRoot -Right $LegacyCollectorOutputRoot)) {
            Write-Warn "Preserving custom output directory outside managed locations: $CollectorOutputRoot"
        }
        if (-not (Test-SamePath -Left $CollectorDbPath -Right (Join-Path $DefaultUserDataDir "collector.db")) -and
            -not (Test-SamePath -Left $CollectorDbPath -Right $ProjectCollectorDbPath)) {
            Write-Warn "Preserving custom database outside managed locations: $CollectorDbPath"
        }

        Remove-ManagedPath -Path $ProjectCollectorOutputRoot -ExpectedPath (Join-Path $CollectorRoot "output") -Label "collected output" -WhatIf:$WhatIfPreference -Confirm:$false
        Remove-ManagedPath -Path $ProjectCollectorOutputArchiveRoot -ExpectedPath (Join-Path $CollectorRoot "output-archive") -Label "archived collected output" -WhatIf:$WhatIfPreference -Confirm:$false
        foreach ($suffix in @("", "-wal", "-shm", "-journal")) {
            $dbFile = "$ProjectCollectorDbPath$suffix"
            Remove-ManagedPath -Path $dbFile -ExpectedPath ((Join-Path $CollectorRoot "data\collector.db") + $suffix) -Label "project database file" -WhatIf:$WhatIfPreference -Confirm:$false
        }
        if (Test-Path -LiteralPath $DefaultUserDataDir -PathType Container) {
            foreach ($name in @(
                "collector.db", "collector.db-wal", "collector.db-shm", "collector.db-journal",
                "active-release.json", "auth-password.txt", "garnet-runtime.json"
            )) {
                $path = Join-Path $DefaultUserDataDir $name
                Remove-ManagedPath -Path $path -ExpectedPath (Join-Path $DefaultUserDataDir $name) -Label "managed data file" -WhatIf:$WhatIfPreference -Confirm:$false
            }
            foreach ($name in @(
                "output", "migrations", "config", "secrets", "update-backups", "garnet-data",
                "tor-expert", "tor_bridge_runtime", "tor_bridge_runtime_auto", "runtimes", "npm-cache", "playwright"
            )) {
                $path = Join-Path $DefaultUserDataDir $name
                Remove-ManagedPath -Path $path -ExpectedPath (Join-Path $DefaultUserDataDir $name) -Label "managed data directory" -WhatIf:$WhatIfPreference -Confirm:$false
            }
            foreach ($item in Get-ChildItem -LiteralPath $DefaultUserDataDir -Force -ErrorAction Stop) {
                if ($item.Name -ieq "postgresql") {
                    Write-Warn "Preserving PostgreSQL cluster data managed by its Windows service: $($item.FullName)"
                }
                elseif ($item.Name -ieq "app") {
                    Write-Warn "Preserving managed application releases for deferred cleanup: $($item.FullName)"
                }
                else {
                    Write-Warn "Preserving unrecognized data-root item: $($item.FullName)"
                }
            }
            Remove-EmptyManagedDirectory -Path $DefaultUserDataDir -ExpectedPath $DefaultUserDataDir -WhatIf:$WhatIfPreference -Confirm:$false
        }
        Write-Info "Uninstall complete: managed runtime and data were removed"
    }
    else {
        Write-Info "Uninstall complete: data was preserved"
        Write-Info "Preserved database: $CollectorDbPath"
        Write-Info "Preserved collected output: $CollectorOutputRoot"
        Write-Info "Preserved Garnet checkpoints: $GarnetCheckpointDir"
    }
    Write-Info "The source checkout and shared system dependencies were not removed"
}

function Show-Status {
    Load-RuntimePorts
    Write-Info "data-root: $DefaultUserDataDir"
    Write-Info "app-root: $AppRoot"
    Write-Info "control-root: $UpdateStateRoot"
    Write-Info "migration-root: $MigrationRoot"
    Write-Info "sqlite-database: $CollectorDbPath"
    Write-Info "collector-output: $CollectorOutputRoot"
    try {
        $dataDrive = Get-DataRootDriveInfo
        Write-Info "data-root-free: $([Math]::Round($dataDrive.AvailableFreeSpace / 1GB, 2)) GiB"
    }
    catch {
        Write-Warn "Unable to read free space for $DefaultUserDataDir"
    }
    $postgresqlDataDirectory = Get-PostgreSqlDataDirectory
    if ($postgresqlDataDirectory) {
        Write-Info "postgresql-data: $postgresqlDataDirectory"
        if (-not (Test-SamePath -Left $postgresqlDataDirectory -Right $DefaultUserDataDir) -and
            -not (Test-PathUnderRoot -Path $postgresqlDataDirectory -Root $DefaultUserDataDir)) {
            Write-Warn "Existing PostgreSQL data is outside the configured data root; it was not moved automatically."
        }
    }
    $records = @(Get-ServiceRecords)
    if ($records.Count -eq 0) {
        Write-Info "No PID file found for $SessionName"
    }
    else {
        foreach ($record in $records) {
            $pidValue = [int]$record.pid
            $state = if (Test-ProcessRunning -ProcessId $pidValue) { "up" } else { "down" }
            Write-Info "$($record.name): $state (pid $pidValue, log $($record.log))"
        }
    }

    $garnetRecord = $records | Where-Object { $_.name -eq "garnet" } | Select-Object -First 1
    $garnetRunning = @((Get-ManagedGarnetProcesses)).Count -gt 0
    if (Test-RedisReady) {
        $provider = if ($garnetRunning) { "managed Garnet $GarnetVersion" } else { "external Redis-compatible service" }
        Write-Info "redis-compatible: up ($RedisUrl; $provider)"
    }
    else {
        Write-Info "redis-compatible: down ($RedisUrl)"
    }
    if ((Test-Path -LiteralPath $GarnetServerExecutable -PathType Leaf) -or $garnetRecord) {
        $garnetState = if ($garnetRunning) { "up" } else { "down" }
        Write-Info "garnet: $garnetState (version $GarnetVersion; checkpoints $GarnetCheckpointDir)"
    }

    Ensure-TorBridgeRuntime
    if ($script:TorBridgeTorExecutable -and $script:TorBridgeTransportExecutable) {
        Write-Info "tor-bridge-runtime: ready"
    }
    elseif ($script:TorBridgeTorExecutable) {
        Write-Info "tor-bridge-runtime: missing transport plugin"
    }
    else {
        Write-Info "tor-bridge-runtime: project Tor Expert Bundle unavailable"
    }

    if (Test-DarkwebApiReady) {
        Write-Info "api: up ($ApiJobsUrl)"
    }
    else {
        Write-Info "api: down or not this project's API ($ApiHealthUrl must return status ok)"
    }

    if (Test-DarkwebFrontendReady) {
        Write-Info "frontend: up ($FrontendUrl)"
    }
    else {
        Write-Info "frontend: down"
    }
}

function Invoke-WithProjectRuntimeLock {
    param([scriptblock]$Body)
    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($ProjectRoot.ToLowerInvariant())
        $identity = [BitConverter]::ToString($sha256.ComputeHash($bytes)).Replace("-", "").Substring(0, 16)
    }
    finally {
        $sha256.Dispose()
    }

    $lockPath = Join-Path ([System.IO.Path]::GetTempPath()) "DarkWebThreatIntel-$identity.lock"
    $lockStream = $null
    $deadline = [DateTime]::UtcNow.AddMinutes(2)
    try {
        while (-not $lockStream -and [DateTime]::UtcNow -lt $deadline) {
            try {
                $lockStream = [System.IO.File]::Open($lockPath, "OpenOrCreate", "ReadWrite", "None")
            }
            catch [System.IO.IOException] {
                Start-Sleep -Milliseconds 250
            }
        }
        if (-not $lockStream) {
            Stop-WithError "Another darkweb runtime operation is still running for this project."
        }
        & $Body
    }
    finally {
        if ($lockStream) {
            $lockStream.Dispose()
        }
    }
}

$pythonBinding = Read-PythonEnvironmentProfile $PythonEnvironmentState
if ($pythonBinding) { Set-CollectorEnvironment $pythonBinding.root }

switch ($Action) {
    "start" { Invoke-WithProjectRuntimeLock { Start-Services } }
    "stop" { Invoke-WithProjectRuntimeLock { Stop-Services } }
    "status" { Show-Status }
    "install" {
        Invoke-WithProjectRuntimeLock {
            Ensure-Environment
            Write-Info "Environment is ready. Run 'darkweb' to start the system."
        }
    }
    "prepare-update" { Invoke-WithProjectRuntimeLock { Prepare-UpdateEnvironment } }
    "health" { Assert-DarkwebHealth }
    "register" { Invoke-WithProjectRuntimeLock { Register-DarkwebCommand } }
    "uninstall" { Invoke-WithProjectRuntimeLock { Uninstall-Darkweb -Mode $UninstallMode -ForceDelete:$Force -WhatIf:$WhatIfPreference -Confirm:$false } }
}
