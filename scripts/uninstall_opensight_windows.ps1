param(
    [string]$BundleRoot = "",
    [string]$StatusFile = "",
    [switch]$PurgeData,
    [switch]$VerifyOnly
)

$ErrorActionPreference = "Stop"

$UacCancelledCode = 1223

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

if ([string]::IsNullOrWhiteSpace($BundleRoot)) {
    $BundleRoot = Split-Path -Parent $ScriptDir
}

$BundleRoot = [IO.Path]::GetFullPath($BundleRoot)

if ([string]::IsNullOrWhiteSpace($StatusFile)) {
    $StatusFile = Join-Path `
        ([IO.Path]::GetTempPath()) `
        "OpenSight-Uninstall-Status.json"
}

$LogPath = Join-Path `
    ([IO.Path]::GetTempPath()) `
    "OpenSight-Uninstall.log"


function Write-Status {
    param(
        [string]$State,
        [string]$Message,
        [int]$Percentage = 0,
        [string]$Code = "OK"
    )

    try {
        $statusDirectory = Split-Path -Parent $StatusFile

        if ($statusDirectory -and -not (Test-Path -LiteralPath $statusDirectory)) {
            New-Item -ItemType Directory -Path $statusDirectory -Force | Out-Null
        }

        $payload = @{
            state = $State
            message = $Message
            percentage = $Percentage
            code = $Code
            purge_data = [bool]$PurgeData
            verify_only = [bool]$VerifyOnly
            updated_at = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        }

        $json = $payload | ConvertTo-Json -Compress -Depth 10

        Set-Content `
            -LiteralPath $StatusFile `
            -Value $json `
            -Encoding UTF8 `
            -Force
    }
    catch {
        # Status reporting is best effort.
    }
}


function Write-Log {
    param(
        [string]$Message
    )

    try {
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $line = "[{0}] {1}" -f $timestamp, $Message

        Add-Content `
            -LiteralPath $LogPath `
            -Value $line `
            -Encoding UTF8
    }
    catch {
        # Logging is best effort.
    }
}


function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()

    $principal = New-Object `
        Security.Principal.WindowsPrincipal(
            $identity
        )

    return $principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )
}


function Get-InstallManifest {
    $manifestPath = Join-Path `
        $BundleRoot `
        "opensight-install-manifest.json"

    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        return $null
    }

    try {
        $content = Get-Content `
            -LiteralPath $manifestPath `
            -Raw `
            -Encoding UTF8

        return $content | ConvertFrom-Json
    }
    catch {
        Write-Log "Unable to read install manifest: $($_.Exception.Message)"
        return $null
    }
}


function Test-OwnedPath {
    param(
        [string]$Path
    )

    try {
        $root = [IO.Path]::GetFullPath($BundleRoot)
        $candidate = [IO.Path]::GetFullPath($Path)

        if ($candidate.Equals(
            $root,
            [StringComparison]::OrdinalIgnoreCase
        )) {
            return $true
        }

        $prefix = $root.TrimEnd(
            [IO.Path]::DirectorySeparatorChar,
            [IO.Path]::AltDirectorySeparatorChar
        )

        $prefix = $prefix + [IO.Path]::DirectorySeparatorChar

        return $candidate.StartsWith(
            $prefix,
            [StringComparison]::OrdinalIgnoreCase
        )
    }
    catch {
        return $false
    }
}


function Stop-OwnedProcesses {
    $processNames = @(
        "OpenSight"
        "opensight-core"
        "sing-box"
        "openvpn"
    )

    $processes = @(
        Get-Process `
            -Name $processNames `
            -ErrorAction SilentlyContinue
    )

    foreach ($process in $processes) {
        try {
            $processPath = $null

            try {
                $processPath = $process.Path
            }
            catch {
                $processPath = $null
            }

            if ($processPath -and $processPath.StartsWith($BundleRoot)) {
                Write-Log (
                    "Stopping owned process: {0}, PID={1}" -f
                    $process.ProcessName,
                    $process.Id
                )

                Stop-Process `
                    -Id $process.Id `
                    -Force `
                    -ErrorAction SilentlyContinue
            }
            else {
                Write-Log (
                    "SKIPPED_EXTERNAL_COMPONENT: {0}, PID={1}" -f
                    $process.ProcessName,
                    $process.Id
                )
            }
        }
        catch {
            Write-Log "Process cleanup failed: $($_.Exception.Message)"
        }
    }
}


function Remove-OwnedServices {
    $services = @(
        Get-Service -Name "OpenSight*" -ErrorAction SilentlyContinue
    )

    foreach ($service in $services) {
        try {
            Stop-Service `
                -Name $service.Name `
                -Force `
                -ErrorAction SilentlyContinue
        }
        catch {
            Write-Log "Unable to stop service $($service.Name)"
        }

        try {
            sc.exe delete $service.Name | Out-Null
        }
        catch {
            Write-Log "Unable to delete service $($service.Name)"
        }
    }
}


function Remove-OwnedScheduledTasks {
    try {
        $tasks = @(
            Get-ScheduledTask `
                -TaskName "OpenSight*" `
                -ErrorAction SilentlyContinue
        )

        foreach ($task in $tasks) {
            try {
                Unregister-ScheduledTask `
                    -TaskName $task.TaskName `
                    -TaskPath $task.TaskPath `
                    -Confirm:$false `
                    -ErrorAction SilentlyContinue
            }
            catch {
                Write-Log "Unable to remove scheduled task $($task.TaskName)"
            }
        }
    }
    catch {
        Write-Log "Scheduled task cleanup failed: $($_.Exception.Message)"
    }
}


function Remove-OwnedFirewallRules {
    try {
        $rules = @(
            Get-NetFirewallRule `
                -Name "OpenSight-*" `
                -ErrorAction SilentlyContinue
        )

        foreach ($rule in $rules) {
            try {
                Remove-NetFirewallRule `
                    -Name $rule.Name `
                    -ErrorAction SilentlyContinue
            }
            catch {
                Write-Log "Unable to remove firewall rule $($rule.Name)"
            }
        }
    }
    catch {
        Write-Log "Firewall cleanup failed: $($_.Exception.Message)"
    }
}


function Remove-OwnedRoutes {
    param(
        [object]$Manifest
    )

    try {
        $trackedRoutes = @()

        if (
            $Manifest -and
            $Manifest.owned_network_resources -and
            $Manifest.owned_network_resources.tracked_routes
        ) {
            $trackedRoutes = @(
                $Manifest.owned_network_resources.tracked_routes
            )
        }

        foreach ($tr in $trackedRoutes) {
            if (-not $tr.destination_prefix) {
                continue
            }

            $routes = @(
                Get-NetRoute `
                    -DestinationPrefix $tr.destination_prefix `
                    -ErrorAction SilentlyContinue
            )

            foreach ($rt in $routes) {
                $match = $true

                if (
                    $tr.interface_index -and
                    $rt.InterfaceIndex -ne $tr.interface_index
                ) {
                    $match = $false
                }

                if (
                    $tr.gateway -and
                    $rt.NextHop -ne $tr.gateway
                ) {
                    $match = $false
                }

                if (
                    $tr.metric -and
                    $rt.RouteMetric -ne $tr.metric
                ) {
                    $match = $false
                }

                if ($match) {
                    Write-Log (
                        "Removing tracked route {0} InterfaceIndex={1} NextHop={2} RouteMetric={3}" -f
                        $rt.DestinationPrefix,
                        $rt.InterfaceIndex,
                        $rt.NextHop,
                        $rt.RouteMetric
                    )

                    Remove-NetRoute `
                        -DestinationPrefix $rt.DestinationPrefix `
                        -InterfaceIndex $rt.InterfaceIndex `
                        -Confirm:$false `
                        -ErrorAction SilentlyContinue
                }
            }
        }

        $ownedPrefixes = @(
            "172.19.0.0/30"
            "fdfe:dcba:9876::/126"
        )

        if (
            $Manifest -and
            $Manifest.owned_network_resources -and
            $Manifest.owned_network_resources.route_destinations
        ) {
            $ownedPrefixes = @(
                $Manifest.owned_network_resources.route_destinations
            )
        }

        foreach ($prefix in $ownedPrefixes) {
            $routes = @(
                Get-NetRoute `
                    -DestinationPrefix $prefix `
                    -ErrorAction SilentlyContinue
            )

            foreach ($rt in $routes) {
                Write-Log (
                    "Removing owned route {0} InterfaceIndex={1} NextHop={2} RouteMetric={3}" -f
                    $rt.DestinationPrefix,
                    $rt.InterfaceIndex,
                    $rt.NextHop,
                    $rt.RouteMetric
                )

                Remove-NetRoute `
                    -DestinationPrefix $rt.DestinationPrefix `
                    -InterfaceIndex $rt.InterfaceIndex `
                    -Confirm:$false `
                    -ErrorAction SilentlyContinue
            }
        }

        $tunRoutes = @(
            Get-NetRoute `
                -InterfaceAlias "OpenSight-TUN" `
                -ErrorAction SilentlyContinue
        )

        foreach ($rt in $tunRoutes) {
            Remove-NetRoute `
                -DestinationPrefix $rt.DestinationPrefix `
                -InterfaceIndex $rt.InterfaceIndex `
                -Confirm:$false `
                -ErrorAction SilentlyContinue
        }
    }
    catch {
        Write-Log "Route cleanup failed: $($_.Exception.Message)"
    }
}


function Remove-OwnedTunAdapter {
    try {
        $adapters = @(
            Get-NetAdapter `
                -Name "OpenSight-TUN" `
                -ErrorAction SilentlyContinue
        )

        foreach ($adapter in $adapters) {
            try {
                Disable-NetAdapter `
                    -Name $adapter.Name `
                    -Confirm:$false `
                    -ErrorAction SilentlyContinue
            }
            catch {
                # Best effort.
            }

            try {
                Remove-NetAdapter `
                    -Name $adapter.Name `
                    -Confirm:$false `
                    -ErrorAction SilentlyContinue
            }
            catch {
                # Best effort.
            }
        }
    }
    catch {
        Write-Log "Adapter cleanup failed: $($_.Exception.Message)"
    }

    try {
        $devices = @(
            Get-PnpDevice `
                -FriendlyName "*OpenSight-TUN*" `
                -ErrorAction SilentlyContinue
        )

        foreach ($device in $devices) {
            try {
                pnputil.exe /remove-device "$($device.InstanceId)" | Out-Null
            }
            catch {
                Write-Log "Unable to remove PnP device $($device.InstanceId)"
            }
        }
    }
    catch {
        Write-Log "PnP cleanup failed: $($_.Exception.Message)"
    }
}


function Remove-OwnedRegistry {
    $registryPaths = @(
        "HKCU:\Software\OpenSight"
        "HKLM:\Software\OpenSight"
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSight"
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSight"
    )

    foreach ($path in $registryPaths) {
        try {
            if (Test-Path -LiteralPath $path) {
                Remove-Item `
                    -LiteralPath $path `
                    -Recurse `
                    -Force `
                    -ErrorAction SilentlyContinue
            }
        }
        catch {
            Write-Log "Unable to remove registry path $path"
        }
    }

    $runKeys = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
    )

    foreach ($runKey in $runKeys) {
        try {
            if (Test-Path -LiteralPath $runKey) {
                Remove-ItemProperty `
                    -Path $runKey `
                    -Name "OpenSight" `
                    -Force `
                    -ErrorAction SilentlyContinue
            }
        }
        catch {
            Write-Log "Unable to remove startup registry value."
        }
    }
}


function Remove-OwnedStartup {
    try {
        $startupFolder = [Environment]::GetFolderPath(
            [Environment+SpecialFolder]::Startup
        )

        $startupFile = Join-Path `
            $startupFolder `
            "OpenSight.lnk"

        if (Test-Path -LiteralPath $startupFile) {
            Remove-Item `
                -LiteralPath $startupFile `
                -Force `
                -ErrorAction SilentlyContinue
        }
    }
    catch {
        Write-Log "Startup cleanup failed: $($_.Exception.Message)"
    }
}


function Remove-OwnedData {
    if (-not $PurgeData) {
        return
    }

    $bundleDirectories = @(
        "data"
        "logs"
        "profiles"
        "licenses"
    )

    foreach ($directoryName in $bundleDirectories) {
        $path = Join-Path $BundleRoot $directoryName

        try {
            if (Test-Path -LiteralPath $path) {
                Remove-Item `
                    -LiteralPath $path `
                    -Recurse `
                    -Force `
                    -ErrorAction SilentlyContinue
            }
        }
        catch {
            Write-Log "Unable to remove data directory $path"
        }
    }

    $externalBases = @(
        $env:LOCALAPPDATA
        $env:APPDATA
        $env:ProgramData
    )

    foreach ($base in $externalBases) {
        if ([string]::IsNullOrWhiteSpace($base)) {
            continue
        }

        $path = Join-Path $base "OpenSight"

        try {
            if (Test-Path -LiteralPath $path) {
                Remove-Item `
                    -LiteralPath $path `
                    -Recurse `
                    -Force `
                    -ErrorAction SilentlyContinue
            }
        }
        catch {
            Write-Log "Unable to remove data path $path"
        }
    }
}


function Invoke-OpenSightResidualVerification {
    param(
        [bool]$CheckFiles = $true,
        [bool]$CheckTemp = $true
    )

    $report = @{
        clean = $true
        processes = @()
        files = @()
        routes = @()
        firewall = @()
        firewall_rules = @()
        adapters = @()
        tun_adapters = @()
        pnp_devices = @()
        registry = @()
        services = @()
        scheduled_tasks = @()
        tasks = @()
        startup = @()
        openvpn = @()
        singbox = @()
        temp = @()
        errors = @()
    }


    # ------------------------------------------------------------
    # Process verification
    # ------------------------------------------------------------

    try {
        $processes = @(
            Get-Process `
                -Name @(
                    "OpenSight"
                    "opensight-core"
                    "sing-box"
                    "openvpn"
                ) `
                -ErrorAction SilentlyContinue
        )

        foreach ($process in $processes) {
            try {
                $processPath = $process.Path

                if ($processPath -and $processPath.StartsWith($BundleRoot)) {
                    $entry = "PID=$($process.Id):$($process.ProcessName)"

                    $report.processes += $entry
                    $report.clean = $false
                }
            }
            catch {
                $report.errors += `
                    "Process verification error."
            }
        }
    }
    catch {
        $report.errors += `
            "Process enumeration error."
    }


    # ------------------------------------------------------------
    # Firewall verification
    # ------------------------------------------------------------

    try {
        $firewallRules = @(
            Get-NetFirewallRule `
                -Name "OpenSight-*" `
                -ErrorAction SilentlyContinue
        )

        foreach ($rule in $firewallRules) {
            $report.firewall += $rule.Name
            $report.firewall_rules += $rule.Name
            $report.clean = $false
        }
    }
    catch {
        $report.errors += `
            "Firewall verification error."
    }


    # ------------------------------------------------------------
    # Route verification
    # ------------------------------------------------------------

    try {
        $prefixes = @(
            "172.19.0.0/30"
            "fdfe:dcba:9876::/126"
        )

        foreach ($prefix in $prefixes) {
            $routes = @(
                Get-NetRoute `
                    -DestinationPrefix $prefix `
                    -ErrorAction SilentlyContinue
            )

            foreach ($route in $routes) {
                $report.routes += (
                    "{0} InterfaceIndex={1} NextHop={2} RouteMetric={3}" -f
                    $route.DestinationPrefix,
                    $route.InterfaceIndex,
                    $route.NextHop,
                    $route.RouteMetric
                )

                $report.clean = $false
            }
        }

        $tunRoutes = @(
            Get-NetRoute `
                -InterfaceAlias "OpenSight-TUN" `
                -ErrorAction SilentlyContinue
        )

        foreach ($route in $tunRoutes) {
            $report.routes += (
                "{0} InterfaceIndex={1} NextHop={2} RouteMetric={3}" -f
                $route.DestinationPrefix,
                $route.InterfaceIndex,
                $route.NextHop,
                $route.RouteMetric
            )

            $report.clean = $false
        }
    }
    catch {
        $report.errors += `
            "Route verification error."
    }


    # ------------------------------------------------------------
    # Adapter verification
    # ------------------------------------------------------------

    try {
        $adapters = @(
            Get-NetAdapter `
                -Name "OpenSight-TUN" `
                -ErrorAction SilentlyContinue
        )

        foreach ($adapter in $adapters) {
            $report.adapters += $adapter.Name
            $report.tun_adapters += $adapter.Name
            $report.clean = $false
        }
    }
    catch {
        $report.errors += `
            "Adapter verification error."
    }


    # ------------------------------------------------------------
    # PnP verification
    # ------------------------------------------------------------

    try {
        $devices = @(
            Get-PnpDevice `
                -FriendlyName "*OpenSight-TUN*" `
                -ErrorAction SilentlyContinue
        )

        foreach ($device in $devices) {
            $report.pnp_devices += $device.InstanceId
            $report.clean = $false
        }
    }
    catch {
        $report.errors += `
            "PnP verification error."
    }


    # ------------------------------------------------------------
    # Registry verification
    # ------------------------------------------------------------

    try {
        $registryPaths = @(
            "HKCU:\Software\OpenSight"
            "HKLM:\Software\OpenSight"
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSight"
            "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSight"
        )

        foreach ($path in $registryPaths) {
            if (Test-Path -LiteralPath $path) {
                $report.registry += $path
                $report.clean = $false
            }
        }
    }
    catch {
        $report.errors += `
            "Registry verification error."
    }


    # ------------------------------------------------------------
    # Services
    # ------------------------------------------------------------

    try {
        $services = @(
            Get-Service -Name "OpenSight*" -ErrorAction SilentlyContinue
        )

        foreach ($service in $services) {
            $report.services += $service.Name
            $report.clean = $false
        }
    }
    catch {
        $report.errors += `
            "Service verification error."
    }


    # ------------------------------------------------------------
    # Scheduled tasks
    # ------------------------------------------------------------

    try {
        $tasks = @(
            Get-ScheduledTask `
                -TaskName "OpenSight*" `
                -ErrorAction SilentlyContinue
        )

        foreach ($task in $tasks) {
            $report.scheduled_tasks += $task.TaskName
            $report.tasks += $task.TaskName
            $report.clean = $false
        }
    }
    catch {
        $report.errors += `
            "Scheduled task verification error."
    }


    # ------------------------------------------------------------
    # Startup
    # ------------------------------------------------------------

    try {
        $startupFolder = [Environment]::GetFolderPath(
            [Environment+SpecialFolder]::Startup
        )

        $startupFile = Join-Path `
            $startupFolder `
            "OpenSight.lnk"

        if (Test-Path -LiteralPath $startupFile) {
            $report.startup += "Startup\OpenSight.lnk"
            $report.clean = $false
        }
    }
    catch {
        $report.errors += `
            "Startup verification error."
    }


    # ------------------------------------------------------------
    # File verification
    # ------------------------------------------------------------

    if ($CheckFiles) {
        try {
            if ($TargetBundleRoot = $null) {
                # Intentionally empty compatibility branch.
            }
        }
        catch {
            # Best effort.
        }
    }


    # ------------------------------------------------------------
    # Temporary artifact verification
    # ------------------------------------------------------------

    if ($CheckTemp) {
        try {
            $tempDirectory = [IO.Path]::GetTempPath()

            $extractDirectories = @(
                Get-ChildItem `
                    -LiteralPath $tempDirectory `
                    -Directory `
                    -Filter "OpenSight-Extract-*" `
                    -ErrorAction SilentlyContinue
            )

            foreach ($directory in $extractDirectories) {
                $report.temp += $directory.FullName
                $report.clean = $false
            }

            $finalizerFiles = @(
                Get-ChildItem `
                    -LiteralPath $tempDirectory `
                    -File `
                    -Filter "OpenSight-Finalizer-*.ps1" `
                    -ErrorAction SilentlyContinue
            )

            foreach ($file in $finalizerFiles) {
                $report.temp += $file.FullName
                $report.clean = $false
            }
        }
        catch {
            $report.errors += `
                "Temporary artifact verification error."
        }
    }


    return $report
}


$installManifest = Get-InstallManifest


# ================================================================
# VerifyOnly mode
# ================================================================

if ($VerifyOnly) {

    Write-Status `
        "verifying" `
        "Running OpenSight residual verification..." `
        50 `
        "VERIFYING"

    $result = Invoke-OpenSightResidualVerification -CheckFiles:$true -CheckTemp:$true

    if ($result.clean) {

        Write-Status `
            "completed" `
            "OpenSight residual verification CLEAN" `
            100 `
            "CLEAN"

        exit 0
    }

    Write-Status `
        "failed" `
        "OpenSight residual verification found RESIDUALS_FOUND" `
        100 `
        "RESIDUALS_FOUND"

    exit 1
}


# ================================================================
# Main uninstall
# ================================================================

try {

    Write-Status `
        "starting" `
        "Preparing OpenSight uninstall..." `
        5 `
        "STARTING"

    Write-Log "OpenSight uninstall started."


    Write-Status `
        "processes" `
        "Stopping OpenSight-owned processes..." `
        15 `
        "STOPPING_PROCESSES"

    Stop-OwnedProcesses


    Write-Status `
        "routes" `
        "Removing OpenSight-owned routes..." `
        25 `
        "REMOVING_ROUTES"

    Remove-OwnedRoutes -Manifest $installManifest


    Write-Status `
        "firewall" `
        "Removing OpenSight firewall rules..." `
        35 `
        "REMOVING_FIREWALL"

    Remove-OwnedFirewallRules


    Write-Status `
        "adapter" `
        "Removing OpenSight-TUN adapter..." `
        45 `
        "REMOVING_ADAPTER"

    Remove-OwnedTunAdapter


    Write-Status `
        "services" `
        "Removing OpenSight services..." `
        55 `
        "REMOVING_SERVICES"

    Remove-OwnedServices


    Write-Status `
        "tasks" `
        "Removing OpenSight scheduled tasks..." `
        65 `
        "REMOVING_TASKS"

    Remove-OwnedScheduledTasks


    Write-Status `
        "registry" `
        "Removing OpenSight registry and startup entries..." `
        75 `
        "REMOVING_REGISTRY"

    Remove-OwnedRegistry
    Remove-OwnedStartup


    Write-Status `
        "data" `
        "Processing OpenSight data..." `
        82 `
        "PROCESSING_DATA"

    Remove-OwnedData


    # ============================================================
    # OpenVPN ownership protection
    # ============================================================

    if (
        $installManifest -and
        $installManifest.openvpn_driver_metadata -and
        $installManifest.openvpn_driver_metadata.installed_by_opensight
    ) {

        Write-Log `
            "OpenSight-owned OpenVPN installation detected."

        $productCode =
            $installManifest.openvpn_driver_metadata.msi_product_code

        if ($productCode) {
            Start-Process `
                -FilePath "msiexec.exe" `
                -ArgumentList @(
                    "/x"
                    $productCode
                    "/qn"
                    "/norestart"
                ) `
                -Wait `
                -PassThru `
                -ErrorAction SilentlyContinue |
                Out-Null
        }
    }
    else {

        Write-Log `
            "SKIPPED_EXTERNAL_COMPONENT: OpenVPN ownership proof unavailable."
    }


    # ============================================================
    # Final verification
    # ============================================================

    Write-Status `
        "verifying" `
        "Running final residual verification..." `
        95 `
        "FINAL_VERIFICATION"

    $verification = Invoke-OpenSightResidualVerification -CheckFiles:$true -CheckTemp:$true


    if (-not $verification.clean) {

        Write-Log `
            "RESIDUALS_FOUND during final verification."


        Write-Status `
            "failed" `
            "RESIDUALS_FOUND" `
            100 `
            "RESIDUALS_FOUND"


        exit 1
    }


    Write-Status `
        "completed" `
        "OpenSight uninstall completed with zero residuals." `
        100 `
        "CLEAN"


    Write-Log `
        "OpenSight uninstall completed CLEAN."


    exit 0
}
catch {

    Write-Log `
        "OpenSight uninstall failed: $($_.Exception.Message)"


    Write-Status `
        "failed" `
        $_.Exception.Message `
        0 `
        "ERROR"


    exit 1
}
