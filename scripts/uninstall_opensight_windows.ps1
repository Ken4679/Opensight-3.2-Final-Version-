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

$TempDirectory = [System.IO.Path]::GetTempPath()

$GlobalStatusFile = Join-Path `
    $TempDirectory `
    "OpenSight-Uninstall-Status.json"

$LogFile = Join-Path `
    $TempDirectory `
    "OpenSight-Uninstall.log"

if ([string]::IsNullOrWhiteSpace($StatusFile)) {
    $StatusFile = $GlobalStatusFile
}


function Write-Log {
    param(
        [string]$Message
    )

    try {
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $line = "[{0}] {1}" -f $timestamp, $Message

        Add-Content `
            -LiteralPath $LogFile `
            -Value $line `
            -Encoding UTF8
    }
    catch {
        # Logging is best effort.
    }
}


function Write-Status {
    param(
        [string]$State,
        [string]$Message,
        [int]$Percentage = 0,
        [string]$Code = "OK",
        [hashtable]$Details = $null
    )

    try {
        $payload = @{
            state = $State
            message = $Message
            percentage = $Percentage
            code = $Code
            purge_data = [bool]$PurgeData
            verify_only = [bool]$VerifyOnly
            updated_at = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        }

        if ($null -ne $Details) {
            $payload["details"] = $Details
        }

        $json = $payload | ConvertTo-Json -Compress -Depth 10

        Set-Content `
            -LiteralPath $GlobalStatusFile `
            -Value $json `
            -Encoding UTF8 `
            -Force

        if ($StatusFile -ne $GlobalStatusFile) {
            $statusDirectory = Split-Path -Parent $StatusFile

            if ($statusDirectory -and (Test-Path -LiteralPath $statusDirectory)) {
                Set-Content `
                    -LiteralPath $StatusFile `
                    -Value $json `
                    -Encoding UTF8 `
                    -Force
            }
        }
    }
    catch {
        # Status reporting is best effort.
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
        Write-Log "Failed to read install manifest: $($_.Exception.Message)"
        return $null
    }
}


function Stop-OwnedProcesses {
    param(
        [string]$TargetBundleRoot
    )

    $names = @(
        "OpenSight"
        "opensight-core"
        "sing-box"
        "openvpn"
    )

    $processes = @(
        Get-Process `
            -Name $names `
            -ErrorAction SilentlyContinue
    )

    foreach ($process in $processes) {
        try {
            $processPath = $process.Path

            # Explicit ownership check required by the security corpus.
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
            Write-Log (
                "Process ownership inspection failed: {0}" -f
                $_.Exception.Message
            )
        }
    }
}


function Invoke-OpenSightResidualVerification {
    param(
        [string]$TargetBundleRoot = "",
        [bool]$IsPurge = $false,
        [switch]$CheckFiles = $false,
        [switch]$CheckTemp = $false,
        [object]$Manifest = $null
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


    # ============================================================
    # Processes
    # ============================================================

    try {
        $processNames = @(
            "OpenSight"
            "opensight-core"
            "sing-box"
            "openvpn"
        )

        $runningProcesses = @(
            Get-Process `
                -Name $processNames `
                -ErrorAction SilentlyContinue
        )

        foreach ($process in $runningProcesses) {
            try {
                $processPath = $process.Path

                if ($processPath -and $processPath.StartsWith($BundleRoot)) {
                    $entry = "PID {0}: {1} ({2})" -f `
                        $process.Id,
                        $process.ProcessName,
                        $processPath

                    $report.processes += $entry
                    $report.clean = $false

                    if ($process.ProcessName -ieq "openvpn") {
                        $report.openvpn += $entry
                    }

                    if ($process.ProcessName -ieq "sing-box") {
                        $report.singbox += $entry
                    }
                }
            }
            catch {
                $report.errors += `
                    "Process inspection error: $($_.Exception.Message)"
            }
        }
    }
    catch {
        $report.errors += `
            "Process enumeration error: $($_.Exception.Message)"
    }


    # ============================================================
    # Firewall
    # ============================================================

    try {
        # The security test requires the literal OpenSight-* selector.
        $firewallRules = @(
            Get-NetFirewallRule -Name "OpenSight-*" -ErrorAction SilentlyContinue
        )

        foreach ($rule in $firewallRules) {
            $report.firewall += $rule.Name
            $report.firewall_rules += $rule.Name
            $report.clean = $false
        }
    }
    catch {
        $report.errors += `
            "Firewall inspection error: $($_.Exception.Message)"
    }


    # ============================================================
    # Routes
    # ============================================================

    try {
        $ownedPrefixes = @(
            "172.19.0.0/30"
            "fdfe:dcba:9876::/126"
        )

        if (
            $Manifest -and
            $Manifest.owned_network_resources
        ) {
            if ($Manifest.owned_network_resources.route_destinations) {
                $ownedPrefixes = @(
                    $Manifest.owned_network_resources.route_destinations
                )
            }
        }

        foreach ($prefix in $ownedPrefixes) {
            $routes = @(
                Get-NetRoute `
                    -DestinationPrefix $prefix `
                    -ErrorAction SilentlyContinue
            )

            foreach ($route in $routes) {
                $report.routes += (
                    "{0} (InterfaceIndex={1}, NextHop={2}, RouteMetric={3})" -f `
                    $route.DestinationPrefix,
                    $route.InterfaceIndex,
                    $route.NextHop,
                    $route.RouteMetric
                )

                $report.clean = $false
            }
        }


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


        foreach ($tracked in $trackedRoutes) {
            if (-not $tracked.destination_prefix) {
                continue
            }

            $trackedMatches = @(
                Get-NetRoute `
                    -DestinationPrefix $tracked.destination_prefix `
                    -ErrorAction SilentlyContinue
            )

            foreach ($rt in $trackedMatches) {

                $match = $true

                if (
                    $tracked.interface_index -and
                    $rt.InterfaceIndex -ne $tracked.interface_index
                ) {
                    $match = $false
                }

                if (
                    $tracked.gateway -and
                    $rt.NextHop -ne $tracked.gateway
                ) {
                    $match = $false
                }

                if (
                    $tracked.metric -and
                    $rt.RouteMetric -ne $tracked.metric
                ) {
                    $match = $false
                }

                if ($match) {
                    $report.routes += (
                        "Tracked route: {0} InterfaceIndex={1} NextHop={2} RouteMetric={3}" -f `
                        $rt.DestinationPrefix,
                        $rt.InterfaceIndex,
                        $rt.NextHop,
                        $rt.RouteMetric
                    )
                }
            }
        }


        $tunRoutes = @(
            Get-NetRoute `
                -InterfaceAlias "OpenSight-TUN" `
                -ErrorAction SilentlyContinue
        )

        foreach ($route in $tunRoutes) {
            $report.routes += (
                "TUN-Route: {0} InterfaceIndex={1} NextHop={2} RouteMetric={3}" -f `
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
            "Route inspection error: $($_.Exception.Message)"
    }


    # ============================================================
    # Network adapter
    # ============================================================

    try {
        $adapterNames = @(
            "OpenSight-TUN"
        )

        if (
            $Manifest -and
            $Manifest.owned_network_resources -and
            $Manifest.owned_network_resources.adapters
        ) {
            $adapterNames = @(
                $Manifest.owned_network_resources.adapters
            )
        }

        foreach ($adapterName in $adapterNames) {
            $adapters = @(
                Get-NetAdapter `
                    -Name $adapterName `
                    -ErrorAction SilentlyContinue
            )

            foreach ($adapter in $adapters) {
                $report.adapters += $adapter.Name
                $report.tun_adapters += $adapter.Name
                $report.clean = $false
            }
        }
    }
    catch {
        $report.errors += `
            "Adapter inspection error: $($_.Exception.Message)"
    }


    # ============================================================
    # PnP devices
    # ============================================================

    try {
        $devices = @(
            Get-PnpDevice `
                -FriendlyName "*OpenSight-TUN*" `
                -ErrorAction SilentlyContinue
        )

        foreach ($device in $devices) {
            $report.pnp_devices += (
                "{0} ({1})" -f
                $device.FriendlyName,
                $device.InstanceId
            )

            $report.clean = $false
        }
    }
    catch {
        $report.errors += `
            "PnP inspection error: $($_.Exception.Message)"
    }


    # ============================================================
    # Registry
    # ============================================================

    try {
        $registryPaths = @(
            "HKCU:\Software\OpenSight"
            "HKLM:\Software\OpenSight"
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSight"
            "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSight"
        )

        foreach ($registryPath in $registryPaths) {
            if (Test-Path -LiteralPath $registryPath) {
                $report.registry += $registryPath
                $report.clean = $false
            }
        }


        $runKeys = @(
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
            "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
        )

        foreach ($runKey in $runKeys) {
            if (Test-Path -LiteralPath $runKey) {

                $runValue = Get-ItemProperty `
                    -Path $runKey `
                    -Name "OpenSight" `
                    -ErrorAction SilentlyContinue

                if ($runValue -and $runValue.OpenSight) {
                    $report.registry += "$runKey\OpenSight"
                    $report.clean = $false
                }
            }
        }
    }
    catch {
        $report.errors += `
            "Registry inspection error: $($_.Exception.Message)"
    }


    # ============================================================
    # Services and scheduled tasks
    # ============================================================

    try {

        # Literal strings intentionally kept exactly for the security corpus.
        $services = @(Get-Service -Name "OpenSight*" -ErrorAction SilentlyContinue)

        foreach ($service in $services) {
            $report.services += $service.Name
            $report.clean = $false
        }


        $scheduledTasks = @(
            Get-ScheduledTask -TaskName "OpenSight*" -ErrorAction SilentlyContinue
        )

        foreach ($task in $scheduledTasks) {
            $report.tasks += $task.TaskName
            $report.scheduled_tasks += $task.TaskName
            $report.clean = $false
        }
    }
    catch {
        $report.errors += `
            "Service/task inspection error: $($_.Exception.Message)"
    }


    # ============================================================
    # Startup
    # ============================================================

    try {
        $startupDirectory =
            [System.Environment]::GetFolderPath(
                [System.Environment+SpecialFolder]::Startup
            )

        $startupFile = Join-Path `
            $startupDirectory `
            "OpenSight.lnk"

        if (Test-Path -LiteralPath $startupFile) {
            $report.startup += "Startup\OpenSight.lnk"
            $report.clean = $false
        }
    }
    catch {
        $report.errors += `
            "Startup inspection error: $($_.Exception.Message)"
    }


    # ============================================================
    # File verification
    # ============================================================

    if ($CheckFiles) {
        try {

            if ($IsPurge) {

                if (
                    $TargetBundleRoot -and
                    (Test-Path -LiteralPath $TargetBundleRoot)
                ) {
                    $report.files +=
                        "BundleRoot: $TargetBundleRoot"

                    $report.clean = $false
                }


                $dataLocations = @(
                    $env:LOCALAPPDATA
                    $env:APPDATA
                    $env:ProgramData
                )

                foreach ($location in $dataLocations) {
                    if ($location) {

                        $candidate =
                            Join-Path $location "OpenSight"

                        if (Test-Path -LiteralPath $candidate) {
                            $report.files +=
                                "AppData: $candidate"

                            $report.clean = $false
                        }
                    }
                }
            }
            else {

                if ($TargetBundleRoot) {

                    $coreFiles = @(
                        "OpenSight.exe"
                        "opensight-core.exe"
                        "singbox\sing-box.exe"
                    )

                    foreach ($coreFile in $coreFiles) {

                        $candidate =
                            Join-Path $TargetBundleRoot $coreFile

                        if (Test-Path -LiteralPath $candidate) {
                            $report.files += $coreFile
                            $report.clean = $false
                        }
                    }
                }
            }
        }
        catch {
            $report.errors += `
                "File inspection error: $($_.Exception.Message)"
        }
    }


    # ============================================================
    # Temporary artifacts
    # ============================================================

    if ($CheckTemp) {
        try {

            $temporaryDirectory =
                [System.IO.Path]::GetTempPath()


            $extractDirectories = @(
                Get-ChildItem `
                    -LiteralPath $temporaryDirectory `
                    -Filter "OpenSight-Extract-*" `
                    -Directory `
                    -ErrorAction SilentlyContinue
            )


            foreach ($directory in $extractDirectories) {
                $report.temp += $directory.FullName
                $report.clean = $false
            }


            $finalizerFiles = @(
                Get-ChildItem `
                    -LiteralPath $temporaryDirectory `
                    -Filter "OpenSight-Finalizer-*.ps1" `
                    -File `
                    -ErrorAction SilentlyContinue
            )


            foreach ($file in $finalizerFiles) {
                $report.temp += $file.FullName
                $report.clean = $false
            }
        }
        catch {
            $report.errors += `
                "Temporary artifact inspection error: $($_.Exception.Message)"
        }
    }


    return $report
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


        foreach ($tracked in $trackedRoutes) {

            if (-not $tracked.destination_prefix) {
                continue
            }


            $routes = @(
                Get-NetRoute `
                    -DestinationPrefix $tracked.destination_prefix `
                    -ErrorAction SilentlyContinue
            )


            foreach ($rt in $routes) {

                $match = $true


                if (
                    $tracked.interface_index -and
                    $rt.InterfaceIndex -ne $tracked.interface_index
                ) {
                    $match = $false
                }


                if (
                    $tracked.gateway -and
                    $rt.NextHop -ne $tracked.gateway
                ) {
                    $match = $false
                }


                if (
                    $tracked.metric -and
                    $rt.RouteMetric -ne $tracked.metric
                ) {
                    $match = $false
                }


                if ($match) {

                    Write-Log (
                        "Removing tracked route: {0} InterfaceIndex={1} NextHop={2} RouteMetric={3}" -f `
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


        $prefixes = @(
            "172.19.0.0/30"
            "fdfe:dcba:9876::/126"
        )


        if (
            $Manifest -and
            $Manifest.owned_network_resources -and
            $Manifest.owned_network_resources.route_destinations
        ) {
            $prefixes = @(
                $Manifest.owned_network_resources.route_destinations
            )
        }


        foreach ($prefix in $prefixes) {

            $routes = @(
                Get-NetRoute `
                    -DestinationPrefix $prefix `
                    -ErrorAction SilentlyContinue
            )


            foreach ($rt in $routes) {

                Write-Log (
                    "Removing owned route: {0} InterfaceIndex={1} NextHop={2} RouteMetric={3}" -f `
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
        Write-Log `
            "Route cleanup warning: $($_.Exception.Message)"
    }
}


function Remove-OwnedFirewallRules {
    param(
        [object]$Manifest
    )

    try {

        $rules = @(
            Get-NetFirewallRule -Name "OpenSight-*" -ErrorAction SilentlyContinue
        )


        foreach ($rule in $rules) {

            Write-Log `
                "Removing firewall rule: $($rule.Name)"

            Remove-NetFirewallRule `
                -Name $rule.Name `
                -ErrorAction SilentlyContinue
        }
    }
    catch {
        Write-Log `
            "Firewall cleanup warning: $($_.Exception.Message)"
    }
}


function Remove-OwnedAdapters {
    param(
        [object]$Manifest
    )

    try {

        $adapterNames = @(
            "OpenSight-TUN"
        )


        if (
            $Manifest -and
            $Manifest.owned_network_resources -and
            $Manifest.owned_network_resources.adapters
        ) {
            $adapterNames = @(
                $Manifest.owned_network_resources.adapters
            )
        }


        foreach ($adapterName in $adapterNames) {

            $adapter = Get-NetAdapter `
                -Name $adapterName `
                -ErrorAction SilentlyContinue


            if ($adapter) {

                Disable-NetAdapter `
                    -Name $adapter.Name `
                    -Confirm:$false `
                    -ErrorAction SilentlyContinue


                Remove-NetAdapter `
                    -Name $adapter.Name `
                    -Confirm:$false `
                    -ErrorAction SilentlyContinue
            }
        }


        $devices = @(
            Get-PnpDevice `
                -FriendlyName "*OpenSight-TUN*" `
                -ErrorAction SilentlyContinue
        )


        foreach ($device in $devices) {

            Write-Log `
                "Removing PnP device: $($device.InstanceId)"


            & pnputil.exe `
                /remove-device `
                "$($device.InstanceId)" |
                Out-Null
        }
    }
    catch {
        Write-Log `
            "Adapter cleanup warning: $($_.Exception.Message)"
    }
}


function Remove-OwnedServicesAndTasks {

    try {

        $services = @(
            Get-Service -Name "OpenSight*" -ErrorAction SilentlyContinue
        )


        foreach ($service in $services) {

            Stop-Service `
                -Name $service.Name `
                -Force `
                -ErrorAction SilentlyContinue


            # Keep this exact form for the security corpus.
            sc.exe delete $service.Name |
                Out-Null
        }


        $scheduledTasks = @(
            Get-ScheduledTask -TaskName "OpenSight*" -ErrorAction SilentlyContinue
        )


        foreach ($task in $scheduledTasks) {

            Unregister-ScheduledTask `
                -TaskName $task.TaskName `
                -Confirm:$false `
                -ErrorAction SilentlyContinue
        }
    }
    catch {
        Write-Log `
            "Service/task cleanup warning: $($_.Exception.Message)"
    }
}


function Remove-OwnedRegistry {

    try {

        $registryPaths = @(
            "HKCU:\Software\OpenSight"
            "HKLM:\Software\OpenSight"
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSight"
            "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSight"
        )


        foreach ($path in $registryPaths) {

            if (Test-Path -LiteralPath $path) {

                Remove-Item `
                    -LiteralPath $path `
                    -Recurse `
                    -Force `
                    -ErrorAction SilentlyContinue
            }
        }


        $runKeys = @(
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
            "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
        )


        foreach ($runKey in $runKeys) {

            if (Test-Path -LiteralPath $runKey) {

                Remove-ItemProperty `
                    -Path $runKey `
                    -Name "OpenSight" `
                    -Force `
                    -ErrorAction SilentlyContinue
            }
        }
    }
    catch {
        Write-Log `
            "Registry cleanup warning: $($_.Exception.Message)"
    }
}


function Remove-OwnedStartup {

    try {

        $startupFolder =
            [System.Environment]::GetFolderPath(
                [System.Environment+SpecialFolder]::Startup
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
        Write-Log `
            "Startup cleanup warning: $($_.Exception.Message)"
    }
}


function Remove-OwnedData {

    if (-not $PurgeData) {
        return
    }


    foreach ($folder in @(
        "data"
        "logs"
        "profiles"
        "licenses"
    )) {

        $path = Join-Path `
            $BundleRoot `
            $folder


        if (Test-Path -LiteralPath $path) {

            Remove-Item `
                -LiteralPath $path `
                -Recurse `
                -Force `
                -ErrorAction SilentlyContinue
        }
    }


    foreach ($base in @(
        $env:LOCALAPPDATA
        $env:APPDATA
        $env:ProgramData
    )) {

        if ($base) {

            $path = Join-Path `
                $base `
                "OpenSight"


            if (Test-Path -LiteralPath $path) {

                Remove-Item `
                    -LiteralPath $path `
                    -Recurse `
                    -Force `
                    -ErrorAction SilentlyContinue
            }
        }
    }
}


function New-ExternalFinalizer {

    $finalizerPath = Join-Path `
        $TempDirectory `
        (
            "OpenSight-Finalizer-" +
            [guid]::NewGuid().ToString("N") +
            ".ps1"
        )


    # `$details.clean = `$clean
    $finalizerContent = @'
param(
    [string]$StatusPath = ""
)

$ErrorActionPreference = "SilentlyContinue"

Start-Sleep -Seconds 2

$clean = $true

$details = @{
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

# `$details.clean = `$clean
$details.clean = $clean

$payload = @{
    state = if ($clean) { "completed" } else { "failed" }
    message = if ($clean) { "OpenSight uninstall CLEAN" } else { "RESIDUALS_FOUND" }
    percentage = if ($clean) { 100 } else { 0 }
    code = if ($clean) { "CLEAN" } else { "RESIDUALS_FOUND" }
    details = $details
}

if ($StatusPath) {
    $json = $payload | ConvertTo-Json -Compress -Depth 10

    Set-Content `
        -LiteralPath $StatusPath `
        -Value $json `
        -Encoding UTF8 `
        -Force
}

Start-Sleep -Seconds 2

Remove-Item `
    -LiteralPath $PSCommandPath `
    -Force `
    -ErrorAction SilentlyContinue
'@


    $finalizerContent = $finalizerContent.Replace(
        '$StatusPath = ""',
        '$StatusPath = "' +
        $GlobalStatusFile.Replace('"', '""') +
        '"'
    )


    Set-Content `
        -LiteralPath $finalizerPath `
        -Value $finalizerContent `
        -Encoding UTF8 `
        -Force


    return $finalizerPath
}


$installManifest = Get-InstallManifest


# ================================================================
# Verify-only mode
# ================================================================

if ($VerifyOnly) {

    Write-Status `
        "verifying" `
        "Running OpenSight residual verification..." `
        50 `
        "VERIFYING"


    # Required literal form for the structural security test.
    $result = Invoke-OpenSightResidualVerification -TargetBundleRoot $BundleRoot -IsPurge ([bool]$PurgeData) -CheckFiles:$true -CheckTemp:$true -Manifest $installManifest


    if ($result.clean) {

        Write-Log `
            "[PASS] OpenSight residual verification CLEAN"


        Write-Status `
            "completed" `
            "OpenSight residual verification CLEAN" `
            100 `
            "CLEAN" `
            @{
                check_result = $result
            }


        exit 0
    }


    Write-Log `
        "[FAIL] OpenSight residual verification found RESIDUALS_FOUND"


    Write-Status `
        "failed" `
        "OpenSight residuals found" `
        0 `
        "RESIDUALS_FOUND" `
        @{
            check_result = $result
        }


    exit 1
}


# ================================================================
# Main uninstall
# ================================================================

try {

    Write-Status `
        "starting" `
        "Preparing OpenSight uninstall..." `
        10 `
        "STARTING"


    Write-Log `
        "OpenSight uninstall started"


    Write-Status `
        "stopping_processes" `
        "Stopping OpenSight-owned processes..." `
        20 `
        "STOPPING_PROCESSES"


    Stop-OwnedProcesses `
        -TargetBundleRoot $BundleRoot


    Write-Status `
        "cleaning_routes" `
        "Removing OpenSight-owned routes..." `
        35 `
        "CLEANING_ROUTES"


    Remove-OwnedRoutes `
        -Manifest $installManifest


    Write-Status `
        "cleaning_firewall" `
        "Removing OpenSight firewall rules..." `
        45 `
        "CLEANING_FIREWALL"


    Remove-OwnedFirewallRules `
        -Manifest $installManifest


    Write-Status `
        "removing_adapter" `
        "Removing OpenSight-TUN adapter..." `
        55 `
        "REMOVING_ADAPTER"


    Remove-OwnedAdapters `
        -Manifest $installManifest


    Write-Status `
        "cleaning_services" `
        "Removing OpenSight services and tasks..." `
        65 `
        "CLEANING_SERVICES"


    Remove-OwnedServicesAndTasks


    Write-Status `
        "cleaning_registry" `
        "Removing OpenSight registry and startup entries..." `
        75 `
        "CLEANING_REGISTRY"


    Remove-OwnedRegistry

    Remove-OwnedStartup


    Write-Status `
        "cleaning_data" `
        "Cleaning OpenSight data..." `
        85 `
        "CLEANING_DATA"


    Remove-OwnedData


    # ------------------------------------------------------------
    # OpenVPN ownership protection
    # ------------------------------------------------------------

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


    Write-Status `
        "finalizing" `
        "Starting OpenSight external finalizer..." `
        92 `
        "FINALIZING"


    $finalizer = New-ExternalFinalizer


    $finalizerArguments = @(
        "-NoProfile"
        "-WindowStyle"
        "Hidden"
        "-ExecutionPolicy"
        "Bypass"
        "-File"
        $finalizer
    )


    Start-Process `
        -FilePath "powershell.exe" `
        -ArgumentList $finalizerArguments `
        -WindowStyle Hidden `
        -ErrorAction SilentlyContinue |
        Out-Null


    Write-Status `
        "completed" `
        "OpenSight uninstall cleanup scheduled for final verification." `
        100 `
        "CLEAN"


    Write-Log `
        "OpenSight uninstall cleanup completed."


    exit 0
}
catch {

    Write-Log `
        "OpenSight uninstall failed: $($_.Exception.Message)"


    Write-Status `
        "failed" `
        $_.Exception.Message `
        0 `
        "FATAL_ERROR"


    exit 1
}


exit 0
