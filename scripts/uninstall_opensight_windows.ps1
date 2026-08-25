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

$globalTempStatus = Join-Path ([System.IO.Path]::GetTempPath()) "OpenSight-Uninstall-Status.json"
$logPath = Join-Path ([System.IO.Path]::GetTempPath()) "OpenSight-Uninstall.log"

if ([string]::IsNullOrWhiteSpace($StatusFile)) {
    $StatusFile = $globalTempStatus
}

function Log-Message([string]$Message) {
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    try {
        "[$timestamp] $Message" | Out-File -FilePath $logPath -Append -Encoding utf8
    } catch {}
}

function Write-Status([string]$State, [string]$Message, [int]$Percentage = 0, [string]$Code = "OK", [hashtable]$Details = $null) {
    try {
        $payload = @{
            state = $State
            message = $Message
            percentage = $Percentage
            code = $Code
            purge_data = [bool]$PurgeData
            verify_only = [bool]$VerifyOnly
            updated_at = [int][double]::Parse((Get-Date -UFormat %s))
        }
        if ($Details) {
            $payload["details"] = $Details
        }
        $jsonStr = $payload | ConvertTo-Json -Compress -Depth 5

        # 写入外部全局临时状态文件（持久存在于 Temp 目录，绝不随 BundleRoot 丢失）
        Set-Content -LiteralPath $globalTempStatus -Value $jsonStr -Encoding UTF8 -Force

        # 若指定的状态文件路径不同且所在目录存在，则同步写入
        if ($StatusFile -ne $globalTempStatus) {
            $dir = Split-Path -Parent $StatusFile
            if ($dir -and (Test-Path -LiteralPath $dir)) {
                Set-Content -LiteralPath $StatusFile -Value $jsonStr -Encoding UTF8 -Force
            }
        }
    } catch {}
}

# 1. 检查并申请管理员权限 (RunAs)
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Log-Message "当前非管理员权限，正在请求提升 UAC..."
    Write-Status "elevating" "正在申请 Windows 管理员授权以安全清理虚拟网卡与网络配置..." 10 "ELEVATING"
    
    $argsList = @(
        "-NoProfile", "-WindowStyle", "Hidden", "-ExecutionPolicy", "Bypass",
        "-File", "`"$PSCommandPath`"",
        "-BundleRoot", "`"$BundleRoot`"",
        "-StatusFile", "`"$StatusFile`""
    )
    if ($PurgeData) { $argsList += "-PurgeData" }
    if ($VerifyOnly) { $argsList += "-VerifyOnly" }

    try {
        $child = Start-Process -FilePath "powershell.exe" -ArgumentList $argsList -Verb RunAs -Wait -PassThru -ErrorAction Stop
        exit $child.ExitCode
    } catch {
        Log-Message "用户取消了管理员授权: $_"
        Write-Status "failed" "用户取消了管理员授权，卸载未能执行。" 0 "UAC_CANCELLED"
        exit $UacCancelledCode
    }
}

Log-Message "--- OpenSight 卸载/验证流程启动 (PurgeData: $PurgeData, VerifyOnly: $VerifyOnly) ---"
Log-Message "便携根目录: $BundleRoot"

# 2. 读取安装归属权清单 (Install Manifest)
$ManifestFile = Join-Path $BundleRoot "opensight-install-manifest.json"
$installManifest = $null
if (Test-Path -LiteralPath $ManifestFile -PathType Leaf) {
    try {
        $installManifest = Get-Content -LiteralPath $ManifestFile -Raw -Encoding utf8 | ConvertFrom-Json
        Log-Message "成功读取安装归属权清单: $ManifestFile"
    } catch {
        Log-Message "解析安装清单失败: $_"
    }
}

# 3. 辅助函数：执行系统状态残留自检 (Canonical Evidence-based Residual Verification)
function Invoke-OpenSightResidualVerification(
    [string]$TargetBundleRoot = "",
    [bool]$IsPurge = $false,
    [switch]$CheckFiles = $false,
    [switch]$CheckTemp = $false,
    [object]$Manifest = $null
) {
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

    # A. 检查残留进程 (Scoped by process name and bundle root for ownership proof)
    try {
        $allProcs = Get-Process -ErrorAction SilentlyContinue
        foreach ($p in $allProcs) {
            $pName = $p.ProcessName.ToLowerInvariant()
            if ($pName -in @("opensight", "opensight-core", "sing-box", "openvpn")) {
                try {
                    $pPath = $p.Path
                    if ($pPath -and $TargetBundleRoot -and $pPath.StartsWith($TargetBundleRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
                        if ($pName -eq "sing-box") {
                            $report.singbox += "PID $($p.Id): $($p.ProcessName) ($pPath)"
                        } elseif ($pName -eq "openvpn") {
                            $report.openvpn += "PID $($p.Id): $($p.ProcessName) ($pPath)"
                        }
                        $report.processes += "PID $($p.Id): $($p.ProcessName) ($pPath)"
                        $report.clean = $false
                    } elseif ($pName -in @("opensight", "opensight-core") -and -not $TargetBundleRoot) {
                        # 若未指定 BundleRoot，但发现同名进程，按安全原则记录
                        $report.processes += "PID $($p.Id): $($p.ProcessName)"
                        $report.clean = $false
                    }
                } catch {
                    if ($pName -in @("opensight", "opensight-core") -and -not $TargetBundleRoot) {
                        $report.processes += "PID $($p.Id): $($p.ProcessName)"
                        $report.clean = $false
                    }
                }
            }
        }
    } catch {
        $report.errors += "进程自检异常: $_"
    }

    # B. 检查防火墙规则 (OpenSight-*, OpenSight-KillSwitch-*)
    try {
        $prefixes = @("OpenSight-", "OpenSight-KillSwitch-")
        if ($Manifest -and $Manifest.owned_network_resources -and $Manifest.owned_network_resources.firewall_rule_prefixes) {
            $prefixes = $Manifest.owned_network_resources.firewall_rule_prefixes
        }
        foreach ($pfx in $prefixes) {
            $filterName = if ($pfx.EndsWith("*")) { $pfx } else { $pfx + "*" }
            $rules = @(Get-NetFirewallRule -Name $filterName -ErrorAction SilentlyContinue)
            if ($rules.Count -gt 0) {
                foreach ($r in $rules) {
                    if ($report.firewall -notcontains $r.Name) {
                        $report.firewall += $r.Name
                        $report.firewall_rules += $r.Name
                    }
                }
                $report.clean = $false
            }
        }
    } catch {
        $report.errors += "防火墙自检异常: $_"
    }

    # C. 检查 OpenSight 专属路由 (严格归属校验)
    try {
        $ownedPrefixes = @("172.19.0.0/30", "fdfe:dcba:9876::/126")
        if ($Manifest -and $Manifest.owned_network_resources) {
            if ($Manifest.owned_network_resources.route_destinations) {
                $ownedPrefixes = $Manifest.owned_network_resources.route_destinations
            }
            if ($Manifest.owned_network_resources.tracked_routes) {
                foreach ($tr in $Manifest.owned_network_resources.tracked_routes) {
                    if ($tr.destination_prefix -and $ownedPrefixes -notcontains $tr.destination_prefix) {
                        $ownedPrefixes += $tr.destination_prefix
                    }
                }
            }
        }
        foreach ($pfx in $ownedPrefixes) {
            $routes = @(Get-NetRoute -DestinationPrefix $pfx -ErrorAction SilentlyContinue)
            if ($routes.Count -gt 0) {
                foreach ($rt in $routes) {
                    $report.routes += "$($rt.DestinationPrefix) (ifIndex: $($rt.InterfaceIndex))"
                }
                $report.clean = $false
            }
        }
        # 检查绑定在 OpenSight-TUN 上的任意路由
        $tunRoutes = @(Get-NetRoute -InterfaceAlias "OpenSight-TUN" -ErrorAction SilentlyContinue)
        if ($tunRoutes.Count -gt 0) {
            foreach ($rt in $tunRoutes) {
                $report.routes += "TUN-Route: $($rt.DestinationPrefix)"
            }
            $report.clean = $false
        }
    } catch {
        $report.errors += "路由自检异常: $_"
    }

    # D. 检查 TUN 网卡
    try {
        $adapterNames = @("OpenSight-TUN")
        if ($Manifest -and $Manifest.owned_network_resources -and $Manifest.owned_network_resources.adapters) {
            $adapterNames = $Manifest.owned_network_resources.adapters
        }
        foreach ($aname in $adapterNames) {
            $adapters = @(Get-NetAdapter -Name $aname -ErrorAction SilentlyContinue)
            if ($adapters.Count -gt 0) {
                foreach ($a in $adapters) {
                    $report.adapters += $a.Name
                    $report.tun_adapters += $a.Name
                }
                $report.clean = $false
            }
        }
    } catch {
        $report.errors += "TUN 网卡自检异常: $_"
    }

    # E. 检查 PnP 设备 (仅核验 OpenSight 专属设备，严禁影响系统其他网卡)
    try {
        $devices = @(Get-PnpDevice -FriendlyName "*OpenSight-TUN*" -ErrorAction SilentlyContinue)
        if ($devices.Count -gt 0) {
            foreach ($d in $devices) {
                $report.pnp_devices += "$($d.FriendlyName) ($($d.InstanceId))"
            }
            $report.clean = $false
        }
    } catch {
        $report.errors += "PnP 设备自检异常: $_"
    }

    # F. 检查注册表残留
    try {
        $regKeysToCheck = @(
            "HKCU:\Software\OpenSight",
            "HKLM:\Software\OpenSight",
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSight",
            "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSight"
        )
        foreach ($rk in $regKeysToCheck) {
            if (Test-Path $rk) {
                $report.registry += $rk
                $report.clean = $false
            }
        }
        # 检查 Run 启动项
        $runKeys = @(
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
            "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
        )
        foreach ($runKey in $runKeys) {
            if (Test-Path $runKey) {
                $prop = Get-ItemProperty -Path $runKey -Name "OpenSight" -ErrorAction SilentlyContinue
                if ($prop -and $prop.OpenSight) {
                    $report.registry += "$runKey\OpenSight"
                    $report.clean = $false
                }
            }
        }
    } catch {
        $report.errors += "注册表自检异常: $_"
    }

    # G. 检查服务与计划任务
    try {
        $svcs = @(Get-Service -Name "OpenSight*" -ErrorAction SilentlyContinue)
        if ($svcs.Count -gt 0) {
            foreach ($s in $svcs) { $report.services += $s.Name }
            $report.clean = $false
        }
        $tasks = @(Get-ScheduledTask -TaskName "OpenSight*" -ErrorAction SilentlyContinue)
        if ($tasks.Count -gt 0) {
            foreach ($t in $tasks) {
                $report.tasks += $t.TaskName
                $report.scheduled_tasks += $t.TaskName
            }
            $report.clean = $false
        }
    } catch {
        $report.errors += "任务/服务自检异常: $_"
    }

    # H. 检查启动项快捷方式
    try {
        $startupFile = Join-Path ([System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::Startup)) "OpenSight.lnk"
        if (Test-Path -LiteralPath $startupFile) {
            $report.startup += "Startup\OpenSight.lnk"
            $report.clean = $false
        }
    } catch {
        $report.errors += "启动项自检异常: $_"
    }

    # I. 文件残留自检 (支持 VerifyOnly 与 Full Purge 模式深度核验)
    if ($CheckFiles) {
        try {
            if ($IsPurge) {
                if ($TargetBundleRoot -and (Test-Path -LiteralPath $TargetBundleRoot)) {
                    $report.files += "BundleRoot: $TargetBundleRoot"
                    $report.clean = $false
                }
                foreach ($envDir in @($env:LOCALAPPDATA, $env:APPDATA, $env:ProgramData)) {
                    if ($envDir) {
                        $appDataTarget = Join-Path $envDir "OpenSight"
                        if (Test-Path -LiteralPath $appDataTarget) {
                            $report.files += "AppData: $appDataTarget"
                            $report.clean = $false
                        }
                    }
                }
            } else {
                # 正常模式：校验核心二进制与运行文件已清除
                if ($TargetBundleRoot) {
                    $coreFiles = @("OpenSight.exe", "opensight-core.exe", "singbox\sing-box.exe")
                    foreach ($cf in $coreFiles) {
                        $cfp = Join-Path $TargetBundleRoot $cf
                        if (Test-Path -LiteralPath $cfp) {
                            $report.files += $cf
                            $report.clean = $false
                        }
                    }
                }
            }
        } catch {
            $report.errors += "文件自检异常: $_"
        }
    }

    # J. 临时文件残留自检 (注：%TEMP%\OpenSight-Uninstall.log 为有意保留的诊断日志，不作为残留项)
    if ($CheckTemp) {
        try {
            $tempDir = [System.IO.Path]::GetTempPath()
            $tempExtracts = @(Get-ChildItem -LiteralPath $tempDir -Filter "OpenSight-Extract-*" -Directory -ErrorAction SilentlyContinue)
            foreach ($te in $tempExtracts) {
                $report.temp += $te.FullName
                $report.clean = $false
            }
            # 检查遗留的非活动 Finalizer 脚本
            $tempFinalizers = @(Get-ChildItem -LiteralPath $tempDir -Filter "OpenSight-Finalizer-*.ps1" -File -ErrorAction SilentlyContinue)
            foreach ($tf in $tempFinalizers) {
                $report.temp += $tf.FullName
                $report.clean = $false
            }
        } catch {
            $report.errors += "临时文件自检异常: $_"
        }
    }

    return $report
}

function Invoke-ResidualCheck([switch]$CheckFiles = $false, [switch]$CheckTemp = $false) {
    return Invoke-OpenSightResidualVerification -TargetBundleRoot $BundleRoot -IsPurge:$PurgeData -CheckFiles:$CheckFiles -CheckTemp:$CheckTemp -Manifest $installManifest
}

# 4. 如果是仅验证模式 (-VerifyOnly)，直接运行自检并返回（支持重启后独立核验）
if ($VerifyOnly) {
    Write-Status "verifying" "正在执行系统残留深度自检..." 50 "VERIFYING"
    $check = Invoke-OpenSightResidualVerification -TargetBundleRoot $BundleRoot -IsPurge:$PurgeData -CheckFiles:$true -CheckTemp:$true -Manifest $installManifest
    if ($check.clean) {
        Log-Message "[PASS] 自检完成：未发现任何 OpenSight 残留组件 (CLEAN)"
        Write-Status "completed" "自检通过：系统未发现任何 OpenSight 残留组件 (CLEAN)" 100 "CLEAN" @{ check_result = $check }
        exit 0
    } else {
        Log-Message "[FAIL] 自检发现残留组件: $(ConvertTo-Json $check -Compress)"
        Write-Status "failed" "自检发现残留组件 (RESIDUALS_FOUND)" 0 "RESIDUALS_FOUND" @{ check_result = $check }
        exit 1
    }
}

# 5. 执行完整卸载流水线 (Idempotent Zero-Residual Execution)
try {
    Write-Status "starting" "正在准备卸载 OpenSight..." 15 "STARTING"

    # Step A: 停止 OpenSight 相关进程 (严格基于可执行文件路径与 BundleRoot 归属校验，绝不误杀外部用户程序)
    Write-Status "stopping_processes" "正在安全终止 OpenSight 关联进程..." 25 "STOPPING_PROCESSES"
    Log-Message "正在终止 OpenSight 进程..."
    try {
        $targetProcs = Get-Process -Name "OpenSight", "opensight-core", "sing-box", "openvpn" -ErrorAction SilentlyContinue
        foreach ($p in $targetProcs) {
            try {
                $pPath = $p.Path
                if ($pPath -and $pPath.StartsWith($BundleRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
                    Log-Message "终止 OpenSight 所属进程: $($p.ProcessName) (PID: $($p.Id), Path: $pPath)"
                    Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
                } else {
                    Log-Message "跳过非本便携包外部进程: $($p.ProcessName) (PID: $($p.Id), Path: $pPath) [SKIPPED_EXTERNAL_COMPONENT]"
                }
            } catch {
                Log-Message "无法获取进程路径: $($p.ProcessName) (PID: $($p.Id))"
            }
        }
        Start-Sleep -Milliseconds 500
    } catch {
        Log-Message "进程清理警告: $_"
    }

    # Step B: 精确清理 OpenSight 专属路由 (依据归属元数据精确匹配 DestinationPrefix, InterfaceIndex, NextHop, RouteMetric，禁止任何全局重置)
    Write-Status "cleaning_routes" "正在清理 OpenSight 分流路由表项..." 35 "CLEANING_ROUTES"
    Log-Message "正在清理 OpenSight 专属路由 (精确归属匹配)..."
    try {
        # 1. 优先按安装清单中登记的 tracked_routes 精确匹配清理
        if ($installManifest -and $installManifest.owned_network_resources -and $installManifest.owned_network_resources.tracked_routes) {
            foreach ($tr in $installManifest.owned_network_resources.tracked_routes) {
                if ($tr.destination_prefix) {
                    $matchingRoutes = @(Get-NetRoute -DestinationPrefix $tr.destination_prefix -ErrorAction SilentlyContinue)
                    foreach ($rt in $matchingRoutes) {
                        # 精确匹配 interface_index, gateway / NextHop, metric
                        $match = $true
                        if ($tr.interface_index -and $rt.InterfaceIndex -ne $tr.interface_index) { $match = $false }
                        if ($tr.gateway -and $rt.NextHop -ne $tr.gateway) { $match = $false }
                        if ($tr.metric -and $rt.RouteMetric -ne $tr.metric) { $match = $false }
                        if ($match) {
                            Log-Message "精确移除 OpenSight 记录路由: $($rt.DestinationPrefix) (ifIndex: $($rt.InterfaceIndex), NextHop: $($rt.NextHop), Metric: $($rt.RouteMetric))"
                            Remove-NetRoute -DestinationPrefix $rt.DestinationPrefix -InterfaceIndex $rt.InterfaceIndex -Confirm:$false -ErrorAction SilentlyContinue
                        }
                    }
                }
            }
        }

        # 2. 清理 OpenSight-TUN 虚拟网卡接口上的专属关联路由
        $tunRoutes = @(Get-NetRoute -InterfaceAlias "OpenSight-TUN" -ErrorAction SilentlyContinue)
        foreach ($rt in $tunRoutes) {
            Log-Message "移除网卡关联路由: $($rt.DestinationPrefix) (ifIndex: $($rt.InterfaceIndex))"
            Remove-NetRoute -DestinationPrefix $rt.DestinationPrefix -InterfaceIndex $rt.InterfaceIndex -Confirm:$false -ErrorAction SilentlyContinue
        }

        # 3. 严格限定已知 OpenSight 专属保留分流网段 (172.19.0.0/30, fdfe:dcba:9876::/126)
        $ownedPrefixes = @("172.19.0.0/30", "fdfe:dcba:9876::/126")
        if ($installManifest -and $installManifest.owned_network_resources -and $installManifest.owned_network_resources.route_destinations) {
            $ownedPrefixes = $installManifest.owned_network_resources.route_destinations
        }
        foreach ($pfx in $ownedPrefixes) {
            $routes = @(Get-NetRoute -DestinationPrefix $pfx -ErrorAction SilentlyContinue)
            foreach ($rt in $routes) {
                Log-Message "移除专属保留路由: $($rt.DestinationPrefix) (ifIndex: $($rt.InterfaceIndex))"
                Remove-NetRoute -DestinationPrefix $rt.DestinationPrefix -InterfaceIndex $rt.InterfaceIndex -Confirm:$false -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Log-Message "路由清理异常: $_"
    }

    # Step C: 清理防火墙规则 (严格限定 OpenSight-* 规则前缀，禁止全局重置策略)
    Write-Status "cleaning_firewall" "正在清理 OpenSight 防火墙安全规则..." 45 "CLEANING_FIREWALL"
    Log-Message "正在清理防火墙规则 (OpenSight-*)..."
    try {
        $prefixes = @("OpenSight-", "OpenSight-KillSwitch-")
        if ($installManifest -and $installManifest.owned_network_resources -and $installManifest.owned_network_resources.firewall_rule_prefixes) {
            $prefixes = $installManifest.owned_network_resources.firewall_rule_prefixes
        }
        foreach ($pfx in $prefixes) {
            $filterName = if ($pfx.EndsWith("*")) { $pfx } else { $pfx + "*" }
            $fwRules = @(Get-NetFirewallRule -Name $filterName -ErrorAction SilentlyContinue)
            foreach ($r in $fwRules) {
                Log-Message "删除防火墙规则: $($r.Name)"
                Remove-NetFirewallRule -Name $r.Name -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Log-Message "防火墙规则清理异常: $_"
    }

    # Step D: 清理 TUN 虚拟网卡与 PnP 设备
    Write-Status "removing_adapter" "正在移除 OpenSight-TUN 虚拟网卡..." 55 "REMOVING_ADAPTER"
    Log-Message "正在清理 OpenSight-TUN 虚拟网卡..."
    try {
        $adapterNames = @("OpenSight-TUN")
        if ($installManifest -and $installManifest.owned_network_resources -and $installManifest.owned_network_resources.adapters) {
            $adapterNames = $installManifest.owned_network_resources.adapters
        }
        foreach ($aname in $adapterNames) {
            $tunAdapter = Get-NetAdapter -Name $aname -ErrorAction SilentlyContinue
            if ($tunAdapter) {
                Disable-NetAdapter -Name $tunAdapter.Name -Confirm:$false -ErrorAction SilentlyContinue
                Remove-NetAdapter -Name $tunAdapter.Name -Confirm:$false -ErrorAction SilentlyContinue
            }
        }
    } catch {
        Log-Message "TUN 网卡移除警告: $_"
    }

    try {
        $devices = @(Get-PnpDevice -FriendlyName "*OpenSight-TUN*" -ErrorAction SilentlyContinue)
        foreach ($dev in $devices) {
            Log-Message "移除 PnP 设备: $($dev.InstanceId)"
            & pnputil.exe /remove-device "$($dev.InstanceId)" | Out-Null
        }
    } catch {
        Log-Message "PnP 设备清理警告: $_"
    }

    # Step E: 卸载 OpenSight 拥有的 OpenVPN 组件 (基于安装清单强归属权证明，绝不误删外部 OpenVPN)
    Write-Status "evaluating_openvpn" "正在评估 OpenVPN 组件归属权..." 65 "EVALUATING_OPENVPN"
    $msiPath = Join-Path $BundleRoot "openvpn\OpenVPN-2.7.5-I001-amd64.msi"
    $shouldUninstallOpenVpn = $false
    $msiProductCode = $null

    if ($installManifest -and $installManifest.openvpn_driver_metadata) {
        if ($installManifest.openvpn_driver_metadata.installed_by_opensight) {
            $shouldUninstallOpenVpn = $true
            $msiProductCode = $installManifest.openvpn_driver_metadata.msi_product_code
        }
    }
    
    if (-not $shouldUninstallOpenVpn) {
        # 检查 repair_status.json 作为安装凭据兜底
        $repairStatusFile = Join-Path $BundleRoot "data\repair_status.json"
        if (Test-Path -LiteralPath $repairStatusFile -PathType Leaf) {
            try {
                $rs = Get-Content -LiteralPath $repairStatusFile -Raw -Encoding utf8 | ConvertFrom-Json
                if ($rs.state -eq "completed") {
                    $shouldUninstallOpenVpn = $true
                }
            } catch {}
        }
    }

    if ($shouldUninstallOpenVpn) {
        Log-Message "检测到由 OpenSight 管理的专属 OpenVPN 驱动组件，正在执行安全静默卸载..."
        Write-Status "uninstalling_openvpn" "正在卸载 OpenSight 专属 OpenVPN 驱动..." 75 "UNINSTALLING_OPENVPN"
        try {
            if ($msiProductCode) {
                Log-Message "使用 ProductCode 执行静默卸载: $msiProductCode"
                $msiProc = Start-Process -FilePath "msiexec.exe" -ArgumentList @("/x", "$msiProductCode", "/qn", "/norestart") -Wait -PassThru -ErrorAction SilentlyContinue
                Log-Message "OpenVPN ProductCode 卸载返回码: $($msiProc.ExitCode)"
            } elseif (Test-Path -LiteralPath $msiPath -PathType Leaf) {
                Log-Message "使用本地 MSI 执行静默卸载: $msiPath"
                $msiProc = Start-Process -FilePath "msiexec.exe" -ArgumentList @("/x", "`"$msiPath`"", "/qn", "/norestart") -Wait -PassThru -ErrorAction SilentlyContinue
                Log-Message "OpenVPN MSI 卸载返回码: $($msiProc.ExitCode)"
            }
        } catch {
            Log-Message "OpenVPN 卸载调用异常: $_"
        }
    } else {
        Log-Message "未发现 OpenSight 专属 OpenVPN 驱动安装归属证明，保留外部/系统现有组件 (SKIPPED_EXTERNAL_COMPONENT)。"
    }

    # Step F: 清理注册表、服务、计划任务与启动项
    Write-Status "cleaning_registry" "正在清理注册表配置、服务与计划任务..." 80 "CLEANING_REGISTRY"
    try {
        # 清理注册表项
        $regKeysToRemove = @(
            "HKCU:\Software\OpenSight",
            "HKLM:\Software\OpenSight",
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSight",
            "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSight"
        )
        foreach ($rk in $regKeysToRemove) {
            if (Test-Path $rk) {
                Remove-Item -Path $rk -Recurse -Force -ErrorAction SilentlyContinue
            }
        }
        $runKeys = @(
            "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
            "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
        )
        foreach ($runKey in $runKeys) {
            if (Test-Path $runKey) {
                Remove-ItemProperty -Path $runKey -Name "OpenSight" -Force -ErrorAction SilentlyContinue
            }
        }

        # 清理服务
        $svcs = @(Get-Service -Name "OpenSight*" -ErrorAction SilentlyContinue)
        foreach ($s in $svcs) {
            Stop-Service -Name $s.Name -Force -ErrorAction SilentlyContinue
            & sc.exe delete "$($s.Name)" | Out-Null
        }

        # 清理计划任务
        $tasks = @(Get-ScheduledTask -TaskName "OpenSight*" -ErrorAction SilentlyContinue)
        foreach ($t in $tasks) {
            Unregister-ScheduledTask -TaskName $t.TaskName -Confirm:$false -ErrorAction SilentlyContinue
        }

        # 清理启动项快捷方式
        $startupFile = Join-Path ([System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::Startup)) "OpenSight.lnk"
        if (Test-Path -LiteralPath $startupFile) {
            Remove-Item -LiteralPath $startupFile -Force -ErrorAction SilentlyContinue
        }
    } catch {
        Log-Message "注册表/服务/计划任务清理警告: $_"
    }

    # Step G: 数据目录预清理 (若指定 -PurgeData)
    if ($PurgeData) {
        Write-Status "purging_data" "正在抹除用户数据、凭据与配置..." 88 "PURGING_DATA"
        Log-Message "正在彻底抹除数据目录 (data, logs, profiles, licenses)..."
        foreach ($sub in @("data", "logs", "profiles", "licenses")) {
            $subPath = Join-Path $BundleRoot $sub
            if (Test-Path -LiteralPath $subPath) {
                if ($sub -eq "data") {
                    Get-ChildItem -LiteralPath $subPath -Exclude "uninstall_status.json" -Force -Recurse -ErrorAction SilentlyContinue |
                        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
                } else {
                    Remove-Item -LiteralPath $subPath -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
        }
        
        # 检查并清理 AppData 中的独立缓存（仅当属于 OpenSight 时）
        foreach ($envDir in @($env:LOCALAPPDATA, $env:APPDATA, $env:ProgramData)) {
            if ($envDir) {
                $appDataTarget = Join-Path $envDir "OpenSight"
                if (Test-Path -LiteralPath $appDataTarget) {
                    Remove-Item -LiteralPath $appDataTarget -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
        }
    } else {
        Write-Status "preserving_data" "保留用户数据与节点配置 (正常卸载模式)..." 88 "PRESERVING_DATA"
        Log-Message "保留用户数据目录 (正常模式)。"
    }

    # Step H: 生成外部终态验证与清理调度器 (External Verifier & Finalizer)
    Write-Status "finalizing" "正在启动外部终态验证与收尾流程..." 92 "FINALIZING"
    Log-Message "正在启动外部终态验证与收尾流程..."

    $escapedBundleRoot = $BundleRoot.Replace("'", "''")
    $escapedStatusFile = $StatusFile.Replace("'", "''")
    $escapedGlobalTempStatus = $globalTempStatus.Replace("'", "''")
    $escapedLogPath = $logPath.Replace("'", "''")
    $isPurge = if ($PurgeData) { "true" } else { "false" }

    $externalScriptPath = Join-Path ([System.IO.Path]::GetTempPath()) ("OpenSight-Finalizer-" + [guid]::NewGuid().ToString("N") + ".ps1")
    $escapedExternalScriptPath = $externalScriptPath.Replace("'", "''")

    $externalScriptContent = @"
`$ErrorActionPreference = 'SilentlyContinue'
Start-Sleep -Seconds 2

# 1. 终止残留后台进程并等待完全释放 (严格依据便携包路径归属)
`$maxProcWait = 12
while (`$maxProcWait -gt 0) {
    `$procs = Get-Process -Name 'OpenSight', 'opensight-core', 'sing-box', 'openvpn' -ErrorAction SilentlyContinue
    `$ownedProcs = @()
    foreach (`$p in `$procs) {
        try {
            `$pPath = `$p.Path
            if (`$pPath -and `$pPath.StartsWith('$escapedBundleRoot', [System.StringComparison]::OrdinalIgnoreCase)) {
                `$ownedProcs += `$p
            }
        } catch {}
    }
    if (`$ownedProcs.Count -eq 0) { break }
    foreach (`$p in `$ownedProcs) {
        Stop-Process -Id `$p.Id -Force -ErrorAction SilentlyContinue
    }
    Start-Sleep -Milliseconds 500
    `$maxProcWait--
}

# 2. 尝试删除便携包或内部可执行文件
if ($isPurge -eq 'true') {
    for (`$i = 0; `$i -lt 10; `$i++) {
        if (Test-Path -LiteralPath '$escapedBundleRoot') {
            try {
                Remove-Item -LiteralPath '$escapedBundleRoot' -Recurse -Force -ErrorAction Stop
                break
            } catch {
                Start-Sleep -Milliseconds 800
            }
        } else {
            break
        }
    }
} else {
    # 正常模式：删除核心二进制
    `$binaries = @('OpenSight.exe', 'opensight-core.exe', 'singbox\sing-box.exe', 'openvpn\openvpn.exe')
    foreach (`$b in `$binaries) {
        `$bp = Join-Path '$escapedBundleRoot' `$b
        if (Test-Path -LiteralPath `$bp) {
            Remove-Item -LiteralPath `$bp -Force -ErrorAction SilentlyContinue
        }
    }
}

# 3. 清理临时目录中的 OpenSight 临时文件与解压包 (注：保留诊断日志 %TEMP%\OpenSight-Uninstall.log 供排障查阅)
`$tempBase = [System.IO.Path]::GetTempPath()
`$extractDirs = @(Get-ChildItem -LiteralPath `$tempBase -Filter 'OpenSight-Extract-*' -Directory -ErrorAction SilentlyContinue)
foreach (`$ed in `$extractDirs) {
    Remove-Item -LiteralPath `$ed.FullName -Recurse -Force -ErrorAction SilentlyContinue
}

# 4. 外部终态深度自检 (Canonical Evidence-based External Verification)
`$clean = `$true
`$details = @{
    clean = `$true
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

# 进程检查 (严格基于 BundleRoot 可执行文件路径归属)
`$allProcs = Get-Process -ErrorAction SilentlyContinue
foreach (`$p in `$allProcs) {
    `$pName = `$p.ProcessName.ToLowerInvariant()
    if (`$pName -in @('opensight', 'opensight-core', 'sing-box', 'openvpn')) {
        try {
            `$pPath = `$p.Path
            if (`$pPath -and `$pPath.StartsWith('$escapedBundleRoot', [System.StringComparison]::OrdinalIgnoreCase)) {
                if (`$pName -eq 'sing-box') { `$details.singbox += "PID `$(`$p.Id): `$(`$p.ProcessName) (`$pPath)" }
                elseif (`$pName -eq 'openvpn') { `$details.openvpn += "PID `$(`$p.Id): `$(`$p.ProcessName) (`$pPath)" }
                `$details.processes += "PID `$(`$p.Id): `$(`$p.ProcessName) (`$pPath)"
                `$clean = `$false
            }
        } catch {}
    }
}

# 防火墙检查
`$fw = @(Get-NetFirewallRule -Name 'OpenSight-*' -ErrorAction SilentlyContinue)
if (`$fw.Count -gt 0) {
    `$clean = `$false
    foreach (`$r in `$fw) {
        if (`$details.firewall -notcontains `$r.Name) {
            `$details.firewall += `$r.Name
            `$details.firewall_rules += `$r.Name
        }
    }
}

# 路由检查
`$rt = @(Get-NetRoute -DestinationPrefix '172.19.0.0/30', 'fdfe:dcba:9876::/126' -ErrorAction SilentlyContinue)
if (`$rt.Count -gt 0) { `$clean = `$false; foreach (`$r in `$rt) { `$details.routes += "`$(`$r.DestinationPrefix)" } }
`$tunRt = @(Get-NetRoute -InterfaceAlias 'OpenSight-TUN' -ErrorAction SilentlyContinue)
if (`$tunRt.Count -gt 0) { `$clean = `$false; foreach (`$r in `$tunRt) { `$details.routes += "TUN-Route: `$(`$r.DestinationPrefix)" } }

# TUN 网卡检查
`$tun = @(Get-NetAdapter -Name 'OpenSight-TUN' -ErrorAction SilentlyContinue)
if (`$tun.Count -gt 0) {
    `$clean = `$false
    foreach (`$a in `$tun) {
        `$details.adapters += `$a.Name
        `$details.tun_adapters += `$a.Name
    }
}

# PnP 设备检查 (严格限定 OpenSight 专属设备，严禁影响系统其他网卡)
`$pnp = @(Get-PnpDevice -FriendlyName '*OpenSight-TUN*' -ErrorAction SilentlyContinue)
if (`$pnp.Count -gt 0) { `$clean = `$false; foreach (`$d in `$pnp) { `$details.pnp_devices += "`$(`$d.FriendlyName) (`$(`$d.InstanceId))" } }

# 注册表检查
if (Test-Path 'HKCU:\Software\OpenSight') { `$clean = `$false; `$details.registry += 'HKCU:\Software\OpenSight' }
if (Test-Path 'HKLM:\Software\OpenSight') { `$clean = `$false; `$details.registry += 'HKLM:\Software\OpenSight' }
if (Test-Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSight') { `$clean = `$false; `$details.registry += 'HKCU:\...\Uninstall\OpenSight' }
if (Test-Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenSight') { `$clean = `$false; `$details.registry += 'HKLM:\...\Uninstall\OpenSight' }
foreach (`$runKey in @('HKCU:\Software\Microsoft\Windows\CurrentVersion\Run', 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run')) {
    if (Test-Path `$runKey) {
        `$prop = Get-ItemProperty -Path `$runKey -Name 'OpenSight' -ErrorAction SilentlyContinue
        if (`$prop -and `$prop.OpenSight) {
            `$details.registry += "`$runKey\OpenSight"
            `$clean = `$false
        }
    }
}

# 服务与任务检查
`$svcs = @(Get-Service -Name 'OpenSight*' -ErrorAction SilentlyContinue)
if (`$svcs.Count -gt 0) { `$clean = `$false; foreach (`$s in `$svcs) { `$details.services += `$s.Name } }
`$tasks = @(Get-ScheduledTask -TaskName 'OpenSight*' -ErrorAction SilentlyContinue)
if (`$tasks.Count -gt 0) {
    `$clean = `$false
    foreach (`$t in `$tasks) {
        `$details.tasks += `$t.TaskName
        `$details.scheduled_tasks += `$t.TaskName
    }
}

# 启动项检查
`$startupFile = Join-Path ([System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::Startup)) 'OpenSight.lnk'
if (Test-Path -LiteralPath `$startupFile) { `$clean = `$false; `$details.startup += 'Startup\OpenSight.lnk' }

# 文件检查 (BundleRoot, AppData)
if ($isPurge -eq 'true') {
    if (Test-Path -LiteralPath '$escapedBundleRoot') {
        `$clean = `$false
        `$details.files += "BundleRoot: '$escapedBundleRoot'"
    }
    foreach (`$envDir in @(`$env:LOCALAPPDATA, `$env:APPDATA, `$env:ProgramData)) {
        if (`$envDir) {
            `$appDataTarget = Join-Path `$envDir 'OpenSight'
            if (Test-Path -LiteralPath `$appDataTarget) {
                `$clean = `$false
                `$details.files += "AppData: `$appDataTarget"
            }
        }
    }
    # 检查临时文件目录 (排除有意保留的诊断日志)
    `$remExtracts = @(Get-ChildItem -LiteralPath `$tempBase -Filter 'OpenSight-Extract-*' -Directory -ErrorAction SilentlyContinue)
    if (`$remExtracts.Count -gt 0) {
        `$clean = `$false
        foreach (`$re in `$remExtracts) { `$details.temp += `$re.FullName }
    }
} else {
    `$checkBins = @('OpenSight.exe', 'opensight-core.exe', 'singbox\sing-box.exe')
    foreach (`$cb in `$checkBins) {
        `$cbp = Join-Path '$escapedBundleRoot' `$cb
        if (Test-Path -LiteralPath `$cbp) {
            `$clean = `$false
            `$details.files += `$cb
        }
    }
}

`$details.clean = `$clean

# 5. 写入终态报告 (仅当真正清理完成才置为 completed / CLEAN)
`$finalPayload = @{
    state = if (`$clean) { 'completed' } else { 'failed' }
    message = if (`$clean) { 'OpenSight 卸载与清理圆满完成 (CLEAN)' } else { '卸载已执行，但部分项未能完全清除。' }
    percentage = if (`$clean) { 100 } else { 0 }
    code = if (`$clean) { 'CLEAN' } else { 'RESIDUALS_FOUND' }
    purge_data = ($isPurge -eq 'true')
    verify_only = `$false
    updated_at = [int][double]::Parse((Get-Date -UFormat %s))
    details = `$details
}
`$finalJson = `$finalPayload | ConvertTo-Json -Compress -Depth 5
Set-Content -LiteralPath '$escapedGlobalTempStatus' -Value `$finalJson -Encoding UTF8 -Force

`$dir = Split-Path -Parent '$escapedStatusFile'
if (`$dir -and (Test-Path -LiteralPath `$dir) -and ('$escapedStatusFile' -ne '$escapedGlobalTempStatus')) {
    Set-Content -LiteralPath '$escapedStatusFile' -Value `$finalJson -Encoding UTF8 -Force
}

# 6. 清理辅助脚本
Start-Sleep -Seconds 3
if (Test-Path -LiteralPath '$escapedExternalScriptPath') {
    Remove-Item -LiteralPath '$escapedExternalScriptPath' -Force -ErrorAction SilentlyContinue
}
"@

    Set-Content -LiteralPath $externalScriptPath -Value $externalScriptContent -Encoding UTF8 -Force

    # 启动外部独立收尾进程
    Start-Process -FilePath "powershell.exe" -ArgumentList @(
        "-NoProfile", "-WindowStyle", "Hidden", "-ExecutionPolicy", "Bypass", "-File", "`"$externalScriptPath`""
    ) -ErrorAction SilentlyContinue | Out-Null

    exit 0
} catch {
    Log-Message "卸载过程出现严重异常: $_"
    Write-Status "failed" "卸载异常终止: $($_.Exception.Message)" 0 "FATAL_ERROR"
    exit 1
}
