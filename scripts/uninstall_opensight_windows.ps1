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
    $StatusFile = Join-Path $BundleRoot "data\uninstall_status.json"
}

$logPath = Join-Path ([System.IO.Path]::GetTempPath()) "OpenSight-Uninstall.log"

function Log-Message([string]$Message) {
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "[$timestamp] $Message" | Out-File -FilePath $logPath -Append -Encoding utf8
}

function Write-Status([string]$State, [string]$Message, [int]$Percentage = 0, [string]$Code = "OK", [hashtable]$Details = $null) {
    try {
        $dir = Split-Path -Parent $StatusFile
        if ($dir -and !(Test-Path -LiteralPath $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
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
        $payload | ConvertTo-Json -Compress -Depth 5 | Set-Content -LiteralPath $StatusFile -Encoding UTF8 -Force
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

# 3. 辅助函数：执行系统状态自检 (Verification)
function Invoke-ResidualCheck() {
    $report = @{
        clean = $true
        processes = @()
        firewall_rules = @()
        tun_adapters = @()
        pnp_devices = @()
        routes = @()
        registry = @()
        services = @()
        tasks = @()
        errors = @()
    }

    # A. 检查残留进程
    try {
        $allProcs = Get-Process -ErrorAction SilentlyContinue
        foreach ($p in $allProcs) {
            $pName = $p.ProcessName.ToLowerInvariant()
            if ($pName -in @("opensight", "opensight-core")) {
                $report.processes += "PID $($p.Id): $($p.ProcessName)"
                $report.clean = $false
            } elseif ($pName -in @("sing-box", "openvpn")) {
                try {
                    $pPath = $p.Path
                    if ($pPath -and $pPath.StartsWith($BundleRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
                        $report.processes += "PID $($p.Id): $($p.ProcessName) ($pPath)"
                        $report.clean = $false
                    }
                } catch {}
            }
        }
    } catch {
        $report.errors += "进程自检异常: $_"
    }

    # B. 检查防火墙规则
    try {
        $rules = @(Get-NetFirewallRule -Name "OpenSight-*" -ErrorAction SilentlyContinue)
        if ($rules.Count -gt 0) {
            foreach ($r in $rules) {
                $report.firewall_rules += $r.Name
            }
            $report.clean = $false
        }
    } catch {
        $report.errors += "防火墙自检异常: $_"
    }

    # C. 检查 TUN 网卡
    try {
        $adapters = @(Get-NetAdapter -Name "OpenSight-TUN" -ErrorAction SilentlyContinue)
        if ($adapters.Count -gt 0) {
            foreach ($a in $adapters) {
                $report.tun_adapters += $a.Name
            }
            $report.clean = $false
        }
    } catch {
        $report.errors += "TUN 网卡自检异常: $_"
    }

    # D. 检查 PnP 设备
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

    # E. 检查注册表残留
    try {
        if (Test-Path "HKCU:\Software\OpenSight") {
            $report.registry += "HKCU:\Software\OpenSight"
            $report.clean = $false
        }
        if (Test-Path "HKLM:\Software\OpenSight") {
            $report.registry += "HKLM:\Software\OpenSight"
            $report.clean = $false
        }
    } catch {
        $report.errors += "注册表自检异常: $_"
    }

    # F. 检查计划任务与服务
    try {
        $tasks = @(Get-ScheduledTask -TaskName "OpenSight*" -ErrorAction SilentlyContinue)
        if ($tasks.Count -gt 0) {
            foreach ($t in $tasks) { $report.tasks += $t.TaskName }
            $report.clean = $false
        }
        $svcs = @(Get-Service -Name "OpenSight*" -ErrorAction SilentlyContinue)
        if ($svcs.Count -gt 0) {
            foreach ($s in $svcs) { $report.services += $s.Name }
            $report.clean = $false
        }
    } catch {
        $report.errors += "任务/服务自检异常: $_"
    }

    return $report
}

# 4. 如果是仅验证模式 (-VerifyOnly)，直接运行自检并返回
if ($VerifyOnly) {
    Write-Status "verifying" "正在执行系统残留深度自检..." 50 "VERIFYING"
    $check = Invoke-ResidualCheck
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

    # Step A: 停止 OpenSight 相关进程 (严格归属校验，绝不误杀外部用户程序)
    Write-Status "stopping_processes" "正在安全终止 OpenSight 关联进程..." 25 "STOPPING_PROCESSES"
    Log-Message "正在终止 OpenSight 进程..."
    try {
        Get-Process -Name "OpenSight", "opensight-core" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        
        # 仅终止位于本便携包内的 sing-box 与 openvpn
        $helperProcs = Get-Process -Name "sing-box", "openvpn" -ErrorAction SilentlyContinue
        foreach ($hp in $helperProcs) {
            try {
                if ($hp.Path -and $hp.Path.StartsWith($BundleRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
                    Log-Message "终止便携包所属子进程: $($hp.ProcessName) (PID: $($hp.Id))"
                    Stop-Process -Id $hp.Id -Force -ErrorAction SilentlyContinue
                }
            } catch {}
        }
        Start-Sleep -Milliseconds 500
    } catch {
        Log-Message "进程清理警告: $_"
    }

    # Step B: 清理防火墙规则 (严格限定 OpenSight-* 规则前缀)
    Write-Status "cleaning_firewall" "正在清理 OpenSight 防火墙安全规则..." 40 "CLEANING_FIREWALL"
    Log-Message "正在清理防火墙规则 (OpenSight-*)..."
    try {
        $fwRules = @(Get-NetFirewallRule -Name "OpenSight-*" -ErrorAction SilentlyContinue)
        foreach ($r in $fwRules) {
            Log-Message "删除防火墙规则: $($r.Name)"
            Remove-NetFirewallRule -Name $r.Name -ErrorAction SilentlyContinue
        }
    } catch {
        Log-Message "防火墙规则清理异常: $_"
    }

    # Step C: 清理 TUN 虚拟网卡与 PnP 设备
    Write-Status "removing_adapter" "正在移除 OpenSight-TUN 虚拟网卡..." 55 "REMOVING_ADAPTER"
    Log-Message "正在清理 OpenSight-TUN 虚拟网卡..."
    try {
        $tunAdapter = Get-NetAdapter -Name "OpenSight-TUN" -ErrorAction SilentlyContinue
        if ($tunAdapter) {
            Disable-NetAdapter -Name $tunAdapter.Name -Confirm:$false -ErrorAction SilentlyContinue
            Remove-NetAdapter -Name $tunAdapter.Name -Confirm:$false -ErrorAction SilentlyContinue
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

    # Step D: 卸载 OpenSight 拥有的 OpenVPN 组件 (严格归属权判定，防误删外部 OpenVPN)
    Write-Status "evaluating_openvpn" "正在评估 OpenVPN 组件归属权..." 70 "EVALUATING_OPENVPN"
    $msiPath = Join-Path $BundleRoot "openvpn\OpenVPN-2.7.5-I001-amd64.msi"
    $shouldUninstallOpenVpn = $false

    if (Test-Path -LiteralPath $msiPath -PathType Leaf) {
        # 检查是否是由 OpenSight 修复/安装的 OpenVPN
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
        Log-Message "检测到由 OpenSight 管理的 OpenVPN 驱动组件，正在执行安全静默卸载..."
        Write-Status "uninstalling_openvpn" "正在卸载 OpenSight 专属 OpenVPN 驱动..." 75 "UNINSTALLING_OPENVPN"
        try {
            $msiProc = Start-Process -FilePath "msiexec.exe" -ArgumentList @("/x", "`"$msiPath`"", "/qn", "/norestart") -Wait -PassThru -ErrorAction SilentlyContinue
            Log-Message "OpenVPN msiexec 卸载返回码: $($msiProc.ExitCode)"
        } catch {
            Log-Message "OpenVPN 卸载调用异常: $_"
        }
    } else {
        Log-Message "未发现 OpenSight 专属 OpenVPN 驱动安装记录，保留外部/系统现有组件 (SKIPPED_EXTERNAL_COMPONENT)。"
    }

    # Step E: 清理注册表与启动项
    Write-Status "cleaning_registry" "正在清理注册表配置与启动项..." 80 "CLEANING_REGISTRY"
    try {
        if (Test-Path "HKCU:\Software\OpenSight") {
            Remove-Item -Path "HKCU:\Software\OpenSight" -Recurse -Force -ErrorAction SilentlyContinue
        }
        if (Test-Path "HKLM:\Software\OpenSight") {
            Remove-Item -Path "HKLM:\Software\OpenSight" -Recurse -Force -ErrorAction SilentlyContinue
        }
        $startupFile = Join-Path ([System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::Startup)) "OpenSight.lnk"
        if (Test-Path -LiteralPath $startupFile) {
            Remove-Item -LiteralPath $startupFile -Force -ErrorAction SilentlyContinue
        }
    } catch {
        Log-Message "注册表/启动项清理警告: $_"
    }

    # Step F: 清理用户数据 (若指定 -PurgeData)
    if ($PurgeData) {
        Write-Status "purging_data" "正在抹除用户数据、凭据与配置..." 88 "PURGING_DATA"
        Log-Message "正在彻底抹除数据目录 (data, logs, profiles)..."
        foreach ($sub in @("data", "logs", "profiles")) {
            $subPath = Join-Path $BundleRoot $sub
            if (Test-Path -LiteralPath $subPath) {
                # 如果是 data 目录，保留 statusFile 供 GUI 轮询，其它文件清理
                if ($sub -eq "data") {
                    Get-ChildItem -LiteralPath $subPath -Exclude "uninstall_status.json" -Force -Recurse -ErrorAction SilentlyContinue |
                        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
                } else {
                    Remove-Item -LiteralPath $subPath -Recurse -Force -ErrorAction SilentlyContinue
                }
            }
        }
        
        # 检查并清理 AppData 中的独立缓存（仅当属于 OpenSight 时）
        foreach ($envDir in @($env:LOCALAPPDATA, $env:APPDATA)) {
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

    # Step G: 卸载后完整性自检 (Verification)
    Write-Status "verifying" "正在执行卸载后完整性自检 (Verification)..." 95 "VERIFYING"
    $verifyResult = Invoke-ResidualCheck

    if ($verifyResult.clean) {
        Log-Message "[SUCCESS] 卸载与自检全部通过 (PASS: CLEAN)！"
        Write-Status "completed" "OpenSight 卸载与清理圆满完成 (CLEAN)" 100 "CLEAN" @{ check_result = $verifyResult }
    } else {
        Log-Message "[WARN] 卸载后自检发现未完全清理项: $(ConvertTo-Json $verifyResult -Compress)"
        Write-Status "failed" "卸载已执行，但部分非关键项未能自动移除。" 0 "PARTIAL_RESIDUALS" @{ check_result = $verifyResult }
    }

    # Step H: 调度便携目录自清理（若 PurgeData 且主进程退出后）
    if ($PurgeData) {
        $escapedBundleRoot = $BundleRoot.Replace("'", "''")
        $selfDeleteScript = @"
Start-Sleep -Seconds 3
for (`$i = 0; `$i -lt 5; `$i++) {
    try {
        if (Test-Path -LiteralPath '$escapedBundleRoot') {
            Remove-Item -LiteralPath '$escapedBundleRoot' -Recurse -Force -ErrorAction Stop
        }
        break
    } catch {
        Start-Sleep -Seconds 1
    }
}
"@
        $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($selfDeleteScript))
        Start-Process -FilePath "powershell.exe" -ArgumentList @(
            "-NoProfile", "-WindowStyle", "Hidden", "-ExecutionPolicy", "Bypass", "-EncodedCommand", $encoded
        ) -ErrorAction SilentlyContinue | Out-Null
    }

    exit 0
} catch {
    Log-Message "卸载过程出现严重异常: $_"
    Write-Status "failed" "卸载异常终止: $($_.Exception.Message)" 0 "FATAL_ERROR"
    exit 1
}
