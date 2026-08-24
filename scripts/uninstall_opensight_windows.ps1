param(
    [string]$BundleRoot = ""
)

$ErrorActionPreference = "Stop"
$UacCancelledCode = 1223
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if ([string]::IsNullOrWhiteSpace($BundleRoot)) {
    $BundleRoot = Split-Path -Parent $ScriptDir
}
$BundleRoot = [IO.Path]::GetFullPath($BundleRoot)
$Msi = Join-Path $BundleRoot "openvpn\OpenVPN-2.7.5-I001-amd64.msi"

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    try {
        $child = Start-Process -FilePath "powershell.exe" -ArgumentList @(
            "-NoProfile", "-WindowStyle", "Hidden", "-ExecutionPolicy", "Bypass",
            "-File", "`"$PSCommandPath`"",
            "-BundleRoot", "`"$BundleRoot`""
        ) -Verb RunAs -Wait -PassThru -ErrorAction Stop
        exit $child.ExitCode
    }
    catch {
        exit $UacCancelledCode
    }
}

$cleanupReport = @{
    processes_stopped   = $true
    msi_uninstalled     = $true
    firewall_cleaned    = $true
    tun_adapter_removed = $true
    pnp_device_removed  = $true
    critical_failed     = $false
    errors              = @()
}

$logPath = Join-Path ([System.IO.Path]::GetTempPath()) "OpenSight-Uninstall.log"
"--- OpenSight Full Uninstall Started at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ---" | Out-File -FilePath $logPath -Encoding utf8

try {
    # 1. 终止关联进程
    try {
        Get-Process -Name "sing-box","OpenSight","opensight-core","openvpn" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    } catch {
        $cleanupReport.processes_stopped = $false
        $cleanupReport.errors += "进程终止异常: $_"
        "进程终止异常: $_" | Out-File -FilePath $logPath -Append -Encoding utf8
    }

    # 2. 卸载 OpenVPN 驱动（如果存在）
    if (Test-Path -LiteralPath $Msi -PathType Leaf) {
        $proc = Start-Process -FilePath "msiexec.exe" -ArgumentList @(
            "/x", "`"$Msi`"", "/qn", "/norestart"
        ) -Wait -PassThru -ErrorAction SilentlyContinue
        if ($proc -and $proc.ExitCode -notin @(0, 1605, 1614, 3010)) {
            $cleanupReport.msi_uninstalled = $false
            $cleanupReport.critical_failed = $true
            $cleanupReport.errors += "OpenVPN 驱动卸载失败 (msiexec 代码: $($proc.ExitCode))"
            "OpenVPN 驱动卸载失败 (msiexec 代码: $($proc.ExitCode))" | Out-File -FilePath $logPath -Append -Encoding utf8
        }
    }

    # 3. 清理防火墙 KillSwitch 规则
    try {
        $rules = @(Get-NetFirewallRule -Name "OpenSight-KillSwitch-*" -ErrorAction SilentlyContinue)
        foreach ($rule in $rules) {
            Remove-NetFirewallRule -Name $rule.Name -ErrorAction Stop
        }
    } catch {
        $cleanupReport.firewall_cleaned = $false
        $cleanupReport.critical_failed = $true
        $cleanupReport.errors += "防火墙 KillSwitch 规则清理失败: $_"
        "防火墙 KillSwitch 规则清理失败: $_" | Out-File -FilePath $logPath -Append -Encoding utf8
    }

    # 4. 清理 TUN 虚拟网卡
    try {
        $adapter = Get-NetAdapter -Name "OpenSight-TUN" -ErrorAction SilentlyContinue
        if ($adapter) {
            Disable-NetAdapter -Name $adapter.Name -Confirm:$false -ErrorAction SilentlyContinue
            Remove-NetAdapter -Name $adapter.Name -Confirm:$false -ErrorAction Stop
        }
    } catch {
        $cleanupReport.tun_adapter_removed = $false
        $cleanupReport.critical_failed = $true
        $cleanupReport.errors += "OpenSight-TUN 虚拟网卡移除失败: $_"
        "OpenSight-TUN 虚拟网卡移除失败: $_" | Out-File -FilePath $logPath -Append -Encoding utf8
    }

    # 5. 清理 PnP 设备 (严格审计 pnputil 退出码)
    try {
        $devices = @(Get-PnpDevice -FriendlyName "*OpenSight-TUN*" -ErrorAction SilentlyContinue)
        foreach ($device in $devices) {
            & pnputil.exe /remove-device "$($device.InstanceId)" | Out-Null
            if ($LASTEXITCODE -notin @(0, 3010)) {
                $cleanupReport.pnp_device_removed = $false
                $cleanupReport.critical_failed = $true
                $cleanupReport.errors += "PnP 设备清理失败: $($device.InstanceId) (代码: $LASTEXITCODE)"
                "PnP 设备清理失败: $($device.InstanceId) (代码: $LASTEXITCODE)" | Out-File -FilePath $logPath -Append -Encoding utf8
            }
        }
    } catch {
        $cleanupReport.pnp_device_removed = $false
        $cleanupReport.critical_failed = $true
        $cleanupReport.errors += "PnP 设备查询/移除异常: $_"
        "PnP 设备查询/移除异常: $_" | Out-File -FilePath $logPath -Append -Encoding utf8
    }

    # 6. 计算清理状态并生成对应对话框
    $errorsText = $cleanupReport.errors -join "`n"
    $statusType = "COMPLETE"
    if ($cleanupReport.critical_failed) {
        $statusType = "FAILED"
    } elseif ($cleanupReport.errors.Count -gt 0) {
        $statusType = "PARTIAL"
    }

    $escapedBundleRoot = $BundleRoot.Replace("'", "''")
    $escapedLogPath = $logPath.Replace("'", "''")
    $escapedErrorsText = $errorsText.Replace("'", "''").Replace('"', '`"')

    $cleanupScript = @"
Start-Sleep -Seconds 2
`$deleted = `$false
for (`$i = 0; `$i -lt 5; `$i++) {
    try {
        if (Test-Path -LiteralPath '$escapedBundleRoot') {
            Remove-Item -LiteralPath '$escapedBundleRoot' -Recurse -Force -ErrorAction Stop
        }
        `$deleted = `$true
        break
    } catch {
        Start-Sleep -Seconds 1
    }
}

try {
    Add-Type -AssemblyName System.Windows.Forms
    if ('$statusType' -eq 'FAILED') {
        [System.Windows.Forms.MessageBox]::Show(
            "OpenSight 卸载未能完全清理系统组件 (FAILED)！`n`n发生以下关键错误：`n$escapedErrorsText`n`n详细日志位于：$escapedLogPath",
            "OpenSight 卸载失败",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Error
        ) | Out-Null
    } elseif ('$statusType' -eq 'PARTIAL') {
        [System.Windows.Forms.MessageBox]::Show(
            "OpenSight 卸载完成，但有部分非关键告警 (PARTIAL)：`n`n$escapedErrorsText`n`n详细日志位于：$escapedLogPath",
            "OpenSight 卸载完成 (含警告)",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Warning
        ) | Out-Null
    } elseif (-not `$deleted -and (Test-Path -LiteralPath '$escapedBundleRoot')) {
        [System.Windows.Forms.MessageBox]::Show(
            "OpenSight 驱动、虚拟网卡与系统服务已完全清理。`n`n由于便携目录正被资源管理器或其他程序打开占用，未能自动删除文件夹。`n`n请关闭占用窗口后手动删除本目录：`n$escapedBundleRoot",
            "OpenSight 卸载完成",
            [System.Windows.Forms.MessageBoxButtons]::OK,
            [System.Windows.Forms.MessageBoxIcon]::Information
        ) | Out-Null
    }
} catch {}
"@
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cleanupScript))
    Start-Process -FilePath "powershell.exe" -ArgumentList @(
        "-NoProfile", "-WindowStyle", "Hidden", "-ExecutionPolicy", "Bypass", "-EncodedCommand", $encoded
    ) | Out-Null

    if ($statusType -eq "FAILED") {
        exit 1
    } elseif ($statusType -eq "PARTIAL") {
        exit 2
    } else {
        exit 0
    }
}
catch {
    $_ | Out-File -FilePath $logPath -Append -Encoding utf8
    exit 1
}
