param()

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$BundleRoot = Split-Path -Parent $ScriptDir
$Msi = Join-Path $BundleRoot "openvpn\OpenVPN-2.7.5-I001-amd64.msi"
$UacCancelledCode = 1223

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    try {
        $child = Start-Process -FilePath "powershell.exe" -ArgumentList @(
            "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $PSCommandPath
        ) -Verb RunAs -Wait -PassThru -ErrorAction Stop
        exit $child.ExitCode
    }
    catch {
        Write-Error "用户取消了管理员授权，OpenVPN 未卸载。"
        exit $UacCancelledCode
    }
}

if (Test-Path -LiteralPath $Msi -PathType Leaf) {
    $proc = Start-Process -FilePath "msiexec.exe" -ArgumentList @(
        "/x", "`"$Msi`"", "/qn", "/norestart"
    ) -Wait -PassThru
    if ($proc.ExitCode -notin @(0, 1605, 1614)) {
        exit $proc.ExitCode
    }
}

Remove-Item -LiteralPath (Join-Path $BundleRoot "openvpn") -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "OpenVPN 已卸载。"
exit 0