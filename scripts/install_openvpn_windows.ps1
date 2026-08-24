$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$BundleRoot = Split-Path -Parent $ScriptDir
$Msi = Join-Path $BundleRoot "openvpn\OpenVPN-2.7.5-I001-amd64.msi"
$UacCancelledCode = 1223

if (!(Test-Path -LiteralPath $Msi -PathType Leaf)) {
    Write-Error "Bundled OpenVPN MSI not found: $Msi"
    exit 1
}

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    try {
        $child = Start-Process -FilePath "powershell.exe" -ArgumentList @(
            "-NoProfile", "-WindowStyle", "Hidden", "-ExecutionPolicy", "Bypass", "-File", $PSCommandPath
        ) -Verb RunAs -Wait -PassThru -ErrorAction Stop
        exit $child.ExitCode
    }
    catch {
        exit $UacCancelledCode
    }
}

$proc = Start-Process -FilePath "msiexec.exe" -ArgumentList @("/i", "`"$Msi`"", "/qn", "/norestart") -Wait -PassThru
exit $proc.ExitCode
