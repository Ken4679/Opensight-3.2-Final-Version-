param(
    [Parameter(Mandatory=$true)][string]$SingBox,
    [Parameter(Mandatory=$true)][string]$Config,
    [Parameter(Mandatory=$true)][string]$PidFile,
    [Parameter(Mandatory=$true)][string]$StopFile
)

$ErrorActionPreference = "Stop"
$UacCancelledCode = 1223
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    try {
        $child = Start-Process -FilePath "powershell.exe" -ArgumentList @(
            "-NoProfile", "-WindowStyle", "Hidden", "-ExecutionPolicy", "Bypass",
            "-File", "`"$PSCommandPath`"",
            "-SingBox", "`"$SingBox`"",
            "-Config", "`"$Config`"",
            "-PidFile", "`"$PidFile`"",
            "-StopFile", "`"$StopFile`""
        ) -Verb RunAs -Wait -PassThru -ErrorAction Stop
        exit $child.ExitCode
    }
    catch {
        Write-Error "用户取消了管理员授权，应用分流未启动。"
        exit $UacCancelledCode
    }
}

$proc = $null
try {
    $proc = Start-Process -FilePath $SingBox -ArgumentList @("run", "-c", "`"$Config`"") -PassThru -WindowStyle Hidden -WorkingDirectory (Split-Path -Parent $Config)
    $proc.Id | Set-Content -LiteralPath $PidFile -Encoding ascii

    while ($true) {
        if ($proc.HasExited) {
            exit $proc.ExitCode
        }
        if (Test-Path -LiteralPath $StopFile) {
            Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
            exit 0
        }
        Start-Sleep -Milliseconds 300
    }
}
finally {
    Remove-Item -LiteralPath $PidFile -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $Config -Force -ErrorAction SilentlyContinue
}
