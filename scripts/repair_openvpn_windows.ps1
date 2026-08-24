param(
    [string]$StatusFile = ""
)
$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$BundleRoot = Split-Path -Parent $ScriptDir
$OpenVpnDir = Join-Path $BundleRoot "openvpn"
$UacCancelledCode = 1223
if ([string]::IsNullOrWhiteSpace($StatusFile)) { $StatusFile = Join-Path $BundleRoot "data\repair_status.json" }
function Write-Status([string]$State, [string]$Message, [int]$Percentage = 0, [string]$Code = "OK") {
    try {
        $dir = Split-Path -Parent $StatusFile
        if ($dir -and !(Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        @{ state=$State; message=$Message; percentage=$Percentage; code=$Code; updated_at=[int][double]::Parse((Get-Date -UFormat %s)) } |
            ConvertTo-Json -Compress | Set-Content -LiteralPath $StatusFile -Encoding UTF8 -Force
    } catch {}
}
function Read-Constant([string]$Name, [string]$Path) {
    $content = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
    $pattern = "(?m)^" + [regex]::Escape($Name) + "\s*:\s*Final\[[^]]+\]\s*=\s*['\"'](?<value>[^'\"']+)['\"']"
    $m = [regex]::Match($content, $pattern)
    if (-not $m.Success) { throw "无法从 constants.py 读取 $Name" }
    return $m.Groups['value'].Value
}
Write-Status "starting" "正在检查本地修复文件..." 5
$Constants = Join-Path $BundleRoot "src\opensight\core\constants.py"
$Manifest = Join-Path $BundleRoot "SECURITY-MANIFEST.json"
$MsiName=$null; $ExpectedHash=$null; $ExpectedSize=$null; $Version=$null
try {
    if (Test-Path -LiteralPath $Constants -PathType Leaf) {
        $MsiName = Read-Constant "OPENVPN_MSI_NAME" $Constants
        $ExpectedHash = Read-Constant "OPENVPN_MSI_SHA256" $Constants
        $ExpectedSize = [int64](Read-Constant "OPENVPN_MSI_SIZE" $Constants)
        $Version = Read-Constant "OPENVPN_VERSION" $Constants
    } elseif (Test-Path -LiteralPath $Manifest -PathType Leaf) {
        $manifest = Get-Content -LiteralPath $Manifest -Raw -Encoding UTF8 | ConvertFrom-Json
        $artifact = $manifest.artifacts | Where-Object { $_.artifact_name -like "OpenVPN-*.msi" } | Select-Object -First 1
        if (-not $artifact) { throw "安全清单中未找到 OpenVPN 安装包" }
        $MsiName=[IO.Path]::GetFileName($artifact.local_path); $ExpectedHash=[string]$artifact.expected_sha256; $ExpectedSize=[int64]$artifact.file_size_bytes; $Version=[string]$artifact.version
    } else { throw "找不到 OpenVPN 安全校验信息" }
    $Msi = Join-Path $OpenVpnDir $MsiName
    if (!(Test-Path -LiteralPath $Msi -PathType Leaf)) { Write-Status "failed" "本地 OpenVPN 安装包不存在，已停止修复；不会从网络下载文件。" 0 "LOCAL_MSI_MISSING"; exit 1 }
    Write-Status "verifying" "正在校验本地 OpenVPN 安装包..." 30
    if ((Get-Item -LiteralPath $Msi).Length -ne $ExpectedSize) { throw "本地安装包大小校验失败" }
    $ActualHash=(Get-FileHash -LiteralPath $Msi -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($ActualHash -ne $ExpectedHash.ToLowerInvariant()) { throw "本地安装包 SHA-256 校验失败" }
    $principal=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Status "elevating" "正在申请管理员权限，请在 Windows 提示框中点击“是”。" 15
        try {
            $child=Start-Process -FilePath "powershell.exe" -ArgumentList @("-NoProfile","-WindowStyle","Hidden","-ExecutionPolicy","Bypass","-File","`"$PSCommandPath`"","-StatusFile","`"$StatusFile`") -Verb RunAs -Wait -PassThru -ErrorAction Stop
            exit $child.ExitCode
        } catch { Write-Status "failed" "用户取消了管理员授权，驱动没有安装。" 0 "UAC_CANCELLED"; exit $UacCancelledCode }
    }
    Write-Status "installing" "正在使用本地安装包修复 Windows 虚拟网卡驱动..." 60
    $install=Start-Process -FilePath "msiexec.exe" -ArgumentList @("/i","`"$Msi`"","/qn","/norestart") -Wait -PassThru
    if ($install.ExitCode -notin @(0,3010)) { throw "Windows 驱动安装失败，错误代码：$($install.ExitCode)" }
    Write-Status "extracting" "正在整理内置 OpenVPN 运行文件..." 82
    $extract=Join-Path ([IO.Path]::GetTempPath()) ("OpenSight-Extract-"+[guid]::NewGuid().ToString("N")); New-Item -ItemType Directory -Path $extract -Force | Out-Null
    try {
        $admin=Start-Process -FilePath "msiexec.exe" -ArgumentList @("/a","`"$Msi`"","TARGETDIR=`"$extract`"","/qn","/norestart") -Wait -PassThru
        if ($admin.ExitCode -notin @(0,3010)) { throw "无法读取本地 OpenVPN 安装包，错误代码：$($admin.ExitCode)" }
        $bin=Get-ChildItem -LiteralPath $extract -Recurse -Filter "openvpn.exe" -File | Select-Object -First 1
        if (-not $bin) { throw "本地安装包中未找到 openvpn.exe" }
        New-Item -ItemType Directory -Path $OpenVpnDir -Force | Out-Null
        Get-ChildItem -LiteralPath $bin.Directory.FullName -File | ForEach-Object { Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $OpenVpnDir $_.Name) -Force }
        Write-Status "completed" "OpenVPN $Version 驱动与运行文件已就绪。" 100
    } finally { Remove-Item -LiteralPath $extract -Recurse -Force -ErrorAction SilentlyContinue }
} catch { Write-Status "failed" $_.Exception.Message 0 "ERROR"; exit 1 }
exit 0
