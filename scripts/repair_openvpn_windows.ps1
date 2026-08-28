param(
    [string]$StatusFile = ""
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$BundleRoot = Split-Path -Parent $ScriptDir
$OpenVpnDir = Join-Path $BundleRoot "openvpn"

$UacCancelledCode = 1223

if ([string]::IsNullOrWhiteSpace($StatusFile)) {
    $StatusFile = Join-Path $BundleRoot "data\repair_status.json"
}


function Write-Status {
    param(
        [string]$State,
        [string]$Message,
        [int]$Percentage = 0,
        [string]$Code = "OK"
    )

    try {
        $dir = Split-Path -Parent $StatusFile

        if ($dir -and -not (Test-Path -LiteralPath $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }

        $timestamp = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()

        $status = @{
            state      = $State
            message    = $Message
            percentage = $Percentage
            code       = $Code
            updated_at = $timestamp
        }

        $status |
            ConvertTo-Json -Compress |
            Set-Content -LiteralPath $StatusFile -Encoding UTF8 -Force
    }
    catch {
        # Status reporting must never stop the repair process.
    }
}


function Read-Constant {
    param(
        [string]$Name,
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "constants.py 不存在: $Path"
    }

    $content = Get-Content -LiteralPath $Path -Raw -Encoding UTF8

    # First try the normal Python double-quoted form:
    #
    # NAME: Final[str] = "value"
    #
    # This regex intentionally contains no escaped double quotes.
    $patternDouble = '(?m)^\s*' +
        [regex]::Escape($Name) +
        '\s*:\s*Final\[[^\]]+\]\s*=\s*"(?<value>[^"]+)"'

    $match = [regex]::Match(
        $content,
        $patternDouble
    )

    if ($match.Success) {
        return $match.Groups["value"].Value
    }


    # Also support Python single-quoted form:
    #
    # NAME: Final[str] = 'value'
    #
    $patternSingle = '(?m)^\s*' +
        [regex]::Escape($Name) +
        "\s*:\s*Final\[[^\]]+\]\s*=\s*'(?<value>[^']+)'"

    $match = [regex]::Match(
        $content,
        $patternSingle
    )

    if ($match.Success) {
        return $match.Groups["value"].Value
    }


    throw "无法从 constants.py 读取 $Name"
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


function Get-MsiProductCode {
    param(
        [string]$MsiPath
    )

    $productCode = $null

    try {
        $windowsInstaller = New-Object `
            -ComObject WindowsInstaller.Installer

        $database = $windowsInstaller.GetType().InvokeMember(
            "OpenDatabase",
            "InvokeMethod",
            $null,
            $windowsInstaller,
            @($MsiPath, 0)
        )

        $view = $database.GetType().InvokeMember(
            "OpenView",
            "InvokeMethod",
            $null,
            $database,
            @(
                "SELECT Value FROM Property WHERE Property = 'ProductCode'"
            )
        )

        $view.GetType().InvokeMember(
            "Execute",
            "InvokeMethod",
            $null,
            $view,
            $null
        )

        $record = $view.GetType().InvokeMember(
            "Fetch",
            "InvokeMethod",
            $null,
            $view,
            $null
        )

        if ($record) {
            $productCode = $record.GetType().InvokeMember(
                "StringData",
                "GetProperty",
                $null,
                $record,
                @(1)
            )
        }
    }
    catch {
        $productCode = $null
    }

    return $productCode
}


Write-Status `
    -State "starting" `
    -Message "正在检查本地修复文件..." `
    -Percentage 5 `
    -Code "OK"


$Constants = Join-Path `
    $BundleRoot `
    "src\opensight\core\constants.py"

$SecurityManifest = Join-Path `
    $BundleRoot `
    "SECURITY-MANIFEST.json"


$MsiName = $null
$ExpectedHash = $null
$ExpectedSize = $null
$Version = $null


try {

    # ================================================================
    # Read trusted OpenVPN metadata
    # ================================================================

    if (Test-Path -LiteralPath $Constants -PathType Leaf) {

        $MsiName = Read-Constant `
            -Name "OPENVPN_MSI_NAME" `
            -Path $Constants

        $ExpectedHash = Read-Constant `
            -Name "OPENVPN_MSI_SHA256" `
            -Path $Constants

        $ExpectedSize = [int64](
            Read-Constant `
                -Name "OPENVPN_MSI_SIZE" `
                -Path $Constants
        )

        $Version = Read-Constant `
            -Name "OPENVPN_VERSION" `
            -Path $Constants
    }
    elseif (Test-Path -LiteralPath $SecurityManifest -PathType Leaf) {

        $manifest = Get-Content `
            -LiteralPath $SecurityManifest `
            -Raw `
            -Encoding UTF8 |
            ConvertFrom-Json

        $artifact = $manifest.artifacts |
            Where-Object {
                $_.artifact_name -like "OpenVPN-*.msi"
            } |
            Select-Object -First 1

        if (-not $artifact) {
            throw "安全清单中未找到 OpenVPN 安装包"
        }

        $MsiName = [IO.Path]::GetFileName(
            [string]$artifact.local_path
        )

        $ExpectedHash = [string]$artifact.expected_sha256

        $ExpectedSize = [int64](
            $artifact.file_size_bytes
        )

        $Version = [string]$artifact.version
    }
    else {
        throw "找不到 OpenVPN 安全校验信息"
    }


    # ================================================================
    # Locate local MSI
    # ================================================================

    $Msi = Join-Path `
        $OpenVpnDir `
        $MsiName


    if (-not (Test-Path -LiteralPath $Msi -PathType Leaf)) {

        Write-Status `
            -State "failed" `
            -Message "本地 OpenVPN 安装包不存在，已停止修复；不会从网络下载文件。" `
            -Percentage 0 `
            -Code "LOCAL_MSI_MISSING"

        exit 1
    }


    # ================================================================
    # Verify MSI size
    # ================================================================

    Write-Status `
        -State "verifying" `
        -Message "正在校验本地 OpenVPN 安装包..." `
        -Percentage 30 `
        -Code "VERIFYING"


    $actualSize = (
        Get-Item -LiteralPath $Msi
    ).Length


    if ($actualSize -ne $ExpectedSize) {
        throw "本地安装包大小校验失败"
    }


    # ================================================================
    # Verify MSI SHA-256
    # ================================================================

    $ActualHash = (
        Get-FileHash `
            -LiteralPath $Msi `
            -Algorithm SHA256
    ).Hash.ToLowerInvariant()


    if ($ActualHash -ne $ExpectedHash.ToLowerInvariant()) {
        throw "本地安装包 SHA-256 校验失败"
    }


    # ================================================================
    # Check administrator privileges
    # ================================================================

    if (-not (Test-Administrator)) {

        Write-Status `
            -State "elevating" `
            -Message "正在申请管理员权限，请在 Windows 提示框中点击“是”。" `
            -Percentage 15 `
            -Code "UAC_REQUIRED"


        try {

            $childArguments = @(
                "-NoProfile"
                "-WindowStyle"
                "Hidden"
                "-ExecutionPolicy"
                "Bypass"
                "-File"
                $PSCommandPath
                "-StatusFile"
                $StatusFile
            )


            $child = Start-Process `
                -FilePath "powershell.exe" `
                -ArgumentList $childArguments `
                -Verb RunAs `
                -Wait `
                -PassThru `
                -ErrorAction Stop


            exit $child.ExitCode
        }
        catch {

            Write-Status `
                -State "failed" `
                -Message "用户取消了管理员授权，驱动没有安装。" `
                -Percentage 0 `
                -Code "UAC_CANCELLED"

            exit $UacCancelledCode
        }
    }


    # ================================================================
    # Install OpenVPN
    # ================================================================

    Write-Status `
        -State "installing" `
        -Message "正在使用本地安装包修复 Windows 虚拟网卡驱动..." `
        -Percentage 60 `
        -Code "INSTALLING"


    $installArguments = @(
        "/i"
        $Msi
        "/qn"
        "/norestart"
    )


    $install = Start-Process `
        -FilePath "msiexec.exe" `
        -ArgumentList $installArguments `
        -Wait `
        -PassThru


    if ($install.ExitCode -notin @(0, 3010)) {
        throw "Windows 驱动安装失败，错误代码：$($install.ExitCode)"
    }


    # ================================================================
    # Extract OpenVPN runtime
    # ================================================================

    Write-Status `
        -State "extracting" `
        -Message "正在整理内置 OpenVPN 运行文件..." `
        -Percentage 82 `
        -Code "EXTRACTING"


    $extractName = (
        "OpenSight-Extract-" +
        [guid]::NewGuid().ToString("N")
    )


    $extract = Join-Path `
        ([IO.Path]::GetTempPath()) `
        $extractName


    New-Item `
        -ItemType Directory `
        -Path $extract `
        -Force |
        Out-Null


    try {

        $adminArguments = @(
            "/a"
            $Msi
            "TARGETDIR=$extract"
            "/qn"
            "/norestart"
        )


        $admin = Start-Process `
            -FilePath "msiexec.exe" `
            -ArgumentList $adminArguments `
            -Wait `
            -PassThru


        if ($admin.ExitCode -notin @(0, 3010)) {
            throw "无法读取本地 OpenVPN 安装包，错误代码：$($admin.ExitCode)"
        }


        # ------------------------------------------------------------
        # Find openvpn.exe
        # ------------------------------------------------------------

        $bin = Get-ChildItem `
            -LiteralPath $extract `
            -Recurse `
            -Filter "openvpn.exe" `
            -File |
            Select-Object -First 1


        if (-not $bin) {
            throw "本地安装包中未找到 openvpn.exe"
        }


        # ------------------------------------------------------------
        # Copy runtime files
        # ------------------------------------------------------------

        New-Item `
            -ItemType Directory `
            -Path $OpenVpnDir `
            -Force |
            Out-Null


        Get-ChildItem `
            -LiteralPath $bin.Directory.FullName `
            -File |
            ForEach-Object {

                $target = Join-Path `
                    $OpenVpnDir `
                    $_.Name


                Copy-Item `
                    -LiteralPath $_.FullName `
                    -Destination $target `
                    -Force
            }


        # ------------------------------------------------------------
        # Read MSI ProductCode
        # ------------------------------------------------------------

        $prodCode = Get-MsiProductCode `
            -MsiPath $Msi


        # ------------------------------------------------------------
        # Update installation manifest
        # ------------------------------------------------------------

        $manifestPath = Join-Path `
            $BundleRoot `
            "opensight-install-manifest.json"


        if (Test-Path -LiteralPath $manifestPath -PathType Leaf) {

            try {

                $installationManifest = Get-Content `
                    -LiteralPath $manifestPath `
                    -Raw `
                    -Encoding UTF8 |
                    ConvertFrom-Json


                if ($installationManifest.openvpn_driver_metadata) {

                    $metadata =
                        $installationManifest.openvpn_driver_metadata


                    $metadata.installed_by_opensight = $true


                    $metadata.install_timestamp =
                        [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()


                    $metadata.install_path =
                        $OpenVpnDir


                    $metadata.version =
                        $Version


                    $metadata.expected_sha256 =
                        $ExpectedHash


                    $metadata.source_msi =
                        $MsiName


                    if ($prodCode) {
                        $metadata.msi_product_code =
                            $prodCode
                    }


                    $installationManifest |
                        ConvertTo-Json -Depth 10 |
                        Set-Content `
                            -LiteralPath $manifestPath `
                            -Encoding UTF8 `
                            -Force
                }
            }
            catch {
                # Installation itself succeeded. Manifest metadata is
                # auxiliary and must not invalidate the repair.
            }
        }


        # ============================================================
        # Final success
        # ============================================================

        Write-Status `
            -State "completed" `
            -Message "OpenVPN $Version 驱动与运行文件已就绪。" `
            -Percentage 100 `
            -Code "OK"
    }
    finally {

        Remove-Item `
            -LiteralPath $extract `
            -Recurse `
            -Force `
            -ErrorAction SilentlyContinue
    }
}
catch {

    Write-Status `
        -State "failed" `
        -Message $_.Exception.Message `
        -Percentage 0 `
        -Code "ERROR"

    exit 1
}


exit 0
