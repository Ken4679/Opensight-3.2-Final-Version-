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

        $status = @{
            state = $State
            message = $Message
            percentage = $Percentage
            code = $Code
            updated_at = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        }

        $json = $status | ConvertTo-Json -Compress
        Set-Content -LiteralPath $StatusFile -Value $json -Encoding UTF8 -Force
    }
    catch {
        # Status reporting is best effort.
    }
}

function Read-Constant {
    param(
        [string]$Name,
        [string]$Path
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "constants.py not found: $Path"
    }

    $lines = Get-Content -LiteralPath $Path -Encoding UTF8

    foreach ($line in $lines) {
        $trimmed = $line.Trim()

        if (-not $trimmed.StartsWith($Name)) {
            continue
        }

        if (-not $trimmed.Contains("=")) {
            continue
        }

        $parts = $trimmed.Split("=", 2)

        if ($parts.Count -ne 2) {
            continue
        }

        $value = $parts[1].Trim()

        if ($value.Length -ge 2) {
            $first = $value.Substring(0, 1)
            $last = $value.Substring($value.Length - 1, 1)

            if (($first -eq '"') -and ($last -eq '"')) {
                return $value.Substring(1, $value.Length - 2)
            }

            if (($first -eq "'") -and ($last -eq "'")) {
                return $value.Substring(1, $value.Length - 2)
            }
        }

        return $value
    }

    throw "Unable to read $Name from constants.py"
}

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)

    return $principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )
}

function Get-MsiProductCode {
    param(
        [string]$MsiPath
    )

    try {
        $installer = New-Object -ComObject WindowsInstaller.Installer

        $database = $installer.GetType().InvokeMember(
            "OpenDatabase",
            "InvokeMethod",
            $null,
            $installer,
            @($MsiPath, 0)
        )

        $view = $database.GetType().InvokeMember(
            "OpenView",
            "InvokeMethod",
            $null,
            $database,
            @("SELECT Value FROM Property WHERE Property = 'ProductCode'")
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
            return $record.GetType().InvokeMember(
                "StringData",
                "GetProperty",
                $null,
                $record,
                @(1)
            )
        }
    }
    catch {
        return $null
    }

    return $null
}

Write-Status "starting" "Checking local repair files..." 5 "OK"

$Constants = Join-Path $BundleRoot "src\opensight\core\constants.py"
$SecurityManifest = Join-Path $BundleRoot "SECURITY-MANIFEST.json"

$MsiName = $null
$ExpectedHash = $null
$ExpectedSize = $null
$Version = $null

try {
    if (Test-Path -LiteralPath $Constants -PathType Leaf) {
        $MsiName = Read-Constant "OPENVPN_MSI_NAME" $Constants
        $ExpectedHash = Read-Constant "OPENVPN_MSI_SHA256" $Constants
        $ExpectedSize = [int64](Read-Constant "OPENVPN_MSI_SIZE" $Constants)
        $Version = Read-Constant "OPENVPN_VERSION" $Constants
    }
    elseif (Test-Path -LiteralPath $SecurityManifest -PathType Leaf) {
        $manifestJson = Get-Content -LiteralPath $SecurityManifest -Raw -Encoding UTF8
        $manifest = $manifestJson | ConvertFrom-Json

        $artifact = $manifest.artifacts |
            Where-Object { $_.artifact_name -like "OpenVPN-*.msi" } |
            Select-Object -First 1

        if (-not $artifact) {
            throw "OpenVPN MSI entry not found in SECURITY-MANIFEST.json"
        }

        $MsiName = [IO.Path]::GetFileName([string]$artifact.local_path)
        $ExpectedHash = [string]$artifact.expected_sha256
        $ExpectedSize = [int64]$artifact.file_size_bytes
        $Version = [string]$artifact.version
    }
    else {
        throw "OpenVPN security metadata not found"
    }

    $Msi = Join-Path $OpenVpnDir $MsiName

    if (-not (Test-Path -LiteralPath $Msi -PathType Leaf)) {
        Write-Status "failed" "Local OpenVPN MSI is missing. No network download will be attempted." 0 "LOCAL_MSI_MISSING"
        exit 1
    }

    Write-Status "verifying" "Verifying local OpenVPN MSI..." 30 "VERIFYING"

    $actualSize = (Get-Item -LiteralPath $Msi).Length

    if ($actualSize -ne $ExpectedSize) {
        throw "OpenVPN MSI size verification failed"
    }

    $ActualHash = (Get-FileHash -LiteralPath $Msi -Algorithm SHA256).Hash.ToLowerInvariant()
    $ExpectedHashNormalized = $ExpectedHash.ToLowerInvariant()

    if ($ActualHash -ne $ExpectedHashNormalized) {
        throw "OpenVPN MSI SHA-256 verification failed"
    }

    if (-not (Test-Administrator)) {
        Write-Status "elevating" "Requesting administrator privileges..." 15 "UAC_REQUIRED"

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
            Write-Status "failed" "Administrator authorization was cancelled." 0 "UAC_CANCELLED"
            exit $UacCancelledCode
        }
    }

    Write-Status "installing" "Installing OpenVPN Windows driver..." 60 "INSTALLING"

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
        throw "OpenVPN driver installation failed with code $($install.ExitCode)"
    }

    Write-Status "extracting" "Extracting OpenVPN runtime files..." 82 "EXTRACTING"

    $extract = Join-Path `
        ([IO.Path]::GetTempPath()) `
        ("OpenSight-Extract-" + [guid]::NewGuid().ToString("N"))

    New-Item -ItemType Directory -Path $extract -Force | Out-Null

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
            throw "OpenVPN MSI administrative extraction failed with code $($admin.ExitCode)"
        }

        $bin = Get-ChildItem `
            -LiteralPath $extract `
            -Recurse `
            -Filter "openvpn.exe" `
            -File |
            Select-Object -First 1

        if (-not $bin) {
            throw "openvpn.exe was not found inside the OpenVPN MSI"
        }

        New-Item `
            -ItemType Directory `
            -Path $OpenVpnDir `
            -Force |
            Out-Null

        $runtimeFiles = Get-ChildItem `
            -LiteralPath $bin.Directory.FullName `
            -File

        foreach ($file in $runtimeFiles) {
            $target = Join-Path $OpenVpnDir $file.Name
            Copy-Item `
                -LiteralPath $file.FullName `
                -Destination $target `
                -Force
        }

        $prodCode = Get-MsiProductCode -MsiPath $Msi

        $manifestPath = Join-Path $BundleRoot "opensight-install-manifest.json"

        if (Test-Path -LiteralPath $manifestPath -PathType Leaf) {
            try {
                $installationManifestJson = Get-Content `
                    -LiteralPath $manifestPath `
                    -Raw `
                    -Encoding UTF8

                $installationManifest = $installationManifestJson | ConvertFrom-Json

                if ($installationManifest.openvpn_driver_metadata) {
                    $metadata = $installationManifest.openvpn_driver_metadata

                    $metadata.installed_by_opensight = $true
                    $metadata.install_timestamp = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
                    $metadata.install_path = $OpenVpnDir
                    $metadata.version = $Version
                    $metadata.expected_sha256 = $ExpectedHash
                    $metadata.source_msi = $MsiName

                    if ($prodCode) {
                        $metadata.msi_product_code = $prodCode
                    }

                    $updatedManifest = $installationManifest | ConvertTo-Json -Depth 10

                    Set-Content `
                        -LiteralPath $manifestPath `
                        -Value $updatedManifest `
                        -Encoding UTF8 `
                        -Force
                }
            }
            catch {
                # Installation succeeded; manifest update is optional.
            }
        }

        Write-Status "completed" "OpenVPN $Version runtime and driver are ready." 100 "OK"
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
    Write-Status "failed" $_.Exception.Message 0 "ERROR"
    exit 1
}

exit 0
