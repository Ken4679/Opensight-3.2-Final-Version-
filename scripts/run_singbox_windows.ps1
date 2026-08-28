param(
    [Parameter(Mandatory = $true)]
    [string]$SingBox,

    [Parameter(Mandatory = $true)]
    [string]$Config,

    [Parameter(Mandatory = $true)]
    [string]$PidFile,

    [Parameter(Mandatory = $true)]
    [string]$StopFile
)

$ErrorActionPreference = "Stop"

$UacCancelledCode = 1223


function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)

    return $principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )
}


function Start-ElevatedProcess {
    $arguments = @(
        "-NoProfile"
        "-WindowStyle"
        "Hidden"
        "-ExecutionPolicy"
        "Bypass"
        "-File"
        $PSCommandPath
        "-SingBox"
        $SingBox
        "-Config"
        $Config
        "-PidFile"
        $PidFile
        "-StopFile"
        $StopFile
    )

    $startParameters = @{
        FilePath = "powershell.exe"
        ArgumentList = $arguments
        Verb = "RunAs"
        Wait = $true
        PassThru = $true
        ErrorAction = "Stop"
    }

    try {
        $child = Start-Process @startParameters
        return $child.ExitCode
    }
    catch {
        return $UacCancelledCode
    }
}


function Ensure-ParentDirectory {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $parent = Split-Path -Parent $Path

    if ($parent -and -not (Test-Path -LiteralPath $parent)) {
        New-Item `
            -ItemType Directory `
            -Path $parent `
            -Force |
            Out-Null
    }
}


function Stop-ChildProcess {
    param(
        [Parameter(Mandatory = $false)]
        [System.Diagnostics.Process]$Process
    )

    if ($null -eq $Process) {
        return
    }

    try {
        if (-not $Process.HasExited) {
            Stop-Process `
                -Id $Process.Id `
                -Force `
                -ErrorAction SilentlyContinue
        }
    }
    catch {
        # Best effort cleanup.
    }
}


# ================================================================
# Administrator check
# ================================================================

if (-not (Test-Administrator)) {

    $elevatedExitCode = Start-ElevatedProcess

    if ($elevatedExitCode -eq $UacCancelledCode) {
        Write-Error "Administrator authorization was cancelled."
    }

    exit $elevatedExitCode
}


# ================================================================
# Validate executable
# ================================================================

if (-not (Test-Path -LiteralPath $SingBox -PathType Leaf)) {
    Write-Error "sing-box executable not found: $SingBox"
    exit 1
}


# ================================================================
# Validate configuration
# ================================================================

if (-not (Test-Path -LiteralPath $Config -PathType Leaf)) {
    Write-Error "sing-box configuration not found: $Config"
    exit 1
}


# ================================================================
# Validate parent directories
# ================================================================

Ensure-ParentDirectory -Path $PidFile


$workingDirectory = Split-Path -Parent $Config

if ([string]::IsNullOrWhiteSpace($workingDirectory)) {
    $workingDirectory = (Get-Location).Path
}


# ================================================================
# Start sing-box
# ================================================================

$proc = $null

try {

    $processArguments = @(
        "run"
        "-c"
        $Config
    )


    $startParameters = @{
        FilePath = $SingBox
        ArgumentList = $processArguments
        PassThru = $true
        WindowStyle = "Hidden"
        WorkingDirectory = $workingDirectory
        ErrorAction = "Stop"
    }


    $proc = Start-Process @startParameters


    # ------------------------------------------------------------
    # Write process ID
    # ------------------------------------------------------------

    Set-Content `
        -LiteralPath $PidFile `
        -Value ([string]$proc.Id) `
        -Encoding ascii `
        -Force


    # ============================================================
    # Monitor sing-box
    # ============================================================

    while ($true) {

        if ($proc.HasExited) {
            exit $proc.ExitCode
        }


        if (Test-Path -LiteralPath $StopFile) {

            Stop-ChildProcess -Process $proc

            exit 0
        }


        Start-Sleep -Milliseconds 300
    }
}
catch {

    Write-Error $_.Exception.Message

    Stop-ChildProcess -Process $proc

    exit 1
}
finally {

    Remove-Item `
        -LiteralPath $PidFile `
        -Force `
        -ErrorAction SilentlyContinue

    Remove-Item `
        -LiteralPath $Config `
        -Force `
        -ErrorAction SilentlyContinue
}


exit 0
