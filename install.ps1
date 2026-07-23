#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [switch]$Uninstall,
    [switch]$AllowUnsigned
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$driverName = "blackshard"
$protectionServiceName = "BlackshardProtectionService"
$sourceDriver = Join-Path $PSScriptRoot "blackshard.sys"
$sourceAgent = Join-Path $PSScriptRoot "blackshard.exe"
$destinationDriver = Join-Path $env:SystemRoot "System32\drivers\blackshard.sys"
$agentDirectory = Join-Path $env:ProgramFiles "Blackshard"
$destinationAgent = Join-Path $agentDirectory "blackshard.exe"
$serviceRegistryPath = "HKLM:\System\CurrentControlSet\Services\$driverName"

function Test-BlackshardFilterLoaded {
    $filterOutput = & fltmc.exe filters 2>$null
    return ($filterOutput -match "(?im)^blackshard\s")
}

function Get-DriverLoadDiagnostics {
    $lines = New-Object Collections.Generic.List[string]
    try {
        $signature = Get-AuthenticodeSignature -LiteralPath $destinationDriver
        $lines.Add("Installed driver signature: $($signature.Status) - $($signature.StatusMessage)")
    }
    catch {
        $lines.Add("Installed driver signature could not be inspected: $($_.Exception.Message)")
    }

    try {
        $since = (Get-Date).AddMinutes(-5)
        $events = Get-WinEvent -FilterHashtable @{ LogName = "System"; StartTime = $since } -ErrorAction Stop |
            Where-Object {
                $_.ProviderName -match "(?i)(FilterManager|Service Control Manager|CodeIntegrity)" -and
                $_.Message -match "(?i)(blackshard|driver|filter)"
            } |
            Select-Object -First 8
        foreach ($event in $events) {
            $message = ([string]$event.Message -replace "\s+", " ").Trim()
            $lines.Add("System event $($event.Id) [$($event.ProviderName)]: $message")
        }
    }
    catch {
        $lines.Add("Recent driver events could not be read: $($_.Exception.Message)")
    }

    if ($lines.Count -eq 0) {
        return "No relevant Windows driver events were found in the last five minutes."
    }
    return $lines -join "`n"
}

function Remove-BlackshardInstallation {
    Write-Host "[*] Stopping Blackshard protection service..." -ForegroundColor Cyan
    & sc.exe stop $protectionServiceName 2>$null | Out-Host
    & sc.exe delete $protectionServiceName 2>$null | Out-Host

    if (Test-BlackshardFilterLoaded) {
        Write-Host "[*] Unloading Blackshard minifilter..." -ForegroundColor Cyan
        & fltmc.exe unload $driverName | Out-Host
    }

    & sc.exe stop $driverName 2>$null | Out-Host
    & sc.exe delete $driverName 2>$null | Out-Host
    Start-Sleep -Seconds 1

    if (Test-Path -LiteralPath $destinationDriver) {
        Remove-Item -LiteralPath $destinationDriver -Force
    }
    if (Test-Path -LiteralPath $destinationAgent -PathType Leaf) {
        Remove-Item -LiteralPath $destinationAgent -Force
    }
    if (Test-Path -LiteralPath $agentDirectory -PathType Container) {
        $remaining = @(Get-ChildItem -LiteralPath $agentDirectory -Force)
        if ($remaining.Count -eq 0) {
            Remove-Item -LiteralPath $agentDirectory -Force
        }
    }

    Write-Host "[+] Blackshard was removed." -ForegroundColor Green
}

if ($Uninstall) {
    Remove-BlackshardInstallation
    exit 0
}

if (-not [Environment]::Is64BitOperatingSystem) {
    throw "This build supports only 64-bit Windows."
}

if (-not (Test-Path -LiteralPath $sourceDriver)) {
    throw "blackshard.sys was not found beside install.ps1. Run deploy.ps1 after building the driver."
}
if (-not (Test-Path -LiteralPath $sourceAgent -PathType Leaf)) {
    throw "blackshard.exe was not found beside install.ps1. Run deploy.ps1 before copying dist to the VM."
}

$signature = Get-AuthenticodeSignature -LiteralPath $sourceDriver
if ($signature.Status -ne "Valid" -and -not $AllowUnsigned) {
    throw @"
blackshard.sys does not have a trusted signature (status: $($signature.Status)).
Production Windows systems must use a properly signed driver. On an isolated test VM,
run enable-test-signing.ps1, reboot, and then run install.ps1 again.
Use -AllowUnsigned only when code-integrity enforcement is already disabled in a disposable VM.
"@
}

if ($signature.Status -ne "Valid") {
    Write-Warning "Installing an untrusted driver in test mode. Never do this on a production system."
}

$agentSignature = Get-AuthenticodeSignature -LiteralPath $sourceAgent
if ($agentSignature.Status -ne "Valid") {
    Write-Warning "The development agent is not Authenticode-signed. Use it only in this disposable VM."
}

& sc.exe stop $protectionServiceName 2>$null | Out-Host
& sc.exe delete $protectionServiceName 2>$null | Out-Host
Start-Sleep -Seconds 1
New-Item -ItemType Directory -Path $agentDirectory -Force | Out-Null
Copy-Item -LiteralPath $sourceAgent -Destination $destinationAgent -Force

if (Test-BlackshardFilterLoaded) {
    & fltmc.exe unload $driverName | Out-Host
}
& sc.exe stop $driverName 2>$null | Out-Host
& sc.exe delete $driverName 2>$null | Out-Host

# Wait for the SCM to fully remove the service. sc.exe delete only marks the
# service for deletion; the actual registry key removal is deferred until all
# handles are closed. If we create the new service too early, the deferred
# cleanup can wipe out the Instances subkey we add for the minifilter, causing
# fltmc load to fail with 0x800704db ("The specified service does not exist").
$waitLimit = 20          # 20 × 500 ms = 10 seconds
for ($i = 0; $i -lt $waitLimit; $i++) {
    $query = & sc.exe query $driverName 2>&1
    if ($LASTEXITCODE -ne 0) {
        # Service no longer exists in SCM — safe to proceed.
        break
    }
    Start-Sleep -Milliseconds 500
}
if (Test-Path -LiteralPath $serviceRegistryPath) {
    # The registry key is still present even though SCM says the service is
    # gone (handles from a filter-manager reference, etc.). Force-remove it
    # so the subsequent sc.exe create starts from a clean slate.
    Remove-Item -LiteralPath $serviceRegistryPath -Recurse -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 500
}

Copy-Item -LiteralPath $sourceDriver -Destination $destinationDriver -Force

$createCmd = 'sc.exe create "{0}" type= filesys start= demand error= normal binPath= "{1}" group= "FSFilter Anti-Virus" depend= FltMgr' -f $driverName, $destinationDriver
$createOutput = & cmd.exe /c $createCmd 2>&1
$createExitCode = $LASTEXITCODE
$createOutput | Out-Host
if ($createExitCode -ne 0) {
    throw "Could not create the Blackshard driver service (sc.exe exit code $createExitCode)."
}

if (-not (Test-Path -LiteralPath $serviceRegistryPath)) {
    New-Item -Path $serviceRegistryPath -Force | Out-Null
}

# Minifilter instance registration. Some Windows builds read the instances
# from Services\<name>\Instances (the "legacy" layout) while others read from
# Services\<name>\Parameters\Instances (the INF-standard layout populated by
# DiInstallDriverW).  The production Rust installer covers both paths; this
# development script must do the same.
$instanceLayouts = @(
    (Join-Path $serviceRegistryPath "Instances"),
    (Join-Path $serviceRegistryPath "Parameters\Instances")
)
foreach ($instancesPath in $instanceLayouts) {
    $instancePath = Join-Path $instancesPath "blackshard Instance"
    New-Item -Path $instancesPath -Force | Out-Null
    New-ItemProperty -Path $instancesPath -Name "DefaultInstance" -Value "blackshard Instance" -PropertyType String -Force | Out-Null
    New-Item -Path $instancePath -Force | Out-Null
    # Development-only placeholder. A production package must use the unique
    # altitude assigned to Blackshard by Microsoft and install its signed INF/CAT
    # through the Driver Store instead of this development script.
    New-ItemProperty -Path $instancePath -Name "Altitude" -Value "320000.4242" -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $instancePath -Name "Flags" -Value 0 -PropertyType DWord -Force | Out-Null
}

# Parameters-level driver settings (matching the INF's AddRegistry section).
$parametersPath = Join-Path $serviceRegistryPath "Parameters"
New-Item -Path $parametersPath -Force | Out-Null
New-ItemProperty -Path $parametersPath -Name "DebugFlags" -Value 0 -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path $parametersPath -Name "SupportedFeatures" -Value 3 -PropertyType DWord -Force | Out-Null

Write-Host "[*] Loading Blackshard minifilter..." -ForegroundColor Cyan

# Capture a registry snapshot before the load attempt so failures are
# diagnosable from the log alone.
$registryDump = & reg.exe query "HKLM\System\CurrentControlSet\Services\$driverName" /s 2>&1
$registryDump | Out-Host

$loadOutput = & fltmc.exe load $driverName 2>&1
$loadExitCode = $LASTEXITCODE
$loadOutput | Out-Host
if ($loadExitCode -ne 0) {
    $loadMessage = ($loadOutput | Out-String).Trim()
    $diagnostics = Get-DriverLoadDiagnostics
    $regDump = ($registryDump | Out-String).Trim()
    throw @"
The service was installed, but Windows refused to load the minifilter (fltmc exit code $loadExitCode).
fltmc output: $loadMessage
$diagnostics
Service registry state:
$regDump
"@
}

if (-not (Test-BlackshardFilterLoaded)) {
    throw "fltmc reported success, but Blackshard is absent from the loaded filter list."
}

Write-Host "[*] Installing Blackshard protection service..." -ForegroundColor Cyan
$null = New-Service `
    -Name $protectionServiceName `
    -BinaryPathName $destinationAgent `
    -StartupType Automatic `
    -Description "Blackshard real-time protection and quarantine service"

$serviceCommand = "`"$destinationAgent`" --service"
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$protectionServiceName" -Name ImagePath -Value $serviceCommand -Type ExpandString

& sc.exe failure $protectionServiceName "reset= 86400" "actions= restart/30000/restart/30000/none/0" | Out-Host
Start-Service -Name $protectionServiceName

$serviceRunning = $false
for ($attempt = 0; $attempt -lt 20; $attempt++) {
    $query = & sc.exe query $protectionServiceName 2>&1
    if ($LASTEXITCODE -eq 0 -and (($query | Out-String) -match '(?im)STATE\s*:\s*4\s+RUNNING')) {
        $serviceRunning = $true
        break
    }
    Start-Sleep -Milliseconds 250
}
if (-not $serviceRunning) {
    throw "The Blackshard protection service did not reach RUNNING state."
}

Write-Host "[+] Blackshard minifilter and protection service are running." -ForegroundColor Green
& fltmc.exe instances -f $driverName | Out-Host
