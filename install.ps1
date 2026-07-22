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
Start-Sleep -Seconds 1

Copy-Item -LiteralPath $sourceDriver -Destination $destinationDriver -Force

$createOutput = & sc.exe create $driverName "type= filesys" "start= demand" "error= normal" "binPath= $destinationDriver" "group= FSFilter Anti-Virus" "depend= FltMgr" 2>&1
$createExitCode = $LASTEXITCODE
$createOutput | Out-Host
if ($createExitCode -ne 0) {
    throw "Could not create the Blackshard driver service (sc.exe exit code $createExitCode)."
}

New-Item -Path $serviceRegistryPath -Force | Out-Null
New-ItemProperty -Path $serviceRegistryPath -Name "DebugFlags" -Value 0 -PropertyType DWord -Force | Out-Null
New-ItemProperty -Path $serviceRegistryPath -Name "SupportedFeatures" -Value 3 -PropertyType DWord -Force | Out-Null

$instancesPath = Join-Path $serviceRegistryPath "Instances"
$instancePath = Join-Path $instancesPath "blackshard Instance"
New-Item -Path $instancesPath -Force | Out-Null
New-ItemProperty -Path $instancesPath -Name "DefaultInstance" -Value "blackshard Instance" -PropertyType String -Force | Out-Null
New-Item -Path $instancePath -Force | Out-Null
# Development-only placeholder. A production package must use the unique
# altitude assigned to Blackshard by Microsoft and install its signed INF/CAT
# through the Driver Store instead of this development script.
New-ItemProperty -Path $instancePath -Name "Altitude" -Value "320000.4242" -PropertyType String -Force | Out-Null
New-ItemProperty -Path $instancePath -Name "Flags" -Value 0 -PropertyType DWord -Force | Out-Null

Write-Host "[*] Loading Blackshard minifilter..." -ForegroundColor Cyan
$loadOutput = & fltmc.exe load $driverName 2>&1
$loadExitCode = $LASTEXITCODE
$loadOutput | Out-Host
if ($loadExitCode -ne 0) {
    throw @"
The service was installed, but Windows refused to load the minifilter (fltmc exit code $loadExitCode).
Check driver signing, Secure Boot/test-signing configuration, and the System event log.
"@
}

if (-not (Test-BlackshardFilterLoaded)) {
    throw "fltmc reported success, but Blackshard is absent from the loaded filter list."
}

Write-Host "[*] Installing Blackshard protection service..." -ForegroundColor Cyan
$serviceCommand = '"{0}" --service' -f $destinationAgent
$serviceOutput = & sc.exe create $protectionServiceName "type= own" "start= auto" "error= normal" "obj= LocalSystem" "binPath= $serviceCommand" 2>&1
$serviceExitCode = $LASTEXITCODE
$serviceOutput | Out-Host
if ($serviceExitCode -ne 0) {
    throw "Could not create the Blackshard protection service (sc.exe exit code $serviceExitCode)."
}
& sc.exe description $protectionServiceName "Blackshard real-time protection and quarantine service" | Out-Host
& sc.exe failure $protectionServiceName "reset= 86400" "actions= restart/30000/restart/30000/none/0" | Out-Host
$startOutput = & sc.exe start $protectionServiceName 2>&1
$startExitCode = $LASTEXITCODE
$startOutput | Out-Host
if ($startExitCode -ne 0) {
    throw "Could not start the Blackshard protection service (sc.exe exit code $startExitCode)."
}

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
