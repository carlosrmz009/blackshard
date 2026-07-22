#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [switch]$Uninstall,
    [switch]$AllowUnsigned
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$driverName = "blackshard"
$sourceDriver = Join-Path $PSScriptRoot "blackshard.sys"
$destinationDriver = Join-Path $env:SystemRoot "System32\drivers\blackshard.sys"
$serviceRegistryPath = "HKLM:\System\CurrentControlSet\Services\$driverName"

function Test-BlackshardFilterLoaded {
    $filterOutput = & fltmc.exe filters 2>$null
    return ($filterOutput -match "(?im)^blackshard\s")
}

function Remove-BlackshardInstallation {
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

Write-Host "[+] Blackshard minifilter is loaded and ready for the agent." -ForegroundColor Green
& fltmc.exe instances -f $driverName | Out-Host
