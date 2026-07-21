#Requires -RunAsAdministrator
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$driverName = "blackshard"
$driverPath = Join-Path $env:SystemRoot "System32\drivers\blackshard.sys"

Write-Host "=== Blackshard service ===" -ForegroundColor Cyan
& sc.exe query $driverName | Out-Host
$serviceExitCode = $LASTEXITCODE

Write-Host "`n=== Loaded minifilter ===" -ForegroundColor Cyan
$filterOutput = & fltmc.exe filters 2>&1
$filterOutput | Out-Host
$loaded = $filterOutput -match "(?im)^blackshard\s"

if ($loaded) {
    Write-Host "`n=== Filter instances ===" -ForegroundColor Cyan
    & fltmc.exe instances -f $driverName | Out-Host
}

Write-Host "`n=== Installed driver signature ===" -ForegroundColor Cyan
if (Test-Path -LiteralPath $driverPath) {
    Get-AuthenticodeSignature -LiteralPath $driverPath |
        Select-Object Status, StatusMessage, SignerCertificate |
        Format-List |
        Out-Host
} else {
    Write-Host "Driver file not found: $driverPath" -ForegroundColor Red
}

if ($serviceExitCode -eq 0 -and $loaded) {
    Write-Host "[PASS] The Blackshard kernel minifilter is loaded." -ForegroundColor Green
    Write-Host "Launch blackshard.exe and confirm it shows FILTER CONNECTED, then run its harmless self-test."
    exit 0
}

Write-Host "[FAIL] The Blackshard kernel minifilter is not loaded." -ForegroundColor Red
exit 1
