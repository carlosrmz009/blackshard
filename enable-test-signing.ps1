#Requires -RunAsAdministrator
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$driverPath = Join-Path $PSScriptRoot "blackshard.sys"
if (-not (Test-Path -LiteralPath $driverPath)) {
    throw "blackshard.sys was not found beside this script."
}

$subject = "CN=Blackshard Development Test"
$certificate = Get-ChildItem -LiteralPath "Cert:\LocalMachine\My" |
    Where-Object Subject -eq $subject |
    Sort-Object NotAfter -Descending |
    Select-Object -First 1

if (-not $certificate -or $certificate.NotAfter -lt (Get-Date).AddDays(30)) {
    $certificate = New-SelfSignedCertificate `
        -Type CodeSigningCert `
        -Subject $subject `
        -CertStoreLocation "Cert:\LocalMachine\My" `
        -HashAlgorithm SHA256 `
        -NotAfter (Get-Date).AddYears(2)
}

$publicCertificatePath = Join-Path $PSScriptRoot "blackshard-test.cer"
Export-Certificate -Cert $certificate -FilePath $publicCertificatePath -Force | Out-Null
Import-Certificate -FilePath $publicCertificatePath -CertStoreLocation "Cert:\LocalMachine\Root" | Out-Null
Import-Certificate -FilePath $publicCertificatePath -CertStoreLocation "Cert:\LocalMachine\TrustedPublisher" | Out-Null

Write-Host "[*] Test-signing blackshard.sys..." -ForegroundColor Cyan
$signature = Set-AuthenticodeSignature `
    -LiteralPath $driverPath `
    -Certificate $certificate `
    -HashAlgorithm SHA256 `
    -IncludeChain All
if ($signature.Status -ne "Valid") {
    throw "The driver signature could not be validated after signing: $($signature.Status)"
}

Write-Host "[*] Enabling Windows test-signing mode..." -ForegroundColor Yellow
& bcdedit.exe /set testsigning on | Out-Host
if ($LASTEXITCODE -ne 0) {
    throw "Windows could not enable test-signing. Disable Secure Boot in this disposable VM and retry."
}

Write-Host "[+] Driver signed for development testing." -ForegroundColor Green
Write-Host "Restart the VM, then run install.ps1 as Administrator." -ForegroundColor Yellow
