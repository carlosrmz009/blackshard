#Requires -RunAsAdministrator
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$subject = "CN=Blackshard Development Test"
foreach ($store in @("My", "Root", "TrustedPublisher")) {
    Get-ChildItem -LiteralPath "Cert:\LocalMachine\$store" |
        Where-Object Subject -eq $subject |
        Remove-Item -Force
}

& bcdedit.exe /set testsigning off | Out-Host
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

Write-Host "[+] Blackshard test certificates removed and test-signing disabled." -ForegroundColor Green
Write-Host "Restart Windows to apply the boot configuration change." -ForegroundColor Yellow
