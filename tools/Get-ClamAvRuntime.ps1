#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$OutputDirectory = (Join-Path $PSScriptRoot "..\build\clamav-runtime")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$version = "1.5.2"
$expectedSha256 = "6f868ed7a7e5a15aced82c53a4fa9f3f42fa9d7f7de14a606ba8db0756518eed"
$url = "https://github.com/Cisco-Talos/clamav/releases/download/clamav-$version/clamav-$version.win.x64.zip"
$cacheDirectory = Join-Path $PSScriptRoot "..\build\downloads"
$archivePath = Join-Path $cacheDirectory "clamav-$version.win.x64.zip"

New-Item -ItemType Directory -Path $cacheDirectory -Force | Out-Null
if (-not (Test-Path -LiteralPath $archivePath -PathType Leaf) -or
    (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expectedSha256) {
    Remove-Item -LiteralPath $archivePath -Force -ErrorAction SilentlyContinue
    Write-Host "[*] Downloading pinned ClamAV $version runtime..." -ForegroundColor Cyan
    Invoke-WebRequest -Uri $url -OutFile $archivePath -UseBasicParsing
}

$actualSha256 = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualSha256 -ne $expectedSha256) {
    throw "ClamAV runtime hash mismatch. Expected $expectedSha256, received $actualSha256."
}

if (Test-Path -LiteralPath $OutputDirectory) {
    $resolvedOutput = (Resolve-Path -LiteralPath $OutputDirectory).Path
    $expectedRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\build"))
    if (-not $resolvedOutput.StartsWith($expectedRoot, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to replace unexpected runtime directory: $resolvedOutput"
    }
    Remove-Item -LiteralPath $resolvedOutput -Recurse -Force
}

$extractDirectory = Join-Path $cacheDirectory "clamav-$version-extracted"
if (Test-Path -LiteralPath $extractDirectory) {
    Remove-Item -LiteralPath $extractDirectory -Recurse -Force
}
Expand-Archive -LiteralPath $archivePath -DestinationPath $extractDirectory -Force
$clamscan = Get-ChildItem -LiteralPath $extractDirectory -Filter "clamscan.exe" -File -Recurse |
    Select-Object -First 1
if ($null -eq $clamscan) {
    throw "The authenticated ClamAV archive did not contain clamscan.exe."
}

$runtimeRoot = $clamscan.Directory.FullName
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
foreach ($runtimeFile in @("clamd.exe", "clamscan.exe", "freshclam.exe", "sigtool.exe", "COPYING", "COPYING.txt")) {
    $source = Join-Path $runtimeRoot $runtimeFile
    if (Test-Path -LiteralPath $source -PathType Leaf) {
        Copy-Item -LiteralPath $source -Destination $OutputDirectory -Force
    }
}
Get-ChildItem -LiteralPath $runtimeRoot -Filter "*.dll" -File |
    Copy-Item -Destination $OutputDirectory -Force
$certificates = Join-Path $runtimeRoot "certs"
if (Test-Path -LiteralPath $certificates -PathType Container) {
    Copy-Item -LiteralPath $certificates -Destination $OutputDirectory -Recurse -Force
}
foreach ($required in @("clamd.exe", "clamscan.exe", "freshclam.exe", "sigtool.exe", "libclamav.dll", "libfreshclam.dll")) {
    if (-not (Test-Path -LiteralPath (Join-Path $OutputDirectory $required) -PathType Leaf)) {
        throw "The ClamAV runtime is missing $required."
    }
}
Write-Host "[+] ClamAV $version runtime prepared at $OutputDirectory" -ForegroundColor Green
