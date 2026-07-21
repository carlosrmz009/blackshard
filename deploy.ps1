[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Push-Location $PSScriptRoot
try {
    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
        throw "Cargo is not installed or is not available in PATH."
    }

    & (Join-Path $PSScriptRoot "build-driver.ps1")
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }

    cargo build --release
    if ($LASTEXITCODE -ne 0) {
        exit $LASTEXITCODE
    }

    $driverSource = Join-Path $PSScriptRoot "src\driver\blackshard_driver.c"
    $driverBinary = Join-Path $PSScriptRoot "src\driver\x64\Release\blackshard.sys"
    $agentBinary = Join-Path $PSScriptRoot "target\release\blackshard.exe"

    if (-not (Test-Path -LiteralPath $driverBinary)) {
        throw "The driver build completed without producing blackshard.sys."
    }
    if ((Get-Item -LiteralPath $driverBinary).LastWriteTimeUtc -lt (Get-Item -LiteralPath $driverSource).LastWriteTimeUtc) {
        throw "blackshard.sys is older than its source. Refusing to package a stale kernel driver."
    }
    if (-not (Test-Path -LiteralPath $agentBinary)) {
        throw "The Cargo build completed without producing blackshard.exe."
    }

    $distributionDirectory = Join-Path $PSScriptRoot "dist"
    if (Test-Path -LiteralPath $distributionDirectory) {
        $resolvedDistribution = (Resolve-Path -LiteralPath $distributionDirectory).Path
        if ($resolvedDistribution -ne (Join-Path $PSScriptRoot "dist")) {
            throw "Refusing to clean unexpected distribution path: $resolvedDistribution"
        }
        Remove-Item -LiteralPath $resolvedDistribution -Recurse -Force
    }
    New-Item -ItemType Directory -Path $distributionDirectory | Out-Null

    foreach ($scriptName in @(
        "install.ps1",
        "uninstall.ps1",
        "verify.ps1",
        "enable-test-signing.ps1",
        "disable-test-signing.ps1"
    )) {
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot $scriptName) -Destination $distributionDirectory
    }

    Copy-Item -LiteralPath $driverBinary -Destination (Join-Path $distributionDirectory "blackshard.sys")
    Copy-Item -LiteralPath $agentBinary -Destination (Join-Path $distributionDirectory "blackshard.exe")
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot "README.md") -Destination $distributionDirectory

    $signature = Get-AuthenticodeSignature -LiteralPath (Join-Path $distributionDirectory "blackshard.sys")
    if ($signature.Status -ne "Valid") {
        Write-Warning "The packaged driver is not production-signed. Use the included test-signing script only in an isolated VM."
    }

    Write-Host "[+] Distribution created successfully:" -ForegroundColor Green
    Get-ChildItem -LiteralPath $distributionDirectory -File |
        Select-Object Name, Length, LastWriteTime |
        Format-Table -AutoSize |
        Out-Host
}
finally {
    Pop-Location
}
