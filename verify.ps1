#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [switch]$DevelopmentVm
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$driverName = "blackshard"
$protectionServiceName = "BlackshardProtectionService"
$driverPath = Join-Path $env:SystemRoot "System32\drivers\blackshard.sys"
$applicationNames = @("blackshard-service.exe", "blackshard-ui.exe")
$healthPath = Join-Path $env:ProgramData "Blackshard\service-health.json"

function Invoke-ServiceQuery {
    param(
        [Parameter(Mandatory)]
        [string]$Name,
        [Parameter(Mandatory)]
        [string]$Label
    )

    Write-Host "`n=== $Label ($Name) ===" -ForegroundColor Cyan
    $output = & sc.exe query $Name 2>&1
    $exitCode = $LASTEXITCODE
    $output | Out-Host
    return [pscustomobject]@{
        Exists  = ($exitCode -eq 0)
        Running = ($exitCode -eq 0 -and (($output | Out-String) -match "(?im)STATE\s*:\s*4\s+RUNNING"))
    }
}

$driverService = Invoke-ServiceQuery -Name $driverName -Label "Kernel minifilter service"

$protectionService = Invoke-ServiceQuery `
    -Name $protectionServiceName `
    -Label "User-mode protection service"

Write-Host "`n=== Loaded minifilter ===" -ForegroundColor Cyan
$filterOutput = & fltmc.exe filters 2>&1
$filterExitCode = $LASTEXITCODE
$filterOutput | Out-Host
$loaded = ($filterExitCode -eq 0 -and (($filterOutput | Out-String) -match "(?im)^\s*blackshard\s+"))

$instancesHealthy = $false
if ($loaded) {
    Write-Host "`n=== Filter instances ===" -ForegroundColor Cyan
    $instanceOutput = & fltmc.exe instances -f $driverName 2>&1
    $instanceExitCode = $LASTEXITCODE
    $instanceOutput | Out-Host
    $instancesHealthy = ($instanceExitCode -eq 0 -and (($instanceOutput | Out-String) -match "(?im)^\s*blackshard\s+"))
}

Write-Host "`n=== Installed driver file ===" -ForegroundColor Cyan
if (Test-Path -LiteralPath $driverPath -PathType Leaf) {
    $driverFile = Get-Item -LiteralPath $driverPath
    $driverFile | Select-Object FullName, Length, LastWriteTimeUtc | Format-List | Out-Host
    Write-Host "Embedded Authenticode status (the production driver may instead be trusted through its signed catalog):"
    Get-AuthenticodeSignature -LiteralPath $driverPath |
        Select-Object Status, StatusMessage, SignerCertificate |
        Format-List |
        Out-Host
} else {
    Write-Host "Driver file not found: $driverPath" -ForegroundColor Red
}

$applicationsPresent = $true
$applicationsSigned = $true
Write-Host "`n=== Blackshard application signatures ===" -ForegroundColor Cyan
foreach ($applicationName in $applicationNames) {
    $installedPath = Join-Path $env:ProgramFiles "Blackshard\$applicationName"
    $localPath = Join-Path $PSScriptRoot $applicationName
    $applicationPath = if (Test-Path -LiteralPath $installedPath -PathType Leaf) {
        $installedPath
    } elseif (Test-Path -LiteralPath $localPath -PathType Leaf) {
        $localPath
    } else {
        $null
    }
    if ($null -eq $applicationPath) {
        Write-Host "$applicationName was not found in Program Files or beside verify.ps1." -ForegroundColor Red
        $applicationsPresent = $false
        $applicationsSigned = $false
        continue
    }
    $applicationSignature = Get-AuthenticodeSignature -LiteralPath $applicationPath
    $applicationSignature |
        Select-Object Path, Status, StatusMessage, SignerCertificate |
        Format-List |
        Out-Host
    if ($applicationSignature.Status -ne "Valid") {
        $applicationsSigned = $false
    }
}

$healthHealthy = $false
Write-Host "`n=== Protection-service health ===" -ForegroundColor Cyan
if (Test-Path -LiteralPath $healthPath -PathType Leaf) {
    try {
        $health = Get-Content -LiteralPath $healthPath -Raw | ConvertFrom-Json
        $health | Format-List | Out-Host
        $updatedAt = [DateTimeOffset]::Parse([string]$health.updated_at)
        $ageSeconds = ([DateTimeOffset]::UtcNow - $updatedAt.ToUniversalTime()).TotalSeconds
        $healthHealthy = (
            [int]$health.schema_version -eq 3 -and
            [string]$health.lifecycle -eq "running" -and
            [string]$health.connection -eq "connected" -and
            [string]$health.readiness -eq "Ready" -and
            [bool]$health.real_time_enabled -and
            -not [bool]$health.external_rules_suppressed -and
            $ageSeconds -ge -5 -and
            $ageSeconds -le 15
        )
        if (-not $healthHealthy) {
            Write-Host "Health is stale or does not report running, connected real-time protection." -ForegroundColor Red
        }
        $driverBypasses = [uint64]$health.counters.service_unavailable_bypasses +
            [uint64]$health.counters.object_resolution_bypasses +
            [uint64]$health.counters.oversize_path_bypasses +
            [uint64]$health.counters.irql_bypasses +
            [uint64]$health.counters.enforcement_bypasses +
            [uint64]$health.counters.bypassed_due_to_load
        if ($driverBypasses -gt 0 -or [uint64]$health.counters.driver_timeouts -gt 0) {
            Write-Host "Warning: the driver reports $driverBypasses bypassed requests and $($health.counters.driver_timeouts) timeouts since load. Review before release qualification." -ForegroundColor Yellow
        }
    } catch {
        Write-Host "Could not validate $healthPath`: $($_.Exception.Message)" -ForegroundColor Red
        $healthHealthy = $false
    }
} else {
    Write-Host "Health file not found: $healthPath" -ForegroundColor Red
}

$productionHealthy = (
    $driverService.Running -and
    $loaded -and
    $instancesHealthy -and
    $null -ne $protectionService -and
    $protectionService.Running -and
    $healthHealthy -and
    $applicationsPresent -and
    $applicationsSigned
)
$developmentHealthy = (
    $driverService.Running -and
    $loaded -and
    $instancesHealthy -and
    $protectionService.Running -and
    $healthHealthy -and
    $applicationsPresent
)

if (($DevelopmentVm -and $developmentHealthy) -or (-not $DevelopmentVm -and $productionHealthy)) {
    if ($DevelopmentVm) {
        Write-Host "`n[PASS] The development-VM minifilter and protection service are healthy." -ForegroundColor Green
        Write-Host "Launch .\blackshard-ui.exe and run the harmless protection test. This result is not production qualification."
    } else {
        Write-Host "`n[PASS] Both Blackshard services, filter attachment, service health, and application signature passed local checks." -ForegroundColor Green
        Write-Host "Run the UI's harmless protection test. This diagnostic does not prove detection efficacy or release readiness."
    }
    exit 0
}

Write-Host "`n[FAIL] Blackshard did not pass all checks for this mode." -ForegroundColor Red
if (-not $DevelopmentVm) {
    Write-Host "Use -DevelopmentVm only for the legacy unsigned/test-signed disposable-VM workflow."
}
exit 1
