#Requires -Version 5.1

[CmdletBinding()]
param(
    [string]$OutputPath = (Join-Path $PWD 'blackshard-compatibility.json'),
    [switch]$DevelopmentVm
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-Captured {
    param([scriptblock]$Command)
    try {
        $text = (& $Command 2>&1 | Out-String).Trim()
        [ordered]@{ exit_code = $LASTEXITCODE; output = $text }
    } catch {
        [ordered]@{ exit_code = -1; output = $_.Exception.Message }
    }
}

$os = Get-CimInstance Win32_OperatingSystem
$computer = Get-CimInstance Win32_ComputerSystem
$processors = @(Get-CimInstance Win32_Processor | Select-Object Name, NumberOfCores, NumberOfLogicalProcessors)
$video = @(Get-CimInstance Win32_VideoController | Select-Object Name, DriverVersion, Status)
$volumes = @(Get-Volume | Where-Object DriveLetter | Select-Object DriveLetter, FileSystemType, HealthStatus)
$secureBoot = try { [bool](Confirm-SecureBootUEFI) } catch { $null }
$memoryIntegrity = try {
    $value = Get-ItemPropertyValue -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity' -Name Enabled
    [bool]$value
} catch { $null }
$binary = Join-Path $PSScriptRoot '..\target\release\blackshard.exe'
$signature = if (Test-Path -LiteralPath $binary -PathType Leaf) {
    $status = Get-AuthenticodeSignature -LiteralPath $binary
    $subject = if ($null -ne $status.SignerCertificate) { [string]$status.SignerCertificate.Subject } else { $null }
    [ordered]@{ status = [string]$status.Status; subject = $subject }
} else { $null }

$verifyArguments = @()
if ($DevelopmentVm) { $verifyArguments += '-DevelopmentVm' }
$verification = try {
    $output = (& (Join-Path $PSScriptRoot '..\verify.ps1') @verifyArguments 2>&1 | Out-String).Trim()
    [ordered]@{ exit_code = $LASTEXITCODE; output = $output }
} catch {
    [ordered]@{ exit_code = -1; output = $_.Exception.Message }
}

$record = [ordered]@{
    schema_version = 1
    collected_at = [DateTimeOffset]::UtcNow.ToString('o')
    operating_system = [ordered]@{
        caption = $os.Caption
        version = $os.Version
        build = $os.BuildNumber
        architecture = $os.OSArchitecture
    }
    hardware = [ordered]@{
        manufacturer = $computer.Manufacturer
        model = $computer.Model
        memory_bytes = [UInt64]$computer.TotalPhysicalMemory
        processors = $processors
        video = $video
        volumes = $volumes
    }
    security = [ordered]@{
        secure_boot = $secureBoot
        memory_integrity = $memoryIntegrity
        application_signature = $signature
    }
    services = [ordered]@{
        minifilter = Invoke-Captured { sc.exe query blackshard }
        protection_service = Invoke-Captured { sc.exe query BlackshardProtectionService }
        filter_instances = Invoke-Captured { fltmc.exe instances -f blackshard }
    }
    verification = $verification
}

$fullOutput = [IO.Path]::GetFullPath($OutputPath)
$parent = Split-Path -Parent $fullOutput
New-Item -ItemType Directory -Path $parent -Force | Out-Null
$temporary = "$fullOutput.tmp-$([Guid]::NewGuid().ToString('N'))"
try {
    [IO.File]::WriteAllText($temporary, ($record | ConvertTo-Json -Depth 12), [Text.UTF8Encoding]::new($false))
    Move-Item -LiteralPath $temporary -Destination $fullOutput -Force
} finally {
    if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force }
}
Write-Host "Compatibility evidence: $fullOutput"
