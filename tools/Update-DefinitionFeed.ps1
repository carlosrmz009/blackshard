#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$DatabaseDirectory,
    [Parameter(Mandatory = $true)]
    [string]$FeedRoot,
    [Parameter(Mandatory = $true)]
    [string]$PrivateKeyPath,
    [Parameter(Mandatory = $true)]
    [string]$PublicKeyPath,
    [Parameter(Mandatory = $true)]
    [string]$FeedBaseUrl,
    [string]$BaseBundlePath,
    [string]$OpenSslPath,
    [string]$ValidatorPath = (Join-Path $PSScriptRoot "..\target\release\blackshard-service.exe"),
    [string]$DefinitionCompilerPath = (Join-Path $PSScriptRoot "..\target\release\blackshard-definition-compiler.exe"),
    [ValidateRange(1, 168)]
    [int]$ExpiryHours = 24,
    [switch]$IncludePua,
    [Parameter(Mandatory = $true)]
    [switch]$AcceptClamAvGpl2,
    [Parameter(Mandatory = $true)]
    [switch]$AcceptAbuseChTerms
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$feedFullPath = [IO.Path]::GetFullPath($FeedRoot)
New-Item -ItemType Directory -Path $feedFullPath -Force | Out-Null
$lockPath = Join-Path $feedFullPath ".definition-feed.lock"
$lock = $null
try {
    try {
        $lock = [IO.File]::Open(
            $lockPath,
            [IO.FileMode]::OpenOrCreate,
            [IO.FileAccess]::ReadWrite,
            [IO.FileShare]::None
        )
    }
    catch {
        throw "Another definition-feed update is already running."
    }

    $manifestPath = Join-Path $feedFullPath "stable\manifest.json"
    $sequence = [UInt64]1
    if (Test-Path -LiteralPath $manifestPath -PathType Leaf) {
        $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
        $installedSequence = [UInt64]$manifest.manifest.sequence
        if ($installedSequence -eq 0 -or $installedSequence -ge [UInt64]::MaxValue - 1) {
            throw "The current feed manifest has an invalid or terminal sequence."
        }
        $sequence = $installedSequence + 1
    }

    $arguments = @{
        DatabaseDirectory = $DatabaseDirectory
        FeedRoot = $feedFullPath
        PrivateKeyPath = $PrivateKeyPath
        PublicKeyPath = $PublicKeyPath
        Sequence = $sequence
        Version = [DateTimeOffset]::UtcNow.ToString("yyyy.MM.dd.HHmm")
        FeedBaseUrl = $FeedBaseUrl
        OpenSslPath = $OpenSslPath
        ValidatorPath = $ValidatorPath
        DefinitionCompilerPath = $DefinitionCompilerPath
        ExpiryHours = $ExpiryHours
        IncludePua = $IncludePua
        IncludeMalwareBazaar = $true
        AcceptClamAvGpl2 = $true
        AcceptAbuseChTerms = $true
    }
    if ([string]::IsNullOrWhiteSpace($OpenSslPath)) {
        $arguments.Remove("OpenSslPath")
    }
    if (-not [string]::IsNullOrWhiteSpace($BaseBundlePath)) {
        $arguments.BaseBundlePath = $BaseBundlePath
    }

    & (Join-Path $PSScriptRoot "Build-StaticDefinitionFeed.ps1") @arguments
    Write-Host "Definition feed advanced to sequence $sequence."
}
finally {
    if ($null -ne $lock) {
        $lock.Dispose()
    }
}
