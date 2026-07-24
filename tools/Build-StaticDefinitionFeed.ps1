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
    [UInt64]$Sequence,
    [Parameter(Mandatory = $true)]
    [string]$Version,
    [Parameter(Mandatory = $true)]
    [string]$FeedBaseUrl,
    [string]$BaseBundlePath,
    [string]$OpenSslPath,
    [string]$ValidatorPath = (Join-Path $PSScriptRoot '..\target\release\blackshard-service.exe'),
    [ValidateRange(1, 168)]
    [int]$ExpiryHours = 24,
    [switch]$IncludePua,
    [Parameter(Mandatory = $true)]
    [switch]$AcceptClamAvGpl2
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$feedUri = $null
if (-not [Uri]::TryCreate($FeedBaseUrl, [UriKind]::Absolute, [ref]$feedUri) -or
    $feedUri.Scheme -ne 'https' -or [string]::IsNullOrWhiteSpace($feedUri.Host) -or
    -not [string]::IsNullOrEmpty($feedUri.UserInfo) -or
    -not [string]::IsNullOrEmpty($feedUri.Query) -or
    -not [string]::IsNullOrEmpty($feedUri.Fragment)) {
    throw 'FeedBaseUrl must be an absolute HTTPS URL without credentials, query, or fragment.'
}

$feedFullPath = [IO.Path]::GetFullPath($FeedRoot).TrimEnd([IO.Path]::DirectorySeparatorChar)
foreach ($keyPath in @($PrivateKeyPath, $PublicKeyPath)) {
    $keyFullPath = [IO.Path]::GetFullPath($keyPath)
    if ($keyFullPath.StartsWith($feedFullPath + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Signing keys must be outside the web-published feed directory.'
    }
}

$stableDirectory = Join-Path $feedFullPath 'stable'
$workspace = Join-Path ([IO.Path]::GetTempPath()) ('blackshard-feed-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $workspace -Force | Out-Null
try {
    $candidate = Join-Path $workspace 'candidate.bundle'
    $importArguments = @{
        DatabaseDirectory = $DatabaseDirectory
        OutputPath = $candidate
        BundleId = ('stable-' + $Version)
        AcceptClamAvGpl2 = $true
        IncludePua = $IncludePua
    }
    if (-not [string]::IsNullOrWhiteSpace($BaseBundlePath)) {
        $importArguments.BaseBundlePath = $BaseBundlePath
    }
    & (Join-Path $PSScriptRoot 'Import-ClamAvSha256.ps1') @importArguments

    # Immutable payload names let a client that fetched the previous manifest
    # complete its download while a new manifest is being published.
    $payloadUrl = $FeedBaseUrl.TrimEnd('/') + "/stable/rules-$Sequence.bundle"
    $publishArguments = @{
        BundlePath = $candidate
        PrivateKeyPath = $PrivateKeyPath
        PublicKeyPath = $PublicKeyPath
        Sequence = $Sequence
        Version = $Version
        PayloadUrl = $payloadUrl
        OutputDirectory = $stableDirectory
        ExpiryHours = $ExpiryHours
        ValidatorPath = $ValidatorPath
    }
    if (-not [string]::IsNullOrWhiteSpace($OpenSslPath)) {
        $publishArguments.OpenSslPath = $OpenSslPath
    }
    & (Join-Path $PSScriptRoot 'Publish-DefinitionBundle.ps1') @publishArguments

    Write-Host 'Static definition feed is ready.'
    Write-Host "Manifest URL: $($FeedBaseUrl.TrimEnd('/'))/stable/manifest.json"
    Write-Host "Deploy rules-$Sequence.bundle before manifest.json and retain both publication hashes in the release log."
} finally {
    if (Test-Path -LiteralPath $workspace -PathType Container) {
        $resolvedWorkspace = [IO.Path]::GetFullPath($workspace)
        $temporaryRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
        if (-not $resolvedWorkspace.StartsWith($temporaryRoot, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Refusing to clean a feed workspace outside the system temporary directory.'
        }
        Remove-Item -LiteralPath $workspace -Recurse -Force
    }
}
