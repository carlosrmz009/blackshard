#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$BaseBundlePath,
    [Parameter(Mandatory = $true)]
    [string]$YaraSourcePath,
    [Parameter(Mandatory = $true)]
    [string]$Namespace,
    [Parameter(Mandatory = $true)]
    [string]$Provider,
    [Parameter(Mandatory = $true)]
    [string]$SourceUrl,
    [Parameter(Mandatory = $true)]
    [string]$License,
    [Parameter(Mandatory = $true)]
    [string]$OutputPath,
    [string]$BundleId = ('community-' + [DateTimeOffset]::UtcNow.ToString('yyyyMMddHHmm')),
    [Parameter(Mandatory = $true)]
    [switch]$AcceptReviewedSource
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $AcceptReviewedSource) {
    throw 'Review the source provenance, license, rule scope, and false-positive risk before importing.'
}
foreach ($path in @($BaseBundlePath, $YaraSourcePath)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Required file was not found: $path" }
    if ((Get-Item -LiteralPath $path).Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw "Import inputs must not be reparse points: $path"
    }
}
if ($Namespace -notmatch '^[A-Za-z_][A-Za-z0-9_]{0,63}$' -or $Namespace -eq 'blackshard_builtin') {
    throw 'Namespace must be a non-reserved YARA identifier of at most 64 characters.'
}
if ($BundleId -notmatch '^[A-Za-z0-9._-]{1,128}$') {
    throw 'BundleId must contain 1 through 128 letters, digits, dots, underscores, or dashes.'
}
$sourceUri = $null
if (-not [Uri]::TryCreate($SourceUrl, [UriKind]::Absolute, [ref]$sourceUri) -or
    $sourceUri.Scheme -ne 'https' -or [string]::IsNullOrWhiteSpace($sourceUri.Host) -or
    -not [string]::IsNullOrEmpty($sourceUri.UserInfo) -or
    -not [string]::IsNullOrEmpty($sourceUri.Fragment)) {
    throw 'SourceUrl must be an absolute HTTPS provenance URL without credentials or a fragment.'
}
if ($Provider -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$') {
    throw 'Provider must contain 1 through 96 letters, digits, dots, underscores, or dashes.'
}
if ([string]::IsNullOrWhiteSpace($License) -or [Text.Encoding]::UTF8.GetByteCount($License) -gt 256) {
    throw 'License must contain 1 through 256 UTF-8 bytes.'
}

$sourceBytes = [IO.File]::ReadAllBytes([IO.Path]::GetFullPath($YaraSourcePath))
if ($sourceBytes.Length -eq 0 -or $sourceBytes.Length -gt 512KB) {
    throw 'A reviewed YARA source must contain 1 byte through 512 KiB.'
}
$strictUtf8 = [Text.UTF8Encoding]::new($false, $true)
try { $sourceText = $strictUtf8.GetString($sourceBytes) } catch { throw 'YARA source must be valid UTF-8.' }
if ($sourceText.Contains([char]0)) { throw 'YARA source must not contain NUL bytes.' }

$bundle = Get-Content -LiteralPath $BaseBundlePath -Raw | ConvertFrom-Json
if ([int]$bundle.schema_version -ne 2) { throw 'Only Blackshard definition schema 2 can be extended.' }
foreach ($propertyName in @('exact_sha256', 'yara_bundles', 'similarity_profiles', 'sources')) {
    $property = $bundle.PSObject.Properties[$propertyName]
    if ($null -eq $property) {
        $bundle | Add-Member -NotePropertyName $propertyName -NotePropertyValue @()
    } elseif ($null -eq $property.Value) {
        $property.Value = @()
    }
}
if (@($bundle.yara_bundles | Where-Object namespace -eq $Namespace).Count -ne 0) {
    throw "The bundle already contains YARA namespace '$Namespace'."
}

$bundle.bundle_id = $BundleId
$bundle.yara_bundles = @($bundle.yara_bundles) + @([ordered]@{
    namespace = $Namespace
    source = $sourceText
    # Unmapped authenticated rules default to low-risk suspicious/advisory
    # findings in the client and can never authorize quarantine.
    policies = @()
})
$sourceDigest = [Security.Cryptography.SHA256]::Create()
try { $digest = $sourceDigest.ComputeHash($sourceBytes) } finally { $sourceDigest.Dispose() }
$digestHex = -join ($digest | ForEach-Object { $_.ToString('x2') })
$bundle.sources = @($bundle.sources) + @([ordered]@{
    provider = $Provider
    source_url = $SourceUrl
    retrieved_at = [DateTimeOffset]::UtcNow.ToString('o')
    content_sha256 = $digestHex
    license = $License
})

$outputFullPath = [IO.Path]::GetFullPath($OutputPath)
$outputDirectory = Split-Path -Parent $outputFullPath
New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
$temporaryPath = "$outputFullPath.tmp-$([Guid]::NewGuid().ToString('N'))"
try {
    [IO.File]::WriteAllText($temporaryPath, ($bundle | ConvertTo-Json -Depth 12), [Text.UTF8Encoding]::new($false))
    Move-Item -LiteralPath $temporaryPath -Destination $outputFullPath -Force
} finally {
    if (Test-Path -LiteralPath $temporaryPath) { Remove-Item -LiteralPath $temporaryPath -Force }
}
Write-Host "Added reviewed YARA namespace '$Namespace': $outputFullPath"
Write-Host "Source SHA-256: $digestHex"
Write-Host 'The candidate remains inert until Publish-DefinitionBundle.ps1 compiles and signs it.'
