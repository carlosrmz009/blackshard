#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$DatabaseDirectory,
    [Parameter(Mandatory = $true)]
    [string]$OutputPath,
    [string]$BundleId = ("community-" + [DateTimeOffset]::UtcNow.ToString("yyyyMMddHHmm")),
    [string]$BaseBundlePath,
    [string]$ClamAvMirrorBaseUrl = 'https://database.clamav.net',
    [switch]$IncludePua,
    [Parameter(Mandatory = $true)]
    [switch]$AcceptClamAvGpl2
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not $AcceptClamAvGpl2) {
    throw "Review ClamAV's GPLv2 terms and rerun with -AcceptClamAvGpl2."
}
if (-not (Test-Path -LiteralPath $DatabaseDirectory -PathType Container)) {
    throw "ClamAV database directory was not found: $DatabaseDirectory"
}
if ($BundleId -notmatch '^[A-Za-z0-9._-]{1,128}$') {
    throw "BundleId must contain 1 through 128 letters, digits, dots, underscores, or dashes."
}

$maximumSignatures = 100000
$bundle = if ([string]::IsNullOrWhiteSpace($BaseBundlePath)) {
    [ordered]@{
        schema_version      = 2
        bundle_id          = $BundleId
        exact_sha256       = @()
        yara_bundles       = @()
        similarity_profiles = @()
        sources             = @()
    }
} else {
    if (-not (Test-Path -LiteralPath $BaseBundlePath -PathType Leaf)) {
        throw "Base bundle was not found: $BaseBundlePath"
    }
    Get-Content -LiteralPath $BaseBundlePath -Raw | ConvertFrom-Json
}

if ([int]$bundle.schema_version -ne 2) {
    throw "Only Blackshard definition schema 2 can be extended."
}
$bundle.bundle_id = $BundleId
foreach ($propertyName in @('exact_sha256', 'yara_bundles', 'similarity_profiles', 'sources')) {
    $property = $bundle.PSObject.Properties[$propertyName]
    if ($null -eq $property) {
        $bundle | Add-Member -NotePropertyName $propertyName -NotePropertyValue @()
    } elseif ($null -eq $property.Value) {
        $property.Value = @()
    }
}

$seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$records = [Collections.Generic.List[object]]::new()
foreach ($existing in @($bundle.exact_sha256)) {
    if (-not $seen.Add([string]$existing.sha256)) {
        throw "The base bundle contains duplicate SHA-256 signatures."
    }
    $records.Add($existing)
}

$patterns = @('*.hsb')
if ($IncludePua) { $patterns += '*.hsu' }
$databaseFiles = @(
    foreach ($pattern in $patterns) {
        Get-ChildItem -LiteralPath $DatabaseDirectory -Filter $pattern -File -Recurse
    }
)
if ($databaseFiles.Count -eq 0) {
    throw "No ClamAV SHA-256 .hsb database files were found. Use freshclam and sigtool --unpack first."
}

foreach ($file in $databaseFiles) {
    if ($file.Length -gt 512MB) {
        throw "Refusing oversized ClamAV database file: $($file.FullName)"
    }
    foreach ($line in [IO.File]::ReadLines($file.FullName)) {
        if ([string]::IsNullOrWhiteSpace($line) -or $line.StartsWith('#')) { continue }
        $fields = $line.Split(':', 3)
        if ($fields.Count -ne 3) { continue }
        $digest = $fields[0].Trim().ToLowerInvariant()
        $declaredSize = $fields[1].Trim()
        $name = $fields[2].Trim()
        if ($digest -notmatch '^[0-9a-f]{64}$' -or $declaredSize -notmatch '^(?:[0-9]+|\*)$') {
            continue
        }
        if (-not $seen.Add($digest)) { continue }
        $safeName = [regex]::Replace($name, '[^A-Za-z0-9._-]', '_')
        if ($safeName.Length -gt 145) { $safeName = $safeName.Substring(0, 145) }
        if ([string]::IsNullOrWhiteSpace($safeName)) { $safeName = 'Unclassified' }
        $records.Add([ordered]@{
            sha256     = $digest
            threat_name = "ClamAV.$safeName"
            family     = $null
        })
        if ($records.Count -gt $maximumSignatures) {
            throw "The merged bundle exceeds Blackshard's $maximumSignatures-signature safety limit. Split and curate the source set."
        }
    }
}

$existingSources = @($bundle.sources | Where-Object { $_.provider -ne 'Cisco-Talos-ClamAV' })
$clamSources = @(
    foreach ($file in $databaseFiles) {
        $databaseName = $file.BaseName
        [ordered]@{
            provider       = 'Cisco-Talos-ClamAV'
            source_url     = "$($ClamAvMirrorBaseUrl.TrimEnd('/'))/$databaseName.cvd"
            retrieved_at   = [DateTimeOffset]::UtcNow.ToString('o')
            content_sha256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
            license        = 'GPL-2.0; publisher must review ClamAV database redistribution terms'
        }
    }
)
$bundle.sources = @($existingSources) + @($clamSources)

$bundle.exact_sha256 = @($records | Sort-Object sha256)
$json = $bundle | ConvertTo-Json -Depth 12
$outputFullPath = [IO.Path]::GetFullPath($OutputPath)
$outputDirectory = Split-Path -Parent $outputFullPath
New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
$temporaryPath = "$outputFullPath.tmp-$([Guid]::NewGuid().ToString('N'))"
try {
    [IO.File]::WriteAllText($temporaryPath, $json, [Text.UTF8Encoding]::new($false))
    Move-Item -LiteralPath $temporaryPath -Destination $outputFullPath -Force
} finally {
    if (Test-Path -LiteralPath $temporaryPath) {
        Remove-Item -LiteralPath $temporaryPath -Force
    }
}

Write-Host "Created unsigned candidate bundle: $outputFullPath"
Write-Host "Exact SHA-256 signatures: $($records.Count)"
Write-Host "This candidate is inert until reviewed and wrapped in a Blackshard-signed update envelope."
