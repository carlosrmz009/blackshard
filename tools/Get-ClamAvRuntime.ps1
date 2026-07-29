#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$OutputDirectory = (Join-Path $PSScriptRoot "..\build\clamav-runtime")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$releaseApi = "https://api.github.com/repos/Cisco-Talos/clamav/releases/latest"
$repositoryUrl = "https://github.com/Cisco-Talos/clamav"
$buildRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\build"))
$cacheDirectory = Join-Path $buildRoot "downloads"

function Assert-ChildPath {
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        [Parameter(Mandatory)]
        [string]$Root,
        [Parameter(Mandatory)]
        [string]$Description
    )

    $fullPath = [IO.Path]::GetFullPath($Path)
    $fullRoot = [IO.Path]::GetFullPath($Root).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar
    )
    if (-not $fullPath.StartsWith(
        $fullRoot + [IO.Path]::DirectorySeparatorChar,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw "$Description must remain below $fullRoot`: $fullPath"
    }
    return $fullPath
}

$headers = @{
    Accept                 = "application/vnd.github+json"
    "X-GitHub-Api-Version" = "2022-11-28"
    "User-Agent"           = "Blackshard-ClamAV-Runtime-Resolver"
}
if (-not [string]::IsNullOrWhiteSpace($env:GITHUB_TOKEN)) {
    $headers.Authorization = "Bearer $($env:GITHUB_TOKEN)"
}

Write-Host "[*] Resolving the latest stable ClamAV release..." -ForegroundColor Cyan
$release = Invoke-RestMethod -Uri $releaseApi -Headers $headers -UseBasicParsing
if ([bool]$release.draft -or [bool]$release.prerelease) {
    throw "GitHub's latest ClamAV release endpoint returned a draft or prerelease."
}
$tagMatch = [regex]::Match([string]$release.tag_name, "^clamav-(\d+\.\d+\.\d+)$")
if (-not $tagMatch.Success) {
    throw "The latest ClamAV release tag is not a stable semantic version: $($release.tag_name)"
}
$version = $tagMatch.Groups[1].Value
$assetName = "clamav-$version.win.x64.zip"
$assets = @($release.assets | Where-Object { [string]$_.name -ceq $assetName })
if ($assets.Count -ne 1) {
    throw "The latest ClamAV release must contain exactly one $assetName asset."
}
$asset = $assets[0]
$digestMatch = [regex]::Match([string]$asset.digest, "^sha256:([0-9a-fA-F]{64})$")
if (-not $digestMatch.Success) {
    throw "GitHub did not publish a valid SHA-256 digest for $assetName."
}
$expectedSha256 = $digestMatch.Groups[1].Value.ToLowerInvariant()
$expectedUrl = "$repositoryUrl/releases/download/clamav-$version/$assetName"
if ([string]$asset.browser_download_url -cne $expectedUrl) {
    throw "The ClamAV release asset URL was unexpected: $($asset.browser_download_url)"
}
if ([uint64]$asset.size -lt 10MB -or [uint64]$asset.size -gt 1GB) {
    throw "The ClamAV release asset size is outside the accepted range: $($asset.size) bytes."
}
$signatureAssetName = "$assetName.sig"
$signatureAssets = @($release.assets | Where-Object { [string]$_.name -ceq $signatureAssetName })
if ($signatureAssets.Count -ne 1) {
    throw "The latest ClamAV release must contain exactly one $signatureAssetName asset."
}
$signatureAsset = $signatureAssets[0]
$signatureDigestMatch = [regex]::Match(
    [string]$signatureAsset.digest,
    "^sha256:([0-9a-fA-F]{64})$"
)
if (-not $signatureDigestMatch.Success) {
    throw "GitHub did not publish a valid SHA-256 digest for $signatureAssetName."
}
$expectedSignatureSha256 = $signatureDigestMatch.Groups[1].Value.ToLowerInvariant()
$expectedSignatureUrl = "$expectedUrl.sig"
if ([string]$signatureAsset.browser_download_url -cne $expectedSignatureUrl) {
    throw "The ClamAV release signature URL was unexpected: $($signatureAsset.browser_download_url)"
}
if ([uint64]$signatureAsset.size -lt 256 -or [uint64]$signatureAsset.size -gt 64KB) {
    throw "The ClamAV release signature size is outside the accepted range: $($signatureAsset.size) bytes."
}

New-Item -ItemType Directory -Path $cacheDirectory -Force | Out-Null
$archivePath = Join-Path $cacheDirectory $assetName
$cachedHash = if (Test-Path -LiteralPath $archivePath -PathType Leaf) {
    (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
}
else {
    ""
}
if ($cachedHash -ne $expectedSha256) {
    Remove-Item -LiteralPath $archivePath -Force -ErrorAction SilentlyContinue
    $partialPath = "$archivePath.$([Guid]::NewGuid().ToString('N')).partial"
    try {
        Write-Host "[*] Downloading latest stable ClamAV $version runtime..." -ForegroundColor Cyan
        Invoke-WebRequest -Uri $expectedUrl -OutFile $partialPath -UseBasicParsing
        $downloadedHash = (Get-FileHash -LiteralPath $partialPath -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($downloadedHash -ne $expectedSha256) {
            throw "ClamAV runtime hash mismatch. Expected $expectedSha256, received $downloadedHash."
        }
        Move-Item -LiteralPath $partialPath -Destination $archivePath
    }
    finally {
        Remove-Item -LiteralPath $partialPath -Force -ErrorAction SilentlyContinue
    }
}

$actualSha256 = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualSha256 -ne $expectedSha256) {
    throw "ClamAV runtime hash mismatch. Expected $expectedSha256, received $actualSha256."
}

$signaturePath = Join-Path $cacheDirectory $signatureAssetName
$cachedSignatureHash = if (Test-Path -LiteralPath $signaturePath -PathType Leaf) {
    (Get-FileHash -LiteralPath $signaturePath -Algorithm SHA256).Hash.ToLowerInvariant()
}
else {
    ""
}
if ($cachedSignatureHash -ne $expectedSignatureSha256) {
    Remove-Item -LiteralPath $signaturePath -Force -ErrorAction SilentlyContinue
    Invoke-WebRequest -Uri $expectedSignatureUrl -OutFile $signaturePath -UseBasicParsing
}
$actualSignatureSha256 = (Get-FileHash -LiteralPath $signaturePath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualSignatureSha256 -ne $expectedSignatureSha256) {
    throw "ClamAV release-signature hash mismatch. Expected $expectedSignatureSha256, received $actualSignatureSha256."
}

$gpgCandidates = @(
    (Get-Command gpg.exe -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source -First 1),
    (Join-Path $env:ProgramFiles "Git\usr\bin\gpg.exe"),
    (Join-Path $env:ProgramFiles "Git\mingw64\bin\gpg.exe")
) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) -and (Test-Path -LiteralPath $_ -PathType Leaf) }
$gpg = $gpgCandidates | Select-Object -First 1
if ([string]::IsNullOrWhiteSpace($gpg)) {
    throw "GnuPG is required to verify the official ClamAV release signature."
}
$gpgHome = Assert-ChildPath `
    -Path (Join-Path $cacheDirectory "clamav-release-keyring") `
    -Root $buildRoot `
    -Description "ClamAV release keyring"
if (Test-Path -LiteralPath $gpgHome) {
    Remove-Item -LiteralPath $gpgHome -Recurse -Force
}
New-Item -ItemType Directory -Path $gpgHome | Out-Null
$talosKeyUrl = "https://raw.githubusercontent.com/Cisco-Talos/clamav-documentation/main/src/manual/cisco-talos.gpg"
$talosKeyPath = Join-Path $gpgHome "cisco-talos.gpg"
Invoke-WebRequest -Uri $talosKeyUrl -OutFile $talosKeyPath -UseBasicParsing
$keyText = Get-Content -LiteralPath $talosKeyPath -Raw
if ($keyText -notmatch "-----BEGIN PGP PUBLIC KEY BLOCK-----") {
    throw "The official ClamAV documentation endpoint did not return an armored GPG public key."
}
function ConvertTo-GpgPath {
    param(
        [Parameter(Mandatory)]
        [string]$Path
    )

    $fullPath = [IO.Path]::GetFullPath($Path)
    if ($gpg -match "(?i)\\Git\\") {
        $driveMatch = [regex]::Match($fullPath, "^([A-Za-z]):\\(.*)$")
        if (-not $driveMatch.Success) {
            throw "Git-for-Windows GnuPG cannot resolve this path: $fullPath"
        }
        return "/$($driveMatch.Groups[1].Value.ToLowerInvariant())/$($driveMatch.Groups[2].Value.Replace('\', '/'))"
    }
    return $fullPath
}

$gpgHomeArgument = ConvertTo-GpgPath -Path $gpgHome
$talosKeyArgument = ConvertTo-GpgPath -Path $talosKeyPath
$signatureArgument = ConvertTo-GpgPath -Path $signaturePath
$archiveArgument = ConvertTo-GpgPath -Path $archivePath
$savedErrorActionPreference = $ErrorActionPreference
try {
    $ErrorActionPreference = "Continue"
    $importOutput = & $gpg --batch --homedir $gpgHomeArgument --import $talosKeyArgument 2>&1
    $importExitCode = $LASTEXITCODE
    $verifyOutput = if ($importExitCode -eq 0) {
        & $gpg --batch --homedir $gpgHomeArgument --status-fd 1 `
            --verify $signatureArgument $archiveArgument 2>&1
    }
    $verifyExitCode = $LASTEXITCODE
}
finally {
    $ErrorActionPreference = $savedErrorActionPreference
}
if ($importExitCode -ne 0) {
    throw "Could not import the current Cisco Talos ClamAV release key: $($importOutput | Out-String)"
}
if ($verifyExitCode -ne 0 -or ($verifyOutput | Out-String) -notmatch "(?m)^\[GNUPG:\] VALIDSIG ") {
    throw "The Cisco Talos GPG signature did not authenticate $assetName`: $($verifyOutput | Out-String)"
}
$validSignature = [regex]::Match(
    ($verifyOutput | Out-String),
    "(?m)^\[GNUPG:\] VALIDSIG ([0-9A-F]{40,64})\b"
)
$signingFingerprint = $validSignature.Groups[1].Value

$OutputDirectory = Assert-ChildPath -Path $OutputDirectory -Root $buildRoot -Description "ClamAV output directory"
if (Test-Path -LiteralPath $OutputDirectory) {
    Remove-Item -LiteralPath $OutputDirectory -Recurse -Force
}

$extractDirectory = Assert-ChildPath `
    -Path (Join-Path $cacheDirectory "clamav-$version-extracted") `
    -Root $buildRoot `
    -Description "ClamAV extraction directory"
if (Test-Path -LiteralPath $extractDirectory) {
    Remove-Item -LiteralPath $extractDirectory -Recurse -Force
}
Expand-Archive -LiteralPath $archivePath -DestinationPath $extractDirectory -Force
$clamscan = Get-ChildItem -LiteralPath $extractDirectory -Filter "clamscan.exe" -File -Recurse |
    Select-Object -First 1
if ($null -eq $clamscan) {
    throw "The verified ClamAV archive did not contain clamscan.exe."
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

$requiredExecutables = @("clamd.exe", "clamscan.exe", "freshclam.exe", "sigtool.exe")
$requiredLibraries = @("libclamav.dll", "libfreshclam.dll")
foreach ($required in $requiredExecutables + $requiredLibraries) {
    if (-not (Test-Path -LiteralPath (Join-Path $OutputDirectory $required) -PathType Leaf)) {
        throw "The ClamAV runtime is missing $required."
    }
}
$versionOutput = & (Join-Path $OutputDirectory "clamscan.exe") --version 2>&1
if ($LASTEXITCODE -ne 0 -or ($versionOutput | Out-String) -notmatch ("(?m)^ClamAV\s+" + [regex]::Escape($version) + "(\D|$)")) {
    throw "The prepared ClamAV runtime did not report the resolved version $version`: $($versionOutput | Out-String)"
}

$metadata = [ordered]@{
    schema_version  = 1
    version         = $version
    release_tag     = [string]$release.tag_name
    release_url     = [string]$release.html_url
    published_at    = [string]$release.published_at
    archive_name    = $assetName
    archive_sha256  = $actualSha256
    signature_name  = $signatureAssetName
    signer_fingerprint = $signingFingerprint
    signing_key_url = $talosKeyUrl
    resolved_at_utc = [DateTimeOffset]::UtcNow.ToString("o")
}
$metadata | ConvertTo-Json |
    Set-Content -LiteralPath (Join-Path $OutputDirectory "clamav-runtime.json") -Encoding UTF8

Write-Host "[+] Latest stable ClamAV $version runtime prepared at $OutputDirectory" -ForegroundColor Green
