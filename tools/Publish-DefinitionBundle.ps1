#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$BundlePath,
    [Parameter(Mandatory = $true)]
    [string]$PrivateKeyPath,
    [Parameter(Mandatory = $true)]
    [string]$PublicKeyPath,
    [Parameter(Mandatory = $true)]
    [UInt64]$Sequence,
    [Parameter(Mandatory = $true)]
    [string]$Version,
    [Parameter(Mandatory = $true)]
    [string]$PayloadUrl,
    [Parameter(Mandatory = $true)]
    [string]$OutputDirectory,
    [ValidateRange(1, 168)]
    [int]$ExpiryHours = 24,
    [string]$OpenSslPath,
    [string]$ValidatorPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Add-BigEndianBytes {
    param([Collections.Generic.List[byte]]$Destination, [byte[]]$Bytes)
    if ([BitConverter]::IsLittleEndian) { [Array]::Reverse($Bytes) }
    $Destination.AddRange($Bytes)
}

function Add-LengthPrefixedUtf8 {
    param([Collections.Generic.List[byte]]$Destination, [string]$Value)
    $encoded = [Text.Encoding]::UTF8.GetBytes($Value)
    if ($encoded.Length -gt [UInt32]::MaxValue) { throw "Manifest string is too long." }
    Add-BigEndianBytes $Destination ([BitConverter]::GetBytes([UInt32]$encoded.Length))
    $Destination.AddRange($encoded)
}

foreach ($path in @($BundlePath, $PrivateKeyPath, $PublicKeyPath)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Required file was not found: $path" }
    if ((Get-Item -LiteralPath $path).Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw "Signing inputs must not be reparse points: $path"
    }
}
if ($Sequence -eq 0 -or $Sequence -eq [UInt64]::MaxValue) {
    throw "Sequence must be between 1 and UInt64.MaxValue - 1."
}
if ([string]::IsNullOrWhiteSpace($Version) -or [Text.Encoding]::UTF8.GetByteCount($Version) -gt 128) {
    throw "Version must contain 1 through 128 UTF-8 bytes."
}
$payloadUri = $null
if (-not [Uri]::TryCreate($PayloadUrl, [UriKind]::Absolute, [ref]$payloadUri) -or
    $payloadUri.Scheme -ne 'https' -or [string]::IsNullOrWhiteSpace($payloadUri.Host) -or
    -not [string]::IsNullOrEmpty($payloadUri.UserInfo) -or
    -not [string]::IsNullOrEmpty($payloadUri.Fragment)) {
    throw "PayloadUrl must be an absolute HTTPS URL without credentials or a fragment."
}
$payloadFileName = [IO.Path]::GetFileName($payloadUri.AbsolutePath)
if ($payloadFileName -notmatch '^[A-Za-z0-9._-]{1,128}$' -or $payloadFileName -eq 'manifest.json') {
    throw 'PayloadUrl must end in a safe, non-manifest payload filename.'
}

if ([string]::IsNullOrWhiteSpace($OpenSslPath)) {
    $openssl = Get-Command openssl.exe -ErrorAction SilentlyContinue
    if ($null -eq $openssl) { throw "OpenSSL was not found. Pass -OpenSslPath explicitly." }
    $OpenSslPath = $openssl.Source
}
if (-not (Test-Path -LiteralPath $OpenSslPath -PathType Leaf)) { throw "OpenSSL was not found: $OpenSslPath" }

$payload = [IO.File]::ReadAllBytes([IO.Path]::GetFullPath($BundlePath))
if ($payload.Length -gt 16MB) { throw "Definition bundle exceeds the 16 MiB client limit." }
$parsedBundle = [Text.Encoding]::UTF8.GetString($payload) | ConvertFrom-Json
if ([int]$parsedBundle.schema_version -ne 2) { throw "Definition bundle schema must be 2." }
$payloadHash = [Security.Cryptography.SHA256]::Create()
try { $payloadDigest = $payloadHash.ComputeHash($payload) } finally { $payloadHash.Dispose() }
$payloadDigestHex = -join ($payloadDigest | ForEach-Object { $_.ToString('x2') })

$issued = [DateTimeOffset]::FromUnixTimeSeconds([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())
$expires = $issued.AddHours($ExpiryHours)
$manifest = [ordered]@{
    schema_version = 2
    product = 'blackshard'
    channel = 'stable'
    sequence = $Sequence
    version = $Version
    issued_at = $issued.ToString('o')
    expires_at = $expires.ToString('o')
    payload_url = $PayloadUrl
    payload_size = [UInt64]$payload.Length
    payload_sha256 = $payloadDigestHex
}

$signed = [Collections.Generic.List[byte]]::new()
$signed.AddRange([Text.Encoding]::ASCII.GetBytes("BLACKSHARD-UPDATE-MANIFEST-V2`0"))
Add-BigEndianBytes $signed ([BitConverter]::GetBytes([UInt32]2))
Add-LengthPrefixedUtf8 $signed 'blackshard'
Add-LengthPrefixedUtf8 $signed 'stable'
Add-BigEndianBytes $signed ([BitConverter]::GetBytes([UInt64]$Sequence))
Add-BigEndianBytes $signed ([BitConverter]::GetBytes([Int64]$issued.ToUnixTimeSeconds()))
Add-BigEndianBytes $signed ([BitConverter]::GetBytes([UInt32]0))
Add-BigEndianBytes $signed ([BitConverter]::GetBytes([Int64]$expires.ToUnixTimeSeconds()))
Add-BigEndianBytes $signed ([BitConverter]::GetBytes([UInt32]0))
Add-BigEndianBytes $signed ([BitConverter]::GetBytes([UInt64]$payload.Length))
Add-LengthPrefixedUtf8 $signed $Version
Add-LengthPrefixedUtf8 $signed $PayloadUrl
$signed.AddRange($payloadDigest)

$outputFullPath = [IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Path $outputFullPath -Force | Out-Null
$workDirectory = Join-Path $outputFullPath (".signing-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $workDirectory | Out-Null
try {
    $signingInput = Join-Path $workDirectory 'manifest.bin'
    $signaturePath = Join-Path $workDirectory 'manifest.sig'
    $publicDerPath = Join-Path $workDirectory 'public.der'
    [IO.File]::WriteAllBytes($signingInput, $signed.ToArray())
    & $OpenSslPath pkeyutl -sign -rawin -inkey $PrivateKeyPath -in $signingInput -out $signaturePath
    if ($LASTEXITCODE -ne 0) { throw "OpenSSL could not sign the manifest." }
    & $OpenSslPath pkeyutl -verify -pubin -inkey $PublicKeyPath -rawin -in $signingInput -sigfile $signaturePath
    if ($LASTEXITCODE -ne 0) { throw "The supplied public key did not verify the new signature." }
    & $OpenSslPath pkey -pubin -in $PublicKeyPath -outform DER -out $publicDerPath
    if ($LASTEXITCODE -ne 0) { throw "OpenSSL could not export the Ed25519 public key." }
    $publicDer = [IO.File]::ReadAllBytes($publicDerPath)
    $prefixHex = -join ($publicDer[0..([Math]::Min(11, $publicDer.Length - 1))] | ForEach-Object { $_.ToString('x2') })
    if ($publicDer.Length -ne 44 -or $prefixHex -ne '302a300506032b6570032100') {
        throw "PublicKeyPath is not a canonical Ed25519 SubjectPublicKeyInfo key."
    }
    $publicKeyHex = -join ($publicDer[12..43] | ForEach-Object { $_.ToString('x2') })
    $signature = [IO.File]::ReadAllBytes($signaturePath)
    if ($signature.Length -ne 64) { throw "Ed25519 signature must be exactly 64 bytes." }
    $signatureHex = -join ($signature | ForEach-Object { $_.ToString('x2') })
    $envelope = [ordered]@{ manifest = $manifest; signature_ed25519 = $signatureHex }

    $publicationId = [Guid]::NewGuid().ToString('N')
    $payloadCandidate = Join-Path $workDirectory "rules-$publicationId.bundle"
    $envelopeCandidate = Join-Path $workDirectory "envelope-$publicationId.json"
    [IO.File]::WriteAllBytes($payloadCandidate, $payload)
    [IO.File]::WriteAllText(
        $envelopeCandidate,
        ($envelope | ConvertTo-Json -Depth 8),
        [Text.UTF8Encoding]::new($false)
    )
    if (-not [string]::IsNullOrWhiteSpace($ValidatorPath)) {
        if (-not (Test-Path -LiteralPath $ValidatorPath -PathType Leaf)) {
            throw "Blackshard validator was not found: $ValidatorPath"
        }
        foreach ($value in @($envelopeCandidate, $payloadCandidate, $publicKeyHex)) {
            if ($value.Contains('"')) { throw "Validator arguments must not contain quote characters." }
        }
        $validatorArguments = "--verify-definition-update `"$envelopeCandidate`" `"$payloadCandidate`" $publicKeyHex"
        $validator = Start-Process -FilePath $ValidatorPath -ArgumentList $validatorArguments -PassThru -WindowStyle Hidden
        if (-not $validator.WaitForExit(15000)) {
            $validator.Kill()
            $validator.WaitForExit()
            throw "Blackshard definition validation exceeded 15 seconds."
        }
        if ($validator.ExitCode -ne 0) {
            throw "Blackshard rejected the newly signed definition update (exit $($validator.ExitCode))."
        }
        Write-Host "Blackshard client validation: passed"
    }

    $payloadOutput = Join-Path $outputFullPath $payloadFileName
    $envelopeOutput = Join-Path $outputFullPath 'manifest.json'
    Move-Item -LiteralPath $payloadCandidate -Destination $payloadOutput -Force
    Move-Item -LiteralPath $envelopeCandidate -Destination $envelopeOutput -Force
    Write-Host "Published payload: $payloadOutput"
    Write-Host "Published envelope: $envelopeOutput"
    Write-Host "Payload SHA-256: $payloadDigestHex"
    Write-Host "Release public key: $publicKeyHex"
} finally {
    if (Test-Path -LiteralPath $workDirectory -PathType Container) {
        $resolvedWork = [IO.Path]::GetFullPath($workDirectory)
        $resolvedOutput = [IO.Path]::GetFullPath($outputFullPath).TrimEnd([IO.Path]::DirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
        if (-not $resolvedWork.StartsWith($resolvedOutput, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Refusing to clean a signing workspace outside the selected output directory."
        }
        Remove-Item -LiteralPath $workDirectory -Recurse -Force
    }
}
