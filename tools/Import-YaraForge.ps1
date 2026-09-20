#Requires -Version 5.1

<#
.SYNOPSIS
Imports a YARA-Forge rule package into a blackshard definition bundle.

.DESCRIPTION
YARA-Forge aggregates the public YARA rule repositories into deduplicated, quality graded packages
that are guaranteed to compile. It is preferred over importing each upstream repository separately
because it tracks the licence of every rule and lets the restrictive ones be excluded.

Three tiers are published:

  core      highest confidence, lowest false positive risk, and the default here
  extended  broader coverage with a correspondingly higher false positive rate
  full      everything, including rules that are noisy or expensive to evaluate

Only the release asset is downloaded; its SHA-256 is recorded in the bundle provenance so a later
build can prove which package it consumed. The resulting rules are handed to Import-YaraSource.ps1,
which performs the actual bundle merge.

.PARAMETER Tier
Which YARA-Forge package to import. Defaults to 'core'.

.PARAMETER Tag
A specific YARA-Forge release tag, for example '20260913'. Defaults to the latest release.

.PARAMETER ExcludeLicensePattern
A regular expression matched against each rule's `license` metadata. Any rule that matches is
dropped before import. Nothing is excluded by default.

The core tier is dominated by the Detection Rule License 1.1, which permits commercial use with
attribution, alongside Apache-2.0, BSD-2-Clause, MIT and CC BY 4.0. None of these forbid commercial
use, so no exclusion is needed for a straightforward deployment. Use this parameter if a specific
licence is incompatible with how you intend to redistribute the bundle; the extended and full tiers
draw from a wider set of sources than core, so review their mix before shipping them.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$BaseBundlePath,
    [Parameter(Mandatory = $true)]
    [string]$OutputPath,
    [ValidateSet('core', 'extended', 'full')]
    [string]$Tier = 'core',
    [string]$Tag,
    [string]$Namespace = 'yara_forge',
    [string]$BundleId = ('yara-forge-' + [DateTimeOffset]::UtcNow.ToString('yyyyMMddHHmm')),
    [string]$ExcludeLicensePattern,
    [Parameter(Mandatory = $true)]
    [switch]$AcceptReviewedSource
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not $AcceptReviewedSource) {
    throw 'Review the YARA-Forge package licences and false-positive posture before importing.'
}

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$repository = 'YARAHQ/yara-forge'
$headers = @{ 'User-Agent' = 'blackshard-yara-forge-importer' }

function Remove-RulesByLicense {
    <#
    .SYNOPSIS
    Copies a rule file, omitting every rule whose license metadata matches a pattern.

    .DESCRIPTION
    Rules are delimited by a top level `rule` keyword, so the file is walked a line at a time while
    tracking brace depth. Anything outside a rule body, such as the import statements, is always
    preserved.
    #>
    param(
        [Parameter(Mandatory)][string]$InputPath,
        [Parameter(Mandatory)][string]$OutputPath,
        [Parameter(Mandatory)][string]$Pattern
    )

    $writer = [IO.StreamWriter]::new($OutputPath, $false, [Text.UTF8Encoding]::new($false))
    $dropped = 0
    try {
        $buffer = [Collections.Generic.List[string]]::new()
        $depth = 0
        $inRule = $false
        $matched = $false

        foreach ($line in [IO.File]::ReadLines($InputPath)) {
            if (-not $inRule) {
                if ($line -match '^rule\s') {
                    $inRule = $true
                    $matched = $false
                    $buffer.Clear()
                }
                else {
                    $writer.WriteLine($line)
                    continue
                }
            }

            $buffer.Add($line)
            if ($line -match '^\s+license\s*=\s*"(.+)"' -and $Matches[1] -match $Pattern) {
                $matched = $true
            }

            $depth += ([regex]::Matches($line, '{')).Count
            $depth -= ([regex]::Matches($line, '}')).Count

            if ($depth -le 0) {
                if ($matched) { $dropped++ } else { $buffer | ForEach-Object { $writer.WriteLine($_) } }
                $inRule = $false
                $depth = 0
            }
        }
    }
    finally {
        $writer.Dispose()
    }
    return $dropped
}

if (-not $Tag) {
    $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$repository/releases/latest" -Headers $headers
    $Tag = $release.tag_name
    Write-Host "[*] Latest YARA-Forge release is $Tag"
}
if ($Tag -notmatch '^[A-Za-z0-9._-]{1,64}$') {
    throw "Refusing an implausible release tag: $Tag"
}

$assetName = "yara-forge-rules-$Tier.zip"
$assetUrl = "https://github.com/$repository/releases/download/$Tag/$assetName"

$staging = Join-Path ([IO.Path]::GetTempPath()) ("yara-forge-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $staging -Force | Out-Null

try {
    $archive = Join-Path $staging $assetName
    Write-Host "[*] Downloading $assetUrl"
    Invoke-WebRequest -Uri $assetUrl -OutFile $archive -Headers $headers -UseBasicParsing

    $sha256 = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()
    Write-Host "[*] Package SHA-256 is $sha256"

    Expand-Archive -LiteralPath $archive -DestinationPath $staging -Force
    $rulePath = Join-Path $staging "packages/$Tier/yara-rules-$Tier.yar"
    if (-not (Test-Path -LiteralPath $rulePath -PathType Leaf)) {
        throw "The YARA-Forge package did not contain the expected rule file: $rulePath"
    }

    $licenses = @(Select-String -LiteralPath $rulePath -Pattern '^\s+license\s*=\s*"(.+)"' -AllMatches |
        ForEach-Object { $_.Matches[0].Groups[1].Value } | Sort-Object -Unique)
    Write-Host "[*] Package carries $($licenses.Count) distinct rule licences:"
    $licenses | ForEach-Object { Write-Host "      $_" }

    if ($ExcludeLicensePattern) {
        $filtered = Join-Path $staging "yara-rules-$Tier-filtered.yar"
        $dropped = Remove-RulesByLicense -InputPath $rulePath -OutputPath $filtered -Pattern $ExcludeLicensePattern
        Write-Host "[*] Excluded $dropped rules whose licence matched /$ExcludeLicensePattern/"
        $rulePath = $filtered
    }

    $ruleCount = @(Select-String -LiteralPath $rulePath -Pattern '^rule\s' -AllMatches).Count
    Write-Host "[*] Importing $ruleCount rules into namespace '$Namespace'"

    & (Join-Path $PSScriptRoot 'Import-YaraSource.ps1') `
        -BaseBundlePath $BaseBundlePath `
        -YaraSourcePath $rulePath `
        -Namespace $Namespace `
        -Provider "YARA-Forge ($Tier)" `
        -SourceUrl $assetUrl `
        -License 'Mixed; per-rule licence retained in each rule''s metadata' `
        -OutputPath $OutputPath `
        -BundleId $BundleId `
        -AcceptReviewedSource

    Write-Host "[+] Wrote $OutputPath" -ForegroundColor Green
}
finally {
    Remove-Item -LiteralPath $staging -Recurse -Force -ErrorAction SilentlyContinue
}
