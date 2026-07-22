#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$DetectionReportPath,
    [Parameter(Mandatory = $true)]
    [string]$LabelsCsvPath,
    [Parameter(Mandatory = $true)]
    [string]$OutputPath,
    [switch]$AllowScanErrors
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-SafeRatio {
    param([double]$Numerator, [double]$Denominator)
    if ($Denominator -eq 0) { return $null }
    return $Numerator / $Denominator
}

function Get-WilsonInterval {
    param([double]$Successes, [double]$Trials)
    if ($Trials -eq 0) { return [ordered]@{ lower = $null; upper = $null } }
    $z = 1.959963984540054
    $p = $Successes / $Trials
    $denominator = 1 + (($z * $z) / $Trials)
    $center = ($p + (($z * $z) / (2 * $Trials))) / $denominator
    $margin = ($z / $denominator) * [Math]::Sqrt((($p * (1 - $p)) / $Trials) + (($z * $z) / (4 * $Trials * $Trials)))
    return [ordered]@{ lower = [Math]::Max(0.0, $center - $margin); upper = [Math]::Min(1.0, $center + $margin) }
}

foreach ($path in @($DetectionReportPath, $LabelsCsvPath)) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Required file was not found: $path" }
}
$report = Get-Content -LiteralPath $DetectionReportPath -Raw | ConvertFrom-Json
if ([int]$report.schema_version -ne 1 -or $null -eq $report.results) {
    throw 'Detection report schema is unsupported.'
}

$labels = @{}
foreach ($row in @(Import-Csv -LiteralPath $LabelsCsvPath)) {
    $relativePath = ([string]$row.path).Replace('\', '/').TrimStart('/')
    $label = ([string]$row.label).ToLowerInvariant()
    if ([string]::IsNullOrWhiteSpace($relativePath) -or $label -notin @('clean', 'malicious')) {
        throw 'Every label row must contain path and label=clean|malicious.'
    }
    if ($labels.ContainsKey($relativePath)) { throw "Duplicate corpus label: $relativePath" }
    $labels[$relativePath] = $label
}

$rows = @{}
foreach ($result in @($report.results)) {
    $relativePath = ([string]$result.path).Replace('\', '/').TrimStart('/')
    if ($rows.ContainsKey($relativePath)) { throw "Duplicate detection result: $relativePath" }
    $rows[$relativePath] = $result
}
if ($labels.Count -ne $rows.Count) {
    throw "Label/result count mismatch: $($labels.Count) labels and $($rows.Count) results."
}

$tp = 0; $tn = 0; $fp = 0; $fn = 0; $errors = 0
$strictTp = 0; $strictTn = 0; $strictFp = 0; $strictFn = 0
foreach ($entry in $labels.GetEnumerator()) {
    if (-not $rows.ContainsKey($entry.Key)) { throw "No detection result for labeled path: $($entry.Key)" }
    $result = $rows[$entry.Key]
    $verdict = ([string]$result.verdict).ToLowerInvariant()
    $scanFailed = $verdict -eq 'error' -or -not [string]::IsNullOrWhiteSpace([string]$result.error)
    if ($scanFailed) {
        $errors++
        # If explicitly retained in a score, errors are assigned against the
        # product: a missed malicious sample or a disrupted clean sample.
        if ($entry.Value -eq 'malicious') {
            $fn++; $strictFn++
        } else {
            $fp++; $strictFp++
        }
        continue
    }
    $positive = $verdict -in @('suspicious', 'malicious')
    $strictPositive = $verdict -eq 'malicious'
    if ($entry.Value -eq 'malicious') {
        if ($positive) { $tp++ } else { $fn++ }
        if ($strictPositive) { $strictTp++ } else { $strictFn++ }
    } else {
        if ($positive) { $fp++ } else { $tn++ }
        if ($strictPositive) { $strictFp++ } else { $strictTn++ }
    }
}
if ($errors -gt 0 -and -not $AllowScanErrors) {
    throw "The report contains $errors scan errors. Resolve them or explicitly use -AllowScanErrors for conservative scoring."
}

$metrics = [ordered]@{
    schema_version = 1
    generated_at = [DateTimeOffset]::UtcNow.ToString('o')
    source_report = [IO.Path]::GetFullPath($DetectionReportPath)
    source_labels = [IO.Path]::GetFullPath($LabelsCsvPath)
    samples = $labels.Count
    scan_errors = $errors
    review_threshold = [ordered]@{
        positive_verdicts = @('suspicious', 'malicious')
        true_positive = $tp; true_negative = $tn; false_positive = $fp; false_negative = $fn
        recall = Get-SafeRatio $tp ($tp + $fn)
        precision = Get-SafeRatio $tp ($tp + $fp)
        false_positive_rate = Get-SafeRatio $fp ($fp + $tn)
        recall_95_percent_wilson = Get-WilsonInterval $tp ($tp + $fn)
        false_positive_rate_95_percent_wilson = Get-WilsonInterval $fp ($fp + $tn)
    }
    malicious_threshold = [ordered]@{
        positive_verdicts = @('malicious')
        true_positive = $strictTp; true_negative = $strictTn; false_positive = $strictFp; false_negative = $strictFn
        recall = Get-SafeRatio $strictTp ($strictTp + $strictFn)
        precision = Get-SafeRatio $strictTp ($strictTp + $strictFp)
        false_positive_rate = Get-SafeRatio $strictFp ($strictFp + $strictTn)
        recall_95_percent_wilson = Get-WilsonInterval $strictTp ($strictTp + $strictFn)
        false_positive_rate_95_percent_wilson = Get-WilsonInterval $strictFp ($strictFp + $strictTn)
    }
}

$outputFullPath = [IO.Path]::GetFullPath($OutputPath)
$outputDirectory = Split-Path -Parent $outputFullPath
New-Item -ItemType Directory -Path $outputDirectory -Force | Out-Null
$temporaryPath = "$outputFullPath.tmp-$([Guid]::NewGuid().ToString('N'))"
try {
    [IO.File]::WriteAllText($temporaryPath, ($metrics | ConvertTo-Json -Depth 10), [Text.UTF8Encoding]::new($false))
    Move-Item -LiteralPath $temporaryPath -Destination $outputFullPath -Force
} finally {
    if (Test-Path -LiteralPath $temporaryPath) { Remove-Item -LiteralPath $temporaryPath -Force }
}
Write-Host "Scored $($labels.Count) samples; review-threshold recall=$($metrics.review_threshold.recall), FPR=$($metrics.review_threshold.false_positive_rate)."
Write-Host "Evidence metrics: $outputFullPath"
