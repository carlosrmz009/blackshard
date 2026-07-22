#Requires -Version 5.1

[CmdletBinding()]
param(
    [string]$ProductVersion = "0.1.0",
    [string]$AgentPath,
    [string]$DriverPackageDirectory,
    [string]$AssignedMinifilterAltitude,
    [string]$SigningCertificateThumbprint,
    [ValidateSet("CurrentUser", "LocalMachine")]
    [string]$CertificateStoreLocation = "CurrentUser",
    [string]$TimestampUrl = "http://timestamp.digicert.com",
    [string]$OutputDirectory,
    [string]$SignToolPath,
    [string]$InfVerifPath,
    [switch]$AcceptWixEula
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))

if ([string]::IsNullOrWhiteSpace($AgentPath)) {
    $AgentPath = Join-Path $repositoryRoot "target\release\blackshard.exe"
}

if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $repositoryRoot "target\production-installer"
}

function Assert-FileExists {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "$Description was not found: $Path"
    }
}

function Invoke-NativeTool {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath,
        [Parameter(Mandatory = $true)]
        [string[]]$ArgumentList,
        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    Write-Host "==> $Description"
    & $FilePath @ArgumentList
    if ($LASTEXITCODE -ne 0) {
        throw "$Description failed with exit code $LASTEXITCODE."
    }
}

function Resolve-WindowsKitTool {
    param(
        [Parameter(Mandatory = $true)]
        [string]$FileName
    )

    $kitRoots = @()
    if (-not [string]::IsNullOrWhiteSpace(${env:ProgramFiles(x86)})) {
        $kitRoots += (Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\bin")
    }
    if (-not [string]::IsNullOrWhiteSpace($env:ProgramFiles)) {
        $kitRoots += (Join-Path $env:ProgramFiles "Windows Kits\10\bin")
    }

    $candidates = @()
    foreach ($kitRoot in $kitRoots) {
        if (-not (Test-Path -LiteralPath $kitRoot -PathType Container)) {
            continue
        }

        $versionDirectories = Get-ChildItem -LiteralPath $kitRoot -Directory -ErrorAction SilentlyContinue
        foreach ($versionDirectory in $versionDirectories) {
            $candidate = Join-Path $versionDirectory.FullName "x64\$FileName"
            if (Test-Path -LiteralPath $candidate -PathType Leaf) {
                $candidates += Get-Item -LiteralPath $candidate
            }
        }
    }

    $selected = $candidates |
        Sort-Object @{ Expression = {
            $version = $null
            if ([Version]::TryParse($_.Directory.Parent.Name, [ref]$version)) {
                return $version
            }
            return [Version]"0.0"
        }; Descending = $true } |
        Select-Object -First 1

    if ($null -eq $selected) {
        return $null
    }

    return $selected.FullName
}

function Resolve-InfVerif {
    if (-not [string]::IsNullOrWhiteSpace($InfVerifPath)) {
        Assert-FileExists -Path $InfVerifPath -Description "InfVerif"
        return [System.IO.Path]::GetFullPath($InfVerifPath)
    }

    $installed = Resolve-WindowsKitTool -FileName "infverif.exe"
    if (-not [string]::IsNullOrWhiteSpace($installed)) {
        return $installed
    }

    $nugetRoot = Join-Path $repositoryRoot "target\wdk-nuget"
    if (Test-Path -LiteralPath $nugetRoot -PathType Container) {
        $fallback = Get-ChildItem -LiteralPath $nugetRoot -Filter "infverif.exe" -File -Recurse -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match "[\\/]x64[\\/]infverif\.exe$" } |
            Sort-Object FullName -Descending |
            Select-Object -First 1
        if ($null -ne $fallback) {
            return $fallback.FullName
        }
    }

    throw "InfVerif was not found. Install the current WDK or run build-driver.ps1 to provision the pinned WDK fallback."
}

function Resolve-MsBuildEngine {
    $dotnet = Get-Command "dotnet.exe" -ErrorAction SilentlyContinue
    if ($null -ne $dotnet) {
        $installedSdks = @(& $dotnet.Source --list-sdks 2>$null)
        if ($LASTEXITCODE -eq 0 -and $installedSdks.Count -gt 0) {
            return @{
                Kind = "dotnet"
                Path = $dotnet.Source
            }
        }
    }

    $visualStudioRoot = ${env:ProgramFiles(x86)}
    if (-not [string]::IsNullOrWhiteSpace($visualStudioRoot)) {
        $vsWhere = Join-Path $visualStudioRoot "Microsoft Visual Studio\Installer\vswhere.exe"
        if (Test-Path -LiteralPath $vsWhere -PathType Leaf) {
            $installationPath = (& $vsWhere -latest -products * -requires Microsoft.Component.MSBuild -property installationPath 2>$null | Select-Object -First 1)
            if ($LASTEXITCODE -eq 0 -and -not [string]::IsNullOrWhiteSpace($installationPath)) {
                $candidate = Join-Path $installationPath "MSBuild\Current\Bin\amd64\MSBuild.exe"
                if (Test-Path -LiteralPath $candidate -PathType Leaf) {
                    return @{
                        Kind = "msbuild"
                        Path = $candidate
                    }
                }
            }
        }

        $knownMsBuild = Join-Path $visualStudioRoot "Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\amd64\MSBuild.exe"
        if (Test-Path -LiteralPath $knownMsBuild -PathType Leaf) {
            return @{
                Kind = "msbuild"
                Path = $knownMsBuild
            }
        }
    }

    throw "No supported build engine was found. Install the .NET SDK or Visual Studio 2022 Build Tools with MSBuild."
}

function Invoke-WixProjectBuild {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$BuildEngine,
        [Parameter(Mandatory = $true)]
        [string]$ProjectPath,
        [Parameter(Mandatory = $true)]
        [hashtable]$Properties,
        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    $propertyArguments = @()
    foreach ($propertyName in ($Properties.Keys | Sort-Object)) {
        $propertyArguments += "/p:$propertyName=$($Properties[$propertyName])"
    }

    if ($BuildEngine.Kind -eq "dotnet") {
        $arguments = @(
            "build",
            $ProjectPath,
            "--configuration", "Release",
            "--nologo"
        ) + $propertyArguments
    }
    else {
        $arguments = @(
            $ProjectPath,
            "/restore",
            "/t:Build",
            "/m",
            "/nologo",
            "/verbosity:minimal"
        ) + $propertyArguments
    }

    Invoke-NativeTool -FilePath $BuildEngine.Path -ArgumentList $arguments -Description $Description
}

function Get-PeMachine {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
    try {
        $reader = New-Object System.IO.BinaryReader($stream)
        try {
            if ($reader.ReadUInt16() -ne 0x5A4D) {
                throw "Not a PE file: $Path"
            }
            $stream.Position = 0x3C
            $peOffset = $reader.ReadInt32()
            if ($peOffset -lt 0 -or $peOffset -gt ($stream.Length - 6)) {
                throw "Invalid PE header offset in: $Path"
            }
            $stream.Position = $peOffset
            if ($reader.ReadUInt32() -ne 0x00004550) {
                throw "Invalid PE signature in: $Path"
            }
            return $reader.ReadUInt16()
        }
        finally {
            $reader.Dispose()
        }
    }
    finally {
        $stream.Dispose()
    }
}

function Assert-X64PeFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    $machine = Get-PeMachine -Path $Path
    if ($machine -ne 0x8664) {
        throw "$Description must be an x64 PE image (machine 0x8664); found 0x$($machine.ToString('X4')) in $Path"
    }
}

function Assert-CodeSigningCertificate {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Thumbprint,
        [Parameter(Mandatory = $true)]
        [string]$StoreLocation
    )

    $normalizedThumbprint = ($Thumbprint -replace "[^0-9A-Fa-f]", "").ToUpperInvariant()
    if ($normalizedThumbprint -notmatch "^[0-9A-F]{40}$") {
        throw "SigningCertificateThumbprint must be a 40-character SHA-1 certificate thumbprint."
    }

    $certificatePath = "Cert:\$StoreLocation\My\$normalizedThumbprint"
    if (-not (Test-Path -LiteralPath $certificatePath)) {
        throw "The signing certificate was not found at $certificatePath."
    }

    $certificate = Get-Item -LiteralPath $certificatePath
    if (-not $certificate.HasPrivateKey) {
        throw "The signing certificate does not have an accessible private key: $certificatePath"
    }

    $now = Get-Date
    if ($now -lt $certificate.NotBefore -or $now -ge $certificate.NotAfter) {
        throw "The signing certificate is not currently valid (valid from $($certificate.NotBefore) through $($certificate.NotAfter))."
    }

    $codeSigningOid = "1.3.6.1.5.5.7.3.3"
    $hasCodeSigningEku = $false
    foreach ($eku in $certificate.EnhancedKeyUsageList) {
        if ($eku.ObjectId.Value -eq $codeSigningOid) {
            $hasCodeSigningEku = $true
            break
        }
    }
    if (-not $hasCodeSigningEku) {
        throw "The selected certificate does not include the Code Signing EKU ($codeSigningOid)."
    }

    $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
    try {
        $chain.ChainPolicy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::Online
        $chain.ChainPolicy.RevocationFlag = [System.Security.Cryptography.X509Certificates.X509RevocationFlag]::ExcludeRoot
        $chain.ChainPolicy.VerificationFlags = [System.Security.Cryptography.X509Certificates.X509VerificationFlags]::NoFlag
        $chain.ChainPolicy.UrlRetrievalTimeout = [TimeSpan]::FromSeconds(20)
        if (-not $chain.Build($certificate)) {
            $chainErrors = @($chain.ChainStatus | ForEach-Object { $_.Status.ToString() + ": " + $_.StatusInformation.Trim() }) -join "; "
            throw "The signing certificate chain or revocation status could not be validated: $chainErrors"
        }

        $rootCertificate = $chain.ChainElements[$chain.ChainElements.Count - 1].Certificate
        if ($certificate.Thumbprint -eq $rootCertificate.Thumbprint) {
            throw "A self-signed code-signing certificate is not accepted for a public production release."
        }
    }
    finally {
        $chain.Dispose()
    }

    return @{
        Certificate = $certificate
        Thumbprint = $normalizedThumbprint
    }
}

function Assert-MicrosoftSignedDriverPackage {
    param(
        [Parameter(Mandatory = $true)]
        [string]$InfPath,
        [Parameter(Mandatory = $true)]
        [string]$SysPath,
        [Parameter(Mandatory = $true)]
        [string]$CatPath,
        [Parameter(Mandatory = $true)]
        [string]$SignTool,
        [Parameter(Mandatory = $true)]
        [string]$InfVerif,
        [Parameter(Mandatory = $true)]
        [string]$ExpectedAltitude
    )

    $infText = Get-Content -LiteralPath $InfPath -Raw
    $altitudeMatches = [regex]::Matches(
        $infText,
        '(?im)^\s*HKR\s*,\s*"Parameters\\Instances\\blackshard Instance"\s*,\s*"Altitude"\s*,[^\r\n,]*,\s*"([0-9]+(?:\.[0-9]+)?)"\s*(?:;.*)?$'
    )
    if ($altitudeMatches.Count -ne 1) {
        throw "The driver INF must declare exactly one altitude for the Blackshard minifilter instance; found $($altitudeMatches.Count)."
    }
    $declaredAltitude = $altitudeMatches[0].Groups[1].Value
    if ($declaredAltitude -in @("328000", "320000.4242")) {
        throw "The driver INF uses a reserved/development altitude ($declaredAltitude). Obtain Blackshard's unique altitude from Microsoft before packaging."
    }
    if ($declaredAltitude -ne $ExpectedAltitude) {
        throw "The driver INF altitude ($declaredAltitude) does not match -AssignedMinifilterAltitude ($ExpectedAltitude)."
    }

    Invoke-NativeTool -FilePath $InfVerif -ArgumentList @("/h", "/v", $InfPath) -Description "Validate the driver INF against current rules"

    $catalogSignature = Get-AuthenticodeSignature -LiteralPath $CatPath
    if ($catalogSignature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
        throw "The driver catalog does not have a valid trusted Authenticode signature: $($catalogSignature.StatusMessage)"
    }
    if ($null -eq $catalogSignature.SignerCertificate) {
        throw "The driver catalog signature does not expose a signer certificate."
    }

    $catalogSigner = $catalogSignature.SignerCertificate.Subject
    if ($catalogSigner -notmatch "Microsoft Windows (Hardware Compatibility|Third Party Component)") {
        throw "The driver catalog is not signed by the Microsoft hardware-signing pipeline. Signer: $catalogSigner"
    }

    Invoke-NativeTool -FilePath $SignTool -ArgumentList @("verify", "/kp", "/all", "/v", "/c", $CatPath, $SysPath) -Description "Verify the kernel-mode driver and catalog"
    Invoke-NativeTool -FilePath $SignTool -ArgumentList @("verify", "/kp", "/all", "/v", "/c", $CatPath, $InfPath) -Description "Verify the driver INF is covered by the catalog"
}

function Invoke-AuthenticodeSign {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [string]$Description,
        [Parameter(Mandatory = $true)]
        [string]$SignTool,
        [Parameter(Mandatory = $true)]
        [string]$Thumbprint,
        [Parameter(Mandatory = $true)]
        [string]$StoreLocation,
        [Parameter(Mandatory = $true)]
        [string]$TimestampServer
    )

    $arguments = @("sign", "/v", "/s", "My")
    if ($StoreLocation -eq "LocalMachine") {
        $arguments += "/sm"
    }
    $arguments += @(
        "/sha1", $Thumbprint,
        "/fd", "SHA256",
        "/tr", $TimestampServer,
        "/td", "SHA256",
        "/d", $Description,
        $Path
    )

    Invoke-NativeTool -FilePath $SignTool -ArgumentList $arguments -Description "Sign $Description"
    Invoke-NativeTool -FilePath $SignTool -ArgumentList @("verify", "/pa", "/all", "/v", $Path) -Description "Verify $Description signature"
}

function Remove-BuildWorkspaceSafely {
    param(
        [Parameter(Mandatory = $true)]
        [string]$BuildWorkspace,
        [Parameter(Mandatory = $true)]
        [string]$AllowedParent
    )

    if (-not (Test-Path -LiteralPath $BuildWorkspace -PathType Container)) {
        return
    }

    $resolvedWorkspace = [System.IO.Path]::GetFullPath((Resolve-Path -LiteralPath $BuildWorkspace).Path)
    $resolvedParent = [System.IO.Path]::GetFullPath((Resolve-Path -LiteralPath $AllowedParent).Path)
    $parentPrefix = $resolvedParent.TrimEnd([System.IO.Path]::DirectorySeparatorChar) + [System.IO.Path]::DirectorySeparatorChar
    if (-not $resolvedWorkspace.StartsWith($parentPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to remove build workspace outside $resolvedParent`: $resolvedWorkspace"
    }

    Remove-Item -LiteralPath $resolvedWorkspace -Recurse -Force
}

if (-not $AcceptWixEula) {
    throw "Review the WiX v7 OSMF/EULA terms at https://docs.firegiant.com/wix/osmf/ and rerun with -AcceptWixEula."
}

$versionMatch = [regex]::Match($ProductVersion, "^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
if (-not $versionMatch.Success) {
    throw "ProductVersion must contain exactly three numeric fields, for example 1.2.345."
}
$majorVersion = [int]$versionMatch.Groups[1].Value
$minorVersion = [int]$versionMatch.Groups[2].Value
$buildVersion = [int]$versionMatch.Groups[3].Value
if ($majorVersion -gt 255 -or $minorVersion -gt 255 -or $buildVersion -gt 65535) {
    throw "ProductVersion exceeds Windows Installer limits (major/minor <= 255, build <= 65535)."
}

if ([string]::IsNullOrWhiteSpace($DriverPackageDirectory)) {
    throw "DriverPackageDirectory is required and must contain the Microsoft-signed blackshard.inf, blackshard.sys, and blackshard.cat files."
}
if ([string]::IsNullOrWhiteSpace($AssignedMinifilterAltitude) -or
    $AssignedMinifilterAltitude -notmatch '^[0-9]+(?:\.[0-9]+)?$' -or
    $AssignedMinifilterAltitude -in @("328000", "320000.4242")) {
    throw "AssignedMinifilterAltitude is required and must be Blackshard's unique Microsoft-assigned production altitude."
}
if ([string]::IsNullOrWhiteSpace($SigningCertificateThumbprint)) {
    throw "SigningCertificateThumbprint is required. Unsigned release output is not supported."
}

$timestampUri = $null
if (-not [Uri]::TryCreate($TimestampUrl, [UriKind]::Absolute, [ref]$timestampUri) -or $timestampUri.Scheme -notin @("http", "https")) {
    throw "TimestampUrl must be an absolute HTTP or HTTPS URL."
}

$AgentPath = [System.IO.Path]::GetFullPath($AgentPath)
$DriverPackageDirectory = [System.IO.Path]::GetFullPath($DriverPackageDirectory)
$OutputDirectory = [System.IO.Path]::GetFullPath($OutputDirectory)

Assert-FileExists -Path $AgentPath -Description "Release agent"
if (-not (Test-Path -LiteralPath $DriverPackageDirectory -PathType Container)) {
    throw "DriverPackageDirectory was not found: $DriverPackageDirectory"
}

$driverInf = Join-Path $DriverPackageDirectory "blackshard.inf"
$driverSys = Join-Path $DriverPackageDirectory "blackshard.sys"
$driverCat = Join-Path $DriverPackageDirectory "blackshard.cat"
Assert-FileExists -Path $driverInf -Description "Production driver INF"
Assert-FileExists -Path $driverSys -Description "Production driver binary"
Assert-FileExists -Path $driverCat -Description "Production driver catalog"
Assert-X64PeFile -Path $AgentPath -Description "Blackshard agent"
Assert-X64PeFile -Path $driverSys -Description "Blackshard driver"

if ([string]::IsNullOrWhiteSpace($SignToolPath)) {
    $SignToolPath = Resolve-WindowsKitTool -FileName "signtool.exe"
    if ([string]::IsNullOrWhiteSpace($SignToolPath)) {
        throw "signtool.exe was not found. Install a current Windows SDK."
    }
}
Assert-FileExists -Path $SignToolPath -Description "SignTool"
$SignToolPath = [System.IO.Path]::GetFullPath($SignToolPath)
$InfVerifPath = Resolve-InfVerif
$certificateInfo = Assert-CodeSigningCertificate -Thumbprint $SigningCertificateThumbprint -StoreLocation $CertificateStoreLocation
$normalizedThumbprint = $certificateInfo.Thumbprint

Assert-MicrosoftSignedDriverPackage -InfPath $driverInf -SysPath $driverSys -CatPath $driverCat -SignTool $SignToolPath -InfVerif $InfVerifPath -ExpectedAltitude $AssignedMinifilterAltitude

$buildParent = Join-Path $repositoryRoot "target\installer"
New-Item -ItemType Directory -Path $buildParent -Force | Out-Null
$buildParent = [System.IO.Path]::GetFullPath((Resolve-Path -LiteralPath $buildParent).Path)
$buildRoot = Join-Path $buildParent ("production-" + [Guid]::NewGuid().ToString("N"))
$stageDirectory = Join-Path $buildRoot "stage"
$stagedDriverDirectory = Join-Path $stageDirectory "DriverPackage"
$msiOutputDirectory = Join-Path $buildRoot "msi-output"
$bundleOutputDirectory = Join-Path $buildRoot "bundle-output"
$msiIntermediateDirectory = Join-Path $buildRoot "msi-obj"
$bundleIntermediateDirectory = Join-Path $buildRoot "bundle-obj"

New-Item -ItemType Directory -Path $stagedDriverDirectory -Force | Out-Null
New-Item -ItemType Directory -Path $msiOutputDirectory -Force | Out-Null
New-Item -ItemType Directory -Path $bundleOutputDirectory -Force | Out-Null

try {
    $stagedAgent = Join-Path $stageDirectory "blackshard.exe"
    Copy-Item -LiteralPath $AgentPath -Destination $stagedAgent
    Copy-Item -LiteralPath (Join-Path $repositoryRoot "LICENSE") -Destination (Join-Path $stageDirectory "LICENSE.txt")
    Copy-Item -LiteralPath $driverInf -Destination (Join-Path $stagedDriverDirectory "blackshard.inf")
    Copy-Item -LiteralPath $driverSys -Destination (Join-Path $stagedDriverDirectory "blackshard.sys")
    Copy-Item -LiteralPath $driverCat -Destination (Join-Path $stagedDriverDirectory "blackshard.cat")

    Invoke-AuthenticodeSign -Path $stagedAgent -Description "Blackshard Windows Client" -SignTool $SignToolPath -Thumbprint $normalizedThumbprint -StoreLocation $CertificateStoreLocation -TimestampServer $TimestampUrl

    $buildEngine = Resolve-MsBuildEngine
    $certificateStoreArguments = "/s My"
    if ($CertificateStoreLocation -eq "LocalMachine") {
        $certificateStoreArguments = "/sm /s My"
    }

    $commonProperties = @{
        AcceptEula = "wix7"
        ProductVersion = $ProductVersion
        SignOutput = "true"
        SignToolPath = $SignToolPath
        SigningCertificateThumbprint = $normalizedThumbprint
        CertificateStoreArguments = $certificateStoreArguments
        TimestampUrl = $TimestampUrl
    }

    $packageProperties = $commonProperties.Clone()
    $packageProperties["StageDir"] = $stageDirectory
    $packageProperties["OutputPath"] = $msiOutputDirectory
    $packageProperties["BaseIntermediateOutputPath"] = $msiIntermediateDirectory
    Invoke-WixProjectBuild -BuildEngine $buildEngine -ProjectPath (Join-Path $PSScriptRoot "package\Blackshard.Package.wixproj") -Properties $packageProperties -Description "Build and sign the Blackshard MSI"

    $msiFiles = @(Get-ChildItem -LiteralPath $msiOutputDirectory -Filter "*.msi" -File -Recurse)
    if ($msiFiles.Count -ne 1) {
        throw "Expected exactly one MSI output, but found $($msiFiles.Count) under $msiOutputDirectory."
    }
    $signedMsi = $msiFiles[0].FullName
    Invoke-NativeTool -FilePath $SignToolPath -ArgumentList @("verify", "/pa", "/all", "/v", $signedMsi) -Description "Verify the signed Blackshard MSI"

    $bundleProperties = $commonProperties.Clone()
    $bundleProperties["MsiPath"] = $signedMsi
    $bundleProperties["OutputPath"] = $bundleOutputDirectory
    $bundleProperties["BaseIntermediateOutputPath"] = $bundleIntermediateDirectory
    Invoke-WixProjectBuild -BuildEngine $buildEngine -ProjectPath (Join-Path $PSScriptRoot "bundle\Blackshard.Bundle.wixproj") -Properties $bundleProperties -Description "Build and sign the Blackshard setup bundle"

    $bundleFiles = @(Get-ChildItem -LiteralPath $bundleOutputDirectory -Filter "*.exe" -File -Recurse)
    if ($bundleFiles.Count -ne 1) {
        throw "Expected exactly one setup executable, but found $($bundleFiles.Count) under $bundleOutputDirectory."
    }
    $signedBundle = $bundleFiles[0].FullName
    Invoke-NativeTool -FilePath $SignToolPath -ArgumentList @("verify", "/pa", "/all", "/v", $signedBundle) -Description "Verify the signed Blackshard setup bundle"

    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    $finalSetupPath = Join-Path $OutputDirectory "BlackshardSetup.exe"
    Copy-Item -LiteralPath $signedBundle -Destination $finalSetupPath -Force
    $finalSetupPath = [System.IO.Path]::GetFullPath($finalSetupPath)
    $finalHash = (Get-FileHash -LiteralPath $finalSetupPath -Algorithm SHA256).Hash

    Write-Host ""
    Write-Host "Production installer created: $finalSetupPath"
    Write-Host "SHA-256: $finalHash"
    Write-Host "This build writes one distributable setup executable."
}
finally {
    Remove-BuildWorkspaceSafely -BuildWorkspace $buildRoot -AllowedParent $buildParent
}
