[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$AgentPath,
    [Parameter(Mandatory)]
    [string]$DriverPath,
    [string]$OutputDirectory = (Join-Path $PSScriptRoot "..\target\development-installer")
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Resolve-RequiredFile([string]$Path, [string]$Description) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "$Description was not found: $Path"
    }
    $item = Get-Item -LiteralPath $Path
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw "$Description must not be a reparse point: $Path"
    }
    return $item.FullName
}

$iexpress = Join-Path $env:SystemRoot "System32\iexpress.exe"
$iexpress = Resolve-RequiredFile $iexpress "Windows IExpress"
$AgentPath = Resolve-RequiredFile $AgentPath "Blackshard agent"
$DriverPath = Resolve-RequiredFile $DriverPath "Blackshard development driver"
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

$buildRoot = Join-Path ([IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\target"))) "development-installer-build"
if (Test-Path -LiteralPath $buildRoot) {
    $resolvedBuildRoot = (Resolve-Path -LiteralPath $buildRoot).Path
    $allowedParent = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot "..\target"))
    if (-not $resolvedBuildRoot.StartsWith($allowedParent + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Refusing to clean unexpected installer workspace: $resolvedBuildRoot"
    }
    Remove-Item -LiteralPath $resolvedBuildRoot -Recurse -Force
}
New-Item -ItemType Directory -Path $buildRoot | Out-Null

$cscCandidates = @(
    (Join-Path $env:WINDIR "Microsoft.NET\Framework64\v4.0.30319\csc.exe"),
    (Join-Path $env:WINDIR "Microsoft.NET\Framework\v4.0.30319\csc.exe")
)
$csc = $cscCandidates |
    Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } |
    Select-Object -First 1
if (-not $csc) {
    throw "The .NET Framework C# compiler is required to build the VM setup interface."
}

$uiSource = Resolve-RequiredFile (Join-Path $PSScriptRoot "development\SetupUi.cs") "VM setup UI source"
$uiExecutable = Join-Path $buildRoot "BlackshardSetupUi.exe"
$uiManifest = Join-Path $buildRoot "BlackshardSetupUi.manifest"
$manifest = @"
<?xml version="1.0" encoding="utf-8"?>
<assembly manifestVersion="1.0" xmlns="urn:schemas-microsoft-com:asm.v1">
  <assemblyIdentity version="1.0.0.0" name="BlackshardDevelopment.SetupUi" />
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="requireAdministrator" uiAccess="false" />
      </requestedPrivileges>
    </security>
  </trustInfo>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}" />
      <supportedOS Id="{4f476546-9374-4f8b-9b18-69815ec5e903}" />
    </application>
  </compatibility>
</assembly>
"@
[IO.File]::WriteAllText($uiManifest, $manifest, [Text.Encoding]::UTF8)
$compiler = Start-Process -FilePath $csc -ArgumentList @(
    "/nologo",
    "/target:winexe",
    "/optimize+",
    "/platform:x64",
    ('/win32manifest:"{0}"' -f $uiManifest),
    "/reference:System.dll",
    "/reference:System.Drawing.dll",
    "/reference:System.Windows.Forms.dll",
    ('/out:"{0}"' -f $uiExecutable),
    ('"{0}"' -f $uiSource)
) -WorkingDirectory $buildRoot -WindowStyle Hidden -Wait -PassThru
if ($compiler.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $uiExecutable -PathType Leaf)) {
    throw "The Blackshard VM setup interface could not be compiled (csc exit code $($compiler.ExitCode))."
}

$payload = [ordered]@{
    "BlackshardSetupUi.exe" = $uiExecutable
    "blackshard.exe" = $AgentPath
    "blackshard.sys" = $DriverPath
    "install.ps1" = (Join-Path $PSScriptRoot "..\install.ps1")
    "uninstall.ps1" = (Join-Path $PSScriptRoot "..\uninstall.ps1")
    "verify.ps1" = (Join-Path $PSScriptRoot "..\verify.ps1")
    "enable-test-signing.ps1" = (Join-Path $PSScriptRoot "..\enable-test-signing.ps1")
    "disable-test-signing.ps1" = (Join-Path $PSScriptRoot "..\disable-test-signing.ps1")
    "vm-setup.ps1" = (Join-Path $PSScriptRoot "development\vm-setup.ps1")
}

foreach ($entry in $payload.GetEnumerator()) {
    $source = Resolve-RequiredFile $entry.Value "Installer payload $($entry.Key)"
    $destination = Join-Path $buildRoot $entry.Key
    if (-not $source.Equals([IO.Path]::GetFullPath($destination), [StringComparison]::OrdinalIgnoreCase)) {
        Copy-Item -LiteralPath $source -Destination $destination
    }
}

$outputPath = Join-Path $OutputDirectory "BlackshardVmSetup.exe"
if (Test-Path -LiteralPath $outputPath -PathType Leaf) {
    Remove-Item -LiteralPath $outputPath -Force
}
$strings = New-Object Collections.Generic.List[string]
$sourceEntries = New-Object Collections.Generic.List[string]
$index = 0
foreach ($name in $payload.Keys) {
    $strings.Add(('FILE{0}="{1}"' -f $index, $name))
    $sourceEntries.Add(('%FILE{0}%=' -f $index))
    $index++
}

$sedPath = Join-Path $buildRoot "BlackshardVmSetup.sed"
$sed = @"
[Version]
Class=IEXPRESS
SEDVersion=3

[Options]
PackagePurpose=InstallApp
ShowInstallProgramWindow=0
HideExtractAnimation=1
UseLongFileName=1
InsideCompressed=0
CAB_FixedSize=0
CAB_ResvCodeSigning=0
RebootMode=N
InstallPrompt=%InstallPrompt%
DisplayLicense=%DisplayLicense%
FinishMessage=%FinishMessage%
TargetName=%TargetName%
FriendlyName=%FriendlyName%
AppLaunched=%AppLaunched%
PostInstallCmd=%PostInstallCmd%
AdminQuietInstCmd=%AdminQuietInstCmd%
UserQuietInstCmd=%UserQuietInstCmd%
SourceFiles=SourceFiles

[Strings]
InstallPrompt=
DisplayLicense=
FinishMessage=
TargetName=$outputPath
FriendlyName=Blackshard VM Development Setup
AppLaunched=BlackshardSetupUi.exe
PostInstallCmd=<None>
AdminQuietInstCmd=
UserQuietInstCmd=
$($strings -join "`r`n")

[SourceFiles]
SourceFiles0=$buildRoot\

[SourceFiles0]
$($sourceEntries -join "`r`n")
"@
[IO.File]::WriteAllText($sedPath, $sed, [Text.Encoding]::ASCII)

$iexpressProcess = Start-Process -FilePath $iexpress -ArgumentList @("/N", "BlackshardVmSetup.sed") `
    -WorkingDirectory $buildRoot -WindowStyle Hidden -Wait -PassThru
if ($iexpressProcess.ExitCode -ne 0) {
    throw "IExpress failed with exit code $($iexpressProcess.ExitCode)."
}
if (-not (Test-Path -LiteralPath $outputPath -PathType Leaf)) {
    throw "IExpress completed without producing $outputPath."
}

$hash = (Get-FileHash -LiteralPath $outputPath -Algorithm SHA256).Hash
Write-Host "[+] VM development installer created: $outputPath" -ForegroundColor Green
Write-Host "[+] SHA-256: $hash" -ForegroundColor Green
