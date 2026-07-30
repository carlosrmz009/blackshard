[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$ServicePath,
    [Parameter(Mandatory)]
    [string]$UiPath,
    [Parameter(Mandatory)]
    [string]$DriverPath,
    [Parameter(Mandatory)]
    [string]$AmsiX64Path,
    [Parameter(Mandatory)]
    [string]$AmsiX86Path,
    [Parameter(Mandatory)]
    [string]$ClamRuntimePath,
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
$ServicePath = Resolve-RequiredFile $ServicePath "blackshard protection service"
$UiPath = Resolve-RequiredFile $UiPath "blackshard desktop UI"
$DriverPath = Resolve-RequiredFile $DriverPath "blackshard development driver"
$AmsiX64Path = Resolve-RequiredFile $AmsiX64Path "blackshard x64 AMSI provider"
$AmsiX86Path = Resolve-RequiredFile $AmsiX86Path "blackshard x86 AMSI provider"
$ClamRuntimePath = Resolve-RequiredFile $ClamRuntimePath "Verified latest ClamAV runtime archive"
$oobeSource = Resolve-RequiredFile (Join-Path $PSScriptRoot "..\oobe.png") "blackshard OOBE image"
$logoSource = Resolve-RequiredFile (Join-Path $PSScriptRoot "..\logo.png") "blackshard logo"
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

$uiSource = Resolve-RequiredFile (Join-Path $PSScriptRoot "development\setup-ui.cs") "VM setup UI source"
$fontRoot = Join-Path $PSScriptRoot "..\assets\fonts"
$interRegular = Resolve-RequiredFile (Join-Path $fontRoot "Inter-Regular.ttf") "Inter Regular font"
$interBold = Resolve-RequiredFile (Join-Path $fontRoot "Inter-Bold.ttf") "Inter Bold font"
$jetBrainsMonoRegular = Resolve-RequiredFile (Join-Path $fontRoot "JetBrainsMono-Regular.ttf") "JetBrains Mono Regular font"
$jetBrainsMonoBold = Resolve-RequiredFile (Join-Path $fontRoot "JetBrainsMono-Bold.ttf") "JetBrains Mono Bold font"
$interLicense = Resolve-RequiredFile (Join-Path $fontRoot "LICENSE-Inter.txt") "Inter license"
$jetBrainsMonoLicense = Resolve-RequiredFile (Join-Path $fontRoot "LICENSE-JetBrainsMono.txt") "JetBrains Mono license"
$uiExecutable = Join-Path $buildRoot "blackshard-setup-ui.exe"
$uiManifest = Join-Path $buildRoot "blackshard-setup-ui.manifest"
$manifest = @"
<?xml version="1.0" encoding="utf-8"?>
<assembly manifestVersion="1.0" xmlns="urn:schemas-microsoft-com:asm.v1">
  <assemblyIdentity version="1.0.0.0" name="blackshard.development.setup-ui" />
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="asInvoker" uiAccess="false" />
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
    ('/resource:"{0}",blackshard.fonts.Inter.Regular.ttf' -f $interRegular),
    ('/resource:"{0}",blackshard.fonts.Inter.Bold.ttf' -f $interBold),
    ('/resource:"{0}",blackshard.fonts.JetBrainsMono.Regular.ttf' -f $jetBrainsMonoRegular),
    ('/resource:"{0}",blackshard.fonts.JetBrainsMono.Bold.ttf' -f $jetBrainsMonoBold),
    ('/resource:"{0}",blackshard.fonts.Inter.LICENSE.txt' -f $interLicense),
    ('/resource:"{0}",blackshard.fonts.JetBrainsMono.LICENSE.txt' -f $jetBrainsMonoLicense),
    ('/out:"{0}"' -f $uiExecutable),
    ('"{0}"' -f $uiSource)
) -WorkingDirectory $buildRoot -WindowStyle Hidden -Wait -PassThru
if ($compiler.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $uiExecutable -PathType Leaf)) {
    throw "The blackshard VM setup interface could not be compiled (csc exit code $($compiler.ExitCode))."
}

$iconPath = Join-Path $buildRoot "blackshard.ico"
Add-Type -AssemblyName System.Drawing
$sourceImage = $null
$iconBitmap = $null
$graphics = $null
$pngStream = $null
$iconStream = $null
$iconWriter = $null
try {
    $sourceImage = [Drawing.Image]::FromFile($logoSource)
    $iconBitmap = [Drawing.Bitmap]::new(
        256,
        256,
        [Drawing.Imaging.PixelFormat]::Format32bppArgb
    )
    $graphics = [Drawing.Graphics]::FromImage($iconBitmap)
    $graphics.Clear([Drawing.Color]::Transparent)
    $graphics.CompositingQuality = [Drawing.Drawing2D.CompositingQuality]::HighQuality
    $graphics.InterpolationMode = [Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $graphics.PixelOffsetMode = [Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    $maximumDimension = 224.0
    $scale = [Math]::Min(
        $maximumDimension / [double]$sourceImage.Width,
        $maximumDimension / [double]$sourceImage.Height
    )
    $drawWidth = [Math]::Max(1, [int][Math]::Round($sourceImage.Width * $scale))
    $drawHeight = [Math]::Max(1, [int][Math]::Round($sourceImage.Height * $scale))
    $drawX = [int][Math]::Floor((256 - $drawWidth) / 2.0)
    $drawY = [int][Math]::Floor((256 - $drawHeight) / 2.0)
    $graphics.DrawImage($sourceImage, $drawX, $drawY, $drawWidth, $drawHeight)

    $pngStream = [IO.MemoryStream]::new()
    $iconBitmap.Save($pngStream, [Drawing.Imaging.ImageFormat]::Png)
    $pngBytes = $pngStream.ToArray()

    $iconStream = [IO.File]::Open($iconPath, [IO.FileMode]::Create, [IO.FileAccess]::Write)
    $iconWriter = [IO.BinaryWriter]::new($iconStream)
    $iconWriter.Write([uint16]0)
    $iconWriter.Write([uint16]1)
    $iconWriter.Write([uint16]1)
    $iconWriter.Write([byte]0)
    $iconWriter.Write([byte]0)
    $iconWriter.Write([byte]0)
    $iconWriter.Write([byte]0)
    $iconWriter.Write([uint16]1)
    $iconWriter.Write([uint16]32)
    $iconWriter.Write([uint32]$pngBytes.Length)
    $iconWriter.Write([uint32]22)
    $iconWriter.Write($pngBytes)
}
finally {
    if ($null -ne $iconWriter) { $iconWriter.Dispose() }
    elseif ($null -ne $iconStream) { $iconStream.Dispose() }
    if ($null -ne $pngStream) { $pngStream.Dispose() }
    if ($null -ne $graphics) { $graphics.Dispose() }
    if ($null -ne $iconBitmap) { $iconBitmap.Dispose() }
    if ($null -ne $sourceImage) { $sourceImage.Dispose() }
}
if (-not (Test-Path -LiteralPath $iconPath -PathType Leaf)) {
    throw "The blackshard shortcut icon could not be created from $logoSource."
}

$payload = [ordered]@{
    "blackshard-setup-ui.exe" = $uiExecutable
    "blackshard-service.exe" = $ServicePath
    "blackshard-ui.exe" = $UiPath
    "blackshard.sys" = $DriverPath
    "blackshard-amsi-x64.dll" = $AmsiX64Path
    "blackshard-amsi-x86.dll" = $AmsiX86Path
    "clamav-runtime.zip" = $ClamRuntimePath
    "install.ps1" = (Join-Path $PSScriptRoot "..\install.ps1")
    "uninstall.ps1" = (Join-Path $PSScriptRoot "..\uninstall.ps1")
    "verify.ps1" = (Join-Path $PSScriptRoot "..\verify.ps1")
    "enable-test-signing.ps1" = (Join-Path $PSScriptRoot "..\enable-test-signing.ps1")
    "disable-test-signing.ps1" = (Join-Path $PSScriptRoot "..\disable-test-signing.ps1")
    "vm-setup.ps1" = (Join-Path $PSScriptRoot "development\vm-setup.ps1")
    "oobe.png" = $oobeSource
    "logo.png" = $logoSource
    "blackshard.ico" = $iconPath
}

foreach ($entry in $payload.GetEnumerator()) {
    $source = Resolve-RequiredFile $entry.Value "Installer payload $($entry.Key)"
    $destination = Join-Path $buildRoot $entry.Key
    if (-not $source.Equals([IO.Path]::GetFullPath($destination), [StringComparison]::OrdinalIgnoreCase)) {
        Copy-Item -LiteralPath $source -Destination $destination
    }
}

$packageOutputDirectory = Join-Path $buildRoot "package-output"
New-Item -ItemType Directory -Path $packageOutputDirectory | Out-Null
$packageOutputPath = Join-Path $packageOutputDirectory "blackshard-vm-setup.exe"
$outputPath = Join-Path $OutputDirectory "blackshard-vm-setup.exe"
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

$sedPath = Join-Path $buildRoot "blackshard-vm-setup.sed"
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
TargetName=$packageOutputPath
FriendlyName=blackshard VM development setup
AppLaunched=blackshard-setup-ui.exe
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

$iexpressProcess = Start-Process -FilePath $iexpress -ArgumentList @("/N", "blackshard-vm-setup.sed") `
    -WorkingDirectory $buildRoot -WindowStyle Hidden -Wait -PassThru
if ($iexpressProcess.ExitCode -ne 0) {
    throw "IExpress failed with exit code $($iexpressProcess.ExitCode)."
}
if (-not (Test-Path -LiteralPath $packageOutputPath -PathType Leaf)) {
    throw "IExpress completed without producing $packageOutputPath."
}
Copy-Item -LiteralPath $packageOutputPath -Destination $outputPath -Force

$hash = (Get-FileHash -LiteralPath $outputPath -Algorithm SHA256).Hash
Write-Host "[+] VM development installer created: $outputPath" -ForegroundColor Green
Write-Host "[+] SHA-256: $hash" -ForegroundColor Green
