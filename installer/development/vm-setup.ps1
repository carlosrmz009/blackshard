#Requires -Version 5.1
[CmdletBinding()]
param(
    [switch]$ResumeAfterReboot,
    [switch]$Uninstall,
    [switch]$UiMode
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$taskName = "BlackshardDevelopmentSetupResume"
$stageRoot = Join-Path $env:ProgramData "BlackshardDevelopmentInstaller"
$logPath = Join-Path $stageRoot "setup.log"
$successPath = Join-Path $stageRoot "installed.txt"
$failurePath = Join-Path $stageRoot "failed.txt"
$installedAgent = Join-Path $env:ProgramFiles "Blackshard\blackshard.exe"
$uninstallRegistryPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\BlackshardDevelopment"
$runOnceRegistryPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
$startMenuShortcut = Join-Path $env:ProgramData "Microsoft\Windows\Start Menu\Programs\Blackshard.lnk"
$bootstrapLogPath = Join-Path $env:TEMP "BlackshardVmSetup.log"

function Test-SystemAccount {
    return [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -eq "S-1-5-18"
}

function Show-SetupMessage([string]$Message, [string]$Title, [bool]$ErrorMessage = $false) {
    if ($UiMode -or (Test-SystemAccount) -or -not [Environment]::UserInteractive) {
        return
    }
    try {
        Add-Type -AssemblyName PresentationFramework
        $icon = if ($ErrorMessage) {
            [Windows.MessageBoxImage]::Error
        }
        else {
            [Windows.MessageBoxImage]::Information
        }
        [void][Windows.MessageBox]::Show(
            $Message,
            $Title,
            [Windows.MessageBoxButton]::OK,
            $icon
        )
    }
    catch {
        # The persistent log remains available if the graphical dialog cannot be created.
    }
}

trap {
    $detail = ($_ | Out-String).Trim()
    $record = "[{0:o}] {1}" -f (Get-Date), $detail
    try { Add-Content -LiteralPath $bootstrapLogPath -Value $record -Encoding UTF8 } catch {}
    try {
        if (Test-Path -LiteralPath $stageRoot -PathType Container) {
            Add-Content -LiteralPath $logPath -Value $record -Encoding UTF8
        }
    }
    catch {}
    if ($ResumeAfterReboot -or (Test-SystemAccount)) {
        try { Set-Content -LiteralPath $failurePath -Value $record -Encoding UTF8 -Force } catch {}
    }
    Show-SetupMessage -Message ("Blackshard VM setup failed.`n`n{0}`n`nDiagnostic log:`n{1}" -f $detail, $bootstrapLogPath) `
        -Title "Blackshard VM Setup" -ErrorMessage $true
    Write-Output "BLACKSHARD_UI:ERROR:$detail"
    exit 1
}

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Invoke-SelfElevated {
    $arguments = @(
        "-NoLogo",
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", ('"{0}"' -f $PSCommandPath)
    )
    if ($ResumeAfterReboot) { $arguments += "-ResumeAfterReboot" }
    if ($Uninstall) { $arguments += "-Uninstall" }
    if ($UiMode) { $arguments += "-UiMode" }
    $process = Start-Process -FilePath "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" `
        -ArgumentList ($arguments -join " ") -Verb RunAs -WindowStyle Hidden -Wait -PassThru
    exit $process.ExitCode
}

function Assert-DisposableVirtualMachine {
    $computer = Get-CimInstance -ClassName Win32_ComputerSystem
    $identity = "{0} {1}" -f $computer.Manufacturer, $computer.Model
    $knownVirtualMachine = $identity -match "(?i)(virtual machine|vmware|virtualbox|kvm|qemu|xen|parallels|hyper-v|nutanix|bochs)"
    if (-not $knownVirtualMachine) {
        throw @"
Blackshard VM Development Setup refused to run because this system was not identified as a virtual machine:
$identity

This installer enables Windows test-signing and installs a development kernel driver. Use it only in a disposable, snapshotted VM. It intentionally has no physical-machine override.
"@
    }
}

function Assert-SecureBootDisabled {
    try {
        if (Confirm-SecureBootUEFI -ErrorAction Stop) {
            throw "Secure Boot is enabled. Turn it off in this disposable VM's firmware settings, then run setup again."
        }
    }
    catch {
        if ($_.FullyQualifiedErrorId -match "(?i)(PlatformRequiresUEFI|CmdletizationQuery_NotSupported|NotSupported)") {
            # Legacy BIOS guests do not expose Secure Boot.
            return
        }
        throw
    }
}

function Test-TestSigningActive {
    $output = & bcdedit.exe /enum "{current}" 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Windows boot configuration could not be inspected."
    }
    $configured = ($output | Out-String) -match "(?im)^\s*testsigning\s+Yes\s*$"
    $control = Get-ItemProperty `
        -LiteralPath "HKLM:\System\CurrentControlSet\Control" `
        -Name SystemStartOptions `
        -ErrorAction SilentlyContinue
    $startOptions = if ($null -eq $control) { "" } else { [string]$control.SystemStartOptions }
    return $configured -and ($startOptions -match "(?i)(^|\s)TESTSIGNING($|\s)")
}

function Set-StageAcl {
    New-Item -ItemType Directory -Path $stageRoot -Force | Out-Null
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $inheritance = [Security.AccessControl.InheritanceFlags]"ContainerInherit, ObjectInherit"
    $propagation = [Security.AccessControl.PropagationFlags]::None
    $allow = [Security.AccessControl.AccessControlType]::Allow
    foreach ($sid in @("S-1-5-18", "S-1-5-32-544")) {
        $identity = [Security.Principal.SecurityIdentifier]::new($sid)
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $identity,
            [Security.AccessControl.FileSystemRights]::FullControl,
            $inheritance,
            $propagation,
            $allow
        )
        [void]$acl.AddAccessRule($rule)
    }
    $users = [Security.Principal.SecurityIdentifier]::new("S-1-5-32-545")
    $readRule = [Security.AccessControl.FileSystemAccessRule]::new(
        $users,
        [Security.AccessControl.FileSystemRights]"ReadAndExecute, Synchronize",
        $inheritance,
        $propagation,
        $allow
    )
    [void]$acl.AddAccessRule($readRule)
    Set-Acl -LiteralPath $stageRoot -AclObject $acl
}

function Copy-InstallerPayload {
    Set-StageAcl
    $required = @(
        "blackshard.exe",
        "blackshard.sys",
        "install.ps1",
        "uninstall.ps1",
        "verify.ps1",
        "enable-test-signing.ps1",
        "disable-test-signing.ps1",
        "vm-setup.ps1",
        "BlackshardSetupUi.exe"
    )
    foreach ($name in $required) {
        $source = Join-Path $PSScriptRoot $name
        if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
            throw "The installer payload is incomplete: $name is missing."
        }
        Copy-Item -LiteralPath $source -Destination (Join-Path $stageRoot $name) -Force
    }
    Remove-Item -LiteralPath $successPath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $failurePath -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $logPath -Force -ErrorAction SilentlyContinue
}

function Register-ResumeTask {
    $powerShell = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
    $resumeScript = Join-Path $stageRoot "vm-setup.ps1"
    $action = New-ScheduledTaskAction -Execute $powerShell `
        -Argument ('-NoLogo -NoProfile -ExecutionPolicy Bypass -File "{0}" -ResumeAfterReboot' -f $resumeScript)
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 15) `
        -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
        -Principal $principal -Settings $settings -Force | Out-Null
}

function Remove-ResumeTask {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
}

function Install-ShortcutsAndRegistration {
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($startMenuShortcut)
    $shortcut.TargetPath = $installedAgent
    $shortcut.WorkingDirectory = Split-Path -Parent $installedAgent
    $shortcut.Description = "Blackshard antivirus"
    $shortcut.Save()

    New-Item -Path $uninstallRegistryPath -Force | Out-Null
    $uninstallCommand = '"{0}" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "{1}" -Uninstall' -f `
        "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe", (Join-Path $stageRoot "vm-setup.ps1")
    New-ItemProperty -Path $uninstallRegistryPath -Name DisplayName -Value "Blackshard Development (VM Only)" -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $uninstallRegistryPath -Name DisplayVersion -Value "0.1.0-dev" -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $uninstallRegistryPath -Name Publisher -Value "Blackshard Open Source Project" -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $uninstallRegistryPath -Name DisplayIcon -Value $installedAgent -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $uninstallRegistryPath -Name UninstallString -Value $uninstallCommand -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $uninstallRegistryPath -Name NoModify -Value 1 -PropertyType DWord -Force | Out-Null
    New-ItemProperty -Path $uninstallRegistryPath -Name NoRepair -Value 1 -PropertyType DWord -Force | Out-Null
}

function Install-AllComponents {
    Write-Output "BLACKSHARD_UI:STATUS:Trusting the VM development certificate and signing the minifilter."
    & (Join-Path $stageRoot "enable-test-signing.ps1") -SkipBootConfiguration
    Write-Output "BLACKSHARD_UI:STATUS:Installing the kernel minifilter and LocalSystem protection service."
    $installer = Join-Path $stageRoot "install.ps1"
    $verifier = Join-Path $stageRoot "verify.ps1"
    & $installer
    & $verifier -DevelopmentVm
    Install-ShortcutsAndRegistration

    New-Item -Path $runOnceRegistryPath -Force | Out-Null
    New-ItemProperty -Path $runOnceRegistryPath -Name "BlackshardDevelopmentLaunch" `
        -Value ('"{0}"' -f $installedAgent) -PropertyType String -Force | Out-Null
    Set-Content -LiteralPath $successPath `
        -Value ("Installed and verified at {0:o}" -f (Get-Date)) -Encoding UTF8
    Remove-Item -LiteralPath $failurePath -Force -ErrorAction SilentlyContinue
    Remove-ResumeTask
    Write-Output "BLACKSHARD_UI:INSTALL_COMPLETE"

    Write-Host "[+] Blackshard UI, LocalSystem service, and minifilter are installed and verified." -ForegroundColor Green
    Write-Host "[+] Blackshard will open when an interactive user signs in." -ForegroundColor Green
}

function Start-ImmediateSystemInstall {
    Write-Output "BLACKSHARD_UI:STATUS:Repairing the partial installation with LocalSystem authority."
    Register-ResumeTask
    Start-ScheduledTask -TaskName $taskName
    $marker = $successPath
    for ($attempt = 0; $attempt -lt 120; $attempt++) {
        if (Test-Path -LiteralPath $marker -PathType Leaf) {
            Write-Output "BLACKSHARD_UI:INSTALL_COMPLETE"
            Show-SetupMessage -Message @"
Blackshard was installed and verified successfully.

The LocalSystem protection service and minifilter are now active. Open Blackshard from the Start menu.
"@ -Title "Blackshard VM Setup"
            return
        }
        if (Test-Path -LiteralPath $failurePath -PathType Leaf) {
            $failure = (Get-Content -LiteralPath $failurePath -Raw -ErrorAction SilentlyContinue).Trim()
            if ([string]::IsNullOrWhiteSpace($failure)) {
                $failure = "The LocalSystem installation worker failed without diagnostic text."
            }
            throw "The LocalSystem installation failed:`n$failure`n`nFull worker log: $logPath"
        }
        Start-Sleep -Seconds 1
    }
    $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    $taskInfo = Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction SilentlyContinue
    $taskState = if ($null -eq $task) { "missing" } else { [string]$task.State }
    $lastResult = if ($null -eq $taskInfo) { "unknown" } else { "0x{0:X8}" -f [uint32]$taskInfo.LastTaskResult }
    $tail = if (Test-Path -LiteralPath $logPath -PathType Leaf) {
        (Get-Content -LiteralPath $logPath -Tail 40 -ErrorAction SilentlyContinue) -join "`n"
    } else {
        "The LocalSystem worker did not create its log."
    }
    throw "The SYSTEM installation did not finish within two minutes (task state: $taskState; last result: $lastResult).`n`n$tail`n`nFull worker log: $logPath"
}

function Remove-AllComponents {
    Remove-ResumeTask
    $uninstaller = Join-Path $stageRoot "uninstall.ps1"
    if (Test-Path -LiteralPath $uninstaller -PathType Leaf) {
        & $uninstaller
    }
    Remove-Item -LiteralPath $startMenuShortcut -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $uninstallRegistryPath -Recurse -Force -ErrorAction SilentlyContinue
    Remove-ItemProperty -Path $runOnceRegistryPath -Name "BlackshardDevelopmentLaunch" -ErrorAction SilentlyContinue
    $disableTestSigning = Join-Path $stageRoot "disable-test-signing.ps1"
    if (Test-Path -LiteralPath $disableTestSigning -PathType Leaf) {
        & $disableTestSigning
    }
    Write-Host "[+] Blackshard development components were removed. Restart the VM to leave test-signing mode." -ForegroundColor Green
}

if (-not (Test-Administrator)) {
    Invoke-SelfElevated
}

Write-Output "BLACKSHARD_UI:STATUS:Validating the virtual-machine safety boundary."
Assert-DisposableVirtualMachine

if ($Uninstall) {
    Remove-AllComponents
    exit 0
}

if ($ResumeAfterReboot) {
    New-Item -ItemType Directory -Path $stageRoot -Force | Out-Null
    Remove-Item -LiteralPath $failurePath -Force -ErrorAction SilentlyContinue
    try { Start-Transcript -LiteralPath $logPath -Append | Out-Null } catch {}
    try {
        Install-AllComponents
    }
    finally {
        try { Stop-Transcript | Out-Null } catch {}
    }
    exit 0
}

Assert-SecureBootDisabled
$testSigningActive = Test-TestSigningActive
Write-Output "BLACKSHARD_UI:STATUS:Staging the protected installer payload."
Copy-InstallerPayload
try { Start-Transcript -LiteralPath $bootstrapLogPath -Append | Out-Null } catch {}
try {
    if ($testSigningActive) {
        Write-Host "[*] Test-signing is already active; starting the SYSTEM installation without another reboot..." -ForegroundColor Cyan
        Start-ImmediateSystemInstall
        exit 0
    }
    Write-Host "[*] Enabling Windows test-signing mode for the disposable VM..." -ForegroundColor Yellow
    Write-Output "BLACKSHARD_UI:STATUS:Enabling Windows test-signing for the disposable VM."
    & bcdedit.exe /set testsigning on | Out-Host
    if ($LASTEXITCODE -ne 0) {
        throw "Windows could not enable test-signing. Disable Secure Boot in this disposable VM and retry."
    }
    Register-ResumeTask
    Write-Output "BLACKSHARD_UI:REBOOT_PENDING"
    Write-Host "[+] Setup will automatically resume during the next VM boot." -ForegroundColor Green
    Show-SetupMessage -Message @"
The test certificate and boot configuration are ready.

The disposable VM will restart in 15 seconds. Blackshard setup will resume automatically during boot and install the UI, protection service, and minifilter.

Run shutdown /a now if you need to postpone the restart.
"@ -Title "Blackshard VM Setup"
    Write-Host "[*] Restarting the disposable VM in 15 seconds. Run 'shutdown /a' now to postpone." -ForegroundColor Yellow
    & shutdown.exe /r /t 15 /d p:2:4 /c "Blackshard development setup must restart to activate test-signing."
    if ($LASTEXITCODE -ne 0) {
        throw "Windows refused the setup restart request. Restart the VM manually; setup will resume automatically."
    }
}
finally {
    try { Stop-Transcript | Out-Null } catch {}
}
