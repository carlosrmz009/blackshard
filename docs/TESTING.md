# Blackshard testing guide

Blackshard has two deliberately different test environments. Do not move live malware, an unsigned minifilter, or test-signing configuration onto a personal computer.

## 1. Main development PC: clean functionality and false positives

Do not install the development minifilter on this machine. Keep Microsoft Defender or the existing antivirus enabled and do not enable Windows test-signing mode. Use the freshly built `target\release\blackshard.exe` only for UI inspection and bounded on-demand corpus evaluation; full real-time/service assertions belong in the VM until production signing exists.

Prepare a representative clean corpus you are legally permitted to scan. Include copies or generated fixtures representing:

- signed Microsoft and third-party applications;
- installers, game files, developer toolchains, build outputs, scripts, and source trees;
- Office documents with and without macros, PDFs, ZIP/OOXML/Gzip archives, media, databases, and encrypted files;
- large files, malformed-but-benign fixtures, cloud placeholders, and long paths;
- software specific to your normal work.

Do not scan browser credential stores, private keys, confidential client material, or the live Windows directory merely to increase the sample count. Prefer a dedicated read-only corpus directory.

Run a reproducible baseline:

```powershell
.\tools\Measure-DetectionCorpus.ps1 `
    -CorpusDirectory D:\Blackshard-Corpora\clean `
    -ReportPath D:\Blackshard-Evidence\clean-report.json
```

Create `labels.csv` with exactly two columns:

```csv
path,label
signed-app.exe,clean
documents/report.docx,clean
```

Then score it:

```powershell
.\tools\Score-DetectionCorpus.ps1 `
    -DetectionReportPath D:\Blackshard-Evidence\clean-report.json `
    -LabelsCsvPath D:\Blackshard-Evidence\labels.csv `
    -OutputPath D:\Blackshard-Evidence\clean-metrics.json
```

Every suspicious or malicious clean-file result is a false-positive candidate. Record the file SHA-256, Blackshard evidence codes, signature status, file type/size, definition sequence, scan time, and whether another antivirus intervened. Do not upload the file publicly without permission.

Repeat representative workloads while recording idle and active CPU, memory, disk I/O, scan throughput, and p95/p99 latency. A useful first matrix is a Rust build, source-tree copy, archive extraction, Office/PDF open, game launch, browser download, and a system reboot. Compare against the same workload without Blackshard and retain both reports.

## 2. Disposable VM: real-time and malware evaluation

Use an x64 VM with no personal accounts, credentials, secrets, shared clipboard, shared folders, drag-and-drop, USB passthrough, host filesystem mounts, or host network bridge. Prefer no network adapter. If observation requires networking, use an isolated simulation network with no route to the host, LAN, or Internet. Take a powered-off clean snapshot first.

Copy the complete `dist` directory into the clean VM before introducing samples. In an elevated PowerShell:

### One-click VM setup

The CI development artifact contains `BlackshardVmSetup.exe`. This development-only installer bundles the UI/engine, LocalSystem service, and minifilter. It refuses to run when Windows does not identify the system as a virtual machine. Before launching it:

1. Take a powered-off clean snapshot.
2. Disconnect the VM from the host, LAN, and Internet and disable every host integration.
3. Disable Secure Boot in the **VM firmware settings**. Do not change the host's Secure Boot setting.
4. Double-click `BlackshardVmSetup.exe`, approve its administrator prompt, confirm the isolation checkbox, and select **Install full protection**. The Blackshard-styled setup window keeps PowerShell hidden, shows every installation phase, retains failures in its activity log, and supports retrying a partial installation.

Setup creates and trusts a VM-local development certificate, test-signs the bundled driver, enables Windows test-signing, and schedules setup to resume during the required reboot. It restarts the VM after a 15-second warning. After boot, the scheduled SYSTEM task installs and starts the driver and protection service, runs `verify.ps1 -DevelopmentVm`, creates a Start-menu shortcut, registers an uninstaller, and opens Blackshard at the next sign-in. Setup logs are written to `C:\ProgramData\BlackshardDevelopmentInstaller\setup.log`. Pre-staging failures are also retained in `%TEMP%\BlackshardVmSetup.log`; interactive failures remain visible in a message box instead of disappearing with a console window.

This installer is intentionally unsigned and is not a public release installer. Never run it on a physical or personal machine. Remove it from **Installed apps** when testing is complete, then reboot to finish leaving test-signing mode.

### Manual setup and troubleshooting

The equivalent manual sequence remains available when diagnosing installer or boot-resume failures:

```powershell
.\enable-test-signing.ps1
# Reboot.
.\install.ps1
.\verify.ps1 -DevelopmentVm
.\blackshard.exe
```

Run tests in increasing risk order:

1. Run the dashboard's **Harmless protection test** and require a Blackshard-attributed block.
2. Run the EICAR test from the README and confirm detection, history, notification, quarantine, restore, and delete behavior.
3. Exercise benign ZIP/OOXML/Gzip/PDF fixtures and a synthetic mass-file writer to validate archive limits and ransomware audit telemetry without malware.
4. Only then test legally possessed malware such as WannaCry or other destructive samples. Use one sample and one restored snapshot per run. Do not obtain samples through Blackshard project infrastructure or a personal browser session.

For every malware run, capture before execution:

```powershell
.\verify.ps1 -DevelopmentVm *> .\before.txt
Get-FileHash -Algorithm SHA256 -LiteralPath .\sample-under-test.bin
Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber
```

Start screen/video and resource monitoring, then record these outcomes independently:

- detected during custom/full scan;
- blocked on open or executable mapping;
- quarantined, with a matching hash and Blackshard history event;
- notification displayed;
- process started or did not start;
- protected-file write/rename/delete activity alerted or blocked;
- service/filter remained healthy and bypass/timeout counters did not unexpectedly increase;
- reboot persistence, recovery, and uninstall behavior.

Do not count a disappearance as a Blackshard success unless Blackshard history and quarantine identify it; Microsoft Defender or another product may have acted first. If attribution testing requires temporarily disabling a competing antivirus, do so only inside this offline disposable snapshot, never weaken the host, and revert the entire VM immediately afterward.

After each sample, export only non-sensitive logs/evidence, power off the VM, and revert to the clean snapshot. Do not attempt to disinfect and reuse a VM that executed destructive malware. MEMZ-class payloads can intentionally damage the guest boot path; WannaCry-class malware must never have a route to other systems.

## Acceptance rules

- Zero unexplained malicious verdicts on the clean corpus.
- Every false positive has a reproducible fixture and regression test before changing thresholds.
- No detection claim is based on the training/rule-development samples.
- Malware recall, clean false-positive rate, latency, and bypass counters are reported for the exact commit and definition sequence.
- A crash, parser hang, service disconnect, driver timeout, or unattributed sample execution is a failed test even if a later scan finds the file.
