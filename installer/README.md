# Blackshard production packaging foundation

This directory contains a fail-closed WiX 7 packaging pipeline for the Phase 1 x64 Windows client. When every production prerequisite is present, it emits one distributable file:

```text
target\production-installer\BlackshardSetup.exe
```

The setup executable is a signed WiX Burn bundle containing a signed MSI. The MSI embeds the signed Blackshard executable, the project license, and a complete `blackshard.inf` / `blackshard.sys` / `blackshard.cat` driver package. No runtime download is required to install those payloads.

## Current boundary

This is deliberately a production **packaging foundation**, not a claim that the current client is already independently validated or production-ready.

The MSI registers the signed `blackshard-service.exe --service` entry point as the automatic, LocalSystem, own-process **Blackshard Protection Service**, with SCM name `BlackshardProtectionService`. The distinct name is mandatory because `blackshard` is already the minifilter driver's SCM service name. It stops the user-mode service before upgrade or removal, starts it after installation, removes it on uninstall, restarts it 30 seconds after each of the first two failures, and resets that failure count after one healthy day. A third consecutive failure is left stopped to avoid an endless crash loop. The same signed service executable supplies the privileged driver lifecycle helper modes:

```text
blackshard-service.exe --install-driver <absolute-INF-path>
blackshard-service.exe --uninstall-driver <absolute-INF-path>
```

The installer deliberately fails if either mode returns anything except zero. A fresh installation is rolled back by uninstalling the newly added package. If same-package driver removal is rolled back, the MSI reinstalls the package from the still-present staged INF. A major upgrade crosses two MSI package versions, so restoring the old driver package after a late new-product failure is not considered proven until fault-injection tests demonstrate it for every supported upgrade path. The helper implementations must be idempotent, reject every path except a canonical absolute INF path inside the installed `DriverPackage` directory, use Microsoft's supported [`DiInstallDriverW`](https://learn.microsoft.com/en-us/windows/win32/api/newdev/nf-newdev-diinstalldriverw) / [`DiUninstallDriverW`](https://learn.microsoft.com/en-us/windows/win32/api/newdev/nf-newdev-diuninstalldriverw) path without interactive UI, unload the minifilter before removal, and return zero only when the requested operation is complete. DIFx must not be introduced.

An executable [type-18 Windows Installer custom action](https://learn.microsoft.com/en-us/windows/win32/msi/custom-action-type-18) cannot report `NeedReboot` through MSI state: Windows Installer treats every nonzero EXE exit code, including 3010, as failure. Consequently the helper must complete without a reboot for this wiring to succeed. Before releasing an upgrade that can require a reboot, replace this bridge with an MSI-aware native DLL custom action or a Burn package that propagates restart state and add reboot-path integration tests. Silently ignoring `NeedReboot` is not acceptable.

`ServiceControl Wait="yes"` keeps upgrade and uninstall ordering deterministic. The service now cooperatively cancels its real-time, update, and IPC workers, but the complete shutdown path still needs a measured deadline test under active scan/update load plus forced-failure upgrade coverage before release.

The setup must not be released until all of these remaining release gates are complete:

- The implemented driver helper modes are integration-tested across install, repair, same-version repair, major upgrade, rollback, reboot-required handling, and uninstall.
- The implemented service IPC and UAC handoff are independently reviewed and integration-tested with standard users, administrators, multiple sessions, malformed clients, and service restarts.
- The minifilter INF passes current `InfVerif /h` rules and uses a Microsoft-assigned altitude.
- The complete driver package is submitted through the Windows Hardware Developer Center and the returned catalog is Microsoft-signed for production kernel loading.
- Install, upgrade, repair, rollback, and uninstall are tested on every supported Windows release with Secure Boot and Memory Integrity enabled.

Until those gates are complete, a successfully built package proves that its release inputs passed the fail-closed build checks; it does not prove efficacy, compatibility, or public trust.

### Intentional GUI/service boundary

The GUI stays unelevated. Quick/full/custom scan requests, settings, quarantine operations, activity, and update checks are routed through the local service IPC API. The service authorizes each caller from its impersonated token; machine-wide mutations require an elevated administrator. When needed, the GUI stages a narrowly named, bounded, SHA-256-bound request and asks Windows UAC to run the same signed executable in a restricted helper mode. Production ACLs continue to deny direct ordinary-user writes to service-owned state.

Likewise, a LocalSystem service runs in session 0 and cannot be the user-notification endpoint. The MSI therefore registers `"%ProgramFiles%\Blackshard\blackshard-service.exe" --notification-agent` under the machine `Run` key. Windows starts one hidden, single-instance broker in every interactive user session at logon; MSI ownership removes that registration on upgrade or uninstall. The broker reads the service-owned detection history and only displays quarantine success/failure notifications. It never performs privileged mutations.

The Start menu shortcut is assigned the exact `Blackshard.Security.Client` AppUserModelID required by `winrt-notification`, following Microsoft's [desktop-toast shortcut requirement](https://learn.microsoft.com/en-us/windows/win32/shell/quickstart-sending-desktop-toast). The broker uses that same identity. Installation does not inject a process into an already-running session, so a user who installs after signing in must sign out and back in (or launch `blackshard-service.exe --notification-agent` once) before service-originated notifications appear. The registry value is removed immediately during uninstall; a broker already running in a logged-on session can remain alive until Restart Manager closes it or that session signs out, so the broker should also gain an authenticated service-shutdown/uninstall signal before public release.

## What the MSI owns

- `%ProgramFiles%\Blackshard\blackshard-service.exe`
- `%ProgramFiles%\Blackshard\blackshard-ui.exe`
- `%ProgramFiles%\Blackshard\blackshard-amsi-x64.dll`
- `%ProgramFiles%\Blackshard\blackshard-amsi-x86.dll`
- `%ProgramFiles%\Blackshard\LICENSE.txt`
- `%ProgramFiles%\Blackshard\DriverPackage\blackshard.inf`
- `%ProgramFiles%\Blackshard\DriverPackage\blackshard.sys`
- `%ProgramFiles%\Blackshard\DriverPackage\blackshard.cat`
- A Start menu shortcut
- The machine-wide `BlackshardNotificationAgent` logon entry, which starts `blackshard-service.exe --notification-agent` once per interactive user session and is removed on uninstall
- `%ProgramData%\Blackshard` and the `Definitions`, `Quarantine`, `State`, `Logs`, and `Updates\Staging` directories
- The automatic `BlackshardProtectionService` user-mode service (`blackshard-service.exe --service`); the separate `blackshard` SCM entry belongs to the minifilter driver
- Installation of the validated minifilter package through the signed helper modes

The Start menu shortcut carries `System.AppUserModel.ID=Blackshard.Security.Client`, matching the application constant used for desktop toast notifications.

ProgramData is protected with MSI 5.0 SDDL entries. LocalSystem (the service identity) and Administrators have full control. Authenticated users can read the root status/history/settings files, definitions, and logs, but cannot create or replace them. `Quarantine`, `State`, `Updates`, and `Updates\Staging` use protected DACLs and are inaccessible to ordinary users. Runtime-created descendants inherit the same policy. If the service account changes in the future, these ACLs must be revised in the same release.

Windows Installer owns and removes installed program files. Runtime-created definitions, logs, state, and quarantined evidence are intentionally not deleted blindly during uninstall. A future service-aware uninstaller needs an explicit, reviewed retention or secure-erasure policy before removing those files. The hardened ACLs remain on retained data.

The MSI and Burn bundle have stable upgrade codes and support major upgrades, repair, and uninstall through Windows Apps & Features. Downgrades are blocked.

## Required release inputs

1. Release-built x64 `blackshard-service.exe` and `blackshard-ui.exe`, plus x64/x86 AMSI provider DLLs. The service must be compiled with `BLACKSHARD_MINIFILTER_ALTITUDE`, `BLACKSHARD_UPDATE_MANIFEST_URL`, and `BLACKSHARD_DEFINITION_PUBLIC_KEY_HEX` set to the declared production inputs. The packager verifies the binding without installing the driver.
2. A directory containing exactly named `blackshard.inf`, `blackshard.sys`, and `blackshard.cat` production driver files.
3. A currently valid, publicly trusted Authenticode code-signing certificate with an accessible private key and the Code Signing EKU in either `Cert:\CurrentUser\My` or `Cert:\LocalMachine\My`.
4. A current Windows SDK and WDK, including x64 `signtool.exe` and `infverif.exe`.
5. Either a .NET SDK or Visual Studio 2022 Build Tools with MSBuild.
6. Implemented `--install-driver` and `--uninstall-driver` helper modes conforming to the zero-on-complete-success contract above.
7. Network access for NuGet restore and RFC 3161 timestamping.
8. Review and acceptance of the [WiX v7 OSMF/EULA terms](https://docs.firegiant.com/wix/osmf/). Organizations over the stated revenue threshold must satisfy the maintenance-fee terms before accepting.

The application certificate and the Microsoft-returned driver catalog are different signing inputs. An ordinary Authenticode certificate cannot make an unsigned or test-signed kernel driver production-loadable.

Qualifying open-source projects can apply to SignPath Foundation for sponsored Authenticode signing of user-mode artifacts. That may satisfy item 3 if the resulting certificate and signing workflow pass this packager's trust, EKU, timestamp, and private-key-access requirements (the current local-certificate interface would need an explicitly reviewed SignPath integration). It does not replace the organization EV certificate Microsoft requires to register for driver submission. There is no supported release mode that bypasses the Microsoft-signed catalog.

## Build

Run from the repository root:

```powershell
.\installer\build-production-installer.ps1 `
    -ProductVersion 0.1.0 `
    -DriverPackageDirectory C:\release-inputs\blackshard-driver `
    -AssignedMinifilterAltitude 123456.789 `
    -UpdateManifestUrl https://updates.example/blackshard/stable/manifest.json `
    -DefinitionPublicKeyHex d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a `
    -SigningCertificateThumbprint 0123456789ABCDEF0123456789ABCDEF01234567 `
    -CertificateStoreLocation CurrentUser `
    -AcceptWixEula
```

Optional parameters select different service, UI, AMSI-provider, output, timestamp-service, SignTool, or InfVerif paths. There is intentionally no unsigned-release switch.

The altitude, URL, key, thumbprint, and paths shown above are examples. Replace all of them with the reviewed production values; never publish a build using a documentation test key.

The script:

1. Rejects malformed MSI versions and missing inputs.
2. Confirms the service, UI, x64 AMSI provider, and driver are x64 PE images; confirms the x86 AMSI provider is an x86 PE image; and verifies that the service is release-bound to the declared driver altitude, update URL, and definition public key.
3. Validates the code-signing certificate, private key, validity period, Code Signing EKU, trust chain, and online revocation status, and rejects self-signed certificates.
4. Runs current hardened INF validation.
5. requires a trusted Microsoft hardware-pipeline signature on the catalog.
6. Uses SignTool kernel-policy verification to prove that the catalog covers both the SYS and INF.
7. Copies inputs to an isolated build staging directory and Authenticode-signs the staged service, UI, and AMSI providers.
8. Builds an MSI that installs the service, applies hardened ProgramData ACLs, and transactionally invokes the signed driver helper.
9. Signs the MSI, then builds and signs both the detached Burn engine and final bundle.
10. Authenticode-verifies every signed release artifact and prints the final SHA-256 hash.
11. Removes the verified temporary build directory and writes only `BlackshardSetup.exe` for this build.

The current development `dist` output is expected to fail these gates because it does not contain a Microsoft-signed production catalog. Test certificates, test-signing mode, and an unsigned catalog are never accepted by this pipeline.

## Source layout

- `package/Product.wxs` defines the machine-wide MSI payload, service lifecycle, driver transaction, hardened data directories, notification shortcut and per-user broker launch, and upgrade behavior.
- `package/Blackshard.Package.wixproj` pins the WiX 7 utility extension and enforces signed MSI output with warnings treated as errors.
- `bundle/Bundle.wxs` embeds the MSI in a one-file x64 Burn setup executable.
- `bundle/Blackshard.Bundle.wixproj` enforces signing of the Burn engine and final bundle.
- `build-production-installer.ps1` validates all release inputs and orchestrates the build.

## Production-signing notes

- Obtain the Microsoft-signed driver package through the [Windows Hardware Program](https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/hardware-program-register).
- Follow Microsoft's [driver signing policy](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/driver-signing) and [minifilter altitude allocation](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/allocated-altitudes) requirements.
- Timestamp all application and installer signatures. Timestamping preserves signature validity after the signing certificate expires, but does not substitute for certificate validity at signing time.
- Authenticode signing establishes publisher identity and integrity; it does not guarantee immediate Microsoft Defender SmartScreen reputation. Reputation has to be earned through stable, correctly signed releases and normal distribution.
- Phase 1 packaging is x64-only. ARM64 support requires a separately compiled and Microsoft-signed ARM64 driver and native client package; it cannot be made universal by relabeling x64 binaries.

Do not ask users to enable Windows test-signing mode, disable Secure Boot, disable Memory Integrity, or add antivirus exclusions for a production release.
