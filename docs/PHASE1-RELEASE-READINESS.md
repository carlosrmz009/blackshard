# Phase 1 release readiness

This document separates code that exists in the repository from evidence and external artifacts required for a responsible public antivirus release. A successful local build, passing unit tests, or a signed setup executable is not proof of malware-detection efficacy, low false-positive rates, compatibility, or operational security.

Last reviewed: July 22, 2026.

## Intended Phase 1 deliverable

The user downloads one x64 Windows executable: `BlackshardSetup.exe`. The signed WiX Burn bundle contains a signed MSI, the signed Blackshard application, and the complete Microsoft-signed minifilter package (`blackshard.inf`, `blackshard.sys`, and `blackshard.cat`). No runtime download is needed to install those payloads.

Installation creates multiple components because Windows cannot run a file-system minifilter, a LocalSystem service, a per-user UI/notification process, and persistent machine data safely from one portable process:

```text
BlackshardSetup.exe
  -> blackshard                      kernel FILE_SYSTEM_DRIVER
  -> BlackshardProtectionService     LocalSystem user-mode service
  -> blackshard.exe                  GUI, service entry point, helper modes, notification broker
  -> %ProgramData%\Blackshard        definitions, settings, history, state, quarantine
```

There is no P2P/Shardnet component in Phase 1.

## Implemented in source

### Detection and enforcement

- Complete-file SHA-256 signature lookup with embedded EICAR and inert Blackshard self-test records.
- Authenticated external exact hashes, YARA-X source bundles, compact family-similarity profiles, and provenance records with strict schema/count/size limits and compilation before activation.
- A bounded 64-element bottom-k PE similarity engine with size gating, an 85% minimum publisher threshold, fixed memory, visible-result limits, and a dedicated match-rate circuit breaker. Similarity remains advisory and cannot authorize blocking or quarantine.
- Bounded static analysis for PE structure, executable/import/section anomalies, suspicious script behavior combinations, content classification, and contextual entropy.
- Entropy alone never escalates a file to suspicious or malicious.
- Exact trusted signature matches authorize automatic blocking and quarantine. A positive result from an installed Windows AMSI provider can deny executable use but never authorizes Blackshard quarantine. YARA and heuristic findings are recorded for review; they are not automatically destructive.
- Bounded AMSI-consumer scanning for scripts, Office content, and YARA-selected samples. Provider input is capped at 4 MiB; Blackshard does not register its own AMSI provider.
- A 64 MiB per-file analysis ceiling. A file larger than the ceiling is marked truncated and cannot qualify for exact-signature automatic action because its complete SHA-256 was not obtained.
- No pathname/metadata clean-verdict cache in the enforcement path.
- Minifilter protocol v5 with fixed-size/versioned messages, normalized paths, live file IDs, stable process-start keys, stream content-generation tracking, bounded 1.5-second scan waits, 100-millisecond behavior-telemetry waits, post-create inspection for selected high-risk opens, executable-section creation gating, and protected-document write/rename/delete telemetry.
- User mode scans an opened non-reparse-point candidate, validates its Windows file ID against the kernel notification, reads that exact handle, and checks for mutation during analysis.
- Executable mapping fails closed on analysis/identity errors or a write generation race. General read/open inspection still has explicit fail-open paths for service absence, timeout, unsupported object resolution, high IRQL, overload, and overlong names; counters expose those bypasses.

### Service and user experience

- Automatic LocalSystem `BlackshardProtectionService`, distinct from the `blackshard` kernel service.
- Protected local named-pipe control API with no network listener, remote-pipe rejection, bounded frames/timeouts, caller PID/token checks, per-scan ownership, and elevated-admin checks for machine-wide sensitive actions.
- Unelevated desktop operation with narrowly scoped, SHA-256-bound UAC helper requests for settings, quarantine mutations, and activity clearing.
- Quick, full, and custom scans; bounded workers; progress; cancellation; exclusions; resource settings; optional network-drive traversal.
- Machine-owned quarantine with identity/hash revalidation, encrypted neutralized containers, no-overwrite restore, delete, corruption checks, event history, and ACL-isolated storage.
- Per-user notification broker for quarantine success/failure toasts; LocalSystem does not attempt to show session-0 UI.
- DirectX 12/WGPU desktop UI with protection health, scan controls/results, quarantine, activity, settings, definitions, update state, and Authenticode status.
- Harmless exact-signature end-to-end self-test.
- In-memory ZIP/nested-ZIP/OOXML, Gzip, and OLE stream inspection with shared bomb/resource limits; bounded MS-OVBA decompression; and active PDF-content analysis. Exact malware found inside a fully read container can authorize quarantining that outer container.
- Per-process ransomware-like mass-modification correlation across protected writes, renames, and deletions with PID-reuse-resistant kernel start keys, cached Authenticode trust tiers, bounded state, audit-by-default operation, and optional modification denial that never quarantines victim documents.

### Definition updates and packaging

- Ed25519-authenticated manifests and definition payloads, HTTPS-only WinHTTP transport, native Windows certificate validation/revocation behavior, redirects disabled, payload-origin allowlisting, expiry/future-time/rollback checks, bounded downloads, atomic activation, and last-known-good fallback.
- Configurable 1-24 hour definition interval, defaulting to four hours, with jitter and a manual-check trigger.
- A compile-time trust key and manifest endpoint are required. With neither configured, the application truthfully remains on embedded definitions and does not pretend to update.
- Fail-closed WiX 7 MSI/Burn build that produces one signed setup executable and rejects development altitudes, unsuitable Authenticode certificates, invalid INFs, and driver catalogs that fail kernel-policy verification.
- Side-effect-free release-binary preflight that binds the packaged EXE to the exact Microsoft-assigned altitude, HTTPS update-manifest URL, and Ed25519 definition public key declared to the packager.
- Maintainer tools to import reviewed SHA-256 intelligence from FreshClam-verified ClamAV databases and to create and client-validate schema-2 Ed25519 update publications with an offline key.
- Hardened installed-data ACLs, service lifecycle/recovery configuration, Start menu identity, notification-agent logon registration, upgrade code, repair, downgrade blocking, and uninstall ownership.

## Not implemented or not established

- A hosted production definition feed, production manifest URL, production Ed25519 key, offline signing ceremony, key rotation/revocation mechanism, emergency rollback playbook, or feed service-level objective.
- A background updater for the application, driver, MSI, or Burn bundle. The current online updater handles definitions only.
- A Blackshard Windows AMSI provider. The client consumes the Windows AMSI API, so that layer depends on providers already installed on the machine.
- RAR/7z/ISO payload expansion, executable unpacking/emulation, behavioral sandboxing, cloud detonation/reputation, memory scanning, boot-sector scanning, email/web proxying, exploit prevention, process termination/suspension, or ransomware rollback.
- A bundled ClamAV resident engine. The maintainer importer can ingest reviewed SHA-256 records from FreshClam-verified data, but no upstream content is automatically trusted or shipped by this repository.
- A production-grade reputation backend, telemetry pipeline, or sample-submission workflow.
- ARM64 binaries or an ARM64 Microsoft-signed driver package.
- Independent security review, independent antivirus lab certification, published detection/false-positive measurements, or a supported-performance envelope.
- Sustained fuzzing/OSS-Fuzz onboarding and a legally operated, independently labeled large malware/clean corpus. The repository now provides fuzz targets and a bounded corpus/latency report generator, but not the external sample rights or evidence itself.
- Shardnet/P2P. It is explicitly outside Phase 1.

## Mandatory external release gates

Every item below must have retained evidence for the exact release candidate.

### Windows driver identity and signing

- Obtain a unique Blackshard minifilter altitude from Microsoft and replace the development placeholder. Minifilter instances cannot responsibly ship on an arbitrary altitude. See [allocated filter altitudes](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/allocated-altitudes) and [requesting a minifilter altitude](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/minifilter-altitude-request).
- Validate the final INF with the current WDK `InfVerif /h /v` rules, including the intended Windows 10/11 compatibility behavior. See [minifilter INF requirements](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/creating-an-inf-file-for-a-minifilter-driver).
- Submit the exact final INF/SYS/CAT package through Microsoft's Hardware Developer Program and retain the Microsoft-returned production-signed catalog. An ordinary application certificate or test certificate cannot make a kernel driver production-loadable. See [driver signing offerings](https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/driver-signing-offerings), [attestation signing](https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/code-signing-attestation), and [kernel-mode signing requirements](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/kernel-mode-code-signing-requirements--windows-vista-and-later-).
- Test load, attach, unload, repair, major upgrade, rollback, reboot-required paths, and uninstall with Secure Boot and Memory Integrity enabled.

### Application and installer trust

- Acquire a currently valid publicly trusted Authenticode signing identity, protect its private key/build authorization, and RFC 3161 timestamp the EXE, MSI, Burn engine, and final bundle. A qualifying open-source project may apply for SignPath Foundation's no-cost signing program, subject to its eligibility and source/build-origin controls.
- Verify the final files from a clean machine with both normal Authenticode policy and SignTool kernel policy where applicable.
- Establish stable publisher identity and distribution practices. A valid signature provides identity/integrity but does not guarantee immediate [Microsoft Defender SmartScreen reputation](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/smartscreen-reputation).
- Never ask an end user to enable test-signing mode, disable Secure Boot/Memory Integrity, suppress SmartScreen, or add an antivirus exclusion.

The application-signing sponsorship path does not satisfy the Windows Hardware Developer Program identity gate. Microsoft currently requires an organization-controlled EV code-signing certificate to register a dashboard account for either attestation or WHCP submission and directs organizations without one to purchase it from an approved certificate authority. The Entra directory can be free, but there is no supported zero-certificate path for a new public x64 minifilter. This is an external funding/sponsorship prerequisite, not a switch Blackshard can implement.

### Definition-feed operations

- Provision the production trust key and HTTPS manifest endpoint at release build time; publish the corresponding operational ownership and incident-response contacts.
- Keep the signing key offline or in appropriately controlled signing hardware. Define separate build, feed-publishing, and emergency-revocation authority.
- Add and exercise a trust-key rotation/recovery design. The present single embedded key cannot be treated as a complete long-lived trust framework.
- Operate a staged/canary release process, false-positive kill switch, rollback procedure, expiry monitoring, audit log, availability monitoring, and reproducible definition build.
- Validate multiple updates per day under offline, captive-portal, proxy, metered-network, clock-skew, expired-certificate, tampering, replay, rollback, partial-write, power-loss, and last-known-good scenarios.
- Keep detection definitions independently rollback-protected from application releases. Do not silently fall back to unauthenticated content.

### Security, quality, and efficacy evidence

- Threat-model and independently review the kernel/user protocol, named-pipe authorization, service helper modes, update trust chain, quarantine/restore paths, installer custom actions, ACL inheritance, and privileged path handling.
- Fuzz/parsing-test PE input, YARA bundles, update envelopes, IPC frames, filter messages, quarantine metadata, health/history files, and malformed paths/reparse points.
- Run Microsoft driver verification and stress tooling appropriate to the supported matrix, including Driver Verifier in isolated systems. Complete required Hardware Lab Kit tests for the chosen distribution/signing path.
- Test clean install, repair, same-version maintenance, major upgrade, rollback after injected failures, uninstall, interrupted update, service crash/restart, filter disconnect, multiple users, non-admin users, and notification logon/logout behavior.
- Build versioned malicious and clean corpora with provenance and legal handling. Measure per-family recall, zero-day proxy recall, false-positive rate, precision, time-to-verdict, quarantine success, bypass counts, and confidence intervals. Never train and score on the same samples.
- Include representative signed software, installers, archives, packed applications, developer toolchains, games, media, encrypted files, large files, network shares, cloud placeholders, and line-of-business software in the clean corpus.
- Conduct adversarial tests only in isolated disposable VMs without credentials or sensitive data. Do not use live malware on a developer workstation.
- Publish reproducible limitations and comparison methodology. Do not claim “highest accuracy,” “zero-day protection,” “universal,” “lighter than commercial AV,” or “production-ready” without measured, independently reviewable evidence.

### Performance and compatibility

- Establish idle CPU/RAM/I/O, boot impact, application-launch latency, file-copy/build workload overhead, scan throughput, update bandwidth, battery impact, and worst-case queue/timeout behavior on low-, mid-, and high-end hardware.
- Set pass/fail budgets before measuring and include Defender/coexistence baselines. A small binary or bounded queue alone does not prove lower total resource use.
- Validate every supported, still-serviced Windows edition/build, filesystem, locale, long-path policy, multi-user configuration, and common virtualization/storage stack.
- Treat ordinary Windows 10 Home/Pro 22H2 as out of Microsoft support after October 14, 2025 unless the project explicitly qualifies an applicable ESU/LTSC edition. Do not advertise “any Windows PC.”
- Produce and qualify a separate ARM64 application, driver, catalog, MSI, and bundle before advertising ARM64 support.

## Release acceptance record

For each candidate, archive at minimum:

- source commit and reproducible dependency lockfile;
- compiler, Rust, SDK, WDK, WiX, SignTool, and InfVerif versions;
- signed artifact SHA-256 values and certificate/catalog verification logs;
- Microsoft altitude assignment and Hardware Program submission identifiers;
- installer transaction/fault-injection results;
- OS/hardware/virtualization test matrix;
- unit, integration, fuzz, driver, security-review, corpus, false-positive, and performance reports;
- definition/feed key identifiers and update/rollback exercises;
- known limitations, supported versions, privacy statement, incident contact, and rollback/removal instructions.

Only after all release-blocking findings are closed should the project tag a candidate as production-ready. Until then, use the repository build only for development and use unsigned/test-signed kernel code only inside a disposable VM.

## Safe validation commands

Source checks:

```powershell
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --release
.\build-driver.ps1
```

Installed production-candidate checks from an elevated repository PowerShell:

```powershell
.\verify.ps1
sc.exe query blackshard
sc.exe query BlackshardProtectionService
fltmc.exe filters | Select-String blackshard
fltmc.exe instances -f blackshard
Get-Content -Raw "$env:ProgramData\Blackshard\service-health.json" | ConvertFrom-Json
Get-AuthenticodeSignature "$env:ProgramFiles\Blackshard\blackshard.exe" | Format-List
```

Disposable-VM legacy development checks:

```powershell
.\verify.ps1 -DevelopmentVm
```

Use the UI's **Run harmless protection test** for the preferred exact-signature enforcement check. The optional EICAR procedure and expected SHA-256 are documented in the root [README](../README.md#harmless-protection-validation).
