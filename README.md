# Blackshard

Blackshard is an open-source Windows antivirus being built as a complete, independently measurable protection product rather than a demonstration scanner. Phase 1 combines a file-system minifilter, a LocalSystem protection service, a layered Rust detection engine, and a minimal desktop UI. The longer-term project vision is at [blackshard.dev](https://blackshard.dev/).

## Release status

The project goal is a production antivirus competitive with the leading commercial products. The present source tree is still a **pre-release build and is not yet a safe replacement for an independently validated antivirus**. A public build becomes production-ready only after the signing, distribution, compatibility, efficacy, false-positive, and performance gates in [Phase 1 release readiness](docs/PHASE1-RELEASE-READINESS.md) are complete. Product quality is established by measured recall, precision, false-positive rate, latency, bypass rate, and adversarial resilience—not by changing the label in this README.

In particular, this repository does not ship a Microsoft-assigned minifilter altitude, a Microsoft-signed production driver catalog, an organization Authenticode certificate, or an operational signed definition feed. Those are release inputs, not settings an end user should work around.

## Implemented architecture

- **Known-malware matching:** complete-file SHA-256 signatures, including the harmless EICAR and Blackshard test signatures. A complete-file match from the embedded or authenticated definition set is eligible for automatic blocking and quarantine.
- **Bounded YARA-X analysis:** compiled rules identify suspicious script chains, LOLBin activity, AMSI-bypass indicators, and other combinations. YARA and heuristics can raise findings, but do not cause destructive automatic action by themselves.
- **Windows antimalware-provider consultation:** scripts, Office content, and YARA-selected samples are submitted through the installed Windows AMSI stack with a strict 4 MiB input bound. An AMSI provider detection can deny executable use, but deliberately cannot authorize Blackshard quarantine.
- **Static analysis:** bounded PE parsing, executable-section and import anomalies, script behavior combinations, file-type checks, and contextual entropy evidence. High entropy alone contributes no risk because compressed, encrypted, and media files are commonly high entropy.
- **Adaptive family similarity:** authenticated definition bundles can carry compact 64-element bottom-k fingerprints for related PE families. The linear, fixed-memory pass runs only for PE files that fall within a profile's size band, requires at least 85% similarity, is protected by a match-rate circuit breaker, and is advisory rather than destructive until independently corroborated.
- **Real-time enforcement:** protocol v5 performs post-create inspection of selected high-risk opens, gates executable section creation, and emits bounded protected-document write, rename, and delete telemetry keyed by the kernel process-start key. User mode opens candidates without following reparse points, checks the live Windows file ID, scans that exact handle without a pathname cache, and the driver tracks writes with a content generation counter.
- **Archive and document inspection:** ZIP, nested ZIP, OOXML, Gzip, and OLE streams are inspected in memory under shared depth, entry, expansion, compression-ratio, finding, and time budgets. VBA compressed containers are decoded; active PDF JavaScript/launch actions and suspicious Office macro/external-content combinations are detected. Entries are never extracted to disk. RAR and 7z payload expansion is not yet implemented.
- **Ransomware behavior:** distinct writes, renames, and deletions of user document/media data are correlated per stable process identity in a ten-second window. Authenticode-trusted, unknown, and untrusted writers have separate thresholds. Audit mode is the default; optional block mode denies threshold-crossing modifications but never quarantines the victim documents.
- **On-demand scans:** quick, full, and custom scans with bounded worker queues, progress, cancellation, exclusions, optional network-drive traversal, and configurable resource use.
- **Service boundary:** `BlackshardProtectionService` owns detection, settings, quarantine, history, and updates. The desktop UI talks to it over a local named pipe with bounded messages, remote clients rejected, caller token/process validation, per-scan ownership, and elevated-administrator authorization for machine-wide mutations. The UI remains unelevated and uses narrow, digest-bound UAC helper requests only when those mutations are requested.
- **Quarantine:** exact-hash and file-identity revalidation, encrypted/neutralized storage, no-overwrite restore, explicit deletion, machine ACLs, activity records, and per-user toast notifications through a session broker.
- **Definitions:** bounded Ed25519-authenticated bundles, HTTPS-only retrieval through Windows WinHTTP, expiry and rollback checks, atomic activation, last-known-good recovery, origin restrictions, and hot reload. The default schedule is every four hours with jitter when a release endpoint and trust key are compiled in.
- **Desktop client:** a DirectX 12/WGPU UI with dashboard, scan, quarantine, activity, settings, update state, service/filter health, build-signature status, and a harmless end-to-end protection test.
- **One-file distribution:** the release pipeline emits one signed `BlackshardSetup.exe`. Setup installs the signed application/service and the INF/SYS/CAT driver package; Windows necessarily keeps those installed components separate at runtime.

Blackshard consumes the Windows AMSI API but does **not** register as an AMSI provider. It does not embed the resource-heavy ClamAV engine; the definition publishing tools can instead import reviewed SHA-256 records from FreshClam-verified databases as a legacy-threat layer. Blackshard does not yet self-update application/driver binaries in the background or implement Shardnet/P2P. AMSI coverage therefore depends on providers already installed on Windows and is an additional signal, not an independent Blackshard script engine.

## Install Blackshard — regular users

Only install a release explicitly marked production-ready on the project's official release page. Until one exists, keep Microsoft Defender or another supported antivirus enabled.

1. Download `BlackshardSetup.exe` and its published SHA-256 checksum from the official Blackshard release.
2. Right-click the file, select **Properties → Digital Signatures**, and confirm Windows reports a valid Blackshard publisher signature. Do not continue if the publisher is missing or Windows reports an invalid signature.
3. Double-click `BlackshardSetup.exe`, approve the normal administrator prompt, and restart Windows if setup requests it.
4. Open **Blackshard** from the Start menu. The dashboard must report the protection service running, the filter connected, current definitions, and no degraded-event warning.
5. Run **Harmless protection test**. This validates the end-to-end enforcement path without live malware.

Never enable test-signing mode, disable Secure Boot or Memory Integrity, suppress SmartScreen, or add an antivirus exclusion to install a public Blackshard release. Those actions are only part of the disposable-VM developer workflow below.

## Component names

Do not confuse the two Service Control Manager entries:

| SCM name | Type | Purpose |
| --- | --- | --- |
| `blackshard` | `FILE_SYSTEM_DRIVER` | Kernel minifilter installed from the signed driver package |
| `BlackshardProtectionService` | `WIN32_OWN_PROCESS` | LocalSystem user-mode scanner, quarantine owner, update client, and local control server |

A healthy installation requires both entries, a loaded filter instance, a fresh service-health record, and a connected filter port. A registered but stopped `blackshard` driver provides no protection.

## Supported build target

The current Phase 1 package is native **Windows x64**. ARM64 needs separately compiled application and driver binaries plus a separately submitted Microsoft-signed driver package; an x64 setup cannot be made architecture-universal by renaming it.

Public release support must be limited to Windows editions still serviced by Microsoft and validated by the project. Ordinary Windows 10 Home/Pro 22H2 reached end of support on October 14, 2025; LTSC and ESU servicing have different lifecycles. See [Microsoft's Windows 10 lifecycle](https://learn.microsoft.com/en-us/lifecycle/products/windows-10-home-and-pro).

## Build Blackshard — developers

Requirements:

- Rust with the `x86_64-pc-windows-msvc` toolchain
- Visual Studio 2022 C++ Build Tools
- A current Windows Driver Kit (WDK), or internet access for the pinned Microsoft WDK NuGet fallback
- Administrator rights only for driver installation/removal and service diagnostics

Run the user-mode checks:

```powershell
cargo fmt --check
cargo test
cargo clippy --all-targets -- -D warnings
cargo build --release
```

Build the driver:

```powershell
.\build-driver.ps1
```

`build-driver.ps1` prefers an installed WDK. If only the Windows SDK is present, it downloads the pinned official `Microsoft.Windows.WDK.x64` package into ignored `target\wdk-nuget`, verifies its SHA-512, and uses it as a workspace-local build layer. `-NoNuGetFallback` disables that fallback.

The resulting `target\release\blackshard.exe` is a developer artifact unless it was compiled with the production altitude/update trust values and passed the production packager. Building the Rust executable alone does not install the LocalSystem service or minifilter.

## Community and online definitions

Installed clients retrieve only short-lived Blackshard envelopes authenticated by the release Ed25519 key. They do not trust an arbitrary third-party URL directly. This prevents a compromised mirror or poisoned community rule from immediately becoming machine-wide enforcement policy.

Maintainers can use Cisco Talos ClamAV as a reviewed legacy-hash input without running a second resident engine:

1. Install the current official ClamAV tools on an isolated definition-build host.
2. Run `freshclam` against the official database distribution, then use `sigtool --unpack` on the verified CVD/CLD files.
3. Import SHA-256 `.hsb` records into a schema-2 candidate:

```powershell
.\tools\Import-ClamAvSha256.ps1 `
    -DatabaseDirectory C:\definitions\clamav-unpacked `
    -OutputPath C:\definitions\candidate.bundle `
    -BundleId community-20260722-1 `
    -AcceptClamAvGpl2
```

4. Review provenance, licensing, duplicates, expected match volume, clean-corpus results, and any YARA/similarity additions. Sign on an offline-controlled host:

```powershell
.\tools\Publish-DefinitionBundle.ps1 `
    -BundlePath C:\definitions\candidate.bundle `
    -PrivateKeyPath E:\offline-key\blackshard-ed25519-private.pem `
    -PublicKeyPath E:\offline-key\blackshard-ed25519-public.pem `
    -Sequence 42 `
    -Version 2026.07.22.1 `
    -PayloadUrl https://updates.blackshard.dev/stable/rules-42.bundle `
    -OutputDirectory C:\definitions\publish `
    -ValidatorPath .\target\release\blackshard.exe
```

5. Upload `rules-42.bundle` first and `manifest.json` last. Clients verify product/channel scope, signature, sequence, expiry, size, and SHA-256 before atomic activation. The default four-hour schedule provides six checks per day with jitter.

YARA Forge publishes a curated GPL-3.0 core set weekly, but its current combined core package is deliberately not loaded wholesale: thousands of heterogeneous rules need license/provenance review, YARA-X compatibility testing, policy mapping, performance measurement, and clean-corpus qualification. Reviewed subsets can be placed in the bundle's `yara_bundles` field and remain non-destructive unless independently corroborated.

After pinning a reviewed upstream file by content hash, maintainers can add it without hand-editing JSON:

```powershell
.\tools\Import-YaraSource.ps1 `
    -BaseBundlePath C:\definitions\candidate.bundle `
    -YaraSourcePath C:\definitions\reviewed-core.yar `
    -Namespace yara_forge_reviewed_20260722 `
    -Provider YARA-Forge `
    -SourceUrl https://github.com/YARAHQ/yara-forge/releases/tag/2026-07-19 `
    -License GPL-3.0 `
    -OutputPath C:\definitions\candidate-with-yara.bundle `
    -AcceptReviewedSource
```

Imported rules without an explicit policy are advisory suspicious findings (risk 25), never quarantine authority. `Publish-DefinitionBundle.ps1` invokes the release client to compile and validate the entire candidate before signing output becomes publishable.

The publish directory is a static HTTPS feed: host `stable/manifest.json` and its signed payload with no server-side execution, immutable audit logs, restrictive deployment credentials, and payload-first/manifest-last replacement. Prefer immutable sequence-named payloads such as `stable/rules-42.bundle`; the feed builder does this automatically so in-flight clients can still retrieve the previous generation. The private definition key must not be stored on the web host. Clients reject a mirror that cannot present a normal Windows-trusted HTTPS certificate or content that does not match the signed manifest.

`tools\Build-StaticDefinitionFeed.ps1` performs the bounded ClamAV SHA-256 import and signed publication as one release operation, refuses signing keys stored beneath the public feed directory, and emits the exact manifest URL to compile into release clients. Hosting and operational credentials remain deliberately outside the repository.

## Detection evaluation and fuzzing

Build the release client, then evaluate a legally held corpus from an isolated VM:

```powershell
.\tools\Measure-DetectionCorpus.ps1 `
    -CorpusDirectory D:\corpora\clean-2026-07 `
    -ReportPath D:\evidence\clean-report.json
```

The report records each relative path/verdict plus aggregate bytes, throughput, and p50/p95/p99 latency. Keep clean, malicious, training, rule-development, and time-separated evaluation sets disjoint. Never commit samples or private filenames.

Create a CSV with `path,label` columns (`label` is `clean` or `malicious`) whose paths exactly match the report, then calculate both review-threshold and strict-malicious confusion matrices, recall, precision, false-positive rates, and 95% Wilson intervals:

```powershell
.\tools\Score-DetectionCorpus.ps1 `
    -DetectionReportPath D:\evidence\combined-report.json `
    -LabelsCsvPath D:\evidence\labels.csv `
    -OutputPath D:\evidence\metrics.json
```

Fuzz targets for arbitrary static-analysis bytes and MS-OVBA decompression are under `fuzz/`; see [fuzz/README.md](fuzz/README.md). Capture a local compatibility record with:

```powershell
.\tools\Collect-CompatibilityEvidence.ps1 -OutputPath .\blackshard-compatibility.json
```

The security boundaries and independent-review packet are defined in [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md). These tools make evidence reproducible; they do not substitute for a legally sourced corpus, sustained fuzzing, compatibility labs, or independent reviewers.

## Production installer flow

The intended end-user artifact is:

```text
target\production-installer\BlackshardSetup.exe
```

It can be built only when the release operator has all production inputs: a Microsoft-assigned altitude, a current INF, a production-built x64 agent, a Microsoft-returned signed CAT covering the INF/SYS, and a publicly trusted organization Authenticode certificate with timestamping access.

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

Before that packaging command, the release EXE must be compiled with the exact production values. The packager executes a side-effect-free validation mode and rejects any mismatch:

```powershell
$env:BLACKSHARD_MINIFILTER_ALTITUDE = '123456.789'
$env:BLACKSHARD_UPDATE_MANIFEST_URL = 'https://updates.example/blackshard/stable/manifest.json'
$env:BLACKSHARD_DEFINITION_PUBLIC_KEY_HEX = 'd75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a'
cargo build --release
```

The example values are placeholders; a production build requires the Microsoft-assigned altitude and the real offline-controlled feed public key.

There is intentionally no unsigned production switch. The script rejects a development altitude, an untrusted/self-signed application certificate, an invalid INF, and a catalog that does not pass Microsoft kernel-policy verification. See [installer/README.md](installer/README.md) for all inputs and transaction caveats.

### Public trust and cost reality

Blackshard itself requires no Microsoft software license or per-user royalty. A qualifying open-source project can apply to [SignPath Foundation](https://signpath.org/) for no-cost Authenticode signing of the user-mode application and installer, subject to SignPath's eligibility and build-origin policies.

That option does not remove the kernel-driver identity requirement. Microsoft requires an organization to register an EV code-signing certificate with the Windows Hardware Developer Program before it can submit a new minifilter for Microsoft signing. The Entra directory can be created free, and the EV certificate is used to establish the organization rather than to sign the returned driver, but Microsoft currently instructs organizations without one to purchase it from an approved certificate authority. There is no safe technical workaround compatible with normal Secure Boot and Windows code-integrity policy. Blackshard must fund, sponsor, or obtain that external prerequisite before a public minifilter release; end users must never be asked to weaken their PCs instead.

After installing a qualified build, open an elevated PowerShell in the repository or diagnostics bundle and run:

```powershell
.\verify.ps1
```

## Disposable-VM development flow

The root `deploy.ps1`, `install.ps1`, `enable-test-signing.ps1`, `disable-test-signing.ps1`, and `uninstall.ps1` scripts are **development tools for a disposable, snapshotted VM only**. They are not an alternative installer and must never be given to end users.

Clean CI builds also emit `BlackshardVmSetup.exe`, a one-click **development VM installer** with a Blackshard-styled graphical progress/error interface. It bundles the agent and test minifilter, configures test-signing, resumes automatically after reboot, installs and verifies both services, repairs partial attempts, and registers uninstall. It refuses systems that Windows does not identify as virtual machines and does not weaken the production installer's signature gates. See [the testing guide](docs/TESTING.md#one-click-vm-setup).

They use a placeholder altitude and may require Windows test-signing mode. Do not enable test signing, disable Secure Boot or Memory Integrity, install an unsigned driver, or add antivirus exclusions on a personal or production computer.

In an isolated VM:

```powershell
.\deploy.ps1
```

Copy the complete `dist` directory to the VM, take a snapshot, then use an elevated PowerShell:

```powershell
.\enable-test-signing.ps1
# Reboot the VM.
.\install.ps1
.\verify.ps1 -DevelopmentVm
.\blackshard.exe
```

Remove it and restore normal code-integrity state before reusing the VM:

```powershell
.\uninstall.ps1
.\disable-test-signing.ps1
# Reboot, or revert the VM snapshot.
```

## Harmless protection validation

The preferred test uses no malware and no generic high-entropy trigger:

1. Confirm the UI reports the protection service running, the filter connected, and real-time protection active.
2. On the Dashboard, select **Run harmless protection test**.
3. A pass means Blackshard generated its inert 72-byte test payload, launched a separate read probe, received an exact-signature verdict, and the minifilter denied that probe end to end.
4. Check Activity/Quarantine and `%ProgramData%\Blackshard\history.jsonl` for Blackshard attribution. A green UI alone is not sufficient evidence.

EICAR is the standard non-malicious antivirus test file. Use it only in the disposable malware-test VM because another installed security product may intercept it first. Do not disable that product merely to force the test. To create the exact 68-byte file:

```powershell
$eicarPath = Join-Path $env:TEMP 'eicar.com'
$eicar = 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
[IO.File]::WriteAllText($eicarPath, $eicar, [Text.Encoding]::ASCII)
(Get-FileHash -Algorithm SHA256 -LiteralPath $eicarPath).Hash
```

The expected digest is `275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F`. Run a Blackshard custom scan on the file's directory. A valid Blackshard result is an `EICAR-Test-File` detection accompanied by a Blackshard history event; disappearance without that attribution may have been caused by another antivirus.

Never test with live malware on a personal machine. Use an isolated, disposable VM with no sensitive data or credentials for adversarial samples.

The complete clean-PC false-positive workflow, isolated malware-VM procedure, evidence checklist, and acceptance rules are in [docs/TESTING.md](docs/TESTING.md).

## Security and contribution boundary

Detection claims require reproducible evidence. Changes should preserve bounded reads/queues, exact-object validation, fail-closed authentication of update material, non-destructive handling of heuristic findings, and least-privilege service/UI separation. Do not weaken Windows code integrity, ProgramData ACLs, update signature checks, or installer gates to make a development build easier to run.

Phase 1 intentionally contains no P2P networking. Shardnet requires a separately reviewed protocol with signed records, peer authentication, replay protection, privacy controls, rate limiting, revocation, and poisoning resistance.

Blackshard is licensed under GPL-3.0; see [LICENSE](LICENSE).
