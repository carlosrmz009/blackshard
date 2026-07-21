# Blackshard

Blackshard is an open-source adaptive antivirus research project focused on a lightweight Windows endpoint agent. The long-term roadmap includes authenticated peer-to-peer threat intelligence (Shardnet), cross-platform clients, and legacy-system support. See [blackshard.dev](https://blackshard.dev/) for the project vision.

This repository currently implements the Phase 1 Windows prototype:

- A Windows file-system minifilter that can deny file opens.
- A Rust/egui desktop agent that analyzes the first 1 MiB of candidate files.
- A bounded, fail-open kernel/user communication path.
- Truthful connected/disconnected UI state and scan counters.
- A harmless end-to-end enforcement self-test.
- VM-oriented installation, verification, test-signing, and removal scripts.

## Important status

Blackshard is not yet a production antivirus. The current detector is an entropy heuristic: files above an entropy score of `7.2` are blocked. This is useful for exercising the enforcement pipeline, but it can flag compressed or encrypted files and it will miss many malicious files. Do not replace Microsoft Defender or another production endpoint security product with this prototype.

The driver fails open if the agent is disconnected or does not answer within three seconds. This prevents a crashed analyzer from indefinitely freezing file access.

## Requirements

- 64-bit Windows 10 or newer.
- Rust with the `x86_64-pc-windows-msvc` toolchain.
- Visual Studio 2022 C++ Build Tools.
- Either an installed Windows Driver Kit (WDK), or internet access on the first driver build so the pinned Microsoft WDK NuGet fallback can be downloaded.
- Administrator rights for installing or removing the minifilter.
- A properly signed driver for production systems.

`build-driver.ps1` prefers an installed WDK. If only the ordinary Windows SDK is present, it downloads the pinned official `Microsoft.Windows.WDK.x64` package into ignored `target\wdk-nuget`, verifies its SHA-512, and uses it as a workspace-local kernel build layer. `-NoNuGetFallback` disables that behavior.

## Build and package

From PowerShell in the repository root:

```powershell
.\deploy.ps1
```

Deployment builds both the driver and release agent, rejects a stale `.sys`, and creates `dist\` containing the executable and lifecycle scripts.

To build the components separately:

```powershell
.\build-driver.ps1
cargo build --release
```

## Safe test-VM installation

Take a VM snapshot first. Keep the VM isolated from sensitive data and production networks.

The repository does not contain a production driver-signing certificate. For development testing only:

1. Copy the complete `dist` directory into the VM.
2. Disable Secure Boot in the disposable VM if Windows prevents test-signing mode.
3. Open PowerShell as Administrator in `dist`.
4. Sign the driver and enable Windows test-signing:

   ```powershell
   .\enable-test-signing.ps1
   ```

5. Restart the VM.
6. Install and load the minifilter:

   ```powershell
   .\install.ps1
   ```

7. Verify the service, loaded filter, instances, and installed signature:

   ```powershell
   .\verify.ps1
   ```

8. Launch `blackshard.exe` as Administrator. The filter port intentionally rejects unprivileged clients; the header must say `FILTER CONNECTED`.
9. Click **Run harmless self-test**. A pass means a separate probe process was denied access to a generated high-entropy file and no malware was used.

The UI saying `FILTER DISCONNECTED` means no enforcement is active, even if the service is registered.

## Removal

From an elevated PowerShell in `dist`:

```powershell
.\uninstall.ps1
.\disable-test-signing.ps1
```

Restart the VM after disabling test-signing. Reverting the VM snapshot is the cleanest option.

## Manual diagnostics

```powershell
fltmc filters | Select-String blackshard
fltmc instances -f blackshard
sc.exe query blackshard
Get-AuthenticodeSignature .\blackshard.sys
```

Expected healthy state:

- `fltmc filters` lists `blackshard`.
- `fltmc instances -f blackshard` lists at least one attached volume.
- `sc.exe query blackshard` reports `RUNNING`.
- The agent reports `FILTER CONNECTED`.
- The harmless self-test reports `PASS`.

## Detection and enforcement flow

1. The minifilter observes relevant user-mode file opens.
2. It excludes directories, new/overwrite creates, requests without read/execute access, and the connected analyzer process itself.
3. It sends the path and requestor PID to the agent with a three-second timeout.
4. The agent reads at most 1 MiB, calculates Shannon entropy, records the decision, and replies.
5. The minifilter returns `STATUS_ACCESS_DENIED` only for an explicit block verdict received before the timeout.

The self-test creates random-looking bytes, launches a separate copy of the agent in probe mode, and confirms that the kernel blocks that probe. The temporary file is deleted afterward.

## Roadmap boundaries

Shardnet is intentionally not implemented as unauthenticated gossip. A safe peer-to-peer design needs signed shard records, peer authentication, replay protection, privacy-preserving identifiers, rate limiting, revocation, and poisoning resistance. Those protocol decisions belong in a reviewed later phase rather than in the endpoint MVP.

Likewise, Linux, macOS, and legacy operating-system clients require platform-specific enforcement backends. The current protocol and analyzer separation are foundations for that work, but this repository presently targets modern x64 Windows.
