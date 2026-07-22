# Blackshard Phase 1 threat model

Last reviewed: July 22, 2026.

This is a review aid, not an independent security assessment. It defines the security claims and boundaries that must be challenged before public release.

## Protected assets

- Integrity and availability of user files and executables.
- Confidentiality of scanned content, quarantine contents, paths, and history.
- Integrity of the kernel minifilter, LocalSystem service, desktop client, installer, configuration, and definition state.
- Authenticity, freshness, and rollback resistance of definition updates.
- Availability of the workstation under malformed, adversarial, and high-volume file activity.

## Trust boundaries

1. The kernel minifilter sends fixed-size versioned messages to the LocalSystem service. All fields, lengths, operations, identities, and timeouts are untrusted at each boundary.
2. The desktop client and notification process communicate through a local named pipe. The service authenticates the caller's process and token and re-authorizes every privileged request.
3. UAC helpers receive bounded, single-purpose, SHA-256-bound request files. The helper must distrust every pathname and revalidate the requested object.
4. Filesystem paths are attacker-controlled. Enforcement decisions bind an opened non-reparse-point handle to the kernel-provided live file identity and reject mutation races.
5. Definition transport is hostile even over HTTPS. Only a correctly scoped, current Ed25519 manifest and byte-exact payload can become active.
6. Quarantine metadata and storage are machine-owned hostile inputs on read. Restore must verify the authenticated container, original content hash, destination policy, and no-overwrite rule.
7. Installer inputs, CI artifacts, dependencies, developer workstations, signing authorization, and the static feed publisher are a software-supply-chain boundary.

## Attacker capabilities considered

- An unprivileged local process can create, rename, replace, truncate, lock, or rapidly rewrite files; use junctions/reparse points; churn PIDs; flood ports/queues; and submit malformed parser inputs.
- Malware may be packed, encrypted, padded, polyglot, signed with an untrusted or stolen certificate, embedded in a document/archive, or deliberately shaped to evade static rules.
- A network attacker or compromised mirror can block, replay, redirect, truncate, or replace definition responses, but does not possess the offline Ed25519 signing key.
- A local administrator or kernel-mode attacker is outside the prevention boundary. Blackshard must still fail safely and leave useful evidence, but cannot promise containment from an authority equal to or above itself.
- A compromised signing key, CI release identity, Microsoft-signed driver build input, or offline definition key is a release emergency requiring revocation and recovery procedures.

## Security invariants

- Entropy, similarity, generic YARA, archive structure, and ransomware correlation alone never quarantine a file.
- Only a complete, identity-stable, cryptographically exact trusted hash can authorize Blackshard quarantine. AMSI may deny executable use but cannot authorize quarantine.
- Truncated, timed-out, malformed, overloaded, or identity-mismatched scans cannot be represented as clean.
- Executable mapping fails closed when the service cannot establish a stable verdict; ordinary read telemetry has explicit bounded fail-open cases and observable counters.
- Archive expansion is in memory and globally budgeted by depth, entries, expanded bytes, ratio, findings, and time. No archive entry is extracted to disk.
- Ransomware behavior is keyed by process ID plus kernel process-start key, counts distinct protected writes/renames/deletions, defaults to audit, and never quarantines victim documents.
- Update activation is atomic and retains last-known-good state. Invalid, stale, expired, future-dated, redirected, oversized, cross-origin, or rollback content is rejected.
- The public installer must fail closed unless application artifacts and the complete driver package satisfy production signing policy.

## Principal abuse cases and controls

| Abuse case | Present controls | Evidence still required |
|---|---|---|
| Replace a scanned path after notification | non-reparse open, live file-ID check, handle scan, mutation check, content generation | rename/reparse stress and filesystem matrix |
| Flood scan/write messages to exhaust the service | bounded channel, workers, parser/file budgets, driver timeouts, telemetry throttle, bounded behavior state | sustained overload and fail-open counter tests |
| Archive/decompression bomb | shared expansion/ratio/depth/count/time ceilings, no extraction | fuzzing and adversarial archive corpus |
| Broad rule update causes mass false positives | signature/provenance validation, advisory policy, match-rate circuit breaker, last-known-good | staged canary, clean corpus, kill-switch exercise |
| Feed compromise/replay | Windows-trusted HTTPS plus offline Ed25519 signature, product/channel/origin/sequence/time/hash validation | key ceremony, rotation, revocation, expiry monitoring |
| Local IPC privilege escalation | local-only pipe, remote rejection, PID/token authorization, bounded frames, elevated checks | independent Windows security review and race testing |
| Quarantine overwrite or planted metadata | machine ACLs, authenticated encrypted containers, hash verification, no-overwrite restore | ACL inheritance and multi-user adversarial tests |
| Ransomware bypass or false blocking | stable process identity, distinct-file windows, trust-tier thresholds, audit default | rename/delete telemetry, workload baselines, rollback design |
| Supply-chain substitution | locked dependencies, pinned CI actions, production preflight, Authenticode/catalog checks | reproducible builds, SBOM, isolated release/signing process |

## Required independent review scope

Reviewers should receive the exact release commit, symbols, driver package, installer, protocol description, corpus methodology, fuzz crash history, and compatibility evidence. At minimum they should assess the minifilter callbacks and unload paths, kernel/user message validation, race and reparse handling, service/pipe/UAC authorization, parsers, update cryptography and operations, quarantine lifecycle, installer rollback/custom actions, ACLs, privacy, and denial-of-service behavior.

All findings need severity, exploit preconditions, affected versions, remediation commit, regression test, and closure evidence. The project must publish a limitations summary even when full exploit details are embargoed.
