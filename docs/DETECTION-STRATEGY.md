# Detection strategy and commercial-parity program

Blackshard's target is measurable protection quality competitive with leading commercial Windows antivirus products. No single signature feed, heuristic score, or machine-learning model establishes that result. The product must combine independent layers and demonstrate their behavior on time-separated malware and clean corpora at very low false-positive rates.

## Current cascade

1. Exact whole-file SHA-256 lookup provides the cheapest high-confidence known-malware decision.
2. Bounded content classification and PE/script structural analysis extract interpretable signals. Entropy alone has no risk weight.
3. Signed bottom-k similarity profiles look for close PE-family variants with fixed memory and linear sampled work. Size gating avoids computing a sketch when no profile could match.
4. Built-in and authenticated YARA-X rules evaluate semantic byte/string relationships under source, count, and time limits.
5. Eligible script, Office, or rule-selected content is submitted to the installed Windows AMSI provider.
6. Authenticated FreshClam CVD/CLD generations feed both a native SHA-256 index and a bounded full-engine ClamAV worker. The service duplicates the already-open file handle into the worker so pathname replacement cannot substitute another object.
7. Independent signals are fused conservatively. Only Blackshard's trusted exact hashes currently authorize automatic quarantine; ClamAV and AMSI can deny execution; publisher YARA, similarity, and heuristics remain reversible/advisory.
8. Match-rate circuit breakers suppress an external YARA or similarity generation whose observed prevalence exceeds its safety envelope.
9. ZIP/OOXML, Gzip, OLE/VBA, and active PDF content are inspected within shared expansion and time budgets; structured candidates must also pass an isolated parser worker health/scan boundary.
10. Protected write, rename, and delete telemetry is correlated per stable process identity. Separate Authenticode trust tiers reduce false positives; a bounded kernel-side entropy class now participates in write/rename correlation, and audit mode precedes any block-mode rollout.

## Why the adaptive layer is not called “AI malware conviction”

The similarity engine adapts through signed profiles without shipping a large neural runtime. It is deterministic, explainable, bounded, and inexpensive. It can find close variants that have different whole-file hashes, but resemblance is not proof of maliciousness. Automatic destructive action would require independent corroboration and measured calibration.

A future learned PE model must be distributed as signed, versioned data; expose its feature schema and training provenance; report uncertainty; abstain outside its training distribution; and be tested at operational false-positive rates. Research on static malware detection shows that uncertainty-aware ensembles can materially improve results under extreme false-positive constraints, while stale or mismatched feature extractors make model output unreliable. A model will therefore not be embedded merely because it scores well on a random train/test split.

## External intelligence

- Blackshard's Ed25519-signed online bundle is the only direct client trust path.
- The development package pins the official ClamAV runtime by archive SHA-256. Official `freshclam` and `sigtool` verify and atomically activate versioned databases. One `clamd` child remains resident inside the worker job so definitions are compiled once; Blackshard streams bytes from the identity-validated open handle using `INSTREAM` instead of exposing a replaceable pathname.
- YARA Forge core releases are useful upstream material, not automatic policy. Each included subset needs provenance/license review, YARA-X compilation, policy assignment, match-rate analysis, and clean-corpus qualification.
- Public multi-engine or sample-upload services are not silently queried. Uploading user files creates privacy, confidentiality, API-license, availability, and attacker-oracle risks.

## Required parity evidence

Before claiming parity with Bitdefender, Norton, McAfee, Kaspersky, Defender, or another product, publish reproducible results for:

- time-separated family recall and zero-day proxy recall;
- false-positive rate and confidence intervals over a large, representative clean corpus;
- precision, quarantine correctness, and recovery success;
- executable-launch p50/p95/p99 latency and scan throughput;
- idle/active CPU, RAM, disk I/O, battery, boot, and application-launch impact;
- service-outage, queue-overload, timeout, and kernel bypass counts;
- packed, signed, malformed, adversarially padded, and distribution-shifted samples;
- independent lab testing and an external security review.

The evaluation set must not overlap training, profile generation, YARA development, or threshold tuning. Results must name the exact commit, definition sequence, OS matrix, and comparison methodology.

## Next detection layers

The highest-value remaining work is RAR/7z/ISO inspection, executable unpacking/emulation, memory/process inspection, ransomware decoy/canary files and recovery, exploit telemetry, signed model distribution with uncertainty-based abstention, reputation/privacy infrastructure, and a legally operated sample intake/analysis pipeline. Each layer must preserve exact-object identity, bounded resource use, reversible handling of uncertain findings, and an independently measurable false-positive budget.
