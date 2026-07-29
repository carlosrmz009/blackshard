# blackshard fuzzing

Install `cargo-fuzz` with a current nightly Rust toolchain, then run:

```powershell
cargo +nightly fuzz run scan_bytes -- -max_len=1048576 -timeout=10
cargo +nightly fuzz run vba_decompress -- -max_len=1048576 -timeout=10
```

Crashing inputs belong under the corresponding `fuzz/artifacts` directory and
must be minimized before becoming regression tests. Never add real malware or
sensitive documents to the public repository.

The weekly and manually dispatched GitHub Actions fuzz job uploads
`fuzz/artifacts` as a `fuzz-failure-<run>-<attempt>` artifact when either target
fails. The artifact is retained for 30 days. Download it and reproduce a failure
by passing the crashing input to the matching target:

```powershell
cargo +nightly fuzz run scan_bytes .\fuzz\artifacts\scan_bytes\crash-<id>
cargo +nightly fuzz run vba_decompress .\fuzz\artifacts\vba_decompress\crash-<id>
```
