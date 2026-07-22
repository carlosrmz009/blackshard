# Blackshard fuzzing

Install `cargo-fuzz` with a current nightly Rust toolchain, then run:

```powershell
cargo +nightly fuzz run scan_bytes -- -max_len=1048576 -timeout=10
cargo +nightly fuzz run vba_decompress -- -max_len=1048576 -timeout=10
```

Crashing inputs belong under the corresponding `fuzz/artifacts` directory and
must be minimized before becoming regression tests. Never add real malware or
sensitive documents to the public repository.
