#![no_main]

use blackshard::engine::ScanEngine;
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

fuzz_target!(|data: &[u8]| {
    if data.len() > 1024 * 1024 {
        return;
    }
    static ENGINE: OnceLock<ScanEngine> = OnceLock::new();
    let _ = ENGINE.get_or_init(ScanEngine::default).scan_bytes(data);
});
