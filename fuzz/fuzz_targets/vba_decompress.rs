#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() <= 1024 * 1024 {
        let _ = blackshard::vba::decompress(data, 4 * 1024 * 1024);
    }
});
