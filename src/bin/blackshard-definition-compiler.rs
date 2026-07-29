use blackshard::atomic_file;
use blackshard::definitions::{
    DefinitionBundle, DefinitionPayload, DefinitionProvenance, MAX_COMPACT_SHA256_SIGNATURES,
};
use chrono::Utc;
use sha2::{Digest, Sha256};
use std::error::Error;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

const PROVIDER: &str = "abuse.ch-MalwareBazaar-Full";
const SOURCE_URL: &str = "https://bazaar.abuse.ch/export/";
const MAX_EXPORT_BYTES: u64 = 768 * 1024 * 1024;
const MAX_LINE_BYTES: usize = 1024 * 1024;

fn main() {
    if let Err(error) = run() {
        eprintln!("definition compiler failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    let mode = arguments.next();
    let export_path = arguments.next();
    let base_bundle_path = arguments.next();
    let output_path = arguments.next();
    let bundle_id = arguments.next();
    if mode.as_deref() != Some(std::ffi::OsStr::new("--pack-malwarebazaar"))
        || export_path.is_none()
        || base_bundle_path.is_none()
        || output_path.is_none()
        || bundle_id.is_none()
        || arguments.next().is_some()
    {
        return Err(
            "usage: blackshard-definition-compiler --pack-malwarebazaar <export> <base-bundle> <output> <bundle-id>"
                .into(),
        );
    }

    let export_path = PathBuf::from(export_path.expect("checked"));
    let base_bundle_path = PathBuf::from(base_bundle_path.expect("checked"));
    let output_path = PathBuf::from(output_path.expect("checked"));
    let bundle_id = bundle_id.expect("checked").to_string_lossy().into_owned();
    let mut bundle = DefinitionBundle::from_json(&std::fs::read(&base_bundle_path)?)?;
    bundle.bundle_id = bundle_id;

    let (digests, content_sha256) = read_export(&export_path)?;
    bundle.sources.retain(|source| source.provider != PROVIDER);
    bundle.sources.push(DefinitionProvenance {
        provider: PROVIDER.to_owned(),
        source_url: SOURCE_URL.to_owned(),
        retrieved_at: Utc::now(),
        content_sha256,
        license:
            "abuse.ch community export fair use and terms apply; review required before redistribution"
                .to_owned(),
    });

    let count = digests.len();
    let payload = DefinitionPayload::to_compact_bytes(
        bundle,
        digests,
        "MalwareBazaar.Historical".to_owned(),
        None,
    )?;
    atomic_file::write(&output_path, &payload)?;
    println!(
        "Packed {count} unique MalwareBazaar SHA-256 signatures into {} bytes: {}",
        payload.len(),
        output_path.display()
    );
    Ok(())
}

fn read_export(path: &Path) -> Result<(Vec<[u8; 32]>, String), Box<dyn Error>> {
    let metadata = std::fs::metadata(path)?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_EXPORT_BYTES {
        return Err(format!(
            "export must be a non-empty regular file no larger than {MAX_EXPORT_BYTES} bytes"
        )
        .into());
    }

    let mut reader = BufReader::with_capacity(1024 * 1024, File::open(path)?);
    let mut source_hash = Sha256::new();
    let mut digests = Vec::new();
    let mut line = Vec::new();
    loop {
        line.clear();
        let read = reader.read_until(b'\n', &mut line)?;
        if read == 0 {
            break;
        }
        if line.len() > MAX_LINE_BYTES {
            return Err("export contains an oversized line".into());
        }
        source_hash.update(&line);
        if let Some(digest) = first_isolated_sha256(&line) {
            digests.push(digest);
            if digests.len() > MAX_COMPACT_SHA256_SIGNATURES {
                return Err(format!(
                    "export exceeds the {MAX_COMPACT_SHA256_SIGNATURES}-signature safety limit"
                )
                .into());
            }
        }
    }
    if digests.is_empty() {
        return Err("export contains no SHA-256 records".into());
    }
    digests.sort_unstable();
    digests.dedup();
    Ok((digests, hex::encode(source_hash.finalize())))
}

fn first_isolated_sha256(line: &[u8]) -> Option<[u8; 32]> {
    if line.len() < 64 {
        return None;
    }
    for start in 0..=line.len() - 64 {
        let end = start + 64;
        if (start > 0 && line[start - 1].is_ascii_hexdigit())
            || (end < line.len() && line[end].is_ascii_hexdigit())
            || !line[start..end].iter().all(u8::is_ascii_hexdigit)
        {
            continue;
        }
        let mut digest = [0u8; 32];
        if hex::decode_to_slice(&line[start..end], &mut digest).is_ok() {
            return Some(digest);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_only_an_isolated_sha256() {
        let expected = [0xabu8; 32];
        let line = format!("2026-01-01,\"{}\",Win.Test", "ab".repeat(32));
        assert_eq!(first_isolated_sha256(line.as_bytes()), Some(expected));
        assert_eq!(
            first_isolated_sha256(format!("f{}", "ab".repeat(32)).as_bytes()),
            None
        );
        assert_eq!(first_isolated_sha256(b"sha256_hash"), None);
    }
}
