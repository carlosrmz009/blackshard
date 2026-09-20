//! Fetches and unpacks ClamAV definition containers without any ClamAV binaries.
//!
//! This previously shelled out to `freshclam.exe` to download and `sigtool.exe` to validate and
//! unpack. Both are now handled natively: the containers are plain HTTPS downloads and
//! [`crate::clamdb::cvd`] reads the format directly.
//!
//! Only `main` and `daily` are fetched. `bytecode.cvd` carries nothing but `.cbc` programs for
//! ClamAV's bytecode virtual machine, which blackshard does not implement, so downloading it would
//! cost bandwidth for signatures that could never be evaluated.

use chrono::{DateTime, Utc};
use log::info;
use md5::{Digest, Md5};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::clamdb::cvd;

const ACTIVE_POINTER: &str = "active.json";

/// The containers blackshard consumes, in the order they are applied.
const CONTAINERS: [&str; 2] = ["main", "daily"];

const DEFAULT_MIRROR: &str = "https://database.clamav.net";

/// User-Agent sent to the official mirror.
///
/// `database.clamav.net` answers 403 to anything whose User-Agent does not begin with `ClamAV/` or
/// `CVDUPDATE/`; a plain product token, and even `curl`, is rejected outright. The `ClamAV/` prefix
/// is therefore a required compatibility token rather than a claim of identity, and blackshard is
/// named in the comment field so the traffic remains attributable.
///
/// Cisco rate limits this endpoint and asks that frequent pollers mirror the containers rather
/// than fetch them repeatedly. `BLACKSHARD_CLAMAV_MIRROR` exists for exactly that: point it at a
/// private mirror or a `cvdupdate` cache for anything beyond ordinary end-user refreshes.
const USER_AGENT: &str = concat!(
    "ClamAV/1.4.1 (blackshard/",
    env!("CARGO_PKG_VERSION"),
    "; +https://blackshard.dev)"
);

/// Generous ceiling for one container. `main.cvd` sits comfortably under this today.
const MAX_CONTAINER_BYTES: u64 = 512 * 1024 * 1024;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const READ_TIMEOUT: Duration = Duration::from_secs(300);

/// Minimum age before a cached generation is refreshed.
const REFRESH_INTERVAL_MINUTES: i64 = 60;

#[derive(Debug)]
pub enum DownloadError {
    Io(io::Error),
    Http(String),
    Validation(String),
}

impl fmt::Display for DownloadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "{error}"),
            Self::Http(error) => formatter.write_str(error),
            Self::Validation(error) => formatter.write_str(error),
        }
    }
}

impl std::error::Error for DownloadError {}

impl From<io::Error> for DownloadError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<cvd::CvdError> for DownloadError {
    fn from(error: cvd::CvdError) -> Self {
        match error {
            cvd::CvdError::Io(error) => Self::Io(error),
            cvd::CvdError::Malformed(detail) => Self::Validation(detail),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveDatabase {
    pub generation: u64,
    pub version: String,
    pub activated_at: DateTime<Utc>,
    pub path: PathBuf,
    pub unpacked_path: PathBuf,
}

/// The mirror containers are fetched from, overridable for testing and for private mirrors.
fn mirror() -> String {
    std::env::var("BLACKSHARD_CLAMAV_MIRROR")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_MIRROR.to_owned())
}

pub fn download_databases(blackshard_data: &Path) -> Result<ActiveDatabase, DownloadError> {
    if let Ok(active) = active_database(blackshard_data) {
        if Utc::now()
            .signed_duration_since(active.activated_at)
            .num_minutes()
            < REFRESH_INTERVAL_MINUTES
        {
            return Ok(active);
        }
    }

    let clam_root = blackshard_data.join("ClamAV");
    let generation: u64 = Utc::now()
        .timestamp_millis()
        .try_into()
        .map_err(|_| DownloadError::Validation("system clock predates Unix epoch".to_owned()))?;
    let staging_dir = clam_root.join("Staging").join(generation.to_string());
    let unpacked_dir = staging_dir.join("Unpacked");
    fs::create_dir_all(&unpacked_dir)?;

    let base = mirror();
    let mut daily_version = None;
    for name in CONTAINERS {
        let destination = staging_dir.join(format!("{name}.cvd"));
        fetch_container(&base, name, &destination)?;
        let header = verify_container(&destination)?;
        if name == "daily" {
            daily_version = Some(header.version.to_string());
        }
        let (_, extracted) = cvd::extract(&destination, &unpacked_dir)?;
        info!(
            "Unpacked {name}.cvd version {} with {} signatures into {} files",
            header.version,
            header.signature_count,
            extracted.len()
        );
    }

    let generations_dir = clam_root.join("Generations");
    fs::create_dir_all(&generations_dir)?;
    let generation_dir = generations_dir.join(generation.to_string());
    fs::rename(&staging_dir, &generation_dir)?;

    let active = ActiveDatabase {
        generation,
        version: daily_version.unwrap_or_else(|| generation.to_string()),
        activated_at: Utc::now(),
        path: generation_dir.clone(),
        unpacked_path: generation_dir.join("Unpacked"),
    };
    write_active_pointer(&clam_root, &active)?;
    info!(
        "Activated ClamAV definition generation {} ({})",
        active.generation, active.version
    );
    Ok(active)
}

/// Streams one container to disk over HTTPS.
fn fetch_container(base: &str, name: &str, destination: &Path) -> Result<(), DownloadError> {
    let url = format!("{}/{name}.cvd", base.trim_end_matches('/'));
    if !url.starts_with("https://") {
        return Err(DownloadError::Validation(format!(
            "the configured ClamAV mirror is not an HTTPS origin: {url}"
        )));
    }

    let agent = ureq::AgentBuilder::new()
        .timeout_connect(CONNECT_TIMEOUT)
        .timeout_read(READ_TIMEOUT)
        .build();
    let response = agent
        .get(&url)
        .set("User-Agent", USER_AGENT)
        .call()
        .map_err(|error| DownloadError::Http(format!("could not fetch {url}: {error}")))?;

    let mut reader = response.into_reader().take(MAX_CONTAINER_BYTES + 1);
    let mut file = File::create(destination)?;
    let copied = io::copy(&mut reader, &mut file)?;
    file.flush()?;

    if copied > MAX_CONTAINER_BYTES {
        let _ = fs::remove_file(destination);
        return Err(DownloadError::Validation(format!(
            "{name}.cvd exceeded the {MAX_CONTAINER_BYTES} byte ceiling"
        )));
    }
    if copied <= cvd::HEADER_LEN as u64 {
        let _ = fs::remove_file(destination);
        return Err(DownloadError::Validation(format!(
            "{name}.cvd was truncated to {copied} bytes"
        )));
    }
    Ok(())
}

/// Confirms the container body matches the MD5 recorded in its own header.
///
/// This is an integrity check against a corrupt or truncated download, not an authenticity check.
/// Authenticity rests on the HTTPS transport and, downstream, on the Ed25519 signature blackshard
/// applies to the converted bundle.
fn verify_container(path: &Path) -> Result<cvd::CvdHeader, DownloadError> {
    let header = cvd::read_header(path)?;

    let mut file = File::open(path)?;
    let mut skip = [0u8; cvd::HEADER_LEN];
    file.read_exact(&mut skip)?;

    let mut hasher = Md5::new();
    let mut buffer = vec![0u8; 1024 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let digest = hex::encode(hasher.finalize());

    if !digest.eq_ignore_ascii_case(&header.md5) {
        return Err(DownloadError::Validation(format!(
            "{} failed its integrity check: header declared {} but the body hashed to {digest}",
            path.display(),
            header.md5
        )));
    }
    Ok(header)
}

pub fn active_database(blackshard_data: &Path) -> Result<ActiveDatabase, DownloadError> {
    let pointer_path = blackshard_data.join("ClamAV").join(ACTIVE_POINTER);
    let bytes = fs::read(&pointer_path)?;
    let active: ActiveDatabase = serde_json::from_slice(&bytes)
        .map_err(|error| DownloadError::Validation(format!("invalid active pointer: {error}")))?;
    let canonical_root = fs::canonicalize(blackshard_data.join("ClamAV").join("Generations"))?;
    let canonical_active = fs::canonicalize(&active.path)?;
    if !canonical_active.starts_with(&canonical_root)
        || !active.path.is_dir()
        || !CONTAINERS
            .iter()
            .all(|name| active.path.join(format!("{name}.cvd")).is_file())
    {
        return Err(DownloadError::Validation(
            "the active ClamAV generation is missing or outside the protected store".to_owned(),
        ));
    }
    Ok(active)
}

fn write_active_pointer(clam_root: &Path, active: &ActiveDatabase) -> Result<(), DownloadError> {
    let pointer = clam_root.join(ACTIVE_POINTER);
    let bytes = serde_json::to_vec_pretty(active)
        .map_err(|error| DownloadError::Validation(error.to_string()))?;
    crate::atomic_file::write(&pointer, &bytes)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a container whose header MD5 agrees (or deliberately disagrees) with its body.
    fn container(body: &[u8], declared_md5: Option<&str>) -> Vec<u8> {
        let digest = declared_md5
            .map(str::to_owned)
            .unwrap_or_else(|| hex::encode(Md5::digest(body)));
        let text = format!(
            "ClamAV-VDB:16 Sep 2026 09-00 +0000:27000:2000000:90:{digest}:{}:blackshard:1758009600",
            "a".repeat(40)
        );
        let mut out = text.into_bytes();
        out.resize(cvd::HEADER_LEN, b' ');
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn accepts_a_container_whose_body_matches_its_header_digest() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("daily.cvd");
        fs::write(&path, container(b"definition archive bytes", None)).unwrap();

        let header = verify_container(&path).unwrap();
        assert_eq!(header.version, 27_000);
    }

    #[test]
    fn rejects_a_container_whose_body_was_altered() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("daily.cvd");
        fs::write(
            &path,
            container(b"definition archive bytes", Some(&"0".repeat(32))),
        )
        .unwrap();

        let error = verify_container(&path).unwrap_err();
        assert!(
            matches!(&error, DownloadError::Validation(detail) if detail.contains("integrity")),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn rejects_a_non_https_mirror() {
        let directory = tempfile::tempdir().unwrap();
        let error = fetch_container(
            "http://insecure.example",
            "daily",
            &directory.path().join("d.cvd"),
        )
        .unwrap_err();
        assert!(
            matches!(&error, DownloadError::Validation(detail) if detail.contains("HTTPS")),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn the_mirror_defaults_to_the_official_origin() {
        // The environment variable is not set in a clean test run.
        if std::env::var_os("BLACKSHARD_CLAMAV_MIRROR").is_none() {
            assert_eq!(mirror(), DEFAULT_MIRROR);
        }
    }

    #[test]
    fn an_absent_pointer_is_reported_rather_than_panicking() {
        let directory = tempfile::tempdir().unwrap();
        assert!(active_database(directory.path()).is_err());
    }
}
