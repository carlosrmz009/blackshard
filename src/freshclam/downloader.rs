use chrono::{DateTime, Utc};
use log::info;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::Command;

const ACTIVE_POINTER: &str = "active.json";

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveDatabase {
    pub generation: u64,
    pub version: String,
    pub activated_at: DateTime<Utc>,
    pub path: PathBuf,
    pub unpacked_path: PathBuf,
}

/// Download, publisher-verify, unpack, and atomically activate the three
/// official ClamAV databases. The supplied path is Blackshard's protected
/// ProgramData directory, not the global ProgramData root.
pub fn download_databases(blackshard_data: &Path) -> Result<ActiveDatabase, DownloadError> {
    if let Ok(active) = active_database(blackshard_data) {
        if Utc::now()
            .signed_duration_since(active.activated_at)
            .num_minutes()
            < 60
        {
            return Ok(active);
        }
    }

    let sigtool = find_sigtool()?;
    let freshclam = find_runtime_tool("freshclam.exe", "BLACKSHARD_FRESHCLAM_PATH")?;
    let clam_root = blackshard_data.join("ClamAV");
    let generation: u64 = Utc::now()
        .timestamp_millis()
        .try_into()
        .map_err(|_| DownloadError::Validation("system clock predates Unix epoch".to_owned()))?;
    let staging_dir = clam_root.join("Staging").join(generation.to_string());
    let unpacked_dir = staging_dir.join("Unpacked");
    fs::create_dir_all(&unpacked_dir)?;
    run_freshclam(&freshclam, &staging_dir)?;

    let mut daily_version = None;
    for database_base in ["main", "daily", "bytecode"] {
        let destination = locate_database(&staging_dir, database_base).ok_or_else(|| {
            DownloadError::Validation(format!(
                "freshclam did not produce {database_base}.cvd or {database_base}.cld"
            ))
        })?;
        let version = validate_with_sigtool(&sigtool, &destination)?;
        if database_base == "daily" {
            daily_version = Some(version);
        }
        unpack_with_sigtool(&sigtool, &destination, &unpacked_dir)?;
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
        "Activated authenticated ClamAV generation {} ({})",
        active.generation, active.version
    );
    Ok(active)
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
        || !["main", "daily", "bytecode"]
            .iter()
            .all(|name| locate_database(&active.path, name).is_some())
    {
        return Err(DownloadError::Validation(
            "the active ClamAV generation is missing or outside the protected store".to_owned(),
        ));
    }
    Ok(active)
}

fn locate_database(directory: &Path, base: &str) -> Option<PathBuf> {
    ["cld", "cvd"]
        .into_iter()
        .map(|extension| directory.join(format!("{base}.{extension}")))
        .find(|path| path.is_file())
}

fn run_freshclam(freshclam: &Path, staging_dir: &Path) -> Result<(), DownloadError> {
    let config_path = staging_dir.join("freshclam.conf");
    let log_path = staging_dir.join("freshclam.log");
    let config = format!(
        "DatabaseDirectory {}\r\nDatabaseMirror database.clamav.net\r\nUpdateLogFile {}\r\nLogTime yes\r\nForeground yes\r\n",
        staging_dir.display(),
        log_path.display()
    );
    fs::write(&config_path, config)?;
    let output = Command::new(freshclam)
        .arg(format!("--config-file={}", config_path.display()))
        .args(["--stdout", "--verbose"])
        .output()?;
    if !output.status.success() {
        return Err(DownloadError::Http(format!(
            "freshclam failed: {} {}",
            String::from_utf8_lossy(&output.stdout).trim(),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}

fn validate_with_sigtool(sigtool: &Path, database: &Path) -> Result<String, DownloadError> {
    let mut header = [0u8; 512];
    File::open(database)?.read_exact(&mut header)?;
    let header = String::from_utf8_lossy(&header);
    if !header.starts_with("ClamAV-VDB:") {
        return Err(DownloadError::Validation(format!(
            "{} has no valid CVD header",
            database.display()
        )));
    }

    // sigtool performs ClamAV's CVD payload digest and publisher-signature
    // verification. A home-grown SHA-256 comparison is not equivalent.
    let output = Command::new(sigtool).arg("--info").arg(database).output()?;
    if !output.status.success() {
        return Err(DownloadError::Validation(format!(
            "sigtool rejected {}: {}",
            database.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let version = header
        .split(':')
        .nth(2)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("unknown")
        .to_owned();
    Ok(version)
}

fn unpack_with_sigtool(
    sigtool: &Path,
    database: &Path,
    unpacked_dir: &Path,
) -> Result<(), DownloadError> {
    let output = Command::new(sigtool)
        .arg("--unpack")
        .arg(database)
        .current_dir(unpacked_dir)
        .output()?;
    if !output.status.success() {
        return Err(DownloadError::Validation(format!(
            "sigtool could not unpack {}: {}",
            database.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}

fn write_active_pointer(clam_root: &Path, active: &ActiveDatabase) -> Result<(), DownloadError> {
    let pointer = clam_root.join(ACTIVE_POINTER);
    let bytes = serde_json::to_vec_pretty(active)
        .map_err(|error| DownloadError::Validation(error.to_string()))?;
    crate::atomic_file::write(&pointer, &bytes)?;
    Ok(())
}

fn find_sigtool() -> Result<PathBuf, DownloadError> {
    find_runtime_tool("sigtool.exe", "BLACKSHARD_SIGTOOL_PATH")
}

fn find_runtime_tool(file_name: &str, environment_name: &str) -> Result<PathBuf, DownloadError> {
    if let Some(configured) = std::env::var_os(environment_name) {
        let path = PathBuf::from(configured);
        if path.is_file() {
            return Ok(path);
        }
    }
    let executable_dir = std::env::current_exe()?
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| DownloadError::Validation("executable has no parent".to_owned()))?;
    for candidate in [
        executable_dir.join("ClamAV").join(file_name),
        executable_dir.join(file_name),
    ] {
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err(DownloadError::Validation(format!(
        "the packaged ClamAV {file_name} runtime was not found"
    )))
}
