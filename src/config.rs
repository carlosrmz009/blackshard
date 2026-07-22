use crate::atomic_file;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub const SETTINGS_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    pub schema_version: u32,
    pub real_time_protection: bool,
    /// Collect and correlate bounded modification telemetry for protected user data.
    pub ransomware_protection: bool,
    /// Audit is the safe default until a machine's legitimate workload has
    /// been observed. Block mode denies modifications after the behavior threshold.
    pub ransomware_block_mode: bool,
    pub automatic_quarantine: bool,
    pub notify_on_detection: bool,
    pub scan_archives: bool,
    pub scan_network_drives: bool,
    pub low_resource_mode: bool,
    pub max_file_size_mb: u64,
    pub worker_count: usize,
    pub definition_update_interval_hours: u64,
    pub exclusions: Vec<PathBuf>,
}

impl Default for Settings {
    fn default() -> Self {
        let logical_cpus = std::thread::available_parallelism()
            .map(usize::from)
            .unwrap_or(2);
        Self {
            schema_version: SETTINGS_SCHEMA_VERSION,
            real_time_protection: true,
            ransomware_protection: true,
            ransomware_block_mode: false,
            automatic_quarantine: true,
            notify_on_detection: true,
            scan_archives: true,
            scan_network_drives: false,
            low_resource_mode: true,
            max_file_size_mb: 512,
            worker_count: logical_cpus.saturating_sub(1).clamp(1, 4),
            definition_update_interval_hours: 4,
            exclusions: Vec::new(),
        }
    }
}

impl Settings {
    pub fn load(path: &Path) -> io::Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let bytes = fs::read(path)?;
        let mut settings: Self = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
        settings.validate();
        Ok(settings)
    }

    pub fn save(&self, path: &Path) -> io::Result<()> {
        let mut validated = self.clone();
        validated.validate();
        let bytes = serde_json::to_vec_pretty(&validated).map_err(io::Error::other)?;
        atomic_file::write(path, &bytes)
    }

    pub fn default_machine_path() -> PathBuf {
        let base = std::env::var_os("PROGRAMDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
        base.join("Blackshard").join("settings.json")
    }

    pub fn is_excluded(&self, path: &Path) -> bool {
        let candidate = normalize_for_comparison(path);
        self.exclusions.iter().any(|exclusion| {
            let exclusion = normalize_for_comparison(exclusion);
            candidate == exclusion || candidate.starts_with(&exclusion)
        })
    }

    pub fn add_exclusion(&mut self, path: PathBuf) {
        let normalized = normalize_for_comparison(&path);
        if !self
            .exclusions
            .iter()
            .any(|item| normalize_for_comparison(item) == normalized)
        {
            self.exclusions.push(path);
        }
    }

    fn validate(&mut self) {
        self.schema_version = SETTINGS_SCHEMA_VERSION;
        self.max_file_size_mb = self.max_file_size_mb.clamp(1, 4_096);
        self.worker_count = self.worker_count.clamp(1, 16);
        self.definition_update_interval_hours = self.definition_update_interval_hours.clamp(1, 24);
        self.exclusions
            .sort_by_key(|path| normalize_for_comparison(path));
        self.exclusions.dedup_by(|left, right| {
            normalize_for_comparison(left) == normalize_for_comparison(right)
        });
    }
}

fn normalize_for_comparison(path: &Path) -> PathBuf {
    let absolute = canonicalize_with_missing_tail(path);
    #[cfg(windows)]
    {
        PathBuf::from(absolute.to_string_lossy().to_lowercase())
    }
    #[cfg(not(windows))]
    {
        absolute
    }
}

fn canonicalize_with_missing_tail(path: &Path) -> PathBuf {
    if let Ok(canonical) = fs::canonicalize(path) {
        return canonical;
    }

    let mut cursor = path;
    let mut missing = Vec::new();
    while !cursor.exists() {
        if let Some(name) = cursor.file_name() {
            missing.push(name.to_os_string());
        }
        let Some(parent) = cursor.parent() else {
            break;
        };
        cursor = parent;
    }

    let mut rebuilt = fs::canonicalize(cursor).unwrap_or_else(|_| {
        if path.is_absolute() {
            cursor.to_path_buf()
        } else {
            std::env::current_dir().unwrap_or_default().join(cursor)
        }
    });
    for component in missing.into_iter().rev() {
        rebuilt.push(component);
    }
    rebuilt
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_clamps_untrusted_values() {
        let mut settings = Settings {
            max_file_size_mb: u64::MAX,
            worker_count: 0,
            definition_update_interval_hours: 0,
            ..Settings::default()
        };
        settings.validate();
        assert_eq!(settings.max_file_size_mb, 4_096);
        assert_eq!(settings.worker_count, 1);
        assert_eq!(settings.definition_update_interval_hours, 1);
    }

    #[test]
    fn settings_round_trip_atomically() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("config").join("settings.json");
        let expected = Settings {
            real_time_protection: false,
            ..Settings::default()
        };
        expected.save(&path).unwrap();
        let actual = Settings::load(&path).unwrap();
        assert!(!actual.real_time_protection);
        assert_eq!(actual.schema_version, SETTINGS_SCHEMA_VERSION);
    }

    #[test]
    fn exclusions_are_path_component_aware() {
        let temporary = tempfile::tempdir().unwrap();
        let excluded = temporary.path().join("cache");
        fs::create_dir_all(&excluded).unwrap();
        let sibling = temporary.path().join("cache-not-excluded");
        fs::create_dir_all(&sibling).unwrap();
        let mut settings = Settings::default();
        settings.add_exclusion(excluded.clone());

        assert!(settings.is_excluded(&excluded.join("file.bin")));
        assert!(!settings.is_excluded(&sibling.join("file.bin")));
    }
}
