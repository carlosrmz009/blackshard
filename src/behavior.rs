//! Low-overhead correlation of file-modification behavior by stable process
//! identity. This layer consumes bounded minifilter telemetry; it never
//! samples write buffers or uploads filenames.

use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::{Hash, Hasher};
use std::path::Path;
use std::time::Instant;

const WINDOW_MILLIS: u64 = 10_000;
const ALERT_COOLDOWN_MILLIS: u64 = 10_000;
const UNTRUSTED_THRESHOLD: usize = 24;
const UNKNOWN_THRESHOLD: usize = 32;
const TRUSTED_THRESHOLD: usize = 80;
const MAX_TRACKED_PROCESSES: usize = 256;
const MAX_EVENTS_PER_PROCESS: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessTrust {
    Trusted,
    Unknown,
    Untrusted,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BehaviorDecision {
    pub protected_path: bool,
    pub distinct_files: usize,
    pub alert: bool,
    pub block: bool,
}

#[derive(Default)]
struct ProcessActivity {
    events: VecDeque<(u64, u64)>,
    last_seen_millis: u64,
    last_alert_millis: Option<u64>,
}

pub struct RansomwareMonitor {
    started: Instant,
    processes: HashMap<(u32, u64), ProcessActivity>,
}

impl Default for RansomwareMonitor {
    fn default() -> Self {
        Self {
            started: Instant::now(),
            processes: HashMap::new(),
        }
    }
}

impl RansomwareMonitor {
    pub fn observe(
        &mut self,
        process_id: u32,
        process_start_key: u64,
        path: &Path,
        trust: ProcessTrust,
        block_mode: bool,
    ) -> BehaviorDecision {
        let elapsed = self.started.elapsed().as_millis().min(u64::MAX as u128) as u64;
        self.observe_at(
            process_id,
            process_start_key,
            path,
            trust,
            block_mode,
            elapsed,
        )
    }

    fn observe_at(
        &mut self,
        process_id: u32,
        process_start_key: u64,
        path: &Path,
        trust: ProcessTrust,
        block_mode: bool,
        now_millis: u64,
    ) -> BehaviorDecision {
        if !is_protected_document(path) || process_id == 0 || process_start_key == 0 {
            return BehaviorDecision::default();
        }
        self.evict_stale(now_millis);
        if self.processes.len() >= MAX_TRACKED_PROCESSES
            && !self
                .processes
                .contains_key(&(process_id, process_start_key))
        {
            if let Some(oldest) = self
                .processes
                .iter()
                .min_by_key(|(_, activity)| activity.last_seen_millis)
                .map(|(key, _)| *key)
            {
                self.processes.remove(&oldest);
            }
        }

        let activity = self
            .processes
            .entry((process_id, process_start_key))
            .or_default();
        activity.last_seen_millis = now_millis;
        while activity
            .events
            .front()
            .is_some_and(|(timestamp, _)| now_millis.saturating_sub(*timestamp) > WINDOW_MILLIS)
        {
            activity.events.pop_front();
        }
        let fingerprint = path_fingerprint(path);
        if !activity
            .events
            .iter()
            .any(|(_, existing)| *existing == fingerprint)
        {
            activity.events.push_back((now_millis, fingerprint));
            while activity.events.len() > MAX_EVENTS_PER_PROCESS {
                activity.events.pop_front();
            }
        }
        let distinct_files = activity
            .events
            .iter()
            .map(|(_, fingerprint)| *fingerprint)
            .collect::<HashSet<_>>()
            .len();
        let threshold = match trust {
            ProcessTrust::Trusted => TRUSTED_THRESHOLD,
            ProcessTrust::Unknown => UNKNOWN_THRESHOLD,
            ProcessTrust::Untrusted => UNTRUSTED_THRESHOLD,
        };
        let threshold_reached = distinct_files >= threshold;
        let alert = threshold_reached
            && activity
                .last_alert_millis
                .is_none_or(|last| now_millis.saturating_sub(last) >= ALERT_COOLDOWN_MILLIS);
        if alert {
            activity.last_alert_millis = Some(now_millis);
        }
        BehaviorDecision {
            protected_path: true,
            distinct_files,
            alert,
            block: threshold_reached && block_mode,
        }
    }

    fn evict_stale(&mut self, now_millis: u64) {
        self.processes.retain(|_, activity| {
            now_millis.saturating_sub(activity.last_seen_millis) <= WINDOW_MILLIS * 6
        });
    }
}

fn is_protected_document(path: &Path) -> bool {
    let normalized = path
        .to_string_lossy()
        .replace('/', "\\")
        .to_ascii_lowercase();
    let protected_folder = [
        "\\desktop\\",
        "\\documents\\",
        "\\pictures\\",
        "\\music\\",
        "\\videos\\",
        "\\favorites\\",
        "\\onedrive\\",
        "\\onedrive - ",
    ]
    .iter()
    .any(|component| normalized.contains(component));
    if !normalized.contains("\\users\\") || !protected_folder {
        return false;
    }
    let extension = normalized.rsplit_once('.').map(|(_, extension)| extension);
    matches!(
        extension,
        Some(
            "doc"
                | "docx"
                | "docm"
                | "xls"
                | "xlsx"
                | "xlsm"
                | "ppt"
                | "pptx"
                | "pptm"
                | "pdf"
                | "txt"
                | "rtf"
                | "csv"
                | "jpg"
                | "jpeg"
                | "png"
                | "gif"
                | "bmp"
                | "svg"
                | "mp3"
                | "wav"
                | "mp4"
                | "mov"
                | "avi"
                | "zip"
                | "7z"
                | "rar"
                | "sql"
                | "db"
                | "sqlite"
                | "psd"
                | "ai"
        )
    )
}

fn path_fingerprint(path: &Path) -> u64 {
    let normalized = path.to_string_lossy().to_ascii_lowercase();
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    normalized.hash(&mut hasher);
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn document(index: usize) -> std::path::PathBuf {
        format!(r"\Device\HarddiskVolume3\Users\Alice\Documents\file-{index}.docx").into()
    }

    #[test]
    fn distinct_mass_modification_alerts_and_can_block() {
        let mut monitor = RansomwareMonitor::default();
        let mut decision = BehaviorDecision::default();
        for index in 0..UNTRUSTED_THRESHOLD {
            decision = monitor.observe_at(
                120,
                9_999,
                &document(index),
                ProcessTrust::Untrusted,
                true,
                index as u64,
            );
        }
        assert!(decision.alert);
        assert!(decision.block);
        assert_eq!(decision.distinct_files, UNTRUSTED_THRESHOLD);
    }

    #[test]
    fn repeated_writes_to_one_file_do_not_trigger() {
        let mut monitor = RansomwareMonitor::default();
        for index in 0..100 {
            let decision = monitor.observe_at(
                120,
                9_999,
                &document(1),
                ProcessTrust::Untrusted,
                true,
                index,
            );
            assert!(!decision.block);
        }
    }

    #[test]
    fn stable_process_key_prevents_pid_reuse_correlation() {
        let mut monitor = RansomwareMonitor::default();
        for index in 0..UNTRUSTED_THRESHOLD - 1 {
            monitor.observe_at(
                120,
                1,
                &document(index),
                ProcessTrust::Untrusted,
                true,
                index as u64,
            );
        }
        let decision =
            monitor.observe_at(120, 2, &document(999), ProcessTrust::Untrusted, true, 100);
        assert_eq!(decision.distinct_files, 1);
        assert!(!decision.block);
    }

    #[test]
    fn non_user_or_non_document_paths_are_ignored() {
        let mut monitor = RansomwareMonitor::default();
        let decision = monitor.observe_at(
            1,
            2,
            Path::new(r"C:\Windows\Temp\sample.bin"),
            ProcessTrust::Untrusted,
            true,
            0,
        );
        assert!(!decision.protected_path);
    }
}
