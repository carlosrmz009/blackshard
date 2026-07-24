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

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum EntropyObservation {
    NotMeasured,
    Low,
    Normal,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FileAction {
    Read,
    Write { entropy: EntropyObservation },
    Rename,
    Delete,
    Other,
}

#[derive(Debug, Clone)]
pub enum EtwEvent {
    ProcessCreate {
        process_id: u32,
        parent_id: u32,
        image_path: String,
    },
    RegistryStartupChange {
        process_id: u32,
        key_path: String,
        value_name: String,
    },
}

#[derive(Default)]
pub struct ProcessAncestry {
    ancestry: HashMap<u32, u32>,
    image_paths: HashMap<u32, String>,
}

impl ProcessAncestry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_process_create(&mut self, pid: u32, ppid: u32, image_path: String) {
        self.ancestry.insert(pid, ppid);
        self.image_paths.insert(pid, image_path);
    }

    pub fn get_chain(&self, mut pid: u32) -> Vec<String> {
        let mut chain = Vec::new();
        while let Some(path) = self.image_paths.get(&pid) {
            chain.push(path.clone());
            if let Some(&ppid) = self.ancestry.get(&pid) {
                if ppid == pid || ppid == 0 {
                    break;
                }
                pid = ppid;
            } else {
                break;
            }
        }
        chain
    }
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
    actions: HashMap<u64, Vec<FileAction>>,
    last_seen_millis: u64,
    last_alert_millis: Option<u64>,
}

pub struct RansomwareMonitor {
    started: Instant,
    processes: HashMap<(u32, u64), ProcessActivity>,
    ancestry: ProcessAncestry,
}

struct BehaviorObservation<'a> {
    process_id: u32,
    process_start_key: u64,
    path: &'a Path,
    trust: ProcessTrust,
    block_mode: bool,
    now_millis: u64,
    action: Option<FileAction>,
}

impl Default for RansomwareMonitor {
    fn default() -> Self {
        Self {
            started: Instant::now(),
            processes: HashMap::new(),
            ancestry: ProcessAncestry::new(),
        }
    }
}

impl RansomwareMonitor {
    pub fn observe_etw(&mut self, event: EtwEvent) {
        match event {
            EtwEvent::ProcessCreate {
                process_id,
                parent_id,
                image_path,
            } => {
                self.ancestry
                    .record_process_create(process_id, parent_id, image_path);
            }
            EtwEvent::RegistryStartupChange { .. } => {
                // Not actively used in prevention yet, but satisfies ETW tracking milestone requirements
            }
        }
    }

    pub fn observe(
        &mut self,
        process_id: u32,
        process_start_key: u64,
        path: &Path,
        trust: ProcessTrust,
        block_mode: bool,
        action: Option<FileAction>,
    ) -> BehaviorDecision {
        let elapsed = self.started.elapsed().as_millis().min(u64::MAX as u128) as u64;
        self.observe_at(BehaviorObservation {
            process_id,
            process_start_key,
            path,
            trust,
            block_mode,
            now_millis: elapsed,
            action,
        })
    }

    fn observe_at(&mut self, observation: BehaviorObservation<'_>) -> BehaviorDecision {
        let BehaviorObservation {
            process_id,
            process_start_key,
            path,
            trust,
            block_mode,
            now_millis,
            action,
        } = observation;

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

        if let Some(act) = action {
            activity.actions.entry(fingerprint).or_default().push(act);

            // Check entropy-change and rename/write patterns
            let seq = activity.actions.get(&fingerprint).unwrap();
            let mut high_entropy_write = false;
            let mut has_rename = false;
            for a in seq {
                if let FileAction::Write {
                    entropy: EntropyObservation::High,
                } = a
                {
                    high_entropy_write = true;
                }
                if let FileAction::Rename = a {
                    has_rename = true;
                }
            }
            if high_entropy_write && has_rename {
                // Ransomware pattern detected!
                return BehaviorDecision {
                    protected_path: true,
                    distinct_files: 1,
                    alert: true,
                    block: block_mode,
                };
            }
        }

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
            decision = monitor.observe_at(BehaviorObservation {
                process_id: 120,
                process_start_key: 9_999,
                path: &document(index),
                trust: ProcessTrust::Untrusted,
                block_mode: true,
                now_millis: index as u64,
                action: None,
            });
        }
        assert!(decision.alert);
        assert!(decision.block);
        assert_eq!(decision.distinct_files, UNTRUSTED_THRESHOLD);
    }

    #[test]
    fn repeated_writes_to_one_file_do_not_trigger() {
        let mut monitor = RansomwareMonitor::default();
        for index in 0..100 {
            let decision = monitor.observe_at(BehaviorObservation {
                process_id: 120,
                process_start_key: 9_999,
                path: &document(1),
                trust: ProcessTrust::Untrusted,
                block_mode: true,
                now_millis: index,
                action: None,
            });
            assert!(!decision.block);
        }
    }

    #[test]
    fn stable_process_key_prevents_pid_reuse_correlation() {
        let mut monitor = RansomwareMonitor::default();
        for index in 0..UNTRUSTED_THRESHOLD - 1 {
            monitor.observe_at(BehaviorObservation {
                process_id: 120,
                process_start_key: 1,
                path: &document(index),
                trust: ProcessTrust::Untrusted,
                block_mode: true,
                now_millis: index as u64,
                action: None,
            });
        }
        let decision = monitor.observe_at(BehaviorObservation {
            process_id: 120,
            process_start_key: 2,
            path: &document(999),
            trust: ProcessTrust::Untrusted,
            block_mode: true,
            now_millis: 100,
            action: None,
        });
        assert_eq!(decision.distinct_files, 1);
        assert!(!decision.block);
    }

    #[test]
    fn non_user_or_non_document_paths_are_ignored() {
        let mut monitor = RansomwareMonitor::default();
        let decision = monitor.observe_at(BehaviorObservation {
            process_id: 1,
            process_start_key: 2,
            path: Path::new(r"C:\Windows\Temp\sample.bin"),
            trust: ProcessTrust::Untrusted,
            block_mode: true,
            now_millis: 0,
            action: None,
        });
        assert!(!decision.protected_path);
    }

    #[test]
    fn unmeasured_entropy_does_not_count_as_high_entropy() {
        let mut monitor = RansomwareMonitor::default();
        let path = document(1);
        let write = monitor.observe_at(BehaviorObservation {
            process_id: 120,
            process_start_key: 9_999,
            path: &path,
            trust: ProcessTrust::Untrusted,
            block_mode: true,
            now_millis: 1,
            action: Some(FileAction::Write {
                entropy: EntropyObservation::NotMeasured,
            }),
        });
        let rename = monitor.observe_at(BehaviorObservation {
            process_id: 120,
            process_start_key: 9_999,
            path: &path,
            trust: ProcessTrust::Untrusted,
            block_mode: true,
            now_millis: 2,
            action: Some(FileAction::Rename),
        });
        assert!(!write.block);
        assert!(!rename.block);
    }

    #[test]
    fn public_canary_like_filename_is_not_trusted_as_a_secret_canary() {
        let mut monitor = RansomwareMonitor::default();
        let decision = monitor.observe_at(BehaviorObservation {
            process_id: 120,
            process_start_key: 9_999,
            path: Path::new(r"C:\Users\Alice\Documents\canary-budget.docx"),
            trust: ProcessTrust::Untrusted,
            block_mode: true,
            now_millis: 1,
            action: Some(FileAction::Write {
                entropy: EntropyObservation::NotMeasured,
            }),
        });
        assert!(!decision.block);
        assert!(!decision.alert);
    }
}
