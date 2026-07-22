use crate::amsi::{AmsiScanReport, AmsiScanner, AmsiVerdict};
use crate::engine::{ScanEngine, ScanReport, Verdict as StaticVerdict};
use crate::rules::{RuleDisposition, RuleEngine, RuleMatch};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectionVerdict {
    Clean,
    Suspicious,
    Malicious,
    Error,
}

#[derive(Debug, Clone)]
pub struct DetectionReport {
    pub verdict: DetectionVerdict,
    pub risk_score: u8,
    pub confidence: u8,
    pub threat_name: Option<String>,
    pub sha256: Option<String>,
    pub file_size: u64,
    pub bytes_scanned: usize,
    pub truncated: bool,
    pub static_report: Option<ScanReport>,
    pub rule_matches: Vec<RuleMatch>,
    /// Result returned by the locally registered Windows AMSI provider. This is
    /// kept separate from Blackshard's signatures and heuristics so callers can
    /// apply a non-destructive execution policy without authorizing quarantine.
    pub amsi_report: Option<AmsiScanReport>,
    /// An AMSI initialization/provider failure is diagnostic only. The primary
    /// engines continue to produce an independent verdict.
    pub amsi_error: Option<String>,
    pub elapsed: Duration,
    pub from_cache: bool,
    pub error: Option<String>,
    /// True only when a complete-file SHA-256 matched a trusted exact
    /// signature. YARA/heuristic matches can still report malicious or
    /// suspicious findings, but cannot trigger destructive automatic action.
    pub automatic_quarantine_eligible: bool,
    /// True for a trusted exact signature, an explicit malicious rule, or a
    /// Windows AMSI provider/policy detection. Unlike quarantine, an execution
    /// deny is reversible and does not mutate the candidate.
    pub execution_block_eligible: bool,
}

impl DetectionReport {
    pub fn should_quarantine(&self) -> bool {
        self.verdict == DetectionVerdict::Malicious && self.automatic_quarantine_eligible
    }

    pub fn should_block(&self) -> bool {
        self.execution_block_eligible
    }

    pub(crate) fn error(message: impl Into<String>, elapsed: Duration) -> Self {
        Self {
            verdict: DetectionVerdict::Error,
            risk_score: 0,
            confidence: 0,
            threat_name: None,
            sha256: None,
            file_size: 0,
            bytes_scanned: 0,
            truncated: false,
            static_report: None,
            rule_matches: Vec::new(),
            amsi_report: None,
            amsi_error: None,
            elapsed,
            from_cache: false,
            error: Some(message.into()),
            automatic_quarantine_eligible: false,
            execution_block_eligible: false,
        }
    }
}

pub struct DetectionEngine {
    static_engine: ScanEngine,
    rules: RuleEngine,
    amsi: Option<Arc<AmsiScanner>>,
    amsi_initialization_error: Option<String>,
}

impl DetectionEngine {
    pub fn new(static_engine: ScanEngine, rules: RuleEngine) -> Self {
        let (amsi, amsi_initialization_error) = match shared_system_amsi() {
            Ok(scanner) => (Some(scanner), None),
            Err(error) => (None, Some(error)),
        };
        Self {
            static_engine,
            rules,
            amsi,
            amsi_initialization_error,
        }
    }

    pub fn builtin() -> Result<Self, String> {
        Ok(Self::new(ScanEngine::default(), RuleEngine::builtin()?))
    }

    pub fn scan_path(&self, path: &Path) -> DetectionReport {
        let started = Instant::now();
        let symlink_metadata = match fs::symlink_metadata(path) {
            Ok(metadata) => metadata,
            Err(error) => {
                return DetectionReport::error(
                    format!("could not inspect {}: {error}", path.display()),
                    started.elapsed(),
                )
            }
        };
        if symlink_metadata.file_type().is_symlink() || !symlink_metadata.is_file() {
            return DetectionReport::error(
                format!("not a regular file: {}", path.display()),
                started.elapsed(),
            );
        }

        let file = match open_candidate_file(path) {
            Ok(file) => file,
            Err(error) => {
                return DetectionReport::error(
                    format!("could not open {}: {error}", path.display()),
                    started.elapsed(),
                )
            }
        };
        self.scan_open_file(&file)
    }

    /// Scans the exact already-open file object, bypassing all verdict caches.
    /// Real-time enforcement must use this entry point so a pathname swap cannot
    /// substitute a different object between open and analysis.
    pub fn scan_open_file(&self, file: &File) -> DetectionReport {
        let started = Instant::now();
        let before = match file.metadata() {
            Ok(metadata) if metadata.is_file() => metadata,
            Ok(_) => {
                return DetectionReport::error(
                    "the opened candidate is not a regular file",
                    started.elapsed(),
                )
            }
            Err(error) => {
                return DetectionReport::error(
                    format!("could not inspect the opened candidate: {error}"),
                    started.elapsed(),
                )
            }
        };
        let mut reader = match file.try_clone() {
            Ok(reader) => reader,
            Err(error) => {
                return DetectionReport::error(
                    format!("could not duplicate the candidate handle: {error}"),
                    started.elapsed(),
                )
            }
        };
        if let Err(error) = reader.seek(SeekFrom::Start(0)) {
            return DetectionReport::error(
                format!("could not seek the candidate handle: {error}"),
                started.elapsed(),
            );
        }
        let sample_limit = self.static_engine.config().max_read_bytes;
        let (sample, observed_extra) = match read_bounded(&mut reader, sample_limit) {
            Ok(result) => result,
            Err(error) => {
                return DetectionReport::error(
                    format!("could not read the candidate handle: {error}"),
                    started.elapsed(),
                )
            }
        };
        let after = match file.metadata() {
            Ok(metadata) => metadata,
            Err(error) => {
                return DetectionReport::error(
                    format!("could not revalidate the candidate handle: {error}"),
                    started.elapsed(),
                )
            }
        };
        if before.len() != after.len() || before.modified().ok() != after.modified().ok() {
            return DetectionReport::error(
                "the opened file changed while it was being analyzed",
                started.elapsed(),
            );
        }

        let declared_size = before
            .len()
            .max(sample.len() as u64 + u64::from(observed_extra));
        let static_report = self.static_engine.scan_sample(&sample, declared_size);
        let rule_matches = match self.rules.scan(&sample) {
            Ok(matches) => matches,
            Err(error) => {
                return DetectionReport {
                    verdict: DetectionVerdict::Error,
                    risk_score: static_report.risk_score,
                    confidence: 0,
                    threat_name: None,
                    sha256: static_report.sha256.clone(),
                    file_size: declared_size,
                    bytes_scanned: sample.len(),
                    truncated: static_report.truncated,
                    static_report: Some(static_report),
                    rule_matches: Vec::new(),
                    elapsed: started.elapsed(),
                    from_cache: false,
                    error: Some(error),
                    automatic_quarantine_eligible: false,
                }
            }
        };

        combine(static_report, rule_matches, started.elapsed())
    }

    pub fn scan_bytes(&self, bytes: &[u8]) -> DetectionReport {
        let started = Instant::now();
        let static_report = self.static_engine.scan_bytes(bytes);
        match self.rules.scan(bytes) {
            Ok(rule_matches) => combine(static_report, rule_matches, started.elapsed()),
            Err(error) => DetectionReport {
                verdict: DetectionVerdict::Error,
                risk_score: static_report.risk_score,
                confidence: 0,
                threat_name: None,
                sha256: static_report.sha256.clone(),
                file_size: bytes.len() as u64,
                bytes_scanned: bytes.len(),
                truncated: static_report.truncated,
                static_report: Some(static_report),
                rule_matches: Vec::new(),
                elapsed: started.elapsed(),
                from_cache: false,
                error: Some(error),
                automatic_quarantine_eligible: false,
            },
        }
    }

    pub fn clear_cache(&self) {
        // Intentionally a no-op. Metadata-only clean-result caching can be
        // bypassed by restoring timestamps. A future cache must be keyed by a
        // stable file ID plus a mutation journal/version, not a pathname.
    }
}

fn read_bounded(reader: &mut File, limit: usize) -> io::Result<(Vec<u8>, bool)> {
    let mut reader = reader.take(limit.saturating_add(1) as u64);
    let mut bytes = Vec::with_capacity(limit.min(1024 * 1024));
    reader.read_to_end(&mut bytes)?;
    let observed_extra = bytes.len() > limit;
    if observed_extra {
        bytes.truncate(limit);
    }
    Ok((bytes, observed_extra))
}

#[cfg(windows)]
pub(crate) fn open_candidate_file(path: &Path) -> io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;

    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_SHARE_WRITE: u32 = 0x0000_0002;
    const FILE_SHARE_DELETE: u32 = 0x0000_0004;
    const FILE_FLAG_SEQUENTIAL_SCAN: u32 = 0x0800_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

    OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_SEQUENTIAL_SCAN | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

#[cfg(not(windows))]
pub(crate) fn open_candidate_file(path: &Path) -> io::Result<File> {
    OpenOptions::new().read(true).open(path)
}

/// Returns the stable 64-bit file index for an already-open Windows file.
/// The index is unique within its volume for the lifetime of the file object.
#[cfg(windows)]
pub(crate) fn opened_file_id(file: &File) -> io::Result<u64> {
    use std::os::windows::io::AsRawHandle;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct FileTime {
        low_date_time: u32,
        high_date_time: u32,
    }

    #[repr(C)]
    struct ByHandleFileInformation {
        file_attributes: u32,
        creation_time: FileTime,
        last_access_time: FileTime,
        last_write_time: FileTime,
        volume_serial_number: u32,
        file_size_high: u32,
        file_size_low: u32,
        number_of_links: u32,
        file_index_high: u32,
        file_index_low: u32,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GetFileInformationByHandle(
            file: isize,
            information: *mut ByHandleFileInformation,
        ) -> i32;
    }

    let mut information = std::mem::MaybeUninit::<ByHandleFileInformation>::uninit();
    if unsafe {
        GetFileInformationByHandle(file.as_raw_handle() as isize, information.as_mut_ptr())
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let information = unsafe { information.assume_init() };
    Ok(((information.file_index_high as u64) << 32) | information.file_index_low as u64)
}

#[cfg(not(windows))]
pub(crate) fn opened_file_id(_file: &File) -> io::Result<u64> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "stable Windows file identity is unavailable on this platform",
    ))
}

fn combine(
    static_report: ScanReport,
    rule_matches: Vec<RuleMatch>,
    elapsed: Duration,
) -> DetectionReport {
    let automatic_quarantine_eligible = static_report.verdict == StaticVerdict::Malicious
        && !static_report.truncated
        && static_report.sha256.is_some()
        && static_report
            .evidence
            .iter()
            .any(|evidence| evidence.code == "signature.exact_sha256");
    let malicious_rule = rule_matches
        .iter()
        .filter(|item| item.disposition == RuleDisposition::Malicious)
        .max_by_key(|item| item.risk_score);
    let suspicious_rule_score = rule_matches
        .iter()
        .filter(|item| item.disposition == RuleDisposition::Suspicious)
        .map(|item| item.risk_score)
        .max()
        .unwrap_or(0);

    let (verdict, risk_score, confidence, threat_name) = if static_report.verdict
        == StaticVerdict::Malicious
    {
        (
            DetectionVerdict::Malicious,
            100,
            static_report.confidence.max(99),
            Some("Known.Malware.ExactSignature".to_owned()),
        )
    } else if let Some(rule) = malicious_rule {
        (
            DetectionVerdict::Malicious,
            rule.risk_score.max(95),
            99,
            Some(rule.threat_name.clone()),
        )
    } else if static_report.verdict == StaticVerdict::Error {
        (DetectionVerdict::Error, 0, 0, None)
    } else if static_report.verdict == StaticVerdict::Suspicious || suspicious_rule_score > 0 {
        let independent_bonus =
            if static_report.verdict == StaticVerdict::Suspicious && suspicious_rule_score > 0 {
                10
            } else {
                0
            };
        (
            DetectionVerdict::Suspicious,
            static_report
                .risk_score
                .max(suspicious_rule_score)
                .saturating_add(independent_bonus)
                .min(99),
            static_report.confidence.max(75),
            rule_matches
                .iter()
                .filter(|item| item.disposition == RuleDisposition::Suspicious)
                .max_by_key(|item| item.risk_score)
                .map(|item| item.threat_name.clone())
                .or_else(|| Some("Suspicious.StaticAnalysis".to_owned())),
        )
    } else {
        (
            DetectionVerdict::Clean,
            static_report.risk_score,
            static_report.confidence,
            None,
        )
    };

    DetectionReport {
        verdict,
        risk_score,
        confidence,
        threat_name,
        sha256: static_report.sha256.clone(),
        file_size: static_report.file_size,
        bytes_scanned: static_report.bytes_scanned,
        truncated: static_report.truncated,
        error: static_report.error.clone(),
        static_report: Some(static_report),
        rule_matches,
        elapsed,
        from_cache: false,
        automatic_quarantine_eligible,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eicar() -> Vec<u8> {
        [
            "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-",
            "ANTIVIRUS-TEST-FILE!$H+H*",
        ]
        .concat()
        .into_bytes()
    }

    #[test]
    fn eicar_is_malicious_and_quarantinable() {
        let engine = DetectionEngine::builtin().unwrap();
        let report = engine.scan_bytes(&eicar());
        assert_eq!(report.verdict, DetectionVerdict::Malicious);
        assert!(report.should_quarantine());
        assert!(report.automatic_quarantine_eligible);
        assert_eq!(report.risk_score, 100);
    }

    #[test]
    fn entropy_alone_remains_clean() {
        let engine = DetectionEngine::builtin().unwrap();
        let bytes = (0u8..=255).cycle().take(1024 * 1024).collect::<Vec<_>>();
        let report = engine.scan_bytes(&bytes);
        assert_eq!(report.verdict, DetectionVerdict::Clean);
        assert!(!report.should_quarantine());
    }

    #[test]
    fn path_scans_are_not_reused_from_a_metadata_only_cache() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("clean.txt");
        fs::write(&path, b"ordinary text document").unwrap();
        let engine = DetectionEngine::builtin().unwrap();
        let first = engine.scan_path(&path);
        let second = engine.scan_path(&path);
        assert_eq!(first.verdict, DetectionVerdict::Clean);
        assert!(!first.from_cache);
        assert!(!second.from_cache);
    }

    #[test]
    fn exact_open_handle_can_be_scanned_without_reopening_a_path() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("candidate.txt");
        fs::write(&path, b"ordinary text document").unwrap();
        let file = open_candidate_file(&path).unwrap();
        fs::rename(&path, temporary.path().join("renamed.txt")).unwrap();
        let report = DetectionEngine::builtin().unwrap().scan_open_file(&file);
        assert_eq!(report.verdict, DetectionVerdict::Clean);
    }
}
