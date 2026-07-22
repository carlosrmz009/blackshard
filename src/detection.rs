use crate::amsi::{AmsiScanReport, AmsiScanner};
use crate::archive::{inspect_gzip, inspect_ole, inspect_zip, ContainerInspection};
use crate::definitions::{DefinitionMatchRateCircuitBreaker, DefinitionMatchRateState};
use crate::engine::{ContentType, ScanEngine, ScanReport, Verdict as StaticVerdict};
use crate::rules::{RuleDisposition, RuleEngine, RuleMatch};
use crate::similarity::{SimilarityEngine, SimilarityMatch};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};
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
    /// Authenticated family-similarity results. These are advisory and require
    /// corroboration; they never authorize blocking or quarantine alone.
    pub similarity_matches: Vec<SimilarityMatch>,
    /// Bounded findings from ZIP/OOXML contents. Entries are scanned in memory
    /// and are never extracted to the filesystem.
    pub container_inspection: Option<ContainerInspection>,
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
    /// True for a trusted exact signature or a Windows AMSI provider/policy
    /// detection. Publisher-defined YARA classifications remain alert-only
    /// until independently corroborated. Unlike quarantine, an execution deny
    /// is reversible and does not mutate the candidate.
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
            similarity_matches: Vec::new(),
            container_inspection: None,
            amsi_report: None,
            amsi_error: None,
            elapsed,
            from_cache: false,
            error: Some(message.into()),
            automatic_quarantine_eligible: false,
            execution_block_eligible: false,
        }
    }

    pub(crate) fn ransomware_behavior(
        _distinct_files: usize,
        block: bool,
        elapsed: Duration,
    ) -> Self {
        Self {
            verdict: DetectionVerdict::Suspicious,
            risk_score: 95,
            confidence: 90,
            threat_name: Some("Behavior.Ransomware.MassModification".to_owned()),
            sha256: None,
            file_size: 0,
            bytes_scanned: 0,
            truncated: false,
            static_report: None,
            rule_matches: Vec::new(),
            similarity_matches: Vec::new(),
            container_inspection: None,
            amsi_report: None,
            amsi_error: None,
            elapsed,
            from_cache: false,
            error: None,
            automatic_quarantine_eligible: false,
            execution_block_eligible: block,
        }
    }
}

pub struct DetectionEngine {
    static_engine: ScanEngine,
    rules: RuleEngine,
    similarity: SimilarityEngine,
    amsi: Option<Arc<AmsiScanner>>,
    amsi_initialization_error: Option<String>,
    external_rule_circuit_breaker: Mutex<DefinitionMatchRateCircuitBreaker>,
    external_similarity_circuit_breaker: Mutex<DefinitionMatchRateCircuitBreaker>,
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
            similarity: SimilarityEngine::default(),
            amsi,
            amsi_initialization_error,
            external_rule_circuit_breaker: Mutex::new(DefinitionMatchRateCircuitBreaker::default()),
            external_similarity_circuit_breaker: Mutex::new(
                DefinitionMatchRateCircuitBreaker::default(),
            ),
        }
    }

    pub fn with_similarity(mut self, similarity: SimilarityEngine) -> Self {
        self.similarity = similarity;
        self
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
            Ok(matches) => self.apply_external_rule_circuit_breaker(matches),
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
                    similarity_matches: Vec::new(),
                    container_inspection: None,
                    amsi_report: None,
                    amsi_error: None,
                    elapsed: started.elapsed(),
                    from_cache: false,
                    error: Some(error),
                    automatic_quarantine_eligible: false,
                    execution_block_eligible: false,
                }
            }
        };
        let similarity_matches =
            self.apply_similarity_circuit_breaker(self.similarity.scan(&sample, declared_size));
        let (amsi_report, amsi_error) = self.scan_with_amsi(&static_report, &rule_matches, &sample);

        let report = combine(
            static_report,
            rule_matches,
            similarity_matches,
            amsi_report,
            amsi_error,
            started.elapsed(),
        );
        self.with_container_inspection(&sample, report, started)
    }

    pub fn scan_bytes(&self, bytes: &[u8]) -> DetectionReport {
        let started = Instant::now();
        let report = self.scan_leaf_bytes(bytes);
        self.with_container_inspection(bytes, report, started)
    }

    /// Scans one already-expanded object without recursively opening it as a
    /// container. The archive walker owns the single recursion/resource budget.
    pub(crate) fn scan_leaf_bytes(&self, bytes: &[u8]) -> DetectionReport {
        let started = Instant::now();
        let static_report = self.static_engine.scan_bytes(bytes);
        match self.rules.scan(bytes) {
            Ok(rule_matches) => {
                let rule_matches = self.apply_external_rule_circuit_breaker(rule_matches);
                let similarity_matches = self.apply_similarity_circuit_breaker(
                    self.similarity.scan(bytes, bytes.len() as u64),
                );
                let (amsi_report, amsi_error) =
                    self.scan_with_amsi(&static_report, &rule_matches, bytes);
                combine(
                    static_report,
                    rule_matches,
                    similarity_matches,
                    amsi_report,
                    amsi_error,
                    started.elapsed(),
                )
            }
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
                similarity_matches: Vec::new(),
                container_inspection: None,
                amsi_report: None,
                amsi_error: None,
                elapsed: started.elapsed(),
                from_cache: false,
                error: Some(error),
                automatic_quarantine_eligible: false,
                execution_block_eligible: false,
            },
        }
    }

    fn with_container_inspection(
        &self,
        bytes: &[u8],
        mut report: DetectionReport,
        started: Instant,
    ) -> DetectionReport {
        let content_type = report
            .static_report
            .as_ref()
            .map(|static_report| static_report.content_type);
        if report.truncated
            || !matches!(
                content_type,
                Some(ContentType::Zip | ContentType::Gzip | ContentType::OleCompound)
            )
        {
            report.elapsed = started.elapsed();
            return report;
        }

        let inspection = match content_type {
            Some(ContentType::Zip) => inspect_zip(bytes, |entry| self.scan_leaf_bytes(entry)),
            Some(ContentType::OleCompound) => {
                inspect_ole(bytes, |entry| self.scan_leaf_bytes(entry))
            }
            Some(ContentType::Gzip) => inspect_gzip(bytes, |entry| self.scan_leaf_bytes(entry)),
            _ => unreachable!("container type was checked above"),
        };
        let strongest = inspection
            .findings
            .iter()
            .max_by_key(|finding| (finding.verdict_rank(), finding.risk_score));
        if let Some(finding) = strongest {
            match finding.verdict {
                DetectionVerdict::Malicious => {
                    report.verdict = DetectionVerdict::Malicious;
                    report.risk_score = report.risk_score.max(finding.risk_score);
                    report.confidence = report.confidence.max(95);
                }
                DetectionVerdict::Suspicious if report.verdict == DetectionVerdict::Clean => {
                    report.verdict = DetectionVerdict::Suspicious;
                    report.risk_score = report.risk_score.max(finding.risk_score);
                    report.confidence = report.confidence.max(80);
                }
                DetectionVerdict::Error
                | DetectionVerdict::Clean
                | DetectionVerdict::Suspicious => {}
            }
            if report.threat_name.is_none() || finding.verdict == DetectionVerdict::Malicious {
                let nested_name = finding
                    .threat_name
                    .as_deref()
                    .unwrap_or("Suspicious.EmbeddedObject");
                report.threat_name = Some(format!("Container.Contains.{nested_name}"));
            }
            report.automatic_quarantine_eligible |= finding.automatic_quarantine_eligible
                && report.sha256.is_some()
                && !report.truncated;
            report.execution_block_eligible |=
                finding.execution_block_eligible || report.automatic_quarantine_eligible;
        }

        let structural_risk = inspection.structural_risk_score();
        if structural_risk >= 55 && report.verdict == DetectionVerdict::Clean {
            report.verdict = DetectionVerdict::Suspicious;
            report.risk_score = structural_risk;
            report.confidence = 75;
            report.threat_name = Some(if inspection.limit_triggered {
                "Archive.ResourceLimitTriggered".to_owned()
            } else {
                "Office.MacroWithExternalContent".to_owned()
            });
        }
        report.container_inspection = Some(inspection);
        report.elapsed = started.elapsed();
        report
    }

    fn scan_with_amsi(
        &self,
        static_report: &ScanReport,
        rule_matches: &[RuleMatch],
        sample: &[u8],
    ) -> (Option<AmsiScanReport>, Option<String>) {
        let eligible = matches!(
            static_report.content_type,
            ContentType::Script(_) | ContentType::OleCompound
        ) || !rule_matches.is_empty();
        if !eligible {
            return (None, None);
        }
        let Some(scanner) = &self.amsi else {
            return (None, self.amsi_initialization_error.clone());
        };
        match scanner.scan_buffer(sample, "Blackshard.FileContent") {
            Ok(report) => (Some(report), None),
            Err(error) => (None, Some(error.to_string())),
        }
    }

    pub fn clear_cache(&self) {
        // Intentionally a no-op. Metadata-only clean-result caching can be
        // bypassed by restoring timestamps. A future cache must be keyed by a
        // stable file ID plus a mutation journal/version, not a pathname.
    }

    pub fn external_rules_tripped(&self) -> bool {
        let rules_tripped = self
            .external_rule_circuit_breaker
            .lock()
            .map(|breaker| breaker.is_tripped())
            .unwrap_or(true);
        let similarity_tripped = self
            .external_similarity_circuit_breaker
            .lock()
            .map(|breaker| breaker.is_tripped())
            .unwrap_or(true);
        rules_tripped || similarity_tripped
    }

    fn apply_external_rule_circuit_breaker(&self, mut matches: Vec<RuleMatch>) -> Vec<RuleMatch> {
        let external_match = matches
            .iter()
            .any(|matched| matched.namespace != "blackshard_builtin");
        let tripped = self
            .external_rule_circuit_breaker
            .lock()
            .map(|mut breaker| {
                matches!(
                    breaker.observe_external_match(external_match),
                    DefinitionMatchRateState::Tripped { .. }
                )
            })
            .unwrap_or(true);
        if tripped {
            matches.retain(|matched| matched.namespace == "blackshard_builtin");
        }
        matches
    }

    fn apply_similarity_circuit_breaker(
        &self,
        mut matches: Vec<SimilarityMatch>,
    ) -> Vec<SimilarityMatch> {
        let external_match = !matches.is_empty();
        let tripped = self
            .external_similarity_circuit_breaker
            .lock()
            .map(|mut breaker| {
                matches!(
                    breaker.observe_external_match(external_match),
                    DefinitionMatchRateState::Tripped { .. }
                )
            })
            .unwrap_or(true);
        if tripped {
            matches.clear();
        }
        matches
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
    Ok(opened_file_identity(file)?.file_id)
}

#[cfg(windows)]
#[derive(Debug, Clone, Copy)]
pub(crate) struct OpenedFileIdentity {
    pub file_id: u64,
    pub volume_serial_number: u32,
    pub link_count: u32,
}

#[cfg(windows)]
pub(crate) fn opened_file_identity(file: &File) -> io::Result<OpenedFileIdentity> {
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
    Ok(OpenedFileIdentity {
        file_id: ((information.file_index_high as u64) << 32) | information.file_index_low as u64,
        volume_serial_number: information.volume_serial_number,
        link_count: information.number_of_links,
    })
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
    similarity_matches: Vec<SimilarityMatch>,
    amsi_report: Option<AmsiScanReport>,
    amsi_error: Option<String>,
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
    let similarity_score = similarity_matches
        .iter()
        .map(|matched| {
            82u8.saturating_add(
                ((matched.similarity_basis_points.saturating_sub(8_500)) / 125) as u8,
            )
            .min(94)
        })
        .max()
        .unwrap_or(0);

    let amsi_provider_detection = amsi_report
        .as_ref()
        .is_some_and(AmsiScanReport::is_provider_detection);
    let amsi_policy_block = amsi_report
        .as_ref()
        .is_some_and(AmsiScanReport::should_block_execution);

    let (verdict, risk_score, confidence, threat_name) = if static_report.verdict
        == StaticVerdict::Malicious
    {
        (
            DetectionVerdict::Malicious,
            100,
            static_report.confidence.max(99),
            Some("Known.Malware.ExactSignature".to_owned()),
        )
    } else if amsi_provider_detection {
        (
            DetectionVerdict::Malicious,
            99,
            99,
            Some("AMSI.Provider.MalwareDetected".to_owned()),
        )
    } else if let Some(rule) = malicious_rule {
        (
            DetectionVerdict::Malicious,
            rule.risk_score.max(95),
            99,
            Some(rule.threat_name.clone()),
        )
    } else if amsi_policy_block {
        (
            DetectionVerdict::Suspicious,
            90,
            99,
            Some("AMSI.Policy.BlockedByAdministrator".to_owned()),
        )
    } else if static_report.verdict == StaticVerdict::Error {
        (DetectionVerdict::Error, 0, 0, None)
    } else if static_report.verdict == StaticVerdict::Suspicious
        || suspicious_rule_score > 0
        || similarity_score > 0
    {
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
                .max(similarity_score)
                .saturating_add(independent_bonus)
                .min(99),
            static_report.confidence.max(75),
            rule_matches
                .iter()
                .filter(|item| item.disposition == RuleDisposition::Suspicious)
                .max_by_key(|item| item.risk_score)
                .map(|item| item.threat_name.clone())
                .or_else(|| {
                    similarity_matches
                        .first()
                        .map(|matched| matched.threat_name.clone())
                })
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
        similarity_matches,
        container_inspection: None,
        amsi_report,
        amsi_error,
        elapsed,
        from_cache: false,
        automatic_quarantine_eligible,
        execution_block_eligible: automatic_quarantine_eligible || amsi_policy_block,
    }
}

fn shared_system_amsi() -> Result<Arc<AmsiScanner>, String> {
    static SHARED: OnceLock<Result<Arc<AmsiScanner>, String>> = OnceLock::new();
    SHARED
        .get_or_init(|| {
            AmsiScanner::new("Blackshard")
                .map(Arc::new)
                .map_err(|e| e.to_string())
        })
        .clone()
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

    #[test]
    fn amsi_provider_detection_blocks_but_never_authorizes_quarantine() {
        let static_report = ScanEngine::default().scan_bytes(b"ordinary script-like bytes");
        let report = combine(
            static_report,
            Vec::new(),
            Vec::new(),
            Some(AmsiScanReport::synthetic(0x8000, 26, false)),
            None,
            Duration::ZERO,
        );
        assert_eq!(report.verdict, DetectionVerdict::Malicious);
        assert!(report.should_block());
        assert!(!report.should_quarantine());
        assert!(!report.automatic_quarantine_eligible);
    }
}
