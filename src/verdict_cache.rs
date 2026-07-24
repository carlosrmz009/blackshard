use chrono::{DateTime, Utc};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, RwLock};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CacheVerdict {
    Clean,
    Malicious,
    Suspicious,
    ScanError,
}

pub use crate::engine::AnalysisCompleteness;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VerdictCacheKey {
    pub volume_serial: u64,
    pub file_id: u64,
    pub file_size: u64,
    pub content_generation: u64,
}

#[derive(Debug, Clone)]
pub struct CachedVerdict {
    pub verdict: CacheVerdict,
    pub risk_score: u32,
    pub confidence: u8,
    pub threat_name: Option<String>,
    pub sha256: Option<String>,
    pub file_size: u64,
    pub bytes_scanned: usize,
    pub truncated: bool,
    pub definition_generation: u64,
    pub freshclam_generation: u64,
    pub rule_generation: u64,
    pub model_generation: u64,
    pub scanned_at: DateTime<Utc>,
    pub analysis_completeness: AnalysisCompleteness,
    pub automatic_quarantine_eligible: bool,
    pub execution_block_eligible: bool,
    pub clamav_verdict: Option<crate::clamav_worker::protocol::ScanVerdict>,
}

impl CachedVerdict {
    /// Errors are never stable cache entries. A clean result is authoritative
    /// only when every byte was analyzed and a complete-file hash exists.
    pub fn is_cacheable(&self) -> bool {
        if self.verdict == CacheVerdict::ScanError {
            return false;
        }
        if self.verdict == CacheVerdict::Clean {
            return self.analysis_completeness == AnalysisCompleteness::Complete
                && !self.truncated
                && self.sha256.is_some()
                && matches!(
                    self.clamav_verdict,
                    Some(crate::clamav_worker::protocol::ScanVerdict::Clean { .. })
                );
        }
        true
    }
}

pub struct VerdictCache {
    capacity: usize,
    entries: HashMap<VerdictCacheKey, CachedVerdict>,
    lru: VecDeque<VerdictCacheKey>,
}

impl VerdictCache {
    pub fn new(capacity: usize) -> Arc<RwLock<Self>> {
        Arc::new(RwLock::new(Self {
            capacity,
            entries: HashMap::with_capacity(capacity),
            lru: VecDeque::with_capacity(capacity),
        }))
    }

    pub fn get(
        &mut self,
        key: &VerdictCacheKey,
        current_definition_generation: u64,
    ) -> Option<CachedVerdict> {
        if let Some(cached) = self.entries.get(key) {
            let age = Utc::now().signed_duration_since(cached.scanned_at);
            if age.num_hours() < 24
                && cached.definition_generation == current_definition_generation
                && cached.freshclam_generation == current_definition_generation
                && cached.rule_generation == current_definition_generation
                && cached.model_generation == current_definition_generation
            {
                // Update LRU position
                if let Some(pos) = self.lru.iter().position(|k| k == key) {
                    let k = self.lru.remove(pos).unwrap();
                    self.lru.push_back(k);
                }
                return Some(cached.clone());
            } else {
                // Invalidate
                self.entries.remove(key);
                if let Some(pos) = self.lru.iter().position(|k| k == key) {
                    self.lru.remove(pos);
                }
            }
        }
        None
    }

    pub fn insert(&mut self, key: VerdictCacheKey, verdict: CachedVerdict) -> bool {
        if !verdict.is_cacheable() {
            return false;
        }
        if self.entries.contains_key(&key) {
            if let Some(pos) = self.lru.iter().position(|k| k == &key) {
                self.lru.remove(pos);
            }
        } else if self.entries.len() >= self.capacity {
            if let Some(oldest) = self.lru.pop_front() {
                self.entries.remove(&oldest);
            }
        }
        self.lru.push_back(key.clone());
        self.entries.insert(key, verdict);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn clean(completeness: AnalysisCompleteness, truncated: bool) -> CachedVerdict {
        CachedVerdict {
            verdict: CacheVerdict::Clean,
            risk_score: 0,
            confidence: 90,
            threat_name: None,
            sha256: (!truncated).then(|| "00".repeat(32)),
            file_size: 1,
            bytes_scanned: 1,
            truncated,
            definition_generation: 1,
            freshclam_generation: 1,
            rule_generation: 1,
            model_generation: 1,
            scanned_at: Utc::now(),
            analysis_completeness: completeness,
            automatic_quarantine_eligible: false,
            execution_block_eligible: false,
            clamav_verdict: Some(crate::clamav_worker::protocol::ScanVerdict::Clean {
                engine_version: "test".to_owned(),
                database_version: "1".to_owned(),
            }),
        }
    }

    #[test]
    fn rejects_partial_clean_and_scan_errors() {
        let cache = VerdictCache::new(4);
        let key = VerdictCacheKey {
            volume_serial: 1,
            file_id: 2,
            file_size: 3,
            content_generation: 4,
        };
        let mut cache = cache.write().unwrap();
        assert!(!cache.insert(key.clone(), clean(AnalysisCompleteness::PrefixOnly, true)));

        let mut error = clean(AnalysisCompleteness::ResourceLimitReached, false);
        error.verdict = CacheVerdict::ScanError;
        error.sha256 = None;
        assert!(!cache.insert(key.clone(), error));
        assert!(cache.get(&key, 1).is_none());
    }

    #[test]
    fn accepts_complete_hashed_clean() {
        let cache = VerdictCache::new(4);
        let key = VerdictCacheKey {
            volume_serial: 1,
            file_id: 2,
            file_size: 3,
            content_generation: 4,
        };
        let mut cache = cache.write().unwrap();
        assert!(cache.insert(key.clone(), clean(AnalysisCompleteness::Complete, false)));
        assert!(cache.get(&key, 1).is_some());
    }
}
