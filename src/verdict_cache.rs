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
    pub threat_name: Option<String>,
    pub definition_generation: u64,
    pub freshclam_generation: u64,
    pub rule_generation: u64,
    pub model_generation: u64,
    pub scanned_at: DateTime<Utc>,
    pub analysis_completeness: AnalysisCompleteness,
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
            if age.num_hours() < 24 && cached.definition_generation == current_definition_generation {
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

    pub fn insert(&mut self, key: VerdictCacheKey, verdict: CachedVerdict) {
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
    }
}
