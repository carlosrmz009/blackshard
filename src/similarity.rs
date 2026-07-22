//! Bounded locality-sensitive fingerprints for authenticated malware-family
//! profiles. Similarity is an advisory signal only: it can find close variants
//! cheaply, but never authorizes quarantine or execution blocking by itself.

use std::collections::BTreeSet;
use std::sync::Arc;

pub const SKETCH_SIZE: usize = 64;
pub const MIN_SKETCH_BYTES: usize = 4 * 1024;
const SHINGLE_BYTES: usize = 16;
const SHINGLE_STRIDE: usize = 4;
const MAX_VISIBLE_MATCHES: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimilarityProfile {
    pub identifier: String,
    pub threat_name: String,
    pub family: Option<String>,
    pub minimum_file_size: u64,
    pub maximum_file_size: u64,
    pub minimum_similarity_basis_points: u16,
    pub sketch: [u64; SKETCH_SIZE],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimilarityMatch {
    pub identifier: String,
    pub threat_name: String,
    pub family: Option<String>,
    pub similarity_basis_points: u16,
}

#[derive(Clone, Default)]
pub struct SimilarityEngine {
    profiles: Arc<Vec<SimilarityProfile>>,
}

impl SimilarityEngine {
    pub fn new(profiles: Vec<SimilarityProfile>) -> Result<Self, String> {
        for profile in &profiles {
            if profile.minimum_file_size < MIN_SKETCH_BYTES as u64
                || profile.maximum_file_size < profile.minimum_file_size
                || !(8_500..=10_000).contains(&profile.minimum_similarity_basis_points)
                || profile.sketch.windows(2).any(|pair| pair[0] >= pair[1])
            {
                return Err(format!(
                    "similarity profile {} has invalid bounds, threshold, or sketch ordering",
                    profile.identifier
                ));
            }
        }
        Ok(Self {
            profiles: Arc::new(profiles),
        })
    }

    pub fn scan(&self, bytes: &[u8], declared_size: u64) -> Vec<SimilarityMatch> {
        if self.profiles.is_empty() || bytes.len() < MIN_SKETCH_BYTES || !bytes.starts_with(b"MZ") {
            return Vec::new();
        }
        let candidates = self
            .profiles
            .iter()
            .filter(|profile| {
                declared_size >= profile.minimum_file_size
                    && declared_size <= profile.maximum_file_size
            })
            .collect::<Vec<_>>();
        if candidates.is_empty() {
            return Vec::new();
        }
        let Some(sketch) = compute_sketch(bytes) else {
            return Vec::new();
        };

        let mut matches = candidates
            .into_iter()
            .filter_map(|profile| {
                let score = sketch_similarity_basis_points(&sketch, &profile.sketch);
                (score >= profile.minimum_similarity_basis_points).then(|| SimilarityMatch {
                    identifier: profile.identifier.clone(),
                    threat_name: profile.threat_name.clone(),
                    family: profile.family.clone(),
                    similarity_basis_points: score,
                })
            })
            .collect::<Vec<_>>();
        matches.sort_by_key(|matched| std::cmp::Reverse(matched.similarity_basis_points));
        matches.truncate(MAX_VISIBLE_MATCHES);
        matches
    }
}

/// Computes a deterministic bottom-k sketch over overlapping 16-byte shingles.
/// Work is linear in the sampled input and memory is fixed at 64 entries.
pub fn compute_sketch(bytes: &[u8]) -> Option<[u64; SKETCH_SIZE]> {
    if bytes.len() < MIN_SKETCH_BYTES || bytes.len() < SHINGLE_BYTES {
        return None;
    }
    let mut minima = BTreeSet::new();
    for offset in (0..=bytes.len() - SHINGLE_BYTES).step_by(SHINGLE_STRIDE) {
        let mut low = [0u8; 8];
        let mut high = [0u8; 8];
        low.copy_from_slice(&bytes[offset..offset + 8]);
        high.copy_from_slice(&bytes[offset + 8..offset + 16]);
        let hash = mix64(u64::from_le_bytes(low) ^ mix64(u64::from_le_bytes(high)));
        minima.insert(hash);
        if minima.len() > SKETCH_SIZE {
            minima.pop_last();
        }
    }
    if minima.len() != SKETCH_SIZE {
        return None;
    }
    minima.into_iter().collect::<Vec<_>>().try_into().ok()
}

fn mix64(mut value: u64) -> u64 {
    value ^= value >> 30;
    value = value.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value ^= value >> 27;
    value = value.wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

fn sketch_similarity_basis_points(left: &[u64; SKETCH_SIZE], right: &[u64; SKETCH_SIZE]) -> u16 {
    let (mut left_index, mut right_index, mut shared) = (0, 0, 0usize);
    while left_index < SKETCH_SIZE && right_index < SKETCH_SIZE {
        match left[left_index].cmp(&right[right_index]) {
            std::cmp::Ordering::Less => left_index += 1,
            std::cmp::Ordering::Greater => right_index += 1,
            std::cmp::Ordering::Equal => {
                shared += 1;
                left_index += 1;
                right_index += 1;
            }
        }
    }
    ((shared * 10_000) / SKETCH_SIZE) as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(seed: u64, length: usize) -> Vec<u8> {
        let mut state = seed;
        let mut bytes = Vec::with_capacity(length);
        for _ in 0..length {
            state = mix64(state.wrapping_add(0x9e37_79b9_7f4a_7c15));
            bytes.push(state as u8);
        }
        bytes[0..2].copy_from_slice(b"MZ");
        bytes
    }

    #[test]
    fn identical_pe_matches_at_full_similarity() {
        let bytes = sample(7, 32 * 1024);
        let sketch = compute_sketch(&bytes).unwrap();
        let engine = SimilarityEngine::new(vec![SimilarityProfile {
            identifier: "family-a".to_owned(),
            threat_name: "Test.Similar.FamilyA".to_owned(),
            family: Some("FamilyA".to_owned()),
            minimum_file_size: 16 * 1024,
            maximum_file_size: 64 * 1024,
            minimum_similarity_basis_points: 9_000,
            sketch,
        }])
        .unwrap();
        let matches = engine.scan(&bytes, bytes.len() as u64);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].similarity_basis_points, 10_000);
    }

    #[test]
    fn unrelated_content_does_not_match() {
        let reference = sample(11, 32 * 1024);
        let candidate = sample(99, 32 * 1024);
        let score = sketch_similarity_basis_points(
            &compute_sketch(&reference).unwrap(),
            &compute_sketch(&candidate).unwrap(),
        );
        assert!(score < 8_500);
    }

    #[test]
    fn non_pe_and_short_inputs_skip_all_work() {
        let mut bytes = sample(5, 8 * 1024);
        let profile = SimilarityProfile {
            identifier: "family-a".to_owned(),
            threat_name: "Test.Similar.FamilyA".to_owned(),
            family: None,
            minimum_file_size: MIN_SKETCH_BYTES as u64,
            maximum_file_size: 64 * 1024,
            minimum_similarity_basis_points: 9_000,
            sketch: compute_sketch(&bytes).unwrap(),
        };
        let engine = SimilarityEngine::new(vec![profile]).unwrap();
        bytes[0..2].copy_from_slice(b"NO");
        assert!(engine.scan(&bytes, bytes.len() as u64).is_empty());
        assert!(compute_sketch(&bytes[..1024]).is_none());
    }
}
