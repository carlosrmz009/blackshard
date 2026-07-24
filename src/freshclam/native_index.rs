use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::Path;

/// Represents a parsed hash signature from `.hsb` or `.hdb` files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    pub hash: Vec<u8>,
    pub size: Option<u64>,
    pub name: String,
}

/// A fast native memory structure for indexing and evaluating hash-based signatures.
pub struct NativeIndex {
    /// Signatures sorted by hash for binary search.
    pub signatures: Vec<Signature>,
}

impl Default for NativeIndex {
    fn default() -> Self {
        Self::new()
    }
}

impl NativeIndex {
    /// Creates a new, empty NativeIndex.
    pub fn new() -> Self {
        Self {
            signatures: Vec::new(),
        }
    }

    /// Parses and loads signatures from a `.hsb` or `.hdb` file.
    /// Expected format per line: `hash:size:name`
    pub fn load_from_file<P: AsRef<Path>>(&mut self, path: P) -> io::Result<()> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);

        for line in reader.lines() {
            let line = line?;
            let line = line.trim();
            
            // Ignore comments and empty lines
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let parts: Vec<&str> = line.split(':').collect();
            // ClamAV formats typically use `hash:size:name`
            if parts.len() >= 3 {
                let hash_hex = parts[0];
                let size_str = parts[1];
                let name = parts[2..].join(":"); // Support names that might contain colons

                let hash = match hex::decode(hash_hex) {
                    Ok(h) => h,
                    Err(_) => continue, // Skip invalid hex
                };

                let size = if size_str == "*" {
                    None
                } else {
                    size_str.parse::<u64>().ok()
                };

                self.signatures.push(Signature {
                    hash,
                    size,
                    name,
                });
            }
        }

        self.sort_index();
        Ok(())
    }

    /// Sorts the internal signature list to enable fast lookups.
    pub fn sort_index(&mut self) {
        self.signatures.sort_by(|a, b| a.hash.cmp(&b.hash));
    }

    /// Evaluates a file hash and optional size, returning the matched malware name if found.
    pub fn evaluate(&self, hash: &[u8], file_size: Option<u64>) -> Option<&str> {
        if self.signatures.is_empty() {
            return None;
        }

        // Binary search for the hash
        if let Ok(idx) = self.signatures.binary_search_by(|sig| sig.hash.as_slice().cmp(hash)) {
            // There could be multiple signatures with the same hash but different sizes.
            // We need to check around the found index to see if any match the given size.
            
            // Search backwards
            let mut curr = idx;
            loop {
                let sig = &self.signatures[curr];
                if sig.hash != hash {
                    break;
                }
                if Self::size_matches(sig.size, file_size) {
                    return Some(&sig.name);
                }
                if curr == 0 {
                    break;
                }
                curr -= 1;
            }

            // Search forwards
            let mut curr = idx + 1;
            while curr < self.signatures.len() {
                let sig = &self.signatures[curr];
                if sig.hash != hash {
                    break;
                }
                if Self::size_matches(sig.size, file_size) {
                    return Some(&sig.name);
                }
                curr += 1;
            }
        }
        None
    }

    /// Helper to check if a signature size matches an actual file size.
    fn size_matches(sig_size: Option<u64>, file_size: Option<u64>) -> bool {
        match (sig_size, file_size) {
            // If the signature doesn't specify a size (i.e. '*'), it always matches
            (None, _) => true,
            // If the signature specifies a size, the file must match exactly
            (Some(ss), Some(fs)) => ss == fs,
            // If the signature needs a specific size but file size is unknown, it's not a match
            (Some(_), None) => false,
        }
    }
}
