//! Same-volume atomic file replacement helpers.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Replaces `destination` with `source` and requests write-through semantics on
/// Windows. Both paths must be on the same volume.
#[cfg(windows)]
pub fn replace(source: &Path, destination: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;

    const MOVEFILE_REPLACE_EXISTING: u32 = 0x0000_0001;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x0000_0008;

    #[link(name = "kernel32")]
    extern "system" {
        fn MoveFileExW(
            existing_file_name: *const u16,
            new_file_name: *const u16,
            flags: u32,
        ) -> i32;
    }

    fn wide(path: &Path) -> io::Result<Vec<u16>> {
        let mut value = path.as_os_str().encode_wide().collect::<Vec<_>>();
        if value.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "path contains an embedded NUL",
            ));
        }
        value.push(0);
        Ok(value)
    }

    let source = wide(source)?;
    let destination = wide(destination)?;
    let result = unsafe {
        MoveFileExW(
            source.as_ptr(),
            destination.as_ptr(),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    };
    if result == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(windows))]
pub fn replace(source: &Path, destination: &Path) -> io::Result<()> {
    fs::rename(source, destination)
}

/// Writes a complete file beside the destination and atomically publishes it.
pub fn write(destination: &Path, contents: &[u8]) -> io::Result<()> {
    let parent = destination
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "destination has no parent"))?;
    fs::create_dir_all(parent)?;
    let temporary = temporary_path(parent, destination);

    let result = (|| -> io::Result<()> {
        let mut output = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)?;
        output.write_all(contents)?;
        output.sync_all()?;
        drop(output);
        replace(&temporary, destination)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn temporary_path(parent: &Path, destination: &Path) -> PathBuf {
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let name = destination
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("state");
    parent.join(format!(".{name}.{}.{}.tmp", std::process::id(), sequence))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_replaces_an_existing_file_repeatedly() {
        let temporary = tempfile::tempdir().unwrap();
        let destination = temporary.path().join("state.json");
        write(&destination, b"one").unwrap();
        write(&destination, b"two").unwrap();
        write(&destination, b"three").unwrap();
        assert_eq!(fs::read(&destination).unwrap(), b"three");
        assert_eq!(fs::read_dir(temporary.path()).unwrap().count(), 1);
    }
}
