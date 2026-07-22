//! Per-user notification broker for service-generated security events.

use crate::atomic_file;
use crate::config::Settings;
use crate::history::{EventHistory, EventKind};
use crate::notifications::notify_detection;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::PathBuf;
use std::thread;
use std::time::Duration;

const POLL_INTERVAL: Duration = Duration::from_secs(2);
const CURSOR_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NotificationCursor {
    schema_version: u32,
    last_seen: DateTime<Utc>,
}

pub fn run() -> Result<(), String> {
    let _single_instance = SingleInstance::acquire()?;
    let history = EventHistory::default_for_machine();
    let cursor_path = cursor_path();
    let mut last_seen = load_cursor(&cursor_path).unwrap_or_else(|_| Utc::now());
    save_cursor(&cursor_path, last_seen)
        .map_err(|error| format!("could not initialize the notification cursor: {error}"))?;

    loop {
        if let Ok(mut events) = history.recent(512) {
            events.sort_by_key(|event| event.timestamp);
            for event in events.into_iter() {
                if event.timestamp <= last_seen {
                    continue;
                }
                if matches!(
                    event.kind,
                    EventKind::Quarantined | EventKind::QuarantineFailed
                ) && Settings::load(&Settings::default_machine_path())
                    .map(|settings| settings.notify_on_detection)
                    .unwrap_or(true)
                {
                    if let (Some(path), Some(threat_name)) =
                        (event.path.as_deref(), event.threat_name.as_deref())
                    {
                        let _ = notify_detection(
                            threat_name,
                            path,
                            event.kind == EventKind::Quarantined,
                        );
                    }
                }
                last_seen = last_seen.max(event.timestamp);
            }
            let _ = save_cursor(&cursor_path, last_seen);
        }
        thread::sleep(POLL_INTERVAL);
    }
}

fn cursor_path() -> PathBuf {
    std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join("Blackshard")
        .join("notification-cursor.json")
}

fn load_cursor(path: &std::path::Path) -> io::Result<DateTime<Utc>> {
    let bytes = fs::read(path)?;
    if bytes.len() > 4 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "notification cursor exceeds its size limit",
        ));
    }
    let cursor: NotificationCursor = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
    if cursor.schema_version != CURSOR_SCHEMA_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "notification cursor schema is unsupported",
        ));
    }
    Ok(cursor.last_seen)
}

fn save_cursor(path: &std::path::Path, last_seen: DateTime<Utc>) -> io::Result<()> {
    let bytes = serde_json::to_vec(&NotificationCursor {
        schema_version: CURSOR_SCHEMA_VERSION,
        last_seen,
    })
    .map_err(io::Error::other)?;
    atomic_file::write(path, &bytes)
}

#[cfg(windows)]
struct SingleInstance(isize);

#[cfg(windows)]
impl SingleInstance {
    fn acquire() -> Result<Self, String> {
        use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, ERROR_ALREADY_EXISTS};

        #[link(name = "kernel32")]
        extern "system" {
            fn CreateMutexW(
                mutex_attributes: *const std::ffi::c_void,
                initial_owner: i32,
                name: *const u16,
            ) -> isize;
        }

        let name = "Local\\BlackshardNotificationAgent\0"
            .encode_utf16()
            .collect::<Vec<_>>();
        let handle = unsafe { CreateMutexW(std::ptr::null(), 0, name.as_ptr()) };
        if handle == 0 {
            return Err(format!(
                "could not create the notification-agent mutex: {}",
                io::Error::last_os_error()
            ));
        }
        if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
            unsafe { CloseHandle(handle) };
            return Err("the notification agent is already running".to_owned());
        }
        Ok(Self(handle))
    }
}

#[cfg(windows)]
impl Drop for SingleInstance {
    fn drop(&mut self) {
        unsafe { windows_sys::Win32::Foundation::CloseHandle(self.0) };
    }
}

#[cfg(not(windows))]
struct SingleInstance;

#[cfg(not(windows))]
impl SingleInstance {
    fn acquire() -> Result<Self, String> {
        Ok(Self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_round_trip_is_bounded_and_versioned() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("cursor.json");
        let now = Utc::now();
        save_cursor(&path, now).unwrap();
        assert_eq!(load_cursor(&path).unwrap(), now);
        fs::write(&path, vec![b'x'; 4097]).unwrap();
        assert_eq!(
            load_cursor(&path).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}
