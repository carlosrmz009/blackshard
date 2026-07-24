pub mod protocol;
pub mod sandbox;

use protocol::{read_message, write_message, ScanRequest, ScanVerdict};
use sandbox::{spawn_sandboxed_worker, SandboxedChild};
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::windows::io::FromRawHandle;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const MAX_CLAM_SCAN_BYTES: u64 = 512 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClamAvVersions {
    pub engine_version: String,
    pub database_version: String,
}

pub struct ClamAvWorker {
    sandbox: SandboxedChild,
}

impl ClamAvWorker {
    pub fn new() -> std::io::Result<Self> {
        let sandbox = spawn_sandboxed_worker()?;
        Ok(Self { sandbox })
    }

    pub fn scan_path(&mut self, path: &str) -> std::io::Result<ScanVerdict> {
        let req = ScanRequest::ScanPath(path.to_owned());
        self.send_request(req)
    }

    pub fn scan_handle(&mut self, handle: u64) -> std::io::Result<ScanVerdict> {
        let worker_handle = self.sandbox.duplicate_handle_into_worker(handle as isize)?;
        let req = ScanRequest::ScanHandle(worker_handle);
        self.send_request(req)
    }

    pub fn health_check(&mut self) -> std::io::Result<ClamAvVersions> {
        match self.send_request(ScanRequest::HealthCheck)? {
            ScanVerdict::Clean {
                engine_version,
                database_version,
            } => Ok(ClamAvVersions {
                engine_version,
                database_version,
            }),
            ScanVerdict::Error(error) => {
                Err(std::io::Error::new(std::io::ErrorKind::NotFound, error))
            }
            other => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unexpected ClamAV health response: {other:?}"),
            )),
        }
    }

    fn send_request(&mut self, req: ScanRequest) -> std::io::Result<ScanVerdict> {
        let stdin = self
            .sandbox
            .child
            .stdin
            .as_mut()
            .expect("Failed to get stdin");
        write_message(stdin, &req)?;
        let stdout = self
            .sandbox
            .child
            .stdout
            .as_mut()
            .expect("Failed to get stdout");
        read_message(stdout)
    }
}

pub fn run_worker_process() -> std::io::Result<()> {
    let stdin = std::io::stdin();
    let mut stdin_lock = stdin.lock();

    let stdout = std::io::stdout();
    let mut stdout_lock = stdout.lock();
    let mut clam = ClamdSession::default();

    loop {
        match read_message::<_, ScanRequest>(&mut stdin_lock) {
            Ok(req) => {
                let verdict = match req {
                    ScanRequest::ScanPath(path) => clam.scan_path(Path::new(&path)),
                    ScanRequest::ScanHandle(handle) => clam.scan_inherited_handle(handle),
                    ScanRequest::HealthCheck => clam.health_check(),
                };
                write_message(&mut stdout_lock, &verdict)?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                break; // Host closed connection
            }
            Err(e) => {
                return Err(e);
            }
        }
    }

    Ok(())
}

#[derive(Default)]
struct ClamdSession {
    child: Option<Child>,
    database: Option<PathBuf>,
    port: u16,
    config_path: Option<PathBuf>,
    engine_version: Option<String>,
    database_version: Option<String>,
}

impl Drop for ClamdSession {
    fn drop(&mut self) {
        self.stop();
    }
}

impl ClamdSession {
    fn health_check(&mut self) -> ScanVerdict {
        match self.ensure_started().and_then(|_| self.command(b"zPING\0")) {
            Ok(response) if response.trim_end_matches('\0').trim() == "PONG" => {}
            Ok(response) => {
                return ScanVerdict::Error(format!(
                    "clamd returned an invalid health reply: {response:?}"
                ))
            }
            Err(error) => return ScanVerdict::Error(error.to_string()),
        }

        let mut eicar = std::io::Cursor::new(
            b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
        );
        match self.scan_reader(&mut eicar) {
            Ok(ScanVerdict::Detected { signature, .. })
                if signature.to_ascii_lowercase().contains("eicar") =>
            {
                self.clean_verdict()
            }
            Ok(other) => {
                ScanVerdict::Error(format!("clamd end-to-end self-test returned {other:?}"))
            }
            Err(error) => ScanVerdict::Error(format!("clamd end-to-end self-test failed: {error}")),
        }
    }

    fn scan_inherited_handle(&mut self, handle: u64) -> ScanVerdict {
        let mut source = unsafe { File::from_raw_handle(handle as *mut _) };
        if let Err(error) = source.seek(SeekFrom::Start(0)) {
            return ScanVerdict::Error(format!("could not seek duplicated scan handle: {error}"));
        }
        self.scan_reader(&mut source)
            .unwrap_or_else(|error| ScanVerdict::Error(error.to_string()))
    }

    fn scan_path(&mut self, path: &Path) -> ScanVerdict {
        let metadata = match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => metadata,
            Ok(_) => {
                return ScanVerdict::Error("ClamAV candidate is not a regular file".to_owned())
            }
            Err(error) => {
                return ScanVerdict::Error(format!("could not inspect candidate: {error}"))
            }
        };
        if metadata.len() > MAX_CLAM_SCAN_BYTES {
            return ScanVerdict::Error("candidate exceeds the ClamAV scan limit".to_owned());
        }
        match File::open(path).and_then(|mut file| self.scan_reader(&mut file)) {
            Ok(verdict) => verdict,
            Err(error) => ScanVerdict::Error(format!("ClamAV path scan failed: {error}")),
        }
    }

    fn scan_reader(&mut self, reader: &mut impl Read) -> std::io::Result<ScanVerdict> {
        self.ensure_started()?;
        let mut stream = self.connect()?;
        stream.write_all(b"zINSTREAM\0")?;
        let mut buffer = [0u8; 64 * 1024];
        let mut total = 0u64;
        loop {
            let read = reader.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            total = total.saturating_add(read as u64);
            if total > MAX_CLAM_SCAN_BYTES {
                return Ok(ScanVerdict::Error(
                    "candidate exceeds the bounded ClamAV stream limit".to_owned(),
                ));
            }
            stream.write_all(&(read as u32).to_be_bytes())?;
            stream.write_all(&buffer[..read])?;
        }
        stream.write_all(&0u32.to_be_bytes())?;
        stream.flush()?;
        let response = read_clamd_response(&mut stream)?;
        parse_scan_response(&response, &self.versions())
    }

    fn ensure_started(&mut self) -> std::io::Result<()> {
        let database = active_database_directory()?;
        if self.database.as_ref() == Some(&database)
            && self
                .child
                .as_mut()
                .is_some_and(|child| child.try_wait().ok().flatten().is_none())
        {
            return Ok(());
        }
        self.stop();

        let clamd = find_clamd()?;
        let listener = TcpListener::bind(("127.0.0.1", 0))?;
        self.port = listener.local_addr()?.port();
        drop(listener);

        let worker_dir = blackshard_data_directory().join("ClamAV").join("Worker");
        fs::create_dir_all(&worker_dir)?;
        let config_path = worker_dir.join(format!("{}.conf", uuid::Uuid::new_v4()));
        let config = format!(
            "DatabaseDirectory {}\r\nTCPSocket {}\r\nTCPAddr 127.0.0.1\r\nForeground yes\r\nMaxThreads 1\r\nReadTimeout 30\r\nCommandReadTimeout 5\r\nMaxFileSize 512M\r\nMaxScanSize 1G\r\nStreamMaxLength 512M\r\nMaxRecursion 16\r\nMaxFiles 10000\r\n",
            database.display(),
            self.port
        );
        fs::write(&config_path, config)?;
        let child = Command::new(clamd)
            .arg(format!("--config-file={}", config_path.display()))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        self.child = Some(child);
        self.database = Some(database);
        self.config_path = Some(config_path);

        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if let Some(status) = self
                .child
                .as_mut()
                .and_then(|child| child.try_wait().ok())
                .flatten()
            {
                self.stop();
                return Err(std::io::Error::other(format!(
                    "clamd exited while loading definitions: {status}"
                )));
            }
            if self.connect().is_ok() {
                let version_response = self.command(b"zVERSION\0")?;
                let (engine_version, database_version) = parse_version_response(&version_response)?;
                self.engine_version = Some(engine_version);
                self.database_version = Some(database_version);
                return Ok(());
            }
            if Instant::now() >= deadline {
                self.stop();
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "clamd did not become ready within 60 seconds",
                ));
            }
            thread::sleep(Duration::from_millis(100));
        }
    }

    fn connect(&self) -> std::io::Result<TcpStream> {
        let stream = TcpStream::connect_timeout(
            &format!("127.0.0.1:{}", self.port)
                .parse()
                .map_err(std::io::Error::other)?,
            Duration::from_secs(2),
        )?;
        stream.set_read_timeout(Some(Duration::from_secs(30)))?;
        stream.set_write_timeout(Some(Duration::from_secs(30)))?;
        Ok(stream)
    }

    fn command(&self, command: &[u8]) -> std::io::Result<String> {
        let mut stream = self.connect()?;
        stream.write_all(command)?;
        stream.flush()?;
        let _ = stream.shutdown(Shutdown::Write);
        read_clamd_response(&mut stream)
    }

    fn stop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        if let Some(config_path) = self.config_path.take() {
            let _ = fs::remove_file(config_path);
        }
        self.database = None;
        self.engine_version = None;
        self.database_version = None;
        self.port = 0;
    }

    fn versions(&self) -> ClamAvVersions {
        ClamAvVersions {
            engine_version: self
                .engine_version
                .clone()
                .unwrap_or_else(|| "unknown".to_owned()),
            database_version: self
                .database_version
                .clone()
                .unwrap_or_else(|| "unknown".to_owned()),
        }
    }

    fn clean_verdict(&self) -> ScanVerdict {
        let versions = self.versions();
        ScanVerdict::Clean {
            engine_version: versions.engine_version,
            database_version: versions.database_version,
        }
    }
}

fn parse_scan_response(response: &str, versions: &ClamAvVersions) -> std::io::Result<ScanVerdict> {
    let response = response.trim_end_matches('\0').trim();
    if response.ends_with(" OK") {
        return Ok(ScanVerdict::Clean {
            engine_version: versions.engine_version.clone(),
            database_version: versions.database_version.clone(),
        });
    }
    if let Some(found) = response.strip_suffix(" FOUND") {
        let threat_name = found
            .rsplit_once(": ")
            .map(|(_, threat)| threat)
            .unwrap_or("ClamAV.Malware")
            .to_owned();
        return Ok(ScanVerdict::Detected {
            signature: threat_name,
            engine_version: versions.engine_version.clone(),
            database_version: versions.database_version.clone(),
        });
    }
    Ok(ScanVerdict::Error(format!(
        "clamd returned an unrecognized response: {response}"
    )))
}

fn parse_version_response(response: &str) -> std::io::Result<(String, String)> {
    let response = response.trim_end_matches('\0').trim();
    let mut fields = response.split('/');
    let engine = fields
        .next()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| std::io::Error::other("clamd VERSION omitted engine version"))?;
    let database = fields
        .next()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| std::io::Error::other("clamd VERSION omitted database version"))?;
    Ok((engine.to_owned(), database.to_owned()))
}

fn read_clamd_response(stream: &mut TcpStream) -> std::io::Result<String> {
    let mut response = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    while response.len() < 4096 {
        match stream.read(&mut byte) {
            Ok(0) => break,
            Ok(_) if byte[0] == 0 => break,
            Ok(_) => response.push(byte[0]),
            Err(error) => return Err(error),
        }
    }
    if response.len() == 4096 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "clamd response exceeded 4 KiB",
        ));
    }
    String::from_utf8(response)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
}

fn find_clamd() -> std::io::Result<PathBuf> {
    if let Some(configured) = std::env::var_os("BLACKSHARD_CLAMD_PATH") {
        let path = PathBuf::from(configured);
        if path.is_file() {
            return Ok(path);
        }
    }
    let executable_dir = std::env::current_exe()?
        .parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| std::io::Error::other("service executable has no parent directory"))?;
    for candidate in [
        executable_dir.join("ClamAV").join("clamd.exe"),
        executable_dir.join("clamd.exe"),
    ] {
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::NotFound,
        "the packaged ClamAV runtime was not found",
    ))
}

fn blackshard_data_directory() -> PathBuf {
    std::env::var_os("PROGRAMDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
        .join("Blackshard")
}

fn active_database_directory() -> std::io::Result<PathBuf> {
    if let Some(configured) = std::env::var_os("BLACKSHARD_CLAMAV_DATABASE_DIR") {
        let path = fs::canonicalize(PathBuf::from(configured))?;
        if path.is_dir() {
            return Ok(path);
        }
    }
    crate::freshclam::downloader::active_database(&blackshard_data_directory())
        .map(|active| active.path)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::NotFound, error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn versions() -> ClamAvVersions {
        ClamAvVersions {
            engine_version: "ClamAV 1.5.2".to_owned(),
            database_version: "28070".to_owned(),
        }
    }

    #[test]
    fn protocol_preserves_clean_and_detected_metadata() {
        assert_eq!(
            parse_scan_response("stream: OK", &versions()).unwrap(),
            ScanVerdict::Clean {
                engine_version: "ClamAV 1.5.2".to_owned(),
                database_version: "28070".to_owned(),
            }
        );
        assert_eq!(
            parse_scan_response("stream: Win.Test FOUND", &versions()).unwrap(),
            ScanVerdict::Detected {
                signature: "Win.Test".to_owned(),
                engine_version: "ClamAV 1.5.2".to_owned(),
                database_version: "28070".to_owned(),
            }
        );
    }

    #[test]
    fn malformed_sidecar_reply_is_an_error_not_clean() {
        assert!(matches!(
            parse_scan_response("stream: malformed archive ERROR", &versions()).unwrap(),
            ScanVerdict::Error(_)
        ));
    }

    #[test]
    fn version_reply_is_bounded_to_engine_and_database_fields() {
        assert_eq!(
            parse_version_response("ClamAV 1.5.2/28070/Fri Jul 24").unwrap(),
            ("ClamAV 1.5.2".to_owned(), "28070".to_owned())
        );
        assert!(parse_version_response("invalid").is_err());
    }
}
