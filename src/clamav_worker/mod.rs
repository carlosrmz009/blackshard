pub mod protocol;
pub mod sandbox;

use protocol::{read_message, write_message, ScanRequest, ScanVerdict};
use sandbox::{spawn_sandboxed_worker, SandboxedChild};

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
        let req = ScanRequest::ScanHandle(handle);
        self.send_request(req)
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
    // The worker logic returning Clean as a placeholder
    let stdin = std::io::stdin();
    let mut stdin_lock = stdin.lock();

    let stdout = std::io::stdout();
    let mut stdout_lock = stdout.lock();

    loop {
        match read_message::<_, ScanRequest>(&mut stdin_lock) {
            Ok(req) => {
                // Placeholder logic: always returning Clean
                let verdict = match req {
                    ScanRequest::ScanPath(_path) => ScanVerdict::Clean,
                    ScanRequest::ScanHandle(_handle) => ScanVerdict::Clean,
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
