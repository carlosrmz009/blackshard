pub mod protocol;
pub mod sandbox;

use protocol::{read_message, write_message, ParseRequest, ParseResult};
use sandbox::{spawn_sandboxed_worker, SandboxedChild};
use std::fs::File;
use std::os::windows::io::FromRawHandle;

pub struct ParserWorker {
    sandbox: SandboxedChild,
}

impl ParserWorker {
    pub fn new() -> std::io::Result<Self> {
        let sandbox = spawn_sandboxed_worker()?;
        Ok(Self { sandbox })
    }

    pub fn scan_path(&mut self, path: &str) -> std::io::Result<ParseResult> {
        let req = ParseRequest::ScanPath(path.to_owned());
        self.send_request(req)
    }

    pub fn scan_handle(&mut self, handle: u64) -> std::io::Result<ParseResult> {
        let worker_handle = self.sandbox.duplicate_handle_into_worker(handle as isize)?;
        let req = ParseRequest::ScanHandle(worker_handle);
        self.send_request(req)
    }

    pub fn health_check(&mut self) -> std::io::Result<()> {
        match self.send_request(ParseRequest::HealthCheck)? {
            ParseResult::Clean { complete: true } => Ok(()),
            ParseResult::Error(error) => Err(std::io::Error::other(error)),
            other => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unexpected parser health response: {other:?}"),
            )),
        }
    }

    fn send_request(&mut self, req: ParseRequest) -> std::io::Result<ParseResult> {
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

    loop {
        match read_message::<_, ParseRequest>(&mut stdin_lock) {
            Ok(req) => {
                let verdict = match req {
                    ParseRequest::ScanPath(path) => {
                        report_to_result(crate::engine::ScanEngine::default().scan_path(path))
                    }
                    ParseRequest::ScanHandle(handle) => {
                        let file = unsafe { File::from_raw_handle(handle as *mut _) };
                        let size = file.metadata().ok().map(|metadata| metadata.len());
                        report_to_result(
                            crate::engine::ScanEngine::default().scan_reader(file, size),
                        )
                    }
                    ParseRequest::HealthCheck => ParseResult::Clean { complete: true },
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

fn report_to_result(report: crate::engine::ScanReport) -> ParseResult {
    let complete = report.analysis_completeness == crate::engine::AnalysisCompleteness::Complete
        && !report.truncated;
    match report.verdict {
        crate::engine::Verdict::Clean => ParseResult::Clean { complete },
        crate::engine::Verdict::Suspicious => ParseResult::Suspicious {
            risk_score: report.risk_score,
            complete,
        },
        crate::engine::Verdict::Malicious => ParseResult::Malicious {
            threat_name: report
                .evidence
                .iter()
                .find(|evidence| evidence.code == "signature.exact_sha256")
                .map(|evidence| evidence.description.clone())
                .unwrap_or_else(|| "ParserWorker.Malware".to_owned()),
            complete,
        },
        crate::engine::Verdict::Error => {
            ParseResult::Error(report.error.unwrap_or_else(|| "parser failed".to_owned()))
        }
    }
}
