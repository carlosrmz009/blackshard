use chrono::Local;
use eframe::egui;
use std::collections::VecDeque;
use std::ffi::{c_void, OsStr};
use std::fs::{self, File};
use std::io::{self, Read};
use std::mem;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::ptr;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, S_OK};

#[cfg(windows)]
use std::os::windows::process::CommandExt;

#[link(name = "FltLib")]
extern "system" {
    fn FilterConnectCommunicationPort(
        port_name: *const u16,
        options: u32,
        context: *const c_void,
        context_size: u16,
        security_attributes: *const c_void,
        port: *mut HANDLE,
    ) -> i32;

    fn FilterGetMessage(
        port: HANDLE,
        message_buffer: *mut c_void,
        message_buffer_size: u32,
        overlapped: *mut c_void,
    ) -> i32;

    fn FilterReplyMessage(port: HANDLE, reply_buffer: *mut c_void, reply_buffer_size: u32) -> i32;
}

#[repr(C)]
#[derive(Debug)]
struct FilterMessageHeader {
    reply_length: u32,
    message_id: u64,
}

#[repr(C)]
#[derive(Debug)]
struct FilterReplyHeader {
    status: i32,
    message_id: u64,
}

const MAX_FILE_PATH_LENGTH: usize = 260;
const MAX_LOG_ENTRIES: usize = 1_000;
const ENTROPY_THRESHOLD: f64 = 7.2;
const SELF_TEST_ARGUMENT: &str = "--blackshard-self-test-open";
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[repr(C)]
#[derive(Debug)]
struct BlackshardNotification {
    process_id: u32,
    file_path: [u16; MAX_FILE_PATH_LENGTH],
}

#[repr(C)]
#[derive(Debug)]
struct BlackshardMessage {
    header: FilterMessageHeader,
    notification: BlackshardNotification,
}

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BlackshardVerdict {
    Allow = 0,
    Block = 1,
}

#[repr(C)]
#[derive(Debug)]
struct BlackshardReplyMessage {
    header: FilterReplyHeader,
    verdict: BlackshardVerdict,
}

#[derive(Clone)]
struct LogEntry {
    timestamp: String,
    pid: u32,
    file_path: String,
    entropy: f64,
    verdict: BlackshardVerdict,
    scan_error: Option<String>,
}

#[derive(Clone)]
enum ConnectionState {
    Connecting,
    Connected,
    Disconnected(String),
}

#[derive(Clone)]
enum SelfTestState {
    Idle,
    Running,
    Passed,
    Failed(String),
}

struct SharedState {
    connection: ConnectionState,
    self_test: SelfTestState,
    logs: VecDeque<LogEntry>,
    scanned: u64,
    blocked: u64,
}

impl Default for SharedState {
    fn default() -> Self {
        Self {
            connection: ConnectionState::Connecting,
            self_test: SelfTestState::Idle,
            logs: VecDeque::new(),
            scanned: 0,
            blocked: 0,
        }
    }
}

struct BlackshardApp {
    state: Arc<Mutex<SharedState>>,
}

impl eframe::App for BlackshardApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        ctx.set_visuals(egui::Visuals::dark());

        let (connection, self_test, scanned, blocked, logs) = {
            let state = self.state.lock().unwrap();
            (
                state.connection.clone(),
                state.self_test.clone(),
                state.scanned,
                state.blocked,
                state.logs.iter().cloned().collect::<Vec<_>>(),
            )
        };

        egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
            let (status_text, status_color, detail) = match &connection {
                ConnectionState::Connecting => (
                    "BLACKSHARD // CONNECTING",
                    egui::Color32::YELLOW,
                    "Waiting for the kernel minifilter".to_owned(),
                ),
                ConnectionState::Connected => (
                    "BLACKSHARD // FILTER CONNECTED",
                    egui::Color32::GREEN,
                    "Kernel enforcement and user-mode analysis are connected".to_owned(),
                ),
                ConnectionState::Disconnected(error) => (
                    "BLACKSHARD // FILTER DISCONNECTED",
                    egui::Color32::RED,
                    error.clone(),
                ),
            };

            ui.heading(egui::RichText::new(status_text).color(status_color));
            ui.label(detail);
            ui.horizontal(|ui| {
                ui.label(format!("Scanned: {scanned}"));
                ui.separator();
                ui.label(format!("Blocked: {blocked}"));
                ui.separator();
                ui.label(format!("Entropy threshold: {ENTROPY_THRESHOLD:.1}"));
            });

            ui.horizontal(|ui| {
                let can_test = matches!(connection, ConnectionState::Connected)
                    && !matches!(self_test, SelfTestState::Running);

                if ui
                    .add_enabled(can_test, egui::Button::new("Run harmless self-test"))
                    .clicked()
                {
                    {
                        let mut state = self.state.lock().unwrap();
                        state.self_test = SelfTestState::Running;
                    }
                    let state = Arc::clone(&self.state);
                    thread::spawn(move || run_self_test(state));
                }

                match &self_test {
                    SelfTestState::Idle => {
                        ui.label("Self-test has not run");
                    }
                    SelfTestState::Running => {
                        ui.colored_label(egui::Color32::YELLOW, "Self-test running...");
                    }
                    SelfTestState::Passed => {
                        ui.colored_label(
                            egui::Color32::GREEN,
                            "PASS: kernel denied the harmless test file",
                        );
                    }
                    SelfTestState::Failed(error) => {
                        ui.colored_label(egui::Color32::RED, format!("FAIL: {error}"));
                    }
                }
            });
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            if logs.is_empty() {
                ui.centered_and_justified(|ui| {
                    ui.label("No file decisions yet. Connect the filter or run the self-test.");
                });
                return;
            }

            egui::ScrollArea::vertical()
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    for log in &logs {
                        let color = if log.verdict == BlackshardVerdict::Block {
                            egui::Color32::RED
                        } else if log.scan_error.is_some() {
                            egui::Color32::YELLOW
                        } else {
                            egui::Color32::WHITE
                        };

                        let mut text = format!(
                            "[{}] PID: {:<6} | Entropy: {:.2} | Verdict: {:?} | File: {}",
                            log.timestamp, log.pid, log.entropy, log.verdict, log.file_path
                        );
                        if let Some(error) = &log.scan_error {
                            text.push_str(&format!(" | Scan error: {error}"));
                        }

                        ui.colored_label(color, text);
                    }
                });
        });

        ctx.request_repaint_after(Duration::from_millis(250));
    }
}

fn calculate_entropy(file_path: &Path) -> io::Result<f64> {
    let mut file = File::open(file_path)?;
    let mut buffer = vec![0u8; 1024 * 1024];
    let bytes_read = file.read(&mut buffer)?;

    Ok(shannon_entropy(&buffer[..bytes_read]))
}

fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }

    let mut frequency = [0usize; 256];
    for &byte in bytes {
        frequency[byte as usize] += 1;
    }

    let total_bytes = bytes.len() as f64;
    frequency
        .iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let probability = count as f64 / total_bytes;
            -probability * probability.log2()
        })
        .sum()
}

fn device_path_to_openable_path(path: &str) -> PathBuf {
    if path.starts_with("\\Device\\") {
        PathBuf::from(format!("\\\\?\\GLOBALROOT{path}"))
    } else {
        PathBuf::from(path)
    }
}

fn set_connection_state(state: &Arc<Mutex<SharedState>>, connection: ConnectionState) {
    state.lock().unwrap().connection = connection;
}

fn hresult_text(hr: i32) -> String {
    match hr as u32 {
        0x8007_0002 => {
            "Kernel communication port not found; load the minifilter, then retry".to_owned()
        }
        0x8007_0005 => {
            "Access denied by the filter port; run Blackshard as Administrator".to_owned()
        }
        code => format!("Filter communication error 0x{code:08X}; retrying"),
    }
}

fn run_telemetry_loop(state: Arc<Mutex<SharedState>>) {
    let port_name: Vec<u16> = "\\BlackshardPort\0".encode_utf16().collect();

    loop {
        set_connection_state(&state, ConnectionState::Connecting);
        let mut port_handle: HANDLE = 0;
        let connect_hr = unsafe {
            FilterConnectCommunicationPort(
                port_name.as_ptr(),
                0,
                ptr::null(),
                0,
                ptr::null(),
                &mut port_handle,
            )
        };

        if connect_hr != S_OK {
            set_connection_state(
                &state,
                ConnectionState::Disconnected(hresult_text(connect_hr)),
            );
            thread::sleep(Duration::from_secs(2));
            continue;
        }

        set_connection_state(&state, ConnectionState::Connected);
        let disconnect_reason = loop {
            let mut message = unsafe { mem::zeroed::<BlackshardMessage>() };
            let get_message_hr = unsafe {
                FilterGetMessage(
                    port_handle,
                    &mut message as *mut _ as *mut c_void,
                    mem::size_of::<BlackshardMessage>() as u32,
                    ptr::null_mut(),
                )
            };

            if get_message_hr != S_OK {
                break hresult_text(get_message_hr);
            }

            let path_length = message
                .notification
                .file_path
                .iter()
                .position(|&character| character == 0)
                .unwrap_or(MAX_FILE_PATH_LENGTH);
            let path = String::from_utf16_lossy(&message.notification.file_path[..path_length]);
            let openable_path = device_path_to_openable_path(&path);

            let (entropy, scan_error) = match calculate_entropy(&openable_path) {
                Ok(entropy) => (entropy, None),
                Err(error) => (0.0, Some(error.to_string())),
            };
            let verdict = if scan_error.is_none() && entropy > ENTROPY_THRESHOLD {
                BlackshardVerdict::Block
            } else {
                BlackshardVerdict::Allow
            };

            {
                let mut shared = state.lock().unwrap();
                shared.scanned += 1;
                if verdict == BlackshardVerdict::Block {
                    shared.blocked += 1;
                }
                if shared.logs.len() == MAX_LOG_ENTRIES {
                    shared.logs.pop_front();
                }
                shared.logs.push_back(LogEntry {
                    timestamp: Local::now().format("%H:%M:%S").to_string(),
                    pid: message.notification.process_id,
                    file_path: path,
                    entropy,
                    verdict,
                    scan_error,
                });
            }

            let mut reply = BlackshardReplyMessage {
                header: FilterReplyHeader {
                    status: 0,
                    message_id: message.header.message_id,
                },
                verdict,
            };

            // A late reply can fail if the driver's bounded timeout elapsed. The
            // communication port remains valid, so continue receiving messages.
            let _ = unsafe {
                FilterReplyMessage(
                    port_handle,
                    &mut reply as *mut _ as *mut c_void,
                    mem::size_of::<BlackshardReplyMessage>() as u32,
                )
            };
        };

        unsafe { CloseHandle(port_handle) };
        set_connection_state(&state, ConnectionState::Disconnected(disconnect_reason));
        thread::sleep(Duration::from_secs(2));
    }
}

fn fill_self_test_bytes(bytes: &mut [u8]) {
    let mut value = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
        ^ u64::from(std::process::id());

    for chunk in bytes.chunks_mut(8) {
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        let generated = value.to_le_bytes();
        chunk.copy_from_slice(&generated[..chunk.len()]);
    }
}

fn run_self_test(state: Arc<Mutex<SharedState>>) {
    let result = run_self_test_inner();
    let mut shared = state.lock().unwrap();
    shared.self_test = match result {
        Ok(()) => SelfTestState::Passed,
        Err(error) => SelfTestState::Failed(error),
    };
}

fn run_self_test_inner() -> Result<(), String> {
    let test_path =
        std::env::temp_dir().join(format!("blackshard-self-test-{}.bin", std::process::id()));
    let mut test_bytes = vec![0u8; 256 * 1024];
    fill_self_test_bytes(&mut test_bytes);
    fs::write(&test_path, test_bytes)
        .map_err(|error| format!("could not create test file: {error}"))?;

    let executable = std::env::current_exe()
        .map_err(|error| format!("could not locate blackshard.exe: {error}"))?;
    let status = Command::new(executable)
        .arg(SELF_TEST_ARGUMENT)
        .arg(&test_path)
        .creation_flags(CREATE_NO_WINDOW)
        .status()
        .map_err(|error| format!("could not start test probe: {error}"));

    let _ = fs::remove_file(&test_path);

    match status {
        Ok(status) if status.code() == Some(10) => Ok(()),
        Ok(status) if status.success() => Err("test file was opened instead of blocked".to_owned()),
        Ok(status) => Err(format!(
            "test probe failed unexpectedly with exit code {:?}",
            status.code()
        )),
        Err(error) => Err(error),
    }
}

fn self_test_probe_exit_code() -> Option<i32> {
    let mut arguments = std::env::args_os();
    arguments.next();
    if arguments.next().as_deref() != Some(OsStr::new(SELF_TEST_ARGUMENT)) {
        return None;
    }

    let Some(path) = arguments.next() else {
        return Some(12);
    };

    Some(match File::open(path) {
        Ok(_) => 0,
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => 10,
        Err(_) => 11,
    })
}

fn main() -> Result<(), eframe::Error> {
    if let Some(exit_code) = self_test_probe_exit_code() {
        std::process::exit(exit_code);
    }

    let state = Arc::new(Mutex::new(SharedState::default()));
    let telemetry_state = Arc::clone(&state);
    thread::spawn(move || run_telemetry_loop(telemetry_state));

    let mut wgpu_options = eframe::egui_wgpu::WgpuConfiguration::default();
    wgpu_options.supported_backends = eframe::wgpu::Backends::DX12;
    wgpu_options.power_preference = eframe::wgpu::PowerPreference::LowPower;

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([960.0, 640.0]),
        renderer: eframe::Renderer::Wgpu,
        wgpu_options,
        ..Default::default()
    };

    eframe::run_native(
        "Blackshard",
        options,
        Box::new(|_creation_context| Box::new(BlackshardApp { state })),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uniform_bytes_have_zero_entropy() {
        assert_eq!(shannon_entropy(&[0u8; 4096]), 0.0);
    }

    #[test]
    fn self_test_bytes_exceed_blocking_threshold() {
        let mut bytes = vec![0u8; 256 * 1024];
        fill_self_test_bytes(&mut bytes);
        assert!(shannon_entropy(&bytes) > ENTROPY_THRESHOLD);
    }

    #[test]
    fn device_paths_are_mapped_through_globalroot() {
        assert_eq!(
            device_path_to_openable_path("\\Device\\HarddiskVolume3\\sample.bin"),
            PathBuf::from("\\\\?\\GLOBALROOT\\Device\\HarddiskVolume3\\sample.bin")
        );
    }

    #[test]
    fn filter_protocol_layout_matches_x64_minifilter_abi() {
        assert_eq!(mem::size_of::<FilterMessageHeader>(), 16);
        assert_eq!(mem::size_of::<BlackshardNotification>(), 524);
        assert_eq!(mem::size_of::<BlackshardMessage>(), 544);
        assert_eq!(mem::size_of::<FilterReplyHeader>(), 16);
        assert_eq!(mem::size_of::<BlackshardReplyMessage>(), 24);
    }
}
