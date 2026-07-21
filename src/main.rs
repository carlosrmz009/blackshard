use chrono::Local;
use eframe::egui;
use std::ffi::c_void;
use std::fs::File;
use std::io::Read;
use std::mem;
use std::ptr;
use std::sync::{Arc, Mutex};
use std::thread;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, S_OK};

#[link(name = "FltLib")]
extern "system" {
    fn FilterConnectCommunicationPort(
        lpPortName: *const u16,
        dwOptions: u32,
        lpContext: *const c_void,
        wSizeOfContext: u16,
        lpSecurityAttributes: *const c_void,
        hPort: *mut HANDLE,
    ) -> i32;

    fn FilterGetMessage(
        hPort: HANDLE,
        lpMessageBuffer: *mut c_void,
        dwMessageBufferSize: u32,
        lpOverlapped: *mut c_void,
    ) -> i32;

    fn FilterReplyMessage(hPort: HANDLE, lpReplyBuffer: *mut c_void, dwReplyBufferSize: u32)
        -> i32;
}

#[repr(C)]
#[derive(Debug)]
pub struct FILTER_MESSAGE_HEADER {
    pub ReplyLength: u32,
    pub MessageId: u64,
}

#[repr(C)]
#[derive(Debug)]
pub struct FILTER_REPLY_HEADER {
    pub Status: i32,
    pub MessageId: u64,
}

const MAX_FILE_PATH_LENGTH: usize = 260;

#[repr(C)]
#[derive(Debug)]
pub struct BLACKSHARD_NOTIFICATION {
    pub process_id: u32,
    pub file_path: [u16; MAX_FILE_PATH_LENGTH],
}

#[repr(C)]
#[derive(Debug)]
pub struct BLACKSHARD_MESSAGE {
    pub header: FILTER_MESSAGE_HEADER,
    pub notification: BLACKSHARD_NOTIFICATION,
}

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BLACKSHARD_VERDICT {
    Allow = 0,
    Block = 1,
}

#[repr(C)]
#[derive(Debug)]
pub struct BLACKSHARD_REPLY_MSG {
    pub header: FILTER_REPLY_HEADER,
    pub verdict: BLACKSHARD_VERDICT,
}

struct LogEntry {
    timestamp: String,
    pid: u32,
    file_path: String,
    entropy: f64,
    verdict: BLACKSHARD_VERDICT,
}

struct BlackshardApp {
    logs: Arc<Mutex<Vec<LogEntry>>>,
}

impl eframe::App for BlackshardApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        ctx.set_visuals(egui::Visuals::dark());

        egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
            ui.heading(
                egui::RichText::new("BLACKSHARD // AGENT ONLINE").color(egui::Color32::GREEN),
            );
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical()
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    let logs = self.logs.lock().unwrap();
                    for log in logs.iter() {
                        let color = if log.verdict == BLACKSHARD_VERDICT::Block {
                            egui::Color32::RED
                        } else {
                            egui::Color32::WHITE
                        };

                        let text = format!(
                            "[{}] PID: {:<6} | Entropy: {:.2} | Verdict: {:?} | File: {}",
                            log.timestamp, log.pid, log.entropy, log.verdict, log.file_path
                        );

                        ui.colored_label(color, text);
                    }
                });
        });

        ctx.request_repaint();
    }
}

fn calculate_entropy(file_path: &str) -> f64 {
    let mut file = match File::open(file_path) {
        Ok(f) => f,
        Err(_) => {
            return 0.0;
        }
    };

    let mut buffer = [0u8; 1024 * 1024];
    let bytes_read = match file.read(&mut buffer) {
        Ok(n) if n > 0 => n,
        _ => return 0.0,
    };

    let mut frequency = [0usize; 256];
    for &byte in &buffer[..bytes_read] {
        frequency[byte as usize] += 1;
    }

    let mut entropy = 0.0;
    let total_bytes = bytes_read as f64;

    for &count in &frequency {
        if count > 0 {
            let probability = count as f64 / total_bytes;
            entropy -= probability * probability.log2();
        }
    }

    entropy
}

fn run_telemetry_loop(logs: Arc<Mutex<Vec<LogEntry>>>) {
    let port_name: Vec<u16> = "\\BlackshardPort\0".encode_utf16().collect();
    let mut port_handle: HANDLE = 0;

    let hr = unsafe {
        FilterConnectCommunicationPort(
            port_name.as_ptr(),
            0,
            ptr::null(),
            0,
            ptr::null(),
            &mut port_handle,
        )
    };

    if hr != S_OK {
        return;
    }

    let mut message = unsafe { mem::zeroed::<BLACKSHARD_MESSAGE>() };

    loop {
        let get_msg_hr = unsafe {
            FilterGetMessage(
                port_handle,
                &mut message as *mut _ as *mut c_void,
                mem::size_of::<BLACKSHARD_MESSAGE>() as u32,
                ptr::null_mut(),
            )
        };

        if get_msg_hr != S_OK {
            break;
        }

        let pid = message.notification.process_id;

        let path_len = message
            .notification
            .file_path
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(MAX_FILE_PATH_LENGTH);
        let path = String::from_utf16_lossy(&message.notification.file_path[..path_len]);

        let openable_path = if path.starts_with("\\Device\\") {
            format!("\\\\?\\GLOBALROOT{}", path)
        } else {
            path.clone()
        };

        let entropy = calculate_entropy(&openable_path);
        let final_verdict = if entropy > 7.2 {
            BLACKSHARD_VERDICT::Block
        } else {
            BLACKSHARD_VERDICT::Allow
        };

        let timestamp = Local::now().format("%H:%M:%S").to_string();

        logs.lock().unwrap().push(LogEntry {
            timestamp,
            pid,
            file_path: path,
            entropy,
            verdict: final_verdict,
        });

        let mut reply = BLACKSHARD_REPLY_MSG {
            header: FILTER_REPLY_HEADER {
                Status: 0,
                MessageId: message.header.MessageId,
            },
            verdict: final_verdict,
        };

        let _reply_hr = unsafe {
            FilterReplyMessage(
                port_handle,
                &mut reply as *mut _ as *mut c_void,
                mem::size_of::<BLACKSHARD_REPLY_MSG>() as u32,
            )
        };
    }

    unsafe { CloseHandle(port_handle) };
}

fn main() -> Result<(), eframe::Error> {
    let logs = Arc::new(Mutex::new(Vec::new()));
    let logs_clone = Arc::clone(&logs);

    thread::spawn(move || {
        run_telemetry_loop(logs_clone);
    });

    let mut wgpu_options = eframe::egui_wgpu::WgpuConfiguration::default();
    wgpu_options.supported_backends = eframe::wgpu::Backends::DX12;
    wgpu_options.power_preference = eframe::wgpu::PowerPreference::LowPower;

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([800.0, 600.0]),
        renderer: eframe::Renderer::Wgpu,
        wgpu_options,
        ..Default::default()
    };

    eframe::run_native(
        "Blackshard",
        options,
        Box::new(|_cc| Box::new(BlackshardApp { logs }) as Box<dyn eframe::App>),
    )
}
