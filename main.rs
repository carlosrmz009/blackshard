use std::ffi::c_void;
use std::fs::File;
use std::io::Read;
use std::mem;
use std::ptr;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, HRESULT, S_OK};

#[link(name = "FltLib")]
extern "system" {
    fn FilterConnectCommunicationPort(
        lpPortName: *const u16,
        dwOptions: u32,
        lpContext: *const c_void,
        wSizeOfContext: u16,
        lpSecurityAttributes: *const c_void,
        hPort: *mut HANDLE,
    ) -> HRESULT;

    fn FilterGetMessage(
        hPort: HANDLE,
        lpMessageBuffer: *mut c_void,
        dwMessageBufferSize: u32,
        lpOverlapped: *mut c_void,
    ) -> HRESULT;

    fn FilterReplyMessage(
        hPort: HANDLE,
        lpReplyBuffer: *mut c_void,
        dwReplyBufferSize: u32,
    ) -> HRESULT;
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

fn calculate_entropy(file_path: &str) -> f64 {
    let mut file = match File::open(file_path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("[!] Warning: Could not open file for entropy check ({}). Reason: {}", file_path, e);
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

fn main() {
    println!("[*] Blackshard Daemon Starting...");

    let port_name: Vec<u16> = "\\BlackshardPort\0".encode_utf16().collect();
    let mut port_handle: HANDLE = ptr::null_mut();

    println!("[*] Attempting to connect to kernel port: \\BlackshardPort");
    
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
        eprintln!("[!] Failed to connect to port. Is the driver loaded? HRESULT: {:#010X}", hr);
        return;
    }

    println!("[+] Successfully connected to Blackshard Minifilter Driver.");
    println!("[*] Securing execution pipeline. Entering telemetry listening loop...\n");

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
            eprintln!("[!] FilterGetMessage failed with HRESULT: {:#010X}", get_msg_hr);
            break;
        }

        let pid = message.notification.process_id;
        
        let path_len = message.notification.file_path.iter().position(|&c| c == 0).unwrap_or(MAX_FILE_PATH_LENGTH);
        let path = String::from_utf16_lossy(&message.notification.file_path[..path_len]);

        let openable_path = if path.starts_with("\\Device\\") {
            format!("\\\\?\\GLOBALROOT{}", path)
        } else {
            path.clone()
        };

        let entropy = calculate_entropy(&openable_path);
        let mut final_verdict = BLACKSHARD_VERDICT::Allow;

        if entropy > 7.2 {
            println!("============================================================");
            println!("[!!!] HIGH ENTROPY THREAT DETECTED [!!!]");
            println!("  [>] PID     : {}", pid);
            println!("  [>] File    : {}", path);
            println!("  [>] Entropy : {:.2}", entropy);
            println!("  [X] Verdict : BLOCK");
            println!("============================================================");
            final_verdict = BLACKSHARD_VERDICT::Block;
        } else {
            println!("[OK] PID: {:<6} | Entropy: {:.2} | Verdict: ALLOW | File: {}", pid, entropy, path);
        }

        let mut reply = BLACKSHARD_REPLY_MSG {
            header: FILTER_REPLY_HEADER {
                Status: 0,
                MessageId: message.header.MessageId,
            },
            verdict: final_verdict, 
        };

        let reply_hr = unsafe {
            FilterReplyMessage(
                port_handle,
                &mut reply as *mut _ as *mut c_void,
                mem::size_of::<BLACKSHARD_REPLY_MSG>() as u32,
            )
        };

        if reply_hr != S_OK {
            eprintln!("[!] FilterReplyMessage failed with HRESULT: {:#010X}", reply_hr);
        }
    }

    unsafe { CloseHandle(port_handle) };
    println!("[*] Blackshard Daemon Shutting Down.");
}
