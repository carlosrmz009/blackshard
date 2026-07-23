use crate::behavior::{ProcessTrust, RansomwareMonitor};
use crate::config::Settings;
use crate::detection::{
    open_candidate_file, opened_file_id, DetectionEngine, DetectionReport, DetectionVerdict,
};
use crate::history::{EventHistory, EventKind, SecurityEvent};
use crate::quarantine::{IsolationState, QuarantineRecord, QuarantineStore};
use crate::trust;
use std::collections::HashMap;
use std::ffi::c_void;
use std::fs::File;
use std::mem;
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicIsize, Ordering};
use std::sync::{mpsc, Arc, Mutex, RwLock};
use std::thread::{self, JoinHandle};
use std::time::Duration;
use windows_sys::Win32::Foundation::{
    CloseHandle, DuplicateHandle, DUPLICATE_SAME_ACCESS, HANDLE, S_OK,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
};

const BLACKSHARD_PROTOCOL_MAGIC: u32 = 0x3548_5342;
const BLACKSHARD_PROTOCOL_VERSION: u16 = 5;
const OPERATION_PROTECTED_WRITE: u32 = 3;
const OPERATION_PROTECTED_METADATA: u32 = 4;
const MAX_FILE_PATH_LENGTH: usize = 1024;
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

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

    fn FilterSendMessage(
        port: HANDLE,
        input: *const c_void,
        input_size: u32,
        output: *mut c_void,
        output_size: u32,
        bytes_returned: *mut u32,
    ) -> i32;
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct DriverControlRequest {
    magic: u32,
    version: u16,
    size: u16,
    command: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct DriverHealthReply {
    magic: u32,
    version: u16,
    size: u16,
    scan_requests: u64,
    blocks: u64,
    timeouts: u64,
    service_unavailable_bypasses: u64,
    object_resolution_bypasses: u64,
    oversize_path_bypasses: u64,
    irql_bypasses: u64,
    invalid_replies: u64,
    dirty_writes: u64,
    enforcement_bypasses: u64,
    content_race_blocks: u64,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct DriverHealthCounters {
    pub scan_requests: u64,
    pub blocks: u64,
    pub timeouts: u64,
    pub service_unavailable_bypasses: u64,
    pub object_resolution_bypasses: u64,
    pub oversize_path_bypasses: u64,
    pub irql_bypasses: u64,
    pub invalid_replies: u64,
    pub dirty_writes: u64,
    pub enforcement_bypasses: u64,
    pub content_race_blocks: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct FilterMessageHeader {
    reply_length: u32,
    message_id: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct FilterReplyHeader {
    status: i32,
    message_id: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct BlackshardNotification {
    magic: u32,
    version: u16,
    size: u16,
    process_id: u32,
    desired_access: u32,
    operation: u32,
    path_length: u32,
    file_path: [u16; MAX_FILE_PATH_LENGTH],
    file_id: u64,
    content_generation: u64,
    process_start_key: u64,
    must_enforce: u32,
    reserved: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct BlackshardMessage {
    header: FilterMessageHeader,
    notification: BlackshardNotification,
}

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DriverVerdict {
    Allow = 0,
    Block = 1,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct BlackshardReplyMessage {
    header: FilterReplyHeader,
    magic: u32,
    version: u16,
    size: u16,
    verdict: DriverVerdict,
    risk_score: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtectionConnection {
    Connecting,
    Connected,
    Disconnected(String),
    Stopped,
}

#[derive(Debug, Clone)]
pub struct RealtimeDecision {
    pub process_id: u32,
    pub path: PathBuf,
    pub report: DetectionReport,
    /// True only when Filter Manager accepted the block reply before timeout.
    pub block_reply_accepted: bool,
    pub quarantine: Option<QuarantineRecord>,
    pub action_error: Option<String>,
}

#[derive(Debug, Clone)]
pub enum RealtimeEvent {
    Connection(ProtectionConnection),
    Decision(Box<RealtimeDecision>),
    QueueSaturated { process_id: u32, path: PathBuf },
}

#[derive(Debug, Clone, Default)]
pub struct RealtimeCounters {
    pub scanned: u64,
    pub suspicious: u64,
    pub detected: u64,
    pub blocked_replies: u64,
    pub quarantined: u64,
    pub scan_errors: u64,
    pub bypassed_due_to_load: u64,
}

/// Atomically replaceable detector used by the service. Scan workers clone the
/// current immutable engine for each item, so a signed definition activation
/// never invalidates an in-flight decision.
pub type SharedDetectionEngine = Arc<RwLock<Arc<DetectionEngine>>>;

pub fn new_shared_detection_engine(engine: DetectionEngine) -> SharedDetectionEngine {
    Arc::new(RwLock::new(Arc::new(engine)))
}

pub fn replace_detection_engine(shared: &SharedDetectionEngine, engine: DetectionEngine) {
    let mut active = shared
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *active = Arc::new(engine);
}

pub struct RealtimeProtection {
    stop: Arc<AtomicBool>,
    port: Arc<AtomicIsize>,
    worker: Option<JoinHandle<()>>,
    pub counters: Arc<Mutex<RealtimeCounters>>,
}

impl RealtimeProtection {
    pub fn start(
        engine: SharedDetectionEngine,
        quarantine: Arc<QuarantineStore>,
        history: Arc<EventHistory>,
        settings: Arc<RwLock<Settings>>,
        events: mpsc::SyncSender<RealtimeEvent>,
    ) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let port = Arc::new(AtomicIsize::new(0));
        let counters = Arc::new(Mutex::new(RealtimeCounters::default()));
        let worker_stop = Arc::clone(&stop);
        let worker_port = Arc::clone(&port);
        let worker_counters = Arc::clone(&counters);
        let worker = thread::spawn(move || {
            connection_loop(
                engine,
                quarantine,
                history,
                settings,
                events,
                worker_counters,
                worker_stop,
                worker_port,
            )
        });

        Self {
            stop,
            port,
            worker: Some(worker),
            counters,
        }
    }

    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let handle = self.port.swap(0, Ordering::AcqRel);
        if handle != 0 {
            unsafe { CloseHandle(handle) };
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }

    pub fn driver_health(&self) -> Result<DriverHealthCounters, String> {
        let port = self.port.load(Ordering::Acquire);
        if port == 0 {
            return Err("the kernel communication port is not connected".to_owned());
        }
        let process = unsafe { GetCurrentProcess() };
        let mut duplicated = 0;
        if unsafe {
            DuplicateHandle(
                process,
                port,
                process,
                &mut duplicated,
                0,
                0,
                DUPLICATE_SAME_ACCESS,
            )
        } == 0
        {
            return Err(format!(
                "could not duplicate the kernel communication handle: {}",
                std::io::Error::last_os_error()
            ));
        }

        let request = DriverControlRequest {
            magic: BLACKSHARD_PROTOCOL_MAGIC,
            version: BLACKSHARD_PROTOCOL_VERSION,
            size: mem::size_of::<DriverControlRequest>() as u16,
            command: 1,
        };
        let mut reply = unsafe { mem::zeroed::<DriverHealthReply>() };
        let mut returned = 0u32;
        let result = unsafe {
            FilterSendMessage(
                duplicated,
                (&request as *const DriverControlRequest).cast(),
                mem::size_of::<DriverControlRequest>() as u32,
                (&mut reply as *mut DriverHealthReply).cast(),
                mem::size_of::<DriverHealthReply>() as u32,
                &mut returned,
            )
        };
        unsafe { CloseHandle(duplicated) };
        if result != S_OK {
            return Err(hresult_text(result));
        }
        if returned as usize != mem::size_of::<DriverHealthReply>()
            || reply.magic != BLACKSHARD_PROTOCOL_MAGIC
            || reply.version != BLACKSHARD_PROTOCOL_VERSION
            || reply.size as usize != mem::size_of::<DriverHealthReply>()
        {
            return Err("the minifilter returned an invalid health record".to_owned());
        }
        Ok(DriverHealthCounters {
            scan_requests: reply.scan_requests,
            blocks: reply.blocks,
            timeouts: reply.timeouts,
            service_unavailable_bypasses: reply.service_unavailable_bypasses,
            object_resolution_bypasses: reply.object_resolution_bypasses,
            oversize_path_bypasses: reply.oversize_path_bypasses,
            irql_bypasses: reply.irql_bypasses,
            invalid_replies: reply.invalid_replies,
            dirty_writes: reply.dirty_writes,
            enforcement_bypasses: reply.enforcement_bypasses,
            content_race_blocks: reply.content_race_blocks,
        })
    }
}

impl Drop for RealtimeProtection {
    fn drop(&mut self) {
        self.stop();
    }
}

#[derive(Clone, Copy)]
struct WorkItem {
    port: HANDLE,
    message: BlackshardMessage,
}

#[allow(clippy::too_many_arguments)]
fn connection_loop(
    engine: SharedDetectionEngine,
    quarantine: Arc<QuarantineStore>,
    history: Arc<EventHistory>,
    settings: Arc<RwLock<Settings>>,
    events: mpsc::SyncSender<RealtimeEvent>,
    counters: Arc<Mutex<RealtimeCounters>>,
    stop: Arc<AtomicBool>,
    published_port: Arc<AtomicIsize>,
) {
    let port_name: Vec<u16> = "\\BlackshardPort\0".encode_utf16().collect();
    let ransomware_monitor = Arc::new(Mutex::new(RansomwareMonitor::default()));
    let process_trust_cache = Arc::new(Mutex::new(HashMap::new()));
    while !stop.load(Ordering::Acquire) {
        let _ = events.try_send(RealtimeEvent::Connection(ProtectionConnection::Connecting));
        let mut port_handle: HANDLE = 0;
        let connect_result = unsafe {
            FilterConnectCommunicationPort(
                port_name.as_ptr(),
                0,
                ptr::null(),
                0,
                ptr::null(),
                &mut port_handle,
            )
        };
        if connect_result != S_OK {
            let error_text = hresult_text(connect_result);
            log::error!("FilterConnectCommunicationPort failed: connect {error_text}");
            let _ = events.try_send(RealtimeEvent::Connection(
                ProtectionConnection::Disconnected(format!("connect {error_text}")),
            ));
            interruptible_wait(&stop, Duration::from_secs(2));
            continue;
        }

        published_port.store(port_handle, Ordering::Release);
        log::info!("Kernel real-time protection connected via FilterConnectCommunicationPort");
        let _ = history.append(&SecurityEvent::new(
            EventKind::ProtectionStarted,
            "Kernel real-time protection connected",
        ));
        let _ = events.try_send(RealtimeEvent::Connection(ProtectionConnection::Connected));

        let worker_count = settings
            .read()
            .map(|value| value.worker_count.clamp(1, 8))
            .unwrap_or(2);
        let (sender, receiver) = mpsc::sync_channel::<WorkItem>(worker_count * 16);
        let receiver = Arc::new(Mutex::new(receiver));
        let mut scan_workers = Vec::with_capacity(worker_count);
        for _ in 0..worker_count {
            let receiver = Arc::clone(&receiver);
            let engine = Arc::clone(&engine);
            let quarantine = Arc::clone(&quarantine);
            let history = Arc::clone(&history);
            let settings = Arc::clone(&settings);
            let events = events.clone();
            let counters = Arc::clone(&counters);
            let worker_stop = Arc::clone(&stop);
            let ransomware_monitor = Arc::clone(&ransomware_monitor);
            let process_trust_cache = Arc::clone(&process_trust_cache);
            scan_workers.push(thread::spawn(move || {
                realtime_worker(
                    receiver,
                    engine,
                    quarantine,
                    history,
                    settings,
                    events,
                    counters,
                    worker_stop,
                    ransomware_monitor,
                    process_trust_cache,
                )
            }));
        }
        let disconnect_reason = loop {
            if stop.load(Ordering::Acquire) {
                break "real-time protection stopped".to_owned();
            }

            #[repr(C, align(16))]
            struct AlignedMessage(BlackshardMessage);

            let mut message = unsafe { mem::zeroed::<AlignedMessage>() };
            let get_result = unsafe {
                FilterGetMessage(
                    port_handle,
                    &mut message as *mut _ as *mut c_void,
                    mem::size_of::<BlackshardMessage>() as u32,
                    ptr::null_mut(),
                )
            };
            if get_result != S_OK {
                let error_text = hresult_text(get_result);
                log::error!("FilterGetMessage failed: get {error_text}");
                break format!("get {error_text}");
            }

            let message = message.0;
            if !valid_notification(&message.notification) {
                let _ = reply(
                    port_handle,
                    message.header.message_id,
                    DriverVerdict::Allow,
                    0,
                );
                continue;
            }

            let path = notification_path(&message.notification);
            let item = WorkItem {
                port: port_handle,
                message,
            };
            match sender.try_send(item) {
                Ok(()) => {}
                Err(mpsc::TrySendError::Full(item)) => {
                    let overload_verdict = if item.message.notification.must_enforce != 0 {
                        DriverVerdict::Block
                    } else {
                        DriverVerdict::Allow
                    };
                    let accepted = reply(
                        item.port,
                        item.message.header.message_id,
                        overload_verdict,
                        0,
                    );
                    let _ = accepted;
                    if let Ok(mut value) = counters.lock() {
                        value.bypassed_due_to_load += 1;
                    }
                    let _ = events.try_send(RealtimeEvent::QueueSaturated {
                        process_id: item.message.notification.process_id,
                        path,
                    });
                }
                Err(mpsc::TrySendError::Disconnected(item)) => {
                    let disconnected_verdict = if item.message.notification.must_enforce != 0 {
                        DriverVerdict::Block
                    } else {
                        DriverVerdict::Allow
                    };
                    let _ = reply(
                        item.port,
                        item.message.header.message_id,
                        disconnected_verdict,
                        0,
                    );
                    break "real-time scan workers stopped unexpectedly".to_owned();
                }
            }
        };

        drop(sender);
        for worker in scan_workers {
            let _ = worker.join();
        }

        if published_port
            .compare_exchange(port_handle, 0, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            unsafe { CloseHandle(port_handle) };
        }
        let _ = history.append(&SecurityEvent::new(
            EventKind::ProtectionStopped,
            disconnect_reason.clone(),
        ));
        let _ = events.try_send(RealtimeEvent::Connection(if stop.load(Ordering::Acquire) {
            ProtectionConnection::Stopped
        } else {
            ProtectionConnection::Disconnected(disconnect_reason)
        }));
        if !stop.load(Ordering::Acquire) {
            interruptible_wait(&stop, Duration::from_secs(2));
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn realtime_worker(
    receiver: Arc<Mutex<mpsc::Receiver<WorkItem>>>,
    engine: SharedDetectionEngine,
    quarantine: Arc<QuarantineStore>,
    history: Arc<EventHistory>,
    settings: Arc<RwLock<Settings>>,
    events: mpsc::SyncSender<RealtimeEvent>,
    counters: Arc<Mutex<RealtimeCounters>>,
    stop: Arc<AtomicBool>,
    ransomware_monitor: Arc<Mutex<RansomwareMonitor>>,
    process_trust_cache: Arc<Mutex<HashMap<(u32, u64), ProcessTrust>>>,
) {
    loop {
        let item = {
            let receiver = match receiver.lock() {
                Ok(receiver) => receiver,
                Err(_) => return,
            };
            match receiver.recv() {
                Ok(item) => item,
                Err(_) => return,
            }
        };
        if stop.load(Ordering::Acquire) {
            let _ = reply(
                item.port,
                item.message.header.message_id,
                DriverVerdict::Allow,
                0,
            );
            continue;
        }
        let notification = item.message.notification;
        let kernel_path = notification_path(&notification);
        if matches!(
            notification.operation,
            OPERATION_PROTECTED_WRITE | OPERATION_PROTECTED_METADATA
        ) {
            handle_protected_modification(
                &item,
                &notification,
                &kernel_path,
                &settings,
                &history,
                &events,
                &counters,
                &ransomware_monitor,
                &process_trust_cache,
            );
            continue;
        }
        let openable_path = device_path_to_openable_path(&kernel_path);
        let candidate = open_candidate_file(&openable_path);
        let path = candidate
            .as_ref()
            .ok()
            .and_then(|file| opened_final_path(file).ok())
            .unwrap_or_else(|| kernel_path.clone());
        let enabled = settings
            .read()
            .map(|value| value.real_time_protection && !value.is_excluded(&path))
            .unwrap_or(false);
        if !enabled {
            let _ = reply(
                item.port,
                item.message.header.message_id,
                DriverVerdict::Allow,
                0,
            );
            continue;
        }

        let active_engine = {
            let active = engine
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            Arc::clone(&active)
        };
        let report = match candidate {
            Ok(file) => match opened_file_id(&file) {
                Ok(file_id) if file_id == notification.file_id => {
                    active_engine.scan_open_file(&file)
                }
                Ok(file_id) => DetectionReport::error(
                    format!(
                        "kernel/user file identity mismatch (expected {:016x}, opened {:016x})",
                        notification.file_id, file_id
                    ),
                    Duration::ZERO,
                ),
                Err(error) => DetectionReport::error(
                    format!("could not verify the opened file identity: {error}"),
                    Duration::ZERO,
                ),
            },
            Err(error) => DetectionReport::error(
                format!("could not open the exact candidate for analysis: {error}"),
                Duration::ZERO,
            ),
        };
        let driver_verdict = if report.should_block()
            || (notification.must_enforce != 0 && report.verdict == DetectionVerdict::Error)
        {
            DriverVerdict::Block
        } else {
            DriverVerdict::Allow
        };
        let reply_accepted = reply(
            item.port,
            item.message.header.message_id,
            driver_verdict,
            report.risk_score as u32,
        );

        let mut quarantine_record = None;
        let mut action_error = None;
        if report.should_quarantine() {
            let threat_name = report.threat_name.as_deref().unwrap_or("Known.Malware");
            let should_quarantine = settings
                .read()
                .map(|value| value.automatic_quarantine)
                .unwrap_or(true);
            if should_quarantine {
                let quarantine_result = match report.sha256.as_deref() {
                    Some(hash) => quarantine.quarantine_verified(
                        &openable_path,
                        threat_name,
                        report.risk_score,
                        hash,
                        report.file_size,
                        Some(notification.file_id),
                    ),
                    None => Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "the complete file was not hashed; automatic quarantine was withheld",
                    )),
                };
                match quarantine_result {
                    Ok(record) => {
                        let isolated = record.state == IsolationState::Isolated;
                        if isolated {
                            if let Ok(mut value) = counters.lock() {
                                value.quarantined += 1;
                            }
                        } else {
                            action_error = Some(
                                "the source remained after creating a neutralized copy".to_owned(),
                            );
                        }
                        let mut event = SecurityEvent::new(
                            if isolated {
                                EventKind::Quarantined
                            } else {
                                EventKind::QuarantineFailed
                            },
                            if isolated {
                                "Real-time threat moved to quarantine"
                            } else {
                                "Real-time threat blocked; original could not be removed"
                            },
                        );
                        event.path = Some(path.clone());
                        event.threat_name = Some(threat_name.to_owned());
                        event.risk_score = Some(report.risk_score);
                        let _ = history.append(&event);
                        quarantine_record = Some(record);
                    }
                    Err(error) => {
                        action_error = Some(error.to_string());
                        let mut event = SecurityEvent::new(
                            EventKind::QuarantineFailed,
                            "Real-time threat blocked; quarantine failed",
                        );
                        event.path = Some(path.clone());
                        event.threat_name = Some(threat_name.to_owned());
                        event.risk_score = Some(report.risk_score);
                        event.details = action_error.clone();
                        let _ = history.append(&event);
                    }
                }
            }
        }

        if let Ok(mut value) = counters.lock() {
            value.scanned += 1;
            match report.verdict {
                DetectionVerdict::Clean => {}
                DetectionVerdict::Suspicious => value.suspicious += 1,
                DetectionVerdict::Malicious => value.detected += 1,
                DetectionVerdict::Error => value.scan_errors += 1,
            }
            if driver_verdict == DriverVerdict::Block && reply_accepted {
                value.blocked_replies += 1;
            }
        }

        if report.verdict != DetectionVerdict::Clean {
            let mut event = SecurityEvent::new(
                EventKind::Detection,
                match report.verdict {
                    DetectionVerdict::Malicious => "Real-time malicious file detected",
                    DetectionVerdict::Suspicious => "Real-time suspicious file observed",
                    DetectionVerdict::Error => "Real-time scan failed",
                    DetectionVerdict::Clean => unreachable!(),
                },
            );
            event.path = Some(path.clone());
            event.threat_name = report.threat_name.clone();
            event.risk_score = Some(report.risk_score);
            event.details = Some(format!(
                "block_reply_accepted={reply_accepted}; pid={}",
                item.message.notification.process_id
            ));
            let _ = history.append(&event);
        }

        if report.verdict != DetectionVerdict::Clean {
            let _ = events.try_send(RealtimeEvent::Decision(Box::new(RealtimeDecision {
                process_id: notification.process_id,
                path,
                report,
                block_reply_accepted: driver_verdict == DriverVerdict::Block && reply_accepted,
                quarantine: quarantine_record,
                action_error,
            })));
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_protected_modification(
    item: &WorkItem,
    notification: &BlackshardNotification,
    path: &Path,
    settings: &Arc<RwLock<Settings>>,
    history: &Arc<EventHistory>,
    events: &mpsc::SyncSender<RealtimeEvent>,
    counters: &Arc<Mutex<RealtimeCounters>>,
    monitor: &Arc<Mutex<RansomwareMonitor>>,
    trust_cache: &Arc<Mutex<HashMap<(u32, u64), ProcessTrust>>>,
) {
    let (enabled, block_mode) = settings
        .read()
        .map(|settings| {
            (
                settings.real_time_protection
                    && settings.ransomware_protection
                    && !settings.is_excluded(path),
                settings.ransomware_block_mode,
            )
        })
        .unwrap_or((false, false));
    if !enabled {
        let _ = reply(
            item.port,
            item.message.header.message_id,
            DriverVerdict::Allow,
            0,
        );
        return;
    }
    let process_trust = cached_process_trust(
        trust_cache,
        notification.process_id,
        notification.process_start_key,
    );
    let decision = monitor
        .lock()
        .map(|mut monitor| {
            monitor.observe(
                notification.process_id,
                notification.process_start_key,
                path,
                process_trust,
                block_mode,
            )
        })
        .unwrap_or_default();
    let verdict = if decision.block {
        DriverVerdict::Block
    } else {
        DriverVerdict::Allow
    };
    let accepted = reply(
        item.port,
        item.message.header.message_id,
        verdict,
        if decision.alert || decision.block {
            95
        } else {
            0
        },
    );
    if decision.block && accepted {
        if let Ok(mut counters) = counters.lock() {
            counters.blocked_replies += 1;
        }
    }
    if !decision.alert {
        return;
    }

    let report = DetectionReport::ransomware_behavior(
        decision.distinct_files,
        decision.block,
        Duration::ZERO,
    );
    let mut event = SecurityEvent::new(
        EventKind::Detection,
        if decision.block {
            "Ransomware-like mass modification blocked"
        } else {
            "Ransomware-like mass modification observed (audit mode)"
        },
    );
    event.path = Some(path.to_path_buf());
    event.threat_name = report.threat_name.clone();
    event.risk_score = Some(report.risk_score);
    event.details = Some(format!(
        "pid={}; process_start_key={:016x}; operation={}; distinct_protected_files={}; block_mode={block_mode}; block_reply_accepted={accepted}",
        notification.process_id,
        notification.process_start_key,
        if notification.operation == OPERATION_PROTECTED_WRITE {
            "write"
        } else {
            "rename-or-delete"
        },
        decision.distinct_files
    ));
    let _ = history.append(&event);
    let _ = events.try_send(RealtimeEvent::Decision(Box::new(RealtimeDecision {
        process_id: notification.process_id,
        path: path.to_path_buf(),
        report,
        block_reply_accepted: decision.block && accepted,
        quarantine: None,
        action_error: None,
    })));
}

fn cached_process_trust(
    cache: &Mutex<HashMap<(u32, u64), ProcessTrust>>,
    process_id: u32,
    process_start_key: u64,
) -> ProcessTrust {
    let key = (process_id, process_start_key);
    if let Ok(cache) = cache.lock() {
        if let Some(trust) = cache.get(&key) {
            return *trust;
        }
        // Do not let a process-churn workload turn this bounded cache into an
        // unbounded stream of comparatively expensive Authenticode checks.
        // Unknown uses the conservative middle threshold.
        if cache.len() >= 256 {
            return ProcessTrust::Unknown;
        }
    }
    let resolved = process_image_path(process_id)
        .map(|path| match trust::verify_file(&path) {
            trust::AuthenticodeStatus::Trusted { .. } => ProcessTrust::Trusted,
            trust::AuthenticodeStatus::Unsigned | trust::AuthenticodeStatus::Untrusted(_) => {
                ProcessTrust::Untrusted
            }
            trust::AuthenticodeStatus::Error(_) => ProcessTrust::Unknown,
        })
        .unwrap_or(ProcessTrust::Unknown);
    if let Ok(mut cache) = cache.lock() {
        cache.insert(key, resolved);
    }
    resolved
}

fn process_image_path(process_id: u32) -> Option<PathBuf> {
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
    if process == 0 {
        return None;
    }
    let mut buffer = vec![0u16; 32_768];
    let mut length = buffer.len() as u32;
    let succeeded =
        unsafe { QueryFullProcessImageNameW(process, 0, buffer.as_mut_ptr(), &mut length) } != 0;
    unsafe { CloseHandle(process) };
    if !succeeded || length == 0 || length as usize > buffer.len() {
        return None;
    }
    buffer.truncate(length as usize);
    Some(PathBuf::from(String::from_utf16_lossy(&buffer)))
}

fn reply(port: HANDLE, message_id: u64, verdict: DriverVerdict, risk_score: u32) -> bool {
    let mut reply = BlackshardReplyMessage {
        header: FilterReplyHeader {
            status: 0,
            message_id,
        },
        magic: BLACKSHARD_PROTOCOL_MAGIC,
        version: BLACKSHARD_PROTOCOL_VERSION,
        size: (mem::size_of::<BlackshardReplyMessage>() - mem::size_of::<FilterReplyHeader>())
            as u16,
        verdict,
        risk_score,
    };
    unsafe {
        FilterReplyMessage(
            port,
            &mut reply as *mut _ as *mut c_void,
            mem::size_of::<BlackshardReplyMessage>() as u32,
        ) == S_OK
    }
}

fn notification_path(notification: &BlackshardNotification) -> PathBuf {
    let path_length = (notification.path_length as usize).min(MAX_FILE_PATH_LENGTH - 1);
    PathBuf::from(String::from_utf16_lossy(
        &notification.file_path[..path_length],
    ))
}

fn valid_notification(notification: &BlackshardNotification) -> bool {
    notification.magic == BLACKSHARD_PROTOCOL_MAGIC
        && notification.version == BLACKSHARD_PROTOCOL_VERSION
        && notification.size as usize == mem::size_of::<BlackshardNotification>()
        && matches!(notification.operation, 1..=4)
        && notification.file_id != 0
        && notification.content_generation != 0
        && notification.process_start_key != 0
        && ((notification.operation == 1 && notification.must_enforce == 0)
            || (notification.operation == 2 && notification.must_enforce == 1)
            || (matches!(notification.operation, 3..=4) && notification.must_enforce == 0))
        && notification.reserved == 0
        && notification.path_length > 0
        && notification.path_length < MAX_FILE_PATH_LENGTH as u32
}

fn opened_final_path(file: &File) -> std::io::Result<PathBuf> {
    use std::os::windows::io::AsRawHandle;

    #[link(name = "kernel32")]
    extern "system" {
        fn GetFinalPathNameByHandleW(
            file: isize,
            path: *mut u16,
            path_length: u32,
            flags: u32,
        ) -> u32;
    }

    let required =
        unsafe { GetFinalPathNameByHandleW(file.as_raw_handle() as isize, ptr::null_mut(), 0, 0) };
    if required == 0 || required > 32_767 {
        return Err(if required == 0 {
            std::io::Error::last_os_error()
        } else {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "the resolved file path exceeds Windows' long-path limit",
            )
        });
    }
    let mut buffer = vec![0u16; required as usize + 1];
    let written = unsafe {
        GetFinalPathNameByHandleW(
            file.as_raw_handle() as isize,
            buffer.as_mut_ptr(),
            buffer.len() as u32,
            0,
        )
    };
    if written == 0 || written as usize >= buffer.len() {
        return Err(std::io::Error::last_os_error());
    }
    Ok(PathBuf::from(String::from_utf16_lossy(
        &buffer[..written as usize],
    )))
}

fn device_path_to_openable_path(path: &Path) -> PathBuf {
    let display = path.to_string_lossy();
    if display.starts_with("\\Device\\") {
        PathBuf::from(format!("\\\\?\\GLOBALROOT{display}"))
    } else {
        path.to_path_buf()
    }
}

fn hresult_text(hr: i32) -> String {
    match hr as u32 {
        0x8007_0002 => {
            "kernel communication port not found; the signed minifilter is not loaded".to_owned()
        }
        0x8007_0005 => {
            "filter port access denied; the background service must own the connection".to_owned()
        }
        code => format!("filter communication error 0x{code:08X}"),
    }
}

fn interruptible_wait(stop: &AtomicBool, duration: Duration) {
    let steps = (duration.as_millis() / 100).max(1);
    for _ in 0..steps {
        if stop.load(Ordering::Acquire) {
            return;
        }
        thread::sleep(Duration::from_millis(100));
    }
}

pub fn launch_hidden_probe(executable: &Path, argument: &str, path: &Path) -> std::io::Result<i32> {
    use std::os::windows::process::CommandExt;
    let status = std::process::Command::new(executable)
        .arg(argument)
        .arg(path)
        .creation_flags(CREATE_NO_WINDOW)
        .status()?;
    Ok(status.code().unwrap_or(-1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_paths_use_globalroot() {
        assert_eq!(
            device_path_to_openable_path(Path::new(r"\Device\HarddiskVolume3\sample.exe")),
            PathBuf::from(r"\\?\GLOBALROOT\Device\HarddiskVolume3\sample.exe")
        );
    }

    #[test]
    fn protocol_layout_matches_x64_filter_manager_abi() {
        assert_eq!(mem::size_of::<DriverControlRequest>(), 12);
        assert_eq!(mem::size_of::<DriverHealthReply>(), 96);
        assert_eq!(mem::size_of::<FilterMessageHeader>(), 16);
        assert_eq!(mem::size_of::<BlackshardNotification>(), 2104);
        assert_eq!(mem::size_of::<BlackshardMessage>(), 2120);
        assert_eq!(mem::size_of::<FilterReplyHeader>(), 16);
        assert_eq!(mem::size_of::<BlackshardReplyMessage>(), 32);
    }
}
