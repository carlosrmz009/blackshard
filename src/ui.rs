//! Blackshard's desktop shell.
//!
//! The UI deliberately treats runtime health as input from the protection
//! service.  A running window is not evidence that the minifilter, scanner,
//! update trust chain, or independent certification are healthy.

use crate::config::Settings;
use crate::elevation::{self, QuarantineAdminAction};
use crate::history::{EventKind, SecurityEvent};
use crate::ipc::{
    DetectionVerdictView, IpcClient, QuarantineRecordView, RpcErrorCode, ScanFindingView,
    ScanPhaseView, ScanRequestKind, ServiceScanJob,
};
use crate::quarantine::IsolationState;
use chrono::{DateTime, Local, Utc};
use eframe::egui::{self, Align, Color32, FontFamily, FontId, Layout, RichText, Stroke};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use uuid::Uuid;

const BG: Color32 = Color32::from_rgb(8, 11, 9);
const PANEL: Color32 = Color32::from_rgb(13, 17, 14);
const SURFACE: Color32 = Color32::from_rgb(18, 24, 20);
const SURFACE_HOVER: Color32 = Color32::from_rgb(23, 32, 26);
const BORDER: Color32 = Color32::from_rgb(42, 57, 47);
const TEXT: Color32 = Color32::from_rgb(230, 239, 233);
const MUTED: Color32 = Color32::from_rgb(139, 157, 146);
const GREEN: Color32 = Color32::from_rgb(0, 242, 97);
const GREEN_DARK: Color32 = Color32::from_rgb(0, 78, 34);
const AMBER: Color32 = Color32::from_rgb(255, 190, 74);
const RED: Color32 = Color32::from_rgb(255, 82, 98);
const BLUE: Color32 = Color32::from_rgb(85, 175, 255);

const ACTIVITY_LIMIT: usize = 500;
const REFRESH_INTERVAL: Duration = Duration::from_secs(15);
const SETTINGS_SAVE_DEBOUNCE: Duration = Duration::from_millis(650);

/// The actual state of the real-time protection engine, as reported by the
/// background runtime. `Configured` is intentionally not represented here:
/// enabling a setting is not the same as successfully starting protection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtectionStatus {
    Starting,
    Active,
    Paused,
    Degraded(String),
    Unavailable(String),
}

/// State of the kernel minifilter communication channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriverStatus {
    Checking,
    Connected,
    Disconnected(String),
    NotInstalled,
    Error(String),
}

/// Authenticode establishes package identity and integrity. It does not, by
/// itself, mean the antivirus has passed independent efficacy certification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuildTrustStatus {
    Checking,
    AuthenticodeVerified { publisher: String },
    UnsignedDevelopmentBuild,
    VerificationFailed(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertificationStatus {
    NotEvaluated,
    EvaluationInProgress,
    IndependentlyCertified { authority: String },
}

#[derive(Debug, Clone)]
pub enum DefinitionStatus {
    BuiltInOnly {
        version: String,
    },
    Updating {
        current_version: Option<String>,
    },
    Current {
        version: String,
        expires_at: DateTime<Utc>,
    },
    Stale {
        version: String,
        expired_at: DateTime<Utc>,
    },
    Failed(String),
}

/// Handshake for the harmless end-to-end protection test. The UI sets
/// `Requested`; the runtime atomically consumes it with
/// [`take_protection_test_request`] and publishes the final result with
/// [`complete_protection_test`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtectionTestStatus {
    Idle,
    Requested,
    Running,
    Passed(String),
    Failed(String),
}

/// Mutable state shared by the protection runtime and the UI. The runtime
/// should only set `Active`/`Connected` after the corresponding subsystem has
/// completed its own health check.
#[derive(Debug, Clone)]
pub struct UiRuntimeState {
    pub protection: ProtectionStatus,
    pub driver: DriverStatus,
    pub build_trust: BuildTrustStatus,
    pub certification: CertificationStatus,
    pub definitions: DefinitionStatus,
    pub protection_test: ProtectionTestStatus,
    pub realtime_scanned_files: u64,
    pub realtime_blocked_files: u64,
    pub realtime_bypassed_requests: u64,
    pub last_realtime_path: Option<PathBuf>,
    pub desired_real_time_protection: bool,
    pub update_check_requested: bool,
    pub engine_version: String,
    pub freshclam_version: Option<String>,
    pub freshclam_age_hours: Option<u64>,
    pub attention: Option<String>,
    pub readiness: Option<crate::readiness::ReadinessState>,
}

impl Default for UiRuntimeState {
    fn default() -> Self {
        Self {
            protection: ProtectionStatus::Starting,
            driver: DriverStatus::Checking,
            build_trust: BuildTrustStatus::Checking,
            certification: CertificationStatus::NotEvaluated,
            definitions: DefinitionStatus::BuiltInOnly {
                version: "embedded".to_owned(),
            },
            protection_test: ProtectionTestStatus::Idle,
            realtime_scanned_files: 0,
            realtime_blocked_files: 0,
            realtime_bypassed_requests: 0,
            last_realtime_path: None,
            desired_real_time_protection: true,
            update_check_requested: false,
            engine_version: env!("CARGO_PKG_VERSION").to_owned(),
            freshclam_version: None,
            freshclam_age_hours: None,
            attention: None,
            readiness: None,
        }
    }
}

pub type SharedUiState = Arc<Mutex<UiRuntimeState>>;

pub fn new_shared_ui_state() -> SharedUiState {
    Arc::new(Mutex::new(UiRuntimeState::default()))
}

/// Returns true exactly once for each request and moves it to `Running`.
pub fn take_protection_test_request(state: &SharedUiState) -> bool {
    let Ok(mut state) = state.lock() else {
        return false;
    };
    if state.protection_test == ProtectionTestStatus::Requested {
        state.protection_test = ProtectionTestStatus::Running;
        true
    } else {
        false
    }
}

pub fn complete_protection_test(state: &SharedUiState, result: Result<String, String>) {
    if let Ok(mut state) = state.lock() {
        state.protection_test = match result {
            Ok(detail) => ProtectionTestStatus::Passed(detail),
            Err(error) => ProtectionTestStatus::Failed(error),
        };
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Page {
    Dashboard,
    Scan,
    Quarantine,
    Activity,
    Settings,
}

impl Page {
    fn title(self) -> &'static str {
        match self {
            Self::Dashboard => "Dashboard",
            Self::Scan => "Scan",
            Self::Quarantine => "Quarantine",
            Self::Activity => "Activity",
            Self::Settings => "Settings",
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum NoticeLevel {
    Information,
    Success,
    Warning,
    Error,
}

struct Notice {
    level: NoticeLevel,
    message: String,
    created: Instant,
}

#[derive(Clone)]
enum Confirmation {
    Restore(QuarantineRecordView),
    Delete(QuarantineRecordView),
    ClearActivity,
}

#[derive(Debug, Clone, Copy)]
enum QuarantineOperation {
    Restore,
    Delete,
}

struct QuarantineOutcome {
    id: Uuid,
    operation: QuarantineOperation,
    result: Result<String, String>,
}

/// Fully stateful eframe application. Construct it after the detection engine
/// and stores are initialized, then pass it to `eframe::run_native`.
pub struct BlackshardApp {
    runtime: SharedUiState,
    client: IpcClient,
    settings: Settings,
    settings_dirty: bool,
    settings_save_at: Option<Instant>,
    page: Page,
    scan_job: Option<ServiceScanJob>,
    last_handled_scan: Option<Uuid>,
    custom_scan_path: String,
    exclusion_input: String,
    quarantine_records: Vec<QuarantineRecordView>,
    activity: Vec<SecurityEvent>,
    persistent_error: Option<String>,
    notice: Option<Notice>,
    confirmation: Option<Confirmation>,
    busy_quarantine: HashSet<Uuid>,
    operation_sender: mpsc::Sender<QuarantineOutcome>,
    operation_receiver: mpsc::Receiver<QuarantineOutcome>,
    refresh_at: Instant,
    theme_applied: bool,
}

impl BlackshardApp {
    pub fn new(runtime: SharedUiState, client: IpcClient) -> Self {
        let (settings, load_warning) = match client.get_settings() {
            Ok(settings) => (settings, None),
            Err(error) => (
                Settings::default(),
                Some(format!(
                    "The protection service could not provide settings; safe display defaults are in use: {error}"
                )),
            ),
        };
        if let Ok(mut shared) = runtime.lock() {
            shared.desired_real_time_protection = settings.real_time_protection;
        }

        let (operation_sender, operation_receiver) = mpsc::channel();
        let mut app = Self {
            runtime,
            client,
            settings,
            settings_dirty: false,
            settings_save_at: None,
            page: Page::Dashboard,
            scan_job: None,
            last_handled_scan: None,
            custom_scan_path: String::new(),
            exclusion_input: String::new(),
            quarantine_records: Vec::new(),
            activity: Vec::new(),
            persistent_error: None,
            notice: load_warning.map(|message| Notice {
                level: NoticeLevel::Warning,
                message,
                created: Instant::now(),
            }),
            confirmation: None,
            busy_quarantine: HashSet::new(),
            operation_sender,
            operation_receiver,
            refresh_at: Instant::now(),
            theme_applied: false,
        };
        app.refresh_persistent_views();
        app
    }

    pub fn with_machine_defaults(runtime: SharedUiState) -> Self {
        Self::new(runtime, IpcClient)
    }

    /// Lets an installer, command-line argument, or future native folder picker
    /// populate the custom target without adding a dialog dependency.
    pub fn set_custom_scan_path(&mut self, path: impl AsRef<Path>) {
        self.custom_scan_path = path.as_ref().display().to_string();
        self.page = Page::Scan;
    }

    pub fn set_page(&mut self, page: Page) {
        self.page = page;
    }

    pub fn runtime_state(&self) -> SharedUiState {
        Arc::clone(&self.runtime)
    }

    fn runtime_snapshot(&self) -> UiRuntimeState {
        match self.runtime.lock() {
            Ok(state) => state.clone(),
            Err(_) => UiRuntimeState {
                protection: ProtectionStatus::Unavailable(
                    "the runtime health channel is unavailable".to_owned(),
                ),
                driver: DriverStatus::Error("the runtime status lock was poisoned".to_owned()),
                attention: Some(
                    "Blackshard cannot verify protection state; restart the application."
                        .to_owned(),
                ),
                ..UiRuntimeState::default()
            },
        }
    }

    fn refresh_persistent_views(&mut self) {
        let mut errors = Vec::new();
        match self.client.list_quarantine() {
            Ok(records) => self.quarantine_records = records,
            Err(error) => errors.push(format!("Could not read quarantine: {error}")),
        }
        match self.client.recent_activity(ACTIVITY_LIMIT) {
            Ok(events) => self.activity = events,
            Err(error) => errors.push(format!("Could not read activity history: {error}")),
        }
        self.persistent_error = if errors.is_empty() {
            None
        } else {
            Some(errors.join("  "))
        };
        self.refresh_at = Instant::now() + REFRESH_INTERVAL;
    }

    fn poll_background_work(&mut self) {
        while let Ok(outcome) = self.operation_receiver.try_recv() {
            self.busy_quarantine.remove(&outcome.id);
            let action = match outcome.operation {
                QuarantineOperation::Restore => "Restore",
                QuarantineOperation::Delete => "Delete",
            };
            self.notice = Some(match outcome.result {
                Ok(detail) => Notice {
                    level: NoticeLevel::Success,
                    message: format!("{action} completed. {detail}"),
                    created: Instant::now(),
                },
                Err(error) => Notice {
                    level: NoticeLevel::Error,
                    message: format!("{action} failed: {error}"),
                    created: Instant::now(),
                },
            });
            self.refresh_persistent_views();
        }

        let completed_scan = self.scan_job.as_ref().and_then(|job| {
            let snapshot = job.snapshot();
            (snapshot.is_finished() && self.last_handled_scan != Some(snapshot.id))
                .then_some(snapshot.id)
        });
        if let Some(id) = completed_scan {
            if let Some(job) = self.scan_job.as_mut() {
                job.join_if_finished();
            }
            self.last_handled_scan = Some(id);
            self.refresh_persistent_views();
        }

        if Instant::now() >= self.refresh_at {
            self.refresh_persistent_views();
        }

        if self
            .settings_save_at
            .is_some_and(|deadline| Instant::now() >= deadline)
        {
            self.save_settings();
        }

        if self
            .notice
            .as_ref()
            .is_some_and(|notice| notice.created.elapsed() > Duration::from_secs(10))
        {
            self.notice = None;
        }
    }

    fn start_scan(&mut self, kind: ScanRequestKind) {
        let already_running = self
            .scan_job
            .as_ref()
            .is_some_and(|job| !job.snapshot().is_finished());
        if already_running {
            self.notice = Some(Notice {
                level: NoticeLevel::Warning,
                message: "A scan is already running. Cancel it before starting another.".to_owned(),
                created: Instant::now(),
            });
            return;
        }

        self.last_handled_scan = None;
        self.scan_job = match ServiceScanJob::start(self.client.clone(), kind) {
            Ok(job) => Some(job),
            Err(error) => {
                self.notice = Some(Notice {
                    level: NoticeLevel::Error,
                    message: format!("Scan could not start: {error}"),
                    created: Instant::now(),
                });
                return;
            }
        };
        self.page = Page::Scan;
        self.notice = Some(Notice {
            level: NoticeLevel::Information,
            message: "Scan started. Blackshard will continue while you view other pages."
                .to_owned(),
            created: Instant::now(),
        });
    }

    fn start_custom_scan(&mut self) {
        let value = self.custom_scan_path.trim().trim_matches('"');
        if value.is_empty() {
            self.notice = Some(Notice {
                level: NoticeLevel::Warning,
                message: "Enter a file or folder path for the custom scan.".to_owned(),
                created: Instant::now(),
            });
            return;
        }
        let path = PathBuf::from(value);
        if !path.exists() {
            self.notice = Some(Notice {
                level: NoticeLevel::Error,
                message: format!("The custom scan target does not exist: {}", path.display()),
                created: Instant::now(),
            });
            return;
        }
        self.start_scan(ScanRequestKind::Custom {
            roots: vec![path.to_string_lossy().into_owned()],
        });
    }

    fn save_settings(&mut self) {
        self.settings_save_at = None;
        match self.client.save_settings(self.settings.clone()) {
            Ok(_) => {
                self.settings_dirty = false;
                if let Ok(mut runtime) = self.runtime.lock() {
                    runtime.desired_real_time_protection = self.settings.real_time_protection;
                }
                self.notice = Some(Notice {
                    level: NoticeLevel::Success,
                    message: "Settings saved.".to_owned(),
                    created: Instant::now(),
                });
            }
            Err(error) if error.code == RpcErrorCode::AccessDenied => {
                self.settings_dirty = false;
                self.notice = Some(match elevation::request_save_settings(&self.settings) {
                    Ok(()) => Notice {
                        level: NoticeLevel::Information,
                        message: "Approve the Windows administrator prompt to apply these machine protection settings.".to_owned(),
                        created: Instant::now(),
                    },
                    Err(error) => Notice {
                        level: NoticeLevel::Error,
                        message: format!("Administrator approval could not be requested: {error}"),
                        created: Instant::now(),
                    },
                });
            }
            Err(error) => {
                self.notice = Some(Notice {
                    level: NoticeLevel::Error,
                    message: format!("Settings could not be saved: {error}"),
                    created: Instant::now(),
                });
            }
        }
    }

    fn queue_settings_save(&mut self) {
        self.settings_dirty = true;
        self.settings_save_at = Some(Instant::now() + SETTINGS_SAVE_DEBOUNCE);
        if let Ok(mut runtime) = self.runtime.lock() {
            runtime.desired_real_time_protection = self.settings.real_time_protection;
        }
    }

    fn begin_quarantine_operation(&mut self, operation: QuarantineOperation, id: Uuid) {
        if !self.busy_quarantine.insert(id) {
            return;
        }
        let client = self.client.clone();
        let sender = self.operation_sender.clone();
        thread::spawn(move || {
            let result = match operation {
                QuarantineOperation::Restore => client.restore_quarantine(id),
                QuarantineOperation::Delete => client.delete_quarantine(id),
            }
            .or_else(|error| {
                if error.code != RpcErrorCode::AccessDenied {
                    return Err(error.to_string());
                }
                let action = match operation {
                    QuarantineOperation::Restore => QuarantineAdminAction::Restore,
                    QuarantineOperation::Delete => QuarantineAdminAction::Delete,
                };
                elevation::request_quarantine_action(action, id).map(|()| {
                    "Approve the Windows administrator prompt; the list will refresh automatically."
                        .to_owned()
                })
            })
            .map_err(|error| error.to_string());
            let _ = sender.send(QuarantineOutcome {
                id,
                operation,
                result,
            });
        });
    }

    fn apply_theme(ctx: &egui::Context) {
        let mut visuals = egui::Visuals::dark();
        visuals.override_text_color = Some(TEXT);
        visuals.panel_fill = BG;
        visuals.window_fill = PANEL;
        visuals.extreme_bg_color = Color32::from_rgb(7, 9, 8);
        visuals.faint_bg_color = SURFACE;
        visuals.selection.bg_fill = GREEN_DARK;
        visuals.selection.stroke = Stroke::new(1.0_f32, GREEN);
        visuals.hyperlink_color = GREEN;
        visuals.warn_fg_color = AMBER;
        visuals.error_fg_color = RED;
        visuals.widgets.noninteractive.bg_fill = SURFACE;
        visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0_f32, BORDER);
        visuals.widgets.inactive.bg_fill = SURFACE;
        visuals.widgets.inactive.bg_stroke = Stroke::new(1.0_f32, BORDER);
        visuals.widgets.hovered.bg_fill = SURFACE_HOVER;
        visuals.widgets.hovered.bg_stroke = Stroke::new(1.0_f32, GREEN_DARK);
        visuals.widgets.active.bg_fill = GREEN_DARK;
        visuals.widgets.active.bg_stroke = Stroke::new(1.0_f32, GREEN);
        visuals.widgets.open.bg_fill = SURFACE_HOVER;
        visuals.widgets.open.bg_stroke = Stroke::new(1.0_f32, GREEN);

        let mut style = (*ctx.style()).clone();
        style.visuals = visuals;
        style.spacing.item_spacing = egui::vec2(10.0, 9.0);
        style.spacing.button_padding = egui::vec2(14.0, 8.0);
        style.spacing.interact_size.y = 34.0;
        style.text_styles.insert(
            egui::TextStyle::Heading,
            FontId::new(26.0, FontFamily::Monospace),
        );
        style.text_styles.insert(
            egui::TextStyle::Button,
            FontId::new(14.0, FontFamily::Monospace),
        );
        ctx.set_style(style);
    }

    fn render_top_bar(&mut self, ui: &mut egui::Ui, runtime: &UiRuntimeState) {
        ui.add_space(9.0);
        ui.horizontal(|ui| {
            ui.label(
                RichText::new("BLACKSHARD")
                    .family(FontFamily::Monospace)
                    .size(21.0)
                    .strong()
                    .color(GREEN),
            );
            ui.label(
                RichText::new("// WINDOWS SECURITY")
                    .family(FontFamily::Monospace)
                    .size(13.0)
                    .color(MUTED),
            );
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                let (label, color) = compact_health(runtime);
                status_pill(ui, &label, color);
                ui.label(
                    RichText::new(format!("ENGINE {}", runtime.engine_version))
                        .family(FontFamily::Monospace)
                        .size(11.0)
                        .color(MUTED),
                );
            });
        });
        ui.add_space(8.0);
    }

    fn render_sidebar(&mut self, ui: &mut egui::Ui) {
        ui.add_space(18.0);
        ui.label(
            RichText::new("CONTROL CENTER")
                .family(FontFamily::Monospace)
                .size(11.0)
                .color(MUTED),
        );
        ui.add_space(10.0);
        for (page, glyph) in [
            (Page::Dashboard, "//"),
            (Page::Scan, ">>"),
            (Page::Quarantine, "[]"),
            (Page::Activity, "::"),
            (Page::Settings, "=="),
        ] {
            let selected = self.page == page;
            let text = RichText::new(format!("{glyph}  {}", page.title()))
                .family(FontFamily::Monospace)
                .color(if selected { GREEN } else { TEXT });
            let button = egui::Button::new(text)
                .fill(if selected {
                    GREEN_DARK
                } else {
                    Color32::TRANSPARENT
                })
                .stroke(if selected {
                    Stroke::new(1.0_f32, GREEN)
                } else {
                    Stroke::NONE
                })
                .min_size(egui::vec2(ui.available_width(), 40.0));
            if ui.add(button).clicked() {
                self.page = page;
            }
        }

        ui.with_layout(Layout::bottom_up(Align::LEFT), |ui| {
            ui.add_space(14.0);
            ui.label(
                RichText::new("OPEN-SOURCE ENDPOINT DEFENSE")
                    .family(FontFamily::Monospace)
                    .size(9.5)
                    .color(MUTED),
            );
            ui.label(
                RichText::new("PHASE 1 // WINDOWS CLIENT")
                    .family(FontFamily::Monospace)
                    .size(10.0)
                    .color(GREEN),
            );
        });
    }

    fn render_notice(&mut self, ui: &mut egui::Ui) {
        let Some(notice) = &self.notice else {
            return;
        };
        let (label, color) = match notice.level {
            NoticeLevel::Information => ("INFO", BLUE),
            NoticeLevel::Success => ("OK", GREEN),
            NoticeLevel::Warning => ("ATTENTION", AMBER),
            NoticeLevel::Error => ("ERROR", RED),
        };
        egui::Frame::none()
            .fill(color.gamma_multiply(0.10))
            .stroke(Stroke::new(1.0_f32, color.gamma_multiply(0.65)))
            .rounding(egui::Rounding::same(6.0))
            .inner_margin(egui::Margin::symmetric(12.0, 9.0))
            .show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.label(
                        RichText::new(label)
                            .family(FontFamily::Monospace)
                            .strong()
                            .color(color),
                    );
                    ui.label(&notice.message);
                });
            });
        ui.add_space(8.0);
    }

    fn render_dashboard(&mut self, ui: &mut egui::Ui, runtime: &UiRuntimeState) {
        page_heading(
            ui,
            "Security overview",
            "Verified runtime state, recent activity, and fast actions.",
        );

        let (health, detail, color) = overall_health(runtime);
        let test_available = matches!(runtime.protection, ProtectionStatus::Active)
            && matches!(runtime.driver, DriverStatus::Connected);
        let test_busy = matches!(
            runtime.protection_test,
            ProtectionTestStatus::Requested | ProtectionTestStatus::Running
        );
        let mut protection_test_requested = false;
        card(ui, |ui| {
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    ui.label(
                        RichText::new(&health)
                            .family(FontFamily::Monospace)
                            .size(23.0)
                            .strong()
                            .color(color),
                    );
                    ui.label(RichText::new(detail).color(TEXT));
                });
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.label(
                        RichText::new("[+]")
                            .family(FontFamily::Monospace)
                            .size(42.0)
                            .color(color),
                    );
                });
            });
            if let Some(attention) = &runtime.attention {
                ui.add_space(8.0);
                ui.colored_label(AMBER, attention);
            }
            ui.add_space(8.0);
            ui.separator();
            ui.horizontal_wrapped(|ui| {
                if ui
                    .add_enabled(
                        test_available && !test_busy,
                        egui::Button::new("RUN HARMLESS PROTECTION TEST"),
                    )
                    .on_hover_text(
                        "Checks the complete user-mode and kernel blocking path without malware",
                    )
                    .clicked()
                {
                    protection_test_requested = true;
                }
                match &runtime.protection_test {
                    ProtectionTestStatus::Idle if !test_available => {
                        ui.colored_label(MUTED, "Requires an active engine and connected filter");
                    }
                    ProtectionTestStatus::Idle => {
                        ui.colored_label(MUTED, "Not run this session");
                    }
                    ProtectionTestStatus::Requested => {
                        ui.spinner();
                        ui.colored_label(BLUE, "Test queued");
                    }
                    ProtectionTestStatus::Running => {
                        ui.spinner();
                        ui.colored_label(BLUE, "Testing the protection path");
                    }
                    ProtectionTestStatus::Passed(detail) => {
                        ui.colored_label(GREEN, format!("PASSED - {detail}"));
                    }
                    ProtectionTestStatus::Failed(error) => {
                        ui.colored_label(RED, format!("FAILED - {error}"));
                    }
                }
            });
        });
        if protection_test_requested {
            if let Ok(mut state) = self.runtime.lock() {
                state.protection_test = ProtectionTestStatus::Requested;
            }
        }
        ui.add_space(12.0);

        ui.columns(4, |columns| {
            stat_card(
                &mut columns[0],
                "REAL-TIME SCANNED",
                &runtime.realtime_scanned_files.to_string(),
                MUTED,
            );
            stat_card(
                &mut columns[1],
                "THREATS BLOCKED",
                &runtime.realtime_blocked_files.to_string(),
                if runtime.realtime_blocked_files > 0 {
                    RED
                } else {
                    GREEN
                },
            );
            stat_card(
                &mut columns[2],
                "DEGRADED EVENTS",
                &runtime.realtime_bypassed_requests.to_string(),
                if runtime.realtime_bypassed_requests > 0 {
                    AMBER
                } else {
                    GREEN
                },
            );
            stat_card(
                &mut columns[3],
                "IN QUARANTINE",
                &self.quarantine_records.len().to_string(),
                if self.quarantine_records.is_empty() {
                    GREEN
                } else {
                    AMBER
                },
            );
        });
        ui.add_space(12.0);

        let mut scan_request = None;
        card(ui, |ui| {
            section_title(
                ui,
                "RUN A SCAN",
                "Select a scope. Scans run at low priority by default.",
            );
            ui.add_space(6.0);
            ui.columns(3, |columns| {
                if action_tile(
                    &mut columns[0],
                    "QUICK SCAN",
                    "Startup, downloads, desktop, and temporary locations",
                    GREEN,
                ) {
                    scan_request = Some(ScanRequestKind::Quick);
                }
                if action_tile(
                    &mut columns[1],
                    "FULL SCAN",
                    "Every accessible local volume",
                    BLUE,
                ) {
                    scan_request = Some(ScanRequestKind::Full);
                }
                if action_tile(
                    &mut columns[2],
                    "CUSTOM SCAN",
                    "Choose an exact file or folder",
                    MUTED,
                ) {
                    self.page = Page::Scan;
                }
            });
        });
        if let Some(kind) = scan_request {
            self.start_scan(kind);
        }
        ui.add_space(12.0);

        ui.columns(2, |columns| {
            card(&mut columns[0], |ui| {
                section_title(ui, "PROTECTION LAYERS", "Actual subsystem state");
                health_row(ui, "Real-time engine", protection_label(&runtime.protection));
                health_row(ui, "Kernel minifilter", driver_label(&runtime.driver));
                if let (Some(version), Some(age)) = (&runtime.freshclam_version, runtime.freshclam_age_hours) {
                    health_row(ui, "FreshClam DB", (format!("v{} ({}h old)", version, age), GREEN));
                } else {
                    health_row(ui, "Definitions", definition_label(&runtime.definitions));
                }
            });
            card(&mut columns[1], |ui| {
                section_title(ui, "RELEASE ASSURANCE", "Identity and independent evaluation");
                health_row(ui, "Package trust", trust_label(&runtime.build_trust));
                health_row(ui, "AV certification", certification_label(&runtime.certification));
                ui.add_space(4.0);
                ui.label(
                    RichText::new(
                        "A valid signature protects package identity; it does not imply independent antivirus certification.",
                    )
                    .size(11.0)
                    .color(MUTED),
                );
            });
        });
        ui.add_space(12.0);

        card(ui, |ui| {
            section_title(ui, "RECENT ACTIVITY", "Newest security events");
            if self.activity.is_empty() {
                empty_state(ui, "No security events have been recorded yet.");
            } else {
                for event in self.activity.iter().take(5) {
                    activity_row(ui, event);
                }
                if self.activity.len() > 5
                    && ui
                        .button(RichText::new("VIEW ALL ACTIVITY ->").color(GREEN))
                        .clicked()
                {
                    self.page = Page::Activity;
                }
            }
        });
    }

    fn render_scan(&mut self, ui: &mut egui::Ui) {
        page_heading(
            ui,
            "Scan center",
            "Inspect common attack locations, every drive, or an exact target.",
        );

        let running = self
            .scan_job
            .as_ref()
            .is_some_and(|job| !job.snapshot().is_finished());
        let mut requested = None;
        card(ui, |ui| {
            ui.columns(3, |columns| {
                scan_option(
                    &mut columns[0],
                    "QUICK",
                    "High-risk user and startup locations",
                    "Usually a few minutes",
                    GREEN,
                    !running,
                    &mut requested,
                    ScanRequestKind::Quick,
                );
                scan_option(
                    &mut columns[1],
                    "FULL",
                    "All accessible local volumes",
                    "May take significant time",
                    BLUE,
                    !running,
                    &mut requested,
                    ScanRequestKind::Full,
                );
                scan_option(
                    &mut columns[2],
                    "CUSTOM",
                    "One file or directory tree",
                    "Exact scope",
                    MUTED,
                    false,
                    &mut requested,
                    ScanRequestKind::Custom { roots: Vec::new() },
                );
            });
            ui.add_space(12.0);
            ui.label(
                RichText::new("CUSTOM TARGET")
                    .family(FontFamily::Monospace)
                    .size(11.0)
                    .color(MUTED),
            );
            ui.horizontal(|ui| {
                ui.add_sized(
                    [ui.available_width() - 145.0, 36.0],
                    egui::TextEdit::singleline(&mut self.custom_scan_path)
                        .hint_text(r"C:\Users\you\Downloads or C:\path\sample.exe"),
                );
                if ui
                    .add_enabled(!running, egui::Button::new("SCAN TARGET"))
                    .clicked()
                {
                    requested = Some(ScanRequestKind::Custom { roots: Vec::new() });
                }
            });
        });
        if let Some(kind) = requested {
            if matches!(kind, ScanRequestKind::Custom { .. }) {
                self.start_custom_scan();
            } else {
                self.start_scan(kind);
            }
        }

        ui.add_space(12.0);
        let snapshot = self.scan_job.as_ref().map(ServiceScanJob::snapshot);
        let mut cancel_requested = false;
        card(ui, |ui| {
            section_title(ui, "SCAN STATUS", "Live engine progress and results");
            let Some(progress) = snapshot.as_ref() else {
                empty_state(ui, "No scan has run in this session.");
                return;
            };

            let (phase, phase_color) = scan_phase_label(progress.phase);
            ui.horizontal(|ui| {
                status_pill(ui, phase, phase_color);
                ui.label(
                    RichText::new(progress.kind.display_name().to_uppercase())
                        .family(FontFamily::Monospace)
                        .color(TEXT),
                );
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.label(format_duration(Duration::from_millis(
                        progress.elapsed_millis,
                    )));
                });
            });
            ui.add_space(8.0);

            let fraction = if progress.discovered_files > 0 {
                (progress.scanned_files as f32 / progress.discovered_files as f32).clamp(0.0, 1.0)
            } else {
                0.0
            };
            ui.add(
                egui::ProgressBar::new(fraction)
                    .desired_width(ui.available_width())
                    .fill(GREEN)
                    .text(format!(
                        "{} / {} files",
                        progress.scanned_files, progress.discovered_files
                    )),
            );
            if let Some(path) = &progress.current_path {
                ui.label(
                    RichText::new(format!("Current: {path}"))
                        .family(FontFamily::Monospace)
                        .size(11.0)
                        .color(MUTED),
                );
            }
            ui.add_space(6.0);
            ui.horizontal_wrapped(|ui| {
                metric(ui, "Clean", progress.clean_files, GREEN);
                metric(ui, "Suspicious", progress.suspicious_files, AMBER);
                metric(ui, "Malicious", progress.malicious_files, RED);
                metric(ui, "Quarantined", progress.quarantined_files, BLUE);
                metric(ui, "Errors", progress.errors, MUTED);
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if !progress.is_finished()
                        && ui.button(RichText::new("CANCEL SCAN").color(RED)).clicked()
                    {
                        cancel_requested = true;
                    }
                });
            });
            if let Some(failure) = &progress.failure {
                ui.add_space(6.0);
                ui.colored_label(RED, failure);
            }
        });
        if cancel_requested {
            if let Some(job) = &self.scan_job {
                job.cancel();
            }
        }

        if let Some(progress) = snapshot {
            if !progress.findings.is_empty() {
                ui.add_space(12.0);
                card(ui, |ui| {
                    section_title(
                        ui,
                        "FINDINGS",
                        "Suspicious and malicious files, newest engine decisions last",
                    );
                    for finding in progress.findings.iter().rev() {
                        finding_row(ui, finding);
                    }
                });
            }
        }
    }

    fn render_quarantine(&mut self, ui: &mut egui::Ui) {
        page_heading(
            ui,
            "Quarantine",
            "Neutralized files are encrypted and cannot execute from the vault.",
        );
        ui.horizontal(|ui| {
            if ui.button("REFRESH").clicked() {
                self.refresh_persistent_views();
            }
            ui.label(
                RichText::new(
                    "Restore only when you trust the file. Real-time protection may isolate it again.",
                )
                .color(AMBER),
            );
        });
        ui.add_space(10.0);

        if self.quarantine_records.is_empty() {
            card(ui, |ui| empty_state(ui, "Quarantine is empty."));
            return;
        }

        let mut confirmation = None;
        for record in &self.quarantine_records {
            let busy = self.busy_quarantine.contains(&record.id);
            card(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.label(
                            RichText::new(&record.threat_name)
                                .family(FontFamily::Monospace)
                                .strong()
                                .color(RED),
                        );
                        ui.label(RichText::new(&record.original_path).size(12.0).color(TEXT));
                        ui.horizontal_wrapped(|ui| {
                            ui.label(
                                RichText::new(format!(
                                    "{}  |  {}  |  risk {}",
                                    record
                                        .quarantined_at
                                        .with_timezone(&Local)
                                        .format("%Y-%m-%d %H:%M"),
                                    format_bytes(record.size),
                                    record.risk_score
                                ))
                                .size(11.0)
                                .color(MUTED),
                            );
                            let state = match record.state {
                                IsolationState::Isolated => "ISOLATED",
                                IsolationState::SourceStillPresent => "SOURCE STILL PRESENT",
                            };
                            status_pill(
                                ui,
                                state,
                                if record.state == IsolationState::Isolated {
                                    GREEN
                                } else {
                                    RED
                                },
                            );
                        });
                        ui.label(
                            RichText::new(format!("SHA-256 {}", record.sha256))
                                .family(FontFamily::Monospace)
                                .size(10.0)
                                .color(MUTED),
                        );
                    });
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if ui
                            .add_enabled(
                                !busy,
                                egui::Button::new(RichText::new("DELETE").color(RED)),
                            )
                            .clicked()
                        {
                            confirmation = Some(Confirmation::Delete(record.clone()));
                        }
                        if ui
                            .add_enabled(
                                !busy,
                                egui::Button::new(RichText::new("RESTORE").color(AMBER)),
                            )
                            .clicked()
                        {
                            confirmation = Some(Confirmation::Restore(record.clone()));
                        }
                        if busy {
                            ui.spinner();
                        }
                    });
                });
            });
            ui.add_space(8.0);
        }
        if confirmation.is_some() {
            self.confirmation = confirmation;
        }
    }

    fn render_activity(&mut self, ui: &mut egui::Ui) {
        page_heading(
            ui,
            "Activity",
            "Local, append-only security events. Newest entries appear first.",
        );
        ui.horizontal(|ui| {
            if ui.button("REFRESH").clicked() {
                self.refresh_persistent_views();
            }
            if ui
                .add_enabled(
                    !self.activity.is_empty(),
                    egui::Button::new(RichText::new("CLEAR HISTORY").color(RED)),
                )
                .clicked()
            {
                self.confirmation = Some(Confirmation::ClearActivity);
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.label(
                    RichText::new(format!("{} EVENTS SHOWN", self.activity.len()))
                        .family(FontFamily::Monospace)
                        .size(11.0)
                        .color(MUTED),
                );
            });
        });
        ui.add_space(10.0);
        if self.activity.is_empty() {
            card(ui, |ui| empty_state(ui, "No activity has been recorded."));
        } else {
            card(ui, |ui| {
                for event in &self.activity {
                    activity_row(ui, event);
                }
            });
        }
    }

    fn render_settings(&mut self, ui: &mut egui::Ui, runtime: &UiRuntimeState) {
        page_heading(
            ui,
            "Settings",
            "Resource policy, response behavior, updates, and exclusions.",
        );
        let mut changed = false;
        let mut update_requested = false;

        card(ui, |ui| {
            section_title(
                ui,
                "PROTECTION",
                "Configured policy; see the header for actual health",
            );
            changed |= ui
                .checkbox(
                    &mut self.settings.real_time_protection,
                    "Enable real-time protection at startup",
                )
                .changed();
            changed |= ui
                .checkbox(
                    &mut self.settings.automatic_quarantine,
                    "Automatically quarantine confirmed malicious files",
                )
                .changed();
            changed |= ui
                .checkbox(
                    &mut self.settings.notify_on_detection,
                    "Show Windows notifications for detections",
                )
                .changed();
            changed |= ui
                .checkbox(
                    &mut self.settings.scan_archives,
                    "Scan archive container files",
                )
                .changed();
            ui.label(
                RichText::new(
                    "Archive containers are analyzed as files; nested extraction is not enabled in this release.",
                )
                .size(11.0)
                .color(MUTED),
            );
            changed |= ui
                .checkbox(
                    &mut self.settings.scan_network_drives,
                    "Include network drives in scans",
                )
                .changed();
        });
        ui.add_space(10.0);

        card(ui, |ui| {
            section_title(ui, "PERFORMANCE", "Bounded work for low foreground impact");
            changed |= ui
                .checkbox(
                    &mut self.settings.low_resource_mode,
                    "Low-resource mode (recommended)",
                )
                .changed();
            ui.horizontal(|ui| {
                ui.label("Scan workers");
                changed |= ui
                    .add(
                        egui::DragValue::new(&mut self.settings.worker_count)
                            .clamp_range(1..=16)
                            .speed(1),
                    )
                    .changed();
            });
            ui.horizontal(|ui| {
                ui.label("Maximum file size");
                changed |= ui
                    .add(
                        egui::DragValue::new(&mut self.settings.max_file_size_mb)
                            .clamp_range(1..=4_096)
                            .suffix(" MiB"),
                    )
                    .changed();
            });
        });
        ui.add_space(10.0);

        card(ui, |ui| {
            section_title(
                ui,
                "SECURITY UPDATES",
                "Signed definitions with rollback protection",
            );
            ui.horizontal(|ui| {
                ui.label("Check interval");
                changed |= ui
                    .add(
                        egui::DragValue::new(&mut self.settings.definition_update_interval_hours)
                            .clamp_range(1..=24)
                            .suffix(" hours"),
                    )
                    .changed();
                if ui.button("CHECK NOW").clicked() {
                    update_requested = true;
                }
            });
            let (definition, color) = definition_label(&runtime.definitions);
            ui.colored_label(color, definition);
            ui.label(
                RichText::new(
                    "Only authenticated, non-expired updates newer than the installed sequence are accepted.",
                )
                .size(11.0)
                .color(MUTED),
            );
        });
        ui.add_space(10.0);

        card(ui, |ui| {
            section_title(
                ui,
                "EXCLUSIONS",
                "Excluded files are not inspected. Add only paths you fully trust.",
            );
            ui.horizontal(|ui| {
                ui.add_sized(
                    [ui.available_width() - 105.0, 34.0],
                    egui::TextEdit::singleline(&mut self.exclusion_input)
                        .hint_text(r"C:\trusted\path"),
                );
                if ui.button("ADD").clicked() {
                    let value = self.exclusion_input.trim().trim_matches('"');
                    if !value.is_empty() {
                        self.settings.add_exclusion(PathBuf::from(value));
                        self.exclusion_input.clear();
                        changed = true;
                    }
                }
            });
            let mut remove_index = None;
            for (index, exclusion) in self.settings.exclusions.iter().enumerate() {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(exclusion.display().to_string())
                            .family(FontFamily::Monospace)
                            .size(11.0),
                    );
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if ui
                            .small_button(RichText::new("REMOVE").color(RED))
                            .clicked()
                        {
                            remove_index = Some(index);
                        }
                    });
                });
            }
            if let Some(index) = remove_index {
                self.settings.exclusions.remove(index);
                changed = true;
            }
        });
        ui.add_space(10.0);

        card(ui, |ui| {
            section_title(ui, "BUILD ASSURANCE", "Transparent release health");
            health_row(ui, "Authenticode", trust_label(&runtime.build_trust));
            health_row(
                ui,
                "Independent testing",
                certification_label(&runtime.certification),
            );
            ui.add_space(4.0);
            ui.label(
                RichText::new(
                    "Blackshard reports independent certification only when the runtime supplies a named authority. Signed development builds remain clearly identified.",
                )
                .size(11.0)
                .color(MUTED),
            );
        });

        if changed {
            self.queue_settings_save();
        }
        if update_requested {
            if let Ok(mut shared) = self.runtime.lock() {
                shared.update_check_requested = true;
            }
            self.notice = Some(Notice {
                level: NoticeLevel::Information,
                message: "An update check was requested. Runtime status will report the result."
                    .to_owned(),
                created: Instant::now(),
            });
        }
    }

    fn render_confirmation(&mut self, ctx: &egui::Context) {
        let Some(confirmation) = self.confirmation.clone() else {
            return;
        };
        let (title, message, confirm_label, confirm_color) = match &confirmation {
            Confirmation::Restore(record) => (
                "RESTORE QUARANTINED FILE",
                format!(
                    "Restore {} to {}? The file may still be dangerous and can be isolated again by real-time protection.",
                    record.threat_name,
                    record.original_path
                ),
                "RESTORE FILE",
                AMBER,
            ),
            Confirmation::Delete(record) => (
                "PERMANENTLY DELETE FILE",
                format!(
                    "Permanently delete the quarantined copy of {}? This cannot be undone.",
                    record.original_path
                ),
                "DELETE PERMANENTLY",
                RED,
            ),
            Confirmation::ClearActivity => (
                "CLEAR ACTIVITY HISTORY",
                "Delete the local activity history? This does not change quarantine or protection settings."
                    .to_owned(),
                "CLEAR HISTORY",
                RED,
            ),
        };

        let mut accepted = false;
        let mut cancelled = false;
        egui::Window::new(title)
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
            .fixed_size(egui::vec2(460.0, 170.0))
            .show(ctx, |ui| {
                ui.label(message);
                ui.add_space(14.0);
                ui.horizontal(|ui| {
                    if ui
                        .button(RichText::new(confirm_label).color(confirm_color))
                        .clicked()
                    {
                        accepted = true;
                    }
                    if ui.button("CANCEL").clicked() {
                        cancelled = true;
                    }
                });
            });

        if accepted {
            match confirmation {
                Confirmation::Restore(record) => {
                    self.begin_quarantine_operation(QuarantineOperation::Restore, record.id)
                }
                Confirmation::Delete(record) => {
                    self.begin_quarantine_operation(QuarantineOperation::Delete, record.id)
                }
                Confirmation::ClearActivity => match self.client.clear_activity() {
                    Ok(_) => {
                        self.activity.clear();
                        self.notice = Some(Notice {
                            level: NoticeLevel::Success,
                            message: "Activity history cleared.".to_owned(),
                            created: Instant::now(),
                        });
                    }
                    Err(error) if error.code == RpcErrorCode::AccessDenied => {
                        self.notice = Some(match elevation::request_clear_activity() {
                            Ok(()) => Notice {
                                level: NoticeLevel::Information,
                                message: "Approve the Windows administrator prompt to clear machine activity history.".to_owned(),
                                created: Instant::now(),
                            },
                            Err(error) => Notice {
                                level: NoticeLevel::Error,
                                message: format!("Administrator approval could not be requested: {error}"),
                                created: Instant::now(),
                            },
                        });
                    }
                    Err(error) => {
                        self.notice = Some(Notice {
                            level: NoticeLevel::Error,
                            message: format!("Activity history could not be cleared: {error}"),
                            created: Instant::now(),
                        });
                    }
                },
            }
            self.confirmation = None;
        } else if cancelled {
            self.confirmation = None;
        }
    }
}

impl Drop for BlackshardApp {
    fn drop(&mut self) {
        if self.settings_dirty {
            let _ = self.client.save_settings(self.settings.clone());
        }
    }
}

impl eframe::App for BlackshardApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if !self.theme_applied {
            Self::apply_theme(ctx);
            self.theme_applied = true;
        }
        self.poll_background_work();
        let runtime = self.runtime_snapshot();

        if should_show_loading_screen(&runtime) {
            egui::CentralPanel::default()
                .frame(
                    egui::Frame::none()
                        .fill(BG)
                        .inner_margin(egui::Margin::same(22.0)),
                )
                .show(ctx, |ui| {
                    ui.centered_and_justified(|ui| {
                        ui.vertical_centered(|ui| {
                            ui.spinner();
                            ui.add_space(16.0);
                            let status_text = match &runtime.readiness {
                                Some(crate::readiness::ReadinessState::Starting) => "Starting...",
                                Some(crate::readiness::ReadinessState::LoadingSettings) => {
                                    "Loading settings..."
                                }
                                Some(crate::readiness::ReadinessState::LoadingDefinitions) => {
                                    "Loading definitions..."
                                }
                                Some(crate::readiness::ReadinessState::LoadingFreshClam) => {
                                    "Loading definitions..."
                                }
                                Some(
                                    crate::readiness::ReadinessState::StartingDetectionWorkers,
                                ) => "Starting detection workers...",
                                Some(crate::readiness::ReadinessState::ConnectingDriver) => {
                                    "Connecting to driver..."
                                }
                                Some(crate::readiness::ReadinessState::ValidatingProtocol) => {
                                    "Validating protocol..."
                                }
                                Some(crate::readiness::ReadinessState::RunningSelfTest) => {
                                    "Running self test..."
                                }
                                _ => "Starting service...",
                            };
                            ui.label(
                                RichText::new(status_text)
                                    .family(FontFamily::Monospace)
                                    .size(16.0)
                                    .color(MUTED),
                            );
                        });
                    });
                });
            ctx.request_repaint_after(Duration::from_millis(150));
            return;
        }

        egui::TopBottomPanel::top("blackshard_top")
            .exact_height(61.0)
            .frame(
                egui::Frame::none()
                    .fill(PANEL)
                    .stroke(Stroke::new(1.0_f32, BORDER))
                    .inner_margin(egui::Margin::symmetric(18.0, 0.0)),
            )
            .show(ctx, |ui| self.render_top_bar(ui, &runtime));

        egui::SidePanel::left("blackshard_navigation")
            .exact_width(190.0)
            .resizable(false)
            .frame(
                egui::Frame::none()
                    .fill(PANEL)
                    .stroke(Stroke::new(1.0_f32, BORDER))
                    .inner_margin(egui::Margin::symmetric(12.0, 0.0)),
            )
            .show(ctx, |ui| self.render_sidebar(ui));

        egui::CentralPanel::default()
            .frame(
                egui::Frame::none()
                    .fill(BG)
                    .inner_margin(egui::Margin::same(22.0)),
            )
            .show(ctx, |ui| {
                egui::ScrollArea::vertical()
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        self.render_notice(ui);
                        if let Some(error) = &self.persistent_error {
                            ui.colored_label(RED, error);
                            ui.add_space(8.0);
                        }
                        match self.page {
                            Page::Dashboard => self.render_dashboard(ui, &runtime),
                            Page::Scan => self.render_scan(ui),
                            Page::Quarantine => self.render_quarantine(ui),
                            Page::Activity => self.render_activity(ui),
                            Page::Settings => self.render_settings(ui, &runtime),
                        }
                        ui.add_space(24.0);
                    });
            });

        self.render_confirmation(ctx);
        let scan_running = self
            .scan_job
            .as_ref()
            .is_some_and(|job| !job.snapshot().is_finished());
        let operation_running = !self.busy_quarantine.is_empty();
        ctx.request_repaint_after(if scan_running || operation_running {
            Duration::from_millis(150)
        } else {
            Duration::from_secs(1)
        });
    }
}

fn should_show_loading_screen(runtime: &UiRuntimeState) -> bool {
    use crate::readiness::ReadinessState;
    if let Some(readiness) = &runtime.readiness {
        matches!(
            readiness,
            ReadinessState::Starting
                | ReadinessState::LoadingSettings
                | ReadinessState::LoadingDefinitions
                | ReadinessState::LoadingFreshClam
                | ReadinessState::StartingDetectionWorkers
                | ReadinessState::ConnectingDriver
                | ReadinessState::ValidatingProtocol
                | ReadinessState::RunningSelfTest
        )
    } else {
        matches!(runtime.protection, ProtectionStatus::Starting)
    }
}

fn page_heading(ui: &mut egui::Ui, title: &str, subtitle: &str) {
    ui.label(
        RichText::new(title.to_uppercase())
            .family(FontFamily::Monospace)
            .size(25.0)
            .strong()
            .color(TEXT),
    );
    ui.label(RichText::new(subtitle).size(13.0).color(MUTED));
    ui.add_space(16.0);
}

fn section_title(ui: &mut egui::Ui, title: &str, subtitle: &str) {
    ui.horizontal_wrapped(|ui| {
        ui.label(
            RichText::new(title)
                .family(FontFamily::Monospace)
                .size(13.0)
                .strong()
                .color(TEXT),
        );
        ui.label(
            RichText::new(format!("// {subtitle}"))
                .size(11.0)
                .color(MUTED),
        );
    });
}

fn card<R>(ui: &mut egui::Ui, add_contents: impl FnOnce(&mut egui::Ui) -> R) -> R {
    egui::Frame::none()
        .fill(SURFACE)
        .stroke(Stroke::new(1.0_f32, BORDER))
        .rounding(egui::Rounding::same(8.0))
        .inner_margin(egui::Margin::same(15.0))
        .show(ui, add_contents)
        .inner
}

fn status_pill(ui: &mut egui::Ui, label: &str, color: Color32) {
    egui::Frame::none()
        .fill(color.gamma_multiply(0.12))
        .stroke(Stroke::new(1.0_f32, color.gamma_multiply(0.72)))
        .rounding(egui::Rounding::same(10.0))
        .inner_margin(egui::Margin::symmetric(9.0, 4.0))
        .show(ui, |ui| {
            ui.label(
                RichText::new(format!("* {label}"))
                    .family(FontFamily::Monospace)
                    .size(10.5)
                    .strong()
                    .color(color),
            );
        });
}

fn stat_card(ui: &mut egui::Ui, label: &str, value: &str, color: Color32) {
    card(ui, |ui| {
        ui.label(
            RichText::new(label)
                .family(FontFamily::Monospace)
                .size(10.0)
                .color(MUTED),
        );
        ui.label(
            RichText::new(value)
                .family(FontFamily::Monospace)
                .size(28.0)
                .strong()
                .color(color),
        );
    });
}

fn action_tile(ui: &mut egui::Ui, title: &str, detail: &str, color: Color32) -> bool {
    let response = ui.add_sized(
        [ui.available_width(), 68.0],
        egui::Button::new(
            RichText::new(format!("{title}\n{detail}"))
                .family(FontFamily::Monospace)
                .color(color),
        )
        .fill(Color32::from_rgb(14, 20, 16))
        .stroke(Stroke::new(1.0_f32, color.gamma_multiply(0.45))),
    );
    response.clicked()
}

#[allow(clippy::too_many_arguments)]
fn scan_option(
    ui: &mut egui::Ui,
    title: &str,
    detail: &str,
    timing: &str,
    color: Color32,
    enabled: bool,
    request: &mut Option<ScanRequestKind>,
    kind: ScanRequestKind,
) {
    ui.vertical(|ui| {
        ui.label(
            RichText::new(title)
                .family(FontFamily::Monospace)
                .size(17.0)
                .strong()
                .color(color),
        );
        ui.label(RichText::new(detail).size(12.0).color(TEXT));
        ui.label(RichText::new(timing).size(10.5).color(MUTED));
        if !matches!(kind, ScanRequestKind::Custom { .. })
            && ui
                .add_enabled(enabled, egui::Button::new(format!("START {title}")))
                .clicked()
        {
            *request = Some(kind);
        }
    });
}

fn metric(ui: &mut egui::Ui, label: &str, value: u64, color: Color32) {
    ui.label(
        RichText::new(format!("{label} {value}"))
            .family(FontFamily::Monospace)
            .size(11.0)
            .color(color),
    );
}

fn health_row(ui: &mut egui::Ui, label: &str, value: (String, Color32)) {
    ui.horizontal(|ui| {
        ui.label(RichText::new(label).color(MUTED));
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            ui.label(
                RichText::new(value.0)
                    .family(FontFamily::Monospace)
                    .size(10.5)
                    .color(value.1),
            );
        });
    });
}

fn activity_row(ui: &mut egui::Ui, event: &SecurityEvent) {
    let (kind, color) = event_kind_label(&event.kind);
    ui.horizontal(|ui| {
        ui.label(
            RichText::new(
                event
                    .timestamp
                    .with_timezone(&Local)
                    .format("%Y-%m-%d %H:%M:%S")
                    .to_string(),
            )
            .family(FontFamily::Monospace)
            .size(10.5)
            .color(MUTED),
        );
        ui.label(
            RichText::new(kind)
                .family(FontFamily::Monospace)
                .size(10.5)
                .strong()
                .color(color),
        );
        ui.label(&event.summary);
    });
    if event.path.is_some() || event.threat_name.is_some() || event.details.is_some() {
        ui.horizontal_wrapped(|ui| {
            ui.add_space(142.0);
            if let Some(threat) = &event.threat_name {
                ui.colored_label(RED, threat);
            }
            if let Some(path) = &event.path {
                ui.label(
                    RichText::new(path.display().to_string())
                        .size(11.0)
                        .color(MUTED),
                );
            }
            if let Some(details) = &event.details {
                ui.label(RichText::new(details).size(11.0).color(MUTED));
            }
        });
    }
    ui.separator();
}

fn finding_row(ui: &mut egui::Ui, finding: &ScanFindingView) {
    let (verdict, color) = match finding.verdict {
        DetectionVerdictView::Clean => ("CLEAN", GREEN),
        DetectionVerdictView::Suspicious => ("SUSPICIOUS", AMBER),
        DetectionVerdictView::Malicious => ("MALICIOUS", RED),
        DetectionVerdictView::Error => ("SCAN ERROR", MUTED),
    };
    ui.horizontal_wrapped(|ui| {
        status_pill(ui, verdict, color);
        ui.label(
            RichText::new(
                finding
                    .threat_name
                    .as_deref()
                    .unwrap_or("Unclassified finding"),
            )
            .strong()
            .color(color),
        );
        ui.label(
            RichText::new(format!(
                "risk {} | confidence {}%",
                finding.risk_score, finding.confidence
            ))
            .size(11.0)
            .color(MUTED),
        );
    });
    ui.label(
        RichText::new(&finding.path)
            .family(FontFamily::Monospace)
            .size(11.0)
            .color(TEXT),
    );
    if let Some(state) = finding.quarantine_state {
        ui.colored_label(
            if state == IsolationState::Isolated {
                GREEN
            } else {
                RED
            },
            if state == IsolationState::Isolated {
                "Moved to quarantine"
            } else {
                "Neutralized copy created, but the original remains"
            },
        );
    }
    if let Some(error) = &finding.action_error {
        ui.colored_label(RED, format!("Response error: {error}"));
    }
    if let Some(error) = &finding.analysis_error {
        ui.colored_label(MUTED, format!("Analysis note: {error}"));
    }
    ui.separator();
}

fn empty_state(ui: &mut egui::Ui, message: &str) {
    ui.add_space(16.0);
    ui.vertical_centered(|ui| {
        ui.label(
            RichText::new("[ ]")
                .family(FontFamily::Monospace)
                .size(28.0)
                .color(GREEN_DARK),
        );
        ui.label(RichText::new(message).color(MUTED));
    });
    ui.add_space(16.0);
}

fn compact_health(runtime: &UiRuntimeState) -> (String, Color32) {
    match (&runtime.protection, &runtime.driver) {
        (ProtectionStatus::Active, DriverStatus::Connected) => {
            ("PROTECTION ACTIVE".to_owned(), GREEN)
        }
        (ProtectionStatus::Paused, _) => ("PROTECTION PAUSED".to_owned(), AMBER),
        (ProtectionStatus::Unavailable(_), _)
        | (_, DriverStatus::Disconnected(_))
        | (_, DriverStatus::NotInstalled)
        | (_, DriverStatus::Error(_)) => ("PROTECTION LIMITED".to_owned(), RED),
        (ProtectionStatus::Starting, _) | (_, DriverStatus::Checking) => {
            ("VERIFYING PROTECTION".to_owned(), AMBER)
        }
        _ => ("PROTECTION LIMITED".to_owned(), RED),
    }
}

fn overall_health(runtime: &UiRuntimeState) -> (String, String, Color32) {
    match (&runtime.protection, &runtime.driver) {
        (ProtectionStatus::Active, DriverStatus::Connected) => (
            "PROTECTION ACTIVE".to_owned(),
            "The real-time engine and kernel minifilter report a healthy connection.".to_owned(),
            GREEN,
        ),
        (ProtectionStatus::Paused, _) => (
            "PROTECTION PAUSED".to_owned(),
            "Real-time inspection is paused. On-demand scanning remains available.".to_owned(),
            AMBER,
        ),
        (ProtectionStatus::Unavailable(reason), _) => (
            "NOT PROTECTED".to_owned(),
            format!("Real-time protection is unavailable: {reason}"),
            RED,
        ),
        (_, DriverStatus::Disconnected(reason)) | (_, DriverStatus::Error(reason)) => (
            "LIMITED PROTECTION".to_owned(),
            format!("The kernel minifilter is not connected: {reason}"),
            RED,
        ),
        (_, DriverStatus::NotInstalled) => (
            "ON-DEMAND ONLY".to_owned(),
            "The kernel minifilter is not installed; real-time blocking is unavailable.".to_owned(),
            RED,
        ),
        (ProtectionStatus::Degraded(reason), _) => (
            "LIMITED PROTECTION".to_owned(),
            format!("The engine reports degraded protection: {reason}"),
            AMBER,
        ),
        (ProtectionStatus::Starting, _) | (_, DriverStatus::Checking) => (
            "VERIFYING PROTECTION".to_owned(),
            "Blackshard is checking the engine and kernel enforcement channel.".to_owned(),
            AMBER,
        ),
    }
}

fn protection_label(status: &ProtectionStatus) -> (String, Color32) {
    match status {
        ProtectionStatus::Starting => ("STARTING".to_owned(), AMBER),
        ProtectionStatus::Active => ("ACTIVE".to_owned(), GREEN),
        ProtectionStatus::Paused => ("PAUSED".to_owned(), AMBER),
        ProtectionStatus::Degraded(reason) => (format!("DEGRADED | {reason}"), AMBER),
        ProtectionStatus::Unavailable(reason) => (format!("UNAVAILABLE | {reason}"), RED),
    }
}

fn driver_label(status: &DriverStatus) -> (String, Color32) {
    match status {
        DriverStatus::Checking => ("CHECKING".to_owned(), AMBER),
        DriverStatus::Connected => ("CONNECTED".to_owned(), GREEN),
        DriverStatus::Disconnected(reason) => (format!("DISCONNECTED | {reason}"), RED),
        DriverStatus::NotInstalled => ("NOT INSTALLED".to_owned(), RED),
        DriverStatus::Error(reason) => (format!("ERROR | {reason}"), RED),
    }
}

fn trust_label(status: &BuildTrustStatus) -> (String, Color32) {
    match status {
        BuildTrustStatus::Checking => ("CHECKING".to_owned(), AMBER),
        BuildTrustStatus::AuthenticodeVerified { publisher } => {
            (format!("SIGNED | {publisher}"), GREEN)
        }
        BuildTrustStatus::UnsignedDevelopmentBuild => {
            ("UNSIGNED DEVELOPMENT BUILD".to_owned(), AMBER)
        }
        BuildTrustStatus::VerificationFailed(reason) => {
            (format!("SIGNATURE INVALID | {reason}"), RED)
        }
    }
}

fn certification_label(status: &CertificationStatus) -> (String, Color32) {
    match status {
        CertificationStatus::NotEvaluated => ("NOT INDEPENDENTLY EVALUATED".to_owned(), AMBER),
        CertificationStatus::EvaluationInProgress => ("EVALUATION IN PROGRESS".to_owned(), BLUE),
        CertificationStatus::IndependentlyCertified { authority } => {
            (format!("CERTIFIED | {authority}"), GREEN)
        }
    }
}

fn definition_label(status: &DefinitionStatus) -> (String, Color32) {
    match status {
        DefinitionStatus::BuiltInOnly { version } => (format!("BUILT-IN RULES | {version}"), AMBER),
        DefinitionStatus::Updating { current_version } => (
            format!(
                "UPDATING | {}",
                current_version.as_deref().unwrap_or("no installed bundle")
            ),
            BLUE,
        ),
        DefinitionStatus::Current {
            version,
            expires_at,
        } => (
            format!(
                "CURRENT | {version} | EXPIRES {}",
                expires_at.with_timezone(&Local).format("%Y-%m-%d %H:%M")
            ),
            GREEN,
        ),
        DefinitionStatus::Stale {
            version,
            expired_at,
        } => (
            format!(
                "STALE | {version} | EXPIRED {}",
                expired_at.with_timezone(&Local).format("%Y-%m-%d %H:%M")
            ),
            AMBER,
        ),
        DefinitionStatus::Failed(reason) => (format!("UPDATE FAILED | {reason}"), RED),
    }
}

fn scan_phase_label(phase: ScanPhaseView) -> (&'static str, Color32) {
    match phase {
        ScanPhaseView::Enumerating => ("ENUMERATING", BLUE),
        ScanPhaseView::Scanning => ("SCANNING", GREEN),
        ScanPhaseView::Cancelling => ("CANCELLING", AMBER),
        ScanPhaseView::Completed => ("COMPLETED", GREEN),
        ScanPhaseView::Cancelled => ("CANCELLED", AMBER),
        ScanPhaseView::Failed => ("FAILED", RED),
    }
}

fn event_kind_label(kind: &EventKind) -> (&'static str, Color32) {
    match kind {
        EventKind::ProtectionStarted => ("PROTECTION", GREEN),
        EventKind::ProtectionStopped => ("PROTECTION", AMBER),
        EventKind::ScanStarted => ("SCAN START", BLUE),
        EventKind::ScanCompleted => ("SCAN END", GREEN),
        EventKind::Detection => ("DETECTION", RED),
        EventKind::Quarantined => ("QUARANTINE", RED),
        EventKind::QuarantineFailed => ("ACTION FAILED", RED),
        EventKind::Restored => ("RESTORED", AMBER),
        EventKind::UpdateInstalled => ("UPDATE", GREEN),
        EventKind::UpdateFailed => ("UPDATE FAILED", RED),
        EventKind::Error => ("ERROR", RED),
    }
}

fn format_duration(duration: Duration) -> String {
    let seconds = duration.as_secs();
    let hours = seconds / 3_600;
    let minutes = (seconds % 3_600) / 60;
    let seconds = seconds % 60;
    if hours > 0 {
        format!("{hours:02}:{minutes:02}:{seconds:02}")
    } else {
        format!("{minutes:02}:{seconds:02}")
    }
}

fn format_bytes(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = KIB * 1024.0;
    const GIB: f64 = MIB * 1024.0;
    let bytes = bytes as f64;
    if bytes >= GIB {
        format!("{:.1} GiB", bytes / GIB)
    } else if bytes >= MIB {
        format!("{:.1} MiB", bytes / MIB)
    } else if bytes >= KIB {
        format!("{:.1} KiB", bytes / KIB)
    } else {
        format!("{} B", bytes as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_ui_state_never_claims_active_protection() {
        let state = UiRuntimeState::default();
        assert_ne!(compact_health(&state).0, "PROTECTION ACTIVE");
        assert_ne!(overall_health(&state).0, "PROTECTION ACTIVE");
    }

    #[test]
    fn active_label_requires_engine_and_filter() {
        let mut state = UiRuntimeState {
            protection: ProtectionStatus::Active,
            driver: DriverStatus::Disconnected("test".to_owned()),
            ..UiRuntimeState::default()
        };
        assert_eq!(compact_health(&state).0, "PROTECTION LIMITED");

        state.driver = DriverStatus::Connected;
        assert_eq!(compact_health(&state).0, "PROTECTION ACTIVE");
    }

    #[test]
    fn known_driver_failure_overrides_starting_state() {
        let state = UiRuntimeState {
            driver: DriverStatus::NotInstalled,
            ..UiRuntimeState::default()
        };
        assert_eq!(compact_health(&state).0, "PROTECTION LIMITED");
        assert_eq!(overall_health(&state).0, "ON-DEMAND ONLY");
    }

    #[test]
    fn byte_formatting_uses_binary_units() {
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1_048_576), "1.0 MiB");
    }
}
