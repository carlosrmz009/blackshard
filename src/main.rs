#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod atomic_file;
mod config;
mod definitions;
mod detection;
mod driver_installer;
mod engine;
mod history;
mod ipc;
mod notification_agent;
mod notifications;
mod quarantine;
mod realtime;
mod rules;
mod scan_manager;
mod service;
mod trust;
mod ui;
mod update_client;
mod updater;

use crate::ipc::IpcClient;
use crate::service::{
    default_service_health_path, read_service_health, ServiceConnection, ServiceDefinitionHealth,
    ServiceHealthSnapshot, ServiceLifecycle, SERVICE_HEALTH_SCHEMA_VERSION,
};
use crate::ui::{
    complete_protection_test, new_shared_ui_state, take_protection_test_request, BlackshardApp,
    BuildTrustStatus, CertificationStatus, DefinitionStatus, DriverStatus, ProtectionStatus,
    SharedUiState,
};
use chrono::Utc;
use eframe::egui;
use std::error::Error;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

const SERVICE_ARGUMENT: &str = "--service";
const SERVICE_CONSOLE_ARGUMENT: &str = "--service-console";
const SELF_TEST_ARGUMENT: &str = "--blackshard-self-test-open";
const INSTALL_DRIVER_ARGUMENT: &str = "--install-driver";
const UNINSTALL_DRIVER_ARGUMENT: &str = "--uninstall-driver";
const NOTIFICATION_AGENT_ARGUMENT: &str = "--notification-agent";
const HEALTH_POLL_INTERVAL: Duration = Duration::from_secs(1);
const HEALTH_STALE_AFTER_SECONDS: i64 = 10;
const SELF_TEST_PAYLOAD: &[u8] =
    b"BLACKSHARD-HARMLESS-SELF-TEST-V2\nThis file contains no executable code.\n";

fn requested_mode() -> Option<String> {
    std::env::args().nth(1)
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

fn run_service_mode() -> Result<(), Box<dyn Error>> {
    service::run_service_dispatcher()?;
    Ok(())
}

fn run_service_console_mode() -> Result<(), Box<dyn Error>> {
    use std::sync::atomic::AtomicBool;

    let stop = Arc::new(AtomicBool::new(false));
    service::run_service_console(stop).map_err(Into::into)
}

fn driver_change_exit_code(install: bool) -> i32 {
    let mut arguments = std::env::args_os();
    arguments.next();
    arguments.next();
    let Some(inf_path) = arguments.next() else {
        return 2;
    };
    if arguments.next().is_some() {
        return 2;
    }

    let result = if install {
        driver_installer::install_driver(std::path::Path::new(&inf_path))
    } else {
        driver_installer::uninstall_driver(std::path::Path::new(&inf_path))
    };
    match result {
        Ok(driver_installer::DriverChange::Complete) => 0,
        Ok(driver_installer::DriverChange::RebootRequired) => {
            driver_installer::REBOOT_REQUIRED_EXIT_CODE
        }
        Err(_error) => 1,
    }
}

fn apply_service_health(runtime: &SharedUiState, health: ServiceHealthSnapshot) {
    let mut state = match runtime.lock() {
        Ok(state) => state,
        Err(_) => return,
    };

    if health.schema_version != SERVICE_HEALTH_SCHEMA_VERSION {
        let detail = format!(
            "unsupported service health schema {}",
            health.schema_version
        );
        state.driver = DriverStatus::Error(detail.clone());
        state.protection = ProtectionStatus::Unavailable(detail.clone());
        state.attention = Some(detail);
        return;
    }

    let age = Utc::now().signed_duration_since(health.updated_at);
    if age.num_seconds() > HEALTH_STALE_AFTER_SECONDS || age.num_seconds() < -30 {
        let detail = format!(
            "the protection service health timestamp is outside the trusted window ({})",
            age.num_seconds(),
        );
        state.driver = DriverStatus::Error(detail.clone());
        state.protection = ProtectionStatus::Unavailable(detail.clone());
        state.attention = Some(detail);
        return;
    }

    state.engine_version = health.product_version;
    state.realtime_scanned_files = health.counters.scanned;
    state.realtime_blocked_files = health.counters.blocked_replies;
    state.definitions = match health.definitions {
        ServiceDefinitionHealth::BuiltIn { version } => DefinitionStatus::BuiltInOnly { version },
        ServiceDefinitionHealth::Updating { current_version } => {
            DefinitionStatus::Updating { current_version }
        }
        ServiceDefinitionHealth::Current {
            version,
            expires_at,
            ..
        }
        | ServiceDefinitionHealth::LastKnownGood {
            version,
            expires_at,
            ..
        } if expires_at > Utc::now() => DefinitionStatus::Current {
            version,
            expires_at,
        },
        ServiceDefinitionHealth::Current {
            version,
            expires_at,
            ..
        }
        | ServiceDefinitionHealth::LastKnownGood {
            version,
            expires_at,
            ..
        } => DefinitionStatus::Stale {
            version,
            expired_at: expires_at,
        },
        ServiceDefinitionHealth::Failed { detail } => DefinitionStatus::Failed(detail),
    };
    state.driver = match &health.connection {
        ServiceConnection::Connecting => DriverStatus::Checking,
        ServiceConnection::Connected => DriverStatus::Connected,
        ServiceConnection::Disconnected => DriverStatus::Disconnected(
            health
                .connection_detail
                .clone()
                .unwrap_or_else(|| "the minifilter channel is disconnected".to_owned()),
        ),
        ServiceConnection::Stopped => {
            DriverStatus::Disconnected("the protection service is stopped".to_owned())
        }
    };

    state.protection = match health.lifecycle {
        ServiceLifecycle::StartPending => ProtectionStatus::Starting,
        ServiceLifecycle::StopPending | ServiceLifecycle::Stopped => {
            ProtectionStatus::Unavailable("the protection service is stopped".to_owned())
        }
        ServiceLifecycle::Running if !health.real_time_enabled => ProtectionStatus::Paused,
        ServiceLifecycle::Running if health.connection == ServiceConnection::Connected => {
            ProtectionStatus::Active
        }
        ServiceLifecycle::Running => ProtectionStatus::Degraded(
            health
                .connection_detail
                .clone()
                .or(health.last_error.clone())
                .unwrap_or_else(|| "the kernel minifilter is not connected".to_owned()),
        ),
    };

    state.attention = match &state.protection {
        ProtectionStatus::Active | ProtectionStatus::Paused | ProtectionStatus::Starting => None,
        ProtectionStatus::Degraded(detail) | ProtectionStatus::Unavailable(detail) => {
            Some(detail.clone())
        }
    };
}

fn set_health_read_error(runtime: &SharedUiState, error: &io::Error) {
    let mut state = match runtime.lock() {
        Ok(state) => state,
        Err(_) => return,
    };

    if error.kind() == io::ErrorKind::NotFound {
        let detail = "the Blackshard protection service is not installed or has not started";
        state.driver = DriverStatus::NotInstalled;
        state.protection = ProtectionStatus::Unavailable(detail.to_owned());
        state.attention = Some(detail.to_owned());
    } else {
        let detail = format!("could not read protection-service health: {error}");
        state.driver = DriverStatus::Error(detail.clone());
        state.protection = ProtectionStatus::Unavailable(detail.clone());
        state.attention = Some(detail);
    }
}

fn start_service_health_monitor(runtime: SharedUiState) {
    thread::spawn(move || {
        let path = default_service_health_path();
        loop {
            match read_service_health(&path) {
                Ok(health) => apply_service_health(&runtime, health),
                Err(error) => set_health_read_error(&runtime, &error),
            }
            if take_protection_test_request(&runtime) {
                let test_runtime = Arc::clone(&runtime);
                thread::spawn(move || {
                    complete_protection_test(&test_runtime, run_harmless_protection_test());
                });
            }
            process_update_request(&runtime);
            thread::sleep(HEALTH_POLL_INTERVAL);
        }
    });
}

fn process_update_request(runtime: &SharedUiState) {
    let requested = match runtime.lock() {
        Ok(mut state) if state.update_check_requested => {
            state.update_check_requested = false;
            true
        }
        _ => false,
    };
    if !requested {
        return;
    }

    match IpcClient.request_update() {
        Ok(_) => {
            if let Ok(mut state) = runtime.lock() {
                let current_version = match &state.definitions {
                    DefinitionStatus::BuiltInOnly { version }
                    | DefinitionStatus::Current { version, .. }
                    | DefinitionStatus::Stale { version, .. } => Some(version.clone()),
                    DefinitionStatus::Updating { current_version } => current_version.clone(),
                    DefinitionStatus::Failed(_) => None,
                };
                state.definitions = DefinitionStatus::Updating { current_version };
            }
        }
        Err(error) => {
            if let Ok(mut state) = runtime.lock() {
                state.definitions = DefinitionStatus::Failed(format!(
                    "could not ask the protection service to update: {error}"
                ));
            }
        }
    }
}

fn run_harmless_protection_test() -> Result<String, String> {
    let path = std::env::temp_dir().join(format!(
        "blackshard-harmless-test-{}.com",
        std::process::id()
    ));
    fs::write(&path, SELF_TEST_PAYLOAD)
        .map_err(|error| format!("could not create the harmless test file: {error}"))?;

    let result = std::env::current_exe()
        .map_err(|error| format!("could not locate the Blackshard executable: {error}"))
        .and_then(|executable| {
            realtime::launch_hidden_probe(&executable, SELF_TEST_ARGUMENT, &path)
                .map_err(|error| format!("could not launch the isolated test probe: {error}"))
        });
    let _ = fs::remove_file(&path);

    match result {
        Ok(10) => Ok("The minifilter denied the inert test signature end to end.".to_owned()),
        Ok(0) => Err(
            "the inert test signature was opened; real-time enforcement did not block it"
                .to_owned(),
        ),
        Ok(code) => Err(format!(
            "the protection-test probe exited unexpectedly ({code})"
        )),
        Err(error) => Err(error),
    }
}

fn initialize_runtime(runtime: &SharedUiState) {
    if let Ok(mut state) = runtime.lock() {
        state.build_trust = BuildTrustStatus::Checking;
        state.certification = CertificationStatus::NotEvaluated;
        state.definitions = DefinitionStatus::BuiltInOnly {
            version: format!("embedded-{}", env!("CARGO_PKG_VERSION")),
        };
    }

    let trust_runtime = Arc::clone(runtime);
    thread::spawn(move || {
        let trust = match trust::verify_current_executable() {
            trust::AuthenticodeStatus::Trusted { publisher } => {
                BuildTrustStatus::AuthenticodeVerified { publisher }
            }
            trust::AuthenticodeStatus::Unsigned => BuildTrustStatus::UnsignedDevelopmentBuild,
            trust::AuthenticodeStatus::Untrusted(error)
            | trust::AuthenticodeStatus::Error(error) => {
                BuildTrustStatus::VerificationFailed(error)
            }
        };
        if let Ok(mut state) = trust_runtime.lock() {
            state.build_trust = trust;
        }
    });
}

fn run_ui() -> Result<(), Box<dyn Error>> {
    let runtime = new_shared_ui_state();
    initialize_runtime(&runtime);
    start_service_health_monitor(Arc::clone(&runtime));

    let mut wgpu_options = eframe::egui_wgpu::WgpuConfiguration::default();
    wgpu_options.supported_backends = eframe::wgpu::Backends::DX12;
    wgpu_options.power_preference = eframe::wgpu::PowerPreference::LowPower;

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1120.0, 720.0])
            .with_min_inner_size([920.0, 600.0]),
        renderer: eframe::Renderer::Wgpu,
        wgpu_options,
        ..Default::default()
    };

    eframe::run_native(
        "Blackshard",
        options,
        Box::new(move |_creation_context| Box::new(BlackshardApp::with_machine_defaults(runtime))),
    )?;
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    if let Some(exit_code) = self_test_probe_exit_code() {
        std::process::exit(exit_code);
    }

    match requested_mode().as_deref() {
        Some(SERVICE_ARGUMENT) => run_service_mode(),
        Some(SERVICE_CONSOLE_ARGUMENT) => run_service_console_mode(),
        Some(INSTALL_DRIVER_ARGUMENT) => std::process::exit(driver_change_exit_code(true)),
        Some(UNINSTALL_DRIVER_ARGUMENT) => std::process::exit(driver_change_exit_code(false)),
        Some(NOTIFICATION_AGENT_ARGUMENT) => notification_agent::run().map_err(Into::into),
        _ => run_ui(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;
    use std::path::Path;

    #[test]
    fn health_monitor_requires_a_fresh_connected_running_service() {
        let now = Utc::now();
        let runtime = new_shared_ui_state();
        let health = ServiceHealthSnapshot {
            schema_version: SERVICE_HEALTH_SCHEMA_VERSION,
            product_version: "1.2.3".to_owned(),
            process_id: 42,
            lifecycle: ServiceLifecycle::Running,
            connection: ServiceConnection::Connected,
            connection_detail: None,
            real_time_enabled: true,
            started_at: now,
            updated_at: now,
            last_detection_at: None,
            last_error: None,
            definitions: ServiceDefinitionHealth::BuiltIn {
                version: "embedded-test".to_owned(),
            },
            counters: service::ServiceCounters::default(),
        };

        apply_service_health(&runtime, health);
        let state = runtime.lock().unwrap();
        assert_eq!(state.protection, ProtectionStatus::Active);
        assert_eq!(state.driver, DriverStatus::Connected);
    }

    #[test]
    fn disabled_realtime_is_reported_as_paused_not_active() {
        let now = Utc::now();
        let runtime = new_shared_ui_state();
        let health = ServiceHealthSnapshot {
            schema_version: SERVICE_HEALTH_SCHEMA_VERSION,
            product_version: "1.2.3".to_owned(),
            process_id: 42,
            lifecycle: ServiceLifecycle::Running,
            connection: ServiceConnection::Connected,
            connection_detail: None,
            real_time_enabled: false,
            started_at: now,
            updated_at: now,
            last_detection_at: None,
            last_error: None,
            definitions: ServiceDefinitionHealth::BuiltIn {
                version: "embedded-test".to_owned(),
            },
            counters: service::ServiceCounters::default(),
        };

        apply_service_health(&runtime, health);
        assert_eq!(runtime.lock().unwrap().protection, ProtectionStatus::Paused);
    }

    #[test]
    fn missing_health_file_never_claims_protection() {
        let runtime = new_shared_ui_state();
        set_health_read_error(
            &runtime,
            &io::Error::new(io::ErrorKind::NotFound, "missing"),
        );
        let state = runtime.lock().unwrap();
        assert_eq!(state.driver, DriverStatus::NotInstalled);
        assert!(matches!(state.protection, ProtectionStatus::Unavailable(_)));
    }

    #[test]
    fn self_test_probe_argument_is_stable() {
        assert_eq!(SELF_TEST_ARGUMENT, "--blackshard-self-test-open");
        assert!(Path::new(SELF_TEST_ARGUMENT).file_name().is_some());
        assert_eq!(SELF_TEST_PAYLOAD.len(), 72);
        assert_eq!(
            hex::encode(sha2::Sha256::digest(SELF_TEST_PAYLOAD)),
            engine::BLACKSHARD_SELF_TEST_SHA256
        );
    }
}
