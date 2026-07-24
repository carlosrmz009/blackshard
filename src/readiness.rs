use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReadinessState {
    Stopped,
    Starting,
    LoadingSettings,
    LoadingDefinitions,
    LoadingFreshClam,
    StartingDetectionWorkers,
    ConnectingDriver,
    ValidatingProtocol,
    RunningSelfTest,
    Ready,
    Degraded { reason: String },
    Recovering { reason: String },
    Failed { reason: String },
    Stopping,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum UserFacingStatus {
    Starting,
    Protected,
    ProtectionReduced,
    ActionRequired,
    Repairing,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProtectionComponents {
    pub service_operational: bool,
    pub settings_loaded: bool,
    pub native_definitions_loaded: bool,
    pub freshclam_loaded: bool,
    pub freshclam_generation: u64,
    pub rule_generation: u64,
    pub model_generation: u64,
    pub driver_connected: bool,
    pub driver_protocol_validated: bool,
    pub driver_ready_generation: Option<u64>,
    pub clamav_worker_healthy: bool,
    pub parser_worker_healthy: bool,
    pub quarantine_available: bool,
    pub history_available: bool,
    pub ipc_available: bool,
    pub self_test_passed: bool,
    pub consecutive_health_successes: u32,
    pub consecutive_health_failures: u32,
}

impl ProtectionComponents {
    pub fn mandatory_failures(&self) -> Vec<&'static str> {
        let mut failures = Vec::new();
        for (healthy, name) in [
            (self.service_operational, "service message loop"),
            (self.settings_loaded, "settings"),
            (self.native_definitions_loaded, "native definitions"),
            (
                self.freshclam_loaded && self.freshclam_generation != 0,
                "active FreshClam database",
            ),
            (self.rule_generation != 0, "rule generation"),
            (self.driver_connected, "minifilter connection"),
            (self.driver_protocol_validated, "driver protocol"),
            (self.clamav_worker_healthy, "ClamAV scanner worker"),
            (self.parser_worker_healthy, "isolated parser worker"),
            (self.quarantine_available, "quarantine store"),
            (self.history_available, "event history"),
            (self.ipc_available, "local control server"),
            (self.self_test_passed, "end-to-end self-test"),
        ] {
            if !healthy {
                failures.push(name);
            }
        }
        failures
    }
}

pub fn derive_readiness(components: &ProtectionComponents) -> ReadinessState {
    let failures = components.mandatory_failures();
    if !failures.is_empty() {
        return ReadinessState::Degraded {
            reason: format!("Unavailable: {}", failures.join(", ")),
        };
    }
    if components.driver_ready_generation.is_none() {
        return ReadinessState::Recovering {
            reason: "Arming the validated driver generation".to_owned(),
        };
    }
    if components.consecutive_health_successes < 3 {
        return ReadinessState::Recovering {
            reason: format!(
                "Validating stable protection ({}/3)",
                components.consecutive_health_successes
            ),
        };
    }
    ReadinessState::Ready
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Diagnostics {
    pub current_state: ReadinessState,
    pub state_entered_at: DateTime<Utc>,
    pub history: Vec<(ReadinessState, DateTime<Utc>)>,
    pub consecutive_successes: u32,
    pub consecutive_failures: u32,
}

pub struct ReadinessMonitorInner {
    pub current_state: ReadinessState,
    pub state_entered_at: DateTime<Utc>,
    pub history: Vec<(ReadinessState, DateTime<Utc>)>,
    pub consecutive_successes: u32,
    pub consecutive_failures: u32,
}

impl ReadinessMonitorInner {
    fn transition(&mut self, next_state: ReadinessState) {
        if self.current_state != next_state {
            let now = Utc::now();
            self.history
                .push((self.current_state.clone(), self.state_entered_at));
            log::info!(
                "Readiness transitioning from {:?} to {:?}",
                self.current_state,
                next_state
            );
            self.current_state = next_state;
            self.state_entered_at = now;
        }
    }
}

#[derive(Clone)]
pub struct ReadinessMonitor {
    inner: Arc<Mutex<ReadinessMonitorInner>>,
}

impl ReadinessMonitor {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(ReadinessMonitorInner {
                current_state: ReadinessState::Stopped,
                state_entered_at: Utc::now(),
                history: Vec::new(),
                consecutive_successes: 0,
                consecutive_failures: 0,
            })),
        }
    }

    pub fn update_state(&self, new_state: ReadinessState) {
        assert!(
            !matches!(new_state, ReadinessState::Ready),
            "Ready must be derived from ProtectionComponents"
        );
        let mut inner = self.inner.lock().unwrap();
        inner.transition(new_state);
    }

    pub fn report_components(&self, components: &ProtectionComponents) {
        let mut inner = self.inner.lock().unwrap();
        inner.consecutive_successes = components.consecutive_health_successes;
        inner.consecutive_failures = components.consecutive_health_failures;
        let derived = derive_readiness(components);
        let explicit_driver_failure =
            !components.driver_connected || !components.driver_protocol_validated;
        if matches!(inner.current_state, ReadinessState::Ready)
            && matches!(derived, ReadinessState::Degraded { .. })
            && !explicit_driver_failure
            && components.consecutive_health_failures < 2
        {
            return;
        }
        if matches!(
            inner.current_state,
            ReadinessState::Stopping | ReadinessState::Stopped | ReadinessState::Failed { .. }
        ) {
            return;
        }
        inner.transition(derived);
    }

    pub fn report_health(&self, is_healthy: bool, detail: Option<String>) {
        let mut inner = self.inner.lock().unwrap();
        if is_healthy {
            inner.consecutive_failures = 0;
            inner.consecutive_successes = inner.consecutive_successes.saturating_add(1);
        } else {
            inner.consecutive_successes = 0;
            inner.consecutive_failures = inner.consecutive_failures.saturating_add(1);
            let reason = detail.unwrap_or_else(|| "Unknown failure".to_string());
            inner.transition(ReadinessState::Degraded { reason });
        }
    }

    pub fn user_facing_status(&self) -> UserFacingStatus {
        let inner = self.inner.lock().unwrap();
        match &inner.current_state {
            ReadinessState::Stopped | ReadinessState::Stopping => UserFacingStatus::ActionRequired,
            ReadinessState::Starting
            | ReadinessState::LoadingSettings
            | ReadinessState::LoadingDefinitions
            | ReadinessState::LoadingFreshClam
            | ReadinessState::StartingDetectionWorkers
            | ReadinessState::ConnectingDriver
            | ReadinessState::ValidatingProtocol
            | ReadinessState::RunningSelfTest => UserFacingStatus::Starting,
            ReadinessState::Ready => UserFacingStatus::Protected,
            ReadinessState::Degraded { .. } => UserFacingStatus::ProtectionReduced,
            ReadinessState::Recovering { .. } => UserFacingStatus::Repairing,
            ReadinessState::Failed { .. } => UserFacingStatus::ActionRequired,
        }
    }

    pub fn diagnostics(&self) -> Diagnostics {
        let inner = self.inner.lock().unwrap();
        Diagnostics {
            current_state: inner.current_state.clone(),
            state_entered_at: inner.state_entered_at,
            history: inner.history.clone(),
            consecutive_successes: inner.consecutive_successes,
            consecutive_failures: inner.consecutive_failures,
        }
    }
}

impl Default for ReadinessMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn healthy_components() -> ProtectionComponents {
        ProtectionComponents {
            service_operational: true,
            settings_loaded: true,
            native_definitions_loaded: true,
            freshclam_loaded: true,
            freshclam_generation: 7,
            rule_generation: 4,
            model_generation: 0,
            driver_connected: true,
            driver_protocol_validated: true,
            driver_ready_generation: Some(9),
            clamav_worker_healthy: true,
            parser_worker_healthy: true,
            quarantine_available: true,
            history_available: true,
            ipc_available: true,
            self_test_passed: true,
            consecutive_health_successes: 3,
            consecutive_health_failures: 0,
        }
    }

    #[test]
    fn ready_is_derived_only_after_every_mandatory_component_and_hysteresis() {
        let mut components = healthy_components();
        assert_eq!(derive_readiness(&components), ReadinessState::Ready);

        components.consecutive_health_successes = 2;
        assert!(matches!(
            derive_readiness(&components),
            ReadinessState::Recovering { .. }
        ));

        components.consecutive_health_successes = 3;
        components.freshclam_loaded = false;
        assert!(matches!(
            derive_readiness(&components),
            ReadinessState::Degraded { .. }
        ));
    }

    #[test]
    fn missing_driver_self_test_or_worker_never_reports_ready() {
        for mutate in [
            |components: &mut ProtectionComponents| components.driver_connected = false,
            |components: &mut ProtectionComponents| components.self_test_passed = false,
            |components: &mut ProtectionComponents| components.clamav_worker_healthy = false,
            |components: &mut ProtectionComponents| components.parser_worker_healthy = false,
        ] {
            let mut components = healthy_components();
            mutate(&mut components);
            assert!(!matches!(
                derive_readiness(&components),
                ReadinessState::Ready
            ));
        }
    }
}
