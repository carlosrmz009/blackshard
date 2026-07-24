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
            self.history.push((self.current_state.clone(), self.state_entered_at));
            log::info!("Readiness transitioning from {:?} to {:?}", self.current_state, next_state);
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
        let mut inner = self.inner.lock().unwrap();
        inner.transition(new_state);
    }

    pub fn report_health(&self, is_healthy: bool, detail: Option<String>) {
        let mut inner = self.inner.lock().unwrap();
        if is_healthy {
            inner.consecutive_failures = 0;
            inner.consecutive_successes += 1;
            
            if matches!(inner.current_state, ReadinessState::Recovering { .. }) && inner.consecutive_successes >= 3 {
                inner.transition(ReadinessState::Ready);
            } else if matches!(inner.current_state, ReadinessState::Degraded { .. }) {
                inner.transition(ReadinessState::Recovering { reason: "Attempting recovery".to_string() });
            } else if !matches!(inner.current_state, ReadinessState::Ready | ReadinessState::Recovering { .. } | ReadinessState::Degraded { .. } | ReadinessState::Stopping | ReadinessState::Stopped | ReadinessState::Failed { .. }) {
                inner.transition(ReadinessState::Ready);
            }
        } else {
            inner.consecutive_successes = 0;
            inner.consecutive_failures += 1;

            if matches!(inner.current_state, ReadinessState::Ready) && inner.consecutive_failures >= 2 {
                let reason = detail.unwrap_or_else(|| "Unknown failure".to_string());
                inner.transition(ReadinessState::Degraded { reason });
            }
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
