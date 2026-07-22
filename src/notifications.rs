use std::path::Path;

pub const APP_USER_MODEL_ID: &str = "Blackshard.Security.Client";

#[derive(Debug, Clone, Copy)]
pub enum NotificationSeverity {
    Information,
    Warning,
    Critical,
}

/// Delivers a native Windows toast. The production installer registers
/// `APP_USER_MODEL_ID` through the Start-menu shortcut; a portable/development
/// build may return an error because Windows has no registered toast identity.
#[cfg(windows)]
pub fn show_notification(
    title: &str,
    message: &str,
    severity: NotificationSeverity,
) -> Result<(), String> {
    use winrt_notification::{Duration, Sound, Toast};

    let sound = match severity {
        NotificationSeverity::Information => Sound::Default,
        NotificationSeverity::Warning => Sound::SMS,
        NotificationSeverity::Critical => Sound::Reminder,
    };
    Toast::new(APP_USER_MODEL_ID)
        .title(title)
        .text1(message)
        .sound(Some(sound))
        .duration(Duration::Short)
        .show()
        .map_err(|error| error.to_string())
}

#[cfg(not(windows))]
pub fn show_notification(
    _title: &str,
    _message: &str,
    _severity: NotificationSeverity,
) -> Result<(), String> {
    Ok(())
}

pub fn notify_detection(threat_name: &str, path: &Path, isolated: bool) -> Result<(), String> {
    let action = if isolated {
        "The file was moved to quarantine."
    } else {
        "Blackshard detected the file but could not remove the original."
    };
    let message = format!("{threat_name}\n{}\n{action}", path.display());
    show_notification(
        if isolated {
            "Blackshard blocked a threat"
        } else {
            "Blackshard needs your attention"
        },
        &message,
        if isolated {
            NotificationSeverity::Warning
        } else {
            NotificationSeverity::Critical
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_identity_is_stable_for_installer_registration() {
        assert_eq!(APP_USER_MODEL_ID, "Blackshard.Security.Client");
    }
}
