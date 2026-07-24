use crate::realtime;
use std::fs;
use uuid::Uuid;

/// Project-specific inert content used for end-to-end enforcement tests.
///
/// This payload is intentionally not EICAR so another installed antivirus
/// cannot consume the probe before Blackshard observes it.
pub const PAYLOAD: &[u8] =
    b"BLACKSHARD-HARMLESS-SELF-TEST-V2\nThis file contains no executable code.\n";

pub fn run_self_test() -> Result<String, String> {
    let test_id = Uuid::new_v4();
    let file_name = format!("blackshard-selftest-{}.com", test_id);
    let path = std::env::temp_dir().join(file_name);

    fs::write(&path, PAYLOAD)
        .map_err(|error| format!("could not create the test file: {error}"))?;

    let result = std::env::current_exe()
        .map_err(|error| format!("could not locate the executable: {error}"))
        .and_then(|executable| {
            // Note: We use the same argument defined in main.rs: "--blackshard-self-test-open"
            realtime::launch_hidden_probe(&executable, "--blackshard-self-test-open", &path)
                .map_err(|error| format!("could not launch the isolated test probe: {error}"))
        });

    let _ = fs::remove_file(&path);

    match result {
        Ok(10) => Ok("The real-time protection successfully blocked the test file.".to_owned()),
        Ok(0) => Err(
            "The test file was opened successfully; real-time enforcement did not block it."
                .to_owned(),
        ),
        Ok(code) => Err(format!("The test probe exited unexpectedly ({code})")),
        Err(error) => Err(error),
    }
}
