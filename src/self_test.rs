use std::fs;
use uuid::Uuid;
use crate::realtime;

const EICAR: &[u8] = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

pub fn run_self_test() -> Result<String, String> {
    let test_id = Uuid::new_v4();
    let file_name = format!("blackshard-selftest-{}.com", test_id);
    let path = std::env::temp_dir().join(file_name);
    
    fs::write(&path, EICAR)
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
        Ok(0) => Err("The test file was opened successfully; real-time enforcement did not block it.".to_owned()),
        Ok(code) => Err(format!("The test probe exited unexpectedly ({code})")),
        Err(error) => Err(error),
    }
}
