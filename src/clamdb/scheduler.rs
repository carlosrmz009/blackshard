use log::{error, info};
use rand::Rng;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::Duration;

use super::downloader;

/// Checks for new definitions every four hours, give or take fifteen minutes.
///
/// The first check waits a full interval, because the service performs its own update at startup;
/// checking immediately as well would race it for the same staging directory. A generation is
/// only passed on when it differs from the last one seen, since each hand-off makes the service
/// reload every signature and discard its verdict cache.
pub fn start_scheduler(program_data: PathBuf) -> Receiver<downloader::ActiveDatabase> {
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let mut last_generation = downloader::active_database(&program_data)
            .ok()
            .map(|active| active.generation);
        loop {
            let jitter: i64 = rand::thread_rng().gen_range(-900..=900);
            let sleep_duration = Duration::from_secs((4 * 60 * 60 + jitter) as u64);
            info!(
                "Definition updater: next check in {} seconds.",
                sleep_duration.as_secs()
            );
            thread::sleep(sleep_duration);

            match downloader::download_databases(&program_data) {
                Ok(active) if Some(active.generation) != last_generation => {
                    info!(
                        "Definition updater: activated generation {}.",
                        active.generation
                    );
                    last_generation = Some(active.generation);
                    let _ = sender.try_send(active);
                }
                Ok(_) => info!("Definition updater: definitions are already current."),
                Err(error) => error!("Definition update failed: {error}"),
            }
        }
    });
    receiver
}
