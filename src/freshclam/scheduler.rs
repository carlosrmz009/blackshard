use log::{error, info};
use rand::Rng;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::Duration;

use super::downloader;

pub fn start_scheduler(program_data: PathBuf) -> Receiver<super::downloader::ActiveDatabase> {
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::spawn(move || {
        loop {
            info!("FreshClam updater: starting update cycle.");

            match downloader::download_databases(&program_data) {
                Ok(active) => {
                    info!("FreshClam databases updated successfully.");
                    let _ = sender.try_send(active);
                }
                Err(e) => error!("FreshClam update failed: {:?}", e),
            }

            // 4 hours with some random jitter (e.g., +/- 15 minutes)
            let base_duration = Duration::from_secs(4 * 60 * 60);
            let mut rng = rand::thread_rng();
            // Jitter between -900 and 900 seconds
            let jitter: i64 = rng.gen_range(-900..=900);

            let sleep_duration = if jitter < 0 {
                base_duration - Duration::from_secs((-jitter) as u64)
            } else {
                base_duration + Duration::from_secs(jitter as u64)
            };

            info!(
                "FreshClam updater: sleeping for {} seconds.",
                sleep_duration.as_secs()
            );
            thread::sleep(sleep_duration);
        }
    });
    receiver
}
