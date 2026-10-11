// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The audit sweep (WP-3.7, owner decisions of 2026-10-11): at start and every hour, every ended
//! day of every trail on the volume is sealed by a checkpoint, the sealed days past their
//! retention are deleted, and a registered witness is asked for the co-signatures still missing.
//! A sweep runs on a blocking thread: it reads day files, signs and may wait on the witness.

use std::sync::Arc;
use std::time::Duration;

use permguard_host::audit::Engine;

/// How often the sweep runs; the first run is at start.
pub const SWEEP: Duration = Duration::from_secs(3600);

/// The periodic sweep, stopped when this is dropped.
pub struct Sweeping(tokio::task::JoinHandle<()>);

impl Drop for Sweeping {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Sweeps `engine` now and every [`SWEEP`] until the handle is dropped.
pub fn sweep(engine: Arc<Engine>) -> Sweeping {
    Sweeping(tokio::spawn(async move {
        let mut interval = tokio::time::interval(SWEEP);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            let engine = Arc::clone(&engine);
            match tokio::task::spawn_blocking(move || engine.sweep()).await {
                Ok(Ok(written)) if !written.is_empty() => tracing::info!(
                    event.name = "audit.swept",
                    component = "host",
                    checkpoints = written.len(),
                    "audit checkpoints sealed"
                ),
                Ok(Ok(_)) => {}
                Ok(Err(error)) => tracing::error!(
                    event.name = "audit.sweep_failed",
                    component = "host",
                    error = %error,
                    "the audit sweep failed; it runs again within the hour"
                ),
                Err(error) => tracing::error!(
                    event.name = "audit.sweep_failed",
                    component = "host",
                    error = %error,
                    "the audit sweep stopped; it runs again within the hour"
                ),
            }
        }
    }))
}

/// What `audit verify --directory <dir> [--keys <file>] [--checkpoint <file>]` prints for the
/// Host's trails: the report when every trail verifies, an error carrying it when one does not.
pub fn verify(
    directory: &std::path::Path,
    keys: Option<&std::path::Path>,
    checkpoint: Option<&std::path::Path>,
) -> anyhow::Result<String> {
    let report = permguard_host::audit::verify::verify_directory(directory, keys, checkpoint)
        .map_err(anyhow::Error::msg)?;
    if report.sound() {
        Ok(report.render())
    } else {
        anyhow::bail!("{}", report.render())
    }
}
