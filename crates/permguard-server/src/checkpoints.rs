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

/// The warning a configuration naming the retired `file` destination gets at start (WP-3.8, owner
/// decision of 2026-10-11): still accepted, it writes nothing besides the Host trails.
pub fn destination_deprecation(config: &permguard_core::Config) -> Option<&'static str> {
    (config.audit_destination() == permguard_core::AuditDestination::File).then_some(
        "`audit.destination: file` is deprecated: the Host trails on the volume hold every record, \
         and the JSON-lines file sink is gone; `audit.directory` only locates a legacy chain to \
         migrate",
    )
}

/// Lays out the legacy JSON-lines audit chain in `legacy` at start (WP-3.8, owner decisions of
/// 2026-10-11): carried byte for byte into `host/audit/legacy` below the production profile; from
/// it upward its migration declares a backup, so the start is refused while the chain is still in
/// place, naming the command that migrates it.
pub fn lay_out_legacy(
    volume: &permguard_host::storage::volume::Volume,
    legacy: &std::path::Path,
    profile: permguard_core::assurance::AssuranceProfile,
    working_dir: &std::path::Path,
    now: u64,
) -> anyhow::Result<()> {
    use anyhow::Context as _;
    use permguard_host::audit::jsonl::{Laid, lay_out, needs_migration, pending_directory};

    if profile.at_least(permguard_core::assurance::AssuranceProfile::Production)
        && needs_migration(volume, Some(legacy))
            .context("reading the layout of the legacy audit chain")?
    {
        // Where a declared version 1 says the chain waits, which `audit.directory` may no longer
        // name.
        let waiting = pending_directory(volume)
            .context("reading the layout of the legacy audit chain")?
            .unwrap_or_else(|| legacy.display().to_string());
        anyhow::bail!(
            "the legacy audit chain is still in {waiting}, and from the production profile upward \
             its migration declares a backup: run `permguard migrate audit --volume {} --backup \
             <reference>` with the server stopped",
            working_dir.display()
        );
    }
    let laid = lay_out(volume, Some(legacy), profile, None, now)
        .context("laying out the legacy audit chain")?;
    if laid == Laid::Migrated {
        tracing::info!(
            event.name = "audit.legacy_migrated",
            component = "host",
            "the legacy audit chain was carried into host/audit/legacy; `migrate finalize \
             --subsystem audit-legacy` removes its old directory"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use permguard_core::assurance::AssuranceProfile;
    use permguard_host::storage::volume::Volume;

    use super::*;

    const FIXTURE: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../permguard-std/tests/fixtures/legacy/v1/audit/trail"
    );

    fn volume_with_chain(tag: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "permguard-server-legacy-audit-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let legacy = root.join("operations/audit");
        std::fs::create_dir_all(&legacy).expect("created");
        for entry in std::fs::read_dir(FIXTURE).expect("the fixture") {
            let entry = entry.expect("an entry");
            std::fs::copy(entry.path(), legacy.join(entry.file_name())).expect("copied");
        }
        (root, legacy)
    }

    #[test]
    fn a_production_volume_with_a_legacy_audit_chain_refuses_to_start() {
        let (root, legacy) = volume_with_chain("production");
        let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
        let refused = lay_out_legacy(
            &volume,
            &legacy,
            AssuranceProfile::Production,
            &root,
            1_800_000_000,
        )
        .expect_err("the chain is still in place");
        let message = format!("{refused:#}");
        assert!(message.contains("permguard migrate audit"), "{message}");
        assert!(!root.join("host/audit/legacy").exists(), "nothing carried");
        // Below production the start carries it.
        lay_out_legacy(
            &volume,
            &legacy,
            AssuranceProfile::Development,
            &root,
            1_800_000_000,
        )
        .expect("carried");
        assert!(
            root.join("host/audit/legacy/audit-2026-10-02.jsonl")
                .exists()
        );
        drop(volume);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn the_file_destination_is_accepted_and_warned_deprecated() {
        let config = |destination: &str| {
            permguard_core::Config::from_layers(
                permguard_core::BuildSettings::new("9.9.9", "2026", "Test Holder"),
                Vec::<String>::new(),
                permguard_core::config::Layers::new().with_file(vec![(
                    permguard_core::config::SETTING_AUDIT_SINK.to_owned(),
                    destination.to_owned(),
                )]),
            )
            .expect("the configuration reads")
        };
        let warned = destination_deprecation(&config("file")).expect("deprecated");
        assert!(warned.contains("deprecated"), "{warned}");
        assert_eq!(destination_deprecation(&config("tracing")), None);
    }
}
