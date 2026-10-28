// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The ring re-pin pass (WP-4.5): every minute, the memberships this Host coordinates are revised
//! when its own rings moved, and its rings that its memberships as a member pin at an older epoch
//! are re-pinned on a task session. The rings' activation gate waits for both.
//!
//! The same pass ships what this Host's ship tasks have due (WP-5.4, owner decision): a batch
//! waits at most one pass, and a deferred one its subscription's backoff.

use std::sync::Arc;
use std::time::Duration;

use permguard_host::api::HostApi;
use permguard_host::membership::service::Coordinating;

/// How often the pass runs.
pub const PASS: Duration = Duration::from_secs(60);

/// The running pass; dropping it stops it.
pub struct Repinning(tokio::task::JoinHandle<()>);

impl Drop for Repinning {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// What the pass checks of the audit checkpoints' egress (WP-5.9).
#[derive(Debug, Clone, Copy)]
pub struct Egress {
    /// Whether the assurance profile requires the checkpoints to leave the volume.
    pub enforce: bool,
    /// How long a checkpoint may wait for its acknowledgement.
    pub max_lag: Duration,
}

/// Runs the pass now and every [`PASS`] until the handle is dropped.
pub fn drive(coordinating: Arc<Coordinating>, api: Arc<HostApi>, egress: Egress) -> Repinning {
    Repinning(tokio::spawn(async move {
        let mut interval = tokio::time::interval(PASS);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            let revising = Arc::clone(&coordinating);
            match tokio::task::spawn_blocking(move || {
                revising
                    .revise_coordinated()
                    .and_then(|revised| Ok(revised + revising.retire_due()?))
            })
            .await
            {
                Ok(Ok(0)) => {}
                Ok(Ok(revised)) => tracing::info!(
                    event.name = "host.membership.coordinated_repinned",
                    component = "host",
                    memberships = revised,
                    "the memberships this Host coordinates now pin its moved rings"
                ),
                Ok(Err(error)) => tracing::warn!(
                    event.name = "host.membership.coordinated_repin_failed",
                    component = "host",
                    error = %error,
                    "a membership could not be revised for this Host's rings; the next pass tries again"
                ),
                Err(error) => tracing::error!(
                    event.name = "host.membership.coordinated_repin_failed",
                    component = "host",
                    error = %error,
                    "the coordinator's re-pin pass stopped; the next pass tries again"
                ),
            }
            let repinned = api.repin_due().await + api.cutover_due().await;
            let shipped = api.ship_due().await;
            // The origins' history this Host imports, after what it ships (WP-6.2c2a).
            let imported = api.import_due().await;
            if imported > 0 {
                tracing::debug!(
                    event.name = "host.membership.imported",
                    component = "host",
                    batches = imported,
                    "this Host's import tasks brought the origins' batches"
                );
            }
            // The audit checkpoints after the streams, then whether they left in time (WP-5.9).
            let exported = api.export_checkpoints_due().await;
            if exported > 0 {
                tracing::debug!(
                    event.name = "host.audit_exported",
                    component = "host",
                    checkpoints = exported,
                    "audit checkpoints were acknowledged by their coordinators"
                );
            }
            if let Err(error) = api.check_audit_egress(egress.enforce, egress.max_lag) {
                tracing::warn!(
                    event.name = "host.audit_egress_check_failed",
                    component = "host",
                    error = %error,
                    "the audit checkpoints' egress could not be checked; the next pass tries again"
                );
            }
            // A drain's marks go once their streams are shipped, and the Host's readiness with
            // them (WP-5.8).
            if let Err(error) = api.settle_unshipped() {
                tracing::warn!(
                    event.name = "host.stream_settle_failed",
                    component = "host",
                    error = %error,
                    "the unshipped marks could not be settled; the next pass tries again"
                );
            }
            if shipped > 0 {
                tracing::debug!(
                    event.name = "host.membership.shipped",
                    component = "host",
                    batches = shipped,
                    "this Host's ship tasks delivered their batches"
                );
            }
            if repinned > 0 {
                tracing::info!(
                    event.name = "host.membership.member_repinned",
                    component = "host",
                    rings = repinned,
                    "this Host's moved rings are re-pinned with its coordinators"
                );
            }
        }
    }))
}
