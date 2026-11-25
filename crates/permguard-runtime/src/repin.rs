// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The ring re-pin pass (WP-4.5): every minute, the memberships this Host coordinates are revised
//! when its own rings moved, and its rings that its memberships as a member pin at an older epoch
//! are re-pinned on a task session. The rings' activation gate waits for both.
//!
//! The same pass asks the shipper to reconcile (iteration 04, `1-architecture/6` Reconciliation):
//! shipping itself is continuous, woken by every append, and the pass only makes sure a wake lost
//! leaves nothing behind for longer than one pass.
//!
//! A revocation does not wait for the pass (BUG-0223): it replaces an active key at once, without
//! the publish-ahead window, so the memberships are revised as soon as it commits, and a member
//! pins the replacement when it opens its next session rather than refusing every new head for up
//! to a minute.

use std::sync::Arc;
use std::time::Duration;

use permguard_host::api::HostApi;
use permguard_host::membership::service::Coordinating;

/// How often the pass runs.
pub const PASS: Duration = Duration::from_secs(60);
/// The single job the coordinator's revision is (WP-28.2): of the instances, the holder of its
/// lease revises the memberships, at its pass and at a revocation it committed itself.
pub const JOB: &str = "membership/repin";

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

/// Revises the memberships this Host coordinates for its moved rings, and retires what is due.
async fn revise(coordinating: &Arc<Coordinating>, jobs: &permguard_host::jobs::Jobs) {
    let (revising, jobs) = (Arc::clone(coordinating), jobs.clone());
    match tokio::task::spawn_blocking(move || {
        let mut revised = Ok(0);
        jobs.run(JOB, PASS, &mut || {
            revised = revising
                .revise_coordinated()
                .and_then(|revised| Ok(revised + revising.retire_due()?));
            revised.is_ok()
        });
        revised
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
}

/// Runs the pass now and every [`PASS`] until the handle is dropped; the memberships also as soon
/// as a revocation commits. With `imports`, the pass also imports the origins' history.
pub fn drive(
    coordinating: Arc<Coordinating>,
    api: Arc<HostApi>,
    egress: Egress,
    imports: bool,
    jobs: permguard_host::jobs::Jobs,
) -> Repinning {
    let moved = Arc::new(tokio::sync::Notify::new());
    let waking = Arc::clone(&moved);
    if let Err(error) = api.on_rings_moved(Arc::new(move || waking.notify_one())) {
        tracing::warn!(
            event.name = "host.membership.repin_unhooked",
            component = "host",
            error = %error,
            "a revocation is re-pinned at the next pass, not at once"
        );
    }
    Repinning(tokio::spawn(async move {
        let mut interval = tokio::time::interval(PASS);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = interval.tick() => {}
                () = moved.notified() => {
                    // A revocation committed: the memberships now, the rest at the pass.
                    revise(&coordinating, &jobs).await;
                    continue;
                }
            }
            revise(&coordinating, &jobs).await;
            // What the coordinators decided since the last pass, adopted before anything is
            // shipped under a membership they may have suspended or revoked (BUG-0152).
            let _ = api.sync_due().await;
            let repinned = api.repin_due().await + api.cutover_due().await;
            // Reconciled, never shipped here: without a shipper (an embedded test composition),
            // the pass ships as it did.
            let shipped = if api.wake_shipping(true) {
                0
            } else {
                api.ship_due().await
            };
            // The origins' history this Host imports, after what it ships (WP-6.2c2a), unless a
            // `shared-bounded` member's own pass imports it (BUG-0130).
            let imported = if imports { api.import_due().await } else { 0 };
            if imported > 0 {
                tracing::debug!(
                    event.name = "host.membership.imported",
                    component = "host",
                    batches = imported,
                    "this Host's import tasks brought the origins' batches"
                );
            }
            // The Authority Plane's status lists are fetched on their own cadence
            // (`authority_refresh`).
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
