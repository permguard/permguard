// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The dormancy pass (WP-4.6): every minute, the memberships this Host coordinates are suspended
//! once silent past their `dormant_after` and revoked once silent past their `revoke_after`.

use std::sync::Arc;
use std::time::Duration;

use permguard_host::membership::service::Coordinating;

/// How often the pass runs.
pub const PASS: Duration = Duration::from_secs(60);
/// The single job the pass is (WP-28.2).
pub const JOB: &str = "membership/dormancy";

/// The running pass; dropping it stops it.
pub struct Dormancy(tokio::task::JoinHandle<()>);

impl Drop for Dormancy {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Runs the pass now and every [`PASS`] until the handle is dropped.
pub fn drive(coordinating: Arc<Coordinating>, jobs: permguard_host::jobs::Jobs) -> Dormancy {
    Dormancy(tokio::spawn(async move {
        let mut interval = tokio::time::interval(PASS);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            let (passing, jobs) = (Arc::clone(&coordinating), jobs.clone());
            // One instance applies dormancy a pass: the job's lease (WP-28.2).
            match tokio::task::spawn_blocking(move || {
                let mut moved = 0;
                jobs.run(JOB, PASS, &mut || {
                    moved = passing.dormancy_due();
                    true
                });
                moved
            })
            .await
            {
                Ok(0) => {}
                Ok(moved) => {
                    tracing::info!(
                        event.name = "host.membership.dormancy_applied",
                        component = "host",
                        memberships = moved,
                        "memberships silent past their thresholds are suspended or revoked"
                    );
                }
                Err(error) => tracing::error!(
                    event.name = "host.membership.dormancy_failed",
                    component = "host",
                    error = %error,
                    "the dormancy pass stopped; the next pass tries again"
                ),
            }
        }
    }))
}
