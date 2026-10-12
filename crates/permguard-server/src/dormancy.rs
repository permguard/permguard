// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The dormancy pass (WP-4.6): every minute, the memberships this Host coordinates are suspended
//! once silent past their `dormant_after` and revoked once silent past their `revoke_after`.

use std::sync::Arc;
use std::time::Duration;

use permguard_host::membership::service::Coordinating;

/// How often the pass runs.
pub const PASS: Duration = Duration::from_secs(60);

/// The running pass; dropping it stops it.
pub struct Dormancy(tokio::task::JoinHandle<()>);

impl Drop for Dormancy {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Runs the pass now and every [`PASS`] until the handle is dropped.
pub fn drive(coordinating: Arc<Coordinating>) -> Dormancy {
    Dormancy(tokio::spawn(async move {
        let mut interval = tokio::time::interval(PASS);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            let passing = Arc::clone(&coordinating);
            match tokio::task::spawn_blocking(move || passing.dormancy_due()).await {
                Ok(0) => {}
                Ok(moved) => tracing::info!(
                    event.name = "host.membership.dormancy_applied",
                    component = "host",
                    memberships = moved,
                    "memberships silent past their thresholds are suspended or revoked"
                ),
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
