// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The zone keys pass (WP-4.7): every minute, this Host receives, as a member, the keys each of its
//! `zone.secrets` tasks grants whose receipt is not of its manifest's epoch.

use std::sync::Arc;
use std::time::Duration;

use permguard_host::api::HostApi;
use permguard_host::secrets::ZoneKeys;

/// How often the pass runs.
pub const PASS: Duration = Duration::from_secs(60);

/// The running pass; dropping it stops it.
pub struct Receiving(tokio::task::JoinHandle<()>);

impl Drop for Receiving {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Runs the pass now and every [`PASS`] until the handle is dropped.
pub fn drive(api: Arc<HostApi>, keys: Arc<ZoneKeys>) -> Receiving {
    Receiving(tokio::spawn(async move {
        let mut interval = tokio::time::interval(PASS);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            let received = api.zone_due(&keys).await;
            if received > 0 {
                tracing::info!(
                    event.name = "host.membership.zone_keys_received",
                    component = "host",
                    tasks = received,
                    "zone keys are received and confirmed"
                );
            }
        }
    }))
}
