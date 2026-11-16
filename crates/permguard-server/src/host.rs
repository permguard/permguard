// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The server host Permguard starts when a binary does not supply one of its own: the runtime's
//! (the crate boundaries refactoring, RD-15), which starts every registered service, waits, and
//! puts everything away in order, and binds nothing itself. What a server adds is here: the drain
//! of the listeners its services own.

use anyhow::{Context, Result};
use tokio::time::Instant;
use tracing::{info, warn};

pub use permguard_runtime::host::{DefaultServerHost, LAST_START_KEY};

/// Drains `surfaces` whose intake already stopped (WP-2.7): each finishes its open requests
/// until `deadline`, and a surface that had to cut requests makes the drain incomplete. For the
/// services that own listeners.
pub async fn drain_surfaces(
    component: &str,
    surfaces: Vec<permguard_transport::Surface>,
    deadline: std::time::Instant,
) -> Result<permguard_core::Drained> {
    let deadline = Instant::now() + deadline.saturating_duration_since(std::time::Instant::now());
    let mut cut = Vec::new();
    for surface in surfaces {
        let (address, complete) = surface
            .finish(deadline)
            .await
            .with_context(|| format!("draining a {component} listener"))?;
        if complete {
            info!(
                event.name = "surface.drained",
                component = component,
                address = %address,
                "drained"
            );
        } else {
            warn!(
                event.name = "surface.drain_cut",
                component = component,
                address = %address,
                "the drain deadline cut requests still in flight"
            );
            cut.push(address.to_string());
        }
    }

    Ok(if cut.is_empty() {
        permguard_core::Drained::Complete
    } else {
        permguard_core::Drained::Incomplete(format!(
            "requests in flight on {} were cut at the drain deadline",
            cut.join(", ")
        ))
    })
}
