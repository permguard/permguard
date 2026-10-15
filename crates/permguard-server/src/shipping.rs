// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The evidence-aware drain and its recovery (WP-5.8, owner decisions of 2026-10-15).
//!
//! ```text
//! drain   ─▶ ship until no stream is behind its required subscriptions, or the deadline
//!         ─▶ shipped: complete
//!         ─▶ not shipped: each stream behind marked `unshipped` in its STATE, incomplete (75)
//! start   ─▶ in Load, one pass on the marked streams within the drain budget
//!         ─▶ a mark that remains keeps the Host `degraded: evidence`
//! ```
//!
//! The engine never truncates past an acknowledgement, so a stream left behind keeps every record
//! the next process ships.

use std::time::{Duration, Instant};

use anyhow::{Result, anyhow};

use permguard_core::Drained;
use permguard_host::api::HostApi;

/// How long a drain waits before asking a coordinator again that took nothing.
const RETRY: Duration = Duration::from_millis(250);

/// The component the drain and the recovery log as.
const COMPONENT: &str = "host";

/// Ships until no stream is behind its required subscriptions or `deadline`; a stream still
/// behind is marked `unshipped` and the drain is incomplete. A drain that cannot read or mark its
/// streams fails: it is never reported complete.
pub async fn drain(api: &HostApi, deadline: Instant) -> Result<Drained> {
    if !api.ships_streams() {
        return Ok(Drained::Complete);
    }
    // A subscription is kept by the first pass that ships to it: every live membership's are
    // kept now, and one pass runs, before a stream is judged shipped (after the review).
    api.register_subscriptions()
        .map_err(|error| anyhow!("keeping the subscriptions to ship: {error}"))?;
    let mut passed = false;
    loop {
        let behind = api
            .shipping_behind()
            .map_err(|error| anyhow!("reading the streams to ship: {error}"))?;
        if passed && !behind {
            api.settle_unshipped()
                .map_err(|error| anyhow!("settling the unshipped marks: {error}"))?;
            return Ok(Drained::Complete);
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        let first = !passed;
        passed = true;
        match tokio::time::timeout(left, api.ship_due()).await {
            // A coordinator deferring or unreachable is asked again shortly.
            Ok(0) if behind || !first => tokio::time::sleep(left.min(RETRY)).await,
            Ok(_) => {}
            Err(_) => break,
        }
    }
    if !passed {
        return Ok(Drained::Incomplete(
            "the drain deadline passed before any stream was shipped".to_owned(),
        ));
    }
    let marked = api
        .mark_unshipped()
        .map_err(|error| anyhow!("marking the unshipped streams: {error}"))?;
    if marked.is_empty() {
        // Shipped as the deadline came.
        return Ok(Drained::Complete);
    }
    for mark in &marked {
        tracing::warn!(
            event.name = "host.stream_unshipped",
            component = COMPONENT,
            stream = %mark.stream,
            resource = %mark.resource,
            tail = mark.tail,
            truncate_safe = mark.truncate_safe,
            "a stream is left behind its required subscriptions: the volume holds evidence"
        );
    }
    Ok(Drained::Incomplete(format!(
        "{} stream(s) left unshipped behind their required subscriptions; the volume keeps them \
         for a fenced recovery",
        marked.len()
    )))
}

/// Resumes shipping the streams an incomplete drain marked, while the Host is in Load: one pass
/// within `budget`. A mark that remains keeps the Host `degraded: evidence`, and the periodic
/// passes go on.
pub async fn resume(api: &HostApi, budget: Duration) {
    let marked = match api.settle_unshipped() {
        Ok(marked) => marked,
        Err(error) => {
            tracing::error!(
                event.name = "host.stream_resume_failed",
                component = COMPONENT,
                error = %error,
                "the unshipped marks could not be read: the periodic passes try again"
            );
            return;
        }
    };
    if marked.is_empty() {
        return;
    }
    tracing::info!(
        event.name = "host.stream_resuming",
        component = COMPONENT,
        streams = marked.len(),
        "resuming the streams an incomplete drain left"
    );
    let _ = tokio::time::timeout(budget, api.ship_due()).await;
    match api.settle_unshipped() {
        Ok(remaining) if remaining.is_empty() => tracing::info!(
            event.name = "host.stream_resumed",
            component = COMPONENT,
            "every stream an incomplete drain left is shipped"
        ),
        Ok(remaining) => tracing::warn!(
            event.name = "host.stream_unshipped",
            component = COMPONENT,
            streams = remaining.len(),
            "streams are still behind their required subscriptions: degraded until shipped"
        ),
        Err(error) => tracing::error!(
            event.name = "host.stream_resume_failed",
            component = COMPONENT,
            error = %error,
            "the unshipped marks could not be settled: the periodic passes try again"
        ),
    }
}
