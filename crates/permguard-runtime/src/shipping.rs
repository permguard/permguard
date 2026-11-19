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
//!
//! A Host running both Planes also ships to itself (`permguard_host::membership::local`): a short
//! pass, [`drive_local`], so its Control Plane reads its decisions and events within seconds.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow};

use permguard_core::Drained;
use permguard_host::api::HostApi;

/// How long a drain waits before asking a coordinator again that took nothing.
const RETRY: Duration = Duration::from_millis(250);

/// How often the local ship tasks run.
pub const LOCAL_PASS: Duration = Duration::from_secs(2);

/// The component the drain and the recovery log as.
const COMPONENT: &str = "host";

/// Ships until no stream is behind its required subscriptions or `deadline`; a stream still
/// behind is marked `unshipped` and the drain is incomplete. A drain that cannot read or mark its
/// streams fails: it is never reported complete.
pub async fn drain(api: &HostApi, deadline: Instant) -> Result<Drained> {
    if !api.ships_streams() {
        return Ok(Drained::Complete);
    }
    // An identity reset retired the rings that ship (BUG-0163): nothing is shipped, but what is
    // behind is marked, so the next start, under the new identity, reports it.
    if api.identity_retired() {
        return mark_behind(api, true);
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
    // A deadline the listeners' drain already spent still marks what is behind, so the next
    // process recovers it (BUG-0222): only the shipping pass is skipped, never the marks.
    mark_behind(api, passed)
}

/// Marks every stream still behind `unshipped`: the drain is incomplete when one is. `passed`
/// says whether a shipping pass ran, or none was owed.
fn mark_behind(api: &HostApi, passed: bool) -> Result<Drained> {
    let marked = api
        .mark_unshipped()
        .map_err(|error| anyhow!("marking the unshipped streams: {error}"))?;
    if marked.is_empty() {
        if !passed {
            // Nothing was behind, but no pass confirmed it: the reason says what happened.
            return Ok(Drained::Incomplete(
                "the drain deadline passed before the shipping pass ran; no stream was behind \
                 its required subscriptions"
                    .to_owned(),
            ));
        }
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
    let before = if passed {
        ""
    } else {
        "the drain deadline passed before the shipping pass ran: "
    };
    Ok(Drained::Incomplete(format!(
        "{before}{} stream(s) left unshipped behind their required subscriptions; the volume \
         keeps them for a fenced recovery",
        marked.len()
    )))
}

/// Prints the drain receipt of a recovery drain that completed (TD-2): one JSON line on standard
/// output, `{"drain_receipt": {"receipt", "bundle"}}`, which the drain controller reads from the
/// Job's log. A receipt the Host refuses to issue (a stream still behind) fails the drain, so the
/// Job never ends in success without one.
pub fn print_receipt(api: &HostApi) -> Result<()> {
    use std::io::Write as _;

    let export = api
        .drain_receipt()
        .map_err(|error| anyhow!("issuing the drain receipt: {error}"))?;
    let line = serde_json::json!({ "drain_receipt": export });
    let mut out = std::io::stdout().lock();
    writeln!(out, "{line}").map_err(|error| anyhow!("printing the drain receipt: {error}"))?;
    out.flush()
        .map_err(|error| anyhow!("printing the drain receipt: {error}"))?;
    tracing::info!(
        event.name = "host.drain_receipt",
        component = COMPONENT,
        "the drain completed and its signed receipt is printed"
    );
    Ok(())
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

/// The running local ship pass; dropping it stops it.
pub struct LocalShipping(tokio::task::JoinHandle<()>);

impl Drop for LocalShipping {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Runs the local ship tasks now and every [`LOCAL_PASS`] until the handle is dropped, each pass
/// on the blocking pool: the ingest writes the consumer's files.
pub fn drive_local(local: Arc<permguard_host::membership::local::LocalShipping>) -> LocalShipping {
    LocalShipping(tokio::spawn(async move {
        let mut interval = tokio::time::interval(LOCAL_PASS);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            let passing = Arc::clone(&local);
            match tokio::task::spawn_blocking(move || passing.ship_due()).await {
                Ok(0) => {}
                Ok(shipped) => tracing::debug!(
                    event.name = "host.local_shipped",
                    component = COMPONENT,
                    batches = shipped,
                    "this Host's Control Plane took its Data Plane's batches"
                ),
                Err(error) => tracing::error!(
                    event.name = "host.local_ship_failed",
                    component = COMPONENT,
                    error = %error,
                    "the local ship pass stopped; the next pass tries again"
                ),
            }
        }
    }))
}
/// The evidence drained at shutdown for a Host with no listener: the producers ship to their
/// required subscriptions before the deadline, and a stream left behind makes the drain
/// incomplete, marked `unshipped` and resumed at the next start.
///
/// A served Host does this in its Host listener's service, after its requests. A Host embedded in
/// an application has no such service, and would otherwise stop with decisions it owes a
/// coordinator and say nothing: a composition that makes it a member registers this.
#[derive(Debug, Default)]
pub struct EvidenceDrain;

impl permguard_core::Service for EvidenceDrain {
    fn name(&self) -> &'static str {
        "evidence-drain"
    }

    /// Nothing starts: the periodic passes are the composition's, and this is their last one.
    fn start<'a>(
        &'a self,
        _context: &'a permguard_core::ServerContext<'a>,
    ) -> permguard_core::BoxFuture<'a, Result<()>> {
        Box::pin(std::future::ready(Ok(())))
    }

    fn drain<'a>(
        &'a self,
        context: &'a permguard_core::ServerContext<'a>,
        deadline: Instant,
    ) -> permguard_core::BoxFuture<'a, Result<Drained>> {
        Box::pin(async move {
            match context.host_handles::<HostApi>() {
                // No membership side, so nothing is owed anybody.
                None => Ok(Drained::Complete),
                Some(api) => drain(&api, deadline).await,
            }
        })
    }
}
