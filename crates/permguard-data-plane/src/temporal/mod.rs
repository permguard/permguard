// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! `permguard.api.pdp.temporal.v1alpha1`: deciding against what has already happened.
//!
//! # What this is, beside the stateless interface
//!
//! [`crate::authz`] answers *may this subject do this to this?* from the request alone. This
//! answers *may this happen, given what has happened?* — and the difference is not a bigger
//! payload. It is that the plane keeps a history, that a decision depends on it, and that
//! therefore the history has to be durable **before** the decision is made and before the answer
//! goes out.
//!
//! The two interfaces share everything up to that point: the same mirrors, the same verified head,
//! the same freshness bound, the same block list, the same compiled partitions, the same decision
//! log. What is here is only what is genuinely different.
//!
//! # The order of operations, and why it is that order
//!
//! ```text
//! read ─▶ check every addressed partition ─▶ append + fsync ─▶ observe ─▶ decide ─▶ log ─▶ answer
//!           │                                  │                                        │
//!           └ nothing is written if any        └ nothing observes it until it is        └ nothing
//!             partition refuses it               on disk                                  is
//!                                                                                          answered
//!                                                                                          before
//!                                                                                          it is
//! ```
//!
//! Every arrow is load-bearing:
//!
//! - **Check before append**, because a profile may address several partitions with different
//!   schemas, and an event only one of them accepts is not an event: writing it would leave the
//!   partitions holding different histories of the same ledger.
//! - **Append before observe**, because a decision that depended on history the process then lost
//!   is a decision nothing can reproduce. There is no `on_full: open` here: silently dropping an
//!   event changes what *future* authorizations mean, so a journal that cannot accept fails the
//!   request closed.
//! - **Observe before answer**, because a caller that got a receipt for an event no engine has
//!   seen would be entitled to assume the next decision accounts for it.
//!
//! # The files
//!
//! | File | Owns |
//! | --- | --- |
//! | [`streams`] | the journals, one per ledger: identity, dedup, watermarks, replay |
//! | [`shipper`] | one round of shipping a contiguous signed batch to the control plane |
//! | [`service`] | the loop that runs those rounds, and the eviction that follows them |
//! | [`imported`] | the history the Host imports over `events.import`, read for shared decisions |
//! | [`mod@imports`] | what the retired HTTP pull imported, read-only until it is archived |
//! | [`submit`] | the one path both transports call |
//! | [`configuration`] | what this plane publishes about the interface |
//! | [`http`] / [`grpc`] | the two bindings, which share the path above and add nothing to it |
//! | [`measure`] | what it counts about itself |

pub mod configuration;
pub mod grpc;
pub mod host;
pub mod http;
pub mod imported;
pub mod imports;
pub mod measure;
pub mod sequencer;
pub mod service;
pub mod shipper;
pub mod streams;
pub mod submit;
#[doc(hidden)]
pub mod testing;

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock, Weak};

use permguard_core::PlaneContext;
use permguard_events::journal::Bounds;

use streams::Streams;
use submit::Submitter;

/// Where the plane keeps what it remembers of each ledger on the Host's event stream, below the
/// working directory (WP-6.2a).
pub const PLANE_DIRECTORY: &str = "planes/data/temporal";

/// The one submitter this process has.
///
/// A singleton for the same reason the decider is, and one more: a journal holds an exclusive lock
/// on its directory, so a second `Streams` would be a second writer for every stream this plane
/// has open — and the second one would fail to open, at the first submission, in production.
static SUBMITTER: OnceLock<Option<Arc<Submitter>>> = OnceLock::new();

/// Import stores by canonical directory, shared by the pull worker and every submitter that reads
/// them.
///
/// The index and deduplication maps inside [`imports::Imports`] are live process state. Opening the
/// same directory twice would give the puller one index to update and the decision path another,
/// stale one to query; newly imported events could then remain invisible until restart. Weak
/// entries keep tests and short-lived compositions from pinning a store after their last user.
static IMPORTS: OnceLock<Mutex<BTreeMap<PathBuf, Weak<imports::Imports>>>> = OnceLock::new();

/// The temporal path, built from the plane's configuration on first use.
///
/// `None` when the deployment did not turn the interface on, which is the ordinary case: a plane
/// that keeps a durable history should be a plane somebody chose to run.
pub fn submitter(context: &PlaneContext<'_>) -> Option<Arc<Submitter>> {
    SUBMITTER
        .get_or_init(|| {
            let config = context.config();
            if !served(config) {
                return None;
            }
            let unavailable = |why: &str| {
                tracing::error!(
                    event.name = "temporal.log_unavailable",
                    component = "temporal",
                    "the temporal interface cannot record its events: {why}"
                );
            };
            // The producer is the Host's (WP-6.2a, owner decisions of 2026-10-18): its stream
            // engine, its id and its run; no configured producer id is read.
            let Some(producer) = crate::handles::event_producer(context) else {
                unavailable("the Host composes no stream engine producing `data/events`");
                return None;
            };
            let Some(host_id) = crate::handles::host_id(context) else {
                unavailable("the Host composes no identity to name the event stream with");
                return None;
            };
            let directory: PathBuf = config.events_directory();
            let bounds = Bounds {
                max_bytes: config.events_max_bytes(),
                segment_bytes: config.events_segment_bytes(),
                max_record_bytes: config.events_max_record_bytes(),
                retention_minimum: config.events_retention_minimum(),
                allowed_lateness: config.events_allowed_lateness(),
                clock_skew: config.events_clock_skew(),
            };

            let submitter = Submitter::new(
                crate::authz::decider(context),
                Arc::new(
                    match Streams::with_group_commit(
                        directory.clone(),
                        config.working_dir().join(PLANE_DIRECTORY),
                        streams::HostSide { producer, host_id },
                        bounds,
                        config.events_group_commit_delay(),
                    ) {
                        Ok(streams) => streams.with_metrics(context.metrics().clone()),
                        Err(error) => {
                            unavailable(&error.to_string());
                            return None;
                        }
                    },
                ),
                crate::blocking::shared(context),
                context.metrics().clone(),
            );
            // A shared mode reads history other planes recorded. Off unless a deployment said so:
            // turning it on changes what the policies mean, and that is a decision rather than a
            // default that shifts when a second plane appears.
            let consistency = config.events_pull_mode();
            let submitter = match consistency.is_shared() {
                true => submitter.with_shared_history(
                    consistency,
                    imports(config),
                    config.events_pull_max_staleness(),
                ),
                false => submitter,
            };
            // The origins the member Host imports over `events.import`, from its consumer
            // (WP-6.2c2b1): what a shared mode decides on and measures its freshness from.
            let submitter = match (
                consistency.is_shared(),
                crate::handles::event_consumer(context),
            ) {
                (true, Some(consumer)) => match imported::Imported::new(
                    consumer,
                    host_id,
                    config.working_dir().join(PLANE_DIRECTORY),
                ) {
                    Ok(imported) => submitter.with_imported(Arc::new(imported)),
                    Err(error) => {
                        unavailable(&error.to_string());
                        return None;
                    }
                },
                (true, None) => {
                    // Said once: the freshness in force is the HTTP pull's last read, not a
                    // verified checkpoint (after the review).
                    tracing::warn!(
                        event.name = "temporal.import_unavailable",
                        component = "temporal",
                        "a shared mode with no Host consumer of `data/events`: no import reaches \
                         this plane, so `shared-bounded` refuses every decision and \
                         `shared-eventual` decides on its own history and what the retired HTTP \
                         pull imported before"
                    );
                    submitter
                }
                _ => submitter,
            };

            Some(Arc::new(submitter))
        })
        .clone()
}

/// This plane's import store — see [`mod@imports`] for what it holds and why it is separate.
///
/// Where imported history lives: beside the journal, never inside it.
///
/// An imported record is evidence another producer created. Putting it in this plane's journal
/// would place it inside this plane's own sequence and hash chain, which would be a claim that
/// this plane recorded it — and the next batch this plane signed would attest that claim.
pub fn imports(config: &permguard_core::Config) -> Arc<imports::Imports> {
    let root = config.events_directory().join("pull");
    let stores = IMPORTS.get_or_init(|| Mutex::new(BTreeMap::new()));
    let mut stores = match stores.lock() {
        Ok(stores) => stores,
        Err(poisoned) => poisoned.into_inner(),
    };
    if let Some(store) = stores.get(&root).and_then(Weak::upgrade) {
        return store;
    }
    let store = Arc::new(imports::Imports::new(root.clone()));
    stores.insert(root, Arc::downgrade(&store));

    store
}

/// Whether this deployment serves the temporal interface at all.
///
/// # Two switches, not one
///
/// `events.enabled` is the operator's: *this plane keeps a durable event history*. It is a
/// commitment about disks, retention and shipping, and it is off by default because a plane that
/// keeps history should be a plane somebody chose to run.
///
/// `experimental.dogwood.enabled` is a different statement: *this deployment accepts a contract
/// whose shape is not yet stable*. The temporal interface exists to decide against history the way
/// Dogwood does, and its request and record shapes are the ones that may still change — so it is
/// served only where both have been said, and a deployment that opted into neither cannot reach it
/// by turning on the one that sounds like storage.
///
/// The contradictory combination — history on, the contract not accepted — is refused at startup
/// by [`startup_check`] rather than silently served as nothing.
pub fn served(config: &permguard_core::Config) -> bool {
    config.events_enabled() && config.experimental_dogwood()
}

/// What a deployment must have said before this interface can be served.
///
/// Run at startup rather than at the first submission, because both failures are configuration
/// mistakes and a configuration mistake should stop a process rather than start one that refuses
/// every request for a reason nobody is watching for.
pub fn startup_check(config: &permguard_core::Config) -> anyhow::Result<()> {
    // Every `experimental.<name>` this deployment wrote down must name a runtime this build
    // actually gates. Checked before the events switch, because a misspelled opt-in is exactly what
    // makes the refusal below look wrong to whoever set it.
    permguard_languages::registry::check_opted_in(config.experimental_named())
        .map_err(|error| anyhow::anyhow!(error))?;

    if !config.events_enabled() {
        return Ok(());
    }
    // Said one of the two things and not the other. Refused rather than quietly served as nothing:
    // an operator who turned on an event history and finds no interface answering has a plane that
    // looks configured and is not, and nothing in its logs to say which switch it is missing.
    if !config.experimental_dogwood() {
        anyhow::bail!(
            "`dataPlane.events.enabled` is true and `experimental.dogwood.enabled` is not. The \
             temporal interface decides against history the way Dogwood does, and its request and \
             record shapes are not yet stable, so it is served only where a deployment has \
             accepted that: set `experimental.dogwood.enabled: true` to serve it, or \
             `dataPlane.events.enabled: false` if this plane should not keep an event history"
        );
    }
    // A shared mode with nothing to read from is a mode that would fail every decision closed —
    // `shared-bounded` immediately, and `shared-eventual` by ranging over an empty history that
    // never fills. Refused here, where it is a configuration mistake rather than an outage.
    if config.events_pull_mode().is_shared() && config.events_pull_ledgers().is_empty() {
        anyhow::bail!(
            "`dataPlane.events.pull.mode` is `{}` and no ledgers are subscribed to. A shared mode \
             decides against history other planes recorded, and this plane has been told to read \
             none of it: name the ledgers under `dataPlane.events.pull.ledgers`, or use `local`",
            config.events_pull_mode().as_str()
        );
    }
    // The HTTP pull is retired (WP-6.2c2b2, owner decision of 2026-10-19): the imported history
    // arrives over `events.import`, verified under the membership's pins. A configuration still
    // naming its key files is refused, so no deployment believes they are in force.
    if config.events_pull_producer_keys_declared() {
        anyhow::bail!(
            "`dataPlane.events.pull.producer_keys` is retired: the history a shared mode decides \
             on is imported by the Host over `events.import`, from its coordinator, verified \
             under the membership's pinned rings. Remove it"
        );
    }
    // One ledger, one import: a ledger named twice is a configuration mistake.
    let mut subscribed = std::collections::BTreeSet::new();
    for subscription in config.events_pull_ledgers() {
        if !subscribed.insert((&subscription.zone, &subscription.ledger)) {
            anyhow::bail!(
                "the shared event ledger `{}/{}` is declared more than once under \
                 `dataPlane.events.pull.ledgers`: name it once",
                subscription.zone,
                subscription.ledger
            );
        }
    }
    // The retention floor has to cover Dogwood's own default look-back plus what a journal must
    // allow for lateness and skew, or the first ledger loaded would be refused at its first
    // submission — which is a configuration mistake found at the worst possible moment.
    let bounds = Bounds {
        max_bytes: config.events_max_bytes(),
        segment_bytes: config.events_segment_bytes(),
        max_record_bytes: config.events_max_record_bytes(),
        retention_minimum: config.events_retention_minimum(),
        allowed_lateness: config.events_allowed_lateness(),
        clock_skew: config.events_clock_skew(),
    };
    let default_window = std::time::Duration::from_secs(
        u64::try_from(permguard_languages::dogwood_default_max_window_seconds()).unwrap_or(0),
    );
    if let Err(why) = bounds.admits(default_window) {
        anyhow::bail!(
            "`dataPlane.events.journal.retention_minimum` is too short for the temporal runtimes \
             this build carries: {why}. A partition whose policies look further back than the \
             journal keeps would answer from a history that had been emptied underneath it"
        );
    }

    Ok(())
}

/// Authorizes `event.submit` on the store `request` names, before anything is read or written,
/// and answers the source the occurrence is recorded under with the ids authorized (WP-6.2a,
/// owner decision of 2026-10-18): the principal the gate authorized, never a value the caller
/// writes.
pub(crate) fn gate(
    authorization: &permguard_host::composition::Authorization,
    actor: &permguard_core::authz::Actor,
    root: &std::path::Path,
    request: &permguard_languages::temporal::SubmitRequest,
) -> Result<(String, Option<(String, String)>), permguard_core::AccessDenial> {
    let store = request.store.as_ref();
    let authorized = crate::authz::gate::submission(
        authorization,
        actor,
        root,
        store.and_then(|store| store.zone.as_deref()),
        store.and_then(|store| store.ledger.as_deref()),
    )?;
    let source = actor.principal()?.to_string();
    Ok((source, authorized))
}
