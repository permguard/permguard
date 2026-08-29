// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Answering decisions: the data plane's reason to exist.
//!
//! # What this is
//!
//! `permguard.api.pdp.native.v1`, Permguard's stateless policy decision interface, served over HTTP and gRPC
//! from the ledgers on this plane's volume. A PEP asks *may this subject do this to this?*; this
//! answers, out of memory, in microseconds, from policies whose whole chain of custody is
//! verifiable.
//!
//! # The files, and why each exists
//!
//! | File | Owns |
//! | --- | --- |
//! | [`wire`] | the payload: the interface's shape, its defaults and its boxcarring rules |
//! | [`store`] | which mirror a zone/ledger names — directories are identities, requests are names |
//! | [`snapshot`] | the volume walk: checkpoint, commit, manifest, load gate, partitions, compile |
//! | [`block`] | the memory of a refusal, so an unserveable ledger is refused once and not every round |
//! | [`cache`] | what stays compiled in memory, inside the two bounds a deployment sets |
//! | [`decide`] | the decision itself: one path, whatever transport arrived |
//! | [`configuration`] | what this PDP publishes about the interface it serves |
//! | [`http`] / [`grpc`] / [`translate`] | the two bindings, and the mapping that keeps them identical |
//! | [`measure`] | what it counts about itself |
//!
//! # The two properties that matter
//!
//! **Fast, because nothing on the decision path touches a policy file.** A
//! partition is read off the volume once, compiled into the engine's own
//! program, and kept; the commit is part of the cache key, so a
//! synchronization that advances a ledger is picked up without a flush and a
//! replaced commit is never served.
//!
//! **Fail-closed, everywhere.** A deny is an answer (`200`, `decision: false`).
//! An error is a deny that says why. A ledger this engine may not serve is
//! `unavailable` — never a quiet deny, because a PEP has to tell "no" from
//! "ask somebody else".

pub mod audit;
pub mod block;
pub mod cache;
pub mod configuration;
pub mod decide;
pub mod grpc;
pub mod http;
pub mod measure;
pub mod quarantine;
pub mod snapshot;
pub mod store;
pub mod translate;
pub mod wire;

use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use permguard_core::ServerContext;

use cache::Cache;
use decide::Decider;

/// The one decider this process has.
///
/// Deliberately a singleton, and the reason is the cache: this plane hosts an
/// HTTP surface, a gRPC surface and a synchronization loop, and all three must
/// share one set of compiled partitions. Three caches inside one memory bound
/// would mean three times the bound — a plane that respects its container
/// limit only until the second transport is used.
static DECIDER: OnceLock<Arc<Decider>> = OnceLock::new();

/// The decision path, built from the plane's configuration on first use and
/// shared from then on.
/// How long one decision may spend evaluating: nine tenths of the transport's request timeout.
///
/// Under it on purpose. The two bounds answer different questions — the transport's is "how long
/// may a client wait", this one is "how long may a thread work" — and the second has to expire
/// first, or the work outlives the answer and holds a thread nobody is waiting for.
fn decision_budget(config: &permguard_core::Config) -> std::time::Duration {
    let timeout = config.limits().request_timeout();

    (timeout * 9 / 10).max(std::time::Duration::from_millis(100))
}

pub fn decider(context: &ServerContext<'_>) -> Arc<Decider> {
    Arc::clone(DECIDER.get_or_init(|| {
        let config = context.config();
        let root: PathBuf = config.mirrors_directory();
        let cache = Arc::new(Cache::new(
            config.authz_cache_partitions(),
            config.authz_cache_bytes(),
        ));

        Arc::new(
            Decider::new(
                root,
                cache,
                context.metrics().clone(),
                None,
                config.authz_max_evaluations(),
            )
            .with_blocking(crate::blocking::shared(context))
            .with_audit(audit::decision_audit(context))
            // The journal is opened once for the plane, not once per decider:
            // there is one spool, and a second writer would share its sequence.
            .with_journal(
                crate::decisions::journal(context),
                context
                    .recorder()
                    .and_then(permguard_core::AuditRecorder::pseudonymizer),
                config.log_include().clone(),
            )
            .with_expiry(config.mirrors_expire_after())
            // A little under the transport's own request timeout, so the work stops before the
            // answer is abandoned rather than after it — the gap is what makes the difference
            // between a plane that sheds load and one that accumulates it.
            .with_budget(Some(decision_budget(config)))
            // What this deployment has opted into. A ledger naming a provisional contract it has
            // not enabled is refused at load rather than served.
            .with_enabled(permguard_languages::registry::Enabled::from_names(
                config.experimental_enabled_names(),
            )),
        )
    }))
}

/// The base URL this plane publishes in its configuration document.
///
/// **One source**, shared with the plane's own discovery document, because two were one too many:
/// this used to read the *global* TLS setting while the listener bound with the *data plane's*,
/// so a plane serving HTTPS could publish `http://` endpoints — and it read the bind address
/// directly, so behind a Service it published `0.0.0.0`. Both are documents a client cannot
/// follow, and neither failure shows up anywhere except in a caller that cannot connect.
pub fn base_url(context: &ServerContext<'_>) -> String {
    permguard_server::plane::plane_http_base(
        context.config(),
        permguard_server::plane::PlaneId::Data,
    )
    .unwrap_or_default()
}
