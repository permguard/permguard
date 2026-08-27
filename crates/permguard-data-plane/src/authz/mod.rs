// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Answering decisions: the data plane's reason to exist.
//!
//! # What this is
//!
//! `permguard.pdp.v1`, Permguard's native policy decision interface, served over HTTP and gRPC
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
            .with_expiry(config.mirrors_expire_after()),
        )
    }))
}

/// The base URL this plane publishes in its configuration document.
///
/// What a PEP would have dialled to reach it: the configured public address,
/// with the scheme its TLS settings imply. A deployment behind a proxy states
/// its own — one setting, later; guessing from a `Host` header would let a
/// caller choose what we publish about ourselves.
pub fn base_url(context: &ServerContext<'_>) -> String {
    let config = context.config();
    let scheme = if config.public_tls().is_some() {
        "https"
    } else {
        "http"
    };
    let address = config
        .setting(permguard_server::plane::SETTING_DATA_HTTP_ADDR)
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| "127.0.0.1:7656".to_owned());

    format!("{scheme}://{address}")
}
