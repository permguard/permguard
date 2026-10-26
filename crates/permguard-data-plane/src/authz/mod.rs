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
//! An evaluation that failed is not one: it is refused as `indeterminate`, and
//! so is a ledger this engine may not serve — never a quiet deny, because a
//! PEP has to tell "no" from "ask somebody else".

pub mod audit;
pub mod block;
pub mod cache;
pub mod configuration;
pub mod decide;
pub mod gate;
pub mod grpc;
pub mod http;
pub mod measure;
pub mod quarantine;
pub mod signing;
pub mod snapshot;
pub mod store;
pub mod translate;
pub mod wire;

use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use permguard_core::PlaneContext;

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

pub fn decider(context: &PlaneContext<'_>) -> Arc<Decider> {
    // The aliases every lookup under the configured root resolves through (WP-7.2d, F-17),
    // assigned on every call rather than once, so the configuration asked about is the one in force.
    store::assign_aliases(
        &context.config().mirrors_directory(),
        context
            .config()
            .mirror_aliases()
            .iter()
            .map(store::Alias::from_config)
            .collect(),
    );
    Arc::clone(DECIDER.get_or_init(|| {
        let config = context.config();
        let root: PathBuf = config.mirrors_directory();
        let cache = Arc::new(
            Cache::new(config.authz_cache_partitions(), config.authz_cache_bytes())
                .with_zone_bounds(
                    config.authz_cache_zone_partitions(),
                    config.authz_cache_zone_bytes(),
                ),
        );

        Arc::new(
            Decider::new(
                root,
                cache,
                context.metrics().clone(),
                None,
                config.authz_max_evaluations(),
            )
            .with_blocking(crate::blocking::shared(context))
            .with_evaluation(crate::blocking::evaluation(context))
            .with_evidence(crate::blocking::evidence(context))
            .with_audit(audit::decision_audit(context))
            // The log is opened once for the plane, not once per decider: one process marks each
            // run of a stream once and measures each stream once (WP-6.1).
            // Signed responses on request, when the deployment offers them and the Host composes
            // the `data.attest` ring that signs them (WP-6.6b).
            .with_response_signing(
                config
                    .response_signing_enabled()
                    .then(|| {
                        let signer = crate::handles::response_signer(context);
                        // Configured on with no ring to sign with: discovery says `disabled`, and
                        // the operator hears why.
                        if signer.is_none() {
                            tracing::warn!(
                                event.name = "authz.response_signing_unavailable",
                                component = "data-plane",
                                "response signing is enabled and this plane composes no \
                                 `data.attest` ring: requests for a signed response are refused"
                            );
                        }
                        signer
                    })
                    .flatten()
                    .map(|signer| signing::ResponseSigning {
                        signer: Arc::new(signer),
                        validity: config.response_signing_validity(),
                        clock_skew: config.response_signing_clock_skew(),
                    }),
            )
            .with_journal(
                crate::decisions::recorder(context),
                crate::handles::zone_key(
                    context,
                    permguard_host::secrets::ZonePurpose::AuditPseudonym,
                ),
                config.log_include().clone(),
            )
            .with_expiry(config.mirrors_expire_after())
            .with_staleness(config.mirrors_stale_after())
            // A little under the transport's own request timeout, so the work stops before the
            // answer is abandoned rather than after it — the gap is what makes the difference
            // between a plane that sheds load and one that accumulates it.
            .with_budget(Some(decision_budget(config)))
            // The configured assurance profile (WP-2.8): the floor every partition meets at load,
            // and whether its engine runs supervised. A manifest cannot lower it.
            .with_profile(config.assurance().profile())
            // What this deployment has opted into. A ledger naming a provisional contract it has
            // not enabled is refused at load rather than served.
            .with_enabled(enabled(config)),
        )
    }))
}

/// What this deployment serves: the experimental runtimes it opted into, and from `production` up
/// only runtimes whose conformance gate passes (TL-6).
pub fn enabled(config: &permguard_core::Config) -> permguard_languages::registry::Enabled {
    let enabled =
        permguard_languages::registry::Enabled::from_names(config.experimental_enabled_names());
    let floor = permguard_core::assurance::AssuranceProfile::Production;
    if config.assurance().profile().at_least(floor) {
        enabled.requiring_conformance()
    } else {
        enabled
    }
}

/// One runtime as the plane's discovery lists it (TL-6): `LanguageListing` in
/// `contracts/openapi/discovery.json`, whose members are exactly these.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct LanguageListing {
    pub name: &'static str,
    pub descriptor_digest: &'static str,
    pub experimental: bool,
    pub served: bool,
    pub conformance: permguard_languages::conformance::Summary,
}

/// The runtimes this build carries as the plane's discovery lists them (TL-6): each with its
/// descriptor's digest, whether it is experimental, whether this deployment serves it, and its
/// conformance gate's result.
pub fn listings(config: &permguard_core::Config) -> Vec<LanguageListing> {
    let enabled = enabled(config);
    permguard_languages::languages()
        .iter()
        .map(|language| LanguageListing {
            name: language.name(),
            descriptor_digest: permguard_languages::descriptor::descriptor_digest(language.name())
                .unwrap_or_default(),
            experimental: language.experimental(),
            served: enabled.serves(*language),
            conformance: permguard_languages::conformance::summary(language.name()),
        })
        .collect()
}

/// [`listings`] as the plane's document carries them.
pub fn languages(config: &permguard_core::Config) -> Vec<serde_json::Value> {
    listings(config)
        .into_iter()
        .filter_map(|listing| serde_json::to_value(listing).ok())
        .collect()
}

/// The base URL this plane publishes in its configuration document.
///
/// **One source**, shared with the plane's own discovery document, because two were one too many:
/// this used to read the *global* TLS setting while the listener bound with the *data plane's*,
/// so a plane serving HTTPS could publish `http://` endpoints — and it read the bind address
/// directly, so behind a Service it published `0.0.0.0`. Both are documents a client cannot
/// follow, and neither failure shows up anywhere except in a caller that cannot connect.
pub fn base_url(context: &PlaneContext<'_>) -> String {
    permguard_server::plane::plane_http_base(
        context.config(),
        permguard_server::plane::PlaneId::Data,
    )
    .unwrap_or_default()
}
