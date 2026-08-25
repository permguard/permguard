// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Recording what this plane decided, as specified in `docs/decision-logs.md`.
//!
//! ```text
//! decide ──► journal ──► spool (durable, local)
//!                            │
//!                            ▼  batched, signed, at-least-once
//!                        control plane
//! ```
//!
//! Two properties shape everything here, and they are in tension only if the
//! log is on the decision path — which is why it is not:
//!
//! - **The decision path never waits on the log.** Not for the network, not
//!   for an acknowledgement, not in any mode. Even a plane configured to
//!   refuse rather than decide unrecorded checks a local spool, never a
//!   socket.
//! - **A record is durable before it is shipped.** A restart loses nothing,
//!   and a control plane that is down for a day costs spool, not availability.
//!
//! [`shipper`] is the sending half. [`journal`] is the writing half: it turns a decision into a record at the
//! position the chain demands, and ends the stream when the spool reaches a
//! bound. [`measure`] is what it reports about itself.

pub mod journal;
pub mod measure;
pub mod service;
pub mod shipper;

pub use journal::{Journal, Written};
pub use service::DecisionService;

use std::sync::{Arc, OnceLock};

use permguard_core::ServerContext;

/// The journal this plane writes to, when it keeps a decision log.
///
/// A singleton for the same reason the decider is one: there is exactly one
/// spool, and a second writer would share its sequence. Two records claiming
/// one `(stream, seq)` closes a stream permanently at the far end, so the
/// impossibility is arranged here rather than trusted to callers.
static JOURNAL: OnceLock<Option<Arc<Journal>>> = OnceLock::new();

/// Resolves the secret input commitments are taken under.
///
/// Resolved here, at startup, and held as bytes: the decision path may not do
/// I/O, and a commitment scheme that reached for a secret store per decision
/// would be one that fails under exactly the load it is meant to record.
fn commitment_key(context: &ServerContext<'_>) -> anyhow::Result<permguard_decisions::Commitment> {
    use anyhow::Context as _;

    let config = context.config();
    let reference = config
        .log_commitment_key_ref()
        .context("the decision log is enabled and names no commitment key")?;
    let secrets = context
        .secrets()
        .context("the decision log is enabled and this build resolved no secret store")?;
    // The reference is safe to name in an error; what it resolves to never is.
    let key = secrets.resolve(reference).with_context(|| {
        format!(
            "resolving the decision-log commitment key `{}` from the {} secret store",
            reference.name(),
            secrets.name()
        )
    })?;
    if key.expose().len() < MINIMUM_COMMITMENT_KEY_LENGTH {
        anyhow::bail!(
            "the secret `{}` is shorter than {MINIMUM_COMMITMENT_KEY_LENGTH} bytes, which is too \
             short to commit to caller attributes with",
            reference.name()
        );
    }

    Ok(permguard_decisions::Commitment::new(
        key.expose().to_vec(),
        config.log_commitment_key_version(),
    ))
}

/// The shortest key this plane will commit under.
///
/// The same floor the pseudonym key has, for the same reason: below it, an
/// exhaustive search over the key is cheaper than a dictionary over the values.
const MINIMUM_COMMITMENT_KEY_LENGTH: usize = 32;

/// Renders a sampling rate the way it is written in configuration.
///
/// `1` and `1.0` are the same number and not the same claim: a reader of the
/// log is being told what the stream claims to be complete about, and a rate
/// that prints as an integer reads like a count.
fn rate(value: f64) -> String {
    let rendered = format!("{value}");
    if rendered.contains('.') {
        return rendered;
    }

    format!("{rendered}.0")
}

/// Opens the journal from the plane's configuration, once.
///
/// `None` when the log is off, or when the spool could not be opened — and the
/// second is not silent: a plane configured to record and unable to is a plane
/// whose operator must hear about it.
pub fn journal(context: &ServerContext<'_>) -> Option<Arc<Journal>> {
    JOURNAL
        .get_or_init(|| {
            let config = context.config();
            if !config.log_enabled() {
                return None;
            }
            let directory = config.working_dir().join(config.log_spool_directory());
            let epoch = journal::Epoch {
                version: config.version().to_owned(),
                build: None,
                // What the manifest's load gate constrains as a range, the
                // marker records as the build that was actually inside it.
                engines: permguard_languages::lookup::languages()
                    .iter()
                    .map(|language| {
                        (
                            language.name().to_owned(),
                            language.language_version().to_owned(),
                        )
                    })
                    .collect(),
                sampling: rate(config.log_sample_permits()),
            };
            let bounds = permguard_decisions::spool::Bounds {
                bytes: config.log_spool_bytes(),
                age: config.log_spool_age(),
                segment_bytes: 8 * 1024 * 1024,
            };
            // The commitment key is the pseudonym key's sibling: a real secret,
            // resolved once from the store, versioned so a reader can tell a
            // different value from a different key, and never looked up on the
            // decision path.
            let commitment = match commitment_key(context) {
                Ok(commitment) => commitment,
                Err(error) => {
                    tracing::error!(
                        event.name = "decisions.unavailable",
                        component = "data-plane",
                        error = %error,
                        "the decision log is configured and its commitment key could not be resolved"
                    );

                    return None;
                }
            };

            match Journal::open(
                &directory,
                config.log_pdp_id(),
                epoch,
                if config.log_on_full_open() {
                    journal::WhenFull::Open
                } else {
                    journal::WhenFull::Closed
                },
                bounds,
                commitment,
                context.metrics().clone(),
            ) {
                Ok(journal) => Some(Arc::new(journal)),
                Err(error) => {
                    tracing::error!(
                        event.name = "decisions.unavailable",
                        component = "data-plane",
                        error = %error,
                        "the decision log is configured and this plane cannot write it"
                    );

                    None
                }
            }
        })
        .clone()
}
