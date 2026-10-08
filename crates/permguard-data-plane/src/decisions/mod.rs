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
//! Two properties shape everything here:
//!
//! - **The decision path never waits on the *network*.** Not for a delivery, not for an
//!   acknowledgement, not in any mode. Even a plane configured to refuse rather than decide
//!   unrecorded checks a local spool, never a socket — so a control plane down for a day costs
//!   spool, not availability.
//! - **A record is durable before its decision is answered.** A restart loses nothing, and no
//!   caller holds a permit this plane cannot account for afterwards.
//!
//! The second one *is* on the decision path, deliberately, and it is not free: writing the record
//! durably is measured at roughly ten times the evaluation it records — the dominant cost of a
//! decision on this plane, and the price of an audit trail that survives the process.
//! `bench/decide.js` reports both numbers so the trade is a number rather than a belief.
//!
//! [`shipper`] is the sending half. [`mod@journal`] is the writing half: it turns a decision into a record at the
//! position the chain demands, and ends the stream when the spool reaches a
//! bound. [`measure`] is what it reports about itself.

pub mod journal;
pub mod measure;
pub mod service;
pub mod shipper;

pub use journal::{Journal, Written};
pub use service::DecisionService;

use std::sync::{Arc, OnceLock};

use permguard_core::PlaneContext;

/// The journal this plane writes to, when it keeps a decision log.
///
/// A singleton for the same reason the decider is one: there is exactly one
/// spool, and a second writer would share its sequence. Two records claiming
/// one `(stream, seq)` closes a stream permanently at the far end, so the
/// impossibility is arranged here rather than trusted to callers.
static JOURNAL: OnceLock<Option<Arc<Journal>>> = OnceLock::new();

/// The scheme input tags are taken under: the Host's zone keys of `decision.commitment`, one key
/// per ledger (WP-3.3). Held by the Host, derived in memory or read at start, so the decision path
/// does no I/O; this plane holds the handle and never a key's bytes.
fn commitment_key(context: &PlaneContext<'_>) -> anyhow::Result<permguard_decisions::Commitment> {
    use anyhow::Context as _;

    let keys = crate::handles::zone_key(
        context,
        permguard_host::secrets::ZonePurpose::DecisionCommitment,
    )
    .context(
        "the decision log is enabled and the Host holds no zone keys for input tags: set \
         `operations.secrets.coordinator_root_ref`",
    )?;
    let version = keys.version().to_string();

    Ok(permguard_decisions::Commitment::with_scoped_mac(
        version,
        move |(zone, ledger), parts| keys.mac(zone, ledger, parts),
    ))
}

/// The file in the spool naming every zone key version this plane has tagged under, with the
/// witness of that version's key (WP-3.3).
pub const ZONE_KEYS_FILE: &str = "ZONE_KEYS";

/// Refuses a zone key version that would name two keys in the spool at `directory`: one the
/// records already written used with another scheme or another key, as their markers' `key_version`
/// says, or one witnessed here under another key. Records the version and its witness the first
/// time (owner decision of 2026-10-08).
///
/// The witness is the tag of a fixed input under the key of the nil zone and ledger: it names the
/// key without showing it. A Host holding only delivered keys cannot compute it and records `-`.
pub fn check_zone_key_version(
    directory: &std::path::Path,
    keys: &permguard_host::secrets::ZoneHandle,
) -> anyhow::Result<()> {
    use anyhow::Context as _;

    let version = keys.version().to_string();
    let witness = keys
        .mac(
            &[0; 16],
            &[0; 16],
            &[permguard_core::domains::digest::SECRET_WITNESS.as_bytes()],
        )
        .map_or_else(
            || "-".to_owned(),
            |tag| tag.iter().map(|byte| format!("{byte:02x}")).collect(),
        );
    let path = directory.join(ZONE_KEYS_FILE);
    let held = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => return Err(error).with_context(|| format!("reading {}", path.display())),
    };
    let entries: Vec<(String, String)> = held
        .lines()
        .filter_map(|line| line.split_once('\t'))
        .map(|(version, witness)| (version.to_owned(), witness.to_owned()))
        .collect();
    if let Some((_, recorded)) = entries.iter().find(|(held, _)| *held == version) {
        if recorded != "-" && witness != "-" && *recorded != witness {
            anyhow::bail!(
                "the zone key version `{version}` names another key than the one this spool \
                 recorded it with: a new key takes a new `operations.secrets.zone_key_version`"
            );
        }
        return Ok(());
    }
    if marker_versions(directory)?.contains(&version) {
        anyhow::bail!(
            "this spool holds records whose markers name `{version}` under the commitment key \
             before zone keys (WP-3.3): raise `operations.secrets.zone_key_version` so one version \
             never names two keys"
        );
    }
    let mut text = held;
    text.push_str(&format!("{version}\t{witness}\n"));
    std::fs::create_dir_all(directory)
        .with_context(|| format!("creating {}", directory.display()))?;
    let dir = permguard_host::storage::Dir::create_root(directory)
        .with_context(|| format!("opening {}", directory.display()))?;
    permguard_host::storage::write::replace_bytes(&dir, ZONE_KEYS_FILE, text.as_bytes())
        .with_context(|| format!("writing {}", path.display()))
}

/// The `commitments.key_version` of every marker in the spool's segments.
fn marker_versions(directory: &std::path::Path) -> anyhow::Result<Vec<String>> {
    use anyhow::Context as _;

    let mut versions = Vec::new();
    let entries = match std::fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(versions),
        Err(error) => {
            return Err(error).with_context(|| format!("listing {}", directory.display()));
        }
    };
    for entry in entries {
        let path = entry
            .with_context(|| format!("listing {}", directory.display()))?
            .path();
        if path.extension().and_then(std::ffi::OsStr::to_str) != Some("jsonl") {
            continue;
        }
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        for line in text.lines() {
            let Ok(record) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            if record["kind"] == "marker"
                && let Some(version) = record["commitments"]["key_version"].as_str()
                && !versions.iter().any(|held| held == version)
            {
                versions.push(version.to_owned());
            }
        }
    }
    Ok(versions)
}

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
pub fn journal(context: &PlaneContext<'_>) -> Option<Arc<Journal>> {
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

            // The zone key version must never name two keys in this spool (WP-3.3, owner decision
            // of 2026-10-08): refused when the records already written used it under another key.
            let checked = crate::handles::zone_key(
                context,
                permguard_host::secrets::ZonePurpose::DecisionCommitment,
            )
            .ok_or_else(|| anyhow::anyhow!("the Host holds no zone keys for input tags"))
            .and_then(|keys| check_zone_key_version(&directory, &keys));
            if let Err(error) = checked {
                tracing::error!(
                    event.name = "decisions.unavailable",
                    component = "data-plane",
                    error = %format!("{error:#}"),
                    "the decision log is configured and its zone key version cannot be used"
                );
                return None;
            }

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
