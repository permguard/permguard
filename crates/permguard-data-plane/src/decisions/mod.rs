// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Recording what this plane decided, as specified in `docs/decision-logs.md`.
//!
//! ```text
//! decide ──► HostLog ──► the Host's producer `data/decisions` (durable, local)
//!                            │
//!                            ▼  sealed, shipped over `decisions.ship`, at-least-once
//!                        coordinator
//! ```
//!
//! Two properties shape everything here:
//!
//! - **The decision path never waits on the *network*.** Not for a delivery, not for an
//!   acknowledgement, not in any mode. A plane that refuses rather than decides unrecorded checks
//!   its local stream, never a socket — so a coordinator down for a day costs disk, not
//!   availability.
//! - **A record is durable before its decision is answered** (`required`, WP-6.1). A restart loses
//!   nothing, and a decision that cannot be recorded is refused `unavailable`.
//!
//! The second one *is* on the decision path, deliberately, and it is not free: writing the record
//! durably is the dominant cost of a decision on this plane, and the price of an audit trail that
//! survives the process. `bench/decide.js` reports both numbers so the trade is a number rather
//! than a belief.
//!
//! [`host`] is the writing half since WP-6.1: the Host's engine owns the run, the sequence, the
//! flush, the reserve and the shipping. [`mod@journal`] and [`shipper`] are the version 1 spool's,
//! kept to ship what an upgraded plane's spool still holds until it is empty (owner decision of
//! 2026-10-16); nothing new is written there. [`measure`] is what the log reports about itself.

pub mod host;
pub mod journal;
pub mod measure;
pub mod service;
pub mod shipper;

pub use host::HostLog;
pub use journal::{Decided, Journal, Written};
pub use service::DecisionService;

use std::sync::{Arc, OnceLock};

use permguard_core::PlaneContext;

/// What the decision path records a decision with (WP-6.1).
pub trait DecisionRecorder: Send + Sync {
    /// Records one decision, answering once it is durable or saying why it is not.
    fn record(&self, decided: &Decided<'_>) -> Result<Written, String>;

    /// Records one decision, and says where a written record sits (WP-6.6): what a response's
    /// evidence names, `None` where the recorder cannot name it.
    fn record_located(
        &self,
        decided: &Decided<'_>,
    ) -> Result<(Written, Option<permguard_languages::attestation::Position>), String>;

    /// Whether a decision that cannot be recorded must be refused.
    fn refuses_unrecorded(&self) -> bool;
}

impl DecisionRecorder for Journal {
    fn record(&self, decided: &Decided<'_>) -> Result<Written, String> {
        Journal::record(self, decided).map_err(|error| error.to_string())
    }

    /// The version 1 spool's stream: its plane id and instance, as its records name them.
    fn record_located(
        &self,
        decided: &Decided<'_>,
    ) -> Result<(Written, Option<permguard_languages::attestation::Position>), String> {
        let written = Journal::record(self, decided).map_err(|error| error.to_string())?;
        let position = match (&written, self.stream()) {
            // A retry answered from the journal may sit in an instance that has since ended: only
            // a record this call wrote is named in the instance live now.
            (Written::Recorded { seq }, Some(stream)) => {
                Some(permguard_languages::attestation::Position {
                    host_id: stream.id,
                    run: stream.instance,
                    sequence: seq.to_string(),
                })
            }
            _ => None,
        };
        Ok((written, position))
    }

    fn refuses_unrecorded(&self) -> bool {
        Journal::refuses_unrecorded(self)
    }
}

/// The log this plane records to, when it keeps one: a singleton, so one process marks each run
/// once and measures each stream once.
static HOST_LOG: OnceLock<Option<Arc<HostLog>>> = OnceLock::new();

/// The version 1 spool an upgraded plane still ships from, when it holds anything unshipped.
static LEGACY: OnceLock<Result<Option<Arc<Journal>>, String>> = OnceLock::new();

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

/// The file naming every zone key version this plane has tagged under, with the witness of that
/// version's key (WP-3.3): beside the spool directory since WP-6.1c, the spool being archived and
/// its directory removed once its shipper sent it.
pub const ZONE_KEYS_FILE: &str = permguard_decisions::archive::ZONE_KEYS;

/// Where the zone key witness of the spool at `spool` lives: beside it, in its parent directory.
pub fn zone_keys_path(spool: &std::path::Path) -> std::path::PathBuf {
    spool.parent().unwrap_or(spool).join(ZONE_KEYS_FILE)
}

/// Refuses a zone key version that would name two keys in this plane's decision log: one the
/// legacy records used with another scheme or another key, as their markers' `key_version` says,
/// in the spool at `spool` or in its archive at `archive`, or one witnessed under another key.
/// Records the version and its witness the first time (owner decision of 2026-10-08).
///
/// The witness is the tag of a fixed input under the key of the nil zone and ledger: it names the
/// key without showing it. A Host holding only delivered keys cannot compute it and records `-`.
/// It lives beside the spool, seeded once from the copy a release before WP-6.1c kept in the
/// spool, or from the archive's when the spool went (owner decision of 2026-10-18).
pub fn check_zone_key_version(
    spool: &std::path::Path,
    archive: &std::path::Path,
    keys: &permguard_host::secrets::ZoneHandle,
) -> anyhow::Result<()> {
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
    let path = zone_keys_path(spool);
    // A seed is written beside the spool only once the version passed: nothing is recorded on a
    // refusal (after the review).
    let (held, seeded) = match read_witness(&path)? {
        Some(text) => (text, false),
        None => match read_witness(&spool.join(ZONE_KEYS_FILE))?.map_or_else(
            || read_witness(&archive.join(ZONE_KEYS_FILE)),
            |seed| Ok(Some(seed)),
        )? {
            Some(seed) => (seed, true),
            None => (String::new(), false),
        },
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
        return if seeded {
            write_witness(&path, &held)
        } else {
            Ok(())
        };
    }
    if marker_versions(spool)?.contains(&version) || marker_versions(archive)?.contains(&version) {
        anyhow::bail!(
            "this spool holds records whose markers name `{version}` under the commitment key \
             before zone keys (WP-3.3): raise `operations.secrets.zone_key_version` so one version \
             never names two keys"
        );
    }
    let mut text = held;
    text.push_str(&format!("{version}\t{witness}\n"));
    write_witness(&path, &text)
}

/// The witness file at `path`, when there is one.
fn read_witness(path: &std::path::Path) -> anyhow::Result<Option<String>> {
    use anyhow::Context as _;

    match std::fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("reading {}", path.display())),
    }
}

/// Replaces the witness file at `path` with `text`.
fn write_witness(path: &std::path::Path, text: &str) -> anyhow::Result<()> {
    use anyhow::Context as _;

    let directory = path.parent().unwrap_or(path);
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

/// The epoch this process records under: its version, its engines and its permit sampling.
fn epoch_of(config: &permguard_core::Config) -> journal::Epoch {
    journal::Epoch {
        version: config.version().to_owned(),
        build: None,
        // What the manifest's load gate constrains as a range, the marker records as the build
        // that was actually inside it.
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
    }
}

/// The decision log on the Host's producer, from the plane's configuration, once (WP-6.1).
///
/// `None` when the log is off, or when it cannot be written — and the second is not silent: a
/// plane configured to record and unable to is a plane whose operator must hear about it, and
/// [`DecisionService`] refuses to start.
pub fn host_log(context: &PlaneContext<'_>) -> Option<Arc<HostLog>> {
    HOST_LOG
        .get_or_init(|| {
            let config = context.config();
            if !config.log_enabled() {
                return None;
            }
            let unavailable = |error: &str| {
                tracing::error!(
                    event.name = "decisions.unavailable",
                    component = "data-plane",
                    error = error,
                    "the decision log is configured and this plane cannot write it"
                );
            };
            let Some(producer) = crate::handles::decision_producer(context) else {
                unavailable("the Host composes no stream engine producing `data/decisions`");
                return None;
            };
            let Some(host_id) = crate::handles::host_id(context) else {
                unavailable("the Host composes no identity to name the decision stream with");
                return None;
            };
            let commitment = match commitment_key(context) {
                Ok(commitment) => commitment,
                Err(error) => {
                    unavailable(&format!("{error:#}"));
                    return None;
                }
            };
            // The zone key version must never name two keys under this plane's decision log
            // (WP-3.3, owner decision of 2026-10-08), witnessed beside the spool (WP-6.1c).
            let directory = config.working_dir().join(config.log_spool_directory());
            let checked = crate::handles::zone_key(
                context,
                permguard_host::secrets::ZonePurpose::DecisionCommitment,
            )
            .ok_or_else(|| anyhow::anyhow!("the Host holds no zone keys for input tags"))
            .and_then(|keys| {
                check_zone_key_version(
                    &directory,
                    &config
                        .working_dir()
                        .join(permguard_decisions::archive::TARGET),
                    &keys,
                )
            });
            if let Err(error) = checked {
                unavailable(&format!("{error:#}"));
                return None;
            }
            Some(Arc::new(HostLog::new(
                producer,
                host_id,
                epoch_of(config),
                commitment,
                host::Bounds {
                    max_bytes: config.log_spool_bytes(),
                    max_age_secs: config.log_spool_age().as_secs(),
                },
                context.metrics().clone(),
            )))
        })
        .clone()
}

/// What the decision path records with: the [`host_log`].
pub fn recorder(context: &PlaneContext<'_>) -> Option<Arc<dyn DecisionRecorder>> {
    host_log(context).map(|log| log as Arc<dyn DecisionRecorder>)
}

/// The version 1 spool an upgraded plane left, opened for its shipper alone when it holds
/// anything unshipped (WP-6.1, owner decision of 2026-10-16); `None` when there is none or it is
/// empty. Never written: decisions are recorded on the Host's stream.
///
/// An error is a spool that exists and cannot be read: records nobody would ship, which the
/// plane refuses to start over rather than strand.
pub fn legacy_spool(context: &PlaneContext<'_>) -> Result<Option<Arc<Journal>>, String> {
    LEGACY
        .get_or_init(|| {
            let config = context.config();
            let directory = config.working_dir().join(config.log_spool_directory());
            open_legacy(
                &directory,
                permguard_decisions::spool::Bounds {
                    bytes: config.log_spool_bytes(),
                    age: config.log_spool_age(),
                    segment_bytes: 8 * 1024 * 1024,
                },
                context.metrics().clone(),
            )
        })
        .clone()
}

/// The legacy spool at `directory`, when it holds anything unshipped.
pub fn open_legacy(
    directory: &std::path::Path,
    bounds: permguard_decisions::spool::Bounds,
    metrics: permguard_core::Metrics,
) -> Result<Option<Arc<Journal>>, String> {
    if !holds_segments(directory)? {
        return Ok(None);
    }
    let journal = Journal::drain(directory, bounds, metrics).map_err(|error| {
        format!(
            "the legacy decision spool at {} cannot be read: {error}",
            directory.display()
        )
    })?;
    if !journal
        .holds_unshipped()
        .map_err(|error| error.to_string())?
    {
        return Ok(None);
    }
    Ok(Some(Arc::new(journal)))
}

/// Whether `directory` holds a version 1 spool's segments, opening nothing.
pub(crate) fn holds_segments(directory: &std::path::Path) -> Result<bool, String> {
    let entries = match std::fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(format!("listing {}: {error}", directory.display())),
    };
    for entry in entries {
        let path = entry
            .map_err(|error| format!("listing {}: {error}", directory.display()))?
            .path();
        if path.extension().and_then(std::ffi::OsStr::to_str) == Some("jsonl") {
            return Ok(true);
        }
    }
    Ok(false)
}
