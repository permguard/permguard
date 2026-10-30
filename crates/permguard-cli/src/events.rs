// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Events read from a Control Plane: pages of them, the lines `permguard events list` prints, and
//! what verifying a page establishes. The command is this module plus its arguments, the target,
//! the export archive and the rendering; a program that embeds the CLI reads the same lines, so
//! the JSON it keeps is the JSON the command prints.

use permguard_control_client::events::{self, EventLog, ReadError, ReadScope, ReadWindow};
use permguard_core::Jwk;
use permguard_events::envelope::Signed;
use permguard_events::{chain, merkle_of, record};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// How many pages `export`, `get` and `verify` will walk before giving up.
///
/// A bound rather than a loop: a command that walks for ever on a store that keeps growing is a
/// command nobody can put in a script.
///
/// Reaching it is **not** a successful export. It used to be: the loop ran out, whatever had been
/// read was printed, and the command exited `0` — so a snapshot that stopped a third of the way
/// through was indistinguishable, to a script, from one that finished. What the bound protects
/// against is an endless command; it must not turn a partial answer into a complete-looking one.
pub const MAX_PAGES: usize = 10_000;

/// What a report of a page states besides its lines.
#[derive(Debug, Clone, Copy, Default)]
pub struct Shape {
    /// Verify the page: the chain or the inclusion paths, and the signatures when keys are given.
    pub verify: bool,
    /// The read kept only some event types: a stream page is then not contiguous.
    pub by_type: bool,
}

/// A page of events, and what checking them concluded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventsReport {
    /// What was read: `acme/agent-governance`, or a producer stream.
    pub scope: String,
    /// One line per event.
    pub events: Vec<EventLine>,
    /// The offset to resume from, which belongs to the caller.
    pub next: String,
    /// The oldest offset still held, to resume from deliberately after a gap.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub oldest_available: String,
    /// The exclusive end this read observed. Echo it to bound an export.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub high_watermark: String,
    /// Whether the store holds more right now.
    pub more: bool,
    /// Whether this command stopped at its own page bound rather than at the end of the snapshot.
    ///
    /// Distinct from `more`, and the distinction is the point: `more` says the store has grown
    /// since, which is ordinary for a tail, while this says *these results are a prefix* of the
    /// snapshot that was asked for. A reader that treated the two as one would take an export that
    /// gave up as an export that finished.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub truncated: bool,
    /// What this page proves about what it covers.
    pub coverage: Coverage,
    /// What verification concluded, when it was asked for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified: Option<Verified>,
}

/// What a page proves about what it covers.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Coverage {
    /// Whether the records are a contiguous run whose chain links across them.
    pub contiguous: bool,
    /// How many positions the store examined to produce this page.
    pub examined: u64,
    /// Whether a scan bound stopped this page before its record or byte bound did.
    pub scan_bounded: bool,
}

/// One event, as a reader sees it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventLine {
    /// Where it sits in its producer's history.
    pub seq: u64,
    /// The caller's identifier for the occurrence.
    pub event_id: String,
    /// The registered contract it is.
    pub event_type: String,
    /// The runtime's own word for what happened.
    pub kind: String,
    /// When it happened, as the caller stated it.
    pub occurred_at: String,
    /// When this plane accepted it.
    pub observed_at: String,
    /// The profile the submission selected.
    pub profile: String,
    /// The partitions it was addressed to.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub policy_partitions: Vec<String>,
    /// The immutable commit the partitions were loaded from.
    pub commit: String,
    /// The producer that recorded it.
    pub producer: String,
    /// Which incarnation of it.
    pub instance: String,
    /// The Dogwood history key's pins and values, when the schema derives one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub history: Option<History>,
}

/// The history key a record carries, explicitly.
///
/// The values and not only the digest, which is the whole point of storing them in the signed
/// record: an investigator looking at an event has to be able to see *which* values put it in that
/// partition, not just that two records agree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct History {
    pub pins: Vec<String>,
    pub values: Vec<String>,
    pub digest: String,
}

/// What `--verify` established, and what it did not.
///
/// Which proof applies is decided by the scope, not by preference. A **producer stream** is a
/// contiguous history, so the chain is what proves it. A **tenant view** is a subsequence — the
/// records in between belong to other tenants and must not be disclosed — so the chain cannot be
/// checked across it, and the inclusion path is what proves each record instead. Reporting a chain
/// result for a tenant page would be reporting a failure of arithmetic as a failure of integrity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Verified {
    /// Which proof applies here: `chain` or `inclusion`.
    pub proof: String,
    /// Whether the records are a contiguous, unaltered chain. Stream scope only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain: Option<bool>,
    /// What broke it, when something did.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_detail: Option<String>,
    /// How many records proved to be in a batch this producer signed.
    pub included: usize,
    /// How many did not — each one is a record the store cannot account for.
    pub not_included: usize,
    /// How many batch signatures verified against the given key set.
    pub signatures: usize,
    /// How many did not.
    pub signatures_failed: usize,
    /// Stated rather than implied: without a key set, signatures are not checked.
    pub signatures_checked: bool,
}

impl Verified {
    /// Whether everything that was checked held.
    pub fn holds(&self) -> bool {
        self.chain.unwrap_or(true)
            && self.not_included == 0
            && (!self.signatures_checked || self.signatures_failed == 0)
    }
}

/// One occurrence, whole: what `permguard events get` prints.
#[derive(Debug, Clone, Serialize)]
pub struct EventReport {
    pub record: Value,
}

/// Reads `scope` through `window`: one page, or with `everything` the whole snapshot the first
/// page names, bounded by [`MAX_PAGES`], its envelopes and inclusion paths always carried, since
/// an export is evidence to verify offline. `snapshot` hears the high watermark an export is of,
/// once. Answers what was read and how many pages it took.
pub fn read(
    reader: &dyn EventLog,
    scope: &ReadScope,
    mut window: ReadWindow,
    everything: bool,
    mut snapshot: impl FnMut(&str),
) -> Result<(Read, usize), ReadError> {
    let mut read = Read::default();
    if everything {
        // An export is an offline-verifiable artifact, not a long `list`. Always carry the signed
        // envelopes and inclusion paths; `--verify` controls whether this command also checks them
        // before writing, not whether the exported file contains its evidence.
        window.proof = true;
    }
    let pages = if everything { MAX_PAGES } else { 1 };
    let mut walked = 0;
    for page_number in 0..pages {
        let page = reader.read(scope, &window)?;
        if everything && page_number == 0 {
            window.until = Some(page.high_watermark.clone());
            snapshot(&page.high_watermark);
        }
        read.absorb(page, &mut window);
        walked = page_number + 1;
        // An empty page is not the end: filtering and scan bounds mean a page may match nothing
        // while still advancing. The export stops from `more` against its own bound.
        if !everything || !read.more {
            break;
        }
    }
    Ok((read, walked))
}

/// What the pages accumulated.
#[derive(Debug, Clone, Default)]
pub struct Read {
    pub records: Vec<Value>,
    pub proof: Vec<Value>,
    pub inclusion: Vec<Value>,
    pub next: String,
    pub oldest_available: String,
    pub high_watermark: String,
    pub more: bool,
    pub examined: u64,
    pub scan_bounded: bool,
}

impl Read {
    /// Adds a page, and moves `window` past it. An envelope two pages carry is kept once.
    pub fn absorb(&mut self, page: events::Page, window: &mut ReadWindow) {
        self.more = page.more;
        self.next.clone_from(&page.next);
        if self.oldest_available.is_empty() {
            self.oldest_available = page.oldest_available;
        }
        self.high_watermark = page.high_watermark;
        self.examined += page.coverage.examined;
        self.scan_bounded |= page.coverage.scan_bounded;
        self.records.extend(page.records);
        for envelope in page.proof {
            if !self.proof.contains(&envelope) {
                self.proof.push(envelope);
            }
        }
        self.inclusion.extend(page.inclusion);
        window.from = Some(page.next);
    }
}

/// The page, as the report prints it.
pub fn report(scope: &ReadScope, read: Read, shape: &Shape, keys: Option<&[Jwk]>) -> EventsReport {
    let verified = shape.verify.then(|| check(scope, &read, keys));

    EventsReport {
        scope: match scope {
            ReadScope::Tenant { zone, ledger } => format!("{zone}/{ledger}"),
            ReadScope::Stream {
                zone,
                ledger,
                producer,
                instance,
                ..
            } => format!("{zone}/{ledger} · {producer}/{instance}"),
        },
        events: read.records.iter().map(line).collect(),
        next: read.next,
        oldest_available: read.oldest_available,
        high_watermark: read.high_watermark,
        more: read.more,
        // Set by the caller, which is the only place that knows whether its own page bound was
        // what stopped it.
        truncated: false,
        coverage: Coverage {
            contiguous: matches!(scope, ReadScope::Stream { .. }) && !shape.by_type,
            examined: read.examined,
            scan_bounded: read.scan_bounded,
        },
        verified,
    }
}

/// One record, as a line.
pub fn line(record: &Value) -> EventLine {
    let text = |path: &[&str]| -> String {
        let mut held = record;
        for segment in path {
            let Some(next) = held.get(*segment) else {
                return String::new();
            };
            held = next;
        }

        held.as_str().unwrap_or_default().to_owned()
    };

    EventLine {
        seq: record
            .get("seq")
            .and_then(Value::as_u64)
            .unwrap_or_default(),
        event_id: text(&["event_id"]),
        event_type: text(&["event_type"]),
        kind: text(&["kind"]),
        occurred_at: text(&["occurred_at"]),
        observed_at: text(&["observed_at"]),
        profile: text(&["profile"]),
        policy_partitions: record
            .get("policy_partitions")
            .and_then(Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(ToOwned::to_owned)
                    .collect()
            })
            .unwrap_or_default(),
        commit: text(&["commit"]),
        producer: text(&["stream", "producer", "id"]),
        instance: text(&["stream", "producer", "instance"]),
        history: record.get("history_key").and_then(|held| {
            Some(History {
                pins: strings(held.get("pins")?),
                values: strings(held.get("values")?),
                digest: held.get("digest")?.as_str()?.to_owned(),
            })
        }),
    }
}

fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(ToOwned::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// Checks what was read, as far as the scope allows.
pub fn check(scope: &ReadScope, read: &Read, keys: Option<&[Jwk]>) -> Verified {
    // A producer stream is a contiguous history, so the chain is what proves it. A tenant view is
    // a subsequence, so it is not — and reporting a chain result for one would be reporting a
    // failure of arithmetic as a failure of integrity.
    let (proof, chain, chain_detail) = match scope {
        ReadScope::Stream { .. } => match chain::verify(&read.records, None) {
            Ok(_) => ("chain".to_owned(), Some(true), None),
            Err(error) => ("chain".to_owned(), Some(false), Some(error.to_string())),
        },
        ReadScope::Tenant { .. } => ("inclusion".to_owned(), None, None),
    };

    // Decode and shape-check every envelope even when no key set was supplied. With keys, retain
    // only envelopes whose signature verifies. A Merkle path is evidence only when its root is one
    // of these envelopes' roots and both the envelope and record belong to the requested scope.
    let mut envelopes = Vec::new();
    let mut signatures = 0;
    let mut signatures_failed = 0;
    let mut malformed_envelopes = 0;
    // The batches the producing Hosts' engines sealed (WP-6.2b): verified the same way, under the
    // keys given, their records bound by their inclusion paths to the batch's Merkle root.
    let mut host_batches = Vec::new();
    for value in &read.proof {
        if let Some(held) = crate::host_proof::host_batch(
            value,
            keys,
            permguard_core::domains::protected::EVENT_BATCH,
        ) {
            match held {
                Ok(batch) => {
                    signatures += usize::from(keys.is_some());
                    host_batches.push(batch);
                }
                Err(()) if keys.is_some() => signatures_failed += 1,
                Err(()) => malformed_envelopes += 1,
            }
            continue;
        }
        let Ok(signed) = serde_json::from_value::<Signed>(value.clone()) else {
            signatures_failed += usize::from(keys.is_some());
            malformed_envelopes += 1;
            continue;
        };
        let decoded = match keys {
            Some(keys) => match signed.verify(keys) {
                Ok(envelope) => {
                    signatures += 1;
                    Some(envelope)
                }
                Err(_) => {
                    signatures_failed += 1;
                    None
                }
            },
            None => {
                let protected = signed.protected().ok().filter(|header| {
                    header.alg == permguard_events::envelope::ALGORITHM
                        && header.typ == permguard_events::envelope::BATCH_TYPE
                });
                protected.and_then(|_| {
                    signed
                        .envelope()
                        .ok()
                        .filter(|envelope| envelope.check_shape().is_ok())
                })
            }
        };
        if let Some(envelope) = decoded {
            envelopes.push(envelope);
        } else if keys.is_none() {
            malformed_envelopes += 1;
        }
    }

    let mut included = 0;
    let mut not_included = 0;
    for (record, path) in read.records.iter().zip(&read.inclusion) {
        let parsed = record::validate(record).ok().filter(valid_occurrence);
        let record_stream = parsed.as_ref().map(|record| &record.stream);
        let root = path.get("root").and_then(Value::as_str);
        let covered = match (record_stream, root) {
            (Some(stream), Some(root)) => {
                let seq = record.get("seq").and_then(Value::as_u64);
                scope_contains(scope, stream)
                    && (envelopes.iter().any(|envelope| {
                        envelope.stream == *stream
                            && envelope.merkle_root == root
                            && seq.is_some_and(|seq| {
                                (envelope.first_seq..=envelope.last_seq).contains(&seq)
                            })
                    }) || (stream.producer.class
                        == permguard_events::PRODUCER_CLASS_DATA_PLANE
                        && host_batches
                            .iter()
                            .any(|batch: &crate::host_proof::HostBatch| {
                                batch.merkle_root == root
                                    && seq.is_some_and(|seq| {
                                        batch.covers(
                                            &stream.producer.id,
                                            &stream.producer.instance,
                                            seq,
                                        )
                                    })
                            })))
            }
            _ => false,
        };
        if covered && accounts_for(record, path) {
            included += 1;
        } else {
            not_included += 1;
        }
    }
    // A record with no path at all is a record the store could not account for, which is the same
    // answer as a path that does not check out.
    not_included += read.records.len().saturating_sub(read.inclusion.len());
    // An export containing an envelope that is not even a well-formed event-batch attestation is
    // not wholly verified merely because another envelope happened to cover all returned records.
    not_included += malformed_envelopes;

    Verified {
        proof,
        chain,
        chain_detail,
        included,
        not_included,
        signatures,
        signatures_failed,
        signatures_checked: keys.is_some(),
    }
}

/// Whether the registered payload agrees with the record fields used for filtering and display.
fn valid_occurrence(record: &record::Record) -> bool {
    let Ok(occurrence) = permguard_languages::event::read_typed(&record.event_type, &record.event)
    else {
        return false;
    };

    occurrence.event_id == record.event_id
        && occurrence.kind == record.kind
        && occurrence.occurred_at == record.occurred_at
}

fn scope_contains(scope: &ReadScope, stream: &permguard_events::Stream) -> bool {
    match scope {
        ReadScope::Tenant { zone, ledger } => stream.zone == *zone && stream.ledger == *ledger,
        ReadScope::Stream {
            zone,
            ledger,
            class,
            producer,
            instance,
        } => {
            stream.zone == *zone
                && stream.ledger == *ledger
                && stream.producer.class == *class
                && stream.producer.id == *producer
                && stream.producer.instance == *instance
        }
    }
}

/// Whether an inclusion path accounts for its record.
fn accounts_for(record: &Value, path: &Value) -> bool {
    let Ok(digest) = record::digest_of(record) else {
        return false;
    };
    let Some(leaf) = path.get("leaf").and_then(Value::as_str) else {
        return false;
    };
    if leaf != digest {
        return false;
    }
    let Some(root) = path.get("root").and_then(Value::as_str) else {
        return false;
    };
    let Some(steps) = path.get("path").cloned().and_then(|held| {
        serde_json::from_value::<Vec<permguard_decisions::merkle::Step>>(held).ok()
    }) else {
        return false;
    };

    merkle_of(leaf, &steps) == root
}

#[cfg(test)]
mod event_versions {
    //! TL-5c: `events` reads each registered event version by its own contract.

    #![allow(clippy::expect_used)]

    use permguard_events::record::{RECORD_TYPE, Record, VERSION, occurrence_digest_of};
    use permguard_events::{GENESIS, Producer, Stream};
    use serde_json::json;

    fn record(event_type: &str, member: &str) -> Record {
        let mut event = json!({
            "event_id": "evt-1",
            "kind": "request",
            "action": "Drupe::Action::Login",
            "principal": "Drupe::OAuthUser::\"alice\"",
            "resource": "Drupe::Gateway::\"gw1\"",
            "occurred_at": "2026-08-28T10:15:30Z",
        });
        event[member] = json!({"input": {"user": "alice"}});
        Record {
            v: VERSION,
            record_type: RECORD_TYPE.to_owned(),
            stream: Stream::new(Producer::data_plane("plane-a", "inst-1"), "acme", "gov"),
            seq: 1,
            prev: GENESIS.to_owned(),
            event_type: event_type.to_owned(),
            event_id: "evt-1".to_owned(),
            source: None,
            occurrence_digest: occurrence_digest_of(&event).expect("it digests"),
            kind: "request".to_owned(),
            profile: "temporal".to_owned(),
            policy_partitions: vec!["governance".to_owned()],
            commit: "sha256:commit".to_owned(),
            history_key: None,
            occurred_at: "2026-08-28T10:15:30Z".to_owned(),
            observed_at: "2026-08-28T10:15:31Z".to_owned(),
            event,
        }
    }

    #[test]
    fn each_event_version_is_read_by_its_own_contract() {
        assert!(super::valid_occurrence(&record(
            permguard_languages::event::EVENT_TYPE,
            "logged"
        )));
        assert!(super::valid_occurrence(&record(
            permguard_languages::event::EVENT_TYPE_V2,
            "fields"
        )));
        assert!(!super::valid_occurrence(&record(
            permguard_languages::event::EVENT_TYPE_V2,
            "logged"
        )));
        assert!(!super::valid_occurrence(&record(
            "permguard.dogwood.event.v3",
            "fields"
        )));
    }
}
