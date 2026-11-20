// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The decision log on the Host's stream producer (WP-6.1, owner decisions of 2026-10-16 and
//! 2026-10-18).
//!
//! ```text
//! decide ──► HostLog ──► data/decisions, one stream per (zone, ledger)
//!                            │  the Host's producer: run, sequence, flush, reserve
//!                            ▼  sealed under data.attest, shipped over decisions.ship
//!                        coordinator
//! ```
//!
//! The plane owns no spool, sequence or signer here. A record names its place as the Host's
//! engine gives it: `stream.id` is the `host_id`, `stream.instance` the run, `seq` and `prev` the
//! engine's own, built under the lock that hands sequences out so no two records claim one.
//!
//! **`required` is the only mode written.** A decision is answered only once its record, and the
//! marker that governs it, are durable; one that cannot be recorded is refused `unavailable`,
//! whether the stream holds more than its bounds allow unacknowledged or the engine refuses the
//! append.

use permguard_core::encoding::hex;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use permguard_core::Metrics;
use permguard_core::authz::Resource;
use permguard_core::metrics::labels;
use permguard_decisions::Commitment;
use permguard_decisions::record::{GENESIS, Record, Stream, VERSION};
use permguard_host::composition::{StreamPosition, StreamProducer};
use permguard_stream::engine::RecordCodec as _;
use tracing::warn;

use super::measure;
use super::record::{Decided, Epoch, Written, decision_body, keeps_permit, marker_body, now};

const COMPONENT: &str = "data-plane";

/// The bounds a stream's unacknowledged records are held to: `log.spool_bytes`, `log.spool_age`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bounds {
    pub max_bytes: u64,
    pub max_age_secs: u64,
}

/// Every this many measures, each stream is measured whether or not it was written since: what
/// lets the age of an idle stream's oldest unacknowledged batch be seen.
const MEASURE_ALL_EVERY: u64 = 30;

/// A measure older than this is taken again on the decision path: a ticker that stopped never
/// leaves a stream answering on a stale measure.
const MEASURE_STALE_AFTER: std::time::Duration = std::time::Duration::from_secs(10);

/// One stream's pressure as last measured.
struct Measured {
    resource: Resource,
    pressure: Option<&'static str>,
    /// Written since it was last measured.
    written: bool,
    /// When it was measured.
    at: std::time::Instant,
    /// The bytes unacknowledged at the measure, when the producer counts them (BUG-0119).
    unacknowledged: Option<u64>,
    /// When the oldest unacknowledged batch was made, at the measure.
    oldest_at: Option<u64>,
    /// The record bytes this log appended since the measure.
    appended: u64,
}

impl Measured {
    /// Whether what was measured, with what was appended since, may have crossed a bound: the
    /// bytes reach `max_bytes`, or the oldest batch has grown past `max_age_secs`. Then the stream
    /// is measured again before a decision is recorded, never answered on a stale figure.
    fn may_cross(&self, bounds: &Bounds, now: u64) -> bool {
        self.unacknowledged
            .is_some_and(|bytes| bytes.saturating_add(self.appended) >= bounds.max_bytes)
            || self
                .oldest_at
                .is_some_and(|oldest| now.saturating_sub(oldest) >= bounds.max_age_secs)
    }
}

/// The writing half of the decision log on the Host's producer.
pub struct HostLog {
    producer: StreamProducer,
    /// The `host_id`, 32 lowercase hex digits: every record's `stream.id`.
    host_id: String,
    epoch: Epoch,
    permit_rate: f64,
    commitment: Commitment,
    /// The zone keys subjects are pseudonymised under, whose fingerprint each marker names
    /// (BUG-0344).
    pseudonyms: Option<Arc<permguard_host::secrets::ZoneHandle>>,
    metrics: Metrics,
    bounds: Bounds,
    /// The run each stream was marked in by this process: a record whose stream is in another
    /// run, or none yet, is preceded by its marker.
    marked: Mutex<BTreeMap<String, [u8; 16]>>,
    /// Each stream this log writes, and its pressure as last measured off the decision path.
    pressure: Mutex<BTreeMap<String, Measured>>,
    /// How many measures ran.
    measures: std::sync::atomic::AtomicU64,
}

impl HostLog {
    /// A log appending to `producer` as the Host `host_id`.
    pub fn new(
        producer: StreamProducer,
        host_id: [u8; 16],
        epoch: Epoch,
        commitment: Commitment,
        bounds: Bounds,
        metrics: Metrics,
    ) -> Self {
        Self {
            producer,
            host_id: hex(&host_id),
            permit_rate: epoch.sampling.parse().unwrap_or(1.0),
            epoch,
            commitment,
            pseudonyms: None,
            metrics,
            bounds,
            marked: Mutex::new(BTreeMap::new()),
            pressure: Mutex::new(BTreeMap::new()),
            measures: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// This log naming, in each marker, the fingerprint of the zone key its subjects are
    /// pseudonymised under (BUG-0344).
    pub fn with_pseudonyms(
        mut self,
        pseudonyms: Option<Arc<permguard_host::secrets::ZoneHandle>>,
    ) -> Self {
        self.pseudonyms = pseudonyms;
        self
    }

    /// Records one decision, answering once it is durable.
    ///
    /// Never touches the network: the append and the flush covering it are the Host's, on this
    /// volume. A permit sampled out writes nothing; a denial or an error is never sampled.
    pub fn record(&self, decided: &Decided<'_>) -> Result<Written, String> {
        self.record_located(decided).map(|(written, _)| written)
    }

    /// Records one decision as [`HostLog::record`] does, and says where a written record sits:
    /// this Host, the run and the sequence the engine gave it (WP-6.6).
    pub fn record_located(
        &self,
        decided: &Decided<'_>,
    ) -> Result<(Written, Option<permguard_languages::attestation::Position>), String> {
        if decided.permit && !keeps_permit(self.permit_rate, decided.id) {
            self.metrics.count(&measure::SAMPLED_OUT, &[]);
            return Ok((Written::SampledOut, None));
        }
        if decided.zone_id.is_empty() || decided.ledger_id.is_empty() {
            return Err("the decision names no zone or ledger id to record it under".to_owned());
        }
        let resource = Resource::ledger(crate::PLANE, decided.zone_id, decided.ledger_id);
        let key = resource.to_string();
        if let Some(reason) = self.pressure_of(&resource, &key) {
            return Ok((Written::Refused(reason.to_owned()), None));
        }
        // Built before the engine's lock is taken: only the position is filled in under it.
        let marker_body = marker_body(
            &self.epoch,
            &self.commitment,
            self.pseudonyms.as_deref(),
            decided.scope.as_ref(),
            None,
        );
        let decision_body = decision_body(&self.epoch, &self.commitment, decided);
        let mut marked_now = false;
        // The bytes appended, which the next pressure check adds to its measure (BUG-0119).
        let records_len = std::sync::atomic::AtomicU64::new(0);
        let receipt = self.producer.append_with(&resource, &mut |position| {
            let mut marked = lock(&self.marked);
            let marker = marked.get(&key) != Some(&position.run_id);
            let instance = hex(&position.run_id);
            let mut seq = position.seq;
            let mut prev = previous(&position);
            let mut records = Vec::with_capacity(2);
            if marker {
                let bytes = self.encode(Record {
                    v: VERSION,
                    stream: Stream::new(self.host_id.clone(), instance.clone()),
                    seq,
                    prev,
                    at: now(),
                    body: marker_body.clone(),
                })?;
                prev = format!(
                    "sha256:{}",
                    hex(&permguard_stream::engine::record_digest(
                        permguard_core::domains::digest::DECISION_RECORD,
                        &bytes,
                    ))
                );
                seq += 1;
                records.push(bytes);
            }
            records.push(self.encode(Record {
                v: VERSION,
                stream: Stream::new(self.host_id.clone(), instance),
                seq,
                prev,
                at: decided.at.clone(),
                body: decision_body.clone(),
            })?);
            // Taken only once every record is built and checked: past this point the engine
            // gives them their sequences, or stops the stream.
            marked.insert(key.clone(), position.run_id);
            marked_now = marker;
            records_len.store(
                records.iter().map(|record| record.len() as u64).sum(),
                std::sync::atomic::Ordering::Relaxed,
            );
            Ok(records)
        })?;
        let appended: u64 = records_len.load(std::sync::atomic::Ordering::Relaxed);
        if let Some(held) = lock(&self.pressure).get_mut(&key) {
            held.written = true;
            held.appended = held.appended.saturating_add(appended);
        }
        if marked_now {
            self.metrics
                .count(&measure::WRITTEN, &[(labels::KIND, "marker")]);
        }
        self.metrics
            .count(&measure::WRITTEN, &[(labels::KIND, "decision")]);

        Ok((
            Written::Recorded { seq: receipt.seq },
            Some(permguard_languages::attestation::Position {
                host_id: uuid_text(&self.host_id),
                run: hex(&receipt.run_id),
                sequence: receipt.seq.to_string(),
            }),
        ))
    }

    /// Measures the pressure of the streams this log writes: what the decision path reads.
    ///
    /// Off the decision path, on a cadence: the measure reads the stream's journal, so it reads
    /// those written since the last measure and those under pressure, and every stream every
    /// [`MEASURE_ALL_EVERY`] measures. A stream whose pressure cannot be measured refuses its
    /// decisions until it can.
    pub fn measure(&self) {
        let all = self
            .measures
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            .is_multiple_of(MEASURE_ALL_EVERY);
        let streams: Vec<(String, Resource)> = lock(&self.pressure)
            .iter_mut()
            .filter(|(_, held)| all || held.written || held.pressure.is_some())
            .map(|(key, held)| {
                held.written = false;
                (key.clone(), held.resource.clone())
            })
            .collect();
        for (key, resource) in streams {
            let measured = self.measured(&resource);
            if let Some(held) = lock(&self.pressure).get_mut(&key) {
                held.pressure = measured.verdict;
                held.unacknowledged = measured.unacknowledged_bytes;
                held.oldest_at = measured.oldest_unacknowledged_at;
                held.appended = 0;
                held.at = std::time::Instant::now();
            }
        }
    }

    /// The pressure of the stream of `resource` as last measured, measured now the first time
    /// this log sees it or when the last measure is stale: a plane restarted beside a stream
    /// already past its bounds refuses from its first decision.
    fn pressure_of(&self, resource: &Resource, key: &str) -> Option<&'static str> {
        if let Some(held) = lock(&self.pressure).get(key)
            && held.at.elapsed() < MEASURE_STALE_AFTER
            && (held.pressure.is_some()
                || !held.may_cross(&self.bounds, permguard_core::time::unix_now()))
        {
            return held.pressure;
        }
        let measured = self.measured(resource);
        let mut pressure = lock(&self.pressure);
        let held = pressure.entry(key.to_owned()).or_insert_with(|| Measured {
            resource: resource.clone(),
            pressure: measured.verdict,
            written: false,
            at: std::time::Instant::now(),
            unacknowledged: None,
            oldest_at: None,
            appended: 0,
        });
        held.pressure = measured.verdict;
        held.unacknowledged = measured.unacknowledged_bytes;
        held.oldest_at = measured.oldest_unacknowledged_at;
        held.appended = 0;
        held.at = std::time::Instant::now();
        held.pressure
    }

    fn measured(&self, resource: &Resource) -> permguard_host::composition::PressureMeasure {
        match self.producer.measure_pressure(
            resource,
            self.bounds.max_bytes,
            self.bounds.max_age_secs,
        ) {
            Ok(measured) => measured,
            Err(error) => {
                warn!(
                    event.name = "decisions.pressure_unknown",
                    component = COMPONENT,
                    error = error.as_str(),
                    "the decision stream's pressure cannot be measured: its decisions are refused \
                     until it can"
                );
                permguard_host::composition::PressureMeasure {
                    verdict: Some(permguard_core::codes::stream::STORE_UNAVAILABLE),
                    ..Default::default()
                }
            }
        }
    }

    /// A record's canonical bytes, checked exactly as `Producer::check` checks them (the same
    /// codec, the same bound), so a record this log built is never refused after its position
    /// was taken and its run marked: the two must change together.
    fn encode(&self, record: Record) -> Result<Vec<u8>, String> {
        let codec = permguard_decisions::stream::Codec;
        let value = record.to_value().map_err(|error| error.to_string())?;
        let bytes = codec.encode(&value)?;
        let limit = permguard_decisions::stream::descriptor().max_record_bytes;
        if bytes.len() as u64 > u64::from(limit) {
            return Err(format!(
                "a decision record of {} bytes; the stream takes up to {limit}",
                bytes.len()
            ));
        }
        if codec.encode(&codec.decode(&bytes)?)? != bytes {
            return Err("a decision record that is not its canonical encoding".to_owned());
        }
        Ok(bytes)
    }
}

impl super::DecisionRecorder for HostLog {
    fn record(&self, decided: &Decided<'_>) -> Result<Written, String> {
        HostLog::record(self, decided)
    }

    fn record_located(
        &self,
        decided: &Decided<'_>,
    ) -> Result<(Written, Option<permguard_languages::attestation::Position>), String> {
        HostLog::record_located(self, decided)
    }

    fn refuses_unrecorded(&self) -> bool {
        true
    }
}

/// The `prev` a record at `position` names: the genesis digest at a run's first sequence.
/// A decision record's `bytes`, rewritten for `position` (BUG-0115): its stream's instance, its
/// sequence and its predecessor those of the new place, everything else as it was.
pub(crate) fn rebase_decision(bytes: &[u8], position: StreamPosition) -> Result<Vec<u8>, String> {
    let codec = permguard_decisions::stream::Codec;
    let mut value = codec.decode(bytes)?;
    let stream = value
        .get_mut("stream")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or("a decision record names no stream")?;
    stream.insert(
        "instance".to_owned(),
        serde_json::Value::from(hex(&position.run_id)),
    );
    let object = value
        .as_object_mut()
        .ok_or("a decision record is an object")?;
    object.insert("seq".to_owned(), serde_json::Value::from(position.seq));
    object.insert(
        "prev".to_owned(),
        serde_json::Value::from(previous(&position)),
    );
    codec.encode(&value)
}

fn previous(position: &StreamPosition) -> String {
    if position.seq == 1 {
        GENESIS.to_owned()
    } else {
        format!("sha256:{}", hex(&position.prev))
    }
}

/// The `host_id`, 32 hex digits, in its canonical UUID form: lowercase, hyphenated.
fn uuid_text(host_id: &str) -> String {
    if host_id.len() != 32 {
        return host_id.to_owned();
    }
    format!(
        "{}-{}-{}-{}-{}",
        &host_id[..8],
        &host_id[8..12],
        &host_id[12..16],
        &host_id[16..20],
        &host_id[20..]
    )
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod carry_tests {
    #![allow(clippy::expect_used)]

    use super::*;

    /// BUG-0115: a decision record carried into a fenced run is rewritten for its new place
    /// alone: its stream's instance, its sequence and its predecessor.
    #[test]
    fn a_carried_decision_record_changes_only_its_place() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../contracts/vectors/evidence.json"
        )))
        .expect("the vectors");
        let original = vectors["decision_record"][0]["record"].clone();
        let codec = permguard_decisions::stream::Codec;
        let bytes = codec.encode(&original).expect("encodes");
        let position = StreamPosition {
            run_id: [7; 16],
            seq: 4,
            prev: [2; 32],
        };
        let carried = codec
            .decode(&rebase_decision(&bytes, position).expect("rebased"))
            .expect("decodes");
        assert_eq!(carried["stream"]["instance"], hex(&[7; 16]));
        assert_eq!(carried["seq"], 4);
        assert_eq!(carried["prev"], format!("sha256:{}", hex(&[2; 32])));
        for member in ["kind", "pdp", "sampling", "commitments", "at"] {
            assert_eq!(carried[member], original[member], "{member}");
        }
        assert_eq!(carried["stream"]["id"], original["stream"]["id"]);
    }
}
