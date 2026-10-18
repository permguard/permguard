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

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard, PoisonError};

use permguard_core::Metrics;
use permguard_core::authz::Resource;
use permguard_core::metrics::labels;
use permguard_decisions::Commitment;
use permguard_decisions::record::{GENESIS, Record, Stream, VERSION};
use permguard_host::composition::{StreamPosition, StreamProducer};
use permguard_stream::engine::RecordCodec as _;
use tracing::warn;

use super::journal::{Decided, Epoch, Written, decision_body, keeps_permit, marker_body, now};
use super::measure;

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
}

/// The writing half of the decision log on the Host's producer.
pub struct HostLog {
    producer: StreamProducer,
    /// The `host_id`, 32 lowercase hex digits: every record's `stream.id`.
    host_id: String,
    epoch: Epoch,
    permit_rate: f64,
    commitment: Commitment,
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
            metrics,
            bounds,
            marked: Mutex::new(BTreeMap::new()),
            pressure: Mutex::new(BTreeMap::new()),
            measures: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Records one decision, answering once it is durable.
    ///
    /// Never touches the network: the append and the flush covering it are the Host's, on this
    /// volume. A permit sampled out writes nothing; a denial or an error is never sampled.
    pub fn record(&self, decided: &Decided<'_>) -> Result<Written, String> {
        if decided.permit && !keeps_permit(self.permit_rate, decided.id) {
            self.metrics.count(&measure::SAMPLED_OUT, &[]);
            return Ok(Written::SampledOut);
        }
        if decided.zone_id.is_empty() || decided.ledger_id.is_empty() {
            return Err("the decision names no zone or ledger id to record it under".to_owned());
        }
        let resource = Resource::ledger(crate::service::PLANE, decided.zone_id, decided.ledger_id);
        let key = resource.to_string();
        if let Some(reason) = self.pressure_of(&resource, &key) {
            return Ok(Written::Refused(reason.to_owned()));
        }
        // Built before the engine's lock is taken: only the position is filled in under it.
        let marker_body = marker_body(&self.epoch, &self.commitment, None);
        let decision_body = decision_body(&self.epoch, &self.commitment, decided);
        let mut marked_now = false;
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
            Ok(records)
        })?;
        if let Some(held) = lock(&self.pressure).get_mut(&key) {
            held.written = true;
        }
        if marked_now {
            self.metrics
                .count(&measure::WRITTEN, &[(labels::KIND, "marker")]);
        }
        self.metrics
            .count(&measure::WRITTEN, &[(labels::KIND, "decision")]);

        Ok(Written::Recorded { seq: receipt.seq })
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
                held.pressure = measured;
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
        {
            return held.pressure;
        }
        let measured = self.measured(resource);
        let mut pressure = lock(&self.pressure);
        let held = pressure.entry(key.to_owned()).or_insert_with(|| Measured {
            resource: resource.clone(),
            pressure: measured,
            written: false,
            at: std::time::Instant::now(),
        });
        held.pressure = measured;
        held.at = std::time::Instant::now();
        held.pressure
    }

    fn measured(&self, resource: &Resource) -> Option<&'static str> {
        match self
            .producer
            .pressure(resource, self.bounds.max_bytes, self.bounds.max_age_secs)
        {
            Ok(pressure) => pressure,
            Err(error) => {
                warn!(
                    event.name = "decisions.pressure_unknown",
                    component = COMPONENT,
                    error = error.as_str(),
                    "the decision stream's pressure cannot be measured: its decisions are refused \
                     until it can"
                );
                Some(permguard_core::codes::stream::STORE_UNAVAILABLE)
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

    fn refuses_unrecorded(&self) -> bool {
        true
    }
}

/// The `prev` a record at `position` names: the genesis digest at a run's first sequence.
fn previous(position: &StreamPosition) -> String {
    if position.seq == 1 {
        GENESIS.to_owned()
    } else {
        format!("sha256:{}", hex(&position.prev))
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
