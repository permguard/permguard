// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What a test composing no Host records events on (WP-6.2a): a stream producer in memory, its
//! runs opened in order, its records by sequence, a prefix a test deletes.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use permguard_core::authz::Resource;
use permguard_host::composition::{
    BuildRecords, ConsumedPage, ProducedRun, StreamAppender, StreamFloor, StreamPosition,
    StreamReceipt,
};

/// A producer holding its streams in memory: runs opened in order, records by sequence, a prefix
/// a test deletes.
#[derive(Default)]
pub struct MemoryProducer {
    streams: Mutex<BTreeMap<String, Vec<HeldRun>>>,
    next_run: Mutex<u8>,
    /// What `pressure` answers.
    pub pressure: Mutex<Option<&'static str>>,
    /// When set, `pressure` cannot be measured.
    pub pressure_error: Mutex<Option<String>>,
    /// The floor a Plane registered.
    pub floor: Mutex<Option<Arc<dyn StreamFloor>>>,
}

struct HeldRun {
    run: [u8; 16],
    records: Vec<Vec<u8>>,
    low_watermark: u64,
    ended: bool,
}

impl MemoryProducer {
    fn new_run(&self) -> [u8; 16] {
        let mut next = self
            .next_run
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *next += 1;
        [*next; 16]
    }

    /// Ends the current run of `resource` and opens its successor, empty.
    pub fn rollover(&self, resource: &Resource) {
        let run = self.new_run();
        let mut streams = self
            .streams
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let runs = streams.entry(resource.to_string()).or_default();
        if let Some(last) = runs.last_mut() {
            last.ended = true;
        }
        runs.push(HeldRun {
            run,
            records: Vec::new(),
            low_watermark: 1,
            ended: false,
        });
    }

    /// Deletes the records of `resource`'s run at `index` below `seq`.
    pub fn delete_below(&self, resource: &Resource, index: usize, seq: u64) {
        let mut streams = self
            .streams
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        streams.get_mut(&resource.to_string()).unwrap()[index].low_watermark = seq;
    }
}

impl StreamAppender for MemoryProducer {
    fn append(&self, _: &Resource, _: &[u8]) -> Result<StreamReceipt, String> {
        Err("not in this test".to_owned())
    }

    fn append_with(
        &self,
        resource: &Resource,
        build: BuildRecords<'_>,
    ) -> Result<StreamReceipt, String> {
        let fresh = self.new_run();
        let mut streams = self
            .streams
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let runs = streams.entry(resource.to_string()).or_default();
        if runs.is_empty() {
            runs.push(HeldRun {
                run: fresh,
                records: Vec::new(),
                low_watermark: 1,
                ended: false,
            });
        }
        let current = runs.last_mut().unwrap();
        let prev = current.records.last().map_or([0; 32], |bytes| {
            permguard_stream::engine::record_digest(
                permguard_core::domains::digest::EVENT_RECORD,
                bytes,
            )
        });
        let built = build(StreamPosition {
            run_id: current.run,
            seq: current.records.len() as u64 + 1,
            prev,
        })?;
        if built.is_empty() {
            return Err("nothing to append".to_owned());
        }
        current.records.extend(built);
        Ok(StreamReceipt {
            run_id: current.run,
            seq: current.records.len() as u64,
        })
    }

    fn pressure(&self, _: &Resource, _: u64, _: u64) -> Result<Option<&'static str>, String> {
        if let Some(error) = self
            .pressure_error
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
        {
            return Err(error);
        }
        Ok(*self
            .pressure
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner))
    }

    fn retain_above(&self, floor: Arc<dyn StreamFloor>) -> Result<(), String> {
        *self
            .floor
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(floor);
        Ok(())
    }

    fn runs(&self, resource: &Resource) -> Result<Vec<ProducedRun>, String> {
        Ok(self
            .streams
            .lock()
            .unwrap()
            .get(&resource.to_string())
            .map(|runs| {
                runs.iter()
                    .map(|run| ProducedRun {
                        run: run.run,
                        last_seq: run.records.len() as u64,
                        low_watermark: run.low_watermark,
                        ended: run.ended,
                    })
                    .collect()
            })
            .unwrap_or_default())
    }

    fn records(
        &self,
        resource: &Resource,
        run: &[u8; 16],
        from: u64,
        limit: usize,
    ) -> Result<ConsumedPage, String> {
        let streams = self
            .streams
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(held) = streams
            .get(&resource.to_string())
            .and_then(|runs| runs.iter().find(|held| held.run == *run))
        else {
            return Ok(ConsumedPage::default());
        };
        let start = from.max(held.low_watermark).max(1);
        Ok(ConsumedPage {
            records: held
                .records
                .iter()
                .enumerate()
                .map(|(at, bytes)| (at as u64 + 1, bytes.clone()))
                .filter(|(seq, _)| *seq >= start)
                .take(limit)
                .collect(),
            low_watermark: (from < held.low_watermark).then_some(held.low_watermark),
        })
    }
}

/// The producer a test's volume at `root` records on: one per root for the process, so a plane
/// a test drops and reopens finds the Host's stream as it left it, as a restarted plane finds the
/// Host's engine.
pub fn producer_at(root: &std::path::Path) -> Arc<MemoryProducer> {
    static PRODUCERS: std::sync::OnceLock<
        Mutex<BTreeMap<std::path::PathBuf, Arc<MemoryProducer>>>,
    > = std::sync::OnceLock::new();
    let mut producers = PRODUCERS
        .get_or_init(|| Mutex::new(BTreeMap::new()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    Arc::clone(producers.entry(root.to_path_buf()).or_default())
}

/// The Host side a test's volume at `root` records on: [`producer_at`] and a fixed `host_id`.
pub fn host_side(root: &std::path::Path) -> super::streams::HostSide {
    super::streams::HostSide {
        producer: permguard_host::composition::StreamProducer::over(
            producer_at(root) as Arc<dyn StreamAppender>
        ),
        host_id: HOST_ID,
    }
}

/// The `host_id` a test records under.
pub const HOST_ID: [u8; 16] = [0xab; 16];
