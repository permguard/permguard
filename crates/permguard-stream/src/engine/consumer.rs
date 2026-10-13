// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The consumer side: one journal per producer run, `consumer/<sha256(resource)>/<producer-host>/
//! <run>/records/`, records kept contiguous from sequence 1. What admits them is the ingest of
//! WP-5.3, after it verified the producer's batch; this handle keeps and reads them with the
//! Plane's codec, and refuses a gap.

use std::sync::{Mutex, PoisonError};

use permguard_core::authz::Resource;
use permguard_host::storage::Dir;
use permguard_host::storage::journal::{Journal, Options};

use super::producer::{RECORDS, decode_group};
use super::{Descriptor, RecordCodec, StreamError, hex};

/// The typed consumer handle of one descriptor.
pub struct Consumer<C> {
    dir: Dir,
    claim: u64,
    descriptor: Descriptor,
    codec: C,
    /// Serializes admissions: one writer per consumer stream.
    writing: Mutex<()>,
}

impl<C> std::fmt::Debug for Consumer<C> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Consumer")
            .field("plane", &self.descriptor.plane)
            .field("stream_type", &self.descriptor.stream_type)
            .finish_non_exhaustive()
    }
}

impl<C: RecordCodec> Consumer<C> {
    pub(crate) fn new(dir: Dir, claim: u64, descriptor: Descriptor, codec: C) -> Self {
        Self {
            dir,
            claim,
            descriptor,
            codec,
            writing: Mutex::new(()),
        }
    }

    fn journal(
        &self,
        resource: &Resource,
        producer: [u8; 16],
        run_id: [u8; 16],
    ) -> Result<Journal, StreamError> {
        let key = self.descriptor.key(resource, producer)?;
        let dir = self
            .dir
            .subdir(&key.resource_component(), true)?
            .subdir(&hex(&producer), true)?
            .subdir(&hex(&run_id), true)?
            .subdir("records", true)?;
        let (journal, _) = Journal::open(
            dir,
            Options {
                claim: self.claim,
                ..Options::default()
            },
        )?;
        Ok(journal)
    }

    /// The last sequence kept of `producer`'s run `run_id` over `resource`.
    fn head(journal: &Journal) -> Result<u64, StreamError> {
        let mut head = 0;
        for frame in journal.frames()? {
            if frame.kind == RECORDS {
                let (first, records) = decode_group(&frame.payload)?;
                head = first + records.len() as u64 - 1;
            }
        }
        Ok(head)
    }

    /// Keeps `records`, verified upstream, from `first_seq` of `producer`'s run `run_id`: refused
    /// unless they continue what is kept and each reads with the codec.
    pub fn admit(
        &self,
        resource: &Resource,
        producer: [u8; 16],
        run_id: [u8; 16],
        first_seq: u64,
        records: &[Vec<u8>],
    ) -> Result<u64, StreamError> {
        let _writing = self.writing.lock().unwrap_or_else(PoisonError::into_inner);
        let mut journal = self.journal(resource, producer, run_id)?;
        let head = Self::head(&journal)?;
        if first_seq != head + 1 || records.is_empty() {
            return Err(StreamError::Invalid(format!(
                "records from sequence {first_seq} do not continue the {head} kept"
            )));
        }
        for record in records {
            if record.len() > self.descriptor.max_record_bytes as usize {
                return Err(StreamError::Invalid(
                    "a record over the stream's bound".to_owned(),
                ));
            }
            self.codec.decode(record).map_err(StreamError::Invalid)?;
        }
        let group = super::producer::encode_group(first_seq, records.iter().map(Vec::as_slice))?;
        journal.append(RECORDS, &group)?;
        Ok(head + records.len() as u64)
    }

    /// The records kept of `producer`'s run `run_id` over `resource` from `from_seq`, at most
    /// `limit`.
    pub fn read(
        &self,
        resource: &Resource,
        producer: [u8; 16],
        run_id: [u8; 16],
        from_seq: u64,
        limit: usize,
    ) -> Result<Vec<(u64, C::Record)>, StreamError> {
        let journal = self.journal(resource, producer, run_id)?;
        let mut found = Vec::new();
        for frame in journal.frames()? {
            if frame.kind != RECORDS {
                continue;
            }
            let (first, records) = decode_group(&frame.payload)?;
            for (offset, bytes) in records.into_iter().enumerate() {
                let seq = first + offset as u64;
                if seq >= from_seq && found.len() < limit {
                    found.push((
                        seq,
                        self.codec.decode(&bytes).map_err(StreamError::Invalid)?,
                    ));
                }
            }
        }
        Ok(found)
    }
}
