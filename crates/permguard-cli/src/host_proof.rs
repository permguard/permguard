// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The `host-batch-v1` entries of a read's `proof[]` (WP-6.2b, owner decision of 2026-10-19): the
//! batch the producing Host's stream engine sealed, `{format, signature}`. `decisions` and `events`
//! both read them when they verify a page, beside the legacy store's JWS entries.

use permguard_core::Jwk;
use permguard_stream::engine::batch::{Jws, envelope_of, verify_signature};
use serde_json::Value;

/// The format a Host entry names.
pub const HOST_FORMAT: &str = "host-batch-v1";

/// What a Host entry attests: the run of one Host's stream, a range of it, and the Merkle root
/// its records' inclusion paths reach.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostBatch {
    /// The producing Host's `host_id`, 32 lowercase hex digits.
    pub producer: String,
    /// The run, 32 lowercase hex digits.
    pub run: String,
    pub first_seq: u64,
    pub last_seq: u64,
    /// The digest of the record at `last_seq`.
    pub head: String,
    pub merkle_root: String,
}

impl HostBatch {
    /// Whether this batch covers `seq` of the run `producer`/`run`.
    pub fn covers(&self, producer: &str, run: &str, seq: u64) -> bool {
        self.producer == producer
            && self.run == run
            && (self.first_seq..=self.last_seq).contains(&seq)
    }
}

/// `None` when `value` is not a Host entry; otherwise its batch, its signature verified under
/// `keys` and `typ` when keys are given, or `Err` when it does not hold. Without keys the batch is
/// read for its arithmetic only, never as attributed.
pub fn host_batch(value: &Value, keys: Option<&[Jwk]>, typ: &str) -> Option<Result<HostBatch, ()>> {
    if value.get("format").and_then(Value::as_str) != Some(HOST_FORMAT) {
        return None;
    }
    let Some(signature) = value
        .get("signature")
        .cloned()
        .and_then(|signature| serde_json::from_value::<Jws>(signature).ok())
    else {
        return Some(Err(()));
    };
    let envelope = match keys {
        Some(keys) => verify_signature(&signature, keys, typ),
        None => envelope_of(&signature),
    };
    Some(
        envelope
            .map(|envelope| HostBatch {
                producer: envelope.stream_key.producer_host_id,
                run: envelope.run,
                first_seq: envelope.first_seq,
                last_seq: envelope.last_seq,
                head: envelope.head,
                merkle_root: envelope.merkle_root,
            })
            .map_err(|_| ()),
    )
}
