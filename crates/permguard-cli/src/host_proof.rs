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
    /// The resource the batch's stream belongs to, the canonical text it signs.
    pub resource: String,
}

impl HostBatch {
    /// Whether this batch covers `seq` of the run `producer`/`run`, whichever spelling of the ids
    /// each side uses: the envelope names its producer as UUID text, a record as 32 hex digits
    /// (BUG-0112, BUG-0113).
    pub fn covers(&self, producer: &str, run: &str, seq: u64) -> bool {
        same_id(&self.producer, producer)
            && same_id(&self.run, run)
            && (self.first_seq..=self.last_seq).contains(&seq)
    }
}

/// Whether two ids name the same thing, as 32 hex digits or as UUID text, in either case.
pub fn same_id(left: &str, right: &str) -> bool {
    let plain = |id: &str| id.replace('-', "").to_ascii_lowercase();
    plain(left) == plain(right)
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
                resource: envelope.stream_key.resource,
            })
            .map_err(|_| ()),
    )
}

/// A Host entry `keys` cannot judge: signed by a key whose `kid` none of them carries. Its batch,
/// read for its range and never attributed, and the `kid`, so a verification reports a key not
/// given rather than a signature that failed (BUG-0114).
pub fn unkeyed_batch(value: &Value, keys: &[Jwk]) -> Option<(HostBatch, String)> {
    use base64::Engine as _;

    if value.get("format").and_then(Value::as_str) != Some(HOST_FORMAT) {
        return None;
    }
    let signature = serde_json::from_value::<Jws>(value.get("signature")?.clone()).ok()?;
    let protected = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&signature.protected)
        .ok()?;
    let kid = serde_json::from_slice::<Value>(&protected)
        .ok()?
        .get("kid")?
        .as_str()?
        .to_owned();
    if keys.iter().any(|key| key.kid == kid) {
        return None;
    }
    let envelope = envelope_of(&signature).ok()?;
    Some((
        HostBatch {
            producer: envelope.stream_key.producer_host_id,
            run: envelope.run,
            first_seq: envelope.first_seq,
            last_seq: envelope.last_seq,
            head: envelope.head,
            merkle_root: envelope.merkle_root,
            resource: envelope.stream_key.resource,
        },
        kid,
    ))
}
