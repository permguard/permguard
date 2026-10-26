// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The signed drain receipt (TD-2).
//!
//! A member Host whose drain completed — every stream it produces shipped to every required
//! subscription, through its durable tail — states it, under its `host.operations` ring:
//!
//! ```text
//! COSE_Sign1 permguard.drain.receipt.v1 over
//! { 1 version, 2 host_id, 3 volume_id, 4 claim generation, 5 drained_at,
//!   6 [ { 1 plane, 2 type, 3 resource, 4 run, 5 last_seq, 6 acknowledged } ] }
//! ```
//!
//! The drain controller reclaims a retained volume only when such a receipt verifies — under the
//! member's verification bundle and the identity pin its coordinator holds, as a snapshot manifest
//! does — and the coordinator's own frontier acknowledges every stream it names through its
//! `last_seq`. The receipt says what the volume held; the coordinator's frontier says it arrived.
//! Neither alone authorizes deleting evidence, and an incomplete drain issues no receipt at all.

use permguard_core::domains::protected;
use permguard_core::keys::Sign as _;
use permguard_objects::cbor::{self, Value};
use permguard_objects::cose::Sign1;

use super::backup::{finish, labelled, labelled_value, take_bytes, take_text, take_uint, uint};
use crate::keys::ring::{HOST_OPERATIONS, Ring};

/// The payload's version.
const VERSION: i64 = 1;

/// The most bytes a receipt is read to: a Host's streams, a few hundred bytes each.
pub const MAX_RECEIPT_BYTES: usize = 256 * 1024;

/// The most streams one receipt names: with the longest resource, still within the bytes.
pub const MAX_STREAMS: usize = 1024;

/// One stream the drain shipped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DrainedStream {
    pub plane: String,
    pub stream_type: String,
    pub resource: String,
    /// The run, hex.
    pub run: String,
    /// The last sequence the run holds.
    pub last_seq: u64,
    /// The least acknowledgement of its required subscriptions: `last_seq`, on a complete drain.
    pub acknowledged: u64,
}

/// The receipt's payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DrainReceipt {
    pub host_id: [u8; 16],
    pub volume_id: [u8; 16],
    /// The claim generation the draining process held.
    pub generation: u64,
    /// When the drain completed, in seconds since the Unix epoch.
    pub drained_at: u64,
    pub streams: Vec<DrainedStream>,
}

impl DrainReceipt {
    /// The canonical bytes.
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        if self.streams.len() > MAX_STREAMS {
            return Err(format!(
                "a drain receipt names at most {MAX_STREAMS} streams"
            ));
        }
        let streams = self
            .streams
            .iter()
            .map(|stream| {
                check_run(&stream.run)?;
                Ok(Value::Map(vec![
                    (Value::Int(1), Value::Text(stream.plane.clone())),
                    (Value::Int(2), Value::Text(stream.stream_type.clone())),
                    (Value::Int(3), Value::Text(stream.resource.clone())),
                    (Value::Int(4), Value::Text(stream.run.clone())),
                    (
                        Value::Int(5),
                        uint(stream.last_seq, "a stream's last sequence")?,
                    ),
                    (
                        Value::Int(6),
                        uint(stream.acknowledged, "a stream's acknowledgement")?,
                    ),
                ]))
            })
            .collect::<Result<Vec<_>, String>>()?;
        cbor::encode(&Value::Map(vec![
            (Value::Int(1), Value::Int(VERSION)),
            (Value::Int(2), Value::Bytes(self.host_id.to_vec())),
            (Value::Int(3), Value::Bytes(self.volume_id.to_vec())),
            (
                Value::Int(4),
                uint(self.generation, "the claim generation")?,
            ),
            (Value::Int(5), uint(self.drained_at, "the drain's time")?),
            (Value::Int(6), Value::Array(streams)),
        ]))
        .map_err(|error| error.to_string())
        .and_then(|bytes| {
            if bytes.len() > MAX_RECEIPT_BYTES {
                Err(format!(
                    "a drain receipt takes at most {MAX_RECEIPT_BYTES} bytes"
                ))
            } else {
                Ok(bytes)
            }
        })
    }

    /// Reads the canonical bytes, closed: labels 1 to 6, all required, none other; version 1.
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        const WHAT: &str = "a drain receipt";
        if bytes.len() > MAX_RECEIPT_BYTES {
            return Err(format!("{WHAT} takes at most {MAX_RECEIPT_BYTES} bytes"));
        }
        let mut held = labelled(bytes, WHAT, 6)?;
        if take_uint(&mut held, 1, "the receipt's version")? != VERSION as u64 {
            return Err(format!("{WHAT} of another version"));
        }
        let host_id = take_bytes::<16>(&mut held, 2, "the host id")?;
        let volume_id = take_bytes::<16>(&mut held, 3, "the volume id")?;
        let generation = take_uint(&mut held, 4, "the claim generation")?;
        let drained_at = take_uint(&mut held, 5, "the drain's time")?;
        let streams = match held.remove(&6) {
            Some(Value::Array(streams)) if streams.len() <= MAX_STREAMS => streams
                .into_iter()
                .map(|stream| {
                    let mut stream = labelled_value(stream, "a drained stream", 6)?;
                    let read = DrainedStream {
                        plane: take_text(&mut stream, 1, "a stream's plane")?,
                        stream_type: take_text(&mut stream, 2, "a stream's type")?,
                        resource: take_text(&mut stream, 3, "a stream's resource")?,
                        run: take_text(&mut stream, 4, "a stream's run")?,
                        last_seq: take_uint(&mut stream, 5, "a stream's last sequence")?,
                        acknowledged: take_uint(&mut stream, 6, "a stream's acknowledgement")?,
                    };
                    finish(stream, "a drained stream")?;
                    check_run(&read.run)?;
                    Ok(read)
                })
                .collect::<Result<_, String>>()?,
            Some(Value::Array(_)) => {
                return Err(format!(
                    "a drain receipt names at most {MAX_STREAMS} streams"
                ));
            }
            _ => return Err("the drained streams are an array".to_owned()),
        };
        finish(held, WHAT)?;
        Ok(Self {
            host_id,
            volume_id,
            generation,
            drained_at,
            streams,
        })
    }
}

/// A run is 16 bytes, as 32 lowercase hexadecimal digits, as the frontier names it.
fn check_run(run: &str) -> Result<(), String> {
    if run.len() != 32
        || !run
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("`{run}` is not a run"));
    }
    Ok(())
}

/// The COSE_Sign1 `permguard.drain.receipt.v1` over `receipt` by the active `host.operations` key,
/// under its kid.
pub fn sign(ring: &Ring, receipt: &DrainReceipt) -> Result<Vec<u8>, String> {
    if ring.id() != HOST_OPERATIONS {
        return Err(format!(
            "a drain receipt is signed under `{HOST_OPERATIONS}`, not `{}`",
            ring.id()
        ));
    }
    let kid = ring.active_key_id().map_err(|error| error.to_string())?;
    let envelope = Sign1::sign_with(
        ring.suite(),
        protected::DRAIN_RECEIPT,
        kid.as_str().as_bytes(),
        receipt.encode()?,
        |bytes| {
            let signature =
                permguard_core::keys::Sign::sign(ring, bytes).map_err(|error| error.to_string())?;
            if signature.key_id() != &kid {
                return Err("the signing key rotated mid-signature".to_owned());
            }
            Ok(signature.bytes().to_vec())
        },
    )
    .map_err(|error| error.to_string())?;
    envelope.encode().map_err(|error| error.to_string())
}

/// Verifies `envelope` under the member's verification bundle, anchored on `pin` (the member's
/// first identity fingerprint, as its coordinator holds it), and answers the receipt: the bundle
/// verifies under the pin, the receipt's key is a `host.operations` key of it and not revoked, the
/// signature verifies over `permguard.drain.receipt.v1`, and the receipt names the bundle's Host.
pub fn verify(
    envelope: &[u8],
    bundle_manifest: &[u8],
    bundle_items: &[Vec<u8>],
    pin: &str,
) -> Result<DrainReceipt, String> {
    use crate::keys::bundle;

    if envelope.len() > MAX_RECEIPT_BYTES {
        return Err(format!(
            "a drain receipt takes at most {MAX_RECEIPT_BYTES} bytes"
        ));
    }
    let verified = bundle::verify(bundle_manifest, bundle_items, pin, "host")
        .map_err(|error| format!("the verification bundle: {error}"))?;
    let payload = super::backup::operations_payload(
        &verified,
        envelope,
        protected::DRAIN_RECEIPT,
        "issue it after the drain",
    )?;
    let receipt = DrainReceipt::decode(&payload)?;
    if receipt.host_id != verified.identity.host_id {
        return Err("the drain receipt names another Host than the bundle".to_owned());
    }
    Ok(receipt)
}
