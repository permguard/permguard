// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Audit checkpoints and anchors (WP-3.7, owner decisions of 2026-10-11), registered in
//! `contracts/cbor/audit.json`.
//!
//! | File                               | Content                                                       |
//! | ---------------------------------- | ------------------------------------------------------------- |
//! | `checkpoints/YYYY-MM-DD.cose`      | the day's seal: a COSE_Sign1 `permguard.audit.checkpoint.v1`  |
//! | `checkpoints/YYYY-MM-DD.<seq>.cose`| an on-demand checkpoint of the day, up to the record `<seq>`   |
//! | `checkpoints/<name>.witness.cose`  | a registered witness's co-signature over `<name>.cose`        |
//! | `ANCHOR.cbor`                      | what retention deleted: the first sequence kept and its seal  |
//!
//! A checkpoint covers one UTC day of one trail from the day's first record to `last_seq`, and
//! names the digest of the trail's checkpoint before it, so the checkpoints of a trail form one
//! chain: a verifier holding any of them finds it in the chain and checks every record from its
//! head to the newest without trusting what the volume holds now. A checkpoint is signed under
//! `host.operations` with its key's kid, and its `key_set_epoch` is the epoch of the ring whose
//! key signs. Checkpoints are never deleted; the anchor binds the deleted prefix to the seal of
//! its last day.

use std::collections::{BTreeMap, BTreeSet};

use permguard_core::domains::digest::AUDIT_CHECKPOINT as CHECKPOINT_DIGEST;
use permguard_core::domains::protected;
use permguard_core::keys::{Jwk, Sign as _};
use permguard_objects::cbor::{self, Value};
use permguard_objects::cose::Sign1;
use permguard_objects::crypto::suite::Suite;
use permguard_objects::digest::Digest;
use sha2::{Digest as _, Sha256};

use crate::keys::ring::{HOST_OPERATIONS, Ring};

use super::record::{Labelled, RecordError, genesis, hex, id16, uint};

/// The ending of a checkpoint file.
pub const CHECKPOINT_SUFFIX: &str = ".cose";
/// The ending of a witness's co-signature, beside the checkpoint it co-signs.
pub const WITNESS_SUFFIX: &str = ".witness.cose";
/// The file naming what retention deleted.
pub const ANCHOR: &str = "ANCHOR.cbor";
/// The most bytes a checkpoint envelope, a co-signature or an anchor takes.
pub const MAX_CHECKPOINT_BYTES: usize = 16 * 1024;

type Result<T> = std::result::Result<T, RecordError>;

/// One checkpoint's payload (labels 1 to 9, owner decision of 2026-10-11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    /// `<class>:<resource>`.
    pub trail: String,
    /// The UTC day, `YYYY-MM-DD`.
    pub period: String,
    /// The day's first record.
    pub first_seq: u64,
    /// The last record covered.
    pub last_seq: u64,
    /// The digest of the record `last_seq`.
    pub head_digest: Digest,
    /// The digest of the trail's previous checkpoint envelope; [`genesis`] for the first.
    pub previous_checkpoint: Digest,
    /// The installation that sealed it.
    pub host_id: [u8; 16],
    /// The epoch of the `host.operations` ring whose key signs.
    pub key_set_epoch: u64,
    /// When it was sealed, in seconds.
    pub created_at: u64,
}

impl Checkpoint {
    /// The canonical bytes.
    pub fn encode(&self) -> Result<Vec<u8>> {
        cbor::encode(&Value::Map(vec![
            (Value::Int(1), Value::Text(self.trail.clone())),
            (Value::Int(2), Value::Text(self.period.clone())),
            (Value::Int(3), uint(self.first_seq)?),
            (Value::Int(4), uint(self.last_seq)?),
            (Value::Int(5), Value::Text(self.head_digest.to_string())),
            (
                Value::Int(6),
                Value::Text(self.previous_checkpoint.to_string()),
            ),
            (Value::Int(7), Value::Bytes(self.host_id.to_vec())),
            (Value::Int(8), uint(self.key_set_epoch)?),
            (Value::Int(9), uint(self.created_at)?),
        ]))
        .map_err(|e| RecordError::Cbor(e.to_string()))
    }

    /// Reads the canonical bytes, refusing an unknown label, a missing one, a value of another
    /// type, a period that is not a day and a range that runs backwards.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_CHECKPOINT_BYTES {
            return Err(RecordError::TooLarge(bytes.len()));
        }
        let value = cbor::decode_canonical(bytes).map_err(|e| RecordError::Cbor(e.to_string()))?;
        let mut map = Labelled::new(value, 9)?;
        let checkpoint = Self {
            trail: map.text(1)?,
            period: map.text(2)?,
            first_seq: map.uint(3)?,
            last_seq: map.uint(4)?,
            head_digest: map.digest(5)?,
            previous_checkpoint: map.digest(6)?,
            host_id: id16(map.bytes(7)?)?,
            key_set_epoch: map.uint(8)?,
            created_at: map.uint(9)?,
        };
        map.finish()?;
        if permguard_core::time::Date::from_iso(&checkpoint.period).is_none() {
            return Err(RecordError::Malformed(format!(
                "`{}` is not a day",
                checkpoint.period
            )));
        }
        if checkpoint.last_seq < checkpoint.first_seq {
            return Err(RecordError::Malformed(
                "the last record covered comes before the first".to_owned(),
            ));
        }
        Ok(checkpoint)
    }
}

/// `ANCHOR.cbor`: the prefix retention deleted (labels 1 to 4, owner decision of 2026-10-11).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Anchor {
    /// `<class>:<resource>`.
    pub trail: String,
    /// The first sequence kept.
    pub low_watermark: u64,
    /// The last day deleted, `YYYY-MM-DD`.
    pub through: String,
    /// The digest of the seal of `through`, whose `last_seq` is `low_watermark - 1`.
    pub checkpoint: Digest,
}

impl Anchor {
    /// The canonical bytes.
    pub fn encode(&self) -> Result<Vec<u8>> {
        cbor::encode(&Value::Map(vec![
            (Value::Int(1), Value::Text(self.trail.clone())),
            (Value::Int(2), uint(self.low_watermark)?),
            (Value::Int(3), Value::Text(self.through.clone())),
            (Value::Int(4), Value::Text(self.checkpoint.to_string())),
        ]))
        .map_err(|e| RecordError::Cbor(e.to_string()))
    }

    /// Reads the canonical bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_CHECKPOINT_BYTES {
            return Err(RecordError::TooLarge(bytes.len()));
        }
        let value = cbor::decode_canonical(bytes).map_err(|e| RecordError::Cbor(e.to_string()))?;
        let mut map = Labelled::new(value, 4)?;
        let anchor = Self {
            trail: map.text(1)?,
            low_watermark: map.uint(2)?,
            through: map.text(3)?,
            checkpoint: map.digest(4)?,
        };
        map.finish()?;
        if permguard_core::time::Date::from_iso(&anchor.through).is_none() {
            return Err(RecordError::Malformed(format!(
                "`{}` is not a day",
                anchor.through
            )));
        }
        Ok(anchor)
    }
}

/// The digest a checkpoint is cited by: SHA-256 over `digest::AUDIT_CHECKPOINT` and the bytes of
/// its envelope.
pub fn envelope_digest(envelope: &[u8]) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(CHECKPOINT_DIGEST.as_bytes());
    hasher.update(envelope);
    let raw: [u8; 32] = hasher.finalize().into();
    #[allow(clippy::expect_used)]
    Digest::parse(&format!("sha256:{}", hex(&raw))).expect("a SHA-256 renders as a digest")
}

/// The `previous_checkpoint` of a trail's first checkpoint.
pub fn no_checkpoint() -> Digest {
    genesis()
}

/// The file name of a checkpoint of `period`: the day's seal, or an on-demand checkpoint up to
/// `last_seq`.
pub fn file_name(period: &str, on_demand: Option<u64>) -> String {
    match on_demand {
        None => format!("{period}{CHECKPOINT_SUFFIX}"),
        Some(seq) => format!("{period}.{seq}{CHECKPOINT_SUFFIX}"),
    }
}

/// The co-signature file of the checkpoint `name`.
pub fn witness_name(name: &str) -> String {
    format!(
        "{}{WITNESS_SUFFIX}",
        name.strip_suffix(CHECKPOINT_SUFFIX).unwrap_or(name)
    )
}

/// The period and, for an on-demand checkpoint, the last sequence a checkpoint file name says;
/// `None` for anything else, a co-signature included.
pub fn parse_name(name: &str) -> Option<(String, Option<u64>)> {
    if name.ends_with(WITNESS_SUFFIX) {
        return None;
    }
    let stem = name.strip_suffix(CHECKPOINT_SUFFIX)?;
    let (period, seq) = match stem.split_once('.') {
        None => (stem, None),
        Some((period, seq)) => {
            if seq.is_empty() || !seq.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            (period, Some(seq.parse().ok()?))
        }
    };
    permguard_core::time::Date::from_iso(period)?;
    Some((period.to_owned(), seq))
}

/// The checkpoint files among `names`, in the order they were sealed: by day, and within a day
/// the on-demand ones by sequence before the day's seal, which closes the day.
pub fn ordered(names: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut found: Vec<((String, u64), String)> = names
        .into_iter()
        .filter_map(|name| {
            parse_name(&name).map(|(period, seq)| ((period, seq.unwrap_or(u64::MAX)), name))
        })
        .collect();
    found.sort();
    found.into_iter().map(|(_, name)| name).collect()
}

/// What signs a checkpoint: the server's `host.operations` ring.
pub trait CheckpointSigner: Send + Sync {
    /// Sets `checkpoint`'s `key_set_epoch` to the epoch of the key set whose key signs, and
    /// answers the COSE_Sign1 `permguard.audit.checkpoint.v1` over it under that key's kid.
    fn seal(&self, checkpoint: &mut Checkpoint) -> std::result::Result<Vec<u8>, String>;
}

impl CheckpointSigner for Ring {
    fn seal(&self, checkpoint: &mut Checkpoint) -> std::result::Result<Vec<u8>, String> {
        if self.id() != HOST_OPERATIONS {
            return Err(format!(
                "a checkpoint is signed under `{HOST_OPERATIONS}`, not `{}`",
                self.id()
            ));
        }
        let kid = self.active_key_id().map_err(|error| error.to_string())?;
        let epoch = self.epoch();
        checkpoint.key_set_epoch = epoch;
        let payload = checkpoint.encode().map_err(|error| error.to_string())?;
        let envelope = Sign1::sign_with(
            self.suite(),
            protected::AUDIT_CHECKPOINT,
            kid.as_str().as_bytes(),
            payload,
            |bytes| {
                let signature =
                    permguard_core::keys::Sign::sign(self, bytes).map_err(|e| e.to_string())?;
                if signature.key_id() != &kid || self.epoch() != epoch {
                    return Err("the signing key rotated mid-signature".to_owned());
                }
                Ok(signature.bytes().to_vec())
            },
        )
        .map_err(|error| error.to_string())?;
        envelope.encode().map_err(|error| error.to_string())
    }
}

/// An external witness co-signing each checkpoint (owner decision of 2026-10-11): none ships;
/// a composition registers one. It holds public keys only.
pub trait CheckpointWitness: Send + Sync {
    /// Its co-signature over the checkpoint `envelope`, kept beside it as it is answered. An
    /// error, or no answer within the witness's own bound, leaves the checkpoint as it was and
    /// is asked again at the next sweep.
    fn cosign(&self, envelope: &[u8]) -> std::result::Result<Vec<u8>, String>;
}

/// A checkpoint whose signature verified, and by which key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signed {
    pub checkpoint: Checkpoint,
    pub kid: String,
    /// Whether the key that signed was revoked since.
    pub revoked: bool,
}

/// The `host.operations` public keys a checkpoint is verified with.
#[derive(Debug, Clone, Default)]
pub struct Keys {
    keys: BTreeMap<String, (Suite, Vec<u8>)>,
    revoked: BTreeSet<String>,
}

impl Keys {
    /// Reads a key document: what `keys export` prints for the `host.operations` ring (its
    /// published `keys`, its `retained` ones, whose old signatures still verify, and the kids it
    /// `revoked`), or a plain JWKS. A document of another ring, a key whose kid is not under
    /// `host.operations` and a document with no key are refused.
    pub fn from_document(text: &str) -> std::result::Result<Self, String> {
        let document: serde_json::Value =
            serde_json::from_str(text).map_err(|error| format!("not a key document: {error}"))?;
        if let Some(ring) = document.get("ring")
            && ring.as_str() != Some(HOST_OPERATIONS)
        {
            return Err(format!(
                "the key document is of the ring {ring}, and checkpoints are signed under \
                 `{HOST_OPERATIONS}`"
            ));
        }
        let mut keys = Self::default();
        let published = document
            .get("keys")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten();
        let retained = document
            .get("retained")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|held| held.get("jwk"));
        for jwk in published.chain(retained) {
            let jwk: Jwk = serde_json::from_value(jwk.clone())
                .map_err(|error| format!("a key of the document does not read: {error}"))?;
            keys.add(&jwk)?;
        }
        for revoked in document
            .get("revoked")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(kid) = revoked.get("kid").and_then(serde_json::Value::as_str) {
                keys.revoked.insert(kid.to_owned());
            }
        }
        if keys.keys.is_empty() {
            return Err("the key document holds no key".to_owned());
        }
        Ok(keys)
    }

    fn add(&mut self, jwk: &Jwk) -> std::result::Result<(), String> {
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
        let under = permguard_objects::crypto::thumbprint::split_kid(&jwk.kid)
            .is_some_and(|(ring, _)| ring == HOST_OPERATIONS);
        if !under {
            return Err(format!(
                "the key `{}` is not a `{HOST_OPERATIONS}` key",
                jwk.kid
            ));
        }
        let suite = crate::keys::ring::suite_of(jwk)
            .ok_or_else(|| format!("the key `{}` is of no suite this build verifies", jwk.kid))?;
        let mut bytes = B64
            .decode(&jwk.x)
            .map_err(|_| format!("the key `{}` does not decode", jwk.kid))?;
        if let Some(y) = jwk.y.as_deref() {
            bytes.insert(0, 0x04);
            bytes.extend(
                B64.decode(y)
                    .map_err(|_| format!("the key `{}` does not decode", jwk.kid))?,
            );
        }
        if bytes.len() != suite.public_key_len() {
            return Err(format!(
                "the key `{}` is not of its suite's length",
                jwk.kid
            ));
        }
        self.keys.insert(jwk.kid.clone(), (suite, bytes));
        Ok(())
    }

    /// Verifies a checkpoint envelope and answers its payload: signed by a key of the set under
    /// its kid, as `permguard.audit.checkpoint.v1`. A signature by a revoked key verifies and is
    /// answered as such: it stands only where a later checkpoint by a key that is not revoked
    /// chains over it (owner decision of 2026-10-11, after the review), which only the chain
    /// shows.
    pub fn verify(&self, envelope: &[u8]) -> std::result::Result<Signed, String> {
        if envelope.len() > MAX_CHECKPOINT_BYTES {
            return Err(format!(
                "{} bytes; a checkpoint takes up to {MAX_CHECKPOINT_BYTES}",
                envelope.len()
            ));
        }
        let sign1 = Sign1::decode(envelope).map_err(|error| error.to_string())?;
        let header = sign1.header().map_err(|error| error.to_string())?;
        let kid = String::from_utf8(header.kid)
            .map_err(|_| "the checkpoint's kid is not text".to_owned())?;
        let revoked = self.revoked.contains(&kid);
        let (suite, public_key) = self
            .keys
            .get(&kid)
            .ok_or_else(|| format!("the checkpoint is signed by `{kid}`, a key the set lacks"))?;
        let payload = sign1
            .verify(*suite, public_key, protected::AUDIT_CHECKPOINT)
            .map_err(|error| error.to_string())?;
        let checkpoint = Checkpoint::decode(payload).map_err(|error| error.to_string())?;
        Ok(Signed {
            checkpoint,
            kid,
            revoked,
        })
    }
}

impl Keys {
    /// Verifies `signature` over `message` by the `host.operations` key whose thumbprint is
    /// `thumbprint` and whose algorithm is `algorithm` (`EdDSA` or `ES256`): how a seal of the
    /// legacy JSON-lines trail names its key, a bare thumbprint (WP-3.8). Answers the key's kid and
    /// whether it was revoked since.
    pub fn verify_by_thumbprint(
        &self,
        thumbprint: &str,
        algorithm: &str,
        message: &[u8],
        signature: &[u8],
    ) -> std::result::Result<(String, bool), String> {
        let kid = format!("{HOST_OPERATIONS}:{thumbprint}");
        let (suite, public_key) = self
            .keys
            .get(&kid)
            .ok_or_else(|| format!("signed by `{thumbprint}`, a key the set lacks"))?;
        let expected = match suite {
            Suite::Ed25519Sha256V1 => "EdDSA",
            Suite::P256Sha256V1 => "ES256",
        };
        if algorithm != expected {
            return Err(format!(
                "signed with `{algorithm}`, and the key `{kid}` is an `{expected}` key"
            ));
        }
        suite
            .verify(public_key, message, signature)
            .map_err(|error| format!("the signature does not verify: {error:?}"))?;
        let revoked = self.revoked.contains(&kid);
        Ok((kid, revoked))
    }
}

/// The payload of a checkpoint envelope, **without verifying** its signature: what the engine
/// reads back of its own checkpoints to continue the chain.
pub fn read_unverified(envelope: &[u8]) -> Result<Checkpoint> {
    let sign1 = Sign1::decode(envelope).map_err(|e| RecordError::Cbor(e.to_string()))?;
    Checkpoint::decode(sign1.payload_unverified())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;

    fn checkpoint() -> Checkpoint {
        Checkpoint {
            trail: "security:host".to_owned(),
            period: "2026-10-11".to_owned(),
            first_seq: 3,
            last_seq: 9,
            head_digest: Digest::compute(b"head"),
            previous_checkpoint: no_checkpoint(),
            host_id: [7; 16],
            key_set_epoch: 2,
            created_at: 1_800_000_000,
        }
    }

    #[test]
    fn a_checkpoint_round_trips_and_refuses_what_it_does_not_name() {
        let checkpoint = checkpoint();
        let bytes = checkpoint.encode().unwrap();
        assert_eq!(Checkpoint::decode(&bytes).unwrap(), checkpoint);

        // An unknown label, a missing one, a value of another type.
        let Value::Map(mut pairs) = cbor::decode_canonical(&bytes).unwrap() else {
            panic!("a map")
        };
        let mut extra = pairs.clone();
        extra.push((Value::Int(10), Value::Int(0)));
        let refused = Checkpoint::decode(&cbor::encode(&Value::Map(extra)).unwrap());
        assert!(
            matches!(&refused, Err(RecordError::Malformed(m)) if m.contains("unknown label 10")),
            "{refused:?}"
        );
        let mut typed = pairs.clone();
        typed[2].1 = Value::Text("3".to_owned());
        let refused = Checkpoint::decode(&cbor::encode(&Value::Map(typed)).unwrap());
        assert!(
            matches!(&refused, Err(RecordError::Malformed(m)) if m.contains("label 3")),
            "{refused:?}"
        );
        pairs.remove(4);
        let refused = Checkpoint::decode(&cbor::encode(&Value::Map(pairs)).unwrap());
        assert!(
            matches!(&refused, Err(RecordError::Malformed(m)) if m.contains("label 5 is required")),
            "{refused:?}"
        );

        // A period that is not a day, a range running backwards.
        let mut bad = checkpoint.clone();
        bad.period = "2026-13-01".to_owned();
        assert!(Checkpoint::decode(&bad.encode().unwrap()).is_err());
        let mut backwards = checkpoint;
        backwards.last_seq = 2;
        assert!(Checkpoint::decode(&backwards.encode().unwrap()).is_err());
    }

    #[test]
    fn an_anchor_round_trips() {
        let anchor = Anchor {
            trail: "access:plane/data".to_owned(),
            low_watermark: 10,
            through: "2026-10-01".to_owned(),
            checkpoint: Digest::compute(b"seal"),
        };
        let bytes = anchor.encode().unwrap();
        assert_eq!(Anchor::decode(&bytes).unwrap(), anchor);
        let mut bad = anchor;
        bad.through = "yesterday".to_owned();
        assert!(Anchor::decode(&bad.encode().unwrap()).is_err());
    }

    #[test]
    fn checkpoint_names_order_by_day_then_sequence_with_the_seal_last() {
        let names = [
            "2026-10-11.cose",
            "2026-10-11.12.cose",
            "2026-10-10.cose",
            "2026-10-11.3.cose",
            "2026-10-11.3.witness.cose",
            "2026-10-11.x.cose",
            "ANCHOR.cbor",
        ]
        .map(str::to_owned);
        assert_eq!(
            ordered(names),
            [
                "2026-10-10.cose",
                "2026-10-11.3.cose",
                "2026-10-11.12.cose",
                "2026-10-11.cose"
            ]
        );
        assert_eq!(
            witness_name("2026-10-11.3.cose"),
            "2026-10-11.3.witness.cose"
        );
        assert_eq!(file_name("2026-10-11", Some(4)), "2026-10-11.4.cose");
    }
}
