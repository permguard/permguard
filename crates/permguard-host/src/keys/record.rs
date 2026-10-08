// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! A ring's records, byte for byte (owner decisions of 2026-10-08; `contracts/cbor/keys.json`).
//!
//! | Record                 | Shape                                                                                              |
//! | ---------------------- | -------------------------------------------------------------------------------------------------- |
//! | `journal.cborseq` item | {1 seq, 2 kind, 3 kid, 4 epoch, 5 at, 6? operation_id, 7? reason, 8? jwk, 9? compromised_at}       |
//! | `ring.cbor`            | {1 ring, 2 suite, 3 epoch, 4 key_set_digest, 5 keys [{1 kid, 2 state, 3 jwk, 4 prepublished_at, 5? activated_at, 6? retired_at, 7? revoked_at}]} |
//! | ring binding payload   | {1 host_id, 2 ring, 3 epoch, 4 key_set_digest, 5 suite, 6 not_before, 7 not_after}, COSE_Sign1 `permguard.host.ring-binding.v1` by the identity key |
//!
//! `jwk` is the RFC 7517 JSON of the public key as it is published, written on `prepublished`
//! only; `reason` and `compromised_at` on `revoked` only. Every map is closed and canonical.

use permguard_objects::cbor::Value;
use permguard_objects::crypto::suite::Suite;

use crate::identity::record::{Labelled, RecordError, encode, uint};

/// The most bytes one journal entry takes.
pub const MAX_ENTRY_BYTES: usize = 16 * 1024;
/// The most bytes a ring binding's payload takes: a peer presents it (WP-11).
pub const MAX_BINDING_BYTES: usize = 4096;
/// The longest revocation reason.
pub const MAX_REASON_BYTES: usize = 256;

/// What a journal entry records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A key enters the published set; its private half exists.
    Prepublished,
    /// The key signs from now on.
    Activated,
    /// The key no longer signs; its public half stays published.
    Retired,
    /// The key is compromised: it leaves the published set at once.
    Revoked,
    /// The key leaves the published set; its public half stays on the volume for good.
    Archived,
    /// The private half is destroyed.
    Destroyed,
    /// A ring binding was issued for the epoch: `kid` names the identity key that signed it.
    Bound,
    /// The private half, held in plaintext, is sealed in place under the KEK (WP-3.2). Journaled
    /// before the sealing: a crash between the two journals it again at the next start.
    Sealed,
    /// The private half's DEK is rewrapped under the current KEK, the ciphertext unchanged;
    /// journaled before, as `Sealed`.
    Rewrapped,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Prepublished => "prepublished",
            Self::Activated => "activated",
            Self::Retired => "retired",
            Self::Revoked => "revoked",
            Self::Archived => "archived",
            Self::Destroyed => "destroyed",
            Self::Bound => "bound",
            Self::Sealed => "sealed",
            Self::Rewrapped => "rewrapped",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "prepublished" => Self::Prepublished,
            "activated" => Self::Activated,
            "retired" => Self::Retired,
            "revoked" => Self::Revoked,
            "archived" => Self::Archived,
            "destroyed" => Self::Destroyed,
            "bound" => Self::Bound,
            "sealed" => Self::Sealed,
            "rewrapped" => Self::Rewrapped,
            _ => return None,
        })
    }
}

/// One entry of `journal.cborseq`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub seq: u64,
    pub kind: Kind,
    pub kid: String,
    /// The ring epoch once the entry applies.
    pub epoch: u64,
    pub at: u64,
    /// The mutation that made it, for an operator's rotation or revocation.
    pub operation_id: Option<[u8; 16]>,
    pub reason: Option<String>,
    pub jwk: Option<String>,
    pub compromised_at: Option<u64>,
}

impl Entry {
    pub fn encode(&self) -> Result<Vec<u8>, RecordError> {
        self.check()?;
        let mut pairs = vec![
            (Value::Int(1), uint(self.seq)?),
            (Value::Int(2), Value::Text(self.kind.as_str().to_owned())),
            (Value::Int(3), Value::Text(self.kid.clone())),
            (Value::Int(4), uint(self.epoch)?),
            (Value::Int(5), uint(self.at)?),
        ];
        if let Some(id) = &self.operation_id {
            pairs.push((Value::Int(6), Value::Bytes(id.to_vec())));
        }
        if let Some(reason) = &self.reason {
            pairs.push((Value::Int(7), Value::Text(reason.clone())));
        }
        if let Some(jwk) = &self.jwk {
            pairs.push((Value::Int(8), Value::Text(jwk.clone())));
        }
        if let Some(at) = self.compromised_at {
            pairs.push((Value::Int(9), uint(at)?));
        }
        encode(pairs)
    }

    pub fn decode(value: Value) -> Result<Self, RecordError> {
        let mut map = Labelled::from_value(value, "a ring journal entry")?;
        let kind = map.text(2)?;
        let entry = Self {
            seq: map.uint(1)?,
            kind: Kind::parse(&kind)
                .ok_or_else(|| RecordError(format!("`{kind}` is not a ring journal kind")))?,
            kid: map.text(3)?,
            epoch: map.uint(4)?,
            at: map.uint(5)?,
            operation_id: map.optional_fixed(6)?,
            reason: map.optional_text(7)?,
            jwk: map.optional_text(8)?,
            compromised_at: map.optional_uint(9)?,
        };
        map.finish()?;
        entry.check()?;
        Ok(entry)
    }

    /// The members each kind carries, and only those.
    fn check(&self) -> Result<(), RecordError> {
        let prepublished = self.kind == Kind::Prepublished;
        let revoked = self.kind == Kind::Revoked;
        if self.jwk.is_some() != prepublished {
            return Err(RecordError(
                "a ring journal entry carries a jwk on `prepublished` and only there".to_owned(),
            ));
        }
        if (self.reason.is_some() || self.compromised_at.is_some()) && !revoked {
            return Err(RecordError(
                "a reason and a compromise time belong to `revoked` only".to_owned(),
            ));
        }
        if revoked && self.reason.is_none() {
            return Err(RecordError("a revocation states its reason".to_owned()));
        }
        if self
            .reason
            .as_ref()
            .is_some_and(|reason| reason.is_empty() || reason.len() > MAX_REASON_BYTES)
        {
            return Err(RecordError(format!(
                "a revocation reason takes 1 to {MAX_REASON_BYTES} bytes"
            )));
        }
        Ok(())
    }
}

/// Where a key is in its life, as `ring.cbor` names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Prepublished,
    Active,
    RetiredPublic,
    Revoked,
    Archived,
}

impl State {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Prepublished => "prepublished",
            Self::Active => "active",
            Self::RetiredPublic => "retired-public",
            Self::Revoked => "revoked",
            Self::Archived => "archived",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "prepublished" => Self::Prepublished,
            "active" => Self::Active,
            "retired-public" => Self::RetiredPublic,
            "revoked" => Self::Revoked,
            "archived" => Self::Archived,
            _ => return None,
        })
    }

    /// Whether a key in this state is in the published set: prepublished, active and
    /// retired-public. A revoked or archived key is not (owner decisions of 2026-10-08).
    pub fn is_published(self) -> bool {
        matches!(
            self,
            Self::Prepublished | Self::Active | Self::RetiredPublic
        )
    }
}

/// One key of `ring.cbor`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyView {
    pub kid: String,
    pub state: State,
    pub jwk: String,
    pub prepublished_at: u64,
    pub activated_at: Option<u64>,
    pub retired_at: Option<u64>,
    pub revoked_at: Option<u64>,
}

/// `ring.cbor`: the materialized public view, rebuilt from the journal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct View {
    pub ring: String,
    pub suite: Suite,
    pub epoch: u64,
    pub key_set_digest: [u8; 32],
    pub keys: Vec<KeyView>,
}

impl View {
    pub fn encode(&self) -> Result<Vec<u8>, RecordError> {
        let mut keys = Vec::with_capacity(self.keys.len());
        for key in &self.keys {
            let mut pairs = vec![
                (Value::Int(1), Value::Text(key.kid.clone())),
                (Value::Int(2), Value::Text(key.state.as_str().to_owned())),
                (Value::Int(3), Value::Text(key.jwk.clone())),
                (Value::Int(4), uint(key.prepublished_at)?),
            ];
            for (label, at) in [
                (5, key.activated_at),
                (6, key.retired_at),
                (7, key.revoked_at),
            ] {
                if let Some(at) = at {
                    pairs.push((Value::Int(label), uint(at)?));
                }
            }
            keys.push(Value::Map(pairs));
        }
        encode(vec![
            (Value::Int(1), Value::Text(self.ring.clone())),
            (Value::Int(2), Value::Text(self.suite.name().to_owned())),
            (Value::Int(3), uint(self.epoch)?),
            (Value::Int(4), Value::Bytes(self.key_set_digest.to_vec())),
            (Value::Int(5), Value::Array(keys)),
        ])
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        let mut map = Labelled::read(bytes, "ring.cbor")?;
        let ring = map.text(1)?;
        let suite = map.suite(2)?;
        let epoch = map.uint(3)?;
        let key_set_digest = map.fixed(4)?;
        let mut keys = Vec::new();
        for item in map.array(5)? {
            let mut key = Labelled::from_value(item, "a key of ring.cbor")?;
            let state = key.text(2)?;
            let view = KeyView {
                kid: key.text(1)?,
                state: State::parse(&state)
                    .ok_or_else(|| RecordError(format!("`{state}` is not a key state")))?,
                jwk: key.text(3)?,
                prepublished_at: key.uint(4)?,
                activated_at: key.optional_uint(5)?,
                retired_at: key.optional_uint(6)?,
                revoked_at: key.optional_uint(7)?,
            };
            key.finish()?;
            keys.push(view);
        }
        map.finish()?;
        Ok(Self {
            ring,
            suite,
            epoch,
            key_set_digest,
            keys,
        })
    }
}

/// The payload of a ring binding: the identity key vouches for one published set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    pub host_id: [u8; 16],
    pub ring: String,
    pub epoch: u64,
    pub key_set_digest: [u8; 32],
    pub suite: Suite,
    pub not_before: u64,
    pub not_after: u64,
}

impl Binding {
    pub fn encode(&self) -> Result<Vec<u8>, RecordError> {
        encode(vec![
            (Value::Int(1), Value::Bytes(self.host_id.to_vec())),
            (Value::Int(2), Value::Text(self.ring.clone())),
            (Value::Int(3), uint(self.epoch)?),
            (Value::Int(4), Value::Bytes(self.key_set_digest.to_vec())),
            (Value::Int(5), Value::Text(self.suite.name().to_owned())),
            (Value::Int(6), uint(self.not_before)?),
            (Value::Int(7), uint(self.not_after)?),
        ])
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        if bytes.len() > MAX_BINDING_BYTES {
            return Err(RecordError(format!(
                "a ring binding takes at most {MAX_BINDING_BYTES} bytes"
            )));
        }
        let mut map = Labelled::read(bytes, "a ring binding")?;
        let binding = Self {
            host_id: map.id(1)?,
            ring: map.text(2)?,
            epoch: map.uint(3)?,
            key_set_digest: map.fixed(4)?,
            suite: map.suite(5)?,
            not_before: map.uint(6)?,
            not_after: map.uint(7)?,
        };
        map.finish()?;
        if binding.not_after <= binding.not_before {
            return Err(RecordError(
                "a ring binding ends after it begins".to_owned(),
            ));
        }
        Ok(binding)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use permguard_objects::cbor;

    fn entry(kind: Kind) -> Entry {
        Entry {
            seq: 1,
            kind,
            kid: "data.attest:FtIu-VbGrfe_KB6CH7GNwODB72MNxj_ml11dEvO-7kk".to_owned(),
            epoch: 1,
            at: 1_800_000_000,
            operation_id: None,
            reason: None,
            jwk: (kind == Kind::Prepublished).then(|| "{}".to_owned()),
            compromised_at: None,
        }
    }

    #[test]
    fn every_record_reads_back_as_written_and_refuses_a_foreign_member() {
        for kind in [
            Kind::Prepublished,
            Kind::Activated,
            Kind::Retired,
            Kind::Archived,
            Kind::Destroyed,
            Kind::Bound,
        ] {
            let written = entry(kind);
            let bytes = written.encode().expect("encodes");
            let read =
                Entry::decode(cbor::decode_canonical(&bytes).expect("canonical")).expect("decodes");
            assert_eq!(read, written);
        }
        let revoked = Entry {
            operation_id: Some([7; 16]),
            reason: Some("key-compromise".to_owned()),
            compromised_at: Some(1_799_999_000),
            ..entry(Kind::Revoked)
        };
        let bytes = revoked.encode().expect("encodes");
        assert_eq!(
            Entry::decode(cbor::decode_canonical(&bytes).expect("canonical")).expect("decodes"),
            revoked
        );

        for (name, refused) in [
            (
                "a jwk off prepublished",
                Entry {
                    jwk: Some("{}".to_owned()),
                    ..entry(Kind::Activated)
                },
            ),
            (
                "a prepublished key without its jwk",
                Entry {
                    jwk: None,
                    ..entry(Kind::Prepublished)
                },
            ),
            ("a revocation without a reason", entry(Kind::Revoked)),
            (
                "a reason off a revocation",
                Entry {
                    reason: Some("x".to_owned()),
                    ..entry(Kind::Retired)
                },
            ),
            (
                "a reason beyond its bound",
                Entry {
                    reason: Some("x".repeat(MAX_REASON_BYTES + 1)),
                    ..entry(Kind::Revoked)
                },
            ),
        ] {
            assert!(refused.encode().is_err(), "{name} was written");
        }

        let mut unknown = cbor::decode_canonical(&entry(Kind::Retired).encode().expect("encodes"))
            .expect("canonical");
        if let Value::Map(pairs) = &mut unknown {
            pairs.push((Value::Int(10), Value::Int(1)));
        }
        assert!(Entry::decode(unknown).is_err(), "an unknown label");

        let view = View {
            ring: "data.attest".to_owned(),
            suite: Suite::Ed25519Sha256V1,
            epoch: 3,
            key_set_digest: [9; 32],
            keys: vec![KeyView {
                kid: "data.attest:x".to_owned(),
                state: State::RetiredPublic,
                jwk: "{}".to_owned(),
                prepublished_at: 1,
                activated_at: Some(2),
                retired_at: Some(3),
                revoked_at: None,
            }],
        };
        assert_eq!(
            View::decode(&view.encode().expect("encodes")).expect("decodes"),
            view
        );

        let binding = Binding {
            host_id: [1; 16],
            ring: "data.attest".to_owned(),
            epoch: 3,
            key_set_digest: [9; 32],
            suite: Suite::Ed25519Sha256V1,
            not_before: 10,
            not_after: 20,
        };
        assert_eq!(
            Binding::decode(&binding.encode().expect("encodes")).expect("decodes"),
            binding
        );
        let backwards = Binding {
            not_after: 10,
            ..binding
        };
        assert!(Binding::decode(&backwards.encode().expect("encodes")).is_err());
    }
}
