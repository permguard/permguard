// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! A ref's state and its digest (WP-7.1; owner decisions of 2026-10-14).
//!
//! ```text
//! RefState   = {1 head, 2 counter, 3? previous_ref_digest}     deterministic CBOR
//! ref_digest = SHA-256("permguard.notp.ref-state.v1\n" || RefState)
//! ```
//!
//! Digests are `sha256:<hex>` text, as NOTP's other digests. The counter moves by one for every
//! different head; `previous_ref_digest` names the state before, absent at a ref's first state.
//! A head statement carries the `ref_digest`, so a client that holds one can tell an advance from
//! a retry, an equivocation or a rollback by `(counter, ref_digest)`.

use permguard_core::domains::digest::NOTP_REF_STATE;
use sha2::{Digest as _, Sha256};

use crate::cbor::{self, CborError, Value};
use crate::digest::{Digest, DigestError};

const KEY_HEAD: i64 = 1;
const KEY_COUNTER: i64 = 2;
const KEY_PREVIOUS: i64 = 3;
/// The most bytes a ref state's encoding takes.
pub const MAX_REF_STATE_BYTES: usize = 256;

/// One ref's state: its head, its counter and the digest of the state before.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefState {
    pub head: Digest,
    pub counter: u64,
    /// The `ref_digest` of the state this one follows; `None` at a ref's first state.
    pub previous_ref_digest: Option<Digest>,
}

impl RefState {
    /// The deterministic CBOR the digest is taken over.
    pub fn encode(&self) -> Result<Vec<u8>, RefStateError> {
        let counter = i64::try_from(self.counter).map_err(|_| RefStateError::CounterRange)?;
        let mut pairs = vec![
            (Value::Int(KEY_HEAD), Value::Text(self.head.to_string())),
            (Value::Int(KEY_COUNTER), Value::Int(counter)),
        ];
        if let Some(previous) = &self.previous_ref_digest {
            pairs.push((Value::Int(KEY_PREVIOUS), Value::Text(previous.to_string())));
        }
        Ok(cbor::encode(&Value::Map(pairs))?)
    }

    /// Reads a ref state, refusing non-canonical bytes and unknown labels.
    pub fn decode(bytes: &[u8]) -> Result<Self, RefStateError> {
        if bytes.len() > MAX_REF_STATE_BYTES {
            return Err(RefStateError::Schema("a ref state is out of its bound"));
        }
        let Value::Map(map) = cbor::decode_canonical(bytes)? else {
            return Err(RefStateError::Schema("a ref state is a map"));
        };
        if map.iter().any(|(key, _)| {
            ![KEY_HEAD, KEY_COUNTER, KEY_PREVIOUS]
                .iter()
                .any(|known| *key == Value::Int(*known))
        }) {
            return Err(RefStateError::Schema(
                "a ref state carries an unknown label",
            ));
        }
        let field = |key: i64| {
            map.iter()
                .find(|(k, _)| *k == Value::Int(key))
                .map(|(_, v)| v)
        };
        let head = match field(KEY_HEAD) {
            Some(Value::Text(text)) => Digest::parse(text)?,
            _ => return Err(RefStateError::Schema("a ref state names its head")),
        };
        let counter = match field(KEY_COUNTER) {
            Some(Value::Int(counter)) if *counter >= 1 => {
                u64::try_from(*counter).map_err(|_| RefStateError::CounterRange)?
            }
            _ => return Err(RefStateError::Schema("a ref state's counter is 1 or more")),
        };
        let previous_ref_digest = match field(KEY_PREVIOUS) {
            Some(Value::Text(text)) => Some(Digest::parse(text)?),
            None => None,
            Some(_) => return Err(RefStateError::Schema("a previous ref digest is text")),
        };
        Ok(Self {
            head,
            counter,
            previous_ref_digest,
        })
    }

    /// `SHA-256(NOTP_REF_STATE || RefState)`.
    pub fn ref_digest(&self) -> Result<Digest, RefStateError> {
        let mut hasher = Sha256::new();
        hasher.update(NOTP_REF_STATE.as_bytes());
        hasher.update(self.encode()?);
        Ok(Digest::from_raw(hasher.finalize().into()))
    }

    /// The state after this one when the head moves to `head`: the counter one higher, this
    /// state's digest as the previous.
    pub fn successor(&self, head: Digest) -> Result<Self, RefStateError> {
        Ok(Self {
            head,
            counter: self
                .counter
                .checked_add(1)
                .ok_or(RefStateError::CounterRange)?,
            previous_ref_digest: Some(self.ref_digest()?),
        })
    }

    /// A ref's first state at `head`.
    pub fn first(head: Digest) -> Self {
        Self {
            head,
            counter: 1,
            previous_ref_digest: None,
        }
    }
}

/// Why a ref state was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefStateError {
    Cbor(CborError),
    Digest(DigestError),
    Schema(&'static str),
    CounterRange,
}

impl std::fmt::Display for RefStateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cbor(error) => write!(f, "encoding: {error}"),
            Self::Digest(error) => write!(f, "digest: {error}"),
            Self::Schema(what) => write!(f, "schema: {what}"),
            Self::CounterRange => write!(f, "counter out of range"),
        }
    }
}

impl std::error::Error for RefStateError {}

impl From<CborError> for RefStateError {
    fn from(error: CborError) -> Self {
        Self::Cbor(error)
    }
}

impl From<DigestError> for RefStateError {
    fn from(error: DigestError) -> Self {
        Self::Digest(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_ref_state_round_trips_and_chains_to_the_one_before() {
        let first = RefState::first(Digest::compute(b"one"));
        assert_eq!(RefState::decode(&first.encode().unwrap()).unwrap(), first);
        let second = first.successor(Digest::compute(b"two")).unwrap();
        assert_eq!(second.counter, 2);
        assert_eq!(
            second.previous_ref_digest,
            Some(first.ref_digest().unwrap())
        );
        assert_eq!(RefState::decode(&second.encode().unwrap()).unwrap(), second);
        assert_ne!(first.ref_digest().unwrap(), second.ref_digest().unwrap());
    }

    #[test]
    fn a_ref_state_with_a_zero_counter_or_an_unknown_label_is_refused() {
        let zero = cbor::encode(&Value::Map(vec![
            (
                Value::Int(1),
                Value::Text(Digest::compute(b"x").to_string()),
            ),
            (Value::Int(2), Value::Int(0)),
        ]))
        .unwrap();
        assert!(RefState::decode(&zero).is_err());
        let unknown = cbor::encode(&Value::Map(vec![
            (
                Value::Int(1),
                Value::Text(Digest::compute(b"x").to_string()),
            ),
            (Value::Int(2), Value::Int(1)),
            (Value::Int(4), Value::Int(1)),
        ]))
        .unwrap();
        assert!(RefState::decode(&unknown).is_err());
    }

    /// Past its bound a ref state is refused before it is parsed, whatever it holds.
    #[test]
    fn a_ref_state_past_its_bound_is_refused_unread() {
        assert_eq!(
            RefState::decode(&[0u8; MAX_REF_STATE_BYTES + 1]),
            Err(RefStateError::Schema("a ref state is out of its bound"))
        );
    }
}
