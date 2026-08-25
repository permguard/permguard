// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Where a consumer stands, in a form that belongs to the consumer.
//!
//! # Why the server keeps none of this
//!
//! The control plane holds no per-consumer cursor. That is what lets any
//! number of independent readers coexist — a SIEM in near-real-time, a nightly
//! export, an application answering "why was I denied" — with none of them
//! able to affect the others, and with nothing to clean up when one goes away.
//!
//! # Why it is opaque, and bound to its scope
//!
//! Opaque, because `(segment, position)` is an implementation detail: a
//! consumer that parsed it would depend on how this store rolls its files.
//!
//! Bound to its scope, because an offset is also a *capability-shaped* value.
//! An offset issued for one tenant, presented under another, must be refused
//! rather than reinterpreted — otherwise a reader that guessed a neighbour's
//! position could learn where that neighbour's records are. A stateless server
//! and a tenant boundary are not in tension: the boundary is in the address,
//! the position is in the consumer, and this binding is what joins them.

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde::{Deserialize, Serialize};

use super::store::Scope;

/// A position inside one scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Offset {
    /// Which scope issued it.
    pub scope: String,
    /// The first sequence of the segment being read.
    pub segment: u64,
    /// How many records of that segment have been returned.
    pub position: u64,
}

impl Offset {
    /// The position a reader starts from when it has none.
    pub fn beginning(scope: &Scope) -> Self {
        Self {
            scope: scope.key(),
            segment: 0,
            position: 0,
        }
    }

    /// Renders the offset as the opaque token a consumer keeps.
    pub fn encode(&self) -> String {
        let body = serde_json::to_vec(self).unwrap_or_default();

        B64.encode(body)
    }

    /// Reads a token, and refuses one that belongs to another scope.
    pub fn decode(token: &str, scope: &Scope) -> Result<Self, OffsetError> {
        let bytes = B64.decode(token).map_err(|_| OffsetError::Malformed)?;
        let offset: Self = serde_json::from_slice(&bytes).map_err(|_| OffsetError::Malformed)?;
        if offset.scope != scope.key() {
            return Err(OffsetError::WrongScope);
        }

        Ok(offset)
    }
}

/// Why an offset was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OffsetError {
    /// Not a token this store issued.
    Malformed,
    /// A token issued for a different scope.
    WrongScope,
    /// A position older than what the scope still holds.
    Expired,
}

impl fmt::Display for OffsetError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed => write!(
                formatter,
                "this is not an offset this store issued: an offset is opaque, and belongs to the consumer that was given it"
            ),
            Self::WrongScope => write!(
                formatter,
                "this offset was issued for a different zone and ledger: an offset is bound to the scope that issued it, and is refused elsewhere rather than reinterpreted"
            ),
            Self::Expired => write!(
                formatter,
                "this offset is older than what is still held: records between it and the oldest available one have left on the retention schedule"
            ),
        }
    }
}

impl std::error::Error for OffsetError {}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    fn tenant(zone: &str) -> Scope {
        Scope::Tenant {
            zone: zone.to_owned(),
            ledger: "main-ledger".to_owned(),
        }
    }

    #[test]
    fn an_offset_round_trips_through_its_own_token() {
        let scope = tenant("acme");
        let offset = Offset {
            scope: scope.key(),
            segment: 42,
            position: 7,
        };

        assert_eq!(
            Offset::decode(&offset.encode(), &scope).expect("it decodes"),
            offset
        );
    }

    #[test]
    fn an_offset_presented_under_another_tenant_is_refused_not_reinterpreted() {
        let token = Offset::beginning(&tenant("acme")).encode();

        assert_eq!(
            Offset::decode(&token, &tenant("other")),
            Err(OffsetError::WrongScope),
            "reinterpreting it would let a reader learn where a neighbour stands"
        );
    }

    #[test]
    fn something_that_is_not_a_token_is_not_read_as_one() {
        assert_eq!(
            Offset::decode("../../etc/passwd", &tenant("acme")),
            Err(OffsetError::Malformed)
        );
    }
}
