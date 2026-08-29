// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The offset a consumer keeps: opaque, versioned, and authenticated.
//!
//! # What the MAC is for
//!
//! Not confidentiality — a consumer may know where it stands. What the MAC establishes is that the
//! position it presents is one this server *issued*, for this scope, under these filters, within
//! this export.
//!
//! Without it the token is a base64 JSON object, and every field in it is a lever. A consumer can
//! move itself to a position it was never given; it can take an offset issued for `acme` and
//! present it under `globex` to learn where that tenant's records sit; it can widen a filter after
//! the fact so a cursor bound to one event type starts returning every other type retained for the
//! ledger. Each of those is a read of somebody else's data or of data the caller was not
//! authorized for, reached by editing a string.
//!
//! So every one of those is inside the MAC, and presenting a token under a different scope, a
//! different filter set or a different export bound is a **stable refusal** rather than a
//! reinterpretation.
//!
//! # Why the key is the server's and rotatable
//!
//! The key never leaves the server and never appears in a token. Rotating it invalidates the
//! outstanding cursors, which is a real cost — so a store keeps the previous key for as long as it
//! wants outstanding cursors to keep working, and this verifies against any of the keys it is
//! given while always issuing under the first.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::frontier::Frontier;

/// The cursor format this build writes.
pub const VERSION: u32 = 1;

/// The shortest key this will authenticate with.
///
/// A short key is a key an attacker can search. Thirty-two bytes is what the rest of this codebase
/// requires of a MAC key, and requiring it here too means a deployment configures one discipline.
pub const MIN_KEY_BYTES: usize = 32;

/// Where a consumer stands inside one segmented stream.
///
/// The two numbers are an implementation detail of how a store rolls its files, which is exactly
/// why they are not the API: they travel inside an authenticated token, and a consumer that
/// decoded one would depend on a layout the store is free to change.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Position {
    /// The first sequence of the segment being read.
    pub segment: u64,
    /// How many records of that segment have been returned.
    pub offset: u64,
}

/// What a cursor stands for, before it is signed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cursor {
    /// The cursor format.
    pub v: u32,
    /// Which API family issued it — the event log, the decision log.
    ///
    /// Inside the MAC because the two stores hold different evidence under different domains, and
    /// a cursor that crossed between them would be a position in one stream presented as a
    /// position in the other.
    pub api: String,
    /// The scope it was issued for, as that store names one.
    pub scope: String,
    /// The digest of the normalized filter set it was issued under.
    ///
    /// A digest rather than the filters themselves, so the token stays short whatever a caller
    /// filtered on — and so that changing a filter is detected rather than described.
    pub filters: String,
    /// The export bound this cursor belongs to, when it belongs to one.
    ///
    /// A tail has none. An export captures the first page's high watermark and presents it on
    /// every page after, and this is what stops a caller presenting an export's cursor without its
    /// bound and quietly turning a finite read into an endless one.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub until: Option<Frontier>,
    /// Where in each contributing stream the next page begins.
    ///
    /// A map because a merged tenant view reads several producers at once, and one number could
    /// not say where each of them stands.
    pub positions: std::collections::BTreeMap<String, Position>,
    /// How far this cursor has observed — what the next page's `more` is measured against.
    pub frontier: Frontier,
}

/// The keys a store authenticates cursors with.
///
/// The first is what new cursors are issued under; the rest are accepted, which is what makes a
/// rotation something a deployment can do without invalidating every consumer's position at once.
#[derive(Clone)]
pub struct CursorKey {
    keys: Vec<Vec<u8>>,
}

impl std::fmt::Debug for CursorKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the material. A key in a log line is a key in a log aggregator.
        formatter
            .debug_struct("CursorKey")
            .field("keys", &self.keys.len())
            .finish()
    }
}

impl CursorKey {
    /// The key new cursors are issued under, plus any older ones still accepted.
    pub fn new(issuing: &[u8], accepted: &[&[u8]]) -> Result<Self, CursorError> {
        if issuing.len() < MIN_KEY_BYTES {
            return Err(CursorError::KeyTooShort);
        }
        let mut keys = vec![issuing.to_vec()];
        for held in accepted {
            if held.len() < MIN_KEY_BYTES {
                return Err(CursorError::KeyTooShort);
            }
            keys.push((*held).to_vec());
        }

        Ok(Self { keys })
    }

    fn issuing(&self) -> &[u8] {
        self.keys.first().map(Vec::as_slice).unwrap_or_default()
    }

    fn tag(key: &[u8], body: &[u8]) -> Vec<u8> {
        let mut mac = match Hmac::<Sha256>::new_from_slice(key) {
            Ok(mac) => mac,
            // Unreachable: `Hmac` accepts any key length, and the constructor already refused a
            // short one. Answering with an empty tag rather than panicking keeps a malformed key
            // from taking the process down, and an empty tag verifies against nothing.
            Err(_) => return Vec::new(),
        };
        mac.update(body);

        mac.finalize().into_bytes().to_vec()
    }
}

/// The signed form: what a consumer holds.
#[derive(Debug, Serialize, Deserialize)]
struct Sealed {
    /// The cursor's JSON, base64url without padding.
    c: String,
    /// The MAC over it, base64url without padding.
    m: String,
}

impl Cursor {
    /// A cursor at the beginning of `scope`, under these filters.
    pub fn beginning(api: &str, scope: &str, filters: &str, until: Option<Frontier>) -> Self {
        Self {
            v: VERSION,
            api: api.to_owned(),
            scope: scope.to_owned(),
            filters: filters.to_owned(),
            until,
            positions: std::collections::BTreeMap::new(),
            frontier: Frontier::empty(),
        }
    }

    /// Where the next page of one stream begins.
    pub fn position(&self, stream: &str) -> Position {
        self.positions.get(stream).copied().unwrap_or_default()
    }

    /// Records where the next page of one stream begins.
    pub fn advance(&mut self, stream: &str, position: Position) {
        self.positions.insert(stream.to_owned(), position);
    }

    /// The opaque token a consumer keeps.
    pub fn seal(&self, key: &CursorKey) -> Result<String, CursorError> {
        let body = serde_json::to_vec(self).map_err(|_| CursorError::Malformed)?;
        let encoded = B64.encode(&body);
        let tag = CursorKey::tag(key.issuing(), encoded.as_bytes());
        let sealed = Sealed {
            c: encoded,
            m: B64.encode(tag),
        };
        let bytes = serde_json::to_vec(&sealed).map_err(|_| CursorError::Malformed)?;

        Ok(B64.encode(bytes))
    }

    /// Reads a token, and refuses one this server did not issue for exactly this read.
    ///
    /// The MAC is checked **before** the body is trusted for anything, and the four bindings are
    /// checked after — so a token that was tampered with is `Forged`, and one that was issued for
    /// a different tenant or filter set is refused by which binding it violates. A caller learns
    /// that its cursor does not belong here; it does not learn anything about what is here.
    pub fn open(
        token: &str,
        key: &CursorKey,
        api: &str,
        scope: &str,
        filters: &str,
    ) -> Result<Self, CursorError> {
        let outer = B64.decode(token).map_err(|_| CursorError::Malformed)?;
        let sealed: Sealed = serde_json::from_slice(&outer).map_err(|_| CursorError::Malformed)?;
        let presented = B64.decode(&sealed.m).map_err(|_| CursorError::Malformed)?;

        // Every accepted key, so a rotation does not invalidate outstanding cursors at once.
        let authentic = key
            .keys
            .iter()
            .any(|held| constant_time_eq(&CursorKey::tag(held, sealed.c.as_bytes()), &presented));
        if !authentic {
            return Err(CursorError::Forged);
        }

        let body = B64.decode(&sealed.c).map_err(|_| CursorError::Malformed)?;
        let cursor: Self = serde_json::from_slice(&body).map_err(|_| CursorError::Malformed)?;
        if cursor.v != VERSION {
            return Err(CursorError::WrongVersion { found: cursor.v });
        }
        if cursor.api != api {
            return Err(CursorError::WrongApi);
        }
        if cursor.scope != scope {
            return Err(CursorError::WrongScope);
        }
        if cursor.filters != filters {
            return Err(CursorError::WrongFilters);
        }

        Ok(cursor)
    }
}

/// The digest of a normalized filter set, as a cursor binds it.
///
/// Normalization is the caller's: what reaches here must already be the *canonical* form of the
/// filters, or two spellings of one filter set would produce two cursors that refuse each other.
pub fn filter_digest(normalized: &serde_json::Value) -> String {
    use sha2::Digest as _;

    let mut hasher = Sha256::new();
    hasher.update(b"permguard.stream.filters.v1\n");
    hasher.update(canonical(normalized).as_bytes());
    let digest = hasher.finalize();

    format!("sha256:{}", hex(&digest))
}

/// A value as one string, with object keys in sorted order.
fn canonical(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Object(fields) => {
            let mut sorted: Vec<(&String, &serde_json::Value)> = fields.iter().collect();
            sorted.sort_by(|left, right| left.0.cmp(right.0));
            let inner: Vec<String> = sorted
                .into_iter()
                .map(|(name, held)| format!("{}:{}", name.len(), canonical(held)))
                .collect();

            format!("o{}[{}]", inner.len(), inner.join(","))
        }
        serde_json::Value::Array(items) => {
            let inner: Vec<String> = items.iter().map(canonical).collect();

            format!("a{}[{}]", inner.len(), inner.join(","))
        }
        serde_json::Value::String(held) => format!("s{}:{held}", held.len()),
        other => other.to_string(),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Compares two tags without leaking where they first differ.
fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() || left.is_empty() {
        return false;
    }
    let mut differing = 0u8;
    for (held, other) in left.iter().zip(right) {
        differing |= held ^ other;
    }

    differing == 0
}

/// Why a cursor was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CursorError {
    /// Not a token at all.
    Malformed,
    /// A token this server did not issue, or one that was edited after it did.
    Forged,
    /// A token from a cursor format this build does not read.
    WrongVersion { found: u32 },
    /// A token issued by a different API family.
    WrongApi,
    /// A token issued for a different scope.
    WrongScope,
    /// A token issued under a different filter set.
    WrongFilters,
    /// A key too short to authenticate with.
    KeyTooShort,
}

impl std::fmt::Display for CursorError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed => write!(
                formatter,
                "this is not an offset this store issued: an offset is opaque, and belongs to the \
                 consumer that was given it"
            ),
            Self::Forged => write!(
                formatter,
                "this offset was not issued by this server, or was changed after it was: an \
                 offset carries a signature over the position, the scope and the filters it was \
                 issued for, and an edited one is refused rather than obeyed"
            ),
            Self::WrongVersion { found } => write!(
                formatter,
                "this offset is version {found}, and this build reads version {VERSION}: start \
                 from the beginning, or from the oldest available position"
            ),
            Self::WrongApi => write!(
                formatter,
                "this offset was issued for a different stream: an offset into the decision log is \
                 not a position in the event log, and neither is reinterpreted as the other"
            ),
            Self::WrongScope => write!(
                formatter,
                "this offset was issued for a different scope: an offset is bound to the zone and \
                 ledger that issued it, and is refused elsewhere rather than reinterpreted"
            ),
            Self::WrongFilters => write!(
                formatter,
                "this offset was issued under different filters: an offset binds the filter set it \
                 was issued for, so changing one starts a new read rather than widening this one"
            ),
            Self::KeyTooShort => write!(
                formatter,
                "an offset signing key is at least {MIN_KEY_BYTES} bytes"
            ),
        }
    }
}

impl std::error::Error for CursorError {}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use serde_json::json;

    const API: &str = "permguard.api.events.native.v1alpha1";
    const KEY: &[u8] = b"a-cursor-key-of-at-least-32-bytes!";
    const OTHER: &[u8] = b"another-cursor-key-32-bytes-long!!";

    fn key() -> CursorKey {
        CursorKey::new(KEY, &[]).expect("the key is long enough")
    }

    fn filters() -> String {
        filter_digest(&json!({"event_type": ["permguard.dogwood.event.v1"]}))
    }

    fn sealed() -> String {
        let mut cursor = Cursor::beginning(API, "acme/main", &filters(), None);
        cursor.advance(
            "p1",
            Position {
                segment: 3,
                offset: 7,
            },
        );

        cursor.seal(&key()).expect("it seals")
    }

    #[test]
    fn a_cursor_round_trips_through_its_own_token() {
        let opened =
            Cursor::open(&sealed(), &key(), API, "acme/main", &filters()).expect("it opens");

        assert_eq!(opened.position("p1").segment, 3);
        assert_eq!(opened.position("p1").offset, 7);
        assert_eq!(opened.position("unseen"), Position::default());
    }

    /// The failure the MAC exists to prevent: editing the position you were given.
    #[test]
    fn a_position_a_consumer_edited_is_refused_rather_than_obeyed() {
        let token = sealed();
        let outer = B64.decode(&token).expect("it decodes");
        let mut sealed: Sealed = serde_json::from_slice(&outer).expect("it parses");
        let mut cursor: Cursor =
            serde_json::from_slice(&B64.decode(&sealed.c).expect("it decodes")).expect("parses");

        // The edit: jump to a position this consumer was never issued.
        cursor.advance(
            "p1",
            Position {
                segment: 99,
                offset: 0,
            },
        );
        sealed.c = B64.encode(serde_json::to_vec(&cursor).expect("it serializes"));
        let forged = B64.encode(serde_json::to_vec(&sealed).expect("it serializes"));

        assert_eq!(
            Cursor::open(&forged, &key(), API, "acme/main", &filters()),
            Err(CursorError::Forged)
        );
    }

    /// A neighbour's position, presented under your own scope, is not a read of your neighbour.
    #[test]
    fn a_cursor_presented_under_another_scope_is_a_stable_refusal() {
        assert_eq!(
            Cursor::open(&sealed(), &key(), API, "globex/main", &filters()),
            Err(CursorError::WrongScope)
        );
    }

    /// Widening a filter after the fact starts a new read rather than widening this one.
    #[test]
    fn a_cursor_presented_under_other_filters_is_refused() {
        let widened = filter_digest(&json!({"event_type": []}));

        assert_eq!(
            Cursor::open(&sealed(), &key(), API, "acme/main", &widened),
            Err(CursorError::WrongFilters)
        );
    }

    /// A decision-log offset is not a position in the event log.
    #[test]
    fn a_cursor_from_another_api_family_is_refused() {
        assert_eq!(
            Cursor::open(
                &sealed(),
                &key(),
                "permguard.decisions",
                "acme/main",
                &filters()
            ),
            Err(CursorError::WrongApi)
        );
    }

    #[test]
    fn a_token_signed_with_a_key_this_server_does_not_hold_is_forged() {
        let elsewhere = CursorKey::new(OTHER, &[]).expect("long enough");
        let token = Cursor::beginning(API, "acme/main", &filters(), None)
            .seal(&elsewhere)
            .expect("it seals");

        assert_eq!(
            Cursor::open(&token, &key(), API, "acme/main", &filters()),
            Err(CursorError::Forged)
        );
    }

    /// A rotation keeps outstanding cursors working while new ones are issued under the new key.
    #[test]
    fn a_rotated_key_still_accepts_the_cursors_the_old_one_issued() {
        let before = CursorKey::new(OTHER, &[]).expect("long enough");
        let outstanding = Cursor::beginning(API, "acme/main", &filters(), None)
            .seal(&before)
            .expect("it seals");

        let after = CursorKey::new(KEY, &[OTHER]).expect("long enough");
        assert!(
            Cursor::open(&outstanding, &after, API, "acme/main", &filters()).is_ok(),
            "a consumer mid-export does not lose its place to a rotation"
        );
        // And what it issues now is under the new key alone.
        let fresh = Cursor::beginning(API, "acme/main", &filters(), None)
            .seal(&after)
            .expect("it seals");
        assert!(Cursor::open(&fresh, &before, API, "acme/main", &filters()).is_err());
    }

    #[test]
    fn a_key_too_short_to_authenticate_with_is_refused() {
        assert_eq!(
            CursorKey::new(b"short", &[]).err(),
            Some(CursorError::KeyTooShort)
        );
        assert_eq!(
            CursorKey::new(KEY, &[b"short"]).err(),
            Some(CursorError::KeyTooShort)
        );
    }

    /// Two spellings of one filter set are one filter set.
    #[test]
    fn the_filter_digest_does_not_depend_on_key_order() {
        assert_eq!(
            filter_digest(&json!({"a": 1, "b": ["x", "y"]})),
            filter_digest(&json!({"b": ["x", "y"], "a": 1}))
        );
        // And is injective where a naive concatenation would collide.
        assert_ne!(
            filter_digest(&json!({"ab": "c"})),
            filter_digest(&json!({"a": "bc"}))
        );
    }

    #[test]
    fn a_garbled_token_is_malformed_rather_than_forged() {
        assert_eq!(
            Cursor::open("not-a-token!!", &key(), API, "acme/main", &filters()),
            Err(CursorError::Malformed)
        );
    }
}
