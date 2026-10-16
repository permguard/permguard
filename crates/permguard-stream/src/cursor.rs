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

/// The version 1 cursor format: still read, through `open` and `open_any`; reads issue version 2
/// (`seal_v2`, WP-5.5).
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

    /// Reads a version 1 token, and refuses one this server did not issue for exactly this read;
    /// a read takes either version through `open_any`.
    ///
    /// The MAC is checked **before** the body is trusted for anything, and the four bindings are
    /// checked after — so a token that was tampered with is `Forged`, and one that was issued for
    /// a different tenant or filter set is refused by which binding it violates. A caller learns
    /// that its cursor does not belong here; it does not learn anything about what is here.
    // conformance: boundary
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

/// The prefix of a version 2 token (WP-5.5): what tells it from a version 1 one, which is opened
/// by the version 1 codec alone.
pub const V2_PREFIX: &str = "v2.";

/// How long a version 2 cursor is valid, unless the deployment says otherwise (WP-5.5).
pub const DEFAULT_LIFETIME: std::time::Duration = std::time::Duration::from_secs(24 * 3600);

/// The payload a version 2 token carries, its members as the blueprint names them (WP-5.5, owner
/// decision of 2026-10-16): authenticated with the key `issued_key_id` names, and bounded by
/// `expires_at`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PayloadV2 {
    version: u32,
    api: String,
    concrete_resource: String,
    filter_digest: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    snapshot_frontier: Option<Frontier>,
    positions: std::collections::BTreeMap<String, Position>,
    frontier: Frontier,
    issued_key_id: String,
    expires_at: u64,
}

impl CursorKey {
    /// What names `key` in a version 2 token: the first sixteen hex characters of HMAC-SHA256
    /// under it over the domain alone, one-way, so a rotation's keys are told apart and none is
    /// shown.
    fn key_id(key: &[u8]) -> String {
        let tag = Self::tag(
            key,
            permguard_core::domains::digest::STREAM_CURSOR_V2.as_bytes(),
        );
        hex(&tag[..8.min(tag.len())])
    }

    /// The MAC of a version 2 payload under `key`.
    fn tag_v2(key: &[u8], payload: &[u8]) -> Vec<u8> {
        let mut message = Vec::with_capacity(
            permguard_core::domains::digest::STREAM_CURSOR_V2.len() + payload.len(),
        );
        message.extend_from_slice(permguard_core::domains::digest::STREAM_CURSOR_V2.as_bytes());
        message.extend_from_slice(payload);
        Self::tag(key, &message)
    }
}

impl Cursor {
    /// The version 2 token a consumer keeps (WP-5.5): issued under the first key, valid until
    /// `now` plus `lifetime`, in seconds.
    pub fn seal_v2(
        &self,
        key: &CursorKey,
        now: u64,
        lifetime: std::time::Duration,
    ) -> Result<String, CursorError> {
        let payload = PayloadV2 {
            version: 2,
            api: self.api.clone(),
            concrete_resource: self.scope.clone(),
            filter_digest: self.filters.clone(),
            snapshot_frontier: self.until.clone(),
            positions: self.positions.clone(),
            frontier: self.frontier.clone(),
            issued_key_id: CursorKey::key_id(key.issuing()),
            expires_at: now.saturating_add(lifetime.as_secs()),
        };
        let value = serde_json::to_value(&payload).map_err(|_| CursorError::Malformed)?;
        let canonical = crate::jcs::canonicalize(&value).map_err(|_| CursorError::Malformed)?;
        let tag = CursorKey::tag_v2(key.issuing(), &canonical);

        Ok(format!(
            "{V2_PREFIX}{}.{}",
            B64.encode(&canonical),
            B64.encode(tag)
        ))
    }

    /// Reads a token of either version: a version 2 one by its own rules, anything else by the
    /// version 1 codec, unchanged (WP-5.5).
    // conformance: boundary
    pub fn open_any(
        token: &str,
        key: &CursorKey,
        api: &str,
        scope: &str,
        filters: &str,
        now: u64,
    ) -> Result<Self, CursorError> {
        match token.strip_prefix(V2_PREFIX) {
            Some(rest) => Self::open_v2(rest, key, api, scope, filters, now),
            None => Self::open(token, key, api, scope, filters),
        }
    }

    /// A version 2 token, after its prefix. The key it names, its MAC, its canonical form and its
    /// expiry are checked before any member is trusted; a token of another API, resource or
    /// filter set, an expired one, or one under a key outside the accepted set is `Forged`.
    fn open_v2(
        rest: &str,
        key: &CursorKey,
        api: &str,
        scope: &str,
        filters: &str,
        now: u64,
    ) -> Result<Self, CursorError> {
        let (payload, mac) = rest.split_once('.').ok_or(CursorError::Malformed)?;
        if mac.contains('.') {
            return Err(CursorError::Malformed);
        }
        let payload = B64.decode(payload).map_err(|_| CursorError::Malformed)?;
        let presented = B64.decode(mac).map_err(|_| CursorError::Malformed)?;
        let parsed: PayloadV2 =
            serde_json::from_slice(&payload).map_err(|_| CursorError::Malformed)?;
        // The key the token names, then its MAC under that key alone.
        let held = key
            .keys
            .iter()
            .find(|held| CursorKey::key_id(held) == parsed.issued_key_id)
            .ok_or(CursorError::Forged)?;
        if !constant_time_eq(&CursorKey::tag_v2(held, &payload), &presented) {
            return Err(CursorError::Forged);
        }
        // Authentic: the canonical form the issuer wrote, nothing else.
        let canonical = serde_json::to_value(&parsed)
            .ok()
            .and_then(|value| crate::jcs::canonicalize(&value).ok());
        if canonical.as_deref() != Some(payload.as_slice()) {
            return Err(CursorError::Malformed);
        }
        if parsed.version != 2 {
            return Err(CursorError::WrongVersion {
                found: parsed.version,
            });
        }
        if now >= parsed.expires_at
            || parsed.api != api
            || parsed.concrete_resource != scope
            || parsed.filter_digest != filters
        {
            return Err(CursorError::Forged);
        }
        Ok(Self {
            v: 2,
            api: parsed.api,
            scope: parsed.concrete_resource,
            filters: parsed.filter_digest,
            until: parsed.snapshot_frontier,
            positions: parsed.positions,
            frontier: parsed.frontier,
        })
    }
}

/// The digest of a normalized filter set, as a cursor binds it: SHA-256 over
/// `permguard.stream.filters.v1\n` and the RFC 8785 form of the filters, like every other evidence
/// digest of this product.
///
/// Normalization is the caller's: what reaches here must already be the *canonical* form of the
/// filters, or two spellings of one filter set would produce two cursors that refuse each other.
///
/// The form carries every member's name. An earlier form wrote a name's length but not the name,
/// so `{"type":"x"}` and `{"zone":"x"}` collided and a cursor could be presented under another
/// filter set; a cursor issued under it is refused as `filters differ`, and its reader starts again.
///
/// A value RFC 8785 refuses — an integer beyond double precision; no filter a store builds holds
/// one — is digested over a `0xff` byte and the canonical form of [`crate::jcs::normalized`], which
/// carries such a number as its decimal text: canonical too, so equal filter sets still agree, and
/// distinct from every digest of a canonical form, since `0xff` never occurs in JSON text.
pub fn filter_digest(normalized: &serde_json::Value) -> String {
    use sha2::Digest as _;

    let mut hasher = Sha256::new();
    hasher.update(permguard_core::domains::digest::STREAM_FILTERS.as_bytes());
    match crate::jcs::canonicalize(normalized) {
        Ok(canonical) => hasher.update(&canonical),
        Err(_) => {
            hasher.update([0xff]);
            // Every number of a normalized value is in range, so this always canonicalizes.
            hasher.update(
                crate::jcs::canonicalize(&crate::jcs::normalized(normalized)).unwrap_or_default(),
            );
        }
    }
    let digest = hasher.finalize();

    format!("sha256:{}", hex(&digest))
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
                "this offset is version {found}, and this build reads versions {VERSION} and 2: \
                 start from the beginning, or from the oldest available position"
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

impl CursorError {
    /// The stable code a read answers this refusal with (WP-5.5): `forged` for a token this
    /// server did not issue for exactly this read, `offset_invalid` for one that is not a token
    /// of a version it reads.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Forged | Self::WrongApi | Self::WrongScope | Self::WrongFilters => {
                permguard_core::codes::common::FORGED
            }
            Self::Malformed | Self::WrongVersion { .. } | Self::KeyTooShort => {
                permguard_core::codes::stream::OFFSET_INVALID
            }
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
        // Names of equal length are names, not lengths: the earlier form collided here.
        assert_ne!(
            filter_digest(&json!({"type": "x"})),
            filter_digest(&json!({"zone": "x"}))
        );
        assert_ne!(
            filter_digest(&json!({"subject": "alice"})),
            filter_digest(&json!({"subjekt": "alice"}))
        );
        // A value RFC 8785 refuses still has a digest, and never a canonical form's.
        let beyond = json!({"n": u64::MAX});
        assert_ne!(
            filter_digest(&beyond),
            filter_digest(&json!({"n": "18446744073709551615"}))
        );
        assert_eq!(
            filter_digest(&beyond),
            filter_digest(&json!({"n": u64::MAX}))
        );
    }

    #[test]
    fn a_garbled_token_is_malformed_rather_than_forged() {
        assert_eq!(
            Cursor::open("not-a-token!!", &key(), API, "acme/main", &filters()),
            Err(CursorError::Malformed)
        );
    }

    fn sealed_v2(key: &CursorKey, now: u64) -> String {
        let mut cursor = Cursor::beginning(API, "acme/main", &filters(), None);
        cursor.advance(
            "p1",
            Position {
                segment: 3,
                offset: 7,
            },
        );
        cursor
            .seal_v2(key, now, DEFAULT_LIFETIME)
            .expect("it seals")
    }

    /// WP-5.5: a version 2 token opens for exactly the read it was issued for, until it expires;
    /// one of another API, resource or filter set, an expired one, an edited one, or one under a
    /// key no longer accepted is `Forged`; a version 1 token still opens through its own codec.
    /// WP-5.5: a cursor of another read is `forged`; one that is not a cursor here is
    /// `offset_invalid`.
    #[test]
    fn a_refused_cursor_names_its_code() {
        for (error, code) in [
            (CursorError::Forged, permguard_core::codes::common::FORGED),
            (CursorError::WrongApi, permguard_core::codes::common::FORGED),
            (
                CursorError::WrongScope,
                permguard_core::codes::common::FORGED,
            ),
            (
                CursorError::WrongFilters,
                permguard_core::codes::common::FORGED,
            ),
            (
                CursorError::Malformed,
                permguard_core::codes::stream::OFFSET_INVALID,
            ),
            (
                CursorError::WrongVersion { found: 3 },
                permguard_core::codes::stream::OFFSET_INVALID,
            ),
            (
                CursorError::KeyTooShort,
                permguard_core::codes::stream::OFFSET_INVALID,
            ),
        ] {
            assert_eq!(error.code(), code, "{error:?}");
        }
    }

    /// WP-5.5: a version 2 token whose MAC is authentic is still refused when its payload is not
    /// the canonical form the issuer writes, when it is not version 2, or when it carries a third
    /// part.
    #[test]
    fn an_authentic_version_2_token_is_read_only_in_its_own_form() {
        let now = 1_800_000_000;
        let token = sealed_v2(&key(), now);
        let body = token
            .strip_prefix(V2_PREFIX)
            .and_then(|rest| rest.split('.').next())
            .expect("a payload");
        let payload = B64.decode(body).expect("base64url");
        let signed = |payload: &[u8]| {
            let tag = CursorKey::tag_v2(key().issuing(), payload);
            format!("{V2_PREFIX}{}.{}", B64.encode(payload), B64.encode(tag))
        };
        // Re-signed unchanged: it opens, so the refusals below are the form's.
        assert!(
            Cursor::open_any(&signed(&payload), &key(), API, "acme/main", &filters(), now).is_ok()
        );

        let mut spaced = b" ".to_vec();
        spaced.extend_from_slice(&payload);
        let text = String::from_utf8(payload.clone()).expect("JSON text");
        let version_3 = text.replacen("\"version\":2", "\"version\":3", 1);
        assert_ne!(version_3, text);
        for (case, token, refused) in [
            ("not canonical", signed(&spaced), CursorError::Malformed),
            (
                "version 3",
                signed(version_3.as_bytes()),
                CursorError::WrongVersion { found: 3 },
            ),
            (
                "a third part",
                format!("{}.{}", signed(&payload), B64.encode(b"x")),
                CursorError::Malformed,
            ),
        ] {
            assert_eq!(
                Cursor::open_any(&token, &key(), API, "acme/main", &filters(), now),
                Err(refused),
                "{case}"
            );
        }
    }

    #[test]
    fn a_version_2_cursor_binds_its_read_its_key_and_its_lifetime() {
        let now = 1_800_000_000;
        let token = sealed_v2(&key(), now);
        assert!(token.starts_with(V2_PREFIX));
        let opened =
            Cursor::open_any(&token, &key(), API, "acme/main", &filters(), now).expect("it opens");
        assert_eq!(opened.v, 2);
        assert_eq!(opened.position("p1").segment, 3);
        assert_eq!(opened.position("p1").offset, 7);

        let other_filters = filter_digest(&json!({"event_type": ["other"]}));
        for (case, api, scope, filters, at) in [
            (
                "another API",
                "permguard.api.decisions.native.v1",
                "acme/main",
                filters(),
                now,
            ),
            ("another resource", API, "globex/main", filters(), now),
            ("another filter set", API, "acme/main", other_filters, now),
            (
                "expired",
                API,
                "acme/main",
                filters(),
                now + DEFAULT_LIFETIME.as_secs(),
            ),
        ] {
            assert_eq!(
                Cursor::open_any(&token, &key(), api, scope, &filters, at),
                Err(CursorError::Forged),
                "{case}"
            );
        }

        // An edited payload, its MAC kept: forged.
        let rest = token.strip_prefix(V2_PREFIX).expect("v2");
        let (payload, mac) = rest.split_once('.').expect("two parts");
        let mut bytes = B64.decode(payload).expect("decodes");
        let needle = b"\"segment\":3";
        let at = bytes
            .windows(needle.len())
            .position(|window| window == needle)
            .expect("the segment");
        bytes[at + needle.len() - 1] = b'9';
        let edited = format!("{V2_PREFIX}{}.{mac}", B64.encode(&bytes));
        assert_eq!(
            Cursor::open_any(&edited, &key(), API, "acme/main", &filters(), now),
            Err(CursorError::Forged)
        );

        // A rotation keeps the previous key accepted; once it is gone, its tokens are forged.
        let rotated = CursorKey::new(OTHER, &[KEY]).expect("rotated");
        assert!(Cursor::open_any(&token, &rotated, API, "acme/main", &filters(), now).is_ok());
        let fresh = CursorKey::new(OTHER, &[]).expect("fresh");
        assert_eq!(
            Cursor::open_any(&token, &fresh, API, "acme/main", &filters(), now),
            Err(CursorError::Forged)
        );
        assert!(
            Cursor::open_any(
                &sealed_v2(&rotated, now),
                &rotated,
                API,
                "acme/main",
                &filters(),
                now
            )
            .is_ok(),
            "issued under the new key"
        );

        // Version 1, by its own codec, never expiring.
        assert!(
            Cursor::open_any(&sealed(), &key(), API, "acme/main", &filters(), u64::MAX).is_ok()
        );
        for malformed in ["v2.", "v2.abc", "v2.a.b.c", "v2.!!.!!"] {
            assert_eq!(
                Cursor::open_any(malformed, &key(), API, "acme/main", &filters(), now),
                Err(CursorError::Malformed),
                "{malformed}"
            );
        }
    }
}
