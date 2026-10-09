// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The verification bundle (WP-3.4, owner decisions of 2026-10-09; `contracts/cbor/keys-bundle.json`).
//!
//! What a verifier needs to check this Host's signatures without asking the Host again: the
//! identity and its succession chain, every public key its rings published, the bindings that
//! vouch for each set and the revocations, as they stood at one fixed frontier.
//!
//! | Item         | Shape                                                                             |
//! | ------------ | --------------------------------------------------------------------------------- |
//! | `identity`   | {1 type, 2 document, 3 successions [bytes], 4 first_public_key}                   |
//! | `key`        | {1 type, 2 ring, 3 kid, 4 jwk, 5 epoch it was prepublished at, 6 state there}     |
//! | `binding`    | {1 type, 2 ring, 3 epoch, 4 envelope}: the first binding of that epoch            |
//! | `revocation` | {1 type, 2 ring, 3 kid, 4 epoch, 5 at, 6 reason, 7? compromised_at}               |
//! | frontier     | {1 identity_epoch, 2 rings [[ring, epoch, seq, key_set_digest]]}, rings sorted    |
//! | manifest     | {1 host_id, 2 resource, 3 frontier (its bytes), 4 items, 5 bundle_digest}         |
//!
//! The manifest is a COSE_Sign1 [`protected::KEYS_BUNDLE`] under `host.operations`, its `kid` the
//! signing key's. The bundle digest is SHA-256 of `permguard.keys.bundle.v1\n` and every item's
//! SHA-256, in ascending order; the items travel in that order, so a page is a slice of one list.
//!
//! The frontier is fixed when the first page is asked: each ring's epoch, the sequence of its last
//! journal entry and its key-set digest, and the identity epoch. Every later page rebuilds the
//! items from the journal's prefix up to that sequence, so a rotation while a client pages changes
//! nothing it receives. A frontier the Host cannot rebuild — the identity rotated since, a ring or
//! an entry it does not hold — is refused, never answered with other items.
//!
//! Signer manifests of the streams (WP-5.x) and pinned peer rings (WP-4.1) are added by their
//! packages; the resource is bound in the manifest today and every resource receives the Host's
//! rings (owner decision of 2026-10-09).

use std::fmt;
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use sha2::{Digest as _, Sha256};

use permguard_core::domains::protected;
use permguard_core::keys::{Jwk, Sign as _};
use permguard_objects::cbor::Value;
use permguard_objects::cose::Sign1;
use permguard_objects::crypto::suite::Suite;
use permguard_objects::crypto::thumbprint::{self, KeySet};

use super::record::{Binding, State};
use super::ring::{HOST_IDENTITY, HOST_OPERATIONS, REGISTERED, Ring, RingError, suite_of};
use crate::identity::record::{Labelled, RecordError, encode, uint};
use crate::identity::{self, Identity};

/// The most bytes one item takes: the identity's carries up to
/// [`identity::MAX_SUCCESSIONS`] succession records.
pub const MAX_ITEM_BYTES: usize = 512 * 1024;
/// The most items one bundle holds.
pub const MAX_ITEMS: usize = 65_536;
/// The most bytes a frontier takes.
pub const MAX_FRONTIER_BYTES: usize = 4096;
/// The most bytes a manifest envelope takes.
pub const MAX_MANIFEST_BYTES: usize = 8192;
/// The items of a page when the caller names no limit.
pub const PAGE_DEFAULT: usize = 100;
/// The most items one page carries.
pub const PAGE_MAX: usize = 500;

const IDENTITY: &str = "identity";
const KEY: &str = "key";
const BINDING: &str = "binding";
const REVOCATION: &str = "revocation";

/// Why a bundle was not built or did not verify.
#[derive(Debug)]
pub enum BundleError {
    /// Bytes that are not a bundle of this profile.
    Malformed(String),
    /// The frontier cannot be rebuilt on this Host.
    Unreproducible(String),
    /// The identity is not the one pinned, or its chain does not verify.
    Anchor(String),
    /// An item lies outside the manifest's frontier.
    Outside(String),
    /// A set the bundle needs is not vouched for by a binding of its frontier epoch.
    Unbound(String),
    /// A signature does not verify.
    Signature(String),
    /// The items are not the ones the manifest counts and digests.
    Digest(String),
    /// A ring could not be read.
    Ring(RingError),
}

impl fmt::Display for BundleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(detail) => write!(f, "not a verification bundle: {detail}"),
            Self::Unreproducible(detail) => write!(f, "the frontier cannot be rebuilt: {detail}"),
            Self::Anchor(detail) => write!(f, "the identity is not the pinned one: {detail}"),
            Self::Outside(detail) => write!(f, "outside the bundle's frontier: {detail}"),
            Self::Unbound(detail) => write!(f, "not vouched for by a binding: {detail}"),
            Self::Signature(detail) => write!(f, "a signature does not verify: {detail}"),
            Self::Digest(detail) => write!(f, "the items are not the manifest's: {detail}"),
            Self::Ring(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for BundleError {}

impl From<RecordError> for BundleError {
    fn from(error: RecordError) -> Self {
        Self::Malformed(error.to_string())
    }
}

impl From<RingError> for BundleError {
    fn from(error: RingError) -> Self {
        Self::Ring(error)
    }
}

/// One item of a bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Item {
    /// The identity: its current document, its succession records in order and its epoch-1
    /// public key, what [`identity::verify_published`] walks.
    Identity {
        document: Vec<u8>,
        successions: Vec<Vec<u8>>,
        first_public_key: Vec<u8>,
    },
    /// A public key a ring published, with the epoch its prepublication opened and its state at
    /// the frontier.
    Key {
        ring: String,
        kid: String,
        jwk: String,
        epoch: u64,
        state: State,
    },
    /// The first binding of one epoch of a ring.
    Binding {
        ring: String,
        epoch: u64,
        envelope: Vec<u8>,
    },
    /// A revocation, as the ring's journal holds it.
    Revocation {
        ring: String,
        kid: String,
        epoch: u64,
        at: u64,
        reason: String,
        compromised_at: Option<u64>,
    },
}

impl Item {
    pub fn encode(&self) -> Result<Vec<u8>, RecordError> {
        let text = |value: &str| Value::Text(value.to_owned());
        match self {
            Self::Identity {
                document,
                successions,
                first_public_key,
            } => encode(vec![
                (Value::Int(1), text(IDENTITY)),
                (Value::Int(2), Value::Bytes(document.clone())),
                (
                    Value::Int(3),
                    Value::Array(successions.iter().cloned().map(Value::Bytes).collect()),
                ),
                (Value::Int(4), Value::Bytes(first_public_key.clone())),
            ]),
            Self::Key {
                ring,
                kid,
                jwk,
                epoch,
                state,
            } => encode(vec![
                (Value::Int(1), text(KEY)),
                (Value::Int(2), text(ring)),
                (Value::Int(3), text(kid)),
                (Value::Int(4), text(jwk)),
                (Value::Int(5), uint(*epoch)?),
                (Value::Int(6), text(state.as_str())),
            ]),
            Self::Binding {
                ring,
                epoch,
                envelope,
            } => encode(vec![
                (Value::Int(1), text(BINDING)),
                (Value::Int(2), text(ring)),
                (Value::Int(3), uint(*epoch)?),
                (Value::Int(4), Value::Bytes(envelope.clone())),
            ]),
            Self::Revocation {
                ring,
                kid,
                epoch,
                at,
                reason,
                compromised_at,
            } => {
                let mut pairs = vec![
                    (Value::Int(1), text(REVOCATION)),
                    (Value::Int(2), text(ring)),
                    (Value::Int(3), text(kid)),
                    (Value::Int(4), uint(*epoch)?),
                    (Value::Int(5), uint(*at)?),
                    (Value::Int(6), text(reason)),
                ];
                if let Some(compromised_at) = compromised_at {
                    pairs.push((Value::Int(7), uint(*compromised_at)?));
                }
                encode(pairs)
            }
        }
    }

    /// Reads one item, refusing a type, a label or a value this profile does not define.
    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        if bytes.len() > MAX_ITEM_BYTES {
            return Err(RecordError(format!(
                "a bundle item takes at most {MAX_ITEM_BYTES} bytes"
            )));
        }
        let mut map = Labelled::read(bytes, "a bundle item")?;
        let item = match map.text(1)?.as_str() {
            IDENTITY => {
                let document = map.bytes(2)?;
                let successions = map.byte_strings(3)?;
                if successions.len() > identity::MAX_SUCCESSIONS {
                    return Err(RecordError(
                        "more succession records than any identity carries".to_owned(),
                    ));
                }
                Self::Identity {
                    document,
                    successions,
                    first_public_key: map.bytes(4)?,
                }
            }
            KEY => Self::Key {
                ring: map.text(2)?,
                kid: map.text(3)?,
                jwk: map.text(4)?,
                epoch: map.uint(5)?,
                state: State::parse(&map.text(6)?).ok_or_else(|| {
                    RecordError("a key's state is not one a ring names".to_owned())
                })?,
            },
            BINDING => Self::Binding {
                ring: map.text(2)?,
                epoch: map.uint(3)?,
                envelope: map.bytes(4)?,
            },
            REVOCATION => Self::Revocation {
                ring: map.text(2)?,
                kid: map.text(3)?,
                epoch: map.uint(4)?,
                at: map.uint(5)?,
                reason: map.text(6)?,
                compromised_at: map.optional_uint(7)?,
            },
            other => {
                return Err(RecordError(format!("`{other}` is not a bundle item type")));
            }
        };
        map.finish()?;
        Ok(item)
    }
}

/// Where one ring stood when the frontier was fixed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RingFrontier {
    pub ring: String,
    pub epoch: u64,
    /// The sequence of its last journal entry.
    pub seq: u64,
    pub key_set_digest: [u8; 32],
}

/// The frontier a bundle is fixed at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frontier {
    pub identity_epoch: u64,
    /// Sorted by ring, each ring once.
    pub rings: Vec<RingFrontier>,
}

impl Frontier {
    pub fn encode(&self) -> Result<Vec<u8>, RecordError> {
        let mut rings = Vec::new();
        for ring in &self.rings {
            rings.push(Value::Array(vec![
                Value::Text(ring.ring.clone()),
                uint(ring.epoch)?,
                uint(ring.seq)?,
                Value::Bytes(ring.key_set_digest.to_vec()),
            ]));
        }
        encode(vec![
            (Value::Int(1), uint(self.identity_epoch)?),
            (Value::Int(2), Value::Array(rings)),
        ])
    }

    /// Reads a frontier: rings this build registers, other than the identity's, sorted and
    /// unique, every epoch and sequence from 1.
    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        if bytes.len() > MAX_FRONTIER_BYTES {
            return Err(RecordError(format!(
                "a frontier takes at most {MAX_FRONTIER_BYTES} bytes"
            )));
        }
        let refused = |detail: &str| RecordError(format!("a frontier: {detail}"));
        let mut map = Labelled::read(bytes, "a frontier")?;
        let identity_epoch = map.uint(1)?;
        let mut rings: Vec<RingFrontier> = Vec::new();
        for value in map.array(2)? {
            let Value::Array(parts) = value else {
                return Err(refused("a ring is an array"));
            };
            let [
                Value::Text(ring),
                Value::Int(epoch),
                Value::Int(seq),
                Value::Bytes(digest),
            ] = parts.as_slice()
            else {
                return Err(refused("a ring is [ring, epoch, seq, key_set_digest]"));
            };
            let epoch = u64::try_from(*epoch).map_err(|_| refused("a negative epoch"))?;
            let seq = u64::try_from(*seq).map_err(|_| refused("a negative sequence"))?;
            let key_set_digest: [u8; 32] = digest
                .as_slice()
                .try_into()
                .map_err(|_| refused("a key-set digest is 32 bytes"))?;
            if !REGISTERED.contains(&ring.as_str()) || ring == HOST_IDENTITY {
                return Err(refused("a ring this build does not register"));
            }
            if epoch == 0 || seq == 0 {
                return Err(refused("epochs and sequences start at 1"));
            }
            if rings.last().is_some_and(|last| last.ring >= *ring) {
                return Err(refused("rings are sorted, each once"));
            }
            rings.push(RingFrontier {
                ring: ring.clone(),
                epoch,
                seq,
                key_set_digest,
            });
        }
        map.finish()?;
        if identity_epoch == 0 {
            return Err(refused("the identity epoch starts at 1"));
        }
        Ok(Self {
            identity_epoch,
            rings,
        })
    }

    fn ring(&self, ring: &str) -> Option<&RingFrontier> {
        self.rings.iter().find(|held| held.ring == ring)
    }
}

/// What the manifest signs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    pub host_id: [u8; 16],
    /// The resource the bundle was asked for, in the Host API's grammar.
    pub resource: String,
    pub frontier: Frontier,
    /// How many items the bundle holds.
    pub items: u64,
    pub bundle_digest: [u8; 32],
    /// When the first page fixed the frontier, seconds since the epoch, UTC.
    pub issued_at: u64,
}

impl Manifest {
    pub fn encode(&self) -> Result<Vec<u8>, RecordError> {
        encode(vec![
            (Value::Int(1), Value::Bytes(self.host_id.to_vec())),
            (Value::Int(2), Value::Text(self.resource.clone())),
            (Value::Int(3), Value::Bytes(self.frontier.encode()?)),
            (Value::Int(4), uint(self.items)?),
            (Value::Int(5), Value::Bytes(self.bundle_digest.to_vec())),
            (Value::Int(6), uint(self.issued_at)?),
        ])
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        if bytes.len() > MAX_MANIFEST_BYTES {
            return Err(RecordError(format!(
                "a bundle manifest takes at most {MAX_MANIFEST_BYTES} bytes"
            )));
        }
        let mut map = Labelled::read(bytes, "a bundle manifest")?;
        let manifest = Self {
            host_id: map.id(1)?,
            resource: map.text(2)?,
            frontier: Frontier::decode(&map.bytes(3)?)?,
            items: map.uint(4)?,
            bundle_digest: map.fixed(5)?,
            issued_at: map.uint(6)?,
        };
        map.finish()?;
        Ok(manifest)
    }
}

/// The SHA-256 of one item's bytes.
pub fn item_digest(item: &[u8]) -> [u8; 32] {
    Sha256::digest(item).into()
}

/// The bundle digest of items whose digests are `digests`, in ascending order.
pub fn bundle_digest(digests: &[[u8; 32]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(protected::KEYS_BUNDLE.as_bytes());
    hasher.update(b"\n");
    for digest in digests {
        hasher.update(digest);
    }
    hasher.finalize().into()
}

/// What a bundle is built from: the open identity and the Host's rings.
pub struct Source<'a> {
    pub identity: &'a Identity,
    pub rings: &'a [Arc<Ring>],
}

/// A bundle built at one frontier: its items in digest order and its manifest, unsigned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Built {
    pub items: Vec<Vec<u8>>,
    pub manifest: Manifest,
    /// The `host.operations` key active at the frontier: the only one that signs its manifest.
    pub signer: Option<String>,
}

impl Source<'_> {
    /// Where the identity and every ring holding a key stand now.
    pub fn frontier(&self) -> Result<Frontier, BundleError> {
        let mut rings = Vec::new();
        for ring in self.rings {
            if let Some((epoch, seq, key_set_digest)) = ring.frontier()? {
                rings.push(RingFrontier {
                    ring: ring.id().to_owned(),
                    epoch,
                    seq,
                    key_set_digest,
                });
            }
        }
        rings.sort_by(|left, right| left.ring.cmp(&right.ring));
        Ok(Frontier {
            identity_epoch: self.identity.epoch(),
            rings,
        })
    }

    /// The bundle at `frontier` for `resource`, rebuilt from the journals' prefixes; `issued_at`
    /// is when its first page fixed the frontier.
    pub fn build(
        &self,
        resource: &str,
        frontier: &Frontier,
        issued_at: u64,
    ) -> Result<Built, BundleError> {
        if self.identity.epoch() != frontier.identity_epoch {
            return Err(BundleError::Unreproducible(format!(
                "the identity is at epoch {} and the frontier at {}",
                self.identity.epoch(),
                frontier.identity_epoch
            )));
        }
        let mut signer = None;
        let mut items = vec![Item::Identity {
            document: self.identity.document(),
            successions: self.identity.successions(),
            first_public_key: self.identity.first_public_key().to_vec(),
        }];
        for fixed in &frontier.rings {
            let ring = self
                .rings
                .iter()
                .find(|ring| ring.id() == fixed.ring)
                .ok_or_else(|| {
                    BundleError::Unreproducible(format!("this Host holds no ring `{}`", fixed.ring))
                })?;
            let history = ring.history(fixed.seq).map_err(|error| match error {
                RingError::Refused(detail) => BundleError::Unreproducible(detail),
                other => BundleError::Ring(other),
            })?;
            if history.epoch != fixed.epoch || history.key_set_digest != fixed.key_set_digest {
                return Err(BundleError::Unreproducible(format!(
                    "`{}` at entry {} is not the set the frontier names",
                    fixed.ring, fixed.seq
                )));
            }
            for (epoch, envelope) in ring.kept_bindings(&history)? {
                items.push(Item::Binding {
                    ring: fixed.ring.clone(),
                    epoch,
                    envelope,
                });
            }
            if fixed.ring == HOST_OPERATIONS {
                signer = history
                    .keys
                    .iter()
                    .find(|key| key.state == State::Active)
                    .map(|key| key.kid.clone());
            }
            for key in history.keys {
                items.push(Item::Key {
                    ring: fixed.ring.clone(),
                    kid: key.kid,
                    jwk: key.jwk,
                    epoch: key.epoch,
                    state: key.state,
                });
            }
            for entry in history.revocations {
                items.push(Item::Revocation {
                    ring: fixed.ring.clone(),
                    kid: entry.kid,
                    epoch: entry.epoch,
                    at: entry.at,
                    reason: entry.reason.unwrap_or_default(),
                    compromised_at: entry.compromised_at,
                });
            }
        }
        let mut encoded = Vec::with_capacity(items.len());
        for item in &items {
            let bytes = item.encode()?;
            encoded.push((item_digest(&bytes), bytes));
        }
        encoded.sort_by_key(|(digest, _)| *digest);
        if encoded.len() > MAX_ITEMS {
            return Err(BundleError::Malformed(format!(
                "a bundle holds at most {MAX_ITEMS} items"
            )));
        }
        let digests: Vec<[u8; 32]> = encoded.iter().map(|(digest, _)| *digest).collect();
        Ok(Built {
            manifest: Manifest {
                host_id: self.identity.host_id(),
                resource: resource.to_owned(),
                frontier: frontier.clone(),
                items: encoded.len() as u64,
                bundle_digest: bundle_digest(&digests),
                issued_at,
            },
            items: encoded.into_iter().map(|(_, bytes)| bytes).collect(),
            signer,
        })
    }
}

impl Source<'_> {
    /// The bundle a later page continues: `manifest` is the signed manifest the first page
    /// answered, presented again as the frontier (owner decision of 2026-10-09). The Host checks
    /// it signed it, under the `host.operations` key active at that frontier, for `resource`;
    /// rebuilds the items there; and requires the manifest it would sign to be that one. A
    /// client cannot name a frontier of its own, and every page carries the same bytes.
    pub fn reopen(&self, manifest: &[u8], resource: &str) -> Result<Built, BundleError> {
        if manifest.len() > MAX_MANIFEST_BYTES {
            return Err(BundleError::Malformed(format!(
                "a manifest envelope takes at most {MAX_MANIFEST_BYTES} bytes"
            )));
        }
        let envelope =
            Sign1::decode(manifest).map_err(|error| BundleError::Malformed(error.to_string()))?;
        let claimed = Manifest::decode(envelope.payload_unverified())?;
        if claimed.resource != resource {
            return Err(BundleError::Malformed(format!(
                "the frontier was issued for `{}`",
                claimed.resource
            )));
        }
        let built = self.build(resource, &claimed.frontier, claimed.issued_at)?;
        let signer = built.signer.clone().ok_or_else(|| {
            BundleError::Unreproducible(format!(
                "no `{HOST_OPERATIONS}` key is active at that frontier"
            ))
        })?;
        let header = envelope
            .header()
            .map_err(|error| BundleError::Malformed(error.to_string()))?;
        if header.kid != signer.as_bytes() {
            return Err(BundleError::Signature(
                "the frontier is not signed by the key active there".to_owned(),
            ));
        }
        let (suite, public_key) = built
            .items
            .iter()
            .find_map(|bytes| match Item::decode(bytes) {
                Ok(Item::Key { ring, kid, jwk, .. })
                    if ring == HOST_OPERATIONS && kid == signer =>
                {
                    serde_json::from_str::<Jwk>(&jwk)
                        .ok()
                        .and_then(|jwk| public_of(&jwk))
                }
                _ => None,
            })
            .ok_or_else(|| {
                BundleError::Unreproducible(format!("`{signer}` is not held at that frontier"))
            })?;
        envelope
            .verify(suite, &public_key, protected::KEYS_BUNDLE)
            .map_err(|error| BundleError::Signature(error.to_string()))?;
        if built.manifest != claimed {
            return Err(BundleError::Unreproducible(
                "the bundle at that frontier is no longer the one it signed".to_owned(),
            ));
        }
        Ok(built)
    }
}

/// Signs `built`'s manifest under `operations`, the `host.operations` ring, with the key active at
/// its frontier: once another key signs, the frontier is no longer one this Host signs.
pub fn sign(operations: &Ring, built: &Built) -> Result<Vec<u8>, BundleError> {
    let kid = operations
        .active_key_id()
        .map_err(|error| BundleError::Signature(error.to_string()))?;
    if built.signer.as_deref() != Some(kid.as_str()) {
        return Err(BundleError::Unreproducible(
            "the `host.operations` key active at the frontier no longer signs".to_owned(),
        ));
    }
    let manifest = &built.manifest;
    let envelope = Sign1::sign_with(
        operations.suite(),
        protected::KEYS_BUNDLE,
        kid.as_str().as_bytes(),
        manifest.encode()?,
        |bytes| {
            let signature = operations.sign(bytes).map_err(|error| error.to_string())?;
            if signature.key_id() != &kid {
                return Err("the signing key rotated mid-signature".to_owned());
            }
            Ok(signature.bytes().to_vec())
        },
    )
    .map_err(|error| BundleError::Signature(error.to_string()))?;
    envelope
        .encode()
        .map_err(|error| BundleError::Malformed(error.to_string()))
}

/// A bundle that verified offline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    pub manifest: Manifest,
    /// The identity's chain, from the pinned first key.
    pub identity: identity::Verified,
    pub items: Vec<Item>,
}

/// The suite and public key bytes a JWK names.
fn public_of(jwk: &Jwk) -> Option<(Suite, Vec<u8>)> {
    let suite = suite_of(jwk)?;
    let mut bytes = B64.decode(&jwk.x).ok()?;
    if let Some(y) = jwk.y.as_deref() {
        bytes.insert(0, 0x04);
        bytes.extend(B64.decode(y).ok()?);
    }
    (bytes.len() == suite.public_key_len()).then_some((suite, bytes))
}

/// Verifies a bundle offline for `resource`, from nothing but the identity's first fingerprint
/// `pin` — what `permguard host identity provision` printed and the operator kept (owner decisions
/// of 2026-10-09):
///
/// 1. the identity chain from its first key, its first fingerprint the pin and its epoch the
///    frontier's;
/// 2. every item inside the frontier, every binding under the identity key its `kid` names;
/// 3. every ring of the frontier bound at its frontier epoch by the **current** identity key, over
///    the set its published keys give, and no binding of that epoch over another set: a superseded
///    identity key vouches for nothing a verifier relies on;
/// 4. the manifest under the `host.operations` key active at the frontier, for `resource`;
/// 5. the items, the manifest's count and digest.
///
/// An item outside the frontier is refused before anything is digested.
pub fn verify(
    manifest: &[u8],
    items: &[Vec<u8>],
    pin: &str,
    resource: &str,
) -> Result<Verified, BundleError> {
    if manifest.len() > MAX_MANIFEST_BYTES {
        return Err(BundleError::Malformed(format!(
            "a manifest envelope takes at most {MAX_MANIFEST_BYTES} bytes"
        )));
    }
    if items.len() > MAX_ITEMS {
        return Err(BundleError::Malformed(format!(
            "a bundle holds at most {MAX_ITEMS} items"
        )));
    }
    let envelope =
        Sign1::decode(manifest).map_err(|error| BundleError::Malformed(error.to_string()))?;
    // Read before its signature only to know the frontier; trusted once the signature verifies.
    let claimed = Manifest::decode(envelope.payload_unverified())?;
    let frontier = &claimed.frontier;
    let decoded: Vec<Item> = items
        .iter()
        .map(|bytes| Item::decode(bytes))
        .collect::<Result<_, _>>()?;

    // 1. The identity, from the pin.
    let mut identities = decoded.iter().filter_map(|item| match item {
        Item::Identity {
            document,
            successions,
            first_public_key,
        } => Some((document, successions, first_public_key)),
        _ => None,
    });
    let (document, successions, first_public_key) = identities
        .next()
        .ok_or_else(|| BundleError::Anchor("the bundle carries no identity".to_owned()))?;
    if identities.next().is_some() {
        return Err(BundleError::Malformed("two identities".to_owned()));
    }
    let chain = identity::verify_published(document, successions, first_public_key)
        .map_err(|error| BundleError::Anchor(error.to_string()))?;
    if chain.first_fingerprint() != pin {
        return Err(BundleError::Anchor(
            "the identity's first fingerprint is not the pinned one".to_owned(),
        ));
    }
    if chain.host_id != claimed.host_id {
        return Err(BundleError::Anchor(
            "the manifest names another Host than the identity".to_owned(),
        ));
    }
    if chain.epoch != frontier.identity_epoch {
        return Err(BundleError::Outside(format!(
            "the identity is at epoch {} and the frontier at {}",
            chain.epoch, frontier.identity_epoch
        )));
    }

    // 2. Every item inside the frontier, every binding under the identity.
    let ring_of = |ring: &str, what: &str| {
        frontier.ring(ring).ok_or_else(|| {
            BundleError::Outside(format!(
                "{what} of `{ring}`, a ring the frontier does not name"
            ))
        })
    };
    let mut bindings: Vec<(String, Binding, usize)> = Vec::new();
    for item in &decoded {
        match item {
            Item::Identity { .. } => {}
            Item::Key {
                ring, kid, epoch, ..
            } => {
                let fixed = ring_of(ring, "a key")?;
                if *epoch > fixed.epoch {
                    return Err(BundleError::Outside(format!(
                        "`{kid}` was prepublished at epoch {epoch}, after the frontier's {}",
                        fixed.epoch
                    )));
                }
                if thumbprint::split_kid(kid).map(|(owner, _)| owner) != Some(ring.as_str()) {
                    return Err(BundleError::Malformed(format!(
                        "`{kid}` is not a key of `{ring}`"
                    )));
                }
            }
            Item::Revocation {
                ring, kid, epoch, ..
            } => {
                let fixed = ring_of(ring, "a revocation")?;
                if *epoch > fixed.epoch {
                    return Err(BundleError::Outside(format!(
                        "the revocation of `{kid}` at epoch {epoch} is after the frontier's {}",
                        fixed.epoch
                    )));
                }
                if thumbprint::split_kid(kid).map(|(owner, _)| owner) != Some(ring.as_str()) {
                    return Err(BundleError::Malformed(format!(
                        "`{kid}` is not a key of `{ring}`"
                    )));
                }
            }
            Item::Binding {
                ring,
                epoch,
                envelope,
            } => {
                let fixed = ring_of(ring, "a binding")?;
                if *epoch > fixed.epoch {
                    return Err(BundleError::Outside(format!(
                        "the binding of `{ring}` epoch {epoch} is after the frontier's {}",
                        fixed.epoch
                    )));
                }
                let (binding, signer) = verify_kept_binding(envelope, &chain, ring, *epoch)?;
                bindings.push((ring.clone(), binding, signer));
            }
        }
    }

    // 3. Each ring's frontier set: its published keys digest to it, and the current identity key
    // binds it.
    let mut operations_keys: Vec<(String, State, Suite, Vec<u8>)> = Vec::new();
    for fixed in &frontier.rings {
        let mut suite = None;
        let mut thumbprints = Vec::new();
        for item in &decoded {
            let Item::Key {
                ring,
                kid,
                jwk,
                state,
                ..
            } = item
            else {
                continue;
            };
            if ring != &fixed.ring {
                continue;
            }
            let jwk: Jwk = serde_json::from_str(jwk)
                .map_err(|error| BundleError::Malformed(format!("the jwk of `{kid}`: {error}")))?;
            let (held, public_key) = public_of(&jwk).ok_or_else(|| {
                BundleError::Malformed(format!("the jwk of `{kid}` is no key of a suite"))
            })?;
            let named = thumbprint::split_kid(kid).map(|(_, thumbprint)| thumbprint);
            if thumbprint::jwk_thumbprint_of(&jwk).as_deref() != named {
                return Err(BundleError::Malformed(format!(
                    "`{kid}` does not name the key its jwk holds"
                )));
            }
            if suite.is_some_and(|suite| suite != held) {
                return Err(BundleError::Malformed(format!(
                    "`{}` mixes suites",
                    fixed.ring
                )));
            }
            suite = Some(held);
            if state.is_published()
                && let Some(thumbprint) = named
            {
                thumbprints.push(thumbprint.to_owned());
            }
            if ring == HOST_OPERATIONS {
                operations_keys.push((kid.clone(), *state, held, public_key));
            }
        }
        let suite = suite.ok_or_else(|| {
            BundleError::Malformed(format!("the bundle carries no key of `{}`", fixed.ring))
        })?;
        let refs: Vec<&str> = thumbprints.iter().map(String::as_str).collect();
        let digest = KeySet::new(&fixed.ring, fixed.epoch, suite, &refs)
            .and_then(|set| set.digest())
            .map_err(|error| BundleError::Malformed(error.to_string()))?;
        if digest != fixed.key_set_digest {
            return Err(BundleError::Digest(format!(
                "the published keys of `{}` are not the frontier's set",
                fixed.ring
            )));
        }
        let of_epoch = bindings
            .iter()
            .filter(|(ring, binding, _)| ring == &fixed.ring && binding.epoch == fixed.epoch);
        let mut bound = false;
        for (_, binding, signer) in of_epoch {
            if binding.key_set_digest != fixed.key_set_digest {
                return Err(BundleError::Signature(format!(
                    "a binding of `{}` epoch {} vouches for another set: equivocation",
                    fixed.ring, fixed.epoch
                )));
            }
            bound |= *signer == chain.epoch as usize;
        }
        if !bound {
            return Err(BundleError::Unbound(format!(
                "`{}` at epoch {}: no binding by the current identity key",
                fixed.ring, fixed.epoch
            )));
        }
    }

    // 4. The manifest, under the `host.operations` key active at the frontier.
    if frontier.ring(HOST_OPERATIONS).is_none() {
        return Err(BundleError::Unbound(format!(
            "`{HOST_OPERATIONS}`, which signs the manifest, is not in the frontier"
        )));
    }
    let header = envelope
        .header()
        .map_err(|error| BundleError::Malformed(error.to_string()))?;
    let signer = String::from_utf8(header.kid)
        .map_err(|_| BundleError::Malformed("the manifest's kid is not text".to_owned()))?;
    let (suite, public_key) = operations_keys
        .iter()
        .find(|(kid, state, ..)| *kid == signer && *state == State::Active)
        .map(|(_, _, suite, public_key)| (*suite, public_key.clone()))
        .ok_or_else(|| {
            BundleError::Signature(format!(
                "`{signer}` is not the `{HOST_OPERATIONS}` key active at the frontier"
            ))
        })?;
    let payload = envelope
        .verify(suite, &public_key, protected::KEYS_BUNDLE)
        .map_err(|error| BundleError::Signature(error.to_string()))?;
    let manifest = Manifest::decode(payload)?;
    if manifest.resource != resource {
        return Err(BundleError::Anchor(format!(
            "the bundle covers `{}`, not `{resource}`",
            manifest.resource
        )));
    }

    // 5. The items are the manifest's.
    let mut digests: Vec<[u8; 32]> = items.iter().map(|bytes| item_digest(bytes)).collect();
    digests.sort_unstable();
    if digests.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(BundleError::Digest("an item appears twice".to_owned()));
    }
    if digests.len() as u64 != manifest.items || bundle_digest(&digests) != manifest.bundle_digest {
        return Err(BundleError::Digest(format!(
            "{} items whose digest is not the manifest's {} items",
            digests.len(),
            manifest.items
        )));
    }
    Ok(Verified {
        manifest,
        identity: chain,
        items: decoded,
    })
}

/// A kept binding, verified under the identity key of the epoch its `kid` names, for `ring` at
/// `epoch`, with that identity epoch. Its validity window is not checked: a bundle verifies
/// evidence after the fact. Which identity epoch signed it decides what it may vouch for: only
/// the current key binds a frontier set.
fn verify_kept_binding(
    envelope: &[u8],
    chain: &identity::Verified,
    ring: &str,
    epoch: u64,
) -> Result<(Binding, usize), BundleError> {
    if envelope.len() > super::ring::MAX_BINDING_ENVELOPE_BYTES {
        return Err(BundleError::Malformed(
            "a binding envelope is too long".to_owned(),
        ));
    }
    let sign1 =
        Sign1::decode(envelope).map_err(|error| BundleError::Malformed(error.to_string()))?;
    let header = sign1
        .header()
        .map_err(|error| BundleError::Malformed(error.to_string()))?;
    let signer_epoch = std::str::from_utf8(&header.kid)
        .ok()
        .filter(|text| !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit()))
        .filter(|text| !text.starts_with('0'))
        .and_then(|text| text.parse::<usize>().ok())
        .filter(|held| *held >= 1 && *held <= chain.public_keys.len())
        .ok_or_else(|| {
            BundleError::Signature(format!(
                "the binding of `{ring}` epoch {epoch} names no identity epoch of the chain"
            ))
        })?;
    let payload = sign1
        .verify(
            chain.suite,
            &chain.public_keys[signer_epoch - 1],
            protected::HOST_RING_BINDING,
        )
        .map_err(|error| {
            BundleError::Signature(format!("the binding of `{ring}` epoch {epoch}: {error}"))
        })?;
    let binding = Binding::decode(payload)?;
    if binding.host_id != chain.host_id || binding.ring != ring || binding.epoch != epoch {
        return Err(BundleError::Signature(format!(
            "the binding kept for `{ring}` epoch {epoch} binds another Host, ring or epoch"
        )));
    }
    Ok((binding, signer_epoch))
}

#[cfg(test)]
mod tests;
