// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! A key ring on the local filesystem.
//!
//! Ed25519 signing keys, one PEM file each, described by a `ring.json` beside them. It is the
//! deployment the user asked for — everything on disk, nothing external — and it is a real one: a
//! mounted volume with `0600` files is what a Kubernetes secret looks like from inside a container.
//!
//! # The lifecycle, and why it is not a swap
//!
//! See [`permguard_core::keys`] for the shape. What this crate adds is the part that has to be right:
//!
//! * a key is created **published**, and signs nothing until `publish_ahead` has passed — long
//!   enough for every verifier holding a cached key set to have refetched it;
//! * the successor is created `publish_ahead` *before* the incumbent is due to stop, so the handover
//!   happens exactly at `rotate_every` rather than `publish_ahead` late;
//! * a key that stops signing stays **retired** and published for `retain`, because a signature made
//!   yesterday has to keep verifying tomorrow;
//! * the very first key of a fresh deployment signs immediately. Publishing ahead protects verifiers
//!   that already cached something, and a deployment starting for the first time has none — waiting
//!   an hour to serve its first request would be downtime bought for nobody.
//!
//! # What serving the key set touches
//!
//! Nothing private. The public half of every key is kept in `ring.json` when the key is created, so
//! answering the key-set endpoint reads one small file and never opens a private key at all.
//!
//! # One writer
//!
//! `ring.json` is written by replacing it, so a reader sees either the old file or the new one and
//! never half of either. Two *processes* maintaining the same directory is a different question, and
//! this does not answer it: they would both be right about what they did and could disagree about
//! what happened. A deployment that shares a volume between replicas should let one of them maintain
//! the ring, or use a key manager backed by something that arbitrates.

mod encoding;
mod service;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, Ed25519KeyPair, KeyPair};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use permguard_core::keys::Result;
use permguard_core::{Jwk, JwkSet, KeyError, KeyId, KeyManager, KeyState, Maintenance, Signature};

pub use service::KeyService;

/// The curve an Edwards key on this ring is on.
const CURVE: &str = "Ed25519";

/// The algorithm an Edwards signature names.
const ALGORITHM: &str = "EdDSA";

/// The curve a NIST key on this ring is on.
const P256_CURVE: &str = "P-256";

/// The algorithm a P-256 signature names.
const P256_ALGORITHM: &str = "ES256";

/// Which signature algorithm a ring produces.
///
/// Both are offered because the choice is rarely about cryptography: Ed25519 is the better default,
/// and ES256 is what hardware answers to. A deployment that keeps its keys in an HSM or a managed
/// KMS usually finds P-256 supported everywhere and Ed25519 nowhere, so a realm that cannot choose
/// is a realm that cannot use its own key custody.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum RingAlgorithm {
    /// EdDSA over Ed25519.
    #[default]
    #[serde(rename = "EdDSA")]
    Ed25519,
    /// ECDSA over P-256 with SHA-256.
    #[serde(rename = "ES256")]
    Es256,
}

impl RingAlgorithm {
    /// The JOSE `alg` a signature by this ring names.
    pub fn jose(self) -> &'static str {
        match self {
            Self::Ed25519 => ALGORITHM,
            Self::Es256 => P256_ALGORITHM,
        }
    }

    /// The curve keys of this ring are on.
    pub fn curve(self) -> &'static str {
        match self {
            Self::Ed25519 => CURVE,
            Self::Es256 => P256_CURVE,
        }
    }

    /// Reads the algorithm a configuration named.
    pub fn parse(value: &str) -> std::result::Result<Self, String> {
        match value {
            "EdDSA" | "Ed25519" => Ok(Self::Ed25519),
            "ES256" | "P-256" => Ok(Self::Es256),
            other => Err(format!(
                "unsupported signing algorithm `{other}`: this build signs with EdDSA or ES256"
            )),
        }
    }
}

/// A private key on the ring, of whichever kind the ring signs with.
enum SigningPair {
    Ed25519(Ed25519KeyPair),
    Es256(Box<EcdsaKeyPair>),
}

impl SigningPair {
    /// Reads a key back from its PKCS#8 document.
    fn from_pkcs8(algorithm: RingAlgorithm, pkcs8: &[u8]) -> Result<Self> {
        match algorithm {
            RingAlgorithm::Ed25519 => Ed25519KeyPair::from_pkcs8(pkcs8)
                .map(Self::Ed25519)
                .map_err(|error| KeyError::backend(format!("reading a key: {error}"))),
            RingAlgorithm::Es256 => EcdsaKeyPair::from_pkcs8(
                &ECDSA_P256_SHA256_FIXED_SIGNING,
                pkcs8,
                &SystemRandom::new(),
            )
            .map(|pair| Self::Es256(Box::new(pair)))
            .map_err(|error| KeyError::backend(format!("reading a key: {error}"))),
        }
    }

    /// The public half, in the encoding its curve publishes.
    fn public_key(&self) -> &[u8] {
        match self {
            Self::Ed25519(pair) => pair.public_key().as_ref(),
            Self::Es256(pair) => pair.public_key().as_ref(),
        }
    }

    fn sign(&self, payload: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::Ed25519(pair) => Ok(pair.sign(payload).as_ref().to_vec()),
            // ECDSA needs entropy per signature; a failure here is the random source, not the key.
            Self::Es256(pair) => pair
                .sign(&SystemRandom::new(), payload)
                .map(|signature| signature.as_ref().to_vec())
                .map_err(|error| KeyError::backend(format!("signing: {error}"))),
        }
    }
}

/// The PEM label PKCS#8 private keys are written under.
const PEM_LABEL: &str = "PRIVATE KEY";

/// The file that says which keys exist and where each of them is in its life.
const RING_FILE: &str = "ring.json";

/// How long each key spends in each state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyPolicy {
    /// How long a key is published before it signs.
    pub publish_ahead: Duration,
    /// How long a key signs before it is replaced.
    pub rotate_every: Duration,
    /// How long a key's private half is kept after it stops signing.
    ///
    /// At this point the private half is deleted: the key will never sign again, and keeping it on
    /// disk only widens the window in which it could leak.
    pub retain: Duration,
    /// How long a key's public half stays in the key set after it stops signing.
    ///
    /// The public half outlives the private one: from `retain` until this elapses the key is
    /// `Archived` — verifiable, but unable to sign. For a ring that seals an audit trail this is the
    /// trail's retention, so a seal keeps verifying for as long as the records it covers are kept.
    /// Treated as at least `retain`: a public half cannot be dropped while its private half is still
    /// on disk.
    pub verify_retain: Duration,
}

/// What time it is, so that a rotation can be tested without waiting for one.
///
/// A trait rather than a parameter because the manager consults the clock from several places, and
/// threading an instant through all of them would let a caller pass two different ones.
pub trait Clock: Send + Sync {
    /// Returns the number of seconds since the Unix epoch.
    fn now(&self) -> u64;
}

/// The clock a deployment uses.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| since.as_secs())
    }
}

/// One key, and where it is in its life.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Entry {
    kid: String,
    state: KeyState,
    /// Which algorithm this key signs with. Absent means the Edwards key this ring used to hold
    /// before it could hold anything else, so an existing ring keeps working untouched.
    #[serde(default)]
    algorithm: RingAlgorithm,
    /// The public half, kept here so that publishing the key set never opens a private key.
    public_key: String,
    created_at: u64,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    activated_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    retired_at: Option<u64>,
}

impl Entry {
    /// Returns this key in the form a client fetches it.
    fn to_jwk(&self) -> Jwk {
        match self.algorithm {
            RingAlgorithm::Ed25519 => Jwk::okp(&self.kid, CURVE, ALGORITHM, &self.public_key),
            RingAlgorithm::Es256 => {
                // A P-256 public key is published as its two coordinates, not as the SEC1 point
                // the key pair hands back.
                let (x, y) = split_p256_point(&self.public_key);
                Jwk::ec(&self.kid, P256_CURVE, P256_ALGORITHM, x, y)
            }
        }
    }
}

/// The state of the whole ring, as it is written to disk.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct Ring {
    /// The format this file is in, so a later version can recognise an earlier one.
    #[serde(default = "one")]
    version: u32,
    #[serde(default)]
    keys: Vec<Entry>,
}

fn one() -> u32 {
    1
}

/// A key ring kept in a directory.
pub struct DirectoryKeyManager {
    directory: PathBuf,
    policy: KeyPolicy,
    clock: Box<dyn Clock>,
    /// Serialises maintenance, so two passes never both decide to publish a successor.
    maintaining: Mutex<()>,
    /// Parsed private keys, kept so signing does not re-read and re-parse a file per signature.
    algorithm: RingAlgorithm,
    signers: Mutex<BTreeMap<String, Arc<SigningPair>>>,
}

impl DirectoryKeyManager {
    /// Builds a manager over the keys in `directory`.
    pub fn new(directory: impl Into<PathBuf>, policy: KeyPolicy) -> Self {
        Self::with_clock(directory, policy, Box::new(SystemClock))
    }

    /// Builds a manager that signs with `algorithm` rather than the default.
    pub fn with_algorithm(
        directory: impl Into<PathBuf>,
        policy: KeyPolicy,
        algorithm: RingAlgorithm,
    ) -> Self {
        Self {
            algorithm,
            ..Self::with_clock(directory, policy, Box::new(SystemClock))
        }
    }

    /// Builds a manager that reads the time from somewhere other than the system.
    pub fn with_clock(
        directory: impl Into<PathBuf>,
        policy: KeyPolicy,
        clock: Box<dyn Clock>,
    ) -> Self {
        Self {
            directory: directory.into(),
            policy,
            clock,
            maintaining: Mutex::new(()),
            algorithm: RingAlgorithm::default(),
            signers: Mutex::new(BTreeMap::new()),
        }
    }

    /// The algorithm this ring signs with.
    pub fn algorithm(&self) -> RingAlgorithm {
        self.algorithm
    }

    /// Returns the directory the ring lives in.
    pub fn directory(&self) -> &Path {
        &self.directory
    }

    /// Returns where the ring file is.
    fn ring_path(&self) -> PathBuf {
        self.directory.join(RING_FILE)
    }

    /// Returns where the private half of `kid` is.
    fn key_path(&self, kid: &str) -> PathBuf {
        self.directory.join(format!("{kid}.pem"))
    }

    /// Reads the ring, treating a directory with nothing in it as an empty one.
    fn read_ring(&self) -> Result<Ring> {
        read_ring_in(&self.directory)
    }

    /// Replaces the ring file, so a reader sees one whole version or the other.
    fn write_ring(&self, ring: &Ring) -> Result<()> {
        let text = serde_json::to_string_pretty(ring)
            .map_err(|error| KeyError::backend(format!("describing the key ring: {error}")))?;

        let path = self.ring_path();
        let staged = path.with_extension("json.tmp");

        fs::write(&staged, text.as_bytes())
            .map_err(|error| KeyError::backend(format!("writing {}: {error}", staged.display())))?;
        fs::rename(&staged, &path)
            .map_err(|error| KeyError::backend(format!("replacing {}: {error}", path.display())))?;

        Ok(())
    }

    /// Creates a key and writes its private half, returning the entry that describes it.
    fn create(&self, now: u64, signing: bool) -> Result<Entry> {
        fs::create_dir_all(&self.directory).map_err(|error| {
            KeyError::backend(format!("creating {}: {error}", self.directory.display()))
        })?;
        restrict(&self.directory, 0o700)?;

        let random = SystemRandom::new();
        let document = match self.algorithm {
            RingAlgorithm::Ed25519 => Ed25519KeyPair::generate_pkcs8(&random)
                .map_err(|error| KeyError::backend(format!("generating a key: {error}")))?,
            RingAlgorithm::Es256 => {
                EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &random)
                    .map_err(|error| KeyError::backend(format!("generating a key: {error}")))?
            }
        };
        let pkcs8 = Zeroizing::new(document.as_ref().to_vec());

        let pair = SigningPair::from_pkcs8(self.algorithm, &pkcs8)?;
        let public_key = encoding::base64url(pair.public_key());
        let kid = thumbprint(self.algorithm, &public_key);

        let path = self.key_path(&kid);
        fs::write(&path, encoding::pem(PEM_LABEL, &pkcs8).as_bytes())
            .map_err(|error| KeyError::backend(format!("writing {}: {error}", path.display())))?;
        restrict(&path, 0o600)?;

        Ok(Entry {
            kid,
            algorithm: self.algorithm,
            state: if signing {
                KeyState::Active
            } else {
                KeyState::Published
            },
            public_key,
            created_at: now,
            activated_at: signing.then_some(now),
            retired_at: None,
        })
    }

    /// Returns the parsed private key for `kid`, reading it the first time it is asked for.
    fn signer(&self, kid: &str) -> Result<Arc<SigningPair>> {
        let mut signers = self
            .signers
            .lock()
            .map_err(|_| KeyError::backend("the key cache lock is poisoned"))?;

        if let Some(pair) = signers.get(kid) {
            return Ok(Arc::clone(pair));
        }

        let path = self.key_path(kid);
        let text = fs::read_to_string(&path).map_err(|error| match error.kind() {
            std::io::ErrorKind::NotFound => KeyError::not_ready(format!(
                "the ring names the key `{kid}` but {} is not there",
                path.display()
            )),
            _ => KeyError::unavailable(error),
        })?;

        let pkcs8 = Zeroizing::new(encoding::from_pem(&text).ok_or_else(|| {
            KeyError::backend(format!("{} is not a PEM private key", path.display()))
        })?);

        // The entry says what kind of key this is: a ring that changed algorithm still verifies and
        // signs with the keys it made before the change, until they age out.
        let algorithm = self
            .read_ring()?
            .keys
            .into_iter()
            .find(|entry| entry.kid == kid)
            .map(|entry| entry.algorithm)
            .unwrap_or(self.algorithm);
        let pair = Arc::new(SigningPair::from_pkcs8(algorithm, &pkcs8)?);

        signers.insert(kid.to_owned(), Arc::clone(&pair));

        Ok(pair)
    }

    /// Forgets a key entirely: the entry, the cached signer, and the file.
    fn forget(&self, kid: &str) -> Result<()> {
        if let Ok(mut signers) = self.signers.lock() {
            signers.remove(kid);
        }

        match fs::remove_file(self.key_path(kid)) {
            Ok(()) => Ok(()),
            // Already gone is the state that was wanted.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(KeyError::backend(format!(
                "removing the key `{kid}`: {error}"
            ))),
        }
    }
}

impl KeyManager for DirectoryKeyManager {
    fn name(&self) -> &'static str {
        "directory"
    }

    fn public_keys(&self) -> Result<Vec<Jwk>> {
        Ok(self.read_ring()?.keys.iter().map(Entry::to_jwk).collect())
    }

    fn active_key_id(&self) -> Result<KeyId> {
        self.read_ring()?
            .keys
            .into_iter()
            .find(|entry| entry.state == KeyState::Active)
            .map(|entry| KeyId::new(entry.kid))
            .ok_or_else(|| {
                KeyError::not_ready(format!(
                    "no key in {} is active yet",
                    self.directory.display()
                ))
            })
    }

    fn sign(&self, payload: &[u8]) -> Result<Signature> {
        let key_id = self.active_key_id()?;
        let signer = self.signer(key_id.as_str())?;
        let algorithm = match signer.as_ref() {
            SigningPair::Ed25519(_) => ALGORITHM,
            SigningPair::Es256(_) => P256_ALGORITHM,
        };

        Ok(Signature::new(key_id, algorithm, signer.sign(payload)?))
    }

    fn maintain(&self) -> Result<Maintenance> {
        let _serialised = self
            .maintaining
            .lock()
            .map_err(|_| KeyError::backend("the key maintenance lock is poisoned"))?;

        let now = self.clock.now();
        let mut ring = self.read_ring()?;
        let mut report = Maintenance::default();

        // A ring with nothing in it: the first key signs at once. See the crate documentation.
        if ring.keys.is_empty() {
            ring.keys.push(self.create(now, true)?);
            report.published += 1;
            report.activated += 1;
        }

        // A realm that changed the algorithm it signs with needs a key of the new kind signing
        // *now*, not at the next rotation. Without this the ring keeps a key of the old kind active
        // and every exchange fails, because what the realm publishes and what it signs with no
        // longer agree — the deployment would look broken rather than migrated. The keys of the old
        // kind stay published, so everything they signed keeps verifying until they age out.
        let active_is_current = ring
            .keys
            .iter()
            .any(|entry| entry.state == KeyState::Active && entry.algorithm == self.algorithm);
        if !active_is_current && !ring.keys.is_empty() {
            for entry in &mut ring.keys {
                if entry.state == KeyState::Active {
                    entry.state = KeyState::Retired;
                    entry.retired_at = Some(now);
                    report.retired += 1;
                }
            }
            ring.keys.push(self.create(now, true)?);
            report.published += 1;
            report.activated += 1;
        }

        // Every published key whose window has passed takes over, oldest first. A loop rather than
        // one step because a process that was stopped for a week comes back with several due, and
        // waking up to a ring that needs three more passes to become correct is not a state worth
        // being able to reach.
        loop {
            let due = ring
                .keys
                .iter()
                .filter(|entry| entry.state == KeyState::Published)
                .filter(|entry| entry.created_at.saturating_add(self.seconds_ahead()) <= now)
                .min_by_key(|entry| entry.created_at)
                .map(|entry| entry.kid.clone());

            let Some(kid) = due else {
                break;
            };

            for entry in &mut ring.keys {
                if entry.state == KeyState::Active {
                    entry.state = KeyState::Retired;
                    entry.retired_at = Some(now);
                    report.retired += 1;
                }
            }

            if let Some(entry) = ring.keys.iter_mut().find(|entry| entry.kid == kid) {
                entry.state = KeyState::Active;
                entry.activated_at = Some(now);
                report.activated += 1;
            }
        }

        // The successor is created before the incumbent is due to stop, so the handover lands on
        // `rotate_every` rather than `publish_ahead` after it.
        let successor_due = ring
            .keys
            .iter()
            .find(|entry| entry.state == KeyState::Active)
            .and_then(|entry| entry.activated_at)
            .is_some_and(|activated| {
                activated
                    .saturating_add(self.seconds_rotating())
                    .saturating_sub(self.seconds_ahead())
                    <= now
            });
        let waiting = ring
            .keys
            .iter()
            .any(|entry| entry.state == KeyState::Published);

        if successor_due && !waiting {
            ring.keys.push(self.create(now, false)?);
            report.published += 1;
        }

        // The two-stage end of a key's life. Its private half is deleted once it has been retired for
        // `retain`: it will never sign again, so keeping it only widens the window it could leak in.
        // Its public half stays — the key moves to `Archived` — until `verify_retain`, so a signature
        // it made keeps verifying that whole time. When a ring wants no separate public lifetime
        // (`verify_retain` no longer than `retain`), the two stages collapse and the key is forgotten
        // outright, exactly as before.
        let retain = self.seconds_retained();
        let verify_retain = self.seconds_verify_retained();
        let has_archive_phase = verify_retain > retain;

        let mut to_archive: Vec<String> = Vec::new();
        let mut to_forget: Vec<String> = Vec::new();
        for entry in &ring.keys {
            let Some(retired_at) = entry.retired_at else {
                continue;
            };

            match entry.state {
                KeyState::Retired if retired_at.saturating_add(retain) <= now => {
                    if has_archive_phase {
                        to_archive.push(entry.kid.clone());
                    } else {
                        to_forget.push(entry.kid.clone());
                    }
                }
                KeyState::Archived if retired_at.saturating_add(verify_retain) <= now => {
                    to_forget.push(entry.kid.clone());
                }
                _ => {}
            }
        }

        // The private half goes for both — archived keeps only its public half, forgotten keeps
        // nothing. `forget` deleting an already-deleted file is not an error, so an archived key
        // being forgotten later is fine.
        for kid in to_archive.iter().chain(to_forget.iter()) {
            self.forget(kid)?;
        }

        for entry in &mut ring.keys {
            if to_archive.contains(&entry.kid) {
                entry.state = KeyState::Archived;
                report.archived += 1;
            }
        }

        ring.keys.retain(|entry| !to_forget.contains(&entry.kid));
        report.forgotten += to_forget.len();

        if !report.is_empty() {
            self.write_ring(&ring)?;
        }

        Ok(report)
    }
}

impl DirectoryKeyManager {
    fn seconds_ahead(&self) -> u64 {
        self.policy.publish_ahead.as_secs()
    }

    fn seconds_rotating(&self) -> u64 {
        self.policy.rotate_every.as_secs()
    }

    fn seconds_retained(&self) -> u64 {
        self.policy.retain.as_secs()
    }

    /// How long the public half stays published — never less than how long the private half is kept.
    fn seconds_verify_retained(&self) -> u64 {
        self.policy
            .verify_retain
            .as_secs()
            .max(self.policy.retain.as_secs())
    }
}

/// Reads the ring in `directory`, treating an absent one as empty.
///
/// Free of any manager: reading the ring file is not resolving a collaborator, it is parsing a
/// format this crate owns, so both the manager and [`export`] read it the same way without either
/// constructing the other.
fn read_ring_in(directory: &Path) -> Result<Ring> {
    let path = directory.join(RING_FILE);

    match fs::read_to_string(&path) {
        Ok(text) => serde_json::from_str(&text).map_err(|error| {
            KeyError::backend(format!(
                "reading the key ring at {}: {error}",
                path.display()
            ))
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Ring::default()),
        Err(error) => Err(KeyError::unavailable(error)),
    }
}

/// Reads a ring on disk and returns its public keys as a JWKS document.
///
/// The way to obtain an operations ring's public half without the server running: those keys are
/// never served over HTTP, so a verifier — after a restore, or following the backup runbook — reads
/// them here. It reads only the ring file, and only the public halves it holds; no private key is
/// opened and no manager is constructed, so this is a pure read of what is already on disk.
pub fn export(directory: impl AsRef<Path>) -> Result<String> {
    let ring = read_ring_in(directory.as_ref())?;
    let document = JwkSet::new(ring.keys.iter().map(Entry::to_jwk).collect());

    serde_json::to_string_pretty(&document)
        .map_err(|error| KeyError::backend(format!("rendering the key set: {error}")))
}

/// Reports whether `signature` over `payload` was made by the key `jwk` publishes.
///
/// It lives here rather than beside whatever produced the signature because this is where the
/// cryptography is, and because the caller has to choose the key set deliberately: verifying against
/// keys fetched from the machine under suspicion checks a signature against a key the same attacker
/// could have replaced.
///
/// Anything that is not an Ed25519 key this build understands answers `false` rather than erroring:
/// a verifier that distinguishes "wrong signature" from "key I could not read" hands an attacker a
/// way to tell which of the two they achieved.
pub fn verify_signature(jwk: &Jwk, payload: &[u8], signature: &[u8]) -> bool {
    if jwk.kty != "OKP" || jwk.crv.as_deref() != Some(CURVE) || jwk.alg != ALGORITHM {
        return false;
    }

    let Some(public) = encoding::from_base64url(&jwk.x) else {
        return false;
    };

    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, public)
        .verify(payload, signature)
        .is_ok()
}

/// Returns the RFC 7638 thumbprint of an Ed25519 public key, which is what names it.
///
/// The name is derived from the key rather than assigned to it, so two deployments never disagree
/// about what a key is called and a client can check that the `kid` it was given belongs to the key
/// it was given.
fn thumbprint(algorithm: RingAlgorithm, public_key: &str) -> String {
    // RFC 7638 §3: the required members, no whitespace, lexicographic order. Which members are
    // required depends on the key type — crv/kty/x for OKP, crv/kty/x/y for EC.
    let canonical = match algorithm {
        RingAlgorithm::Ed25519 => {
            format!(r#"{{"crv":"{CURVE}","kty":"OKP","x":"{public_key}"}}"#)
        }
        RingAlgorithm::Es256 => {
            let (x, y) = split_p256_point(public_key);
            format!(r#"{{"crv":"{P256_CURVE}","kty":"EC","x":"{x}","y":"{y}"}}"#)
        }
    };
    let digest = ring::digest::digest(&ring::digest::SHA256, canonical.as_bytes());

    encoding::base64url(digest.as_ref())
}

/// Splits a SEC1 uncompressed P-256 point into the two coordinates a JWK publishes.
///
/// The key pair hands back `0x04 || x || y`; a JWK carries `x` and `y` separately. A point that is
/// not that shape yields empty coordinates rather than panicking: it would have to be a corrupt
/// ring file, and a key that cannot be described is one no verifier will match.
fn split_p256_point(public_key: &str) -> (String, String) {
    let Some(point) = encoding::from_base64url(public_key) else {
        return (String::new(), String::new());
    };
    if point.len() != 65 || point[0] != 0x04 {
        return (String::new(), String::new());
    }

    (
        encoding::base64url(&point[1..33]),
        encoding::base64url(&point[33..65]),
    )
}

/// Narrows permissions where the platform has them.
#[cfg(unix)]
fn restrict(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .map_err(|error| KeyError::backend(format!("restricting {}: {error}", path.display())))
}

#[cfg(not(unix))]
fn restrict(_path: &Path, _mode: u32) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    #[test]
    fn test_the_name_of_a_key_is_derived_from_the_key() {
        // RFC 7638 leaves nothing to choose, so the same public key must always get the same name.
        let first = thumbprint(
            RingAlgorithm::Ed25519,
            "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
        );
        let second = thumbprint(
            RingAlgorithm::Ed25519,
            "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
        );

        assert_eq!(first, second);
        assert_ne!(first, thumbprint(RingAlgorithm::Ed25519, "AAAA"));
        // base64url of a SHA-256, unpadded.
        assert_eq!(first.len(), 43);
    }

    #[test]
    fn test_a_ring_reads_back_as_what_was_written() {
        let ring = Ring {
            version: 1,
            keys: vec![Entry {
                algorithm: RingAlgorithm::Ed25519,
                kid: "k1".to_owned(),
                state: KeyState::Active,
                public_key: "AAAA".to_owned(),
                created_at: 10,
                activated_at: Some(20),
                retired_at: None,
            }],
        };

        let text = serde_json::to_string(&ring).expect("it serialises");
        let read: Ring = serde_json::from_str(&text).expect("it reads back");

        assert_eq!(read, ring);
        // A key that has not retired must not carry a null saying so: the file is read by later
        // versions of this code, and an absent field is the one thing every version agrees on.
        assert!(!text.contains("retired_at"));
    }
}
