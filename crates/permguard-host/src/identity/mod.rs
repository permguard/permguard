// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The Host identity (WP-2.2): `host/identity/` on the volume.
//!
//! ```text
//! host/identity/
//! ├── INIT                 immutable provisioning marker, written last
//! ├── identity.cose        the signed document of the current epoch; atomic replace
//! ├── succession.cborseq   the succession records, appended
//! ├── BOOT                 this start's boot id and the volume's claim generation
//! └── keys/
//!     ├── <epoch>.key      the private key, through the key provider (0600)
//!     └── <epoch>.pub      the public key, kept for good (owner decision of 2026-10-08)
//! ```
//!
//! | Step      | What                                                                                         |
//! | --------- | -------------------------------------------------------------------------------------------- |
//! | provision | leftovers of an interrupted provisioning removed; `host_id` (UUIDv7) minted; epoch 1 generated and self-tested; the document written; `INIT` last |
//! | open      | `INIT` read and matched to `VOLUME_ID`; the chain verified from the epoch-1 key `INIT` pins to the current document; an interrupted rotation completed; keys of epochs never published removed; possession proven; a `boot_id` minted and `BOOT` written |
//! | rotate    | under the mutation engine: epoch n+1 generated, the succession signed by n and appended, the document signed by n+1, the private key of n-1 destroyed |
//!
//! Without `INIT` nothing is minted at open: the installation does not exist. With `INIT`,
//! missing or damaged state refuses the open; no replacement key is ever generated (the blueprint's
//! provisioning and recovery). The identity key signs only identity documents, successions,
//! proof transcripts and ring bindings.

pub mod record;

use std::sync::{Arc, PoisonError, RwLock};

use permguard_core::domains::protected;
use permguard_objects::cose::Sign1;
pub use permguard_objects::crypto::suite::Suite;
use permguard_objects::digest::Digest;

use crate::keys::{Custody, KeyError, KeyProvider, PublicKey};
use crate::operations::journal::OperationId;
use crate::operations::mutation::{Applying, Domain, Observed};
use crate::storage::volume::Volume;
use crate::storage::write::{self, Published, publish_immutable};
use crate::storage::{Dir, StorageError, sequence, tombstone};

use record::{Boot, Document, Init, RecordError, Succession};

/// The directory below `host/`.
pub const DIRECTORY: &str = "identity";
pub const INIT: &str = "INIT";
pub const DOCUMENT: &str = "identity.cose";
pub const SUCCESSION: &str = "succession.cborseq";
pub const BOOT: &str = "BOOT";
pub const KEYS: &str = "keys";
/// The most bytes one succession record takes.
const MAX_RECORD_BYTES: usize = 16 * 1024;
/// The protocol versions this build speaks, as the document lists them.
pub const PROTOCOLS: &[&str] = &[protected::HOST_SESSION];
/// What the identity key signs for others than itself.
const SIGNS_FOR_OTHERS: &[&str] = &[protected::HOST_PROOF, protected::HOST_RING_BINDING];
/// The domain intents of a rotation carry.
pub const DOMAIN: &str = "identity";
/// The operation a rotation is.
pub const ROTATE: &str = "identity.rotate";
/// The `security` audit actions.
pub const AUDIT_PROVISIONED: &str = "host.identity.provisioned";
pub const AUDIT_ROTATED: &str = "host.identity.rotated";

/// Why the identity did not open, provision or rotate.
#[derive(Debug)]
pub enum IdentityError {
    /// No `INIT`: the installation does not exist.
    NotProvisioned,
    /// `INIT` exists: provisioning happens once.
    Provisioned,
    /// The state after `INIT` is damaged or does not verify; nothing is regenerated.
    Corrupt(String),
    /// The epoch the caller expected is not the current one.
    Conflict {
        expected: u64,
        current: u64,
    },
    /// The identity key may not sign this content type.
    Refused(String),
    /// A rotation whose succession is durable and whose document is not: the next open
    /// completes it.
    Indeterminate(String),
    Key(KeyError),
    Storage(StorageError),
}

impl std::fmt::Display for IdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotProvisioned => f.write_str(
                "the Host identity is not provisioned: no host/identity/INIT on the volume",
            ),
            Self::Provisioned => {
                f.write_str("the Host identity is already provisioned; provisioning happens once")
            }
            Self::Corrupt(detail) => write!(f, "the Host identity does not verify: {detail}"),
            Self::Conflict { expected, current } => write!(
                f,
                "the rotation expected epoch {expected}, the current one is {current}"
            ),
            Self::Refused(detail) => f.write_str(detail),
            Self::Indeterminate(detail) => write!(
                f,
                "the rotation is durable and its document is not; the next start completes it: \
                 {detail}"
            ),
            Self::Key(error) => write!(f, "{error}"),
            Self::Storage(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for IdentityError {}

impl From<StorageError> for IdentityError {
    fn from(error: StorageError) -> Self {
        Self::Storage(error)
    }
}

impl From<KeyError> for IdentityError {
    fn from(error: KeyError) -> Self {
        Self::Key(error)
    }
}

impl From<RecordError> for IdentityError {
    fn from(error: RecordError) -> Self {
        Self::Corrupt(error.0)
    }
}

fn corrupt(detail: impl std::fmt::Display) -> IdentityError {
    IdentityError::Corrupt(detail.to_string())
}

/// The current epoch: its key and its signed document.
#[derive(Debug, Clone)]
struct Current {
    epoch: u64,
    public: PublicKey,
    document: Document,
    envelope: Vec<u8>,
    successions: Vec<Vec<u8>>,
    last: Option<Digest>,
}

/// What a rotation produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rotated {
    pub epoch: u64,
    pub fingerprint: String,
    /// The succession record's envelope.
    pub succession: Vec<u8>,
}

/// The Host identity, open.
pub struct Identity {
    dir: Dir,
    keys: Dir,
    provider: Arc<dyn KeyProvider>,
    init: Init,
    init_bytes: Vec<u8>,
    first_public: Vec<u8>,
    volume_id: [u8; 16],
    boot: Boot,
    current: RwLock<Current>,
}

impl std::fmt::Debug for Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Identity")
            .field("host_id", &record::uuid_text(&self.init.host_id))
            .field("epoch", &self.epoch())
            .finish_non_exhaustive()
    }
}

fn slot(epoch: u64) -> String {
    epoch.to_string()
}

fn public_name(epoch: u64) -> String {
    format!("{epoch}.pub")
}

/// The identity directory of `volume`, and its `keys/` below, created `0700`.
pub fn directories(volume: &Volume) -> Result<(Dir, Dir), StorageError> {
    let dir = volume.host().subdir(DIRECTORY, true)?;
    let keys = dir.subdir(KEYS, true)?;
    Ok((dir, keys))
}

/// The external witness of `volume`'s identity, read from `INIT` alone and without writing
/// anything: what a start compares before it opens the identity. `None` without `INIT`.
pub fn witness_of(volume: &Volume) -> Result<Option<String>, IdentityError> {
    let (dir, _) = directories(volume)?;
    let Some(bytes) = dir.read(INIT)? else {
        return Ok(None);
    };
    let init = Init::decode(&bytes)?;
    Ok(Some(record::witness(
        &bytes,
        &volume.id(),
        &init.fingerprint,
    )))
}

/// The most succession records a published identity may carry: a bound on the work a peer's
/// presentation costs (WP-2.3), far above any real rotation history.
pub const MAX_SUCCESSIONS: usize = 1024;

/// A Host identity as another Host published it, verified (WP-2.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    pub host_id: [u8; 16],
    pub epoch: u64,
    pub suite: Suite,
    /// The current epoch's public key.
    pub public_key: Vec<u8>,
    /// The fingerprint of every epoch's key, epoch 1 first.
    pub fingerprints: Vec<String>,
    pub document: Document,
}

impl Verified {
    /// The fingerprint of the epoch-1 key: what a pin names.
    pub fn first_fingerprint(&self) -> &str {
        self.fingerprints.first().map_or("", String::as_str)
    }

    /// The fingerprint of the current key.
    pub fn fingerprint(&self) -> &str {
        self.fingerprints.last().map_or("", String::as_str)
    }
}

/// Verifies an identity another Host published: its epoch-1 public key, its succession records
/// in order and its current document, as `GET /host/v1/identity` answers them. The chain is
/// walked from the epoch-1 key, every record verified under the key of the epoch before; the
/// document under the last. Nothing of the document is trusted before its signature: the suite
/// it names is checked against the first key's length and pins every verification. The caller
/// matches [`Verified::first_fingerprint`] to the pin it holds; without that match the result is
/// descriptive, never authority.
pub fn verify_published(
    document: &[u8],
    successions: &[Vec<u8>],
    first_public_key: &[u8],
) -> Result<Verified, IdentityError> {
    if successions.len() > MAX_SUCCESSIONS {
        return Err(corrupt("more succession records than any identity carries"));
    }
    let sign1 = Sign1::decode(document).map_err(corrupt)?;
    let claimed = Document::decode(sign1.payload_unverified())?;
    let suite = claimed.suite;
    if first_public_key.len() != suite.public_key_len() {
        return Err(corrupt(
            "the epoch-1 public key is not a key of the document's suite",
        ));
    }
    let mut key = PublicKey {
        suite,
        bytes: first_public_key.to_vec(),
    };
    let mut fingerprints = vec![key.fingerprint()];
    let mut epoch = 1;
    let mut last = None;
    for bytes in successions {
        let envelope = Sign1::decode(bytes).map_err(corrupt)?;
        check_kid(&envelope, epoch)?;
        let payload = envelope
            .verify(suite, &key.bytes, protected::HOST_SUCCESSION)
            .map_err(|error| corrupt(format!("succession to epoch {}: {error}", epoch + 1)))?;
        let record = Succession::decode(payload)?;
        let next = PublicKey {
            suite,
            bytes: record.public_key.clone(),
        };
        if record.host_id != claimed.host_id
            || record.from_epoch != epoch
            || record.to_epoch != epoch + 1
            || record.previous != last.clone().unwrap_or_else(record::zero_digest)
            || record.fingerprint != next.fingerprint()
            || next.bytes.len() != suite.public_key_len()
        {
            return Err(corrupt(format!(
                "the succession to epoch {} does not continue the chain",
                epoch + 1
            )));
        }
        last = Some(record::succession_digest(bytes));
        fingerprints.push(next.fingerprint());
        key = next;
        epoch += 1;
    }
    check_kid(&sign1, epoch)?;
    let payload = sign1
        .verify(suite, &key.bytes, protected::HOST_IDENTITY)
        .map_err(|error| corrupt(format!("the identity document: {error}")))?;
    let verified = Document::decode(payload)?;
    if verified.epoch != epoch
        || !record::is_uuid_v7(&verified.host_id)
        || verified.subject != record::subject(&verified.host_id)
        || verified.public_key != key.bytes
        || verified.fingerprint != key.fingerprint()
        || verified.last_succession != last
        || verified.suite != suite
    {
        return Err(corrupt(
            "the document does not name the key and chain it was published with",
        ));
    }
    Ok(Verified {
        host_id: verified.host_id,
        epoch,
        suite,
        public_key: key.bytes,
        fingerprints,
        document: verified,
    })
}

/// Whether `volume` holds a provisioned identity.
pub fn is_provisioned(volume: &Volume) -> Result<bool, StorageError> {
    Ok(directories(volume)?.0.read(INIT)?.is_some())
}

impl Identity {
    /// Provisions the identity of `volume`: refused when `INIT` exists. Answers the open
    /// identity, its first `boot_id` minted.
    pub fn provision(
        volume: &Volume,
        provider: Arc<dyn KeyProvider>,
        suite: Suite,
        now: u64,
        now_millis: u64,
    ) -> Result<Self, IdentityError> {
        let (dir, keys) = directories(volume)?;
        dir.sweep_temps()?;
        tombstone::complete(&dir)?;
        if dir.read(INIT)?.is_some() {
            return Err(IdentityError::Provisioned);
        }
        // What an interrupted provisioning left: a key of epoch 1, its public half and an epoch-1
        // document, never more. Anything beyond is an identity that existed and lost its INIT,
        // which is never replaced (the blueprint's recovery).
        let succeeded = dir.read(BOOT)?.is_some()
            || dir.read(SUCCESSION)?.is_some_and(|bytes| !bytes.is_empty())
            || keys.names()?.iter().any(|name| {
                name.split('.')
                    .next()
                    .and_then(|stem| stem.parse::<u64>().ok())
                    .is_some_and(|held| held >= 2)
            });
        if succeeded {
            return Err(corrupt(
                "INIT is missing beside an identity that was opened or rotated: it is never \
                 replaced; restore INIT from a backup, or reset the Host",
            ));
        }
        for name in [DOCUMENT, SUCCESSION, BOOT] {
            if dir.read(name)?.is_some() {
                tombstone::delete(&dir, name)?;
            }
        }
        keys.sweep_temps()?;
        tombstone::complete(&keys)?;
        for name in keys.names()? {
            tombstone::delete(&keys, &name)?;
        }
        let host_id = record::uuid_v7(now_millis, random()?);
        let public = provider.generate(&slot(1), suite)?;
        publish_public(&keys, 1, &public.bytes)?;
        // The self-test: the key signs a fresh challenge and its public half verifies it.
        let challenge = random()?;
        let probe = provider.sign(&slot(1), suite, &challenge)?;
        suite
            .verify(&public.bytes, &challenge, &probe)
            .map_err(|error| corrupt(format!("the new key fails its self-test: {error:?}")))?;
        let document = Document {
            host_id,
            subject: record::subject(&host_id),
            epoch: 1,
            suite,
            public_key: public.bytes.clone(),
            fingerprint: public.fingerprint(),
            last_succession: None,
            protocols: PROTOCOLS.iter().map(|p| (*p).to_owned()).collect(),
            revision: 1,
            issued_at: now,
        };
        let envelope = sign_document(provider.as_ref(), &document)?;
        write::replace_bytes(&dir, DOCUMENT, &envelope)?;
        let init = Init {
            host_id,
            volume_id: volume.id(),
            fingerprint: public.fingerprint(),
            created_at: now,
        };
        let bytes = init.encode()?;
        let same = |held: &[u8]| held == bytes.as_slice();
        match publish_immutable(&dir, INIT, &bytes, &same, &same)? {
            Published::Written | Published::AlreadyThere => {}
        }
        tracing::info!(
            event.name = "host.identity_provisioned",
            component = "host",
            host_id = %record::uuid_text(&host_id),
            fingerprint = %public.fingerprint(),
            "the Host identity is provisioned"
        );
        Self::open(volume, provider)
    }

    /// Opens the identity of `volume`, verifying it whole, and mints this start's `boot_id`.
    pub fn open(volume: &Volume, provider: Arc<dyn KeyProvider>) -> Result<Self, IdentityError> {
        let (dir, keys) = directories(volume)?;
        dir.sweep_temps()?;
        tombstone::complete(&dir)?;
        keys.sweep_temps()?;
        tombstone::complete(&keys)?;
        let init_bytes = dir.read(INIT)?.ok_or(IdentityError::NotProvisioned)?;
        let init = Init::decode(&init_bytes)?;
        if init.volume_id != volume.id() {
            return Err(corrupt(
                "INIT names another volume than this one's VOLUME_ID",
            ));
        }
        if !record::is_uuid_v7(&init.host_id) {
            return Err(corrupt("INIT's host_id is not a UUIDv7"));
        }
        let envelope = dir
            .read(DOCUMENT)?
            .ok_or_else(|| corrupt("INIT is there and identity.cose is not"))?;
        let sign1 = Sign1::decode(&envelope).map_err(corrupt)?;
        // The suite is read before the key that verifies it, then checked against every record.
        let claimed = Document::decode(sign1.payload_unverified())?;
        let suite = claimed.suite;
        let first_public = keys
            .read(&public_name(1))?
            .ok_or_else(|| corrupt("the epoch-1 public key is missing"))?;
        // The suite comes from a document not yet verified: its key length must match too, and
        // every verification below pins the algorithm to it.
        if first_public.len() != suite.public_key_len() {
            return Err(corrupt(
                "the epoch-1 public key is not a key of the document's suite",
            ));
        }
        let first = PublicKey {
            suite,
            bytes: first_public.clone(),
        };
        if first.fingerprint() != init.fingerprint {
            return Err(corrupt("the epoch-1 public key is not the one INIT pins"));
        }
        // The chain, from the key INIT pins.
        let mut key = first;
        let mut previous_key = None;
        let mut epoch = 1;
        let mut last = None;
        let mut successions = Vec::new();
        for item in sequence::recover(&dir, SUCCESSION, MAX_RECORD_BYTES)?.items {
            let envelope = Sign1::from_value(item).map_err(corrupt)?;
            let bytes = envelope.encode().map_err(corrupt)?;
            check_kid(&envelope, epoch)?;
            let payload = envelope
                .verify(suite, &key.bytes, protected::HOST_SUCCESSION)
                .map_err(|error| corrupt(format!("succession to epoch {}: {error}", epoch + 1)))?;
            let record = Succession::decode(payload)?;
            let next = PublicKey {
                suite,
                bytes: record.public_key.clone(),
            };
            if record.host_id != init.host_id
                || record.from_epoch != epoch
                || record.to_epoch != epoch + 1
                || record.previous != last.clone().unwrap_or_else(record::zero_digest)
                || record.fingerprint != next.fingerprint()
            {
                return Err(corrupt(format!(
                    "the succession to epoch {} does not continue the chain",
                    epoch + 1
                )));
            }
            match keys.read(&public_name(record.to_epoch))? {
                Some(held) if held == record.public_key => {}
                Some(_) => {
                    return Err(corrupt(format!(
                        "keys/{} is not the key the succession names",
                        public_name(record.to_epoch)
                    )));
                }
                None => publish_public(&keys, record.to_epoch, &record.public_key)?,
            }
            last = Some(record::succession_digest(&bytes));
            successions.push(bytes);
            previous_key = Some(std::mem::replace(&mut key, next));
            epoch += 1;
        }
        // The document: the chain's last epoch, or the one before it when a rotation stopped
        // between its succession and its document, which is completed here.
        let document = if claimed.epoch == epoch {
            check_kid(&sign1, epoch)?;
            let payload = sign1
                .verify(suite, &key.bytes, protected::HOST_IDENTITY)
                .map_err(|error| corrupt(format!("the identity document: {error}")))?;
            Document::decode(payload)?
        } else if claimed.epoch + 1 == epoch
            && let Some(previous_key) = &previous_key
        {
            // The document of the epoch before: verified under that epoch's key before any of it
            // is carried into the document the new key signs.
            check_kid(&sign1, claimed.epoch)?;
            let payload = sign1
                .verify(suite, &previous_key.bytes, protected::HOST_IDENTITY)
                .map_err(|error| corrupt(format!("the previous epoch's document: {error}")))?;
            let claimed = Document::decode(payload)?;
            if claimed.host_id != init.host_id || claimed.public_key != previous_key.bytes {
                return Err(corrupt(
                    "the previous epoch's document does not name this Host and that epoch's key",
                ));
            }
            let document = Document {
                epoch,
                public_key: key.bytes.clone(),
                fingerprint: key.fingerprint(),
                last_succession: last.clone(),
                revision: claimed.revision + 1,
                ..claimed.clone()
            };
            let envelope = sign_document(provider.as_ref(), &document)?;
            write::replace_bytes(&dir, DOCUMENT, &envelope)?;
            tracing::warn!(
                event.name = "host.identity_rotation_completed",
                component = "host",
                epoch,
                "an identity rotation stopped before its document; the document is issued now"
            );
            document
        } else {
            return Err(corrupt(format!(
                "the document is at epoch {} and the chain at {epoch}",
                claimed.epoch
            )));
        };
        if document.host_id != init.host_id
            || document.subject != record::subject(&init.host_id)
            || document.public_key != key.bytes
            || document.fingerprint != key.fingerprint()
            || document.last_succession != last
            || document.suite != suite
        {
            return Err(corrupt(
                "the document does not name the key and chain this volume holds",
            ));
        }
        // Keys of epochs no succession names: a rotation that stopped before its succession, or a
        // volume whose identity files were put back from an older copy. Nothing is removed here:
        // the next rotation replaces them under its own audited operation.
        let strays: Vec<String> = keys
            .names()?
            .into_iter()
            .filter(|name| {
                name.split('.')
                    .next()
                    .and_then(|stem| stem.parse::<u64>().ok())
                    .is_some_and(|held| held > epoch)
            })
            .collect();
        if !strays.is_empty() {
            tracing::error!(
                event.name = "host.identity_keys_unnamed",
                component = "host",
                epoch,
                keys = ?strays,
                "keys of epochs no succession names: a rotation stopped, or the identity files \
                 were put back from an older copy"
            );
        }
        // Possession, proven locally.
        let challenge = random()?;
        let proof = provider.sign(&slot(epoch), suite, &challenge)?;
        suite
            .verify(&key.bytes, &challenge, &proof)
            .map_err(|_| corrupt("the provider's key does not match the document's"))?;
        let envelope = dir
            .read(DOCUMENT)?
            .ok_or_else(|| corrupt("identity.cose vanished"))?;
        let mut boot_id = [0u8; 16];
        boot_id[..10].copy_from_slice(&random()?);
        boot_id[10..].copy_from_slice(&random()?[..6]);
        let boot = Boot {
            boot_id,
            generation: volume.generation(),
        };
        write::replace_bytes(&dir, BOOT, &boot.encode()?)?;
        Ok(Self {
            dir,
            keys,
            provider,
            volume_id: volume.id(),
            init,
            init_bytes,
            first_public,
            boot,
            current: RwLock::new(Current {
                epoch,
                public: key,
                document,
                envelope,
                successions,
                last,
            }),
        })
    }

    pub fn host_id(&self) -> [u8; 16] {
        self.init.host_id
    }

    /// The `host_id` as text: the UUID's canonical form.
    pub fn host_id_text(&self) -> String {
        record::uuid_text(&self.init.host_id)
    }

    pub fn subject(&self) -> String {
        record::subject(&self.init.host_id)
    }

    pub fn boot_id(&self) -> [u8; 16] {
        self.boot.boot_id
    }

    pub fn epoch(&self) -> u64 {
        self.read().epoch
    }

    pub fn suite(&self) -> Suite {
        self.read().public.suite
    }

    pub fn fingerprint(&self) -> String {
        self.read().public.fingerprint()
    }

    /// The fingerprint `INIT` pins: the first epoch's.
    pub fn first_fingerprint(&self) -> &str {
        &self.init.fingerprint
    }

    /// The epoch-1 public key, the suite's raw bytes.
    pub fn first_public_key(&self) -> &[u8] {
        &self.first_public
    }

    /// The signed document of the current epoch.
    pub fn document(&self) -> Vec<u8> {
        self.read().envelope.clone()
    }

    /// Every succession record, oldest first.
    pub fn successions(&self) -> Vec<Vec<u8>> {
        self.read().successions.clone()
    }

    /// The external witness of this identity.
    pub fn witness(&self) -> String {
        record::witness(&self.init_bytes, &self.volume_id, &self.init.fingerprint)
    }

    /// How the identity key is kept.
    pub fn custody(&self) -> Custody {
        self.provider.custody()
    }

    /// Signs `payload` as `content_type` with the current key: only a proof transcript or a ring
    /// binding; the identity key never signs anything else for anyone.
    pub fn sign(&self, content_type: &str, payload: Vec<u8>) -> Result<Vec<u8>, IdentityError> {
        if !SIGNS_FOR_OTHERS.contains(&content_type) {
            return Err(IdentityError::Refused(format!(
                "the identity key does not sign `{content_type}`"
            )));
        }
        let current = self.read();
        sign(
            self.provider.as_ref(),
            current.epoch,
            current.public.suite,
            content_type,
            payload,
        )
    }

    /// Rotates to the next epoch, inside the operation `applying` names: refused when
    /// `expected_epoch` is not the current one.
    pub fn rotate(
        &self,
        _applying: &Applying<'_>,
        expected_epoch: Option<u64>,
        now: u64,
    ) -> Result<Rotated, IdentityError> {
        let mut current = self.current.write().unwrap_or_else(PoisonError::into_inner);
        if let Some(expected) = expected_epoch
            && expected != current.epoch
        {
            return Err(IdentityError::Conflict {
                expected,
                current: current.epoch,
            });
        }
        let suite = current.public.suite;
        let next = current.epoch + 1;
        // A key no succession names, left by a rotation that stopped or by older files put back:
        // replaced here, inside this audited operation.
        if self.keys.read(&format!("{}.key", slot(next)))?.is_some()
            || self.keys.read(&public_name(next))?.is_some()
        {
            tracing::warn!(
                event.name = "host.identity_stray_key_replaced",
                component = "host",
                epoch = next,
                "a key of the next epoch that no succession names is replaced by this rotation"
            );
            if self.keys.read(&format!("{}.key", slot(next)))?.is_some() {
                self.provider.destroy(&slot(next))?;
            }
            if self.keys.read(&public_name(next))?.is_some() {
                tombstone::delete(&self.keys, &public_name(next))?;
            }
        }
        let public = self.provider.generate(&slot(next), suite)?;
        publish_public(&self.keys, next, &public.bytes)?;
        let record = Succession {
            host_id: self.init.host_id,
            from_epoch: current.epoch,
            to_epoch: next,
            fingerprint: public.fingerprint(),
            public_key: public.bytes.clone(),
            previous: current.last.clone().unwrap_or_else(record::zero_digest),
            at: now,
        };
        let succession = sign(
            self.provider.as_ref(),
            current.epoch,
            suite,
            protected::HOST_SUCCESSION,
            record.encode()?,
        )?;
        sequence::append(&self.dir, SUCCESSION, &succession)?;
        // From here the rotation is durable whatever follows: the next open completes it. A
        // failure is uncertain, never a refusal.
        let indeterminate = |error: IdentityError| IdentityError::Indeterminate(error.to_string());
        let last = record::succession_digest(&succession);
        let document = Document {
            epoch: next,
            public_key: public.bytes.clone(),
            fingerprint: public.fingerprint(),
            last_succession: Some(last.clone()),
            revision: current.document.revision + 1,
            issued_at: now,
            ..current.document.clone()
        };
        let envelope = sign_document(self.provider.as_ref(), &document).map_err(indeterminate)?;
        write::replace_bytes(&self.dir, DOCUMENT, &envelope)
            .map_err(|error| indeterminate(error.into()))?;
        // The grace: the key just retired keeps verifying in-flight work until the next rotation,
        // which destroys it; the one before it goes now.
        if next >= 3 {
            let retired = next - 2;
            if let Err(error) = self.provider.destroy(&slot(retired)) {
                tracing::warn!(
                    event.name = "host.identity_key_kept",
                    component = "host",
                    epoch = retired,
                    error = %error,
                    "a retired identity key could not be destroyed"
                );
            }
        }
        current.successions.push(succession.clone());
        *current = Current {
            epoch: next,
            public: public.clone(),
            document,
            envelope,
            successions: std::mem::take(&mut current.successions),
            last: Some(last),
        };
        tracing::info!(
            event.name = "host.identity_rotated",
            component = "host",
            epoch = next,
            fingerprint = %public.fingerprint(),
            "the Host identity rotated"
        );
        Ok(Rotated {
            epoch: next,
            fingerprint: public.fingerprint(),
            succession,
        })
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, Current> {
        self.current.read().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Rotates `identity` as `initiator`, with no request id: the offline CLI. `expected_epoch` is
/// the epoch the operator read.
pub fn rotate(
    mutations: &crate::operations::mutation::Mutations,
    identity: &Identity,
    initiator: crate::operations::journal::Initiator,
    expected_epoch: u64,
    now: u64,
) -> Result<Rotated, crate::operations::mutation::MutationError<IdentityError>> {
    use crate::operations::mutation::{Applied, Begin, Failure, MutationError, Outcome};
    let mut produced = None;
    let outcome = mutations.run(
        Begin {
            domain: DOMAIN,
            operation: ROTATE,
            action: AUDIT_ROTATED,
            initiator,
            request: None,
            target: Some(format!("epoch:{}", expected_epoch.saturating_add(1))),
        },
        |applying| {
            let rotated = identity
                .rotate(applying, Some(expected_epoch), now)
                .map_err(|error| match error {
                    IdentityError::Storage(_) | IdentityError::Indeterminate(_) => {
                        Failure::Indeterminate(error)
                    }
                    other => Failure::Refused(other),
                })?;
            let applied = Applied {
                revision: rotated.epoch,
                target: Some(format!("epoch:{}", rotated.epoch)),
                value: (),
            };
            produced = Some(rotated);
            Ok(applied)
        },
    )?;
    match (outcome, produced) {
        (Outcome::Applied(()), Some(rotated)) => Ok(rotated),
        _ => Err(MutationError::Unrecorded(
            "a rotation with no request id answered without applying".to_owned(),
        )),
    }
}

/// The identity as a domain of the mutation engine: a rotation's intent names the epoch it
/// produces, `epoch:<n>`, which the identity shows once its document reaches it.
pub struct Identities<'a>(pub &'a Identity);

impl Domain for Identities<'_> {
    fn name(&self) -> &'static str {
        DOMAIN
    }

    fn observe(&self, _operation_id: &OperationId, target: Option<&str>) -> Option<Observed> {
        let epoch = target?.strip_prefix("epoch:")?.parse::<u64>().ok()?;
        (self.0.epoch() >= epoch).then(|| Observed {
            revision: epoch,
            target: Some(format!("epoch:{epoch}")),
        })
    }
}

/// The `kid` of an identity envelope is its signing epoch, in decimal.
fn check_kid(envelope: &Sign1, epoch: u64) -> Result<(), IdentityError> {
    let header = envelope.header().map_err(corrupt)?;
    if header.kid != epoch.to_string().into_bytes() {
        return Err(corrupt(format!(
            "an envelope signed at epoch {epoch} names another kid"
        )));
    }
    Ok(())
}

fn sign(
    provider: &dyn KeyProvider,
    epoch: u64,
    suite: Suite,
    content_type: &str,
    payload: Vec<u8>,
) -> Result<Vec<u8>, IdentityError> {
    let kid = epoch.to_string().into_bytes();
    Sign1::sign_with(suite, content_type, &kid, payload, |bytes| {
        provider
            .sign(&slot(epoch), suite, bytes)
            .map_err(|error| error.to_string())
    })
    .and_then(|envelope| envelope.encode())
    .map_err(|error| IdentityError::Refused(error.to_string()))
}

fn sign_document(
    provider: &dyn KeyProvider,
    document: &Document,
) -> Result<Vec<u8>, IdentityError> {
    sign(
        provider,
        document.epoch,
        document.suite,
        protected::HOST_IDENTITY,
        document.encode()?,
    )
}

fn publish_public(keys: &Dir, epoch: u64, bytes: &[u8]) -> Result<(), IdentityError> {
    let same = |held: &[u8]| held == bytes;
    match publish_immutable(keys, &public_name(epoch), bytes, &same, &same)? {
        Published::Written | Published::AlreadyThere => Ok(()),
    }
}

fn random() -> Result<[u8; 10], IdentityError> {
    use ring::rand::SecureRandom as _;
    let mut bytes = [0u8; 10];
    ring::rand::SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| IdentityError::Refused("the OS random source refused".to_owned()))?;
    Ok(bytes)
}

#[cfg(test)]
mod tests;
