// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The rings a Host composes, and the `host.identity` ring beside them (WP-3.1).
//!
//! | Ring              | Keys                                            | Binding                          |
//! | ----------------- | ----------------------------------------------- | -------------------------------- |
//! | `host.identity`   | the identity's current key, read from it        | none: the chain authenticates it |
//! | `host.operations` | its own, below `host/keys/host.operations`      | identity-signed, every epoch     |
//! | `control.attest`  | its own, below `host/keys/control.attest`       | identity-signed, every epoch     |
//! | `data.attest`     | its own, below `host/keys/data.attest`          | identity-signed, every epoch     |
//!
//! `host.identity` is a view: the identity's keys live in `host/identity/keys` through the key
//! provider and nowhere else, its epoch is the identity epoch, and its documents keep the epoch
//! as their COSE kid (owner decision of 2026-10-08). It is never in a Plane's key set.

use std::fmt;
use std::path::Path;
use std::sync::Arc;

use permguard_core::assurance::AssuranceProfile;
use permguard_objects::crypto::suite::Suite;
use permguard_objects::crypto::thumbprint::{self, KeySet};

use super::migration;
use super::ring::{
    Binder, HOST_IDENTITY, Policy, Recorder, Ring, RingError, Rings, Statement, jwk_of,
};
use crate::identity::Identity;
use crate::operations::journal::OperationId;
use crate::operations::mutation::{Domain, Observed};
use crate::storage::StorageError;
use crate::storage::volume::Volume;
use crate::time::TimeGuard;

/// Why a ring could not be opened.
#[derive(Debug)]
pub enum OpenError {
    /// Its layout could not be read, declared or migrated.
    Layout(StorageError),
    /// A legacy ring waits for the offline migration the profile requires.
    Migration(String),
    Ring(RingError),
}

impl fmt::Display for OpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Layout(error) => write!(f, "laying the ring out: {error}"),
            Self::Migration(detail) => f.write_str(detail),
            Self::Ring(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for OpenError {}

/// What opens a Host's rings: the volume, the clock, the identity that binds every set, the
/// audit that records every transition, and the profile a migration's preflight runs under.
pub struct Opener<'a> {
    pub volume: &'a Volume,
    /// The Host whose rings these are: what a sealed key is bound to.
    pub host_id: [u8; 16],
    /// Each ring's provider, from its custody (WP-3.2).
    pub custodian: Arc<super::custody::Custodian>,
    pub time: Arc<TimeGuard>,
    pub binder: Option<Arc<dyn Binder>>,
    pub recorder: Option<Arc<dyn Recorder>>,
    pub profile: AssuranceProfile,
}

impl Opener<'_> {
    /// Lays `ring` out, migrating the legacy ring at `legacy` first (owner decisions of
    /// 2026-10-08), and opens it. From `production` upward a legacy ring is migrated only by
    /// `permguard migrate keys`, which declares the backup the preflight requires.
    pub fn open(
        &self,
        ring: &'static str,
        suite: Suite,
        policy: Policy,
        legacy: Option<&Path>,
    ) -> Result<Arc<Ring>, OpenError> {
        if self.profile.at_least(AssuranceProfile::Production)
            && migration::needs_migration(self.volume, ring, legacy).map_err(OpenError::Layout)?
        {
            return Err(OpenError::Migration(format!(
                "the key ring `{ring}` is still in its legacy directory, and from the production \
                 profile upward its migration declares a backup: run `permguard migrate keys \
                 --volume {} --backup <reference>` with the server stopped",
                self.volume.root().display()
            )));
        }
        let laid = migration::lay_out(
            self.volume,
            ring,
            legacy,
            self.profile,
            None,
            self.time.now_secs(),
        )
        .map_err(OpenError::Layout)?;
        if laid == migration::Laid::Migrated {
            tracing::info!(
                event.name = "host.keys.migrated",
                component = "host",
                ring = ring,
                "a legacy key ring was migrated; `migrate finalize` removes its old directory"
            );
        }
        let dir = super::ring::directory(self.volume, ring).map_err(OpenError::Layout)?;
        let public = dir
            .subdir(super::ring::PUBLIC, true)
            .map_err(OpenError::Layout)?;
        let private = dir
            .subdir(super::ring::PRIVATE, true)
            .map_err(OpenError::Layout)?;
        let stored = super::ring::stored_public(
            crate::storage::Dir::open(public.path()).map_err(OpenError::Layout)?,
        );
        let custodied = self
            .custodian
            .plan(ring, self.host_id, private, stored, suite)
            .map_err(|error| OpenError::Ring(RingError::Provider(error)))?;
        let mut opened = Ring::open_unchecked(
            dir,
            public,
            Arc::clone(&custodied.provider),
            ring,
            suite,
            policy,
            Arc::clone(&self.time),
        )
        .map_err(OpenError::Ring)?;
        if let Some(binder) = &self.binder {
            opened = opened.with_binder(Arc::clone(binder));
        }
        if let Some(recorder) = &self.recorder {
            opened = opened.with_recorder(Arc::clone(recorder));
        }
        // What the custody does at this start is journaled and recorded like any transition,
        // before it is done: a crash between the two seals the key again at the next start.
        opened
            .note_custody(super::record::Kind::Sealed, &custodied.plan.sealed)
            .and_then(|()| {
                opened.note_custody(super::record::Kind::Rewrapped, &custodied.plan.rewrapped)
            })
            .map_err(OpenError::Ring)?;
        custodied
            .apply()
            .map_err(|error| OpenError::Ring(RingError::Provider(error)))?;
        opened.check_held().map_err(OpenError::Ring)?;
        Ok(Arc::new(opened))
    }
}

/// The rings of one Host process.
#[derive(Debug, Default)]
pub struct Registry {
    identity: Option<Arc<Identity>>,
    rings: Vec<Arc<Ring>>,
}

impl Registry {
    /// The rings `rings`, and the identity's view when it is open.
    pub fn new(identity: Option<Arc<Identity>>, rings: Vec<Arc<Ring>>) -> Self {
        Self { identity, rings }
    }

    /// The rings with keys of their own.
    pub fn rings(&self) -> &[Arc<Ring>] {
        &self.rings
    }

    /// The ring `id`, when it has keys of its own.
    pub fn ring(&self, id: &str) -> Option<&Arc<Ring>> {
        self.rings.iter().find(|ring| ring.id() == id)
    }

    /// Every ring id composed: `host.identity` first when the identity is open.
    pub fn ids(&self) -> Vec<&'static str> {
        self.identity
            .as_ref()
            .map(|_| HOST_IDENTITY)
            .into_iter()
            .chain(self.rings.iter().map(|ring| ring.id()))
            .collect()
    }

    /// The public statement of `id`; `None` when no such ring is composed.
    pub fn statement(&self, id: &str) -> Option<Result<Statement, RingError>> {
        if id == HOST_IDENTITY {
            return self.identity.as_deref().map(identity_statement);
        }
        self.ring(id).map(|ring| ring.statement())
    }

    /// The bindings of every ring that holds one for its current epoch.
    pub fn bindings(&self) -> Result<Vec<(String, u64, Vec<u8>)>, RingError> {
        let mut bindings = Vec::new();
        for ring in &self.rings {
            let statement = ring.statement()?;
            if let Some(binding) = statement.binding {
                bindings.push((statement.ring, statement.epoch, binding));
            }
        }
        Ok(bindings)
    }
}

/// The `host.identity` ring: the identity's current key as `host.identity:<thumbprint>`, the
/// identity epoch, and the digest of that one-key set.
pub fn identity_statement(identity: &Identity) -> Result<Statement, RingError> {
    let public = identity.public_key();
    let thumbprint = thumbprint::jwk_thumbprint(public.suite, &public.bytes)
        .map_err(|error| RingError::Corrupt(error.to_string()))?;
    let epoch = identity.epoch();
    let key_set_digest = KeySet::new(HOST_IDENTITY, epoch, public.suite, &[&thumbprint])
        .and_then(|set| set.digest())
        .map_err(|error| RingError::Corrupt(error.to_string()))?;
    Ok(Statement {
        ring: HOST_IDENTITY.to_owned(),
        epoch,
        suite: public.suite,
        key_set_digest,
        keys: vec![jwk_of(
            &thumbprint::kid(HOST_IDENTITY, &thumbprint),
            &public,
        )],
        binding: None,
    })
}

impl Domain for Registry {
    fn name(&self) -> &'static str {
        super::ring::DOMAIN
    }

    fn observe(&self, operation_id: &OperationId, target: Option<&str>) -> Option<Observed> {
        Rings(&self.rings).observe(operation_id, target)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::time::Duration;

    use permguard_core::KeyManager as _;
    use permguard_core::assurance::AssuranceProfile;
    use permguard_core::keys::PublicSet as _;
    use permguard_objects::crypto::suite::Suite;

    use super::*;
    use crate::keys::FileKeyProvider;
    use crate::keys::ring::{DATA_ATTEST, Policy};
    use crate::storage::volume::Volume;
    use crate::time::TimeGuard;

    #[test]
    fn the_identity_ring_is_a_view_of_the_identity_and_never_bound() {
        let root = std::env::temp_dir().join(format!(
            "permguard-host-registry-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
        let (_, keys) = crate::identity::directories(&volume).expect("dirs");
        let identity = Arc::new(
            Identity::provision(
                &volume,
                Arc::new(FileKeyProvider::new(keys)),
                Suite::Ed25519Sha256V1,
                1_800_000_000,
                1_800_000_000_000,
            )
            .expect("provisioned"),
        );
        let time = Arc::new(TimeGuard::system(Duration::from_secs(30)));
        let ring = Arc::new(
            Ring::open(
                &volume,
                DATA_ATTEST,
                Suite::Ed25519Sha256V1,
                Policy {
                    publish_ahead: Duration::from_secs(600),
                    rotate_every: Duration::from_secs(3600),
                    retain: Duration::from_secs(7200),
                },
                time,
            )
            .expect("opens")
            .with_binder(identity.clone()),
        );
        ring.maintain().expect("first");
        let registry = Registry::new(Some(identity.clone()), vec![ring.clone()]);
        assert_eq!(registry.ids(), vec![HOST_IDENTITY, DATA_ATTEST]);

        let statement = registry
            .statement(HOST_IDENTITY)
            .expect("composed")
            .expect("read");
        assert_eq!(statement.epoch, identity.epoch());
        assert!(statement.binding.is_none());
        assert_eq!(statement.keys.len(), 1);
        let kid = &statement.keys[0].kid;
        let public = identity.public_key();
        assert_eq!(
            Some(kid.as_str()),
            thumbprint::jwk_thumbprint(public.suite, &public.bytes)
                .ok()
                .map(|thumbprint| thumbprint::kid(HOST_IDENTITY, &thumbprint))
                .as_deref()
        );
        assert!(
            ring.public_keys()
                .expect("published")
                .iter()
                .all(|key| !key.kid.starts_with(HOST_IDENTITY)),
            "never in a Plane's key set"
        );
        let bindings = registry.bindings().expect("read");
        assert_eq!(bindings.len(), 1);
        assert_eq!(bindings[0].0, DATA_ATTEST);
        assert!(registry.statement("nope").is_none());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn from_production_up_a_legacy_ring_waits_for_the_offline_migration() {
        let root = std::env::temp_dir().join(format!(
            "permguard-host-opener-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let legacy = root.join("operations/keys/data");
        std::fs::create_dir_all(&legacy).expect("created");
        std::fs::write(legacy.join(migration::LEGACY_RING), b"{\"keys\":[]}").expect("written");
        let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
        let policy = Policy {
            publish_ahead: Duration::from_secs(600),
            rotate_every: Duration::from_secs(3600),
            retain: Duration::from_secs(7200),
        };
        let opener = |profile| Opener {
            volume: &volume,
            host_id: [1; 16],
            custodian: Arc::new(crate::keys::custody::Custodian::development()),
            time: Arc::new(TimeGuard::system(Duration::from_secs(30))),
            binder: None,
            recorder: None,
            profile,
        };
        let refused = opener(AssuranceProfile::Production)
            .open(DATA_ATTEST, Suite::Ed25519Sha256V1, policy, Some(&legacy))
            .expect_err("a legacy ring under production");
        assert!(
            matches!(&refused, OpenError::Migration(detail) if detail.contains("permguard migrate keys")),
            "{refused}"
        );
        assert!(
            !root.join("host/keys/data.attest").exists(),
            "nothing laid out or opened"
        );
        // Without a legacy ring, production opens as any profile does.
        let fresh = opener(AssuranceProfile::Production)
            .open(
                crate::keys::ring::CONTROL_ATTEST,
                Suite::Ed25519Sha256V1,
                policy,
                Some(&root.join("operations/keys/control")),
            )
            .expect("no legacy ring");
        assert_eq!(fresh.epoch(), 0);
        let _ = std::fs::remove_dir_all(root);
    }
}

#[cfg(test)]
mod custody_tests {
    #![allow(clippy::expect_used)]

    use std::time::Duration;

    use permguard_core::KeyManager as _;
    use permguard_core::assurance::AssuranceProfile;
    use permguard_core::config::KeyCustody;
    use permguard_core::keys::{PublicSet as _, Sign as _};

    use super::*;
    use crate::keys::KeyProvider as _;
    use crate::keys::custody::{Custodian, Keks, SecretKek};
    use crate::keys::record::Kind;
    use crate::keys::ring::{DATA_ATTEST, journal_entries};
    use crate::secrets::{KeyVersion, Root};

    fn kek(name: &str, version: u64, byte: u8) -> Arc<dyn crate::keys::custody::Wrap> {
        let root =
            Root::from_material(&[byte; 32], KeyVersion::new(version).expect("v")).expect("a root");
        Arc::new(SecretKek::from_root(name, &root).expect("a KEK"))
    }

    fn opener<'a>(volume: &'a Volume, custodian: Custodian) -> Opener<'a> {
        Opener {
            volume,
            host_id: [4; 16],
            custodian: Arc::new(custodian),
            time: Arc::new(TimeGuard::system(Duration::from_secs(30))),
            binder: None,
            recorder: None,
            profile: AssuranceProfile::Development,
        }
    }

    fn policy() -> Policy {
        Policy {
            publish_ahead: Duration::from_secs(600),
            rotate_every: Duration::from_secs(3600),
            retain: Duration::from_secs(7200),
        }
    }

    #[test]
    fn a_ring_moved_to_the_file_custody_is_sealed_then_rewrapped_and_journaled() {
        let root = std::env::temp_dir().join(format!(
            "permguard-host-ring-custody-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
        let private = |slot: &str| {
            std::fs::read(root.join(format!("host/keys/data.attest/private/{slot}.key")))
                .expect("held")
        };

        // Development: plaintext.
        let ring = opener(&volume, Custodian::development())
            .open(DATA_ATTEST, Suite::Ed25519Sha256V1, policy(), None)
            .expect("opens");
        ring.maintain().expect("first");
        let kid = ring.active_key_id().expect("active").to_string();
        let slot = kid.split_once(':').expect("a kid").1.to_owned();
        assert_eq!(private(&slot).first(), Some(&0x30));
        drop(ring);

        // `file`: the key is sealed in place, journaled, and signs as before.
        let file = |keks: Keks| Custodian::new(|_| KeyCustody::File, Ok(Some(keks)));
        let old = kek("kek-a", 1, 1);
        let ring = opener(
            &volume,
            file(Keks {
                current: Arc::clone(&old),
                previous: None,
            }),
        )
        .open(DATA_ATTEST, Suite::Ed25519Sha256V1, policy(), None)
        .expect("opens sealed");
        assert_ne!(private(&slot).first(), Some(&0x30), "sealed at rest");
        let signature = ring.sign(b"after").expect("signs");
        let jwk = ring.public_keys().expect("published");
        assert_eq!(signature.key_id().as_str(), kid);
        assert_eq!(jwk.len(), 1);
        drop(ring);

        // A KEK rotation: rewrapped and journaled; the previous KEK is then no longer needed.
        let ring = opener(
            &volume,
            file(Keks {
                current: kek("kek-b", 2, 2),
                previous: Some(old),
            }),
        )
        .open(DATA_ATTEST, Suite::Ed25519Sha256V1, policy(), None)
        .expect("opens rewrapped");
        ring.sign(b"rotated").expect("signs");
        drop(ring);
        let ring = opener(
            &volume,
            file(Keks {
                current: kek("kek-b", 2, 2),
                previous: None,
            }),
        )
        .open(DATA_ATTEST, Suite::Ed25519Sha256V1, policy(), None)
        .expect("opens under the new KEK alone");
        ring.sign(b"settled").expect("signs");

        let kinds: Vec<Kind> =
            journal_entries(&crate::keys::ring::directory(&volume, DATA_ATTEST).expect("dir"))
                .expect("journal")
                .into_iter()
                .map(|entry| entry.kind)
                .collect();
        assert!(kinds.contains(&Kind::Sealed), "{kinds:?}");
        assert!(kinds.contains(&Kind::Rewrapped), "{kinds:?}");

        // Without its KEK the ring does not open, and nothing is minted.
        drop(ring);
        let refused = opener(
            &volume,
            Custodian::new(|_| KeyCustody::File, Err("no KEK resolved".to_owned())),
        )
        .open(DATA_ATTEST, Suite::Ed25519Sha256V1, policy(), None)
        .expect_err("no KEK");
        assert!(
            format!("{refused}").contains("no KEK resolved"),
            "{refused}"
        );

        // Under other material with the same reference and version the ring does not open
        // either: the start opens every key it signs with, rather than the first signature.
        let refused = opener(
            &volume,
            file(Keks {
                current: kek("kek-b", 2, 9),
                previous: None,
            }),
        )
        .open(DATA_ATTEST, Suite::Ed25519Sha256V1, policy(), None)
        .expect_err("another KEK");
        assert!(matches!(refused, OpenError::Ring(_)), "{refused}");
        let _ = std::fs::remove_dir_all(root);
    }

    fn scratch(tag: &str) -> (std::path::PathBuf, Volume) {
        let root = std::env::temp_dir().join(format!(
            "permguard-host-ring-custody-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
        (root, volume)
    }

    /// WP-3.2 review: the sealing is journaled before it is done, so a crash between the two
    /// leaves the entry and a key the next start seals; a key the journal never named is sealed
    /// without an entry for a key that is not the ring's yet.
    #[test]
    fn a_crash_between_the_journal_and_the_sealing_seals_at_the_next_start() {
        let (root, volume) = scratch("crash");
        let ring = opener(&volume, Custodian::development())
            .open(DATA_ATTEST, Suite::Ed25519Sha256V1, policy(), None)
            .expect("opens");
        ring.maintain().expect("first");
        drop(ring);
        let dir = crate::keys::ring::directory(&volume, DATA_ATTEST).expect("dir");
        let private = dir
            .subdir(crate::keys::ring::PRIVATE, false)
            .expect("private");
        // A key generated before a crash, before its journal entry.
        crate::keys::FileKeyProvider::new(
            crate::storage::Dir::open(private.path()).expect("opens"),
        )
        .generate_addressed(Suite::Ed25519Sha256V1)
        .expect("generated");
        let keks = || Keks {
            current: kek("kek-a", 1, 1),
            previous: None,
        };
        let custodian = Custodian::new(|_| KeyCustody::File, Ok(Some(keks())));

        // The journal written, the sealing not: the crash.
        let stored = crate::keys::ring::stored_public(
            dir.subdir(crate::keys::ring::PUBLIC, false)
                .expect("public"),
        );
        let custodied = custodian
            .plan(
                DATA_ATTEST,
                [4; 16],
                private,
                stored,
                Suite::Ed25519Sha256V1,
            )
            .expect("planned");
        assert_eq!(custodied.plan.sealed.len(), 2);
        let ring = Ring::open_unchecked(
            crate::storage::Dir::open(dir.path()).expect("opens"),
            dir.subdir(crate::keys::ring::PUBLIC, false)
                .expect("public"),
            Arc::clone(&custodied.provider),
            DATA_ATTEST,
            Suite::Ed25519Sha256V1,
            policy(),
            Arc::new(TimeGuard::system(Duration::from_secs(30))),
        )
        .expect("opens");
        ring.note_custody(Kind::Sealed, &custodied.plan.sealed)
            .expect("journaled, the unknown key skipped");
        drop(ring);

        let ring = opener(
            &volume,
            Custodian::new(|_| KeyCustody::File, Ok(Some(keks()))),
        )
        .open(DATA_ATTEST, Suite::Ed25519Sha256V1, policy(), None)
        .expect("the next start seals");
        ring.sign(b"sealed").expect("signs");
        for slot in ring_slots(&root) {
            assert_ne!(
                std::fs::read(root.join(format!("host/keys/data.attest/private/{slot}")))
                    .expect("held")
                    .first(),
                Some(&0x30),
                "{slot} sealed at rest"
            );
        }
        let sealed = journal_entries(&dir)
            .expect("journal")
            .into_iter()
            .filter(|entry| entry.kind == Kind::Sealed)
            .count();
        assert_eq!(
            sealed, 2,
            "the entry of the crashed start and the next one's"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    /// A KEK that unwraps and refuses to wrap: the start fails between the journal and the seal.
    struct Refusing(Arc<dyn crate::keys::custody::Wrap>);

    impl crate::keys::custody::Wrap for Refusing {
        fn kek_ref(&self) -> &str {
            self.0.kek_ref()
        }
        fn kek_version(&self) -> u64 {
            self.0.kek_version()
        }
        fn wrap_algorithm(&self) -> &str {
            self.0.wrap_algorithm()
        }
        fn wrap(
            &self,
            _: &crate::keys::custody::Dek,
            _: &[u8],
        ) -> Result<Vec<u8>, crate::keys::custody::WrapError> {
            Err(crate::keys::custody::WrapError::Unavailable(
                "refused".to_owned(),
            ))
        }
        fn unwrap(
            &self,
            kek_version: u64,
            wrapped: &[u8],
            context: &[u8],
        ) -> Result<crate::keys::custody::Dek, crate::keys::custody::WrapError> {
            self.0.unwrap(kek_version, wrapped, context)
        }
    }

    /// WP-3.2 review: `Opener::open` journals the sealing before it seals. A sealing that fails
    /// leaves the entry, the key in plaintext and the start refused.
    #[test]
    fn the_opener_journals_the_sealing_before_it_seals() {
        let (root, volume) = scratch("order");
        let ring = opener(&volume, Custodian::development())
            .open(DATA_ATTEST, Suite::Ed25519Sha256V1, policy(), None)
            .expect("opens");
        ring.maintain().expect("first");
        drop(ring);

        let refused = opener(
            &volume,
            Custodian::new(
                |_| KeyCustody::File,
                Ok(Some(Keks {
                    current: Arc::new(Refusing(kek("kek-a", 1, 1))),
                    previous: None,
                })),
            ),
        )
        .open(DATA_ATTEST, Suite::Ed25519Sha256V1, policy(), None)
        .expect_err("the sealing fails");
        assert!(format!("{refused}").contains("refused"), "{refused}");
        let dir = crate::keys::ring::directory(&volume, DATA_ATTEST).expect("dir");
        let sealed = journal_entries(&dir)
            .expect("journal")
            .into_iter()
            .filter(|entry| entry.kind == Kind::Sealed)
            .count();
        assert_eq!(sealed, 1, "journaled before the sealing");
        for slot in ring_slots(&root) {
            assert_eq!(
                std::fs::read(root.join(format!("host/keys/data.attest/private/{slot}")))
                    .expect("held")
                    .first(),
                Some(&0x30),
                "{slot} still plaintext"
            );
        }
        let _ = std::fs::remove_dir_all(root);
    }

    /// WP-3.2 review: a sealed key the ring never published blocks neither a start nor a KEK
    /// rotation.
    #[test]
    fn an_orphan_sealed_key_blocks_no_start_and_no_rotation() {
        let (root, volume) = scratch("orphan");
        let file = |keks: Keks| Custodian::new(|_| KeyCustody::File, Ok(Some(keks)));
        let ring = opener(
            &volume,
            file(Keks {
                current: kek("kek-a", 1, 1),
                previous: None,
            }),
        )
        .open(DATA_ATTEST, Suite::Ed25519Sha256V1, policy(), None)
        .expect("opens");
        ring.maintain().expect("first");
        drop(ring);
        // A sealed key generated before a crash, before its public half was stored.
        let orphan = root.join("host/keys/data.attest/private/orphan.key");
        let held = ring_slots(&root);
        std::fs::copy(
            root.join(format!("host/keys/data.attest/private/{}", held[0])),
            &orphan,
        )
        .expect("copied");

        let ring = opener(
            &volume,
            file(Keks {
                current: kek("kek-b", 2, 2),
                previous: Some(kek("kek-a", 1, 1)),
            }),
        )
        .open(DATA_ATTEST, Suite::Ed25519Sha256V1, policy(), None)
        .expect("the rotation is not blocked");
        ring.sign(b"rotated").expect("signs");
        drop(ring);
        opener(
            &volume,
            file(Keks {
                current: kek("kek-b", 2, 2),
                previous: None,
            }),
        )
        .open(DATA_ATTEST, Suite::Ed25519Sha256V1, policy(), None)
        .expect("nor is the start without the previous KEK");
        let _ = std::fs::remove_dir_all(root);
    }

    fn ring_slots(root: &std::path::Path) -> Vec<String> {
        std::fs::read_dir(root.join("host/keys/data.attest/private"))
            .expect("listed")
            .map(|entry| {
                entry
                    .expect("an entry")
                    .file_name()
                    .into_string()
                    .expect("utf-8")
            })
            .filter(|name| name.ends_with(".key"))
            .collect()
    }

    /// WP-3.2 review: a public key copied over another slot's, or a private half swapped for
    /// another key, fails the start.
    #[test]
    fn a_substituted_public_or_private_half_fails_the_start() {
        let (root, volume) = scratch("swap");
        let ring = opener(&volume, Custodian::development())
            .open(DATA_ATTEST, Suite::Ed25519Sha256V1, policy(), None)
            .expect("opens");
        ring.maintain().expect("first");
        let slot = ring
            .active_key_id()
            .expect("active")
            .as_str()
            .split_once(':')
            .expect("a kid")
            .1
            .to_owned();
        drop(ring);
        let keys = root.join("host/keys/data.attest");
        let (stranger, _) =
            crate::keys::FileKeyProvider::new(crate::storage::Dir::open(&root).expect("opens"))
                .generate_addressed(Suite::Ed25519Sha256V1)
                .expect("generated");
        let original = std::fs::read(keys.join(format!("private/{slot}.key"))).expect("held");

        // The private half swapped: the development custody opens it and finds another key.
        std::fs::copy(
            root.join(format!("{stranger}.key")),
            keys.join(format!("private/{slot}.key")),
        )
        .expect("swapped");
        let refused = opener(&volume, Custodian::development())
            .open(DATA_ATTEST, Suite::Ed25519Sha256V1, policy(), None)
            .expect_err("another private half");
        assert!(format!("{refused}").contains("another key"), "{refused}");
        std::fs::write(keys.join(format!("private/{slot}.key")), &original).expect("restored");

        // The public key replaced: the sealing refuses a JWK that is not its name's key.
        let jwk = keys.join(format!("public/{slot}.jwk"));
        let held = std::fs::read_to_string(&jwk).expect("published");
        let mut forged: serde_json::Value = serde_json::from_str(&held).expect("a JWK");
        forged["x"] = serde_json::Value::String(base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            [9u8; 32],
        ));
        std::fs::write(&jwk, forged.to_string()).expect("forged");
        let refused = opener(
            &volume,
            Custodian::new(
                |_| KeyCustody::File,
                Ok(Some(Keks {
                    current: kek("kek-a", 1, 1),
                    previous: None,
                })),
            ),
        )
        .open(DATA_ATTEST, Suite::Ed25519Sha256V1, policy(), None)
        .expect_err("a forged public key");
        assert!(
            format!("{refused}").contains("another key than its name"),
            "{refused}"
        );
        let _ = std::fs::remove_dir_all(root);
    }
}
