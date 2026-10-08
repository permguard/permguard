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
        let mut opened = Ring::open(self.volume, ring, suite, policy, Arc::clone(&self.time))
            .map_err(OpenError::Ring)?;
        if let Some(binder) = &self.binder {
            opened = opened.with_binder(Arc::clone(binder));
        }
        if let Some(recorder) = &self.recorder {
            opened = opened.with_recorder(Arc::clone(recorder));
        }
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
