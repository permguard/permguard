// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What a Host's stores are made of on a backend that is not a volume (iteration 03, WP-28.1).
//!
//! On `files` a composition root opens every store from the volume it claimed. On
//! `postgresql-s3` it has no volume: a build hands it a [`Shared`], made by the adapter of that
//! backend over one database and one bucket, and every store of the Host comes from there. The
//! domain code is the same on both: it is given the store, never told which backend made it.
//!
//! | Store                         | Contract                                         |
//! | ----------------------------- | ------------------------------------------------ |
//! | the clock's high-water mark   | [`ClockMark`]                                    |
//! | the identity, its key slots   | [`IdentityStore`], [`SlotStore`]                 |
//! | the rings                     | [`Home`]                                         |
//! | the memberships               | [`MemberStore`]                                  |
//! | the peers' epochs             | [`SeenStore`]                                    |
//! | the witnesses, delivered keys | [`WitnessStore`], [`DeliveredKeys`], sealed      |
//! | the version witnesses         | [`VersionWitnesses`]                             |
//! | what is held of the authority | [`HeldStore`]                                    |
//! | the bootstrap commitment      | [`BootstrapStore`]                               |
//! | the holds, the plans          | [`HoldStore`], [`ReplayStore`]                   |
//! | the audit trails              | [`Trails`]                                       |
//! | the catalog                   | [`Catalog`](permguard_core::catalog::Catalog)    |
//! | the mutation engine           | [`Engine`], made over the audit's [`Projection`] |

use std::sync::Arc;

use crate::api::replay::ReplayStore;
use crate::audit::store::Trails;
use crate::authz::held::HeldStore;
use crate::authz::store::BootstrapStore;
use crate::holds::HoldStore;
use crate::identity::store::IdentityStore;
use crate::identity::witness::VersionWitnesses;
use crate::keys::registry::Home;
use crate::keys::slots::SlotStore;
use crate::membership::store::MemberStore;
use crate::operations::mutation::{Engine, Projection};
use crate::secrets::sealed::Sealer;
use crate::secrets::{DeliveredKeys, WitnessStore};
use crate::session::peers::SeenStore;
use crate::time::ClockMark;

/// The mutation engine of a backend, made once the audit engine it projects through exists.
pub type Mutations = Box<dyn Fn(Arc<dyn Projection>) -> Arc<dyn Engine> + Send + Sync>;

/// The delivered zone keys of a backend, sealed by what seals the Host's secrets: made once the
/// identity is open, since the seal binds its `host_id`.
pub type Delivered = Box<dyn Fn(Arc<Sealer>) -> Arc<dyn DeliveredKeys> + Send + Sync>;

/// The root the cursors of the Host's audit queries are issued under, sealed by what seals the
/// Host's secrets: one root every instance reads, minted once, so a cursor one instance issued
/// opens at another (iteration 03, WP-28.6).
pub type AuditCursorRoot =
    Box<dyn Fn(Arc<Sealer>) -> Result<zeroize::Zeroizing<Vec<u8>>, String> + Send + Sync>;

/// Every store of a Host on a shared backend, and the connection a Plane's server composes its
/// own stores over.
pub struct Shared {
    /// What the backend is, for a message: `postgresql-s3`.
    pub backend: &'static str,
    /// The id the identity is provisioned and opened under: the deployment's, kept by the
    /// backend, as a volume's id is on files.
    pub home: [u8; 16],
    pub clock_mark: Arc<dyn ClockMark>,
    pub identity: Arc<dyn IdentityStore>,
    pub identity_slots: Arc<dyn SlotStore>,
    pub rings: Arc<dyn Home + Send + Sync>,
    pub members: Arc<dyn MemberStore>,
    pub seen: Arc<dyn SeenStore>,
    pub witnesses: Arc<dyn WitnessStore>,
    pub delivered: Delivered,
    pub versions: Arc<dyn VersionWitnesses>,
    pub held: Arc<dyn HeldStore>,
    pub bootstrap: Arc<dyn BootstrapStore>,
    pub holds: Arc<dyn HoldStore>,
    pub plans: Arc<dyn ReplayStore>,
    pub trails: Arc<dyn Trails>,
    pub audit_cursor_root: AuditCursorRoot,
    /// The catalog of zones and ledgers the Control Plane serves.
    pub catalog: Arc<dyn permguard_core::catalog::Catalog>,
    pub mutations: Mutations,
    /// What the stores of other crates are made of over the same connection, each found by its
    /// type: the stream consumers' runs, a Plane's stores. Every store of the process is over the
    /// one database and the one bucket.
    pub handles: Vec<Arc<dyn std::any::Any + Send + Sync>>,
}

impl Shared {
    /// The mutation engine of an offline command on this backend, the server stopped: its
    /// records written by an audit engine over the backend's trails, under a start of its own
    /// drawn for its Host, as an offline command on files draws one.
    pub fn offline_engine(&self, build: &str) -> Result<Arc<dyn Engine>, String> {
        let time = Arc::new(crate::time::TimeGuard::system(
            std::time::Duration::from_secs(30),
        ));
        let revision = crate::audit::config_revision(std::iter::empty());
        // The Host the records are of: the identity's, once one is provisioned.
        let host = crate::identity::provisioned_in(self.identity.as_ref(), &self.home)
            .map_err(|error| error.to_string())?
            .map_or(self.home, |provisioned| provisioned.host_id);
        let stamp =
            crate::audit::Stamp::draw(host, build, revision).map_err(|error| error.to_string())?;
        let audit =
            crate::audit::Engine::over(Arc::clone(&self.trails), Vec::new(), stamp, time, None)
                .map_err(|error| error.to_string())?;
        Ok((self.mutations)(Arc::new(audit)))
    }

    /// The handle of type `T`, when the backend made one.
    pub fn handle<T: Send + Sync + 'static>(&self) -> Option<Arc<T>> {
        self.handles
            .iter()
            .find_map(|handle| Arc::clone(handle).downcast::<T>().ok())
    }
}

impl std::fmt::Debug for Shared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Shared")
            .field("backend", &self.backend)
            .finish_non_exhaustive()
    }
}
