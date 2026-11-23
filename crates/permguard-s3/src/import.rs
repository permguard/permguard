// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The import of a stopped volume into the `postgresql-s3` backend (iteration 03, WP-28.1): the
//! volume's layout read in this one place, each store carried by the importer WP-27.6 gave it,
//! under the names [`crate::backend`] keeps it under.
//!
//! | Step        | What it does                                                                         |
//! | ----------- | ------------------------------------------------------------------------------------ |
//! | at rest     | no mutation left open, no trail its index names lost: a start on files settles them  |
//! | into nothing | the deployment written as importing, the volume's id, refused over one already kept |
//! | stores      | each store read without writing and written in a transaction of its own              |
//! | completed   | the deployment cleared last: a start refuses a database an import did not complete   |
//!
//! What is not carried is what the backend's own rules leave behind (decision X117): what a deleted
//! zone or ledger left, temporaries, a frame's claim, and the Data Plane's state.

use std::sync::Arc;

use anyhow::{Context, Result, bail};

use permguard_core::Config;
use permguard_core::catalog::{Catalog as _, Selector};
use permguard_host::secrets::sealed::Sealer;
use permguard_host::storage::Dir;
use permguard_host::storage::volume::Volume;
use permguard_postgres as pg;

use crate::backend::Connected;

/// What one import carried: each store's name and how many records of it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Imported {
    /// The id the deployment keeps: the volume's.
    pub deployment: [u8; 16],
    /// Each store carried, in the order it was, and how many of its records.
    pub stores: Vec<(&'static str, usize)>,
}

impl Imported {
    fn carried(&mut self, store: &'static str, records: usize) {
        tracing::info!(
            event.name = "storage.import_store",
            component = "host",
            store,
            records,
            "a store of the volume was imported"
        );
        self.stores.push((store, records));
    }
}

/// An error as text: what a store answers that is not a [`std::error::Error`] of its own.
fn said<E: std::fmt::Display>(error: E) -> anyhow::Error {
    anyhow::anyhow!("{error}")
}

/// Imports `volume`, claimed by this process and at rest, into `connected`, which holds nothing:
/// every store a Control Plane or an Authority Plane keeps, as the volume kept it. `config` is
/// the server's on the backend, its working directory the volume's, and `sealer` seals the
/// secrets the backend keeps sealed, under the custody's key-encryption key.
pub fn volume(
    config: &Config,
    volume: &Volume,
    connected: &Connected,
    sealer: Arc<Sealer>,
) -> Result<Imported> {
    at_rest(volume)?;
    let database = &connected.database;
    let id = volume.id();
    if !pg::deployment::begin_import(database, &id).context("writing the deployment")? {
        bail!(
            "the database keeps a deployment already: a server started on it, or an import began; \
             a volume is imported into a database that holds nothing"
        );
    }
    let mut imported = Imported {
        deployment: id,
        stores: Vec::new(),
    };
    host(volume, connected, &sealer, &mut imported)?;
    control_plane(config, connected, &sealer, &mut imported)?;
    authority_plane(volume, database, &mut imported)?;
    streams(volume, connected, &mut imported)?;
    if !pg::deployment::complete_import(database, &id).context("completing the deployment")? {
        bail!("the database keeps no import of this volume under way: another wrote to it");
    }
    Ok(imported)
}

/// Refuses a volume a start on files has something left to settle on: an operation the mutation
/// engine began and did not end, or a trail its index names and the volume lacks.
fn at_rest(volume: &Volume) -> Result<()> {
    let mutations = permguard_host::operations::mutation::Mutations::open_offline(
        volume,
        permguard_core::build::VERSION,
    )
    .map_err(said)
    .context("opening the volume's mutation journal")?;
    let open = mutations.open_intents();
    if !open.is_empty() {
        bail!(
            "{} operation(s) began on the volume and did not end: start the server on files once, \
             so it settles them, then import",
            open.len()
        );
    }
    Ok(())
}

/// The Host's stores: its identity and keys, its memberships and peers, its secrets and trust,
/// its holds and plans, its clock and its trails.
fn host(
    volume: &Volume,
    connected: &Connected,
    sealer: &Arc<Sealer>,
    imported: &mut Imported,
) -> Result<()> {
    use permguard_host::keys::ring::HOST_IDENTITY;
    use permguard_host::keys::slots::copy_into as copy_slots;

    let database = &connected.database;
    let now = permguard_core::time::unix_now();

    let identity = permguard_host::identity::files::FileIdentity::open(volume)
        .map_err(said)
        .context("opening the identity")?;
    pg::identity::PostgresIdentity::new(database.clone())
        .import(&identity.export().map_err(said)?)
        .map_err(said)
        .context("importing the identity")?;
    imported.carried("identity", 1);
    let (_, keys) = permguard_host::identity::files::directories(volume)?;
    let slots = copy_slots(
        &permguard_host::keys::slots::files::FileSlots::new(keys),
        &pg::slots::PostgresSlots::new(database.clone(), HOST_IDENTITY),
    )
    .map_err(said)
    .context("importing the identity's key slots")?;
    imported.carried("identity key slots", slots);
    let (rings, ring_slots) = rings(volume, database)?;
    imported.carried("key rings", rings);
    imported.carried("key ring slots", ring_slots);

    let members = permguard_host::membership::files::FileMembers::open(volume)
        .map_err(said)
        .context("opening the memberships")?
        .copy_into(&pg::members::PostgresMembers::new(database.clone()))
        .map_err(said)
        .context("importing the memberships")?;
    imported.carried("memberships", members);
    let seen = pg::peers::PostgresSeen::new(database.clone())
        .import(
            &permguard_host::session::peers::files::FileSeen::open(volume)
                .map_err(said)?
                .export()
                .map_err(said)?,
        )
        .map_err(said)
        .context("importing the peers seen")?;
    imported.carried("peers seen", seen);

    let witnesses = pg::witnesses::PostgresWitnesses::new(database.clone())
        .import(
            &permguard_host::secrets::files::FileWitnesses::open(volume)
                .map_err(said)?
                .export()
                .map_err(said)?,
        )
        .map_err(said)
        .context("importing the secrets' witnesses")?;
    imported.carried("secret witnesses", witnesses);
    let delivered = permguard_host::secrets::files::FileDeliveredKeys::open(volume)
        .map_err(said)?
        .export()
        .map_err(said)?;
    let target = pg::delivered::PostgresDeliveredKeys::new(database.clone(), Arc::clone(sealer));
    for (tuple, key) in &delivered {
        permguard_host::secrets::DeliveredKeys::keep(&target, tuple, key)
            .map_err(said)
            .context("importing a delivered zone key")?;
    }
    imported.carried("delivered zone keys", delivered.len());
    let versions =
        permguard_host::identity::witness::files::FileVersionWitnesses::new(volume.root())
            .export()
            .map_err(said)?;
    let target = pg::witnesses::PostgresVersionWitnesses::new(database.clone());
    for (realm, entries) in &versions {
        target
            .import(realm.as_deref(), entries)
            .map_err(said)
            .context("importing the versions' witnesses")?;
    }
    imported.carried("version witnesses", versions.len());

    let held = permguard_host::authz::held::files::FileHeld::open(volume)?;
    let (carried, left) = permguard_host::authz::authority::carry_held(
        permguard_host::authz::held::HeldStore::keys(&held)
            .map_err(said)?
            .as_ref(),
        &held.export().map_err(said)?,
        &pg::held::PostgresHeld::new(database.clone()),
        now,
    )
    .map_err(said)
    .context("importing what the Host held of the Authority Plane")?;
    if left > 0 {
        tracing::warn!(
            event.name = "storage.import_left",
            component = "host",
            store = "held status lists",
            left,
            "status lists that do not verify under the held key set were not carried, as a \
             start does not restore them"
        );
    }
    imported.carried("held status lists", carried);
    let bootstrap = permguard_host::authz::store::BootstrapStore::bootstrap(
        &permguard_host::authz::store::files::FileBootstrap::open(volume).map_err(said)?,
    )
    .map_err(said)?;
    if let Some(commitment) = &bootstrap {
        pg::bootstrap::PostgresBootstrap::new(database.clone())
            .import(commitment)
            .map_err(said)
            .context("importing the bootstrap principal")?;
    }
    imported.carried("bootstrap principal", usize::from(bootstrap.is_some()));
    let holds = match permguard_host::holds::files::FileHolds::open_to_read(volume)? {
        Some(holds) => permguard_host::holds::HoldStore::list(&holds).map_err(said)?,
        None => Vec::new(),
    };
    let holds = pg::holds::PostgresHolds::new(database.clone())
        .import(&holds)
        .map_err(said)
        .context("importing the holds")?;
    imported.carried("holds", holds);
    let (replay, _) =
        permguard_host::api::replay::files::FileReplay::open(volume, now).map_err(said)?;
    let plans = pg::replay::PostgresReplay::new(database.clone())
        .import(&permguard_host::api::replay::ReplayStore::plans(&replay).map_err(said)?)
        .map_err(said)
        .context("importing the plans")?;
    imported.carried("plans", plans);

    use permguard_host::time::ClockMark as _;
    if let Some(mark) = permguard_host::time::files::FileClockMark::open(volume)?
        .read()
        .map_err(said)?
    {
        pg::time::PostgresClockMark::new(Arc::new(database.clone()), crate::backend::CLOCK_MARK)
            .raise(mark)
            .map_err(said)
            .context("importing the clock's mark")?;
    }
    imported.carried("clock mark", 1);

    let trails = trails(volume, connected)?;
    imported.carried("audit trails", trails);
    Ok(())
}

/// Every ring below `host/keys/`, its records and the slots of its private keys, each under the
/// ring's name; the retired rings' records go with the ring they were. Answers how many rings and
/// how many slots.
fn rings(volume: &Volume, database: &pg::Database) -> Result<(usize, usize)> {
    use permguard_host::keys::ring::files::{DIRECTORY, FileRing, PRIVATE, RETIRED};

    let Some(keys) = existing(volume.host(), DIRECTORY)? else {
        return Ok((0, 0));
    };
    let (mut rings, mut slots) = (0, 0);
    for ring in keys.subdirs()? {
        if ring == RETIRED {
            continue;
        }
        let dir = keys.subdir(&ring, false)?;
        let private = existing(&dir, PRIVATE)?;
        let records = FileRing::open(dir, &ring)
            .map_err(said)?
            .export()
            .map_err(said)
            .with_context(|| format!("reading the ring `{ring}`"))?;
        pg::ring::PostgresRing::new(database.clone(), &ring)
            .import(&records)
            .map_err(said)
            .with_context(|| format!("importing the ring `{ring}`"))?;
        if let Some(private) = private {
            slots += permguard_host::keys::slots::copy_into(
                &permguard_host::keys::slots::files::FileSlots::new(private),
                &pg::slots::PostgresSlots::new(database.clone(), &ring),
            )
            .map_err(said)
            .with_context(|| format!("importing the slots of the ring `{ring}`"))?;
        }
        rings += 1;
    }
    Ok((rings, slots))
}

/// Every audit trail of the volume, each as it was. A trail the volume's index names and the
/// volume lacks refuses: on files it is said at every start, and no record of it is carried.
fn trails(volume: &Volume, connected: &Connected) -> Result<usize> {
    use permguard_host::audit::store::{FileTrails, Trails as _};

    let day = permguard_host::audit::trail::day_name(permguard_core::time::unix_now());
    let (files, lost) = FileTrails::open(volume, &day)?;
    if !lost.is_empty() {
        bail!(
            "the volume's audit index names trails the volume lacks ({}): a trail deleted whole is \
             said at every start on files, and an import would carry nothing that says it",
            lost.join(", ")
        );
    }
    let target = pg::audit::PostgresTrails::new(connected.database.clone())
        .with_objects(Arc::new(connected.bucket.clone()));
    let mut carried = 0;
    for (class, digest, resource) in files.held().map_err(said)? {
        let resource = resource
            .map_err(said)
            .with_context(|| format!("the {} trail {digest}", class.as_str()))?;
        let Some(held) = files.view(class, &resource).map_err(said)? else {
            continue;
        };
        target
            .import(class, &resource, held.as_ref())
            .map_err(said)
            .with_context(|| format!("importing the {} trail of `{resource}`", class.as_str()))?;
        carried += 1;
    }
    Ok(carried)
}

/// The Control Plane's stores: the catalog, each live ledger with its objects, each live zone's
/// archives, and the cursor roots of its evidence stores.
fn control_plane(
    config: &Config,
    connected: &Connected,
    sealer: &Arc<Sealer>,
    imported: &mut Imported,
) -> Result<()> {
    use permguard_control_plane::catalog::archives::{ArchiveStore as _, FileArchives, Keeping};
    use permguard_control_plane::store::{FileLedgers, Ledgers as _, copy_objects};

    let database = &connected.database;
    let zones_root = config.zones_directory();
    let catalog = permguard_std::catalog::FileCatalog::new(&zones_root);
    pg::catalog::PostgresCatalog::new(database.clone())
        .import(&catalog.export().context("reading the catalog")?)
        .map_err(said)
        .context("importing the catalog")?;
    let zones = catalog.list_zones().map_err(said)?;
    imported.carried("zones", zones.len());

    let files = FileLedgers::new(zones_root.clone());
    let ledgers =
        crate::control_plane::PostgresLedgers::new(database.clone(), connected.bucket.clone());
    let archives = FileArchives::new(&zones_root);
    let kept =
        crate::control_plane::PostgresArchives::new(database.clone(), connected.bucket.clone());
    let (mut carried, mut objects, mut archived) = (0, 0, 0);
    for zone in &zones {
        for ledger in catalog
            .list_ledgers(&Selector::Id(zone.id.clone()))
            .map_err(said)?
        {
            let from = files.file(&zone.id, &ledger.id);
            let to = ledgers.ledger(&zone.id, &ledger.id);
            // The objects first: no ref names one the bucket lacks.
            objects += copy_objects(from.as_ref(), to.as_ref())
                .with_context(|| format!("publishing the objects of the ledger {}", ledger.id))?;
            ledgers
                .import(&zone.id, &ledger.id, &from.export()?)
                .with_context(|| format!("importing the ledger {}", ledger.id))?;
            carried += 1;
        }
        for (record, asked, archive) in archives.export(&zone.id).map_err(said)? {
            if kept
                .keep(&zone.id, &archive, &asked, &record)
                .map_err(said)
                .with_context(|| format!("importing the archive {}", record.id))?
                != Keeping::Kept
            {
                bail!(
                    "the archive {} was held already: an import writes into nothing",
                    record.id
                );
            }
            archived += 1;
        }
    }
    imported.carried("ledgers", carried);
    imported.carried("ledger objects", objects);
    imported.carried("archives", archived);

    let mut roots = 0;
    for (store, directory) in [
        (
            permguard_control_plane::plane::DECISIONS_API,
            config.working_dir().join(config.decision_store_directory()),
        ),
        (
            permguard_control_plane::plane::EVENTS_API,
            config.event_store_directory(),
        ),
    ] {
        if let Some(held) =
            permguard_control_plane::decisions::cursorkey::files::FileCursorRoots::new(&directory)
                .export()?
        {
            permguard_control_plane::decisions::cursorkey::postgres::PostgresCursorRoots::new(
                database.clone(),
                Arc::clone(sealer),
                store,
            )
            .import(&held)
            .with_context(|| format!("importing the cursor root of the {store} store"))?;
            roots += 1;
        }
    }
    imported.carried("cursor roots", roots);
    Ok(())
}

/// The Authority Plane's accounts, tokens and marks, from its directory of the volume. The
/// administrator's first secret and an offline mark stay where they are: files of the instance,
/// beside its configuration (decision X105).
fn authority_plane(
    volume: &Volume,
    database: &pg::Database,
    imported: &mut Imported,
) -> Result<()> {
    use permguard_authority_plane::marks::MarkStore as _;

    let directory = volume
        .root()
        .join(permguard_host::composition::PLANES)
        .join(permguard_authority_plane::PLANE);
    if !directory.is_dir() {
        imported.carried("service accounts", 0);
        imported.carried("tokens", 0);
        return Ok(());
    }
    let dir = Dir::open(&directory)?;
    let options = volume.journal_options(permguard_host::storage::journal::Options::default());
    let (accounts, _) =
        permguard_authority_plane::accounts::files::FileAccounts::open(&dir, options)
            .map_err(said)
            .context("opening the service accounts")?;
    let accounts = accounts.export().map_err(said)?;
    permguard_authority_plane::accounts::postgres::PostgresAccounts::new(database.clone())
        .import(&accounts)
        .map_err(said)
        .context("importing the service accounts")?;
    imported.carried("service accounts", accounts.accounts.len());
    let (tokens, _) = permguard_authority_plane::tokens::files::FileTokens::open(&dir, options)
        .map_err(said)
        .context("opening the tokens")?;
    let tokens = tokens.export();
    permguard_authority_plane::tokens::postgres::PostgresTokens::new(database.clone())
        .import(&tokens)
        .map_err(said)
        .context("importing the tokens")?;
    imported.carried("tokens", tokens.tokens.len());
    let marks = permguard_authority_plane::marks::files::FileMarks::new(dir).held();
    permguard_authority_plane::tokens::postgres::PostgresMarks::new(database.clone())
        .keep(&marks)
        .map_err(said)
        .context("importing the status lists' marks")?;
    imported.carried("status list marks", marks.len());
    Ok(())
}

/// Every stream consumer's runs, below `host/streams/<plane>/<type>/<version>/consumer`, each
/// under the name the backend keeps its consumer's runs under. A producer is the Data Plane's,
/// and stays on files (decision X103).
fn streams(volume: &Volume, connected: &Connected, imported: &mut Imported) -> Result<()> {
    use permguard_stream::engine::consumer::export;
    use permguard_stream::engine::consumer::store::FileRuns;

    let mut consumers = 0;
    if let Some(streams) = existing(volume.host(), permguard_stream::engine::STREAMS)? {
        for plane in streams.subdirs()? {
            let plane_dir = streams.subdir(&plane, false)?;
            for stream_type in plane_dir.subdirs()? {
                let type_dir = plane_dir.subdir(&stream_type, false)?;
                for version in type_dir.subdirs()? {
                    let Some(consumer) = existing(&type_dir.subdir(&version, false)?, CONSUMER)?
                    else {
                        continue;
                    };
                    let files = FileRuns::new(
                        consumer,
                        volume.generation(),
                        permguard_host::storage::journal::DEFAULT_SEGMENT_BYTES,
                    );
                    let name = crate::backend::consumer(&plane, &stream_type, &version);
                    crate::streams::PostgresRuns::new(
                        connected.database.clone(),
                        connected.bucket.clone(),
                        &name,
                    )
                    .import(&export(&files).map_err(said)?)
                    .map_err(said)
                    .with_context(|| format!("importing the runs of the consumer `{name}`"))?;
                    consumers += 1;
                }
            }
        }
    }
    imported.carried("stream consumers", consumers);
    Ok(())
}

/// The role directory of a stream's consumer, below its version.
const CONSUMER: &str = "consumer";

/// The subdirectory `name` of `dir`, when there is one: nothing is created on the volume.
fn existing(dir: &Dir, name: &str) -> Result<Option<Dir>> {
    if !dir.child_path(name).is_dir() {
        return Ok(None);
    }
    Ok(Some(dir.subdir(name, false)?))
}
