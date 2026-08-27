// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The catalog on the local filesystem: directories named by GUID, indexes that are plain JSON.
//!
//! ```text
//! <root>/zones.json                      what zones exist — the "database" of zones
//! <root>/<zone-id>/ledgers.json          what ledgers that zone holds
//! <root>/<zone-id>/ledgers/<ledger-id>/  the ledger's own directory, empty today on purpose:
//!                                        it is where the ledger's contents will live when that
//!                                        design is made, and its address is already stable
//! ```
//!
//! # How consistency is kept, and what is deliberately not locked
//!
//! Reads never lock. Every index is replaced by writing a sibling and renaming it, so a reader gets
//! the old file or the new one and never half of either — the same discipline `ring.json` already
//! uses. What has to be serialised is the read-check-write of a mutation: two threads creating the
//! name `delivery` must not both find it absent. So mutations take a mutex, and the mutex is scoped to
//! what the mutation can actually damage:
//!
//! * zone mutations share one lock, because zone names are unique across the deployment;
//! * each zone's ledger mutations share a lock *of that zone's own*, because ledger names are unique
//!   only inside it — ledgers in two zones are created in parallel, and neither waits.
//!
//! Where an operation spans both — deleting a zone must prove it holds no ledgers — the zone lock is
//! taken first and the ledger lock second, always in that order, and the facts are re-read after
//! acquiring: the check and the act happen under the same locks or they prove nothing.
//!
//! Two *processes* maintaining one volume is the same question `ring.json` answers the same way:
//! this store has one maintaining process, and a deployment that wants replicas points them at a
//! catalog backed by something that arbitrates.
//!
//! # Ids
//!
//! UUIDv7: the first 48 bits are the creation time in milliseconds, the rest is random. Listing by
//! id is listing by age, which is why the indexes need no ordering of their own.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};

use permguard_core::catalog::{Catalog, CatalogError, Ledger, Selector, Zone, validate_name};

/// What the zone index file is called, beside the zone directories it describes.
const ZONES_FILE: &str = "zones.json";

/// What each zone's ledger index is called, inside the zone's directory.
const LEDGERS_FILE: &str = "ledgers.json";

/// Where a ledger's own contents will live, under its zone.
const LEDGERS_DIRECTORY: &str = "ledgers";

/// What these operations answer with.
type Result<T> = std::result::Result<T, CatalogError>;

/// The zone index, as it is written to disk.
#[derive(Debug, Serialize, Deserialize)]
struct ZoneIndex {
    /// The format this file is in, so a later version can recognise an earlier one.
    #[serde(default = "one")]
    version: u32,
    #[serde(default)]
    zones: Vec<Zone>,
}

/// One zone's ledger index.
#[derive(Debug, Serialize, Deserialize)]
struct LedgerIndex {
    #[serde(default = "one")]
    version: u32,
    #[serde(default)]
    ledgers: Vec<Ledger>,
}

// Not derived: a derive would zero the version, and an empty index is still format one.
impl Default for ZoneIndex {
    fn default() -> Self {
        Self {
            version: one(),
            zones: Vec::new(),
        }
    }
}

impl Default for LedgerIndex {
    fn default() -> Self {
        Self {
            version: one(),
            ledgers: Vec::new(),
        }
    }
}

fn one() -> u32 {
    1
}

/// A catalog kept in a directory.
pub struct FileCatalog {
    root: PathBuf,
    /// Serialises zone mutations: names are unique across the deployment, so their
    /// read-check-write is one critical section.
    zones_lock: Mutex<()>,
    /// One lock per zone, taken for that zone's ledger mutations and nothing else's.
    ledger_locks: Mutex<HashMap<String, Arc<Mutex<()>>>>,
}

impl FileCatalog {
    /// Builds a catalog over `root`, creating nothing until something is stored.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            zones_lock: Mutex::new(()),
            ledger_locks: Mutex::new(HashMap::new()),
        }
    }

    /// Returns the directory the catalog lives in.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The lock for one zone's ledger mutations, made on first use.
    fn ledger_lock(&self, zone_id: &str) -> Result<Arc<Mutex<()>>> {
        let mut locks = self
            .ledger_locks
            .lock()
            .map_err(|_| CatalogError::backend("the ledger lock table is poisoned"))?;

        Ok(Arc::clone(locks.entry(zone_id.to_owned()).or_default()))
    }

    fn zones_path(&self) -> PathBuf {
        self.root.join(ZONES_FILE)
    }

    fn zone_directory(&self, zone_id: &str) -> PathBuf {
        self.root.join(zone_id)
    }

    fn ledgers_path(&self, zone_id: &str) -> PathBuf {
        self.zone_directory(zone_id).join(LEDGERS_FILE)
    }

    fn ledger_directory(&self, zone_id: &str, ledger_id: &str) -> PathBuf {
        self.zone_directory(zone_id)
            .join(LEDGERS_DIRECTORY)
            .join(ledger_id)
    }

    /// Reads an index, treating an absent file as an empty one: a catalog nobody has written to is
    /// a catalog with nothing in it, not an error.
    fn read_index<T: Default + for<'de> Deserialize<'de>>(&self, path: &Path) -> Result<T> {
        let text = match fs::read_to_string(path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(T::default());
            }
            Err(error) => {
                return Err(CatalogError::backend(format!(
                    "reading {}: {error}",
                    path.display()
                )));
            }
        };

        serde_json::from_str(&text).map_err(|error| {
            CatalogError::backend(format!(
                "{} is not a catalog index: {error}",
                path.display()
            ))
        })
    }

    /// Replaces an index, so a reader sees one whole version or the other.
    fn write_index<T: Serialize>(&self, path: &Path, index: &T) -> Result<()> {
        if let Some(directory) = path.parent() {
            fs::create_dir_all(directory).map_err(|error| {
                CatalogError::backend(format!("creating {}: {error}", directory.display()))
            })?;
        }

        let text = serde_json::to_string_pretty(index)
            .map_err(|error| CatalogError::backend(format!("describing the index: {error}")))?;
        let staged = path.with_extension("json.tmp");

        fs::write(&staged, text.as_bytes()).map_err(|error| {
            CatalogError::backend(format!("writing {}: {error}", staged.display()))
        })?;
        fs::rename(&staged, path).map_err(|error| {
            CatalogError::backend(format!("replacing {}: {error}", path.display()))
        })
    }

    /// Finds a zone in the index, by whichever way the selector refers to it.
    fn find_zone<'a>(index: &'a ZoneIndex, zone: &Selector) -> Option<&'a Zone> {
        index.zones.iter().find(|candidate| match zone {
            Selector::Id(id) => candidate.id == *id,
            Selector::Name(name) => candidate.name == *name,
        })
    }

    fn find_ledger<'a>(index: &'a LedgerIndex, ledger: &Selector) -> Option<&'a Ledger> {
        index.ledgers.iter().find(|candidate| match ledger {
            Selector::Id(id) => candidate.id == *id,
            Selector::Name(name) => candidate.name == *name,
        })
    }

    /// The zone a selector refers to, or the error that says so.
    fn require_zone(&self, zone: &Selector) -> Result<Zone> {
        let index: ZoneIndex = self.read_index(&self.zones_path())?;

        Self::find_zone(&index, zone)
            .cloned()
            .ok_or_else(|| CatalogError::NotFound {
                kind: "zone",
                selector: zone.to_string(),
            })
    }
}

/// Seconds since the Unix epoch.
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

/// Mints a UUIDv7: creation time first, so ids sort by age.
fn guid() -> Result<String> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_millis()) as u64;

    let mut bytes = [0_u8; 16];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| CatalogError::backend("the system random number generator refused"))?;

    // The 48-bit timestamp, then version 7, then the RFC 9562 variant; the rest stays random.
    bytes[0] = (millis >> 40) as u8;
    bytes[1] = (millis >> 32) as u8;
    bytes[2] = (millis >> 24) as u8;
    bytes[3] = (millis >> 16) as u8;
    bytes[4] = (millis >> 8) as u8;
    bytes[5] = millis as u8;
    bytes[6] = (bytes[6] & 0x0f) | 0x70;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;

    let mut out = String::with_capacity(36);
    for (at, byte) in bytes.iter().enumerate() {
        if matches!(at, 4 | 6 | 8 | 10) {
            out.push('-');
        }
        out.push_str(&format!("{byte:02x}"));
    }

    Ok(out)
}

impl Catalog for FileCatalog {
    fn name(&self) -> &'static str {
        "directory"
    }

    fn create_zone(&self, name: &str) -> Result<Zone> {
        validate_name(name)?;

        let _guard = self
            .zones_lock
            .lock()
            .map_err(|_| CatalogError::backend("the zone lock is poisoned"))?;

        // Re-read inside the lock: the check and the write have to see the same world.
        let mut index: ZoneIndex = self.read_index(&self.zones_path())?;

        if index.zones.iter().any(|zone| zone.name == name) {
            return Err(CatalogError::NameTaken {
                name: name.to_owned(),
                scope: "this deployment's zones".to_owned(),
            });
        }

        let at = now();
        let zone = Zone {
            id: guid()?,
            name: name.to_owned(),
            created_at: at,
            updated_at: at,
        };

        // The zone's directory exists from birth, so everything that will live inside it — the
        // ledger index, the ledgers themselves — has a home whose address never changes.
        fs::create_dir_all(self.zone_directory(&zone.id).join(LEDGERS_DIRECTORY)).map_err(
            |error| CatalogError::backend(format!("creating the zone directory: {error}")),
        )?;

        index.zones.push(zone.clone());
        self.write_index(&self.zones_path(), &index)?;

        Ok(zone)
    }

    fn list_zones(&self) -> Result<Vec<Zone>> {
        Ok(self.read_index::<ZoneIndex>(&self.zones_path())?.zones)
    }

    fn get_zone(&self, zone: &Selector) -> Result<Zone> {
        self.require_zone(zone)
    }

    fn rename_zone(&self, zone: &Selector, name: &str) -> Result<Zone> {
        validate_name(name)?;

        let _guard = self
            .zones_lock
            .lock()
            .map_err(|_| CatalogError::backend("the zone lock is poisoned"))?;

        let mut index: ZoneIndex = self.read_index(&self.zones_path())?;

        if index.zones.iter().any(|candidate| {
            candidate.name == name && !matches!(zone, Selector::Id(id) if *id == candidate.id)
        }) {
            // Renaming a zone to its own name is a no-op, not a conflict with itself.
            let is_self = Self::find_zone(&index, zone).is_some_and(|found| found.name == name);

            if !is_self {
                return Err(CatalogError::NameTaken {
                    name: name.to_owned(),
                    scope: "this deployment's zones".to_owned(),
                });
            }
        }

        let found = index
            .zones
            .iter_mut()
            .find(|candidate| match zone {
                Selector::Id(id) => candidate.id == *id,
                Selector::Name(current) => candidate.name == *current,
            })
            .ok_or_else(|| CatalogError::NotFound {
                kind: "zone",
                selector: zone.to_string(),
            })?;

        found.name = name.to_owned();
        found.updated_at = now();

        let renamed = found.clone();
        self.write_index(&self.zones_path(), &index)?;

        Ok(renamed)
    }

    fn delete_zone(&self, zone: &Selector) -> Result<Zone> {
        let _zones = self
            .zones_lock
            .lock()
            .map_err(|_| CatalogError::backend("the zone lock is poisoned"))?;

        let mut index: ZoneIndex = self.read_index(&self.zones_path())?;
        let found =
            Self::find_zone(&index, zone)
                .cloned()
                .ok_or_else(|| CatalogError::NotFound {
                    kind: "zone",
                    selector: zone.to_string(),
                })?;

        // Zone lock first, this zone's ledger lock second — the same order everywhere, which is
        // what makes holding both deadlock-free. With both held, the emptiness check is a fact.
        let ledger_lock = self.ledger_lock(&found.id)?;
        let _ledgers = ledger_lock
            .lock()
            .map_err(|_| CatalogError::backend("the ledger lock is poisoned"))?;

        let ledgers: LedgerIndex = self.read_index(&self.ledgers_path(&found.id))?;

        if !ledgers.ledgers.is_empty() {
            return Err(CatalogError::NotEmpty {
                zone: found.name.clone(),
                ledgers: ledgers.ledgers.len(),
            });
        }

        index.zones.retain(|candidate| candidate.id != found.id);
        self.write_index(&self.zones_path(), &index)?;

        // The directory goes last: if this fails the zone is already out of the index, and a
        // leftover empty directory is debris, not a resurrection.
        if let Err(error) = fs::remove_dir_all(self.zone_directory(&found.id))
            && error.kind() != std::io::ErrorKind::NotFound
        {
            return Err(CatalogError::backend(format!(
                "removing the zone directory: {error}"
            )));
        }

        Ok(found)
    }

    fn create_ledger(&self, zone: &Selector, name: &str) -> Result<Ledger> {
        validate_name(name)?;

        let owner = self.require_zone(zone)?;
        let lock = self.ledger_lock(&owner.id)?;
        let _guard = lock
            .lock()
            .map_err(|_| CatalogError::backend("the ledger lock is poisoned"))?;

        // Re-proved under the lock: a concurrent zone deletion waits on this same lock, so after
        // acquiring it the zone either still exists or this create answers NotFound instead of
        // writing into a grave.
        self.require_zone(&Selector::Id(owner.id.clone()))?;

        let mut index: LedgerIndex = self.read_index(&self.ledgers_path(&owner.id))?;

        if index.ledgers.iter().any(|ledger| ledger.name == name) {
            return Err(CatalogError::NameTaken {
                name: name.to_owned(),
                scope: format!("the zone `{}`", owner.name),
            });
        }

        let at = now();
        let ledger = Ledger {
            id: guid()?,
            zone_id: owner.id.clone(),
            name: name.to_owned(),
            default_ref: "main".to_owned(),
            created_at: at,
            updated_at: at,
        };

        // Born with its own directory: the address of whatever a ledger will hold is part of
        // creating one, even while what it holds is still being designed.
        fs::create_dir_all(self.ledger_directory(&owner.id, &ledger.id)).map_err(|error| {
            CatalogError::backend(format!("creating the ledger directory: {error}"))
        })?;

        index.ledgers.push(ledger.clone());
        self.write_index(&self.ledgers_path(&owner.id), &index)?;

        Ok(ledger)
    }

    fn list_ledgers(&self, zone: &Selector) -> Result<Vec<Ledger>> {
        let owner = self.require_zone(zone)?;

        Ok(self
            .read_index::<LedgerIndex>(&self.ledgers_path(&owner.id))?
            .ledgers)
    }

    fn get_ledger(&self, zone: &Selector, ledger: &Selector) -> Result<Ledger> {
        let owner = self.require_zone(zone)?;
        let index: LedgerIndex = self.read_index(&self.ledgers_path(&owner.id))?;

        Self::find_ledger(&index, ledger)
            .cloned()
            .ok_or_else(|| CatalogError::NotFound {
                kind: "ledger",
                selector: ledger.to_string(),
            })
    }

    fn rename_ledger(&self, zone: &Selector, ledger: &Selector, name: &str) -> Result<Ledger> {
        validate_name(name)?;

        let owner = self.require_zone(zone)?;
        let lock = self.ledger_lock(&owner.id)?;
        let _guard = lock
            .lock()
            .map_err(|_| CatalogError::backend("the ledger lock is poisoned"))?;

        let mut index: LedgerIndex = self.read_index(&self.ledgers_path(&owner.id))?;
        let taken = index.ledgers.iter().any(|candidate| {
            candidate.name == name
                && !matches!(ledger, Selector::Id(id) if *id == candidate.id)
                && !matches!(ledger, Selector::Name(current) if *current == candidate.name)
        });

        if taken {
            return Err(CatalogError::NameTaken {
                name: name.to_owned(),
                scope: format!("the zone `{}`", owner.name),
            });
        }

        let found = index
            .ledgers
            .iter_mut()
            .find(|candidate| match ledger {
                Selector::Id(id) => candidate.id == *id,
                Selector::Name(current) => candidate.name == *current,
            })
            .ok_or_else(|| CatalogError::NotFound {
                kind: "ledger",
                selector: ledger.to_string(),
            })?;

        found.name = name.to_owned();
        found.updated_at = now();

        let renamed = found.clone();
        self.write_index(&self.ledgers_path(&owner.id), &index)?;

        Ok(renamed)
    }

    fn delete_ledger(&self, zone: &Selector, ledger: &Selector) -> Result<Ledger> {
        let owner = self.require_zone(zone)?;
        let lock = self.ledger_lock(&owner.id)?;
        let _guard = lock
            .lock()
            .map_err(|_| CatalogError::backend("the ledger lock is poisoned"))?;

        let mut index: LedgerIndex = self.read_index(&self.ledgers_path(&owner.id))?;
        let found =
            Self::find_ledger(&index, ledger)
                .cloned()
                .ok_or_else(|| CatalogError::NotFound {
                    kind: "ledger",
                    selector: ledger.to_string(),
                })?;

        index.ledgers.retain(|candidate| candidate.id != found.id);
        self.write_index(&self.ledgers_path(&owner.id), &index)?;

        if let Err(error) = fs::remove_dir_all(self.ledger_directory(&owner.id, &found.id))
            && error.kind() != std::io::ErrorKind::NotFound
        {
            return Err(CatalogError::backend(format!(
                "removing the ledger directory: {error}"
            )));
        }

        Ok(found)
    }
}
