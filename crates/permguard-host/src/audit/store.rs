// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The trails of a Host, as the audit engine reaches them (iteration 03, decision E33).
//!
//! The engine is one: what a record is, who may write it, what is sealed, what retention
//! deletes and what a query answers are the same on every backend. What differs is where the
//! trails rest and how one of them is held while it changes, and that is [`Trails`]. A trail
//! handed to the engine is a [`Trail`], whose bytes rest in a
//! [`TrailStore`](super::trail::TrailStore).
//!
//! | Backend                  | Keeps the trails in                                   |
//! | ------------------------ | ----------------------------------------------------- |
//! | [`FileTrails`], default  | `host/audit/trails/`, named in `host/audit/index/`    |

use std::collections::BTreeMap;
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use crate::storage::volume::Volume;
use crate::storage::{Dir, StorageError};

use std::sync::Arc;

use crate::time::TimeGuard;

use super::pseudonym::ResourcePseudonyms;
use super::trail::{self, Trail, TrailStore};
use super::{
    ACCESS_QUEUE, ActionSchema, Class, DIRECTORY, Engine, REGISTRY, Refused, Stamp, TRAILS, index,
    record,
};

/// One trail a listing found: its class, the digest it is kept under, and the resource it is
/// of or why it names none.
pub type Listed = (Class, String, Result<String, String>);

/// The trails of a Host: the only way the audit engine reaches one.
pub trait Trails: Send + Sync {
    /// Runs `work` on the trail of `(class, resource)`, opened, or created with `retention`,
    /// and held: of everything that changes one trail, on any instance, one runs at a time,
    /// each on the trail as the one before left it. A trail is known to [`Trails::held`]
    /// before its first record. `work` answers whether the trail is still as it says: one that
    /// is not is read again before it is handed to anything else. `work` may be run again when
    /// the backend could not keep what it did.
    fn hold(
        &self,
        class: Class,
        resource: &str,
        retention: Option<Duration>,
        work: &mut dyn FnMut(&mut Trail) -> bool,
    ) -> Result<(), String>;

    /// What the trail of `(class, resource)` is kept in, to read it; `None` when the Host holds
    /// no such trail.
    fn view(&self, class: Class, resource: &str) -> Result<Option<Box<dyn TrailStore>>, String>;

    /// Every trail the Host holds.
    fn held(&self) -> Result<Vec<Listed>, String>;
}

/// The trails of a volume.
#[derive(Debug)]
pub struct FileTrails {
    trails: Dir,
    /// The trails the volume ever held (BUG-0156), each named before its first record.
    index: Dir,
    open: Mutex<BTreeMap<(Class, String), Trail>>,
}

fn absent(error: &StorageError) -> bool {
    matches!(error, StorageError::Io { source, .. } if source.kind() == std::io::ErrorKind::NotFound)
}

impl FileTrails {
    /// The trails of `volume`, as a Host starts on the day file `day`: answers them with the
    /// trails the index names that the volume lacks, by `<class>:<resource>`. A trail the index
    /// names and the volume lacks was deleted whole: it is said now, and kept said, rather than
    /// recreated at sequence 0 as if it never existed (BUG-0156).
    pub fn open(volume: &Volume, day: &str) -> Result<(Self, Vec<String>), StorageError> {
        let audit = volume.host().subdir(DIRECTORY, true)?;
        let trails = audit.subdir(TRAILS, true)?;
        let index = audit.subdir(index::DIRECTORY, true)?;
        let lost = index::reconcile(&index, &trails, day)?;
        Ok((
            Self {
                trails,
                index,
                open: Mutex::new(BTreeMap::new()),
            },
            lost,
        ))
    }

    /// Holds the trails as the creation of one does: what a test takes to stand where a trail
    /// is being created.
    #[cfg(test)]
    pub(crate) fn creating(&self) -> std::sync::MutexGuard<'_, BTreeMap<(Class, String), Trail>> {
        self.open.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The directory the trails are below.
    pub fn root(&self) -> &Dir {
        &self.trails
    }
}

impl Trails for FileTrails {
    fn hold(
        &self,
        class: Class,
        resource: &str,
        retention: Option<Duration>,
        work: &mut dyn FnMut(&mut Trail) -> bool,
    ) -> Result<(), String> {
        let mut open = self.open.lock().unwrap_or_else(PoisonError::into_inner);
        let key = (class, resource.to_owned());
        if !open.contains_key(&key) {
            // Its directory, then its name in the index, then, by the caller, its first record:
            // no moment holds a record in a trail the index does not know (BUG-0156), and a
            // start that stopped between the two steps leaves a directory without a record,
            // which the next start names, never a name without its directory, which would be
            // read as a trail deleted whole and stay recorded lost for good.
            let trail = Trail::open(&self.trails, class, resource, retention)
                .map_err(|error| error.to_string())?;
            crate::storage::crash::point("audit.trail_created");
            index::record(&self.index, class, resource).map_err(|error| error.to_string())?;
            open.insert(key.clone(), trail);
        }
        let trail = open
            .get_mut(&key)
            .ok_or_else(|| "the trail vanished".to_owned())?;
        if !work(trail) {
            // Reopened at its next use: what a failed append left at the end of the day file
            // is a torn item there, which opening cuts, and the sequence continues from disk.
            open.remove(&key);
        }
        Ok(())
    }

    fn view(&self, class: Class, resource: &str) -> Result<Option<Box<dyn TrailStore>>, String> {
        match trail::directory(&self.trails, class, resource, false) {
            Ok(dir) => Ok(Some(Box::new(dir))),
            Err(error) if absent(&error) => Ok(None),
            Err(error) => Err(error.to_string()),
        }
    }

    fn held(&self) -> Result<Vec<Listed>, String> {
        // Listed with no trail being created: a listing never sees a directory before its name.
        let _creating = self.open.lock().unwrap_or_else(PoisonError::into_inner);
        let storage = |error: StorageError| error.to_string();
        let mut trails = Vec::new();
        for class_name in self.trails.subdirs().map_err(storage)? {
            let Some(class) = Class::parse(&class_name) else {
                continue;
            };
            let class_dir = self.trails.subdir(&class_name, false).map_err(storage)?;
            for digest in class_dir.subdirs().map_err(storage)? {
                let resource = class_dir
                    .subdir(&digest, false)
                    .and_then(|dir| dir.read(trail::META))
                    .map_err(|error| error.to_string())
                    .and_then(|meta| {
                        // A missing file is said to be missing, never decoded as an empty one
                        // and called corrupt (BUG-0078).
                        let meta = meta.ok_or_else(|| format!("its {} is missing", trail::META))?;
                        record::TrailMeta::decode(&meta).map_err(|error| error.to_string())
                    })
                    .and_then(|meta| {
                        // A `META.cbor` naming a resource kept elsewhere would open another trail.
                        if trail::resource_digest(&meta.resource) == digest {
                            Ok(meta.resource)
                        } else {
                            Err("its META.cbor names a resource kept under another digest"
                                .to_owned())
                        }
                    });
                trails.push((class, digest, resource));
            }
        }
        Ok(trails)
    }
}

/// The audit engine on the file backend: the trails of a volume under it.
impl Engine {
    /// The engine of the volume `volume` holds, with the process's registry.
    pub fn open(
        volume: &Volume,
        stamp: Stamp,
        time: Arc<TimeGuard>,
        pseudonyms: Option<ResourcePseudonyms>,
    ) -> Result<Self, Refused> {
        let engine = Self::with_registry(volume, REGISTRY, stamp, time, pseudonyms)?;
        engine.record_lost();
        Ok(engine)
    }

    /// The engine over `registry`, for a test that registers its own actions.
    pub fn with_registry(
        volume: &Volume,
        registry: &'static [ActionSchema],
        stamp: Stamp,
        time: Arc<TimeGuard>,
        pseudonyms: Option<ResourcePseudonyms>,
    ) -> Result<Self, Refused> {
        Self::with_queue(volume, registry, stamp, time, pseudonyms, ACCESS_QUEUE)
    }

    pub(crate) fn with_queue(
        volume: &Volume,
        registry: &'static [ActionSchema],
        stamp: Stamp,
        time: Arc<TimeGuard>,
        pseudonyms: Option<ResourcePseudonyms>,
        queue: usize,
    ) -> Result<Self, Refused> {
        let (trails, found_lost) = FileTrails::open(volume, &trail::day_name(time.now_secs()))
            .map_err(|error| Refused::Storage(error.to_string()))?;
        let trails = Arc::new(trails);
        #[cfg(test)]
        let files = Some(Arc::clone(&trails));
        #[allow(unused_mut)]
        let mut engine =
            Self::over_with_queue(trails, found_lost, registry, stamp, time, pseudonyms, queue)?;
        #[cfg(test)]
        {
            engine.files = files;
        }
        Ok(engine)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::sync::atomic::{AtomicUsize, Ordering};

    use permguard_core::assurance::AssuranceProfile;

    use super::*;

    /// The file backend passes the contract's suite, each case on a volume of its own.
    #[test]
    fn the_file_backend_keeps_the_contract() {
        let root = std::env::temp_dir().join(format!(
            "permguard-audit-trails-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let made = AtomicUsize::new(0);
        super::super::suite::run(&|| {
            let case = made.fetch_add(1, Ordering::Relaxed);
            let volume = Volume::claim(
                &root.join(format!("volume-{case}")),
                AssuranceProfile::Development,
            )
            .expect("claimed");
            let (trails, lost) = FileTrails::open(&volume, "2026-11-20.cborseq").expect("opens");
            assert!(lost.is_empty());
            Arc::new(trails)
        });
        let _ = std::fs::remove_dir_all(root);
    }
}
