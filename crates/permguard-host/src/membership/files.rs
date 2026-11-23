// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The file backend of [`MemberStore`]: `host/members/` on the volume.
//!
//! ```text
//! host/members/
//! ├── FORMAT                             the layout version, 1
//! ├── journal.cborseq                    authoritative, hash-chained transitions
//! ├── snapshot.cbor                      rebuildable summary, replaced atomically
//! ├── invites/<invite_id>.cbor           the invitation; never the token
//! ├── manifests/<membership_id>/
//! │   ├── current.cose
//! │   └── history/<epoch>-<digest>.cose
//! ├── leases/<membership_id>/<task_id>.cose
//! ├── progress/<membership_id>/
//! │   ├── <task_id>.cbor                 the last report, with the coordinator's received_at
//! │   ├── <task_id>.session              the last session leased for the task
//! │   ├── <task_id>.<sha256(resource)>.zone   a zone receipt
//! │   └── manifest.delivered             the last manifest epoch delivered
//! ├── replay/<membership_id>/<task_id>/0000.cbor … 1023.cbor
//! ├── verifications/<membership_id>      a coordinator's pending proof request
//! │   └── results/<operation_id>         immutable exact answers for recovery and replay
//! ├── egress/<membership_id>-<task_id>.cbor   the member's acknowledgements
//! └── audit/<membership_id>/<sha256(trail)>/
//!     ├── META, LAST, ANCHOR, FORKED
//!     └── <count, 20 digits>.cose        a kept checkpoint, the envelope itself
//! ```
//!
//! Every document is a view of the storage library, replaced whole; a kept checkpoint is the
//! envelope itself, published without replacement (BUG-0155), or the view an earlier build wrote.

use std::sync::{Arc, Mutex, PoisonError};

use permguard_core::encoding::hex;
use permguard_objects::cbor::Value;
use sha2::{Digest as _, Sha256};

use super::store::{Change, Doc, Listed, Listing, MemberStore};
use super::{MembershipError, Store, record};
use crate::storage::dir::TEMP_PREFIX;
use crate::storage::volume::Volume;
use crate::storage::write::{Published, publish_immutable, read_view, replace_view};
use crate::storage::{Dir, StorageError, crash, format, sequence, tombstone};

/// The directory below `host/`.
pub const DIRECTORY: &str = "members";
pub const FORMAT: &str = "FORMAT";
pub const JOURNAL: &str = "journal.cborseq";
pub const SNAPSHOT: &str = "snapshot.cbor";
pub const INVITES: &str = "invites";
pub const MANIFESTS: &str = "manifests";
pub const CURRENT: &str = "current.cose";
pub const HISTORY: &str = "history";
/// The leases a member holds, one per task: `leases/<membership_id>/<task_id>.cose` (WP-4.3).
pub const LEASES: &str = "leases";
/// Durable coordinator requests for the next proven inbound session, by membership id (WP-4.8).
pub const VERIFICATIONS: &str = "verifications";
/// Immutable verification results by operation id, separate from consumable pending markers.
pub const VERIFICATION_RESULTS: &str = "results";
/// The layout version `FORMAT` holds.
pub const LAYOUT_VERSION: u64 = 1;
/// The directory of what a coordinator observed of its members' tasks.
pub const PROGRESS: &str = "progress";
/// The directory of the replay windows.
pub const REPLAY: &str = "replay";
const AUDIT: &str = "audit";
const EGRESS: &str = "egress";
const META: &str = "META";
const LAST: &str = "LAST";
const ANCHOR: &str = "ANCHOR";
const FORKED: &str = "FORKED";
const DELIVERED: &str = "manifest.delivered";
const ZONE_RECEIPT: &str = "zone";

impl From<StorageError> for MembershipError {
    fn from(error: StorageError) -> Self {
        Self::Storage(error.to_string())
    }
}

/// The name of a zone receipt: `<task_id>.<sha256(resource)>.zone`.
fn receipt_name(task: &str, resource: &str) -> String {
    format!(
        "{task}.{}.{ZONE_RECEIPT}",
        hex(&Sha256::digest(resource.as_bytes()))
    )
}

/// The name of a replay slot.
fn slot_name(slot: u64) -> String {
    format!("{slot:04}.cbor")
}

/// The name of a kept checkpoint.
fn checkpoint_name(count: u64) -> String {
    format!("{count:020}.cose")
}

/// The memberships of one volume.
pub struct FileMembers {
    dir: Dir,
    /// How many entries are held, from the read that counted them to the write that adds one.
    held: Mutex<u64>,
    /// Held while a document is changed in place, from its read to its write.
    changing: Mutex<()>,
}

impl std::fmt::Debug for FileMembers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileMembers")
            .field("dir", &self.dir.path())
            .finish_non_exhaustive()
    }
}

/// Where a document is, and whether its directory is made when it is read: three kinds always
/// made theirs at a read, and still do.
struct Place {
    path: Vec<String>,
    name: String,
    made_at_read: bool,
}

fn place(doc: &Doc<'_>) -> Place {
    let trail_dir = |membership: &[u8; 16], trail: &str| {
        vec![
            AUDIT.to_owned(),
            hex(membership),
            hex(&Sha256::digest(trail.as_bytes())),
        ]
    };
    let (path, name, made_at_read) = match *doc {
        Doc::Lease { membership, task } => (
            vec![LEASES.to_owned(), hex(membership)],
            format!("{task}.cose"),
            false,
        ),
        Doc::Progress { membership, task } => (
            vec![PROGRESS.to_owned(), hex(membership)],
            format!("{task}.cbor"),
            false,
        ),
        Doc::Session { membership, task } => (
            vec![PROGRESS.to_owned(), hex(membership)],
            format!("{task}.session"),
            false,
        ),
        Doc::Delivered { membership } => (
            vec![PROGRESS.to_owned(), hex(membership)],
            DELIVERED.to_owned(),
            false,
        ),
        Doc::ZoneReceipt {
            membership,
            task,
            resource,
        } => (
            vec![PROGRESS.to_owned(), hex(membership)],
            receipt_name(task, resource),
            false,
        ),
        Doc::ReplaySlot {
            membership,
            task,
            slot,
        } => (
            vec![REPLAY.to_owned(), hex(membership), task.to_owned()],
            slot_name(slot),
            true,
        ),
        Doc::Verification { membership } => {
            (vec![VERIFICATIONS.to_owned()], hex(membership), false)
        }
        Doc::VerificationResult { operation } => (
            vec![VERIFICATIONS.to_owned(), VERIFICATION_RESULTS.to_owned()],
            hex(operation),
            false,
        ),
        Doc::Acks { membership, task } => (
            vec![EGRESS.to_owned()],
            format!("{}-{task}.cbor", hex(membership)),
            true,
        ),
        Doc::TrailName { membership, trail } => {
            (trail_dir(membership, trail), META.to_owned(), false)
        }
        Doc::TrailLast { membership, trail } => {
            (trail_dir(membership, trail), LAST.to_owned(), false)
        }
        Doc::TrailAnchor { membership, trail } => {
            (trail_dir(membership, trail), ANCHOR.to_owned(), false)
        }
        Doc::TrailFork { membership, trail } => {
            (trail_dir(membership, trail), FORKED.to_owned(), false)
        }
    };
    Place {
        path,
        name,
        made_at_read,
    }
}

impl FileMembers {
    /// `host/members/` of `volume`, laid out when absent: a layout this build does not read
    /// refuses the open, and an entry a process that stopped left half written is cut.
    pub fn open(volume: &Volume) -> Result<Self, MembershipError> {
        let dir = volume.host().subdir(DIRECTORY, true)?;
        match read_view(&dir, FORMAT, format::VIEW)? {
            None => replace_view(&dir, FORMAT, format::VIEW, &LAYOUT_VERSION.to_be_bytes())?,
            Some(bytes) if bytes == LAYOUT_VERSION.to_be_bytes() => {}
            Some(_) => {
                return Err(MembershipError::Storage(format!(
                    "{} is a layout this build does not read",
                    dir.child_path(FORMAT).display()
                )));
            }
        }
        dir.subdir(INVITES, true)?;
        dir.subdir(MANIFESTS, true)?;
        let held = sequence::recover(&dir, JOURNAL, record::MAX_RECORD_BYTES * 2)?
            .items
            .len() as u64;
        Ok(Self {
            dir,
            held: Mutex::new(held),
            changing: Mutex::new(()),
        })
    }

    /// The directory `path` names below the store's, each part made when absent and `create`;
    /// `None` when a part is absent and it is not.
    fn below(&self, path: &[String], create: bool) -> Result<Option<Dir>, StorageError> {
        let mut found: Option<Dir> = None;
        for part in path {
            let parent = found.as_ref().unwrap_or(&self.dir);
            if !create && !parent.subdirs()?.iter().any(|held| held == part) {
                return Ok(None);
            }
            found = Some(parent.subdir(part, create)?);
        }
        Ok(found)
    }

    fn read(&self, doc: &Doc<'_>) -> Result<Option<Vec<u8>>, MembershipError> {
        let place = place(doc);
        // The trails' directory itself was always made by a read of what it holds.
        if place.path.first().is_some_and(|part| part == AUDIT) {
            self.dir.subdir(AUDIT, true)?;
        }
        let Some(dir) = self.below(&place.path, place.made_at_read)? else {
            return Ok(None);
        };
        Ok(read_view(&dir, &place.name, format::VIEW)?)
    }

    fn write(&self, doc: &Doc<'_>, bytes: &[u8]) -> Result<(), MembershipError> {
        let place = place(doc);
        let dir = self
            .below(&place.path, true)?
            .ok_or_else(|| MembershipError::Storage("a document's directory".to_owned()))?;
        Ok(replace_view(&dir, &place.name, format::VIEW, bytes)?)
    }

    fn trail(
        &self,
        membership: &[u8; 16],
        trail: &str,
        create: bool,
    ) -> Result<Option<Dir>, StorageError> {
        self.dir.subdir(AUDIT, true)?;
        self.below(
            &[
                AUDIT.to_owned(),
                hex(membership),
                hex(&Sha256::digest(trail.as_bytes())),
            ],
            create,
        )
    }
}

/// The id `text` names: 32 lowercase hexadecimal characters, as [`hex`] writes them.
fn id_of(text: &str) -> Option<[u8; 16]> {
    if text.len() != 32 {
        return None;
    }
    let mut id = [0_u8; 16];
    for (at, byte) in id.iter_mut().enumerate() {
        *byte = u8::from_str_radix(text.get(at * 2..at * 2 + 2)?, 16).ok()?;
    }
    (hex(&id) == text).then_some(id)
}

impl FileMembers {
    /// Writes everything these memberships hold into `to` through its contract, the volume left
    /// as it was: what an import carries to another backend (iteration 03, WP-27.6). Answers how
    /// many records were carried.
    ///
    /// A temporary file is an unfinished write and is not carried; any other file this layout
    /// does not name refuses, so nothing the volume holds is dropped unseen.
    pub fn copy_into(&self, to: &dyn MemberStore) -> Result<usize, MembershipError> {
        let unexpected = |path: &str| {
            MembershipError::Storage(format!("{path} is no record of the memberships"))
        };
        let names = |dir: &Dir| -> Result<Vec<String>, MembershipError> {
            Ok(dir
                .names()?
                .into_iter()
                .filter(|name| !name.starts_with(TEMP_PREFIX))
                .collect())
        };
        let view = |dir: &Dir, name: &str| -> Result<Vec<u8>, MembershipError> {
            read_view(dir, name, format::VIEW)?
                .ok_or_else(|| MembershipError::Storage(format!("{name} vanished")))
        };
        let subdir = |name: &str| -> Result<Option<Dir>, MembershipError> {
            Ok(self.below(&[name.to_owned()], false)?)
        };
        let mut carried = 0;

        let entries = sequence::read(&self.dir, JOURNAL, record::MAX_RECORD_BYTES * 2)?.items;
        for (seq, entry) in (1_u64..).zip(&entries) {
            let bytes = permguard_objects::cbor::encode(entry).map_err(|error| {
                MembershipError::Storage(format!("an entry does not encode: {error:?}"))
            })?;
            to.append(seq, &bytes)?;
            carried += 1;
        }
        for name in names(&self.dir)? {
            match name.as_str() {
                FORMAT | JOURNAL => {}
                SNAPSHOT => {
                    to.replace_summary(&view(&self.dir, SNAPSHOT)?)?;
                    carried += 1;
                }
                _ => return Err(unexpected(&name)),
            }
        }

        if let Some(manifests) = subdir(MANIFESTS)? {
            for member in manifests.subdirs()? {
                let membership = id_of(&member).ok_or_else(|| unexpected(&member))?;
                let dir = manifests.subdir(&member, false)?;
                let mut kept = Vec::new();
                if dir.subdirs()?.iter().any(|name| name == HISTORY) {
                    let history = dir.subdir(HISTORY, false)?;
                    for name in names(&history)? {
                        let (epoch, digest) = name
                            .strip_suffix(".cose")
                            .and_then(|stem| stem.split_once('-'))
                            .and_then(|(epoch, digest)| Some((epoch.parse::<u64>().ok()?, digest)))
                            .ok_or_else(|| unexpected(&name))?;
                        kept.push((epoch, digest.to_owned(), view(&history, &name)?));
                    }
                }
                // Oldest first: the current manifest is the one of the highest epoch.
                kept.sort();
                for (epoch, digest, envelope) in kept {
                    to.keep_manifest(&membership, epoch, &digest, &envelope)?;
                    carried += 1;
                }
            }
        }
        if let Some(invites) = subdir(INVITES)? {
            for name in names(&invites)? {
                let invite = name
                    .strip_suffix(".cbor")
                    .and_then(id_of)
                    .ok_or_else(|| unexpected(&name))?;
                to.keep_invitation(&invite, &view(&invites, &name)?)?;
                carried += 1;
            }
        }

        let mut documents: Vec<(Vec<u8>, DocOwned)> = Vec::new();
        if let Some(leases) = subdir(LEASES)? {
            for member in leases.subdirs()? {
                let membership = id_of(&member).ok_or_else(|| unexpected(&member))?;
                let dir = leases.subdir(&member, false)?;
                for name in names(&dir)? {
                    let task = name
                        .strip_suffix(".cose")
                        .ok_or_else(|| unexpected(&name))?;
                    documents.push((view(&dir, &name)?, DocOwned::Lease(membership, task.into())));
                }
            }
        }
        if let Some(progress) = subdir(PROGRESS)? {
            for member in progress.subdirs()? {
                let membership = id_of(&member).ok_or_else(|| unexpected(&member))?;
                let dir = progress.subdir(&member, false)?;
                for name in names(&dir)? {
                    let bytes = view(&dir, &name)?;
                    let doc = if name == DELIVERED {
                        DocOwned::Delivered(membership)
                    } else if let Some(stem) = name.strip_suffix(&format!(".{ZONE_RECEIPT}")) {
                        let (task, digest) =
                            stem.rsplit_once('.').ok_or_else(|| unexpected(&name))?;
                        let resource = super::zone::Receipt::decode(&bytes)?.resource;
                        if hex(&Sha256::digest(resource.as_bytes())) != digest {
                            return Err(unexpected(&name));
                        }
                        DocOwned::ZoneReceipt(membership, task.into(), resource)
                    } else if let Some(task) = name.strip_suffix(".session") {
                        DocOwned::Session(membership, task.into())
                    } else if let Some(task) = name.strip_suffix(".cbor") {
                        DocOwned::Progress(membership, task.into())
                    } else {
                        return Err(unexpected(&name));
                    };
                    documents.push((bytes, doc));
                }
            }
        }
        if let Some(replay) = subdir(REPLAY)? {
            for member in replay.subdirs()? {
                let membership = id_of(&member).ok_or_else(|| unexpected(&member))?;
                let tasks = replay.subdir(&member, false)?;
                for task in tasks.subdirs()? {
                    let dir = tasks.subdir(&task, false)?;
                    for name in names(&dir)? {
                        let slot = name
                            .strip_suffix(".cbor")
                            .filter(|digits| digits.len() == 4)
                            .and_then(|digits| digits.parse::<u64>().ok())
                            .ok_or_else(|| unexpected(&name))?;
                        documents.push((
                            view(&dir, &name)?,
                            DocOwned::ReplaySlot(membership, task.clone(), slot),
                        ));
                    }
                }
            }
        }
        if let Some(verifications) = subdir(VERIFICATIONS)? {
            for name in names(&verifications)? {
                let membership = id_of(&name).ok_or_else(|| unexpected(&name))?;
                documents.push((
                    view(&verifications, &name)?,
                    DocOwned::Verification(membership),
                ));
            }
            for sub in verifications.subdirs()? {
                if sub != VERIFICATION_RESULTS {
                    return Err(unexpected(&sub));
                }
                let results = verifications.subdir(&sub, false)?;
                for name in names(&results)? {
                    let operation = id_of(&name).ok_or_else(|| unexpected(&name))?;
                    documents.push((
                        view(&results, &name)?,
                        DocOwned::VerificationResult(operation),
                    ));
                }
            }
        }
        if let Some(egress) = subdir(EGRESS)? {
            for name in names(&egress)? {
                let (membership, task) = name
                    .strip_suffix(".cbor")
                    .and_then(|stem| stem.get(..32).zip(stem.get(32..)))
                    .and_then(|(id, rest)| Some((id_of(id)?, rest.strip_prefix('-')?)))
                    .ok_or_else(|| unexpected(&name))?;
                documents.push((
                    view(&egress, &name)?,
                    DocOwned::Acks(membership, task.into()),
                ));
            }
        }
        let mut checkpoints = Vec::new();
        if let Some(audit) = subdir(AUDIT)? {
            for member in audit.subdirs()? {
                let membership = id_of(&member).ok_or_else(|| unexpected(&member))?;
                let trails = audit.subdir(&member, false)?;
                for digest in trails.subdirs()? {
                    let dir = trails.subdir(&digest, false)?;
                    // A trail's directory is named by its name's digest, which its `META` holds.
                    let trail = String::from_utf8(view(&dir, META)?)
                        .ok()
                        .filter(|trail| hex(&Sha256::digest(trail.as_bytes())) == digest)
                        .ok_or_else(|| unexpected(&digest))?;
                    for name in names(&dir)? {
                        let doc = match name.as_str() {
                            META => DocOwned::TrailName(membership, trail.clone()),
                            LAST => DocOwned::TrailLast(membership, trail.clone()),
                            ANCHOR => DocOwned::TrailAnchor(membership, trail.clone()),
                            FORKED => DocOwned::TrailFork(membership, trail.clone()),
                            _ => {
                                let count = name
                                    .strip_suffix(".cose")
                                    .filter(|digits| digits.len() == 20)
                                    .and_then(|digits| digits.parse::<u64>().ok())
                                    .filter(|count| *count > 0)
                                    .ok_or_else(|| unexpected(&name))?;
                                let envelope = self
                                    .checkpoint(&membership, &trail, count)?
                                    .ok_or_else(|| unexpected(&name))?;
                                checkpoints.push((membership, trail.clone(), count, envelope));
                                continue;
                            }
                        };
                        documents.push((view(&dir, &name)?, doc));
                    }
                }
            }
        }
        for sub in self.dir.subdirs()? {
            if ![
                MANIFESTS,
                INVITES,
                LEASES,
                PROGRESS,
                REPLAY,
                VERIFICATIONS,
                EGRESS,
                AUDIT,
            ]
            .contains(&sub.as_str())
            {
                return Err(unexpected(&sub));
            }
        }
        for (bytes, doc) in &documents {
            to.keep(&doc.borrowed(), bytes)?;
            carried += 1;
        }
        for (membership, trail, count, envelope) in &checkpoints {
            to.publish_checkpoint(membership, trail, *count, envelope)?;
            carried += 1;
        }
        Ok(carried)
    }
}

/// A [`Doc`] that owns what names it: what [`FileMembers::copy_into`] reads before it writes.
enum DocOwned {
    Lease([u8; 16], String),
    Progress([u8; 16], String),
    Session([u8; 16], String),
    Delivered([u8; 16]),
    ZoneReceipt([u8; 16], String, String),
    ReplaySlot([u8; 16], String, u64),
    Verification([u8; 16]),
    VerificationResult([u8; 16]),
    Acks([u8; 16], String),
    TrailName([u8; 16], String),
    TrailLast([u8; 16], String),
    TrailAnchor([u8; 16], String),
    TrailFork([u8; 16], String),
}

impl DocOwned {
    fn borrowed(&self) -> Doc<'_> {
        match self {
            Self::Lease(membership, task) => Doc::Lease { membership, task },
            Self::Progress(membership, task) => Doc::Progress { membership, task },
            Self::Session(membership, task) => Doc::Session { membership, task },
            Self::Delivered(membership) => Doc::Delivered { membership },
            Self::ZoneReceipt(membership, task, resource) => Doc::ZoneReceipt {
                membership,
                task,
                resource,
            },
            Self::ReplaySlot(membership, task, slot) => Doc::ReplaySlot {
                membership,
                task,
                slot: *slot,
            },
            Self::Verification(membership) => Doc::Verification { membership },
            Self::VerificationResult(operation) => Doc::VerificationResult { operation },
            Self::Acks(membership, task) => Doc::Acks { membership, task },
            Self::TrailName(membership, trail) => Doc::TrailName { membership, trail },
            Self::TrailLast(membership, trail) => Doc::TrailLast { membership, trail },
            Self::TrailAnchor(membership, trail) => Doc::TrailAnchor { membership, trail },
            Self::TrailFork(membership, trail) => Doc::TrailFork { membership, trail },
        }
    }
}

impl MemberStore for FileMembers {
    fn entries(&self) -> Result<Vec<Value>, MembershipError> {
        // Counted under the same hold as an entry is added.
        let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        let items = sequence::read(&self.dir, JOURNAL, record::MAX_RECORD_BYTES * 2)?.items;
        *held = items.len() as u64;
        Ok(items)
    }

    fn append(&self, seq: u64, entry: &[u8]) -> Result<(), MembershipError> {
        let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        if seq != held.saturating_add(1) {
            return Err(MembershipError::Conflict {
                expected: seq.saturating_sub(1),
                current: *held,
            });
        }
        sequence::append(&self.dir, JOURNAL, entry)?;
        *held = seq;
        crash::point("members.entry_added");
        Ok(())
    }

    fn replace_summary(&self, summary: &[u8]) -> Result<(), MembershipError> {
        Ok(replace_view(&self.dir, SNAPSHOT, format::VIEW, summary)?)
    }

    fn keep_manifest(
        &self,
        membership: &[u8; 16],
        epoch: u64,
        digest: &str,
        envelope: &[u8],
    ) -> Result<(), MembershipError> {
        let dir = self
            .dir
            .subdir(MANIFESTS, true)?
            .subdir(&hex(membership), true)?;
        let history = dir.subdir(HISTORY, true)?;
        replace_view(
            &history,
            &format!("{epoch}-{digest}.cose"),
            format::VIEW,
            envelope,
        )?;
        Ok(replace_view(&dir, CURRENT, format::VIEW, envelope)?)
    }

    fn keep_invitation(&self, invite: &[u8; 16], invitation: &[u8]) -> Result<(), MembershipError> {
        Ok(replace_view(
            &self.dir.subdir(INVITES, true)?,
            &format!("{}.cbor", hex(invite)),
            format::VIEW,
            invitation,
        )?)
    }

    fn doc(&self, doc: &Doc<'_>) -> Result<Option<Vec<u8>>, MembershipError> {
        self.read(doc)
    }

    fn keep(&self, doc: &Doc<'_>, bytes: &[u8]) -> Result<(), MembershipError> {
        self.write(doc, bytes)
    }

    fn change(&self, doc: &Doc<'_>, change: Change<'_>) -> Result<(), MembershipError> {
        let _changing = self.changing.lock().unwrap_or_else(PoisonError::into_inner);
        let held = self.read(doc)?;
        if let Some(bytes) = change(held.as_deref())? {
            self.write(doc, &bytes)?;
        }
        Ok(())
    }

    fn remove(&self, doc: &Doc<'_>) -> Result<bool, MembershipError> {
        let place = place(doc);
        let Some(dir) = self.below(&place.path, false)? else {
            return Ok(false);
        };
        if !dir.exists(&place.name)? {
            return Ok(false);
        }
        tombstone::delete(&dir, &place.name)?;
        Ok(true)
    }

    fn list(&self, listing: &Listing<'_>) -> Result<Vec<Listed>, MembershipError> {
        let mut listed = Vec::new();
        match *listing {
            Listing::ZoneReceipts { membership, task } => {
                let Some(dir) = self.below(&[PROGRESS.to_owned(), hex(membership)], false)? else {
                    return Ok(listed);
                };
                let prefix = format!("{task}.");
                let suffix = format!(".{ZONE_RECEIPT}");
                for name in dir.names()? {
                    // `<task_id>.<64 hex>.zone`: another task's name never matches its digest's
                    // length.
                    let Some(middle) = name
                        .strip_prefix(&prefix)
                        .and_then(|rest| rest.strip_suffix(&suffix))
                    else {
                        continue;
                    };
                    if middle.len() != 64 || !middle.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                        continue;
                    }
                    if let Some(bytes) = read_view(&dir, &name, format::VIEW)? {
                        listed.push(Listed {
                            name: middle.to_owned(),
                            bytes: Ok(bytes),
                        });
                    }
                }
            }
            Listing::ReplaySlots { membership, task } => {
                let dir = self
                    .below(&[REPLAY.to_owned(), hex(membership), task.to_owned()], true)?
                    .ok_or_else(|| MembershipError::Storage("the replay window".to_owned()))?;
                dir.sweep_temps()?;
                for name in dir.names()? {
                    if name.starts_with(TEMP_PREFIX) {
                        continue;
                    }
                    // A slot is named by its number; a file that is not one is listed as it is
                    // named, and does not read.
                    let slot = name
                        .strip_suffix(".cbor")
                        .filter(|digits| digits.len() == 4)
                        .and_then(|digits| digits.parse::<u64>().ok());
                    let bytes = match (slot, read_view(&dir, &name, format::VIEW)) {
                        (None, _) => Err("the file is no slot of the window".to_owned()),
                        (Some(_), Ok(Some(bytes))) => Ok(bytes),
                        (Some(_), Ok(None)) => Err("the slot went missing".to_owned()),
                        (Some(_), Err(error)) => Err(error.to_string()),
                    };
                    listed.push(Listed {
                        name: slot.map_or(name, |slot| slot.to_string()),
                        bytes,
                    });
                }
            }
            Listing::TrailForks { membership } => {
                self.dir.subdir(AUDIT, true)?;
                let Some(member) = self.below(&[AUDIT.to_owned(), hex(membership)], false)? else {
                    return Ok(listed);
                };
                for name in member.subdirs()? {
                    let dir = member.subdir(&name, false)?;
                    let Some(bytes) = read_view(&dir, FORKED, format::VIEW)? else {
                        continue;
                    };
                    let trail = read_view(&dir, META, format::VIEW)?
                        .map(|trail| String::from_utf8_lossy(&trail).into_owned())
                        .unwrap_or_default();
                    listed.push(Listed {
                        name: trail,
                        bytes: Ok(bytes),
                    });
                }
            }
        }
        listed.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(listed)
    }

    fn checkpoint(
        &self,
        membership: &[u8; 16],
        trail: &str,
        count: u64,
    ) -> Result<Option<Vec<u8>>, MembershipError> {
        let Some(dir) = self.trail(membership, trail, false)? else {
            return Ok(None);
        };
        let name = checkpoint_name(count);
        let Some(bytes) = dir.read(&name)? else {
            return Ok(None);
        };
        // The envelope itself since BUG-0155, or the storage view an earlier build wrote.
        if bytes.starts_with(b"PGSVIEW\0") {
            return Ok(read_view(&dir, &name, format::VIEW)?);
        }
        Ok(Some(bytes))
    }

    fn publish_checkpoint(
        &self,
        membership: &[u8; 16],
        trail: &str,
        count: u64,
        envelope: &[u8],
    ) -> Result<(), MembershipError> {
        let dir = self
            .trail(membership, trail, true)?
            .ok_or_else(|| MembershipError::Storage("a trail's directory".to_owned()))?;
        let same = |held: &[u8]| held == envelope;
        match publish_immutable(&dir, &checkpoint_name(count), envelope, &same, &same)? {
            Published::Written | Published::AlreadyThere => Ok(()),
        }
    }
}

impl Store {
    /// Opens the memberships of `volume`, laying `host/members/` out when absent, and replays
    /// its entries, checking their chain: the file backend's way in.
    pub fn open(volume: &Volume) -> Result<Arc<Self>, MembershipError> {
        // A coordinator restored for disaster recovery re-anchors each membership's chain at its
        // first revision since (BUG-0199).
        let restored = crate::restore::marked(volume)?
            .filter(|marker| marker.mode == crate::restore::Mode::Dr)
            .map(|marker| record::RestoreAnchor {
                plan_id: marker.plan_id,
                previous_boot_id: marker.previous_boot_id,
                at: marker.at,
            });
        Self::open_in(Arc::new(FileMembers::open(volume)?), restored)
    }
}
