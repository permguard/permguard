// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The application-consistent snapshot (WP-7.8, `1-architecture/8-architecture-storage-operations.md`
//! application-consistent snapshot, P9).
//!
//! ```text
//! prepare   authorize ─▶ barrier: new mutations refused, those in flight end
//!           ─▶ intent (`host.backup.prepared`) ─▶ inventory of host/, data/, operations/
//!           ─▶ MANIFEST.cose signed under `host.operations` ─▶ roots flushed ─▶ token, once
//! (the storage driver snapshots the volume, bound to the token)
//! finalize  token + snapshot id ─▶ `host.backup.finalized` ─▶ barrier lowered
//! abort     token, or the barrier's expiry ─▶ `host.backup.aborted` ─▶ barrier lowered
//! ```
//!
//! What the barrier stops is the mutation transaction: every Host domain, the catalog, the refs
//! and the collections. Reads and decisions go on, and so do the writers outside the transaction —
//! the audit trail, the stream engine's journals and views, the decision spool, the mirrors —
//! which the barrier does not pause. Verification, not the barrier, decides whether a snapshot is
//! application-consistent: a journal grown past the inventory is a prefix and passes, while a view
//! one of those writers replaced, or a file it created, makes the snapshot crash-consistent only,
//! and it must pass normal recovery. On an idle Host a snapshot inside the barrier verifies.
//!
//! The inventory reads every byte below the roots while mutations are held; one that outlasts the
//! barrier aborts the backup rather than answering it.
//!
//! ```text
//! host/backups/<operation>/
//! ├── INVENTORY.cborseq   one item per file below the roots, in path order
//! ├── MANIFEST.cose       COSE_Sign1 `permguard.snapshot.manifest.v1` under `host.operations`
//! └── STATE               view {1 v: 1, 2 state, 3 at, 4? snapshot_id}
//! ```
//!
//! | Label | Manifest field       | What it binds                                                  |
//! | ----- | -------------------- | -------------------------------------------------------------- |
//! | 1     | `v`                  | `1`                                                            |
//! | 2     | `operation_id`       | 16 bytes, the prepare's operation                              |
//! | 3     | `volume_id`          | 16 bytes, `host/VOLUME_ID`                                     |
//! | 4     | `host_id`            | 16 bytes, the Host                                             |
//! | 5     | `revisions`          | `{text: uint}`: `mutations`, the transaction's next intent     |
//! | 6     | `roots`              | `[{1 name, 2 files, 3 bytes, 4 digest}]`, `host`, `data`, `operations` |
//! | 7     | `at`                 | seconds                                                        |
//! | 8     | `inventory_digest`   | 32 bytes, the whole inventory                                  |
//! | 9     | `recovery_key_id`    | optional, the deployment's recovery-key id                     |
//! | 10    | `encryption_profile` | optional, the backups' encryption profile                      |
//!
//! An inventory item is `{1 path, 2 length, 3 sha256 of the content, 4 append}`; a root's digest
//! and the inventory digest are SHA-256 of [`digest::SNAPSHOT_INVENTORY`] and the items' bytes in
//! order. `append` marks a storage journal segment and a CBOR sequence, which a snapshot may hold
//! longer than the inventory, never different.

use std::collections::BTreeMap;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use sha2::{Digest as _, Sha256};

use permguard_core::domains::{digest, magic, protected};
use permguard_core::keys::{Jwk, Sign as _};
use permguard_objects::cbor::{self, Value};
use permguard_objects::cose::Sign1;

use super::journal::{Initiator, OperationId};
use super::mutation::{
    Applied, BARRIER_DOMAIN, Begin, Domain, Failure, Mutations, Observed, Outcome,
};
use crate::keys::ring::{HOST_OPERATIONS, Ring};
use crate::storage::volume::Volume;
use crate::storage::{Dir, StorageError, format, sequence, write};

/// The domain the backup's operations carry, the one the barrier lets through.
pub const DOMAIN: &str = BARRIER_DOMAIN;
/// The directory below `host/`.
pub const DIRECTORY: &str = "backups";
/// The inventory sidecar.
pub const INVENTORY: &str = "INVENTORY.cborseq";
/// The signed manifest.
pub const MANIFEST: &str = "MANIFEST.cose";
/// The backup's state view.
pub const STATE: &str = "STATE";
/// The roots the inventory covers, below the volume.
pub const ROOTS: [&str; 3] = ["host", "data", "operations"];
/// How long a barrier holds at most before it aborts and mutations resume.
pub const LIFETIME: Duration = Duration::from_secs(10 * 60);
/// How long a prepare waits for the operations already in flight.
pub const DRAIN: Duration = Duration::from_secs(30);
/// The record version this build writes and reads.
const VERSION: i64 = 1;
/// The largest inventory item: a path and a few numbers.
const MAX_ITEM: usize = 64 * 1024;
/// The largest manifest envelope.
pub const MAX_MANIFEST_BYTES: usize = 64 * 1024;

/// The operations and their audit actions.
pub const PREPARE: &str = super::mutation::BARRIER_OPERATIONS[0];
pub const FINALIZE: &str = super::mutation::BARRIER_OPERATIONS[1];
pub const ABORT: &str = super::mutation::BARRIER_OPERATIONS[2];
pub const PREPARED_ACTION: &str = "host.backup.prepared";
pub const FINALIZED_ACTION: &str = "host.backup.finalized";
pub const ABORTED_ACTION: &str = "host.backup.aborted";

/// A backup's state.
pub const PREPARED: &str = "prepared";
pub const FINALIZED: &str = "finalized";
pub const ABORTED: &str = "aborted";

fn storage(error: impl std::fmt::Display) -> String {
    format!("the backups: {error}")
}

pub(super) fn uint(value: u64, what: &str) -> Result<Value, String> {
    i64::try_from(value)
        .map(Value::Int)
        .map_err(|_| format!("{what} is out of range"))
}

/// A canonical map's members, closed to labels `1..=highest`, in order.
pub(super) fn labelled(
    bytes: &[u8],
    what: &str,
    highest: i64,
) -> Result<BTreeMap<i64, Value>, String> {
    let value = cbor::decode_canonical(bytes).map_err(|error| format!("{what}: {error}"))?;
    labelled_value(value, what, highest)
}

pub(super) fn labelled_value(
    value: Value,
    what: &str,
    highest: i64,
) -> Result<BTreeMap<i64, Value>, String> {
    let Value::Map(pairs) = value else {
        return Err(format!("{what} is a map"));
    };
    let mut held = BTreeMap::new();
    for (key, value) in pairs {
        match key {
            Value::Int(label) if (1..=highest).contains(&label) => {
                held.insert(label, value);
            }
            _ => return Err(format!("{what} holds an unknown label")),
        }
    }
    match held.get(&1) {
        Some(Value::Int(version)) if *version != VERSION => Err(format!(
            "{what} of version {version}, which this build does not read"
        )),
        _ => Ok(held),
    }
}

pub(super) fn take_uint(
    held: &mut BTreeMap<i64, Value>,
    label: i64,
    what: &str,
) -> Result<u64, String> {
    match held.remove(&label) {
        Some(Value::Int(value)) if value >= 0 => Ok(value as u64),
        _ => Err(format!("{what} is an unsigned integer")),
    }
}

pub(super) fn take_text(
    held: &mut BTreeMap<i64, Value>,
    label: i64,
    what: &str,
) -> Result<String, String> {
    match held.remove(&label) {
        Some(Value::Text(text)) => Ok(text),
        _ => Err(format!("{what} is text")),
    }
}

fn take_optional_text(
    held: &mut BTreeMap<i64, Value>,
    label: i64,
    what: &str,
) -> Result<Option<String>, String> {
    match held.remove(&label) {
        None => Ok(None),
        Some(Value::Text(text)) => Ok(Some(text)),
        Some(_) => Err(format!("{what} is text")),
    }
}

pub(super) fn take_bytes<const N: usize>(
    held: &mut BTreeMap<i64, Value>,
    label: i64,
    what: &str,
) -> Result<[u8; N], String> {
    match held.remove(&label) {
        Some(Value::Bytes(bytes)) => bytes.try_into().map_err(|_| format!("{what} is {N} bytes")),
        _ => Err(format!("{what} is {N} bytes")),
    }
}

pub(super) fn finish(held: BTreeMap<i64, Value>, what: &str) -> Result<(), String> {
    match held.keys().next() {
        None => Ok(()),
        Some(label) => Err(format!("{what} holds the unexpected label {label}")),
    }
}

/// One root of the volume as the manifest binds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Root {
    pub name: String,
    pub files: u64,
    pub bytes: u64,
    pub digest: [u8; 32],
}

/// The snapshot manifest's payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotManifest {
    pub operation_id: [u8; 16],
    pub volume_id: [u8; 16],
    pub host_id: [u8; 16],
    pub revisions: BTreeMap<String, u64>,
    pub roots: Vec<Root>,
    pub at: u64,
    pub inventory_digest: [u8; 32],
    pub recovery_key_id: Option<String>,
    pub encryption_profile: Option<String>,
}

impl SnapshotManifest {
    /// The canonical bytes.
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        let mut pairs = vec![
            (Value::Int(1), Value::Int(VERSION)),
            (Value::Int(2), Value::Bytes(self.operation_id.to_vec())),
            (Value::Int(3), Value::Bytes(self.volume_id.to_vec())),
            (Value::Int(4), Value::Bytes(self.host_id.to_vec())),
            (
                Value::Int(5),
                Value::Map(
                    self.revisions
                        .iter()
                        .map(|(name, revision)| {
                            Ok((Value::Text(name.clone()), uint(*revision, "a revision")?))
                        })
                        .collect::<Result<_, String>>()?,
                ),
            ),
            (
                Value::Int(6),
                Value::Array(
                    self.roots
                        .iter()
                        .map(|root| {
                            Ok(Value::Map(vec![
                                (Value::Int(1), Value::Text(root.name.clone())),
                                (Value::Int(2), uint(root.files, "a root's files")?),
                                (Value::Int(3), uint(root.bytes, "a root's bytes")?),
                                (Value::Int(4), Value::Bytes(root.digest.to_vec())),
                            ]))
                        })
                        .collect::<Result<_, String>>()?,
                ),
            ),
            (Value::Int(7), uint(self.at, "the manifest's time")?),
            (Value::Int(8), Value::Bytes(self.inventory_digest.to_vec())),
        ];
        if let Some(id) = &self.recovery_key_id {
            pairs.push((Value::Int(9), Value::Text(id.clone())));
        }
        if let Some(profile) = &self.encryption_profile {
            pairs.push((Value::Int(10), Value::Text(profile.clone())));
        }
        cbor::encode(&Value::Map(pairs)).map_err(|error| error.to_string())
    }

    /// Reads the canonical bytes, closed: labels 1 to 8 required, 9 and 10 optional, none other.
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        const WHAT: &str = "a snapshot manifest";
        if bytes.len() > MAX_MANIFEST_BYTES {
            return Err(format!("{WHAT} takes at most {MAX_MANIFEST_BYTES} bytes"));
        }
        let mut held = labelled(bytes, WHAT, 10)?;
        if !held.contains_key(&1) {
            return Err(format!("{WHAT} names no version"));
        }
        held.remove(&1);
        let operation_id = take_bytes::<16>(&mut held, 2, "the operation id")?;
        let volume_id = take_bytes::<16>(&mut held, 3, "the volume id")?;
        let host_id = take_bytes::<16>(&mut held, 4, "the host id")?;
        let revisions = match held.remove(&5) {
            Some(Value::Map(pairs)) => pairs
                .into_iter()
                .map(|(name, revision)| match (name, revision) {
                    (Value::Text(name), Value::Int(revision)) if revision >= 0 => {
                        Ok((name, revision as u64))
                    }
                    _ => Err("a revision is text and an unsigned integer".to_owned()),
                })
                .collect::<Result<_, _>>()?,
            _ => return Err("the revisions are a map".to_owned()),
        };
        let roots = match held.remove(&6) {
            Some(Value::Array(roots)) => roots
                .into_iter()
                .map(|root| {
                    let mut root = labelled_value(root, "a root", 4)?;
                    let read = Root {
                        name: take_text(&mut root, 1, "a root's name")?,
                        files: take_uint(&mut root, 2, "a root's files")?,
                        bytes: take_uint(&mut root, 3, "a root's bytes")?,
                        digest: take_bytes::<32>(&mut root, 4, "a root's digest")?,
                    };
                    finish(root, "a root")?;
                    Ok(read)
                })
                .collect::<Result<_, String>>()?,
            _ => return Err("the roots are an array".to_owned()),
        };
        let at = take_uint(&mut held, 7, "the manifest's time")?;
        let inventory_digest = take_bytes::<32>(&mut held, 8, "the inventory digest")?;
        let recovery_key_id = take_optional_text(&mut held, 9, "the recovery-key id")?;
        let encryption_profile = take_optional_text(&mut held, 10, "the encryption profile")?;
        finish(held, WHAT)?;
        Ok(Self {
            operation_id,
            volume_id,
            host_id,
            revisions,
            roots,
            at,
            inventory_digest,
            recovery_key_id,
            encryption_profile,
        })
    }
}

/// One file the inventory binds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Below the volume, `/`-separated, starting with its root.
    pub path: String,
    pub length: u64,
    pub digest: [u8; 32],
    /// A journal segment or a CBOR sequence: a snapshot may hold it longer, never different.
    pub append: bool,
}

impl Entry {
    /// The canonical bytes.
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        cbor::encode(&Value::Map(vec![
            (Value::Int(1), Value::Text(self.path.clone())),
            (Value::Int(2), uint(self.length, "a file's length")?),
            (Value::Int(3), Value::Bytes(self.digest.to_vec())),
            (Value::Int(4), Value::Bool(self.append)),
        ]))
        .map_err(|error| error.to_string())
    }

    fn read(value: Value) -> Result<Self, String> {
        let Value::Map(pairs) = value else {
            return Err("an inventory item is a map".to_owned());
        };
        let mut held = BTreeMap::new();
        for (key, value) in pairs {
            match key {
                Value::Int(label) if (1..=4).contains(&label) => {
                    held.insert(label, value);
                }
                _ => return Err("an inventory item holds an unknown label".to_owned()),
            }
        }
        let entry = Self {
            path: take_text(&mut held, 1, "a file's path").and_then(|path| {
                below_a_root(&path)
                    .then_some(path)
                    .ok_or_else(|| "a file's path is not below a root".to_owned())
            })?,
            length: take_uint(&mut held, 2, "a file's length")?,
            digest: take_bytes::<32>(&mut held, 3, "a file's digest")?,
            append: match held.remove(&4) {
                Some(Value::Bool(append)) => append,
                _ => return Err("a file's kind is a boolean".to_owned()),
            },
        };
        finish(held, "an inventory item")?;
        Ok(entry)
    }
}

/// SHA-256 of the inventory domain and `items`' canonical bytes, in order.
pub fn inventory_digest<'a>(
    items: impl IntoIterator<Item = &'a Entry>,
) -> Result<[u8; 32], String> {
    let mut hasher = Sha256::new();
    hasher.update(digest::SNAPSHOT_INVENTORY.as_bytes());
    for item in items {
        hasher.update(item.encode()?);
    }
    Ok(hasher.finalize().into())
}

/// SHA-256 of `path`'s first `limit` bytes (all of them when `None`), and how many it read.
fn file_digest(path: &Path, limit: Option<u64>) -> Result<([u8; 32], u64), String> {
    let file = std::fs::File::open(path).map_err(|error| format!("{}: {error}", path.display()))?;
    let mut reader: Box<dyn std::io::Read> = match limit {
        Some(limit) => Box::new(file.take(limit)),
        None => Box::new(file),
    };
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 64 * 1024];
    let mut read = 0u64;
    loop {
        let taken = reader
            .read(&mut buffer)
            .map_err(|error| format!("{}: {error}", path.display()))?;
        if taken == 0 {
            break;
        }
        hasher.update(&buffer[..taken]);
        read += taken as u64;
    }
    Ok((hasher.finalize().into(), read))
}

/// Whether the file at `path`, named `name`, only ever grows: a storage journal segment or a CBOR
/// sequence.
fn appends(path: &Path, name: &str) -> bool {
    if name.ends_with(".cborseq") {
        return true;
    }
    let mut head = [0u8; 8];
    std::fs::File::open(path)
        .and_then(|mut file| file.read_exact(&mut head))
        .is_ok_and(|()| head == *magic::JOURNAL_SEGMENT.as_bytes())
}

/// Every regular file below the roots of the volume at `root`, as `(path below the volume, where
/// it is, its name)`: `host/backups/` and temporaries left out, no symbolic link followed, a name
/// that is not UTF-8 refused rather than bound under another.
fn files(root: &Path) -> Result<Vec<(String, PathBuf, String)>, String> {
    let mut found = Vec::new();
    for name in ROOTS {
        let base = root.join(name);
        if std::fs::symlink_metadata(&base).is_ok_and(|metadata| metadata.is_dir()) {
            walk(&base, name, &mut found)?;
        }
    }
    found.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(found)
}

fn walk(
    dir: &Path,
    relative: &str,
    found: &mut Vec<(String, PathBuf, String)>,
) -> Result<(), String> {
    if relative == format!("host/{DIRECTORY}") {
        return Ok(());
    }
    let listed = std::fs::read_dir(dir).map_err(|error| format!("{}: {error}", dir.display()))?;
    for entry in listed {
        let entry = entry.map_err(|error| format!("{}: {error}", dir.display()))?;
        let name = entry.file_name().into_string().map_err(|name| {
            format!(
                "{relative}/{}: a file name that is not UTF-8",
                name.to_string_lossy()
            )
        })?;
        if name.starts_with(crate::storage::dir::TEMP_PREFIX) {
            continue;
        }
        let path = entry.path();
        let child = format!("{relative}/{name}");
        let metadata =
            std::fs::symlink_metadata(&path).map_err(|error| format!("{child}: {error}"))?;
        if metadata.is_dir() {
            walk(&path, &child, found)?;
        } else if metadata.is_file() {
            found.push((child, path, name));
        }
    }
    Ok(())
}

/// The inventory of the volume at `root`: every file [`files`] finds, in path order, each with
/// its length and digest.
pub fn inventory(root: &Path) -> Result<Vec<Entry>, String> {
    files(root)?
        .into_iter()
        .map(|(child, path, name)| {
            let (digest, length) = file_digest(&path, None)?;
            Ok(Entry {
                append: appends(&path, &name),
                path: child,
                length,
                digest,
            })
        })
        .collect()
}

/// Whether `path` names a file below a root: its root first, then non-empty segments, none of
/// them `.` or `..`.
fn below_a_root(path: &str) -> bool {
    let mut segments = path.split('/');
    segments.next().is_some_and(|root| ROOTS.contains(&root))
        && path.contains('/')
        && segments.all(|segment| !segment.is_empty() && segment != "." && segment != "..")
}

/// The roots the manifest binds, from `entries` in path order.
pub fn roots_of(entries: &[Entry]) -> Result<Vec<Root>, String> {
    ROOTS
        .iter()
        .map(|name| {
            let prefix = format!("{name}/");
            let held: Vec<&Entry> = entries
                .iter()
                .filter(|entry| entry.path.starts_with(&prefix))
                .collect();
            Ok(Root {
                name: (*name).to_owned(),
                files: held.len() as u64,
                bytes: held.iter().map(|entry| entry.length).sum(),
                digest: inventory_digest(held.iter().copied())?,
            })
        })
        .collect()
}

/// A backup's state, as its view holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct State {
    /// `prepared`, `finalized` or `aborted`.
    pub state: String,
    /// When it entered that state, seconds.
    pub at: u64,
    /// The storage driver's snapshot id, once finalized.
    pub snapshot_id: Option<String>,
}

impl State {
    fn encode(&self) -> Result<Vec<u8>, String> {
        let mut pairs = vec![
            (Value::Int(1), Value::Int(VERSION)),
            (Value::Int(2), Value::Text(self.state.clone())),
            (Value::Int(3), uint(self.at, "the state's time")?),
        ];
        if let Some(id) = &self.snapshot_id {
            pairs.push((Value::Int(4), Value::Text(id.clone())));
        }
        cbor::encode(&Value::Map(pairs)).map_err(|error| error.to_string())
    }

    fn decode(bytes: &[u8]) -> Result<Self, String> {
        const WHAT: &str = "a backup's state";
        let mut held = labelled(bytes, WHAT, 4)?;
        if held.remove(&1).is_none() {
            return Err(format!("{WHAT} names no version"));
        }
        let state = Self {
            state: take_text(&mut held, 2, "the state")?,
            at: take_uint(&mut held, 3, "the state's time")?,
            snapshot_id: take_optional_text(&mut held, 4, "the snapshot id")?,
        };
        finish(held, WHAT)?;
        if ![PREPARED, FINALIZED, ABORTED].contains(&state.state.as_str()) {
            return Err(format!("`{}` is not a backup's state", state.state));
        }
        Ok(state)
    }
}

/// The barrier in force: which backup holds it, the digest of its token, until when.
#[derive(Clone)]
struct Held {
    operation_id: OperationId,
    token_digest: [u8; 32],
    expires_at: u64,
    until: Instant,
}

/// What a prepare answers: the token is answered here and nowhere else.
#[derive(Clone)]
pub struct Prepared {
    pub operation_id: OperationId,
    pub revision: u64,
    pub manifest: Vec<u8>,
    pub token: String,
    pub expires_at: u64,
}

/// The token is a secret: never in a `Debug`.
impl std::fmt::Debug for Prepared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Prepared")
            .field("operation_id", &self.operation_id)
            .field("revision", &self.revision)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

/// What a finalize or an abort answers: the backup it ended, and its own operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ended {
    pub backup: OperationId,
    pub operation_id: OperationId,
    pub revision: u64,
}

/// One backup the Host knows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listed {
    pub operation_id: String,
    /// When it was prepared, seconds.
    pub at: u64,
    pub state: String,
    pub snapshot_id: Option<String>,
    /// When it was finalized or aborted, seconds.
    pub ended_at: Option<u64>,
    /// Its signed manifest, as the prepare wrote it.
    pub manifest: Option<Vec<u8>>,
}

/// Why a backup operation was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refused {
    /// A backup is already prepared.
    Busy,
    /// No prepared backup answers to the token.
    Unknown,
    /// The snapshot id is not one.
    InvalidSnapshotId(String),
    /// The barrier, the signing ring or the volume could not serve it.
    Unavailable(String),
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Busy => f.write_str("a backup is already prepared: finalize or abort it first"),
            Self::Unknown => f.write_str("no prepared backup answers to this token"),
            Self::InvalidSnapshotId(detail) => write!(f, "the snapshot id: {detail}"),
            Self::Unavailable(detail) => f.write_str(detail),
        }
    }
}

/// What names the backup an ending ends.
#[derive(Clone, Copy)]
enum Ending<'a> {
    /// The token its prepare answered.
    Token(&'a str),
    /// Its operation, once its barrier expired.
    Expired(OperationId),
}

/// What a backup signs with and binds.
pub struct Signing<'a> {
    pub ring: &'a Ring,
    pub host_id: [u8; 16],
    pub recovery_key_id: Option<String>,
    pub encryption_profile: Option<String>,
}

/// The Host's backups on one volume.
pub struct Backups {
    root: PathBuf,
    volume_id: [u8; 16],
    dir: Dir,
    held: Mutex<Option<Held>>,
    lifetime: Duration,
    /// Whether the one timer thread that aborts expired barriers runs.
    timer: std::sync::atomic::AtomicBool,
}

impl std::fmt::Debug for Backups {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Backups")
            .field("dir", &self.dir.path())
            .finish_non_exhaustive()
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Two digests compared in time that does not depend on where they differ.
fn same(left: &[u8; 32], right: &[u8; 32]) -> bool {
    left.iter()
        .zip(right)
        .fold(0u8, |acc, (left, right)| acc | (left ^ right))
        == 0
}

impl Backups {
    /// Opens `host/backups/` on `volume`, changing nothing: the transaction's recovery meets its
    /// operations before [`Backups::cut`] judges what a restart left prepared.
    pub fn open(volume: &Volume) -> Result<Self, StorageError> {
        let dir = volume.host().subdir(DIRECTORY, true)?;
        dir.sweep_temps()?;
        Ok(Self {
            root: volume.root().to_path_buf(),
            volume_id: volume.id(),
            dir,
            held: Mutex::new(None),
            lifetime: LIFETIME,
            timer: std::sync::atomic::AtomicBool::new(false),
        })
    }

    /// A backup still `prepared` after recovery was cut short by a restart, whose barrier went
    /// with the process: it is recorded `aborted`, and answered so the caller audits it. Called
    /// after `Mutations::recover`, so an ending a crash left open is judged on the state its own
    /// write left, never on this one.
    pub fn cut(&self, now: u64) -> Result<Vec<String>, StorageError> {
        let mut cut = Vec::new();
        for name in self.dir.subdirs()? {
            let operation = self.dir.subdir(&name, false)?;
            let Some(state) = read_state(&operation)? else {
                continue;
            };
            if state.state == PREPARED {
                write_state(
                    &operation,
                    &State {
                        state: ABORTED.to_owned(),
                        at: now,
                        snapshot_id: None,
                    },
                )?;
                cut.push(name);
            }
        }
        Ok(cut)
    }

    /// Records, through the transaction, the abort of every backup a restart cut short — `cut`, as
    /// [`Backups::cut`] answered it — so the trail says how each ended. Answers how many were
    /// recorded; one that cannot be is logged, its state already `aborted` on the volume.
    pub fn record_cut(&self, mutations: &Mutations, cut: &[String], now: u64) -> usize {
        let mut recorded = 0;
        for name in cut {
            let operation = match self.dir.subdir(name, false) {
                Ok(operation) => operation,
                Err(error) => {
                    tracing::warn!(
                        event.name = "host.backup_cut_unrecorded",
                        component = "host",
                        backup = name.as_str(),
                        error = %error,
                        "a backup a restart cut short is aborted and its record could not be written"
                    );
                    continue;
                }
            };
            let revision = mutations.order();
            let answered = mutations.run(
                Begin {
                    domain: DOMAIN,
                    operation: ABORT,
                    action: ABORTED_ACTION,
                    initiator: Initiator::System("backup".to_owned()),
                    request: None,
                    target: Some(name.clone()),
                },
                |applying| {
                    write_state(
                        &operation,
                        &State {
                            state: ABORTED.to_owned(),
                            at: now,
                            snapshot_id: None,
                        },
                    )
                    .map(|()| Applied {
                        revision,
                        target: Some(name.clone()),
                        value: applying.operation_id().to_string(),
                    })
                    .map_err(|error| Failure::Indeterminate(storage(error)))
                },
            );
            match answered {
                Ok(_) => recorded += 1,
                Err(error) => tracing::warn!(
                    event.name = "host.backup_cut_unrecorded",
                    component = "host",
                    backup = name.as_str(),
                    error = %error,
                    "a backup a restart cut short is aborted and its record could not be written"
                ),
            }
        }
        recorded
    }

    /// This store with barriers lasting `lifetime`: for a test that watches one expire.
    pub fn with_lifetime(mut self, lifetime: Duration) -> Self {
        self.lifetime = lifetime;
        self
    }

    /// The volume this store's backups snapshot.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Prepares a backup (WP-7.8): raises the barrier, then, as one operation of the transaction,
    /// takes the inventory, signs the manifest under `host.operations`, writes both beside its
    /// state and flushes the roots. The token is answered here once; the Host keeps its digest.
    pub fn prepare(
        &self,
        mutations: &Mutations,
        initiator: Initiator,
        signing: &Signing<'_>,
        now: u64,
    ) -> Result<Prepared, Refused> {
        // A barrier past its deadline is recorded aborted before another is raised.
        self.expire(mutations, now);
        let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        if held.is_some() {
            return Err(Refused::Busy);
        }
        let mut token = [0u8; 32];
        random(&mut token)?;
        let token_digest: [u8; 32] = Sha256::digest(token).into();
        let until = Instant::now() + self.lifetime;
        mutations
            .quiesce(until, DRAIN)
            .map_err(Refused::Unavailable)?;
        let revision = mutations.order();
        let answered = mutations.run(
            Begin {
                domain: DOMAIN,
                operation: PREPARE,
                action: PREPARED_ACTION,
                initiator,
                request: None,
                target: None,
            },
            |applying| {
                let operation_id = applying.operation_id();
                self.snapshot(&operation_id, revision, signing, now)
                    .map(|manifest| Applied {
                        revision,
                        target: Some(operation_id.to_string()),
                        value: (operation_id.to_string(), B64.encode(manifest)),
                    })
                    .map_err(Failure::Refused)
            },
        );
        let (operation_id, manifest) = match answered {
            Ok(Outcome::Applied((id, manifest)) | Outcome::Replayed((id, manifest))) => {
                match parse_operation(&id) {
                    Some(operation_id) => (operation_id, manifest),
                    None => {
                        mutations.release();
                        return Err(Refused::Unavailable("an operation id".to_owned()));
                    }
                }
            }
            Ok(Outcome::Reconciled { .. }) => {
                mutations.release();
                return Err(Refused::Unavailable(
                    "the prepare was reconciled by recovery: prepare again".to_owned(),
                ));
            }
            Err(error) => {
                mutations.release();
                return Err(Refused::Unavailable(error.to_string()));
            }
        };
        let expires_at = now + self.lifetime.as_secs();
        *held = Some(Held {
            operation_id,
            token_digest,
            expires_at,
            until,
        });
        // An inventory that outlasted the barrier was taken while mutations had resumed: the
        // backup is aborted rather than answered as if it held.
        if Instant::now() >= until {
            drop(held);
            let _ = self.end(
                mutations,
                Initiator::System("backup".to_owned()),
                Ending::Expired(operation_id),
                ABORT,
                ABORTED_ACTION,
                State {
                    state: ABORTED.to_owned(),
                    at: now,
                    snapshot_id: None,
                },
            );
            return Err(Refused::Unavailable(
                "the inventory outlasted the barrier: the backup is aborted".to_owned(),
            ));
        }
        Ok(Prepared {
            operation_id,
            revision,
            manifest: B64
                .decode(manifest)
                .map_err(|error| Refused::Unavailable(error.to_string()))?,
            token: B64.encode(token),
            expires_at,
        })
    }

    /// The inventory, the signed manifest and the `prepared` state of `operation_id`, every root
    /// flushed after; answers the manifest's bytes.
    fn snapshot(
        &self,
        operation_id: &OperationId,
        revision: u64,
        signing: &Signing<'_>,
        now: u64,
    ) -> Result<Vec<u8>, String> {
        let entries = inventory(&self.root)?;
        let manifest = SnapshotManifest {
            operation_id: *operation_id.as_bytes(),
            volume_id: self.volume_id,
            host_id: signing.host_id,
            revisions: BTreeMap::from([("mutations".to_owned(), revision)]),
            roots: roots_of(&entries)?,
            at: now,
            inventory_digest: inventory_digest(&entries)?,
            recovery_key_id: signing.recovery_key_id.clone(),
            encryption_profile: signing.encryption_profile.clone(),
        };
        let signed = sign(signing.ring, &manifest)?;
        let operation = self
            .dir
            .subdir(&operation_id.to_string(), true)
            .map_err(storage)?;
        let mut items = Vec::new();
        for entry in &entries {
            items.extend(entry.encode()?);
        }
        write::replace_bytes(&operation, INVENTORY, &items).map_err(storage)?;
        write::replace_bytes(&operation, MANIFEST, &signed).map_err(storage)?;
        write_state(
            &operation,
            &State {
                state: PREPARED.to_owned(),
                at: now,
                snapshot_id: None,
            },
        )
        .map_err(storage)?;
        // Every root flushed: what the storage driver snapshots next is what the manifest names.
        for name in ROOTS {
            sync_tree(&self.root.join(name))?;
        }
        Ok(signed)
    }

    /// Finalizes the backup `token` names (WP-7.8): binds the storage driver's `snapshot_id` to
    /// it, records it and lowers the barrier.
    pub fn finalize(
        &self,
        mutations: &Mutations,
        initiator: Initiator,
        token: &str,
        snapshot_id: &str,
        now: u64,
    ) -> Result<Ended, Refused> {
        check_snapshot_id(snapshot_id)?;
        self.end(
            mutations,
            initiator,
            Ending::Token(token),
            FINALIZE,
            FINALIZED_ACTION,
            State {
                state: FINALIZED.to_owned(),
                at: now,
                snapshot_id: Some(snapshot_id.to_owned()),
            },
        )
    }

    /// Aborts the backup `token` names: records it and lowers the barrier.
    pub fn abort(
        &self,
        mutations: &Mutations,
        initiator: Initiator,
        token: &str,
        now: u64,
    ) -> Result<Ended, Refused> {
        self.end(
            mutations,
            initiator,
            Ending::Token(token),
            ABORT,
            ABORTED_ACTION,
            State {
                state: ABORTED.to_owned(),
                at: now,
                snapshot_id: None,
            },
        )
    }

    /// Aborts the backup whose barrier has expired, if one has: what a timer and every later
    /// call do, so a prepare nobody ends never holds mutations past its lifetime.
    pub fn expire(&self, mutations: &Mutations, now: u64) -> Option<Ended> {
        let expired = self
            .held
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .filter(|held| Instant::now() >= held.until)
            .map(|held| held.operation_id)?;
        self.end(
            mutations,
            Initiator::System("backup".to_owned()),
            Ending::Expired(expired),
            ABORT,
            ABORTED_ACTION,
            State {
                state: ABORTED.to_owned(),
                at: now,
                snapshot_id: None,
            },
        )
        .ok()
    }

    /// Ends the held backup as `state`, when `ending` names it — its token, or its operation once
    /// its barrier expired — checked under the lock, so an expiry never ends a backup prepared
    /// after it: through the transaction, then the barrier lowered.
    fn end(
        &self,
        mutations: &Mutations,
        initiator: Initiator,
        ending: Ending<'_>,
        operation: &'static str,
        action: &'static str,
        state: State,
    ) -> Result<Ended, Refused> {
        let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        let current = held.clone().ok_or(Refused::Unknown)?;
        match ending {
            Ending::Token(token) => {
                let presented: [u8; 32] =
                    Sha256::digest(B64.decode(token.trim()).map_err(|_| Refused::Unknown)?).into();
                if !same(&presented, &current.token_digest) {
                    return Err(Refused::Unknown);
                }
            }
            Ending::Expired(operation_id) => {
                if current.operation_id != operation_id || Instant::now() < current.until {
                    return Err(Refused::Unknown);
                }
            }
        }
        let target = current.operation_id.to_string();
        let operation_dir = self
            .dir
            .subdir(&target, false)
            .map_err(|error| Refused::Unavailable(storage(error)))?;
        let revision = mutations.order();
        let answered = mutations.run(
            Begin {
                domain: DOMAIN,
                operation,
                action,
                initiator,
                request: None,
                target: Some(target.clone()),
            },
            |applying| {
                write_state(&operation_dir, &state)
                    .map(|()| Applied {
                        revision,
                        target: Some(target.clone()),
                        value: applying.operation_id().to_string(),
                    })
                    .map_err(|error| Failure::Indeterminate(storage(error)))
            },
        );
        // Whatever the record came to, the backup is over: the barrier goes, never left holding
        // mutations behind a failed record.
        *held = None;
        mutations.release();
        match answered {
            Ok(Outcome::Applied(id) | Outcome::Replayed(id)) => Ok(Ended {
                backup: current.operation_id,
                operation_id: parse_operation(&id)
                    .ok_or_else(|| Refused::Unavailable("an operation id".to_owned()))?,
                revision,
            }),
            Ok(Outcome::Reconciled { operation_id, .. }) => Ok(Ended {
                backup: current.operation_id,
                operation_id,
                revision,
            }),
            Err(error) => Err(Refused::Unavailable(error.to_string())),
        }
    }

    /// Starts the one timer that aborts a barrier once it expired, unless it runs: it sleeps until
    /// the barrier held ends, aborts it, and stops when none is held. Every backup call expires a
    /// barrier too; the timer records the abort of one nobody calls about.
    pub fn watch(
        self: &std::sync::Arc<Self>,
        mutations: std::sync::Arc<Mutations>,
        now: std::sync::Arc<dyn Fn() -> u64 + Send + Sync>,
    ) -> std::io::Result<()> {
        use std::sync::atomic::Ordering;
        if self.timer.swap(true, Ordering::SeqCst) {
            return Ok(());
        }
        let backups = std::sync::Arc::clone(self);
        let spawned = std::thread::Builder::new()
            .name("backup-barrier".to_owned())
            .spawn(move || {
                loop {
                    while let Some(until) = backups.held_until() {
                        let left = until.saturating_duration_since(Instant::now());
                        std::thread::sleep(left + Duration::from_millis(10));
                        backups.expire(&mutations, now());
                    }
                    backups.timer.store(false, Ordering::SeqCst);
                    // A prepare between the last look and the flag: this thread takes it on.
                    if backups.held_until().is_none() || backups.timer.swap(true, Ordering::SeqCst)
                    {
                        break;
                    }
                }
            });
        if spawned.is_err() {
            self.timer.store(false, Ordering::SeqCst);
        }
        spawned.map(|_| ())
    }

    /// Until when the held barrier holds, if one is held.
    fn held_until(&self) -> Option<Instant> {
        self.held
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .map(|held| held.until)
    }

    /// When the held barrier ends, unix seconds, if one is held.
    pub fn expires_at(&self) -> Option<u64> {
        self.held
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .map(|held| held.expires_at)
    }

    /// Every backup this Host knows, newest first, the transaction's order telling apart two of one
    /// second.
    pub fn list(&self) -> Result<Vec<Listed>, String> {
        let mut listed = Vec::new();
        let mut ordered = Vec::new();
        for name in self.dir.subdirs().map_err(storage)? {
            let operation = self.dir.subdir(&name, false).map_err(storage)?;
            let Some(state) = read_state(&operation).map_err(storage)? else {
                continue;
            };
            let manifest = operation.read(MANIFEST).map_err(storage)?;
            let read = manifest
                .as_deref()
                .and_then(|bytes| Sign1::decode(bytes).ok())
                .and_then(|envelope| SnapshotManifest::decode(envelope.payload_unverified()).ok());
            let at = read.as_ref().map_or(state.at, |manifest| manifest.at);
            // The transaction's order at the prepare: what tells two backups of one second apart.
            let order = read
                .as_ref()
                .and_then(|manifest| manifest.revisions.get("mutations").copied())
                .unwrap_or_default();
            ordered.push(order);
            listed.push(Listed {
                operation_id: name,
                at,
                ended_at: (state.state != PREPARED).then_some(state.at),
                state: state.state,
                snapshot_id: state.snapshot_id,
                manifest,
            });
        }
        let mut paired: Vec<(u64, Listed)> = ordered.into_iter().zip(listed).collect();
        paired.sort_by(|(left_order, left), (right_order, right)| {
            (right.at, right_order, &right.operation_id).cmp(&(
                left.at,
                left_order,
                &left.operation_id,
            ))
        });
        Ok(paired.into_iter().map(|(_, listed)| listed).collect())
    }
}

/// The backups as the transaction's recovery meets them: an operation shows when its backup's
/// directory holds a state.
impl Domain for Backups {
    fn name(&self) -> &'static str {
        DOMAIN
    }

    /// A prepare (no target) shows once its backup's state exists; a finalize or an abort (the
    /// backup as its target) only once that state is no longer `prepared`, so a crash before its
    /// write is failed, never reconciled as applied. The revision is unknown after a restart: 0.
    fn observe(&self, operation_id: &OperationId, target: Option<&str>) -> Option<Observed> {
        let name = target.map_or_else(|| operation_id.to_string(), str::to_owned);
        let operation = self.dir.subdir(&name, false).ok()?;
        let state = read_state(&operation).ok()??;
        if target.is_some() && state.state == PREPARED {
            return None;
        }
        Some(Observed {
            revision: 0,
            target: Some(name),
        })
    }
}

fn parse_operation(text: &str) -> Option<OperationId> {
    if text.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 16];
    for (at, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(text.get(at * 2..at * 2 + 2)?, 16).ok()?;
    }
    Some(OperationId::from_bytes(bytes))
}

fn random(bytes: &mut [u8]) -> Result<(), Refused> {
    use ring::rand::SecureRandom as _;
    ring::rand::SystemRandom::new()
        .fill(bytes)
        .map_err(|_| Refused::Unavailable("the OS random source refused a token".to_owned()))
}

/// A storage driver's snapshot id: 1 to 512 printable ASCII characters.
fn check_snapshot_id(snapshot_id: &str) -> Result<(), Refused> {
    if snapshot_id.is_empty()
        || snapshot_id.len() > 512
        || !snapshot_id.chars().all(|held| held.is_ascii_graphic())
    {
        return Err(Refused::InvalidSnapshotId(
            "1 to 512 printable ASCII characters, no space".to_owned(),
        ));
    }
    Ok(())
}

fn read_state(dir: &Dir) -> Result<Option<State>, StorageError> {
    write::read_view(dir, STATE, format::VIEW)?
        .map(|bytes| State::decode(&bytes).map_err(StorageError::Corruption))
        .transpose()
}

fn write_state(dir: &Dir, state: &State) -> Result<(), StorageError> {
    let body = state.encode().map_err(StorageError::Corruption)?;
    write::replace_view(dir, STATE, format::VIEW, &body)
}

/// Flushes every directory below `path`.
fn sync_tree(path: &Path) -> Result<(), String> {
    if !std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.is_dir()) {
        return Ok(());
    }
    let dir = Dir::open(path).map_err(storage)?;
    dir.sync().map_err(storage)?;
    for entry in std::fs::read_dir(path).map_err(|error| format!("{}: {error}", path.display()))? {
        let entry = entry.map_err(|error| format!("{}: {error}", path.display()))?;
        if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            sync_tree(&entry.path())?;
        }
    }
    Ok(())
}

/// The COSE_Sign1 `permguard.snapshot.manifest.v1` over `manifest` by the active
/// `host.operations` key, under its kid.
pub fn sign(ring: &Ring, manifest: &SnapshotManifest) -> Result<Vec<u8>, String> {
    if ring.id() != HOST_OPERATIONS {
        return Err(format!(
            "a snapshot manifest is signed under `{HOST_OPERATIONS}`, not `{}`",
            ring.id()
        ));
    }
    let kid = ring.active_key_id().map_err(|error| error.to_string())?;
    let envelope = Sign1::sign_with(
        ring.suite(),
        protected::SNAPSHOT_MANIFEST,
        kid.as_str().as_bytes(),
        manifest.encode()?,
        |bytes| {
            let signature =
                permguard_core::keys::Sign::sign(ring, bytes).map_err(|error| error.to_string())?;
            if signature.key_id() != &kid {
                return Err("the signing key rotated mid-signature".to_owned());
            }
            Ok(signature.bytes().to_vec())
        },
    )
    .map_err(|error| error.to_string())?;
    envelope.encode().map_err(|error| error.to_string())
}

/// What verification found of a snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Consistency {
    /// Every file the manifest binds is in the snapshot as the inventory has it.
    ApplicationConsistent,
    /// The snapshot differs from the manifest: only crash-consistent, it must pass normal
    /// recovery. Each difference, by path.
    CrashConsistent(Vec<String>),
}

/// A snapshot verified against its manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub manifest: SnapshotManifest,
    pub consistency: Consistency,
    /// The append-only files the snapshot holds longer than the inventory: grown past the
    /// prepare, the prefix it bound intact. Information, never a difference.
    pub grown: Vec<String>,
}

/// The payload of `envelope`, a COSE_Sign1 of `protected_type` by the `host.operations` key it
/// names, as the keys bundle `verified` holds it, a revoked key refused (WP-7.8, WP-7.10).
/// `remedy` says how to get a bundle holding the key, when this one does not.
pub fn operations_payload(
    verified: &crate::keys::bundle::Verified,
    envelope: &[u8],
    protected_type: &str,
    remedy: &str,
) -> Result<Vec<u8>, String> {
    use crate::keys::bundle;

    let envelope = Sign1::decode(envelope).map_err(|error| format!("the manifest: {error}"))?;
    let header = envelope
        .header()
        .map_err(|error| format!("the manifest: {error}"))?;
    let kid = String::from_utf8(header.kid.clone())
        .map_err(|_| "the manifest's kid is not text".to_owned())?;
    let revoked = verified.items.iter().any(|item| {
        matches!(item, bundle::Item::Revocation { ring, kid: revoked, .. }
            if ring == HOST_OPERATIONS && *revoked == kid)
    });
    if revoked {
        return Err(format!("the manifest's key `{kid}` is revoked"));
    }
    let (suite, public_key) = verified
        .items
        .iter()
        .find_map(|item| match item {
            bundle::Item::Key {
                ring,
                kid: held,
                jwk,
                ..
            } if ring == HOST_OPERATIONS && *held == kid => serde_json::from_str::<Jwk>(jwk)
                .ok()
                .and_then(|jwk| bundle::public_of(&jwk)),
            _ => None,
        })
        .ok_or_else(|| format!("the bundle holds no `{HOST_OPERATIONS}` key `{kid}`: {remedy}"))?;
    envelope
        .verify(suite, &public_key, protected_type)
        .map(<[u8]>::to_vec)
        .map_err(|error| format!("the manifest's signature: {error}"))
}

/// Verifies the snapshot at `volume` offline (WP-7.8), from nothing in the snapshot but its files:
///
/// 1. the keys bundle the operator kept, verified from the identity `pin` for resource `host`;
/// 2. the manifest under that bundle's `host.operations` key it names, for that bundle's Host, a
///    revoked key refused;
/// 3. the snapshot's `VOLUME_ID` is the manifest's;
/// 4. the inventory beside the manifest against the manifest's digest and each root's;
/// 5. every file: the same bytes, or for an append-only one the same prefix.
///
/// A bundle, a signature, a volume or an inventory that does not verify is refused, never
/// labelled; a file that differs labels the snapshot crash-consistent.
pub fn verify(
    volume: &Path,
    manifest: &[u8],
    bundle_manifest: &[u8],
    bundle_items: &[Vec<u8>],
    pin: &str,
) -> Result<Verdict, String> {
    use crate::keys::bundle;

    if manifest.len() > MAX_MANIFEST_BYTES {
        return Err(format!(
            "a snapshot manifest takes at most {MAX_MANIFEST_BYTES} bytes"
        ));
    }
    let verified = bundle::verify(bundle_manifest, bundle_items, pin, "host")
        .map_err(|error| format!("the verification bundle: {error}"))?;
    let payload = operations_payload(
        &verified,
        manifest,
        protected::SNAPSHOT_MANIFEST,
        "export it after the prepare",
    )?;
    let manifest = SnapshotManifest::decode(&payload)?;
    if manifest.host_id != verified.identity.host_id {
        return Err("the manifest names another Host than the bundle".to_owned());
    }

    let held_id = std::fs::read(volume.join("host").join("VOLUME_ID"))
        .ok()
        .and_then(|bytes| {
            format::decode_file(&bytes, format::VIEW)
                .ok()
                .map(|(_, body)| body.to_vec())
        })
        .ok_or_else(|| "the snapshot holds no readable VOLUME_ID".to_owned())?;
    if held_id != manifest.volume_id {
        return Err("the snapshot is of another volume than the manifest's".to_owned());
    }

    let operation = hex(&manifest.operation_id);
    let inventory_path = volume
        .join("host")
        .join(DIRECTORY)
        .join(&operation)
        .join(INVENTORY);
    let dir = Dir::open(inventory_path.parent().unwrap_or(volume))
        .map_err(|error| format!("the snapshot's inventory: {error}"))?;
    let entries: Vec<Entry> = sequence::read(&dir, INVENTORY, MAX_ITEM)
        .map_err(|error| format!("the snapshot's inventory: {error}"))?
        .items
        .into_iter()
        .map(Entry::read)
        .collect::<Result<_, _>>()?;
    if !same(&inventory_digest(&entries)?, &manifest.inventory_digest) {
        return Err("the inventory is not the one the manifest binds".to_owned());
    }
    if roots_of(&entries)? != manifest.roots {
        return Err("the inventory's roots are not the manifest's".to_owned());
    }

    let mut differences = Vec::new();
    let mut grown = Vec::new();
    // A file the snapshot holds and the inventory does not is state past the barrier.
    let bound: std::collections::BTreeSet<&str> =
        entries.iter().map(|entry| entry.path.as_str()).collect();
    for (path, _, _) in files(volume)? {
        if !bound.contains(path.as_str()) {
            differences.push(format!("{path}: not in the manifest"));
        }
    }
    for entry in &entries {
        let path = volume.join(&entry.path);
        let Ok(metadata) = std::fs::symlink_metadata(&path) else {
            differences.push(format!("{}: missing", entry.path));
            continue;
        };
        if !metadata.is_file() {
            differences.push(format!("{}: not a regular file", entry.path));
            continue;
        }
        let shorter = metadata.len() < entry.length;
        let longer = metadata.len() > entry.length;
        if shorter || (longer && !entry.append) {
            differences.push(format!(
                "{}: {} bytes, the manifest's {}",
                entry.path,
                metadata.len(),
                entry.length
            ));
            continue;
        }
        let (digest, _) = file_digest(&path, Some(entry.length))?;
        if !same(&digest, &entry.digest) {
            differences.push(format!("{}: other bytes", entry.path));
        } else if longer {
            grown.push(entry.path.clone());
        }
    }
    differences.sort();
    Ok(Verdict {
        grown,
        manifest,
        consistency: if differences.is_empty() {
            Consistency::ApplicationConsistent
        } else {
            Consistency::CrashConsistent(differences)
        },
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use permguard_core::assurance::AssuranceProfile;

    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "pg-host-backup-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("the scratch directory");
        dir
    }

    fn manifest() -> SnapshotManifest {
        SnapshotManifest {
            operation_id: [1; 16],
            volume_id: [2; 16],
            host_id: [3; 16],
            revisions: BTreeMap::from([("mutations".to_owned(), 7)]),
            roots: vec![Root {
                name: "host".to_owned(),
                files: 2,
                bytes: 10,
                digest: [4; 32],
            }],
            at: 1_800_000_000,
            inventory_digest: [5; 32],
            recovery_key_id: Some("kms:recovery".to_owned()),
            encryption_profile: None,
        }
    }

    /// WP-7.8: a manifest round trips, its optional labels absent or present, and is closed: an
    /// unknown label, a missing one or another version is refused.
    #[test]
    fn a_manifest_round_trips_and_is_closed() {
        let held = manifest();
        assert_eq!(
            SnapshotManifest::decode(&held.encode().expect("encodes")).expect("decodes"),
            held
        );
        let bare = SnapshotManifest {
            recovery_key_id: None,
            ..manifest()
        };
        assert_eq!(
            SnapshotManifest::decode(&bare.encode().expect("encodes")).expect("decodes"),
            bare
        );
        let Value::Map(pairs) =
            cbor::decode_canonical(&held.encode().expect("encodes")).expect("canonical")
        else {
            panic!("a map");
        };
        let encode =
            |pairs: Vec<(Value, Value)>| cbor::encode(&Value::Map(pairs)).expect("encodes");
        let mut unknown = pairs.clone();
        unknown.push((Value::Int(11), Value::Int(0)));
        assert!(SnapshotManifest::decode(&encode(unknown)).is_err());
        let mut missing = pairs.clone();
        missing.retain(|(key, _)| *key != Value::Int(8));
        assert!(SnapshotManifest::decode(&encode(missing)).is_err());
        let mut other = pairs;
        other[0].1 = Value::Int(2);
        let refused = SnapshotManifest::decode(&encode(other)).expect_err("another version");
        assert!(refused.contains("version 2"), "{refused}");
    }

    /// WP-7.8: the inventory walks the three roots in path order, leaves out `host/backups/` and
    /// temporaries, marks journal segments and CBOR sequences append-only, and digests each root
    /// and the whole under the inventory domain.
    #[test]
    fn the_inventory_binds_every_file_of_the_roots() {
        let root = scratch("inventory");
        for (path, bytes) in [
            ("host/VOLUME_ID", b"id".as_slice()),
            ("host/backups/x/STATE", b"left out"),
            ("host/.tmp-0123", b"left out"),
            ("data/zones/z/journal.cborseq", b"\xa0"),
            ("operations/audit/seg-1.pgj", b"PGJRNSEG-and-frames"),
            ("operations/keys/key", b"wrapped"),
        ] {
            let path = root.join(path);
            std::fs::create_dir_all(path.parent().expect("a parent")).expect("dirs");
            std::fs::write(path, bytes).expect("written");
        }
        let entries = inventory(&root).expect("the inventory");
        let paths: Vec<(&str, bool)> = entries
            .iter()
            .map(|entry| (entry.path.as_str(), entry.append))
            .collect();
        assert_eq!(
            paths,
            vec![
                ("data/zones/z/journal.cborseq", true),
                ("host/VOLUME_ID", false),
                ("operations/audit/seg-1.pgj", true),
                ("operations/keys/key", false),
            ]
        );
        assert_eq!(entries[1].length, 2);
        assert_eq!(entries[1].digest, <[u8; 32]>::from(Sha256::digest(b"id")));
        let roots = roots_of(&entries).expect("roots");
        assert_eq!(
            roots
                .iter()
                .map(|root| (root.name.as_str(), root.files, root.bytes))
                .collect::<Vec<_>>(),
            vec![("host", 1, 2), ("data", 1, 1), ("operations", 2, 26)]
        );
        let mut expected = Sha256::new();
        expected.update(b"permguard.snapshot.inventory.v1\n");
        for entry in &entries {
            expected.update(entry.encode().expect("encodes"));
        }
        assert_eq!(
            inventory_digest(&entries).expect("digest"),
            <[u8; 32]>::from(expected.finalize())
        );
        assert_ne!(roots[0].digest, roots[1].digest);
    }

    /// WP-7.8: a backup a restart cut short while prepared is recorded aborted at the next open,
    /// and answered so the caller audits it; one already ended is left as it was.
    #[test]
    fn a_backup_a_restart_cut_short_is_recorded_aborted() {
        let root = scratch("restart");
        let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
        let backups = Backups::open(&volume).expect("opens");
        let cut = backups.cut(10).expect("cut");
        assert!(cut.is_empty());
        for (name, state) in [("a".repeat(32), PREPARED), ("b".repeat(32), FINALIZED)] {
            let dir = backups.dir.subdir(&name, true).expect("a backup");
            write_state(
                &dir,
                &State {
                    state: state.to_owned(),
                    at: 5,
                    snapshot_id: None,
                },
            )
            .expect("written");
        }
        drop(backups);
        let backups = Backups::open(&volume).expect("reopens");
        let cut = backups.cut(20).expect("cut");
        assert_eq!(cut, vec!["a".repeat(32)]);
        let listed = backups.list().expect("listed");
        let states: Vec<(&str, &str, Option<u64>)> = listed
            .iter()
            .map(|listed| {
                (
                    listed.operation_id.as_str(),
                    listed.state.as_str(),
                    listed.ended_at,
                )
            })
            .collect();
        assert!(
            states.contains(&(&*"a".repeat(32), ABORTED, Some(20))),
            "{states:?}"
        );
        assert!(
            states.contains(&(&*"b".repeat(32), FINALIZED, Some(5))),
            "{states:?}"
        );
        assert!(
            backups
                .observe(&OperationId::from_bytes([0xaa; 16]), None)
                .is_some()
        );
        assert!(
            backups
                .observe(&OperationId::from_bytes([0xcc; 16]), None)
                .is_none()
        );
    }

    /// WP-7.8: a snapshot id is 1 to 512 printable ASCII characters, no space, no control.
    #[test]
    fn a_snapshot_id_is_bounded_and_printable() {
        assert!(check_snapshot_id(&"s".repeat(512)).is_ok());
        for refused in [
            String::new(),
            "s".repeat(513),
            "a\tb".to_owned(),
            "a b".to_owned(),
        ] {
            assert!(check_snapshot_id(&refused).is_err(), "`{refused}`");
        }
    }

    /// WP-7.8: a state view names one of the three states, and nothing else.
    #[test]
    fn a_state_is_one_of_three() {
        let held = State {
            state: "held".to_owned(),
            at: 1,
            snapshot_id: None,
        };
        let refused = State::decode(&held.encode().expect("encodes")).expect_err("not a state");
        assert!(refused.contains("not a backup's state"), "{refused}");
        for state in [PREPARED, FINALIZED, ABORTED] {
            let held = State {
                state: state.to_owned(),
                ..held.clone()
            };
            assert_eq!(
                State::decode(&held.encode().expect("encodes")).expect("reads"),
                held
            );
        }
    }

    /// WP-7.8: an inventory item is closed and names a file below a root, nothing outside it.
    #[test]
    fn an_inventory_item_names_a_file_below_a_root() {
        let item = |path: &str| Entry {
            path: path.to_owned(),
            length: 1,
            digest: [0; 32],
            append: false,
        };
        let read = |entry: &Entry| {
            Entry::read(cbor::decode_canonical(&entry.encode().expect("encodes")).expect("cbor"))
        };
        assert_eq!(
            read(&item("data/a/b")).expect("below a root"),
            item("data/a/b")
        );
        for path in [
            "host",
            "other/x",
            "host/../x",
            "host//x",
            "host/./x",
            "/host/x",
            "host/x/",
        ] {
            assert!(read(&item(path)).is_err(), "`{path}`");
        }
        let Value::Map(mut pairs) =
            cbor::decode_canonical(&item("host/x").encode().expect("encodes")).expect("cbor")
        else {
            panic!("a map");
        };
        pairs.push((Value::Int(5), Value::Int(0)));
        assert!(Entry::read(Value::Map(pairs)).is_err(), "closed");
    }

    /// WP-7.8: an expiry ends only the backup it saw expire, and only past its deadline; a
    /// finalize or an abort shows to recovery only once the state moved on from `prepared`.
    #[test]
    fn an_ending_ends_only_what_it_names() {
        use crate::operations::mutation::Projection;

        struct Silent;
        impl Projection for Silent {
            fn project(&self, _: &permguard_core::AuditEvent<'_>) -> Result<(), String> {
                Ok(())
            }
        }
        let root = scratch("ending");
        let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
        let mutations = Mutations::open(
            &volume,
            std::sync::Arc::new(Silent),
            std::sync::Arc::new(crate::time::TimeGuard::system(Duration::from_secs(30))),
        )
        .expect("the transaction");
        let backups = Backups::open(&volume).expect("opens");
        let held = OperationId::from_bytes([0xaa; 16]);
        let name = held.to_string();
        let dir = backups.dir.subdir(&name, true).expect("a backup");
        write_state(
            &dir,
            &State {
                state: PREPARED.to_owned(),
                at: 1,
                snapshot_id: None,
            },
        )
        .expect("prepared");
        assert!(backups.observe(&held, None).is_some(), "its prepare shows");
        assert!(
            backups
                .observe(&OperationId::from_bytes([1; 16]), Some(&name))
                .is_none(),
            "an ending does not show while the backup is prepared"
        );
        let hold = |until: Instant| {
            *backups.held.lock().expect("held") = Some(Held {
                operation_id: held,
                token_digest: [0; 32],
                expires_at: 0,
                until,
            });
        };
        let aborted = || State {
            state: ABORTED.to_owned(),
            at: 2,
            snapshot_id: None,
        };
        let system = || Initiator::System("backup".to_owned());
        hold(Instant::now() + Duration::from_secs(60));
        assert_eq!(
            backups.end(
                &mutations,
                system(),
                Ending::Expired(held),
                ABORT,
                ABORTED_ACTION,
                aborted()
            ),
            Err(Refused::Unknown),
            "not yet expired"
        );
        hold(Instant::now());
        assert_eq!(
            backups.end(
                &mutations,
                system(),
                Ending::Expired(OperationId::from_bytes([0xbb; 16])),
                ABORT,
                ABORTED_ACTION,
                aborted()
            ),
            Err(Refused::Unknown),
            "another backup"
        );
        let ended = backups
            .end(
                &mutations,
                system(),
                Ending::Expired(held),
                ABORT,
                ABORTED_ACTION,
                aborted(),
            )
            .expect("the expired one ends");
        assert_eq!(ended.backup, held);
        assert!(
            backups.observe(&ended.operation_id, Some(&name)).is_some(),
            "its ending shows once the state moved on"
        );
        assert_eq!(
            read_state(&dir).expect("reads").expect("a state").state,
            ABORTED
        );
    }

    /// WP-7.8b review: a finalize a crash left between its intent and its write is failed by
    /// recovery, never reconciled as applied, because recovery runs before the cut; then the backup
    /// still prepared is cut to `aborted`, and the abort recorded.
    #[test]
    fn an_ending_a_crash_left_open_is_failed_before_the_cut() {
        use crate::operations::mutation::Projection;

        struct Silent;
        impl Projection for Silent {
            fn project(&self, _: &permguard_core::AuditEvent<'_>) -> Result<(), String> {
                Ok(())
            }
        }
        let root = scratch("crash-ending");
        let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
        let open = || {
            Mutations::open(
                &volume,
                std::sync::Arc::new(Silent),
                std::sync::Arc::new(crate::time::TimeGuard::system(Duration::from_secs(30))),
            )
            .expect("the transaction")
        };
        let backup = OperationId::from_bytes([0xaa; 16]).to_string();
        {
            let mutations = open();
            let backups = Backups::open(&volume).expect("opens");
            let dir = backups.dir.subdir(&backup, true).expect("a backup");
            write_state(
                &dir,
                &State {
                    state: PREPARED.to_owned(),
                    at: 1,
                    snapshot_id: None,
                },
            )
            .expect("prepared");
            // The finalize's intent is written; its own write never lands, as a crash would leave it.
            let interrupted = mutations.run(
                Begin {
                    domain: DOMAIN,
                    operation: FINALIZE,
                    action: FINALIZED_ACTION,
                    initiator: Initiator::System("test".to_owned()),
                    request: None,
                    target: Some(backup.clone()),
                },
                |_| -> Result<Applied<String>, Failure<String>> {
                    Err(Failure::Indeterminate("the process died".to_owned()))
                },
            );
            assert!(interrupted.is_err());
        }
        let mutations = open();
        let backups = Backups::open(&volume).expect("reopens");
        let recovered = mutations.recover(&backups).expect("recovered");
        assert!(
            recovered.reconciled.is_empty(),
            "never reconciled as applied"
        );
        assert_eq!(recovered.failed.len(), 1, "the finalize is failed");
        assert_eq!(backups.cut(5).expect("cut"), vec![backup.clone()]);
        assert_eq!(
            backups.record_cut(&mutations, std::slice::from_ref(&backup), 5),
            1
        );
        let listed = backups.list().expect("listed");
        assert_eq!(listed[0].state, ABORTED);
        assert_eq!(listed[0].snapshot_id, None);
    }
}
