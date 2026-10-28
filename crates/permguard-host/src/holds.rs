// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Legal and incident holds (WP-7.3c, owner decisions of 2026-10-21).
//!
//! A hold is an explicit Host file that keeps what a ledger, or every ledger of a zone, holds
//! from the garbage collection: `host/holds/<hold-id>.json`, naming the resource by ids, never by
//! names, with who owns it, why, and either when it expires or when it is due for review.
//!
//! | Field        | Meaning                                                                   |
//! | ------------ | ------------------------------------------------------------------------- |
//! | `id`         | a UUIDv7, the file's name                                                 |
//! | `resource`   | `plane/control/zone/<id>/ledger/<id>`, or `plane/control/zone/<id>`       |
//! | `owner`      | who answers for it, free text                                             |
//! | `reason`     | why, free text                                                            |
//! | `created_at` | seconds since the Unix epoch                                              |
//! | `expires_at` | from it on, the hold keeps nothing and is `expired`                       |
//! | `review_at`  | from it on, the hold still keeps and is `review_due`                      |
//!
//! Exactly one of `expires_at` and `review_at` is set. Adding and releasing a hold are operations
//! of the Host's security-mutation transaction (WP-3.6), domain `holds`, under the phased actions
//! `host.hold.added` and `host.hold.released`; their records name the hold's id and resource and
//! never its free text, and neither does the answer the transaction's journal commits. A release
//! removes the file.
//!
//! A hold's file is read whole or refused: at most [`MAX_HOLD_BYTES`], closed, its ids lowercase
//! GUIDs of a Control Plane zone or ledger, exactly one deadline, times no later than the year
//! 9999. Recovery reads an add whose file lacks its operation, and a release whose file does not
//! read, as failed: the hold stays, and a store that does not read keeps the garbage collection
//! from sweeping.

use std::fmt;

use permguard_core::authz::Resource;
use permguard_core::catalog::is_guid_shaped;
use serde::{Deserialize, Serialize};

use crate::operations::journal::{Initiator, OperationId};
use crate::operations::mutation::{
    Applied, Applying, Begin, Domain, Failure, MutationError, Mutations, Observed, Outcome,
};
use crate::storage::volume::Volume;
use crate::storage::write::replace_bytes;
use crate::storage::{Dir, StorageError};

/// The directory under `host/` the holds live in.
pub const DIRECTORY: &str = "holds";

/// The domain name intents carry.
pub const DOMAIN: &str = "holds";

/// The operations.
pub const ADD: &str = "holds.add";
pub const RELEASE: &str = "holds.release";

/// The `security` audit actions their records carry.
pub const AUDIT_ADDED: &str = "host.hold.added";
pub const AUDIT_RELEASED: &str = "host.hold.released";

/// The Plane whose ledgers a hold keeps.
const PLANE: &str = "control";

/// The longest `owner` or `reason`, in bytes.
pub const MAX_TEXT: usize = 1024;

/// The largest hold file read, in bytes: two texts at their longest and the rest, with room.
pub const MAX_HOLD_BYTES: u64 = 8 * 1024;

/// The latest time a hold carries: 9999-12-31T23:59:59Z.
const MAX_TIME: u64 = 253_402_300_799;

/// One hold, as its file holds it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hold {
    pub id: String,
    pub resource: String,
    pub owner: String,
    pub reason: String,
    pub created_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review_at: Option<u64>,
    /// The operation that wrote it, for recovery.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
}

/// When a new hold stops keeping, or is looked at again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Deadline {
    Expires(u64),
    Review(u64),
}

/// What an operator asks to hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewHold {
    pub resource: String,
    pub owner: String,
    pub reason: String,
    pub deadline: Deadline,
}

/// Where a hold stands at a moment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Active,
    ReviewDue,
    Expired,
}

impl Status {
    /// The word a report carries.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::ReviewDue => "review_due",
            Self::Expired => "expired",
        }
    }
}

impl Hold {
    /// Where the hold stands at `now`.
    pub fn status(&self, now: u64) -> Status {
        match (self.expires_at, self.review_at) {
            (Some(at), _) if now >= at => Status::Expired,
            (_, Some(at)) if now >= at => Status::ReviewDue,
            _ => Status::Active,
        }
    }

    /// Whether the hold keeps the ledger `zone_id`/`ledger_id` at `now`: one it names, or one of
    /// the zone it names, unless it expired.
    pub fn keeps(&self, zone_id: &str, ledger_id: &str, now: u64) -> bool {
        if self.status(now) == Status::Expired {
            return false;
        }
        match Resource::parse(&self.resource) {
            Ok(Resource::Zone { plane, zone_id: z }) => plane == PLANE && z == zone_id,
            Ok(Resource::Ledger {
                plane,
                zone_id: z,
                ledger_id: l,
            }) => plane == PLANE && z == zone_id && l == ledger_id,
            _ => false,
        }
    }
}

/// Why a hold operation did not happen.
#[derive(Debug)]
pub enum HoldError {
    /// The hold asked for is not one this Host keeps.
    Invalid(String),
    /// No hold has this id.
    NotFound(String),
    /// The holds directory failed.
    Storage(StorageError),
    /// A hold's file does not read as one.
    Record(String),
}

impl fmt::Display for HoldError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(detail) => write!(f, "not a hold this Host keeps: {detail}"),
            Self::NotFound(id) => write!(f, "no hold has the id `{id}`"),
            Self::Storage(error) => write!(f, "the holds could not be read or written: {error}"),
            Self::Record(detail) => write!(f, "a hold does not read: {detail}"),
        }
    }
}

impl std::error::Error for HoldError {}

impl From<StorageError> for HoldError {
    fn from(error: StorageError) -> Self {
        Self::Storage(error)
    }
}

/// Whether `id` is an id as the catalog mints them: a GUID in lowercase hex, compared byte for
/// byte (after the review).
fn is_catalog_id(id: &str) -> bool {
    is_guid_shaped(id) && !id.chars().any(|c| c.is_ascii_uppercase())
}

/// An invisible formatting character: a soft hyphen, a zero-width or joining character, a
/// bidirectional control, a word joiner or a byte order mark; a report prints the text as it is.
fn is_format(c: char) -> bool {
    matches!(
        c,
        '\u{00ad}'
            | '\u{200b}'..='\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206f}'
            | '\u{feff}'
    )
}

/// The ids a resource names, when it is a Control Plane zone or ledger named by catalog ids.
fn resource_ids(resource: &str) -> Option<Vec<String>> {
    let ids = match Resource::parse(resource) {
        Ok(Resource::Zone { plane, zone_id }) if plane == PLANE => vec![zone_id],
        Ok(Resource::Ledger {
            plane,
            zone_id,
            ledger_id,
        }) if plane == PLANE => vec![zone_id, ledger_id],
        _ => return None,
    };
    ids.iter().all(|id| is_catalog_id(id)).then_some(ids)
}

/// Whether `text` is an owner or a reason a hold carries.
fn is_text(text: &str) -> bool {
    !text.trim().is_empty()
        && text.len() <= MAX_TEXT
        && !text.chars().any(|c| c.is_control() || is_format(c))
}

/// Refuses a hold this Host would never keep: a resource that is not a zone or a ledger of the
/// Control Plane by ids, an empty or overlong owner or reason, or a deadline already past.
pub fn validate(new: &NewHold, now: u64) -> Result<(), HoldError> {
    let ids = match Resource::parse(&new.resource) {
        Ok(Resource::Zone { plane, zone_id }) if plane == PLANE => vec![zone_id],
        Ok(Resource::Ledger {
            plane,
            zone_id,
            ledger_id,
        }) if plane == PLANE => vec![zone_id, ledger_id],
        _ => {
            return Err(HoldError::Invalid(format!(
                "`{}` is not `plane/control/zone/<id>` or `plane/control/zone/<id>/ledger/<id>`",
                new.resource
            )));
        }
    };
    if !ids.iter().all(|id| is_catalog_id(id)) {
        return Err(HoldError::Invalid(
            "a hold names its zone and ledger by their ids, lowercase as the catalog mints them, \
             never by names"
                .to_owned(),
        ));
    }
    for (what, text) in [("owner", &new.owner), ("reason", &new.reason)] {
        if !is_text(text) {
            return Err(HoldError::Invalid(format!(
                "the {what} is required, at most {MAX_TEXT} bytes and free of control and \
                 invisible formatting characters"
            )));
        }
    }
    let (Deadline::Expires(at) | Deadline::Review(at)) = new.deadline;
    if at <= now || at > MAX_TIME {
        return Err(HoldError::Invalid(
            "a hold's expiry or review date is in the future, no later than the year 9999"
                .to_owned(),
        ));
    }
    Ok(())
}

/// What the transaction's journal commits of a hold change: its id and resource, never its free
/// text (after the review); the caller answers the whole hold.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Committed {
    id: String,
    resource: String,
}

/// The holds of a volume, under `host/holds/`.
pub struct HoldStore {
    dir: Dir,
}

/// A hold's file name, from an id that is one.
fn file(id: &str) -> Option<String> {
    is_catalog_id(id).then(|| format!("{id}.json"))
}

impl HoldStore {
    /// The holds of `volume`, the directory created when absent.
    pub fn open(volume: &Volume) -> Result<Self, StorageError> {
        Ok(Self {
            dir: volume.host().subdir(DIRECTORY, true)?,
        })
    }

    /// Every hold, by id. A file that does not read is an error, never skipped: what a hold
    /// keeps is not guessed.
    pub fn list(&self) -> Result<Vec<Hold>, HoldError> {
        let mut holds = Vec::new();
        for name in self.dir.names()? {
            let Some(id) = name.strip_suffix(".json") else {
                continue;
            };
            if !is_guid_shaped(id) {
                continue;
            }
            holds.push(self.read(&name)?);
        }
        holds.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(holds)
    }

    /// The hold `id`, when there is one.
    pub fn get(&self, id: &str) -> Result<Option<Hold>, HoldError> {
        let Some(name) = file(id) else {
            return Ok(None);
        };
        if !self.dir.exists(&name)? {
            return Ok(None);
        }
        self.read(&name).map(Some)
    }

    /// Whether any hold keeps the ledger `zone_id`/`ledger_id` at `now`.
    pub fn keeps(&self, zone_id: &str, ledger_id: &str, now: u64) -> Result<bool, HoldError> {
        Ok(self
            .list()?
            .iter()
            .any(|hold| hold.keeps(zone_id, ledger_id, now)))
    }

    fn read(&self, name: &str) -> Result<Hold, HoldError> {
        use std::io::Read as _;

        let file_handle = self
            .dir
            .open_read(name)?
            .ok_or_else(|| HoldError::Record(format!("{name} vanished while it was read")))?;
        let mut bytes = Vec::new();
        file_handle
            .take(MAX_HOLD_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| HoldError::Record(format!("{name}: {error}")))?;
        if bytes.len() as u64 > MAX_HOLD_BYTES {
            return Err(HoldError::Record(format!(
                "{name} is larger than {MAX_HOLD_BYTES} bytes"
            )));
        }
        let hold: Hold = serde_json::from_slice(&bytes)
            .map_err(|error| HoldError::Record(format!("{name}: {error}")))?;
        let refused = |why: &str| Err(HoldError::Record(format!("{name}: {why}")));
        if file(&hold.id).as_deref() != Some(name) || !is_catalog_id(&hold.id) {
            return refused("it names another hold");
        }
        if resource_ids(&hold.resource).is_none() {
            return refused("its resource is not a Control Plane zone or ledger by ids");
        }
        if !is_text(&hold.owner) || !is_text(&hold.reason) {
            return refused("its owner or reason is not one a hold carries");
        }
        let deadline = match (hold.expires_at, hold.review_at) {
            (Some(at), None) | (None, Some(at)) => at,
            _ => return refused("it carries both deadlines, or neither"),
        };
        if deadline > MAX_TIME || hold.created_at > MAX_TIME {
            return refused("a time past the year 9999");
        }
        Ok(hold)
    }

    /// Writes `hold`, inside the operation `applying`.
    fn write(&self, applying: &Applying<'_>, hold: &Hold) -> Result<(), HoldError> {
        let _ = applying;
        let name = file(&hold.id).ok_or_else(|| HoldError::Invalid("an id".to_owned()))?;
        let bytes = serde_json::to_vec_pretty(hold)
            .map_err(|error| HoldError::Record(error.to_string()))?;
        replace_bytes(&self.dir, &name, &bytes)?;
        Ok(())
    }

    /// Removes the hold `id`, inside the operation `applying`.
    fn remove(&self, applying: &Applying<'_>, id: &str) -> Result<(), HoldError> {
        let _ = applying;
        let name = file(id).ok_or_else(|| HoldError::NotFound(id.to_owned()))?;
        self.dir.unlink(&name)?;
        self.dir.sync()?;
        Ok(())
    }
}

/// The holds as recovery sees them: an add shows when its file names the operation; a release,
/// when the file is gone.
pub struct Holds<'a>(pub &'a HoldStore);

impl Domain for Holds<'_> {
    fn name(&self) -> &'static str {
        DOMAIN
    }

    fn observe(&self, operation_id: &OperationId, target: Option<&str>) -> Option<Observed> {
        let target = target?;
        let (verb, rest) = target.split_once('/')?;
        let id = rest.split('/').next()?;
        let held = self.0.get(id).ok()?;
        let shown = match verb {
            "hold" => held?.operation.as_deref() == Some(operation_id.to_string().as_str()),
            "released" => held.is_none(),
            _ => false,
        };
        shown.then(|| Observed {
            revision: 1,
            target: Some(target.to_owned()),
        })
    }
}

/// A fresh hold id, a UUIDv7.
fn mint() -> Result<String, HoldError> {
    use ring::rand::SecureRandom as _;

    let mut random = [0u8; 10];
    ring::rand::SystemRandom::new()
        .fill(&mut random)
        .map_err(|_| HoldError::Invalid("the OS random source refused a hold id".to_owned()))?;
    let millis = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_millis() as u64);
    Ok(crate::identity::record::uuid_text(
        &crate::identity::record::uuid_v7(millis, random),
    ))
}

/// How a store error ends an operation: a write that failed may have landed.
fn failure(error: HoldError) -> Failure<HoldError> {
    match error {
        HoldError::Storage(_) => Failure::Indeterminate(error),
        other => Failure::Refused(other),
    }
}

/// The answer of an operation: the whole hold, which the journal never commits.
fn answered(
    outcome: Outcome<Committed>,
    answer: impl FnOnce() -> Result<Hold, HoldError>,
) -> Result<Hold, MutationError<HoldError>> {
    match outcome {
        Outcome::Applied(_) | Outcome::Replayed(_) | Outcome::Reconciled { .. } => {
            answer().map_err(MutationError::Refused)
        }
    }
}

/// Adds the hold `new` as `initiator` at `now`: refused before any operation when it is not one
/// this Host would keep.
pub fn add(
    mutations: &Mutations,
    store: &HoldStore,
    initiator: Initiator,
    new: NewHold,
    now: u64,
) -> Result<Hold, MutationError<HoldError>> {
    validate(&new, now).map_err(MutationError::Refused)?;
    let id = mint().map_err(MutationError::Refused)?;
    let target = format!("hold/{id}/{}", new.resource);
    let (expires_at, review_at) = match new.deadline {
        Deadline::Expires(at) => (Some(at), None),
        Deadline::Review(at) => (None, Some(at)),
    };
    let outcome = mutations.run(
        Begin {
            domain: DOMAIN,
            operation: ADD,
            action: AUDIT_ADDED,
            initiator,
            request: None,
            target: Some(target.clone()),
        },
        |applying| {
            let hold = Hold {
                id: id.clone(),
                resource: new.resource.clone(),
                owner: new.owner.clone(),
                reason: new.reason.clone(),
                created_at: now,
                expires_at,
                review_at,
                operation: Some(applying.operation_id().to_string()),
            };
            store.write(applying, &hold).map_err(failure)?;
            Ok(Applied {
                revision: 1,
                target: Some(target.clone()),
                value: Committed {
                    id: hold.id,
                    resource: hold.resource,
                },
            })
        },
    )?;
    answered(outcome, || {
        store
            .get(&id)?
            .ok_or_else(|| HoldError::NotFound(id.clone()))
    })
}

/// Releases the hold `id` as `initiator`: its file is removed.
pub fn release(
    mutations: &Mutations,
    store: &HoldStore,
    initiator: Initiator,
    id: &str,
) -> Result<Hold, MutationError<HoldError>> {
    let held = store
        .get(id)
        .map_err(MutationError::Refused)?
        .ok_or_else(|| MutationError::Refused(HoldError::NotFound(id.to_owned())))?;
    let target = format!("released/{}/{}", held.id, held.resource);
    let outcome = mutations.run(
        Begin {
            domain: DOMAIN,
            operation: RELEASE,
            action: AUDIT_RELEASED,
            initiator,
            request: None,
            target: Some(target.clone()),
        },
        |applying| {
            store.remove(applying, &held.id).map_err(failure)?;
            Ok(Applied {
                revision: 1,
                target: Some(target.clone()),
                value: Committed {
                    id: held.id.clone(),
                    resource: held.resource.clone(),
                },
            })
        },
    )?;
    answered(outcome, || Ok(held.clone()))
}

#[cfg(test)]
mod tests;
