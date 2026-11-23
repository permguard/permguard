// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The PostgreSQL backend of [`MemberStore`]: the memberships of the Host of one database.
//!
//! | Record     | Kept in                                                              |
//! | ---------- | -------------------------------------------------------------------- |
//! | entry      | `permguard_member_entries`, a row a sequence                         |
//! | view       | `permguard_member_views`: the summary, the manifests, the invitations |
//! | document   | `permguard_member_documents`, a row a document, keyed by what names it |
//! | checkpoint | `permguard_member_checkpoints`, a row a place of a trail             |
//!
//! An entry is the one after the last by the table's key: of the transitions that arrive
//! together, on any instance, one row is written and the others learn the memberships moved. A
//! document changed in place is written only where it still is what the change was given, so a
//! change is one step for every other writer of the document, alone or inside an operation.

use std::cell::RefCell;

use permguard_host::membership::MembershipError;
use permguard_host::membership::store::{Change, Doc, Listed, Listing, MemberStore};
use permguard_objects::cbor::{self, Value};

use crate::database::{Database, DbError, Failure, Unit};

impl From<DbError> for MembershipError {
    fn from(error: DbError) -> Self {
        Self::Storage(error.to_string())
    }
}

type Step<T> = Result<T, Failure<MembershipError>>;

/// The memberships of the Host of one database.
#[derive(Debug, Clone)]
pub struct PostgresMembers {
    database: Database,
}

/// What names a document: its kind, the membership or the operation it is of, and up to two
/// names within it. A part a kind does not have is empty.
struct Key<'a> {
    kind: &'static str,
    owner: &'a [u8; 16],
    scope: &'a str,
    name: String,
}

fn key<'a>(doc: &Doc<'a>) -> Key<'a> {
    let plain = |kind, owner, scope| Key {
        kind,
        owner,
        scope,
        name: String::new(),
    };
    match *doc {
        Doc::Lease { membership, task } => plain("lease", membership, task),
        Doc::Progress { membership, task } => plain("progress", membership, task),
        Doc::Session { membership, task } => plain("session", membership, task),
        Doc::Delivered { membership } => plain("delivered", membership, ""),
        Doc::ZoneReceipt {
            membership,
            task,
            resource,
        } => Key {
            kind: ZONE_RECEIPT,
            owner: membership,
            scope: task,
            name: resource.to_owned(),
        },
        Doc::ReplaySlot {
            membership,
            task,
            slot,
        } => Key {
            kind: REPLAY_SLOT,
            owner: membership,
            scope: task,
            name: slot.to_string(),
        },
        Doc::Verification { membership } => plain("verification", membership, ""),
        Doc::VerificationResult { operation } => plain("verification_result", operation, ""),
        Doc::Acks { membership, task } => plain("acks", membership, task),
        Doc::TrailName { membership, trail } => plain("trail_name", membership, trail),
        Doc::TrailLast { membership, trail } => plain("trail_last", membership, trail),
        Doc::TrailAnchor { membership, trail } => plain("trail_anchor", membership, trail),
        Doc::TrailFork { membership, trail } => plain(TRAIL_FORK, membership, trail),
    }
}

/// How many times a change is asked again on a document another writer moved under it.
const CHANGES: usize = 16;

const ZONE_RECEIPT: &str = "zone_receipt";
const REPLAY_SLOT: &str = "replay_slot";
const TRAIL_FORK: &str = "trail_fork";

fn number(value: u64) -> Step<i64> {
    i64::try_from(value).map_err(|_| {
        Failure::Refused(MembershipError::Invalid(
            "a number past what the store keeps".to_owned(),
        ))
    })
}

fn held(unit: &Unit, key: &Key<'_>) -> Step<Option<Vec<u8>>> {
    Ok(unit
        .query_opt(
            "SELECT record FROM permguard_member_documents
             WHERE kind = $1 AND owner = $2 AND scope = $3 AND name = $4",
            &[&key.kind, &key.owner.as_slice(), &key.scope, &key.name],
        )?
        .map(|row| row.get(0)))
}

fn kept(unit: &Unit, key: &Key<'_>, bytes: &[u8]) -> Step<()> {
    unit.execute(
        "INSERT INTO permguard_member_documents (kind, owner, scope, name, record)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (kind, owner, scope, name) DO UPDATE SET record = EXCLUDED.record",
        &[
            &key.kind,
            &key.owner.as_slice(),
            &key.scope,
            &key.name,
            &bytes,
        ],
    )?;
    Ok(())
}

impl PostgresMembers {
    /// The memberships in `database`, whose schema is this build's.
    pub fn new(database: Database) -> Self {
        Self { database }
    }

    fn unit<T>(&self, work: impl Fn(&Unit) -> Step<T>) -> Result<T, MembershipError> {
        self.database.transaction(work)?
    }

    fn view(&self, kind: &str, name: &str, bytes: &[u8]) -> Result<(), MembershipError> {
        self.unit(|unit| {
            unit.execute(
                "INSERT INTO permguard_member_views (kind, name, record) VALUES ($1, $2, $3)
                 ON CONFLICT (kind, name) DO UPDATE SET record = EXCLUDED.record",
                &[&kind, &name, &bytes],
            )?;
            Ok(())
        })
    }
}

fn hex(bytes: &[u8; 16]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

impl MemberStore for PostgresMembers {
    fn shared(&self) -> bool {
        true
    }

    fn entries_after(&self, seq: u64) -> Result<Vec<Value>, MembershipError> {
        self.unit(|unit| {
            let after = number(seq)?;
            unit.query(
                "SELECT entry FROM permguard_member_entries WHERE seq > $1 ORDER BY seq",
                &[&after],
            )?
            .into_iter()
            .map(|row| {
                cbor::decode_canonical(&row.get::<_, Vec<u8>>(0)).map_err(|error| {
                    Failure::Refused(MembershipError::Storage(format!(
                        "an entry held does not read: {error:?}"
                    )))
                })
            })
            .collect()
        })
    }

    fn entries(&self) -> Result<Vec<Value>, MembershipError> {
        self.unit(|unit| {
            unit.query(
                "SELECT entry FROM permguard_member_entries ORDER BY seq",
                &[],
            )?
            .into_iter()
            .map(|row| {
                cbor::decode_canonical(&row.get::<_, Vec<u8>>(0)).map_err(|error| {
                    Failure::Refused(MembershipError::Storage(format!(
                        "an entry held does not read: {error:?}"
                    )))
                })
            })
            .collect()
        })
    }

    fn append(&self, seq: u64, entry: &[u8]) -> Result<(), MembershipError> {
        self.unit(|unit| {
            let last: i64 = unit
                .query_one(
                    "SELECT COALESCE(MAX(seq), 0) FROM permguard_member_entries",
                    &[],
                )?
                .get(0);
            let moved = |current: i64| {
                Failure::Refused(MembershipError::Conflict {
                    expected: seq.saturating_sub(1),
                    current: current.unsigned_abs(),
                })
            };
            if number(seq)? != last + 1 {
                return Err(moved(last));
            }
            // Another instance that read the same last entry writes the same key: one row is
            // written, and this unit of work, run again, reads the entries as they then stand.
            let added = unit.execute(
                "INSERT INTO permguard_member_entries (seq, entry) VALUES ($1, $2)
                 ON CONFLICT (seq) DO NOTHING",
                &[&(last + 1), &entry],
            )?;
            if added == 1 {
                Ok(())
            } else {
                Err(moved(last + 1))
            }
        })
    }

    fn replace_summary(&self, summary: &[u8]) -> Result<(), MembershipError> {
        self.view("summary", "", summary)
    }

    fn keep_manifest(
        &self,
        membership: &[u8; 16],
        epoch: u64,
        digest: &str,
        envelope: &[u8],
    ) -> Result<(), MembershipError> {
        // The manifest of an epoch is named by its digest; the current one is the one of the
        // highest epoch kept.
        self.view(
            "manifest",
            &format!("{}/{epoch:020}/{digest}", hex(membership)),
            envelope,
        )
    }

    fn keep_invitation(&self, invite: &[u8; 16], invitation: &[u8]) -> Result<(), MembershipError> {
        self.view("invitation", &hex(invite), invitation)
    }

    fn doc(&self, doc: &Doc<'_>) -> Result<Option<Vec<u8>>, MembershipError> {
        let key = key(doc);
        self.unit(|unit| held(unit, &key))
    }

    fn keep(&self, doc: &Doc<'_>, bytes: &[u8]) -> Result<(), MembershipError> {
        let key = key(doc);
        self.unit(|unit| kept(unit, &key, bytes))
    }

    fn change(&self, doc: &Doc<'_>, change: Change<'_>) -> Result<(), MembershipError> {
        let key = key(doc);
        // Asked again when its unit of work is: it is then given what the document holds then.
        let change = RefCell::new(change);
        let work = |unit: &Unit| {
            // The document is written only where it still is what the change was given: a
            // writer that got in between, on any instance and in whatever unit of work, is
            // seen, and the change is asked again on what that writer kept.
            for _ in 0..CHANGES {
                let before = held(unit, &key)?;
                let Some(after) =
                    (*change.borrow_mut())(before.as_deref()).map_err(Failure::Refused)?
                else {
                    return Ok(());
                };
                let owner = key.owner.as_slice();
                let written = match &before {
                    None => unit.execute(
                        "INSERT INTO permguard_member_documents (kind, owner, scope, name, record)
                         VALUES ($1, $2, $3, $4, $5)
                         ON CONFLICT (kind, owner, scope, name) DO NOTHING",
                        &[&key.kind, &owner, &key.scope, &key.name, &after],
                    )?,
                    Some(before) => unit.execute(
                        "UPDATE permguard_member_documents SET record = $5
                         WHERE kind = $1 AND owner = $2 AND scope = $3 AND name = $4
                           AND record = $6",
                        &[&key.kind, &owner, &key.scope, &key.name, &after, before],
                    )?,
                };
                if written == 1 {
                    return Ok(());
                }
            }
            Err(Failure::Refused(MembershipError::Storage(format!(
                "a document kept changing under {CHANGES} changes of it"
            ))))
        };
        // Inside an operation the change is part of its unit of work. Alone, it also waits its
        // turn on the document: many change one document at once, a progress report or an
        // acknowledgement, and asking each again and again would cost more than the wait.
        if self.database.inside() {
            return self.database.transaction(work)?;
        }
        let scope = format!(
            "member-document/{}/{}/{}/{}",
            key.kind,
            hex(key.owner),
            key.scope,
            key.name
        );
        self.database.under_scope(&scope, work)?
    }

    fn remove(&self, doc: &Doc<'_>) -> Result<bool, MembershipError> {
        let key = key(doc);
        self.unit(|unit| {
            Ok(unit.execute(
                "DELETE FROM permguard_member_documents
                 WHERE kind = $1 AND owner = $2 AND scope = $3 AND name = $4",
                &[&key.kind, &key.owner.as_slice(), &key.scope, &key.name],
            )? == 1)
        })
    }

    fn list(&self, listing: &Listing<'_>) -> Result<Vec<Listed>, MembershipError> {
        // A receipt is named by its resource and a slot by its number, within their task; a
        // fork is named by its trail, within its membership.
        let (kind, owner, scope, named) = match *listing {
            Listing::ZoneReceipts { membership, task } => {
                (ZONE_RECEIPT, membership, Some(task), "name")
            }
            Listing::ReplaySlots { membership, task } => {
                (REPLAY_SLOT, membership, Some(task), "name")
            }
            Listing::TrailForks { membership } => (TRAIL_FORK, membership, None, "scope"),
        };
        self.unit(|unit| {
            Ok(unit
                .query(
                    &format!(
                        "SELECT {named}, record FROM permguard_member_documents
                         WHERE kind = $1 AND owner = $2 AND ($3::text IS NULL OR scope = $3)
                         ORDER BY {named} COLLATE \"C\""
                    ),
                    &[&kind, &owner.as_slice(), &scope],
                )?
                .into_iter()
                .map(|row| Listed {
                    name: row.get(0),
                    bytes: Ok(row.get(1)),
                })
                .collect())
        })
    }

    fn checkpoint(
        &self,
        membership: &[u8; 16],
        trail: &str,
        count: u64,
    ) -> Result<Option<Vec<u8>>, MembershipError> {
        self.unit(|unit| {
            Ok(unit
                .query_opt(
                    "SELECT envelope FROM permguard_member_checkpoints
                     WHERE membership = $1 AND trail = $2 AND count = $3",
                    &[&membership.as_slice(), &trail, &number(count)?],
                )?
                .map(|row| row.get(0)))
        })
    }

    fn publish_checkpoint(
        &self,
        membership: &[u8; 16],
        trail: &str,
        count: u64,
        envelope: &[u8],
    ) -> Result<(), MembershipError> {
        self.unit(|unit| {
            let count = number(count)?;
            // Published once: of the checkpoints that arrive together at a place one is kept,
            // and every other caller is judged against it.
            unit.execute(
                "INSERT INTO permguard_member_checkpoints (membership, trail, count, envelope)
                 VALUES ($1, $2, $3, $4) ON CONFLICT (membership, trail, count) DO NOTHING",
                &[&membership.as_slice(), &trail, &count, &envelope],
            )?;
            let held: Vec<u8> = unit
                .query_one(
                    "SELECT envelope FROM permguard_member_checkpoints
                     WHERE membership = $1 AND trail = $2 AND count = $3",
                    &[&membership.as_slice(), &trail, &count],
                )?
                .get(0);
            if held == envelope {
                Ok(())
            } else {
                Err(Failure::Refused(MembershipError::Storage(
                    "another checkpoint is kept at that place of the trail; it is left as it was"
                        .to_owned(),
                )))
            }
        })
    }
}
