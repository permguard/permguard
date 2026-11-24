// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The conformance suite of [`Catalog`]: what every backend of the contract does the same way
//! (`1-architecture/8` Store contracts).
//!
//! [`run`] takes how a backend makes one empty catalog and runs every case on a catalog of its
//! own. A case panics with what it expected, as a test does. A backend proves what only it can,
//! that its records survive its own restart and what it does of a record damaged at rest, in its
//! own tests.
//!
//! | Case                                   | Rule of the contract                                        |
//! | -------------------------------------- | ----------------------------------------------------------- |
//! | `an_empty_catalog`                     | no zone listed, none found                                  |
//! | `a_zone_lives_and_keeps_its_id`        | found by name and by id; a rename keeps the id              |
//! | `names_are_unique_in_their_scope`      | a zone name once; a ledger name once a zone                 |
//! | `a_zone_holding_ledgers_is_kept`       | a zone is deleted only once it holds no ledger              |
//! | `records_are_listed_as_created`        | zones and ledgers are listed in the order they were created |
//! | `a_revision_starts_at_1_and_moves`     | each change moves it by one and keeps its operation         |
//! | `a_stale_revision_changes_nothing`     | a change held to another revision is refused                |
//! | `a_deleted_ledger_leaves_a_tombstone`  | gone from listing and lookup; its name free, its id not     |
//! | `a_deleted_zone_leaves_a_tombstone`    | as a ledger's, and its ledgers' tombstones stay             |
//! | `a_ledger_is_archived_and_restored`    | a change of state moves the revision; no change moves none  |
//! | `a_provenance_is_kept_from_creation`   | what a re-homed ledger was created with is read back        |
//! | `zones_created_together_are_one`       | of the creations of one zone name at once, one succeeds     |
//! | `ledgers_created_together_are_one`     | of the creations of one ledger name at once, one succeeds   |
//! | `changes_together_apply_once`          | of the changes held to one revision at once, one succeeds   |

#![allow(clippy::expect_used, clippy::panic)]

use std::sync::{Arc, Barrier};

use super::{
    Catalog, CatalogError, FIRST_REVISION, ImportedHead, LedgerState, Provenance, Selector, Write,
};

/// How many callers a concurrency case releases at once.
const TOGETHER: usize = 8;

/// Runs every case, each on a catalog `make` made empty for it.
pub fn run(make: &dyn Fn() -> Arc<dyn Catalog>) {
    an_empty_catalog(make().as_ref());
    a_zone_lives_and_keeps_its_id(make().as_ref());
    names_are_unique_in_their_scope(make().as_ref());
    a_zone_holding_ledgers_is_kept(make().as_ref());
    records_are_listed_as_created(make().as_ref());
    a_revision_starts_at_1_and_moves(make().as_ref());
    a_stale_revision_changes_nothing(make().as_ref());
    a_deleted_ledger_leaves_a_tombstone(make().as_ref());
    a_deleted_zone_leaves_a_tombstone(make().as_ref());
    a_ledger_is_archived_and_restored(make().as_ref());
    a_provenance_is_kept_from_creation(make().as_ref());
    zones_created_together_are_one(&make());
    ledgers_created_together_are_one(&make());
    changes_together_apply_once(&make());
}

/// A write held to `revision`, by the operation `operation`.
fn at<'a>(revision: u64, operation: &'a str) -> Write<'a> {
    Write {
        expected_revision: Some(revision),
        operation: Some(operation),
        provenance: None,
    }
}

/// What each of `TOGETHER` callers, released at once, was answered by `call`.
fn together<T: Send + 'static>(call: impl Fn(usize) -> T + Send + Sync + 'static) -> Vec<T> {
    let call = Arc::new(call);
    let barrier = Arc::new(Barrier::new(TOGETHER));
    let callers: Vec<_> = (0..TOGETHER)
        .map(|caller| {
            let (call, barrier) = (Arc::clone(&call), Arc::clone(&barrier));
            std::thread::spawn(move || {
                barrier.wait();
                call(caller)
            })
        })
        .collect();
    callers
        .into_iter()
        .map(|caller| caller.join().expect("a caller finished"))
        .collect()
}

fn an_empty_catalog(catalog: &dyn Catalog) {
    assert!(catalog.list_zones().expect("listed").is_empty());
    assert!(matches!(
        catalog.get_zone(&Selector::parse("delivery")),
        Err(CatalogError::NotFound { .. })
    ));
}

fn a_zone_lives_and_keeps_its_id(catalog: &dyn Catalog) {
    let zone = catalog.create_zone("delivery").expect("created");
    assert_eq!(zone.name, "delivery");
    assert!(super::is_guid_shaped(&zone.id), "the id is a GUID");
    let by_name = catalog
        .get_zone(&Selector::parse("delivery"))
        .expect("found by name");
    let by_id = catalog
        .get_zone(&Selector::parse(&zone.id))
        .expect("found by id");
    assert_eq!(by_name, by_id);

    let renamed = catalog
        .rename_zone(&Selector::parse("delivery"), "delivery-eu")
        .expect("renamed");
    assert_eq!(renamed.id, zone.id, "a rename keeps the id");
    assert!(matches!(
        catalog.get_zone(&Selector::parse("delivery")),
        Err(CatalogError::NotFound { .. })
    ));

    let deleted = catalog
        .delete_zone(&Selector::parse("delivery-eu"))
        .expect("deleted");
    assert_eq!(deleted.id, zone.id);
    assert!(matches!(
        catalog.get_zone(&Selector::parse(&zone.id)),
        Err(CatalogError::NotFound { .. })
    ));
    assert!(catalog.list_zones().expect("listed").is_empty());
}

fn names_are_unique_in_their_scope(catalog: &dyn Catalog) {
    catalog.create_zone("alpha").expect("a zone");
    catalog.create_zone("beta").expect("another");
    assert!(matches!(
        catalog.create_zone("alpha"),
        Err(CatalogError::NameTaken { .. })
    ));
    assert!(matches!(
        catalog.rename_zone(&Selector::parse("beta"), "alpha"),
        Err(CatalogError::NameTaken { .. })
    ));
    let alpha = Selector::parse("alpha");
    catalog
        .create_ledger(&alpha, "policies")
        .expect("a ledger in alpha");
    assert!(matches!(
        catalog.create_ledger(&alpha, "policies"),
        Err(CatalogError::NameTaken { .. })
    ));
    catalog
        .create_ledger(&Selector::parse("beta"), "policies")
        .expect("the same name in another zone is another ledger");
    catalog.create_ledger(&alpha, "rules").expect("a second");
    assert!(matches!(
        catalog.rename_ledger(&alpha, &Selector::parse("rules"), "policies"),
        Err(CatalogError::NameTaken { .. })
    ));
    assert_eq!(catalog.list_zones().expect("listed").len(), 2);
    assert_eq!(catalog.list_ledgers(&alpha).expect("listed").len(), 2);
}

fn a_zone_holding_ledgers_is_kept(catalog: &dyn Catalog) {
    let zone = Selector::parse("keeper");
    catalog.create_zone("keeper").expect("a zone");
    catalog.create_ledger(&zone, "held").expect("a ledger");
    assert!(matches!(
        catalog.delete_zone(&zone),
        Err(CatalogError::NotEmpty { ledgers: 1, .. })
    ));
    catalog.get_zone(&zone).expect("the zone is kept");
    catalog
        .delete_ledger(&zone, &Selector::parse("held"))
        .expect("the ledger goes first");
    catalog.delete_zone(&zone).expect("then the zone");
}

fn records_are_listed_as_created(catalog: &dyn Catalog) {
    for name in ["first", "second", "third"] {
        catalog.create_zone(name).expect("a zone");
    }
    let listed: Vec<String> = catalog
        .list_zones()
        .expect("listed")
        .into_iter()
        .map(|zone| zone.name)
        .collect();
    assert_eq!(listed, ["first", "second", "third"]);
    let zone = Selector::parse("second");
    for name in ["policies", "rules", "audit"] {
        catalog.create_ledger(&zone, name).expect("a ledger");
    }
    let listed: Vec<String> = catalog
        .list_ledgers(&zone)
        .expect("listed")
        .into_iter()
        .map(|ledger| ledger.name)
        .collect();
    assert_eq!(listed, ["policies", "rules", "audit"]);
    assert!(
        catalog
            .list_ledgers(&Selector::parse("first"))
            .expect("listed")
            .is_empty(),
        "a zone lists its own ledgers"
    );
}

fn a_revision_starts_at_1_and_moves(catalog: &dyn Catalog) {
    let zone = catalog
        .create_zone_with(
            "delivery",
            &Write {
                expected_revision: None,
                operation: Some("op-1"),
                provenance: None,
            },
        )
        .expect("created");
    assert_eq!(
        (zone.revision, zone.operation.as_deref()),
        (FIRST_REVISION, Some("op-1"))
    );
    let id = Selector::Id(zone.id.clone());
    let renamed = catalog
        .rename_zone_with(&id, "delivery-eu", &at(1, "op-2"))
        .expect("renamed");
    assert_eq!(
        (renamed.revision, renamed.operation.as_deref()),
        (2, Some("op-2"))
    );
    let ledger = catalog.create_ledger(&id, "policies").expect("a ledger");
    assert_eq!((ledger.revision, ledger.operation), (FIRST_REVISION, None));
    let ledger = catalog
        .rename_ledger_with(&id, &Selector::Id(ledger.id), "audit", &at(1, "op-3"))
        .expect("renamed");
    assert_eq!(
        (ledger.revision, ledger.operation.as_deref()),
        (2, Some("op-3"))
    );
    // What a change answered is what is read afterwards.
    assert_eq!(catalog.get_zone(&id).expect("read"), renamed);
    assert_eq!(
        catalog
            .get_ledger(&id, &Selector::parse("audit"))
            .expect("read"),
        ledger
    );
}

fn a_stale_revision_changes_nothing(catalog: &dyn Catalog) {
    let zone = catalog.create_zone("delivery").expect("a zone");
    let zone_id = Selector::Id(zone.id.clone());
    let ledger = catalog
        .create_ledger(&zone_id, "policies")
        .expect("a ledger");
    let ledger_id = Selector::Id(ledger.id.clone());
    let stale = at(7, "op-x");
    for refused in [
        catalog
            .rename_zone_with(&zone_id, "elsewhere", &stale)
            .err(),
        catalog.delete_zone_with(&zone_id, &stale).err(),
    ] {
        assert!(
            matches!(
                refused,
                Some(CatalogError::RevisionConflict {
                    kind: "zone",
                    current: 1,
                    ..
                })
            ),
            "{refused:?}"
        );
    }
    for refused in [
        catalog
            .rename_ledger_with(&zone_id, &ledger_id, "audit", &stale)
            .err(),
        catalog
            .delete_ledger_with(&zone_id, &ledger_id, &stale)
            .err(),
        catalog
            .set_ledger_state_with(&zone_id, &ledger_id, LedgerState::Archived, &stale)
            .err(),
    ] {
        assert!(
            matches!(
                refused,
                Some(CatalogError::RevisionConflict {
                    kind: "ledger",
                    current: 1,
                    ..
                })
            ),
            "{refused:?}"
        );
    }
    assert_eq!(catalog.get_zone(&zone_id).expect("kept"), zone);
    assert_eq!(
        catalog.get_ledger(&zone_id, &ledger_id).expect("kept"),
        ledger
    );
}

fn a_deleted_ledger_leaves_a_tombstone(catalog: &dyn Catalog) {
    let zone = catalog.create_zone("delivery").expect("a zone");
    let zone_id = Selector::Id(zone.id.clone());
    let ledger = catalog
        .create_ledger(&zone_id, "policies")
        .expect("a ledger");
    assert_eq!(
        catalog
            .ledger_tombstone(&zone.id, &ledger.id)
            .expect("read"),
        None
    );
    let deleted = catalog
        .delete_ledger_with(
            &zone_id,
            &Selector::Name("policies".to_owned()),
            &at(1, "op-delete"),
        )
        .expect("deleted");
    assert_eq!(deleted.id, ledger.id);

    let tombstone = catalog
        .ledger_tombstone(&zone.id, &ledger.id)
        .expect("read")
        .expect("a tombstone");
    assert_eq!(tombstone.id, ledger.id);
    assert_eq!(tombstone.zone_id.as_deref(), Some(zone.id.as_str()));
    assert_eq!(tombstone.name, "policies");
    assert_eq!(tombstone.revision, 1);
    assert_eq!(tombstone.operation.as_deref(), Some("op-delete"));
    assert!(matches!(
        catalog.get_ledger(&zone_id, &Selector::Id(ledger.id.clone())),
        Err(CatalogError::NotFound { .. })
    ));
    assert!(catalog.list_ledgers(&zone_id).expect("listed").is_empty());
    // What is no id names no tombstone.
    assert_eq!(
        catalog.ledger_tombstone(&zone.id, "../x").expect("read"),
        None
    );
    assert_eq!(catalog.zone_tombstone("delivery").expect("read"), None);

    // The name is free again, under an id that is not the deleted one.
    let again = catalog
        .create_ledger(&zone_id, "policies")
        .expect("created again");
    assert_ne!(again.id, ledger.id);
    assert!(
        catalog
            .ledger_tombstone(&zone.id, &ledger.id)
            .expect("read")
            .is_some(),
        "the tombstone stays"
    );
}

fn a_deleted_zone_leaves_a_tombstone(catalog: &dyn Catalog) {
    let zone = catalog.create_zone("delivery").expect("a zone");
    let id = Selector::Id(zone.id.clone());
    let ledger = catalog.create_ledger(&id, "policies").expect("a ledger");
    catalog
        .delete_ledger(&id, &Selector::Id(ledger.id.clone()))
        .expect("the ledger deleted");
    assert_eq!(catalog.zone_tombstone(&zone.id).expect("read"), None);
    catalog
        .delete_zone_with(&id, &at(1, "op-delete"))
        .expect("an emptied zone is deleted");
    let tombstone = catalog
        .zone_tombstone(&zone.id)
        .expect("read")
        .expect("a tombstone");
    assert_eq!(
        (
            tombstone.id.as_str(),
            tombstone.name.as_str(),
            tombstone.zone_id,
            tombstone.operation.as_deref()
        ),
        (zone.id.as_str(), "delivery", None, Some("op-delete"))
    );
    assert!(matches!(
        catalog.get_zone(&id),
        Err(CatalogError::NotFound { .. })
    ));
    assert!(
        catalog
            .ledger_tombstone(&zone.id, &ledger.id)
            .expect("read")
            .is_some(),
        "its ledgers' tombstones stay"
    );
    let again = catalog.create_zone("delivery").expect("created again");
    assert_ne!(again.id, zone.id);
}

fn a_ledger_is_archived_and_restored(catalog: &dyn Catalog) {
    let zone = catalog.create_zone("delivery").expect("a zone");
    let (zone, ledger) = (Selector::Id(zone.id), Selector::Name("policies".to_owned()));
    let created = catalog.create_ledger(&zone, "policies").expect("a ledger");
    assert_eq!(created.state, LedgerState::Active);
    let archived = catalog
        .set_ledger_state_with(&zone, &ledger, LedgerState::Archived, &at(1, "op-1"))
        .expect("archived");
    assert_eq!(
        (archived.state, archived.revision),
        (LedgerState::Archived, 2)
    );
    assert!(matches!(
        catalog.set_ledger_state_with(&zone, &ledger, LedgerState::Active, &at(1, "op-2")),
        Err(CatalogError::RevisionConflict { current: 2, .. })
    ));
    assert_eq!(
        catalog.get_ledger(&zone, &ledger).expect("read"),
        archived,
        "unchanged by the conflict"
    );
    // A state it is already in changes nothing: no revision moves.
    let again = catalog
        .set_ledger_state_with(&zone, &ledger, LedgerState::Archived, &at(2, "op-3"))
        .expect("archived already");
    assert_eq!(again, archived);
    let restored = catalog
        .set_ledger_state_with(&zone, &ledger, LedgerState::Active, &at(2, "op-4"))
        .expect("restored");
    assert_eq!(
        (restored.state, restored.revision),
        (LedgerState::Active, 3)
    );
}

fn a_provenance_is_kept_from_creation(catalog: &dyn Catalog) {
    let zone = catalog.create_zone("target").expect("a zone");
    let zone = Selector::Id(zone.id);
    let provenance = Provenance {
        manifest_digest: format!("sha256:{}", "ab".repeat(32)),
        source_host_id: "11".repeat(16),
        source_zone_id: "01a00000-0000-7000-8000-00000000000a".to_owned(),
        source_ledger_id: "01a00000-0000-7000-8000-00000000000b".to_owned(),
        exported_at: 1_800_000_000,
        heads: vec![ImportedHead {
            r#ref: "main".to_owned(),
            head: format!("sha256:{}", "cd".repeat(32)),
        }],
    };
    let created = catalog
        .create_ledger_with(
            &zone,
            "release",
            &Write {
                expected_revision: None,
                operation: Some("op-import"),
                provenance: Some(&provenance),
            },
        )
        .expect("created");
    assert_eq!(created.provenance.as_ref(), Some(&provenance));
    let renamed = catalog
        .rename_ledger(&zone, &Selector::Id(created.id.clone()), "release-eu")
        .expect("renamed");
    assert_eq!(
        renamed.provenance.as_ref(),
        Some(&provenance),
        "a change keeps it"
    );
    assert_eq!(
        catalog
            .get_ledger(&zone, &Selector::Id(created.id))
            .expect("read")
            .provenance,
        Some(provenance)
    );
    let plain = catalog.create_ledger(&zone, "policies").expect("created");
    assert_eq!(plain.provenance, None);
}

fn zones_created_together_are_one(catalog: &Arc<dyn Catalog>) {
    let racing = Arc::clone(catalog);
    let answers = together(move |_| racing.create_zone("contested"));
    let created: Vec<_> = answers
        .iter()
        .filter_map(|answer| answer.as_ref().ok())
        .collect();
    assert_eq!(created.len(), 1, "one name, one zone: {answers:?}");
    for answer in &answers {
        assert!(
            matches!(answer, Ok(_) | Err(CatalogError::NameTaken { .. })),
            "{answer:?}"
        );
    }
    let listed = catalog.list_zones().expect("listed");
    assert_eq!(listed.len(), 1);
    assert_eq!(&listed[0], created[0]);
}

fn ledgers_created_together_are_one(catalog: &Arc<dyn Catalog>) {
    let zone = Selector::Id(catalog.create_zone("delivery").expect("a zone").id);
    let (racing, within) = (Arc::clone(catalog), zone.clone());
    let answers = together(move |_| racing.create_ledger(&within, "contested"));
    let created: Vec<_> = answers
        .iter()
        .filter_map(|answer| answer.as_ref().ok())
        .collect();
    assert_eq!(created.len(), 1, "one name, one ledger: {answers:?}");
    for answer in &answers {
        assert!(
            matches!(answer, Ok(_) | Err(CatalogError::NameTaken { .. })),
            "{answer:?}"
        );
    }
    let listed = catalog.list_ledgers(&zone).expect("listed");
    assert_eq!(listed.len(), 1);
    assert_eq!(&listed[0], created[0]);
}

fn changes_together_apply_once(catalog: &Arc<dyn Catalog>) {
    let zone = catalog.create_zone("delivery").expect("a zone");
    let id = Selector::Id(zone.id);
    let (racing, held) = (Arc::clone(catalog), id.clone());
    let answers = together(move |caller| {
        racing.rename_zone_with(
            &held,
            &format!("delivery-{caller}"),
            &Write {
                expected_revision: Some(FIRST_REVISION),
                operation: None,
                provenance: None,
            },
        )
    });
    let applied: Vec<_> = answers
        .iter()
        .filter_map(|answer| answer.as_ref().ok())
        .collect();
    assert_eq!(applied.len(), 1, "one revision, one change: {answers:?}");
    for answer in &answers {
        assert!(
            matches!(
                answer,
                Ok(_) | Err(CatalogError::RevisionConflict { current: 2, .. })
            ),
            "{answer:?}"
        );
    }
    assert_eq!(&catalog.get_zone(&id).expect("read"), applied[0]);
    assert_eq!(applied[0].revision, 2);
}
