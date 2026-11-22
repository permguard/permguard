#![cfg(feature = "catalog")]
// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What the file catalog promises: uniqueness under race, referable both ways, durable on disk.

use std::sync::Arc;
use std::thread;

use permguard_core::catalog::{Catalog, CatalogError, Selector};
use permguard_std::catalog::FileCatalog;

fn scratch(name: &str) -> std::path::PathBuf {
    let path =
        std::env::temp_dir().join(format!("permguard-catalog-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    path
}

/// The file backend passes the contract's suite, each case on a root of its own.
#[test]
fn the_file_backend_keeps_the_contract() {
    let made = std::sync::atomic::AtomicUsize::new(0);
    permguard_core::catalog::suite::run(&|| {
        let case = made.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Arc::new(FileCatalog::new(scratch(&format!("suite-{case}"))))
    });
}

#[test]
fn test_a_zone_lives_from_creation_to_deletion() {
    let catalog = FileCatalog::new(scratch("lifecycle"));

    let zone = catalog.create_zone("delivery").expect("a zone is created");
    assert_eq!(zone.name, "delivery");
    assert_eq!(zone.id.len(), 36, "the id is a guid");

    // Referable by name and by id, and both answers are the same zone.
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
    assert_eq!(
        renamed.id, zone.id,
        "the id never changes: that is what it is for"
    );

    let deleted = catalog
        .delete_zone(&Selector::parse("delivery-eu"))
        .expect("deleted");
    assert_eq!(deleted.id, zone.id);
    assert!(catalog.get_zone(&Selector::parse(&zone.id)).is_err());
}

#[test]
fn test_names_are_unique_where_they_claim_to_be() {
    let catalog = FileCatalog::new(scratch("uniqueness"));

    let one = catalog.create_zone("alpha").expect("first zone");
    let two = catalog.create_zone("beta").expect("second zone");

    // Zone names: unique across the deployment.
    assert!(matches!(
        catalog.create_zone("alpha"),
        Err(CatalogError::NameTaken { .. })
    ));

    // Ledger names: unique inside a zone, free across zones.
    catalog
        .create_ledger(&Selector::parse("alpha"), "policies")
        .expect("a ledger in alpha");
    assert!(matches!(
        catalog.create_ledger(&Selector::parse("alpha"), "policies"),
        Err(CatalogError::NameTaken { .. })
    ));
    catalog
        .create_ledger(&Selector::parse("beta"), "policies")
        .expect("the same name in another zone is another ledger");

    let _ = (one, two);
}

#[test]
fn test_a_zone_holding_ledgers_refuses_to_die() {
    let catalog = FileCatalog::new(scratch("not-empty"));

    catalog.create_zone("keeper").expect("a zone");
    catalog
        .create_ledger(&Selector::parse("keeper"), "held")
        .expect("a ledger");

    assert!(matches!(
        catalog.delete_zone(&Selector::parse("keeper")),
        Err(CatalogError::NotEmpty { ledgers: 1, .. })
    ));

    catalog
        .delete_ledger(&Selector::parse("keeper"), &Selector::parse("held"))
        .expect("the ledger goes first");
    catalog
        .delete_zone(&Selector::parse("keeper"))
        .expect("then the zone");
}

/// The reason mutations take a lock at all: two racers for one name, exactly one winner.
#[test]
fn test_two_racers_for_one_name_produce_exactly_one_zone() {
    let catalog = Arc::new(FileCatalog::new(scratch("race")));
    let racers: Vec<_> = (0..8)
        .map(|_| {
            let catalog = Arc::clone(&catalog);
            thread::spawn(move || catalog.create_zone("contested").is_ok())
        })
        .collect();

    let winners = racers
        .into_iter()
        .map(|racer| racer.join().unwrap_or(false))
        .filter(|won| *won)
        .count();

    assert_eq!(winners, 1, "one name, one zone, whatever the interleaving");
    assert_eq!(catalog.list_zones().expect("listable").len(), 1);
}

/// What survives a restart is what is on disk: a second catalog over the same root sees everything.
#[test]
fn test_the_catalog_is_the_disk_and_not_the_process() {
    let root = scratch("durability");

    {
        let catalog = FileCatalog::new(&root);
        catalog.create_zone("persistent").expect("a zone");
        catalog
            .create_ledger(&Selector::parse("persistent"), "kept")
            .expect("a ledger");
    }

    let reopened = FileCatalog::new(&root);
    let zones = reopened.list_zones().expect("zones survive");
    assert_eq!(zones.len(), 1);

    let ledgers = reopened
        .list_ledgers(&Selector::parse("persistent"))
        .expect("ledgers survive");
    assert_eq!(ledgers.len(), 1);
    assert_eq!(ledgers[0].name, "kept");

    // And the ledger's future home exists on disk, addressed by ids that never change.
    let home = root.join(&zones[0].id).join("ledgers").join(&ledgers[0].id);
    assert!(home.is_dir(), "{} is not a directory", home.display());
}

#[test]
fn test_ids_mint_in_creation_order() {
    let catalog = FileCatalog::new(scratch("ordering"));

    let first = catalog.create_zone("first").expect("first");
    std::thread::sleep(std::time::Duration::from_millis(3));
    let second = catalog.create_zone("second").expect("second");

    // UUIDv7: the timestamp leads, so ids sort by age.
    assert!(first.id < second.id, "{} !< {}", first.id, second.id);
}

/// WP-7.3a: a record is born at revision 1, each mutation moves it by one and keeps the operation
/// that wrote it.
#[test]
fn a_record_starts_at_revision_1_and_moves_by_one() {
    use permguard_core::catalog::Write;

    let catalog = FileCatalog::new(scratch("revisions"));
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
        (1, Some("op-1"))
    );
    let renamed = catalog
        .rename_zone_with(
            &Selector::Id(zone.id.clone()),
            "delivery-eu",
            &Write {
                expected_revision: Some(1),
                operation: Some("op-2"),
                provenance: None,
            },
        )
        .expect("renamed");
    assert_eq!(
        (renamed.revision, renamed.operation.as_deref()),
        (2, Some("op-2"))
    );
    let ledger = catalog
        .create_ledger(&Selector::Id(zone.id.clone()), "main-ledger")
        .expect("a ledger");
    assert_eq!(ledger.revision, 1);
    let ledger = catalog
        .rename_ledger_with(
            &Selector::Id(zone.id.clone()),
            &Selector::Id(ledger.id.clone()),
            "audit",
            &Write {
                expected_revision: Some(1),
                operation: Some("op-3"),
                provenance: None,
            },
        )
        .expect("renamed");
    assert_eq!(ledger.revision, 2);
    // Durable: a store opened again reads the same revisions and operations.
    let again = FileCatalog::new(scratch_kept("revisions"));
    let read = again
        .get_zone(&Selector::Id(zone.id.clone()))
        .expect("read");
    assert_eq!(
        (read.revision, read.operation.as_deref()),
        (2, Some("op-2"))
    );
    // Never on the wire.
    assert!(
        !serde_json::to_string(&read.public())
            .expect("JSON")
            .contains("operation")
    );
}

/// WP-7.3a: a change that expected another revision is refused and applies nothing.
#[test]
fn a_stale_revision_is_a_conflict_and_changes_nothing() {
    use permguard_core::catalog::Write;

    let catalog = FileCatalog::new(scratch("conflict"));
    let zone = catalog.create_zone("delivery").expect("a zone");
    let ledger = catalog
        .create_ledger(&Selector::Id(zone.id.clone()), "main-ledger")
        .expect("a ledger");
    let stale = Write {
        expected_revision: Some(7),
        operation: Some("op-x"),
        provenance: None,
    };
    let zone_id = Selector::Id(zone.id.clone());
    let ledger_id = Selector::Id(ledger.id.clone());
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

/// WP-7.3a: a record written before revisions existed reads as revision 1 and no operation.
#[test]
fn a_record_written_before_reads_as_revision_1() {
    let root = scratch("before");
    std::fs::create_dir_all(&root).expect("created");
    std::fs::write(
        root.join("zones.json"),
        br#"{"version":1,"zones":[{"id":"0b1f8c5e-6b7a-4e3d-9c2a-1f0e5d4c3b2a","name":"delivery","created_at":1,"updated_at":1}]}"#,
    )
    .expect("written");
    let catalog = FileCatalog::new(root);
    let zone = catalog
        .get_zone(&Selector::parse("delivery"))
        .expect("read");
    assert_eq!((zone.revision, zone.operation), (1, None));
}

/// The directory a test wrote before, kept as it is.
fn scratch_kept(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("permguard-catalog-{name}-{}", std::process::id()))
}

/// WP-7.3b, owner decisions of 2026-10-20 and 2026-10-21: a deleted ledger leaves a tombstone of
/// its id, with its name, revision and the operation that deleted it, and is gone from listing
/// and lookup; what it held stays on disk.
#[test]
fn a_deleted_ledger_leaves_a_tombstone_and_its_directory() {
    use permguard_core::catalog::Write;

    let root = scratch("ledger-tombstone");
    let catalog = FileCatalog::new(&root);
    let zone = catalog.create_zone("delivery").expect("a zone");
    let ledger = catalog
        .create_ledger(&Selector::Id(zone.id.clone()), "policies")
        .expect("a ledger");
    let held = root
        .join(&zone.id)
        .join("ledgers")
        .join(&ledger.id)
        .join("objects");
    std::fs::create_dir_all(&held).expect("the ledger's objects");
    std::fs::write(held.join("ab"), b"an object").expect("an object");
    assert_eq!(
        catalog
            .ledger_tombstone(&zone.id, &ledger.id)
            .expect("reads"),
        None
    );

    let deleted = catalog
        .delete_ledger_with(
            &Selector::Id(zone.id.clone()),
            &Selector::Name("policies".to_owned()),
            &Write {
                expected_revision: Some(1),
                operation: Some("op-delete"),
                provenance: None,
            },
        )
        .expect("deleted");
    assert_eq!(deleted.id, ledger.id);

    let tombstone = catalog
        .ledger_tombstone(&zone.id, &ledger.id)
        .expect("reads")
        .expect("a tombstone");
    assert_eq!(tombstone.id, ledger.id);
    assert_eq!(tombstone.zone_id.as_deref(), Some(zone.id.as_str()));
    assert_eq!(tombstone.name, "policies");
    assert_eq!(tombstone.revision, 1);
    assert_eq!(tombstone.operation.as_deref(), Some("op-delete"));
    assert!(matches!(
        catalog.get_ledger(
            &Selector::Id(zone.id.clone()),
            &Selector::Id(ledger.id.clone())
        ),
        Err(CatalogError::NotFound { .. })
    ));
    assert!(
        catalog
            .list_ledgers(&Selector::Id(zone.id.clone()))
            .expect("lists")
            .is_empty()
    );
    assert_eq!(
        std::fs::read(held.join("ab")).expect("still there"),
        b"an object",
        "a delete destroys nothing"
    );
    // A name or a malformed id forms no path and reads as no tombstone.
    assert_eq!(
        catalog.ledger_tombstone(&zone.id, "../x").expect("reads"),
        None
    );
    assert_eq!(catalog.zone_tombstone("delivery").expect("reads"), None);

    // The name is free again, under a new id.
    let again = catalog
        .create_ledger(&Selector::Id(zone.id.clone()), "policies")
        .expect("recreated");
    assert_ne!(again.id, ledger.id);
}

/// WP-7.3b: a zone whose ledgers were all deleted is empty and can be deleted; it leaves its own
/// tombstone, and its directory stays with what its ledgers held.
#[test]
fn a_deleted_zone_leaves_a_tombstone_and_its_directory() {
    let root = scratch("zone-tombstone");
    let catalog = FileCatalog::new(&root);
    let zone = catalog.create_zone("delivery").expect("a zone");
    let id = Selector::Id(zone.id.clone());
    let ledger = catalog.create_ledger(&id, "policies").expect("a ledger");
    assert!(matches!(
        catalog.delete_zone(&id),
        Err(CatalogError::NotEmpty { .. })
    ));
    catalog
        .delete_ledger(&id, &Selector::Id(ledger.id.clone()))
        .expect("the ledger deleted");

    catalog
        .delete_zone(&id)
        .expect("an emptied zone is deleted");
    let tombstone = catalog
        .zone_tombstone(&zone.id)
        .expect("reads")
        .expect("a tombstone");
    assert_eq!(
        (tombstone.name.as_str(), tombstone.zone_id),
        ("delivery", None)
    );
    assert!(catalog.get_zone(&id).is_err());
    assert!(
        root.join(&zone.id)
            .join("ledgers")
            .join(&ledger.id)
            .is_dir(),
        "the deleted ledger's directory stays"
    );
    assert!(
        catalog
            .ledger_tombstone(&zone.id, &ledger.id)
            .expect("reads")
            .is_some()
    );
}

/// WP-7.3b, owner decision of 2026-10-21: a ledger is archived and restored, the revision moving
/// each time, held to the revision expected; a record written before reads as active.
#[test]
fn a_ledger_is_archived_and_restored_in_the_store() {
    use permguard_core::catalog::{LedgerState, Write};

    let catalog = FileCatalog::new(scratch("ledger-state"));
    let zone = catalog.create_zone("delivery").expect("a zone");
    let (zone, ledger) = (
        Selector::Id(zone.id.clone()),
        Selector::Name("policies".to_owned()),
    );
    let created = catalog.create_ledger(&zone, "policies").expect("a ledger");
    assert_eq!(created.state, LedgerState::Active);
    let at = |revision| Write {
        expected_revision: Some(revision),
        operation: None,
        provenance: None,
    };

    let archived = catalog
        .set_ledger_state_with(&zone, &ledger, LedgerState::Archived, &at(1))
        .expect("archived");
    assert_eq!(
        (archived.state, archived.revision),
        (LedgerState::Archived, 2)
    );
    assert!(matches!(
        catalog.set_ledger_state_with(&zone, &ledger, LedgerState::Active, &at(1)),
        Err(CatalogError::RevisionConflict { current: 2, .. })
    ));
    let read = catalog.get_ledger(&zone, &ledger).expect("read");
    assert_eq!(
        read.state,
        LedgerState::Archived,
        "unchanged by the conflict"
    );
    let restored = catalog
        .set_ledger_state_with(&zone, &ledger, LedgerState::Active, &at(2))
        .expect("restored");
    assert_eq!(
        (restored.state, restored.revision),
        (LedgerState::Active, 3)
    );

    let old: permguard_core::catalog::Ledger = serde_json::from_str(
        r#"{"id":"i","zone_id":"z","name":"n","created_at":1,"updated_at":1}"#,
    )
    .expect("an old record");
    assert_eq!(old.state, LedgerState::Active);
}

/// WP-7.3b: a tombstone whose id is still indexed is what a delete interrupted between its two
/// writes left; the record stays live, listed and found, and the next delete replaces it.
#[test]
fn a_tombstone_an_interrupted_delete_left_leaves_the_record_live() {
    use permguard_core::catalog::Write;

    let root = scratch("stray-tombstone");
    let catalog = FileCatalog::new(&root);
    let zone = catalog.create_zone("delivery").expect("a zone");
    let id = Selector::Id(zone.id.clone());
    let ledger = catalog.create_ledger(&id, "policies").expect("a ledger");
    let stray = root
        .join(&zone.id)
        .join("tombstones")
        .join(format!("{}.json", ledger.id));
    std::fs::create_dir_all(stray.parent().expect("a parent")).expect("the directory");
    std::fs::write(
        &stray,
        serde_json::json!({
            "id": ledger.id, "zone_id": zone.id, "name": "policies",
            "deleted_at": 1, "revision": 1, "operation": "op-interrupted",
        })
        .to_string(),
    )
    .expect("a stray tombstone");

    let live = Selector::Id(ledger.id.clone());
    assert_eq!(
        catalog.get_ledger(&id, &live).expect("still found").id,
        ledger.id
    );
    assert_eq!(catalog.list_ledgers(&id).expect("lists").len(), 1);
    catalog
        .delete_ledger_with(
            &id,
            &live,
            &Write {
                expected_revision: Some(1),
                operation: Some("op-delete"),
                provenance: None,
            },
        )
        .expect("deleted");
    let tombstone = catalog
        .ledger_tombstone(&zone.id, &ledger.id)
        .expect("reads")
        .expect("a tombstone");
    assert_eq!(
        tombstone.operation.as_deref(),
        Some("op-delete"),
        "replaced"
    );
    assert!(catalog.get_ledger(&id, &live).is_err());
}

/// BUG-0146: a record created under a name another record held starts above every revision that
/// record reached under it, so a change carrying a revision read from a deleted or renamed record
/// is a conflict, never applied to its successor; for zones and ledgers, on a reopened catalog
/// too.
#[test]
fn a_revision_read_from_a_deleted_record_never_matches_its_successor() {
    use permguard_core::catalog::Write;

    let root = scratch("successor");
    let catalog = FileCatalog::new(&root);
    let stale = |revision| Write {
        expected_revision: Some(revision),
        operation: None,
        provenance: None,
    };
    let zone = catalog.create_zone("zonea").expect("a zone");
    let zone_id = Selector::Id(zone.id.clone());

    // A ledger read at revision 1, deleted, and another created under its name.
    let first = catalog
        .create_ledger(&zone_id, "payments")
        .expect("a ledger");
    assert_eq!(first.revision, 1);
    catalog
        .delete_ledger_with(&zone_id, &Selector::Id(first.id.clone()), &stale(1))
        .expect("deleted");
    let catalog = FileCatalog::new(&root);
    let second = catalog
        .create_ledger(&zone_id, "payments")
        .expect("recreated");
    assert!(second.revision > first.revision, "{second:?}");
    let by_name = Selector::Name("payments".to_owned());
    for refused in [
        catalog
            .rename_ledger_with(&zone_id, &by_name, "other", &stale(1))
            .err(),
        catalog
            .delete_ledger_with(&zone_id, &by_name, &stale(1))
            .err(),
    ] {
        assert!(
            matches!(
                refused,
                Some(CatalogError::RevisionConflict { kind: "ledger", .. })
            ),
            "{refused:?}"
        );
    }

    // A ledger renamed away, read before the rename, and another created under the old name.
    let moved = catalog
        .create_ledger(&zone_id, "billing")
        .expect("a ledger");
    catalog
        .rename_ledger_with(
            &zone_id,
            &Selector::Id(moved.id.clone()),
            "invoices",
            &stale(moved.revision),
        )
        .expect("renamed away");
    let successor = catalog
        .create_ledger(&zone_id, "billing")
        .expect("the name reused");
    assert!(successor.revision > moved.revision, "{successor:?}");
    let refused = catalog
        .delete_ledger_with(
            &zone_id,
            &Selector::Name("billing".to_owned()),
            &stale(moved.revision),
        )
        .err();
    assert!(
        matches!(
            refused,
            Some(CatalogError::RevisionConflict { kind: "ledger", .. })
        ),
        "{refused:?}"
    );

    // A record renamed onto a name another record held lands above it too.
    let onto = catalog
        .rename_ledger_with(
            &zone_id,
            &Selector::Id(successor.id.clone()),
            "payments-old",
            &stale(successor.revision),
        )
        .expect("renamed");
    assert!(onto.revision > successor.revision);

    // The same for zones.
    let other = catalog.create_zone("zoneb").expect("a zone");
    assert_eq!(other.revision, 1);
    catalog
        .delete_zone_with(&Selector::Id(other.id.clone()), &stale(1))
        .expect("deleted");
    let again = catalog.create_zone("zoneb").expect("recreated");
    assert!(again.revision > 1, "{again:?}");
    let refused = catalog
        .rename_zone_with(&Selector::Name("zoneb".to_owned()), "zonec", &stale(1))
        .err();
    assert!(
        matches!(
            refused,
            Some(CatalogError::RevisionConflict { kind: "zone", .. })
        ),
        "{refused:?}"
    );
}

/// BUG-0146, through the zone: a ledger created in a zone that was deleted and recreated, or that
/// took the name of a zone renamed away, starts above every revision a ledger reached under the
/// same `<zone>/<ledger>` path, so a change read from the old ledger is a conflict there too; on a
/// reopened catalog as well.
#[test]
fn a_revision_read_through_a_recreated_zone_never_matches_its_successor() {
    use permguard_core::catalog::Write;

    let root = scratch("successor-through-zone");
    let catalog = FileCatalog::new(&root);
    let stale = |revision| Write {
        expected_revision: Some(revision),
        operation: None,
        provenance: None,
    };
    let refused_stale = |catalog: &FileCatalog, zone: &str, ledger: &str, revision: u64| {
        let refused = catalog
            .delete_ledger_with(
                &Selector::Name(zone.to_owned()),
                &Selector::Name(ledger.to_owned()),
                &stale(revision),
            )
            .err();
        assert!(
            matches!(
                refused,
                Some(CatalogError::RevisionConflict { kind: "ledger", .. })
            ),
            "{zone}/{ledger} at {revision}: {refused:?}"
        );
    };

    // A zone deleted with its ledger, and both recreated under the same names.
    let zone = catalog.create_zone("acme").expect("a zone");
    let zone_id = Selector::Id(zone.id.clone());
    let first = catalog
        .create_ledger(&zone_id, "payments")
        .expect("a ledger");
    catalog
        .delete_ledger_with(
            &zone_id,
            &Selector::Id(first.id.clone()),
            &stale(first.revision),
        )
        .expect("the ledger deleted");
    catalog
        .delete_zone_with(&zone_id, &stale(zone.revision))
        .expect("the zone deleted");
    let catalog = FileCatalog::new(&root);
    let zone = catalog.create_zone("acme").expect("the zone recreated");
    let second = catalog
        .create_ledger(&Selector::Id(zone.id.clone()), "payments")
        .expect("the ledger recreated");
    assert!(second.revision > first.revision, "{second:?}");
    refused_stale(&catalog, "acme", "payments", first.revision);

    // A zone renamed away with its ledger, and a new zone taking its name.
    let moved = catalog
        .create_ledger(&Selector::Id(zone.id.clone()), "billing")
        .expect("a ledger");
    catalog
        .rename_zone_with(
            &Selector::Id(zone.id.clone()),
            "acme-old",
            &stale(zone.revision),
        )
        .expect("the zone renamed away");
    let taken = catalog.create_zone("acme").expect("the name reused");
    let successor = catalog
        .create_ledger(&Selector::Id(taken.id.clone()), "billing")
        .expect("a ledger under the old path");
    assert!(successor.revision > moved.revision, "{successor:?}");
    refused_stale(&catalog, "acme", "billing", moved.revision);
}
