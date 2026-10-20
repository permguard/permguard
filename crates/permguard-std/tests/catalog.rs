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
