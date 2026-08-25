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

    let zone = catalog.create_zone("pharma").expect("a zone is created");
    assert_eq!(zone.name, "pharma");
    assert_eq!(zone.id.len(), 36, "the id is a guid");

    // Referable by name and by id, and both answers are the same zone.
    let by_name = catalog
        .get_zone(&Selector::parse("pharma"))
        .expect("found by name");
    let by_id = catalog
        .get_zone(&Selector::parse(&zone.id))
        .expect("found by id");
    assert_eq!(by_name, by_id);

    let renamed = catalog
        .rename_zone(&Selector::parse("pharma"), "pharma-eu")
        .expect("renamed");
    assert_eq!(
        renamed.id, zone.id,
        "the id never changes: that is what it is for"
    );

    let deleted = catalog
        .delete_zone(&Selector::parse("pharma-eu"))
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
