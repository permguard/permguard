// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Several instances on one database: each its own pool of connections, as each process has,
//! all on one schema. What a store's suite proves of the threads of one instance is proven here
//! of instances that share nothing but the database.
//!
//! The tests need a server, as `foundations.rs` says, and are skipped without one.

#![allow(clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;
use std::sync::{Arc, Barrier, Mutex};

use permguard_core::catalog::{Catalog, CatalogError, Selector, Write};
use permguard_host::identity::store::IdentityStore;
use permguard_host::keys::ring::RingError;
use permguard_host::keys::ring::store::RingStore;
use permguard_host::membership::MembershipError;
use permguard_host::membership::store::{Doc, MemberStore};
use permguard_postgres::catalog::PostgresCatalog;
use permguard_postgres::database::Database;
use permguard_postgres::identity::PostgresIdentity;
use permguard_postgres::members::PostgresMembers;
use permguard_postgres::ring::PostgresRing;
use permguard_postgres::testing::{Server, config, scratch, server};

const INSTANCES: usize = 6;
const ROUNDS: u64 = 4;

/// One store an instance, each over a pool of its own on `schema`.
fn instances<S>(server: &Server, schema: &str, store: impl Fn(Database) -> S) -> Vec<S> {
    (0..INSTANCES)
        .map(|_| {
            store(
                Database::connect(config(server, Some(schema.to_owned()), 2))
                    .expect("an instance connects"),
            )
        })
        .collect()
}

/// What every instance answered `call`, all released at once.
fn together<S: Sync, T: Send>(stores: &[S], call: impl Fn(usize, &S) -> T + Sync) -> Vec<T> {
    let barrier = Barrier::new(stores.len());
    std::thread::scope(|scope| {
        let running: Vec<_> = stores
            .iter()
            .enumerate()
            .map(|(instance, store)| {
                let (barrier, call) = (&barrier, &call);
                scope.spawn(move || {
                    barrier.wait();
                    call(instance, store)
                })
            })
            .collect();
        running
            .into_iter()
            .map(|instance| instance.join().expect("an instance finished"))
            .collect()
    })
}

#[test]
fn instances_that_add_one_entry_together_add_it_once_on_postgresql() {
    let Some(server) = server("instances_that_add_one_entry_together_add_it_once_on_postgresql")
    else {
        return;
    };
    let scratch = scratch(&server);
    let rings = instances(&server, &scratch.schema, |database| {
        PostgresRing::new(database, "host-signing")
    });
    let members = instances(&server, &scratch.schema, PostgresMembers::new);
    for seq in 1..=ROUNDS {
        // A CBOR unsigned integer below 24 is its own byte: each instance adds another entry.
        let added = together(&rings, |instance, ring| ring.append(seq, &[instance as u8]));
        for answer in &added {
            assert!(
                matches!(answer, Ok(()) | Err(RingError::Refused(_))),
                "an instance was answered {answer:?}"
            );
        }
        assert_eq!(added.iter().filter(|answer| answer.is_ok()).count(), 1);
        assert_eq!(rings[0].entries().expect("reads").len() as u64, seq);

        let added = together(&members, |instance, store| {
            store.append(seq, &[instance as u8])
        });
        for answer in &added {
            assert!(
                matches!(answer, Ok(()) | Err(MembershipError::Conflict { .. })),
                "an instance was answered {answer:?}"
            );
        }
        assert_eq!(added.iter().filter(|answer| answer.is_ok()).count(), 1);
        assert_eq!(members[0].entries().expect("reads").len() as u64, seq);
    }
}

#[test]
fn instances_that_publish_together_keep_one_record_on_postgresql() {
    let Some(server) = server("instances_that_publish_together_keep_one_record_on_postgresql")
    else {
        return;
    };
    let scratch = scratch(&server);
    let identities = instances(&server, &scratch.schema, PostgresIdentity::new);
    let rings = instances(&server, &scratch.schema, |database| {
        PostgresRing::new(database, "host-signing")
    });
    let members = instances(&server, &scratch.schema, PostgresMembers::new);
    let membership = [7u8; 16];
    for round in 1..=ROUNDS {
        let published = together(&identities, |instance, identity| {
            identity.publish_public(round, &[instance as u8; 32])
        });
        assert_eq!(published.iter().filter(|answer| answer.is_ok()).count(), 1);
        let kept = identities[0]
            .public(round)
            .expect("reads")
            .expect("one key is kept");
        for identity in &identities {
            assert_eq!(identity.public(round).expect("reads"), Some(kept.clone()));
        }

        let thumbprint = format!("thumb-{round}");
        let published = together(&rings, |instance, ring| {
            ring.publish_public(&thumbprint, &[instance as u8; 40])
        });
        assert_eq!(published.iter().filter(|answer| answer.is_ok()).count(), 1);

        let published = together(&members, |instance, store| {
            store.publish_checkpoint(&membership, "security:host", round, &[instance as u8; 8])
        });
        assert_eq!(published.iter().filter(|answer| answer.is_ok()).count(), 1);
    }
    let provisioned = together(&identities, |instance, identity| {
        identity.publish_init(&[instance as u8; 8])
    });
    assert_eq!(
        provisioned.iter().filter(|answer| answer.is_ok()).count(),
        1,
        "one identity is provisioned in a database"
    );
}

#[test]
fn instances_that_change_one_document_together_lose_no_change_on_postgresql() {
    let Some(server) =
        server("instances_that_change_one_document_together_lose_no_change_on_postgresql")
    else {
        return;
    };
    let scratch = scratch(&server);
    let members = instances(&server, &scratch.schema, PostgresMembers::new);
    const EACH: u64 = 10;
    let membership = [7u8; 16];
    let doc = Doc::Acks {
        membership: &membership,
        task: "events.ship",
    };
    together(&members, |_, store| {
        for _ in 0..EACH {
            store
                .change(&doc, &mut |held| {
                    let count = held.map_or(0, |bytes| {
                        u64::from_be_bytes(bytes.try_into().expect("eight bytes"))
                    });
                    Ok(Some((count + 1).to_be_bytes().to_vec()))
                })
                .expect("changed");
        }
    });
    assert_eq!(
        members[0].doc(&doc).expect("reads"),
        Some((INSTANCES as u64 * EACH).to_be_bytes().to_vec()),
        "every change was given what the one before it kept, on whatever instance"
    );
}

#[test]
fn instances_that_change_the_catalog_together_apply_once_on_postgresql() {
    let Some(server) =
        server("instances_that_change_the_catalog_together_apply_once_on_postgresql")
    else {
        return;
    };
    let scratch = scratch(&server);
    let catalogs = instances(&server, &scratch.schema, PostgresCatalog::new);

    let created = together(&catalogs, |_, catalog| catalog.create_zone("delivery"));
    for answer in &created {
        assert!(
            matches!(answer, Ok(_) | Err(CatalogError::NameTaken { .. })),
            "an instance was answered {answer:?}"
        );
    }
    assert_eq!(created.iter().filter(|answer| answer.is_ok()).count(), 1);
    assert_eq!(catalogs[0].list_zones().expect("listed").len(), 1);

    let zone = Selector::parse("delivery");
    let created = together(&catalogs, |_, catalog| {
        catalog.create_ledger(&zone, "policies")
    });
    assert_eq!(created.iter().filter(|answer| answer.is_ok()).count(), 1);
    assert_eq!(catalogs[0].list_ledgers(&zone).expect("listed").len(), 1);

    // A zone deleted while a ledger is created in it: the zone goes empty, or it stays with
    // its ledger, and never a ledger is left in a zone that is gone.
    catalogs[0].create_zone("leaving").expect("a zone");
    let leaving = Selector::parse("leaving");
    let answers = together(&catalogs, |instance, catalog| {
        if instance == 0 {
            catalog.delete_zone(&leaving).map(|_| ())
        } else {
            catalog
                .create_ledger(&leaving, &format!("ledger-{instance}"))
                .map(|_| ())
        }
    });
    match catalogs[0].get_zone(&leaving) {
        Ok(_) => assert!(
            matches!(answers[0], Err(CatalogError::NotEmpty { .. })),
            "a zone that holds ledgers is kept: {:?}",
            answers[0]
        ),
        Err(CatalogError::NotFound { .. }) => {
            assert!(answers[0].is_ok());
            for answer in &answers[1..] {
                assert!(
                    matches!(answer, Err(CatalogError::NotFound { .. })),
                    "a ledger was created in a zone that is gone: {answer:?}"
                );
            }
        }
        Err(other) => panic!("the zone reads {other}"),
    }

    // Renames held to one revision: one applies, the others learn the revision moved.
    let held = Write {
        expected_revision: Some(1),
        operation: None,
        provenance: None,
    };
    let renamed = together(&catalogs, |instance, catalog| {
        catalog.rename_zone_with(&zone, &format!("delivery-{instance}"), &held)
    });
    assert_eq!(renamed.iter().filter(|answer| answer.is_ok()).count(), 1);
    for answer in renamed.iter().filter(|answer| answer.is_err()) {
        assert!(
            matches!(
                answer,
                Err(CatalogError::RevisionConflict { .. } | CatalogError::NotFound { .. })
            ),
            "an instance was answered {answer:?}"
        );
    }
}

/// A change of a document made alone while an operation holds another change of it, not yet
/// committed, is asked again on what the operation kept: the first time stays.
#[test]
fn a_change_alone_sees_the_one_an_operation_made_on_postgresql() {
    let Some(server) = server("a_change_alone_sees_the_one_an_operation_made_on_postgresql") else {
        return;
    };
    let scratch = scratch(&server);
    let databases = instances(&server, &scratch.schema, |database| database);
    let membership = [7u8; 16];
    let doc = Doc::Verification {
        membership: &membership,
    };
    // What every caller does: the first time asked stays, and every one is answered it.
    let schedule = |store: &PostgresMembers, now: u64| {
        let mut scheduled = now;
        store
            .change(&doc, &mut |held| match held {
                Some(first) => {
                    scheduled = u64::from_be_bytes(first.try_into().expect("eight bytes"));
                    Ok(None)
                }
                None => {
                    scheduled = now;
                    Ok(Some(now.to_be_bytes().to_vec()))
                }
            })
            .expect("changed");
        scheduled
    };
    let inside = &databases[0];
    let unit = inside.begin().expect("a unit of work");
    let first = {
        let _entered = inside.enter(&unit);
        schedule(&PostgresMembers::new(inside.clone()), 100)
    };
    assert_eq!(first, 100);
    let alone = PostgresMembers::new(databases[1].clone());
    let second = std::thread::scope(|scope| {
        let asked = scope.spawn(|| schedule(&alone, 200));
        // Long enough for the change made alone to reach the row the operation holds.
        std::thread::sleep(std::time::Duration::from_millis(300));
        unit.commit().expect("the operation is committed");
        asked.join().expect("the change alone finished")
    });
    assert_eq!(second, 100, "every one is answered the first time");
    assert_eq!(
        alone.doc(&doc).expect("reads"),
        Some(100u64.to_be_bytes().to_vec())
    );
}

/// WP-27.5: two instances sign with one key, and no key is in the clear. A key generated on one
/// instance, sealed under a key-encryption key held outside the database, is unsealed and signs
/// on another; the row holds the sealed key, never the PKCS#8; and of two keys generated for one
/// slot together, one is kept.
#[test]
fn instances_sign_with_one_sealed_key_on_postgresql() {
    use permguard_host::keys::KeyProvider as _;
    use permguard_host::keys::custody::{Keks, SealedFileKeyProvider, SecretKek, StoredPublic};
    use permguard_host::secrets::{KeyVersion, Root};
    use permguard_objects::crypto::suite::Suite;
    use permguard_postgres::slots::PostgresSlots;

    let Some(server) = server("instances_sign_with_one_sealed_key_on_postgresql") else {
        return;
    };
    let scratch = scratch(&server);
    // The key-encryption key every instance resolves from the same secret reference.
    let kek = || {
        let root =
            Root::from_material(&[42; 32], KeyVersion::new(1).expect("a version")).expect("a root");
        Keks {
            current: Arc::new(SecretKek::from_root("kek", &root).expect("a KEK")),
            previous: None,
        }
    };
    let published: Arc<Mutex<BTreeMap<String, Vec<u8>>>> = Arc::default();
    let stored = || -> StoredPublic {
        let held = Arc::clone(&published);
        Box::new(move |slot, _| Ok(held.lock().expect("lock").get(slot).cloned()))
    };
    let providers = instances(&server, &scratch.schema, |database| {
        SealedFileKeyProvider::new(
            Arc::new(PostgresSlots::new(database, "host.operations")),
            [7; 16],
            "host.operations",
            kek(),
            stored(),
        )
    });

    let public = providers[0]
        .generate("slot-1", Suite::Ed25519Sha256V1)
        .expect("generated");
    published
        .lock()
        .expect("lock")
        .insert("slot-1".to_owned(), public.bytes.clone());
    for (instance, provider) in providers.iter().enumerate() {
        let message = format!("signed on instance {instance}");
        let signature = provider
            .sign("slot-1", Suite::Ed25519Sha256V1, message.as_bytes())
            .expect("signed");
        Suite::Ed25519Sha256V1
            .verify(&public.bytes, message.as_bytes(), &signature)
            .expect("one key signs on every instance");
    }

    // The row is the sealed key: neither the PKCS#8 nor any other form of the key in the clear.
    let row: Vec<u8> = scratch
        .database
        .write(|unit| {
            Ok(unit
                .query_one(
                    "SELECT bytes FROM permguard_key_slots WHERE slot = 'slot-1'",
                    &[],
                )?
                .get(0))
        })
        .expect("read");
    assert!(
        permguard_objects::crypto::seal::SealedKey::decode(&row).is_ok(),
        "the slot holds a sealed key"
    );
    assert_ne!(row.first(), Some(&0x30), "no PKCS#8 in the clear");

    // Generated together for one slot: one key is kept, the others are refused.
    let generated = together(&providers, |_, provider| {
        provider.generate("slot-2", Suite::Ed25519Sha256V1)
    });
    assert_eq!(generated.iter().filter(|answer| answer.is_ok()).count(), 1);
}
