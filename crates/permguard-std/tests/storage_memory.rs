#![cfg(feature = "storage")]
// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What the in-process store does with a record, and what it releases on shutdown.

use permguard_core::Storage;
use permguard_std::storage::MemoryStorage;

#[tokio::test]
async fn test_a_stored_record_reads_back() {
    let storage = MemoryStorage::new();

    storage
        .put("a", b"one")
        .await
        .expect("the record is stored");

    assert_eq!(
        storage.get("a").await.expect("the record is readable"),
        Some(b"one".to_vec())
    );
}

#[tokio::test]
async fn test_an_absent_record_reads_back_as_none() {
    let storage = MemoryStorage::new();

    assert_eq!(
        storage.get("missing").await.expect("the read succeeds"),
        None
    );
}

#[tokio::test]
async fn test_a_second_put_replaces_the_value() {
    let storage = MemoryStorage::new();

    storage.put("a", b"one").await.expect("the first write");
    storage.put("a", b"two").await.expect("the second write");

    assert_eq!(
        storage.get("a").await.expect("the record is readable"),
        Some(b"two".to_vec())
    );
    assert_eq!(storage.len().expect("the length is readable"), 1);
}

#[tokio::test]
async fn test_a_new_store_is_empty_and_names_itself() {
    let storage = MemoryStorage::new();

    assert!(storage.is_empty().expect("the store is readable"));
    assert_eq!(storage.name(), "memory");
}

#[tokio::test]
async fn test_shutdown_releases_what_the_store_was_holding() {
    let storage = MemoryStorage::new();

    storage
        .put("a", b"one")
        .await
        .expect("the record is stored");
    storage.shutdown().await.expect("the store releases");

    assert!(storage.is_empty().expect("the store is readable"));
}

#[tokio::test]
async fn test_the_default_is_usable_through_the_trait_object() {
    let storage: Box<dyn Storage> = Box::new(MemoryStorage::new());

    storage
        .put("a", b"one")
        .await
        .expect("the record is stored");

    assert_eq!(
        storage.get("a").await.expect("the record is readable"),
        Some(b"one".to_vec())
    );
}
