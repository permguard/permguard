// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The storage contract Permguard runs against.

use crate::error::StorageError;
use crate::future::{BoxFuture, ready};

/// What a store answers with.
pub type Result<T> = std::result::Result<T, StorageError>;

/// The record store the server host and its services read and write.
///
/// Implementations are shared across tasks, so they are `Send + Sync` and take `&self`. The methods
/// are asynchronous because a real store is across a socket, and a synchronous contract would have
/// forced every backend to block a runtime thread.
///
/// The error is typed rather than opaque because a caller has to be able to tell a store that is
/// down from a store that answered: one is worth retrying and the other never will be.
///
/// This is records, not secrets: a value handed to [`Storage::put`] is expected to end up wherever
/// the backend puts records, in whatever form the backend keeps them. Anything that must not land
/// there goes through [`SecretStore`](crate::secrets::SecretStore) instead.
pub trait Storage: Send + Sync {
    /// Returns the name of this implementation, for banners and diagnostics.
    fn name(&self) -> &'static str;

    /// Stores `value` under `key`, replacing any previous value.
    fn put<'a>(&'a self, key: &'a str, value: &'a [u8]) -> BoxFuture<'a, Result<()>>;

    /// Returns the value stored under `key`, when there is one.
    fn get<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<Option<Vec<u8>>>>;

    /// Releases whatever this store is holding, before the process goes away.
    ///
    /// The host calls it during shutdown, within the configured budget. A store with buffered writes,
    /// an open connection pool, or a file to flush does that work here; one with nothing to release
    /// keeps the default.
    fn shutdown(&self) -> BoxFuture<'_, Result<()>> {
        ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    use std::sync::Mutex;
    use std::sync::atomic::{AtomicBool, Ordering};

    /// The single record the stub keeps.
    type Record = Option<(String, Vec<u8>)>;

    /// A store written against the contract from outside any implementation crate.
    #[derive(Default)]
    struct StubStorage {
        last: Mutex<Record>,
        shut_down: AtomicBool,
    }

    impl Storage for StubStorage {
        fn name(&self) -> &'static str {
            "stub"
        }

        fn put<'a>(&'a self, key: &'a str, value: &'a [u8]) -> BoxFuture<'a, Result<()>> {
            Box::pin(async move {
                *self
                    .last
                    .lock()
                    .map_err(|error| StorageError::backend(error.to_string()))? =
                    Some((key.to_owned(), value.to_vec()));

                Ok(())
            })
        }

        fn get<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<Option<Vec<u8>>>> {
            Box::pin(async move {
                Ok(self
                    .last
                    .lock()
                    .map_err(|error| StorageError::backend(error.to_string()))?
                    .as_ref()
                    .filter(|(stored, _)| stored == key)
                    .map(|(_, value)| value.clone()))
            })
        }

        fn shutdown(&self) -> BoxFuture<'_, Result<()>> {
            Box::pin(async move {
                self.shut_down.store(true, Ordering::SeqCst);

                Ok(())
            })
        }
    }

    #[tokio::test]
    async fn test_the_contract_is_implementable_from_outside_and_usable_as_a_trait_object() {
        let storage: Box<dyn Storage> = Box::new(StubStorage::default());

        storage
            .put("a", b"one")
            .await
            .expect("the record is stored");

        assert_eq!(storage.name(), "stub");
        assert_eq!(
            storage.get("a").await.expect("the record is readable"),
            Some(b"one".to_vec())
        );
        assert_eq!(storage.get("b").await.expect("the read succeeds"), None);
    }

    #[tokio::test]
    async fn test_a_store_with_nothing_to_release_keeps_the_default_shutdown() {
        struct Minimal;

        impl Storage for Minimal {
            fn name(&self) -> &'static str {
                "minimal"
            }

            fn put<'a>(&'a self, _key: &'a str, _value: &'a [u8]) -> BoxFuture<'a, Result<()>> {
                ready(Ok(()))
            }

            fn get<'a>(&'a self, _key: &'a str) -> BoxFuture<'a, Result<Option<Vec<u8>>>> {
                ready(Ok(None))
            }
        }

        Minimal
            .shutdown()
            .await
            .expect("the default releases nothing");
    }

    #[tokio::test]
    async fn test_a_store_with_something_to_release_is_told_to() {
        let storage = StubStorage::default();

        storage.shutdown().await.expect("the store releases");

        assert!(storage.shut_down.load(Ordering::SeqCst));
    }
}

/// The store's own maintenance, as the `storage` block of a plane's section
/// declares it.
///
/// # What it is for
///
/// A content-addressed store only ever adds: objects are written before the
/// commit that references them, so a push that never commits leaves objects
/// nothing will reach. This is the block that says whether, how often, and —
/// the part that matters — **how old** such an object must be before it may be
/// removed.
///
/// # Why the grace period is not a tuning knob
///
/// During a push, the uploaded objects are legitimately unreachable until the
/// commit lands. A sweep that ignored their age would delete the work of every
/// push in flight, and the client would learn about it from a commit refused
/// for an object it knows it sent. The window therefore has to exceed the
/// slowest legitimate push by a wide margin; the server refuses a value that
/// does not.
#[derive(Debug, Default, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageSection {
    /// Reclaiming what nothing references.
    #[serde(default)]
    gc: GcSection,
}

/// The sweep itself.
#[derive(Debug, Default, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GcSection {
    #[serde(default)]
    enabled: Option<String>,
    /// How often the store is swept, e.g. `6h`.
    #[serde(default)]
    interval: Option<String>,
    /// How old an unreachable object must be before it may go, e.g. `24h`.
    #[serde(default)]
    grace: Option<String>,
}

impl StorageSection {
    /// The block, as pairs for the configuration-file layer.
    pub fn settings(&self) -> Vec<(String, String)> {
        [
            (crate::config::SETTING_GC_ENABLED, self.gc.enabled.as_ref()),
            (
                crate::config::SETTING_GC_INTERVAL,
                self.gc.interval.as_ref(),
            ),
            (crate::config::SETTING_GC_GRACE, self.gc.grace.as_ref()),
        ]
        .into_iter()
        .filter_map(|(key, value)| value.map(|value| (key.to_owned(), value.clone())))
        .collect()
    }
}

#[cfg(test)]
mod storage_section_tests {
    #![allow(clippy::expect_used)]

    use super::*;

    #[test]
    fn the_block_becomes_the_settings_the_plane_reads() {
        let section: StorageSection =
            serde_norway::from_str("gc:\n  enabled: \"true\"\n  interval: 6h\n  grace: 24h\n")
                .expect("the section parses");

        assert_eq!(
            section.settings(),
            vec![
                (
                    crate::config::SETTING_GC_ENABLED.to_owned(),
                    "true".to_owned()
                ),
                (
                    crate::config::SETTING_GC_INTERVAL.to_owned(),
                    "6h".to_owned()
                ),
                (crate::config::SETTING_GC_GRACE.to_owned(), "24h".to_owned()),
            ]
        );
    }

    #[test]
    fn an_absent_block_leaves_every_default_alone() {
        let section: StorageSection = serde_norway::from_str("{}").expect("an empty block");

        assert!(section.settings().is_empty());
    }
}
