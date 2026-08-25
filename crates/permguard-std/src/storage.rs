// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Implementations of [`permguard_core::Storage`].
//!
//! [`MemoryStorage`] is one implementation of the contract, not the implementation: a build that
//! needs durability, replication, or a managed backend supplies its own and never touches this crate.

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard};

use permguard_core::StorageError;

/// What this store answers with.
type Result<T> = std::result::Result<T, StorageError>;

use permguard_core::{BoxFuture, Storage};

/// A process-local store that keeps records in memory for the lifetime of the process.
///
/// It is the default only because the default has to be something that works without external
/// infrastructure. Nothing it holds survives a restart.
#[derive(Debug, Default)]
pub struct MemoryStorage {
    records: Mutex<BTreeMap<String, Vec<u8>>>,
}

impl MemoryStorage {
    /// Builds an empty in-memory store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the number of records currently held.
    pub fn len(&self) -> Result<usize> {
        Ok(self.records()?.len())
    }

    /// Reports whether the store holds no record.
    pub fn is_empty(&self) -> Result<bool> {
        Ok(self.len()? == 0)
    }

    fn records(&self) -> Result<MutexGuard<'_, BTreeMap<String, Vec<u8>>>> {
        self.records.lock().map_err(|error| {
            StorageError::backend(format!("the in-memory store lock is poisoned: {error}"))
        })
    }
}

impl Storage for MemoryStorage {
    fn name(&self) -> &'static str {
        "memory"
    }

    fn put<'a>(&'a self, key: &'a str, value: &'a [u8]) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            self.records()?.insert(key.to_owned(), value.to_vec());

            Ok(())
        })
    }

    fn get<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<Option<Vec<u8>>>> {
        Box::pin(async move { Ok(self.records()?.get(key).cloned()) })
    }

    /// Drops every record it was holding.
    ///
    /// Nothing here survives the process anyway, so releasing is the honest thing to do rather than a
    /// no-op that pretends there was durability to flush.
    fn shutdown(&self) -> BoxFuture<'_, Result<()>> {
        Box::pin(async move {
            self.records()?.clear();

            Ok(())
        })
    }
}
