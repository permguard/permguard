// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The bucket as the object store of the audit trails kept on PostgreSQL: where their sealed
//! days are settled (`1-architecture/5` Stores).

use permguard_postgres::audit::Objects;

use crate::{Bucket, Put};

/// The most bytes a settled day may hold: a day of records of at most 64 KiB each, far past
/// what a Host writes in a day.
const MAX_DAY_BYTES: usize = 256 * 1024 * 1024;

impl Objects for Bucket {
    fn put_new(&self, key: &str, bytes: &[u8]) -> Result<bool, String> {
        Bucket::put_new(self, key, bytes)
            .map(|put| put == Put::Written)
            .map_err(|error| error.to_string())
    }

    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, String> {
        Bucket::get(self, key, MAX_DAY_BYTES).map_err(|error| error.to_string())
    }

    fn delete(&self, key: &str) -> Result<(), String> {
        Bucket::delete(self, key).map_err(|error| error.to_string())
    }
}
