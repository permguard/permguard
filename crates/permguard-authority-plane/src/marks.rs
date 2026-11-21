// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The highest `iat` signed of each status list, kept so a restarted process signs past it
//! (BUG-0278), and the contract its store keeps (`1-architecture/8` Store contracts).
//!
//! Each change signed moves a list's `iat` one second past the last, so a burst of changes runs
//! it ahead of the clock by as many seconds, and a fixed lead cannot cover that. A Plane refuses
//! a list not after the one it holds, so the mark is kept before a list leaves the process.

use std::collections::BTreeMap;

pub mod files;

/// Where the marks are kept.
pub trait MarkStore: Send + Sync + std::fmt::Debug {
    /// The marks held, by list id. None when the store holds none or what it holds does not
    /// read: the fixed lead of an inherited list then covers it, as before the marks were kept.
    fn held(&self) -> BTreeMap<[u8; 16], u64>;

    /// Keeps `marks` whole, replacing what was held: every list signed, at its highest `iat`.
    /// A mark that cannot be kept is a list not signed.
    fn keep(&self, marks: &BTreeMap<[u8; 16], u64>) -> Result<(), String>;
}
