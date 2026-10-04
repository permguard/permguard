// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Which files are the authority and which can be rebuilt (P4).
//!
//! A file is never called a cache when losing it would change an authorization or verification
//! result. A subsystem says which of its files are which by implementing [`Declared`], and holds
//! them as [`Authoritative`] or [`Rebuildable`] so the difference is in the types: an authoritative
//! file that does not verify is an error to surface, a rebuildable one that does not verify is
//! rebuilt from its authority.

/// The two kinds of file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Authority {
    /// Journals, immutable objects and segments, signed refs: losing one changes a result.
    Authoritative,
    /// Snapshots, materialized views, indexes: rebuilt from an authority, never trusted over it.
    Rebuildable,
}

/// One kind of file a subsystem keeps, by the pattern of its name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileClass {
    pub pattern: &'static str,
    pub authority: Authority,
    /// What it is the authority for, or what it is rebuilt from.
    pub why: &'static str,
}

/// A subsystem's statement of its files.
pub trait Declared {
    fn files() -> &'static [FileClass];
}

/// A handle on an authoritative file or directory.
#[derive(Debug)]
pub struct Authoritative<T>(T);

/// A handle on a rebuildable file or directory.
#[derive(Debug)]
pub struct Rebuildable<T>(T);

impl<T> Authoritative<T> {
    pub fn new(held: T) -> Self {
        Self(held)
    }
    pub fn get(&self) -> &T {
        &self.0
    }
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> Rebuildable<T> {
    pub fn new(held: T) -> Self {
        Self(held)
    }
    pub fn get(&self) -> &T {
        &self.0
    }
    pub fn into_inner(self) -> T {
        self.0
    }
}
