#![forbid(unsafe_code)]
#![deny(clippy::all)]
// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The verified local mirror of a policy ledger (the crate boundaries refactoring, RD-12).
//!
//! | Module                               | What it is                                                              |
//! | ------------------------------------ | ----------------------------------------------------------------------- |
//! | [`store`], [`objects`]               | where the local half lives, and the objects it holds                    |
//! | [`checkpoint`]                       | the commit a mirror stands at, moved atomically                         |
//! | [`verify`]                           | the proof discipline: a signed head, its freshness, its closure         |
//! | [`remote`]                           | what a mirror asks of whoever holds the ledger: the pull verbs of NOTP  |
//! | [`pull`]                             | the fetch cycle that respects the proof: fetch, prove, then checkpoint  |
//!
//! **Pull only, and no network.** A mirror learns the last commit, fetches what it lacks, proves
//! the closure and the signature, and moves a checkpoint. Who answers is a [`remote::Remote`] the
//! caller hands in: a network client's, or a Host's task session. Nothing here opens a connection,
//! so a Data Plane that mirrors over its Host's sessions links no transport.

pub mod checkpoint;
pub mod objects;
pub mod pull;
pub mod remote;
pub mod store;
pub mod verify;

pub use remote::{RefAnswer, Remote};
pub use store::{FsStore, Store};
