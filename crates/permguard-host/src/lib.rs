// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The Host's own modules.
//!
//! The Host is the process that owns one volume and runs the planes on it. Its first module is
//! [`storage`]: the one library every subsystem writes its files through, so that the storage
//! contract of the architecture — immutable content never replaced, views replaced atomically,
//! journals framed and checksummed, a torn tail truncated and never guessed, every durable claim
//! following a flush of file and directory — is implemented and tested once.
//!
//! [`composition`] is the Host's composition core: every generic capability implemented once, and
//! the typed, least-privilege handles a Plane receives for what it declared.

#![forbid(unsafe_code)]

pub mod api;
pub mod audit;
pub mod authz;
pub mod composition;
pub mod operations;
pub mod storage;
pub mod time;
