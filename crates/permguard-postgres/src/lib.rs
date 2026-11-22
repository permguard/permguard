// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The PostgreSQL side of the second storage backend (`1-architecture/8` Storage backends):
//! what every store contract implemented on PostgreSQL is built on.
//!
//! | Module       | What it is                                                                      |
//! | ------------ | ------------------------------------------------------------------------------- |
//! | [`database`] | the connections, their TLS, and the unit of work: one `SERIALIZABLE` transaction |
//! | [`schema`]   | the versioned schema, forward only, checked at start                            |
//! | [`lease`]    | a lease with a generation, checked inside the transaction that writes under it  |
//! | [`time`]     | the clock's high-water mark, the first store contract kept here                 |
//!
//! The store contracts are synchronous, as the file backend's calls are, and are called from
//! threads that drive asynchronous tasks. So this crate uses the synchronous client, and a call
//! to it made from such a thread is run on a thread of its own: the client blocks on a runtime
//! it owns, which a thread already inside a runtime may not do.
//!
//! No state is kept in memory: every decision reads inside its transaction.

pub mod database;
pub mod lease;
pub mod mutations;
pub mod schema;
pub mod time;

pub use database::{Config, Database, DbError, Failure, SqlError, Tls, Unit};
