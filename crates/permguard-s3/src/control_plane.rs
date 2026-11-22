// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The Control Plane's stores on the PostgreSQL and S3 backend: the ones whose objects the
//! bucket keeps, with everything else of them in the database.
//!
//! They implement the Control Plane's contracts from outside its package: its domain links no
//! network client (`1-architecture/11`, Target dependency layers), and this package is one.

pub mod archives;
pub mod ledgers;

pub use archives::PostgresArchives;
pub use ledgers::PostgresLedgers;
