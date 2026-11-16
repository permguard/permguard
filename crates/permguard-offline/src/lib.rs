#![forbid(unsafe_code)]
// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Offline volume administration, shared by the server and the command line (the crate
//! boundaries refactoring, RD-13): what an offline command needs of the server's start, with no
//! server in it.
//!
//! | Module                              | What it is                                                                  |
//! | ----------------------------------- | --------------------------------------------------------------------------- |
//! | [`volume`]                          | the configuration read as `serve` reads it, the rings and their provisioner |
//! | [`factories`]                       | the implementations a configuration names: secrets, keys, signing rings     |
//! | [`custody`], [`keys`]               | the custody the Host's keys are opened through: file, token or KMS          |
//! | [`migrate`]                         | the migrations of the subsystem layouts, under the volume's lock            |
//! | [`legacy_events`], [`legacy_spool`] | the stores earlier releases wrote, moved onto the streams                   |
//!
//! No listener, no transport, no telemetry: the command line links this and the domain libraries,
//! and runs the same code as the server for every proof, migration and restore.

pub mod custody;
pub mod factories;
pub mod keys;
pub mod legacy_events;
pub mod legacy_spool;
pub mod migrate;
pub mod volume;

pub use factories::build_settings;
pub use keys::custodian_for;
pub use migrate::{MigrateCommand, migrate, migrate_audit_on, migrate_keys_on, migrate_on};
