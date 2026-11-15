// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What a plane is configured with, below any server: its setting keys and sections, where its
//! listeners read their addresses and TLS material from, and which planes are served where.
//!
//! The server binds and serves what these say; a plane's domain reads them to name itself, its
//! issuer or its published address, without reaching the server (the crate boundaries
//! refactoring, RD-1).

mod addresses;
pub mod discovery;
pub mod settings;

pub use addresses::{PlaneAddress, PlaneAddresses, PlaneTls};
