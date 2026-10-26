// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! One module per command family: what each command *does*, with the shape
//! it is typed in living in [`crate::args`].

pub mod catalog;
pub mod check;
pub mod config;
pub mod decisions;
pub mod discover;
pub mod events;
pub mod host;
pub(crate) mod host_ops;
pub mod host_proof;
pub mod inspect;
pub mod objects;
pub mod offline_ops;
pub mod reclaim;
pub mod restore;
pub mod workspace;
