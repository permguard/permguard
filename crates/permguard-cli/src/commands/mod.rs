// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! One module per command family: what each command *does*, with the shape
//! it is typed in living in [`crate::args`].

pub mod catalog;
pub mod check;
pub mod config;
pub mod decisions;
pub mod events;
pub mod inspect;
pub mod objects;
pub mod workspace;
