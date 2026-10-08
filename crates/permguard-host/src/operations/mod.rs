// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The Host's operations (WP-3.6): the security-mutation transaction every security domain
//! mutates through, and the domains that do.
//!
//! | Module       | What                                                                       |
//! | ------------ | -------------------------------------------------------------------------- |
//! | [`journal`]  | the entries of `host/audit/mutations/`, byte for byte                      |
//! | [`mutation`] | the engine: intent, audit intent, apply, commit, audit outcome, recovery  |
//! | [`grants`]   | the grant store as a domain, and its operations outside the Host API      |
//!
//! `TODO(WP-3.1)`: the key rings adopt the engine when their journal exists (owner decision of
//! 2026-10-07); a later domain uses the same [`mutation::Mutations::run`].

pub mod grants;
pub mod journal;
pub mod mutation;
