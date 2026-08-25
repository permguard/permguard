// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The git-like content-addressed object model, as specified in
//! `docs/gitlike-object-model.md`.
//!
//! This crate is the shared implementation of everything the specification
//! calls normative and every participant must compute identically: the
//! canonical CBOR profile, digests, the three structural objects, the entry
//! and ref grammars, the policy-id cascade, the manifest, and the signed
//! head statement with its rollback rules.
//!
//! It says what the objects **are**, and nothing about what is done with
//! them: storage keeps them (`permguard-control-plane`'s store, the CLI's
//! mirror), `permguard-notp` moves them, the languages validate their
//! payloads. None of that is visible from here — which is what lets every
//! side compute the same digests without agreeing on anything else.

pub mod cbor;
pub mod compress;
pub mod digest;
pub mod grammar;
pub mod limits;
pub mod manifest;
pub mod object;
pub mod policy_id;
pub mod semver;
pub mod statement;

pub use digest::Digest;
pub use object::{Blob, Commit, Kind, Tree, TreeEntry};
pub use statement::{Freshness, HeadStatement};
