// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The implementations of [`permguard_core`] a deployment gets unless it brings its own.
//!
//! The name is the relationship: `permguard-core` is the foundation everyone agrees on, and this is the
//! layer built on it that actually touches the world — the filesystem, the clock, a random number
//! generator, a hash function. It is the same split Rust itself makes between `core` and `std`, for
//! the same reason.
//!
//! # Why these live together and the contracts do not
//!
//! A crate boundary buys exactly four things a module does not: its own dependency set, its own
//! compilation unit, its own version, and acyclicity enforced by cargo. It does **not** buy
//! replaceability — a trait in a module is as implementable from outside as a trait in a crate of its
//! own.
//!
//! So the boundary that pays for itself is the one between *contracts* and *implementations*, and
//! nothing else here. A crate that implements one of these contracts depends on `permguard-core` and
//! links 22 crates; if the contracts lived beside the implementations it would link 71 — and would
//! ship a certificate-authority-minting library in order to name a trait.
//!
//! Between the implementations themselves there is nothing to isolate: they are leaves, they depend
//! on nothing but the contracts, and six crates of eighty to nine hundred lines each bought six
//! manifests and no property.
//!
//! # Taking only what you need
//!
//! Each area is a feature, so a build links the dependencies of the implementations it actually uses:
//!
//! ```toml
//! permguard-std = { version = "0.1", default-features = false, features = ["secrets", "storage"] }
//! ```
//!
//! `provision` is **not** in the default set, and deliberately: it is the one that can mint a
//! certificate authority. Getting it has to be something written down — `features = ["provision"]` —
//! rather than something inherited by writing the crate's name.

#![forbid(unsafe_code)]
#![deny(clippy::all, clippy::unwrap_used, clippy::expect_used)]

#[cfg(feature = "audit")]
pub mod audit;
#[cfg(feature = "catalog")]
pub mod catalog;
#[cfg(feature = "keys")]
pub mod keys;
#[cfg(feature = "metrics")]
pub mod metrics;
#[cfg(feature = "provision")]
pub mod provision;
#[cfg(feature = "pseudonym")]
pub mod pseudonym;
#[cfg(feature = "secrets")]
pub mod secrets;
#[cfg(feature = "storage")]
pub mod storage;
