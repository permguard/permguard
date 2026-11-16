#![forbid(unsafe_code)]
#![deny(clippy::all, clippy::unwrap_used, clippy::expect_used)]
// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What every Permguard TLS endpoint shares, whichever end of the connection it is.
//!
//! | Module       | What it fixes                                                             |
//! | ------------ | ------------------------------------------------------------------------- |
//! | [`policy`]   | the cipher suites and key-exchange groups an endpoint negotiates          |
//! | [`material`] | certificates, a private key and revocation lists read off the disk        |
//! | [`binding`]  | the RFC 9266 `tls-exporter` channel binding of a TLS 1.3 connection       |
//!
//! A listener is `permguard-transport`'s and a client is `permguard-client`'s: each builds its
//! configuration on this, so neither links the other to agree on an algorithm.

pub mod binding;
pub mod material;
pub mod policy;

pub use binding::{EXPORTER_LABEL, channel_binding};
pub use material::{load_certificates, load_key, load_revocations};
pub use policy::{CIPHER_SUITES, provider};
