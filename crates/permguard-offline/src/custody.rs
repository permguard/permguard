// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The remote custody providers a Host's keys may be held by (WP-3.2), each an adapter this
//! package carries only when its feature asks: a build without one refuses that custody by name.
//!
//! | Feature  | Provider                                                                    |
//! | -------- | --------------------------------------------------------------------------- |
//! | `kms`    | `transit`, a Vault Transit engine reached over one bounded HTTPS client     |
//! | `pkcs11` | [`pkcs11`], a token whose module is loaded at runtime                       |

#[cfg(feature = "pkcs11")]
pub mod pkcs11;
#[cfg(feature = "kms")]
mod transit;

#[cfg(feature = "kms")]
pub use transit::{Endpoint, Transit, TransitKek, TransitKeys, WRAP_TRANSIT};
