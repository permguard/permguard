// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! An application that embeds the whole native composition: the Data Plane over a Host the
//! runtime composes for it, on the application's own Tokio runtime, with no listener, no server
//! and no signal handler. It names one Permguard package, `permguard-embedded`, with the language
//! and the capabilities its build selects.
//!
//! The tests are the profiles' proof; what each profile links is
//! `scripts/check-native-fixture.sh`'s to read.

#![forbid(unsafe_code)]

pub use permguard_embedded::{Actor, Embedded};
