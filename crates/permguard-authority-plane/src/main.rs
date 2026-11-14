// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The Authority Plane as a process of its own (`2-security/8` Where it runs): one Server hosting
//! the Authority Plane alone, the issuer every other Server of the cluster verifies tokens from.
//! The all-in-one and the control-plane binaries register the same module beside their Planes;
//! this binary registers it alone, so `runtime.planes` names `authority` and nothing else.

#![forbid(unsafe_code)]

include!("main_entry.rs");
