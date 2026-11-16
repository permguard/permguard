// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! A facade of the Control Plane's domain, as this package serves it over gRPC.
//!
//! The service traits are `permguard-contracts`' and the facades are the domain's, so neither is
//! this package's to implement one for the other: [`Served`] is, and it holds nothing but the
//! facade.

/// A domain facade served over gRPC.
#[derive(Clone)]
pub(crate) struct Served<T>(pub(crate) T);
