#![forbid(unsafe_code)]
// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The contracts of `contracts/proto`, generated once (the crate boundaries refactoring, RD-9).
//!
//! | Module               | Contract                 | Features                                         |
//! | -------------------- | ------------------------ | ------------------------------------------------ |
//! | [`control::v1`]      | `permguard.control.v1`   | `control`, `control-client`, `control-server`    |
//! | [`data::v1`]         | `permguard.data.v1`      | `data`, `data-client`, `data-server`             |
//! | [`host::v1`]         | `permguard.host.v1`      | `host`, `host-client`, `host-server`             |
//! | [`authority::v1`]    | `permguard.authority.v1` | `authority`, `authority-client`, `authority-server` |
//! | [`health::v1`]       | `grpc.health.v1`         | `health`, `health-client`, `health-server`       |
//!
//! A contract's feature generates its messages; `-client` and `-server` add the stubs of its
//! services. A message is one Rust type for every package that names it, so a client adapter, a
//! server adapter and a test speak of the same value.

/// `permguard.control.v1`: the Control Plane's document, NOTP, the decision log and the event log.
#[cfg(feature = "control")]
pub mod control {
    #[allow(clippy::all, clippy::pedantic, missing_docs)]
    pub mod v1 {
        tonic::include_proto!("permguard.control.v1");
    }
}

/// `permguard.data.v1`: the Data Plane's document and the decision point.
#[cfg(feature = "data")]
pub mod data {
    #[allow(clippy::all, clippy::pedantic, missing_docs)]
    pub mod v1 {
        tonic::include_proto!("permguard.data.v1");
    }
}

/// `permguard.host.v1`: the Host API.
#[cfg(feature = "host")]
pub mod host {
    #[allow(clippy::all, clippy::pedantic, missing_docs)]
    pub mod v1 {
        tonic::include_proto!("permguard.host.v1");
    }
}

/// `permguard.authority.v1`: the Authority Plane.
#[cfg(feature = "authority")]
pub mod authority {
    #[allow(clippy::all, clippy::pedantic, missing_docs)]
    pub mod v1 {
        tonic::include_proto!("permguard.authority.v1");
    }
}

/// `grpc.health.v1`: the standard health service every listener answers.
#[cfg(feature = "health")]
pub mod health {
    #[allow(clippy::all, clippy::pedantic, missing_docs)]
    pub mod v1 {
        tonic::include_proto!("grpc.health.v1");
    }
}

/// The encoded descriptor set of every Permguard contract, as `protoc` wrote it.
#[cfg(feature = "descriptors")]
pub const DESCRIPTORS: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/contracts.bin"));
