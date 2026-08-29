// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The client half of Permguard's gRPC contracts, generated from the one
//! `proto/` root — a single source of truth for the wire, compiled twice: a
//! plane builds the server stubs, this builds the client ones.
//!
//! Two contracts, because a client of a Permguard deployment asks two things:
//! the control plane's catalog and NOTP transfer, and the data plane's
//! decision endpoint.
//!
//! Generating rather than sharing a crate is deliberate: the two halves
//! never exchange Rust types, only bytes on the wire, so a crate both sides
//! import would buy nothing — and having a client depend on the control
//! plane would drag a whole server stack into a client binary.

use std::error::Error;
use std::path::Path;

fn main() -> Result<(), Box<dyn Error>> {
    let contract = Path::new("../../proto");
    let protos = [
        contract.join("permguard/control/v1/control_plane.proto"),
        contract.join("permguard/control/v1/notp.proto"),
        contract.join("permguard/control/v1/decisions.proto"),
        contract.join("permguard/control/v1/events.proto"),
        contract.join("permguard/data/v1/pdp.proto"),
    ];

    for proto in &protos {
        // A moved or renamed contract breaks this build loudly, which is the
        // point: a client that silently stops tracking the wire is worse.
        if !proto.exists() {
            return Err(format!("a plane's contract is not at {}", proto.display()).into());
        }
        println!("cargo:rerun-if-changed={}", proto.display());
    }
    println!("cargo:rerun-if-changed={}", contract.display());

    // The client half is what ships; the server half is generated for the
    // tests, where a fake server proves this client speaks the contract the
    // plane serves — the only way to test a wire without a wire.
    tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        .compile_protos(&protos, &[contract.to_path_buf()])?;

    Ok(())
}
