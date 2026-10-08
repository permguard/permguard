// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The Host API's gRPC contract, compiled from the checked-in `contracts/proto/`, the one source
//! of every wire schema. The server stubs, and the client half too: a Host initiating a peer
//! session is a caller of another Host's `IdentityService.PeerChannel` (WP-2.3). Any other
//! caller generates its own client half from these same files.

use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let protos = ["../../contracts/proto/permguard/host/v1/host.proto"];

    for proto in protos {
        println!("cargo:rerun-if-changed={proto}");
    }
    println!("cargo:rerun-if-changed=../../contracts/proto");

    tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        .compile_protos(&protos, &["../../contracts/proto"])?;

    Ok(())
}
