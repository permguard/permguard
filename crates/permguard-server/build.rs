// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The Host API's gRPC contract, compiled from the checked-in `contracts/proto/`, the one source
//! of every wire schema. The server stubs, and the client half too: a Host initiating a peer
//! session is a caller of another Host's `IdentityService.PeerChannel` (WP-2.3). Any other
//! caller generates its own client half from these same files.

use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let protos = ["../../contracts/proto/permguard/host/v1/host.proto"];
    let iam = ["../../contracts/proto/permguard/iam/v1/iam.proto"];

    for proto in protos {
        println!("cargo:rerun-if-changed={proto}");
    }
    println!("cargo:rerun-if-changed=../../contracts/proto");

    tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        .compile_protos(&protos, &["../../contracts/proto"])?;
    // Identity and access (iteration 02, WP-11.1): its own services, the Host API's messages.
    tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        .extern_path(".permguard.host.v1", "crate::host_api::v1")
        // Its own directory: a generation shares none with the Host API's, which it would
        // otherwise overwrite with the imported package's husk.
        .out_dir(iam_out()?)
        .compile_protos(&iam, &["../../contracts/proto"])?;

    Ok(())
}

/// Where the `permguard.iam.v1` stubs are generated: `OUT_DIR/iam`.
fn iam_out() -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let out = std::path::PathBuf::from(std::env::var("OUT_DIR")?).join("iam");
    std::fs::create_dir_all(&out)?;
    Ok(out)
}
