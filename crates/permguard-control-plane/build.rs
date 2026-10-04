// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The control plane's gRPC contract, compiled from the checked-in
//! `contracts/proto/`, the one source of every wire schema. Server stubs only
//! — a caller generates its own client half from these same files (see the
//! client's `build.rs`), so no crate both sides would have to import exists.

use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let protos = [
        "../../contracts/proto/permguard/control/v1/control_plane.proto",
        "../../contracts/proto/permguard/control/v1/notp.proto",
        "../../contracts/proto/permguard/control/v1/decisions.proto",
        "../../contracts/proto/permguard/control/v1/events.proto",
    ];

    for proto in protos {
        println!("cargo:rerun-if-changed={proto}");
    }
    println!("cargo:rerun-if-changed=../../contracts/proto");

    tonic_prost_build::configure()
        .build_client(false)
        .build_server(true)
        .compile_protos(&protos, &["../../contracts/proto"])?;

    Ok(())
}
