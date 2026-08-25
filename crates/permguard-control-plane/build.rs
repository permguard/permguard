// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The control plane's gRPC contract, compiled from the `.proto` files this
//! crate owns: it serves them, so it keeps them. Server stubs only — a
//! caller generates its own client half from these same files (see the
//! CLI's `build.rs`), which is why the contract lives here and not in a
//! crate both sides would have to import.

use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let protos = [
        "../../proto/permguard/control/v1/control_plane.proto",
        "../../proto/permguard/control/v1/notp.proto",
        "../../proto/permguard/control/v1/decisions.proto",
    ];

    for proto in protos {
        println!("cargo:rerun-if-changed={proto}");
    }
    println!("cargo:rerun-if-changed=../../proto");

    tonic_prost_build::configure()
        .build_client(false)
        .build_server(true)
        .compile_protos(&protos, &["../../proto"])?;

    Ok(())
}
