// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The authority plane's gRPC contract, compiled from the checked-in `contracts/proto/`, the one
//! source of every wire schema. Server stubs only: a caller generates its own client half from
//! the same file.

use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let protos = ["../../contracts/proto/permguard/authority/v1/authority.proto"];

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
