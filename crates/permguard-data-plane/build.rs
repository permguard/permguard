// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    let protos = [
        "../../proto/permguard/data/v1/data_plane.proto",
        "../../proto/permguard/data/v1/pdp.proto",
    ];

    for proto in protos {
        println!("cargo:rerun-if-changed={proto}");
    }
    println!("cargo:rerun-if-changed=../../proto");

    tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        .compile_protos(&protos, &["../../proto"])?;

    Ok(())
}
