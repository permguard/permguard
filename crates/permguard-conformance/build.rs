// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Compiles the Host API stub, `permguard.host.v1`, from the checked-in `contracts/proto/`. No
//! plane serves it yet; compiling it here keeps the stub valid protobuf and its services real
//! traits a test can name.
//!
//! Also writes the descriptor set of every checked-in proto, `contracts.bin`, which the REST to
//! gRPC mapping test resolves the OpenAPI annotations against.

use std::error::Error;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn Error>> {
    let protos = ["../../contracts/proto/permguard/host/v1/host.proto"];
    let every = [
        "../../contracts/proto/permguard/control/v1/control_plane.proto",
        "../../contracts/proto/permguard/control/v1/notp.proto",
        "../../contracts/proto/permguard/control/v1/decisions.proto",
        "../../contracts/proto/permguard/control/v1/events.proto",
        "../../contracts/proto/permguard/data/v1/data_plane.proto",
        "../../contracts/proto/permguard/data/v1/pdp.proto",
        "../../contracts/proto/permguard/host/v1/host.proto",
    ];

    for proto in every {
        println!("cargo:rerun-if-changed={proto}");
    }

    // The descriptor pass generates no code anyone includes: it writes into a directory of its
    // own so the Host stub above is the only generated module.
    let out = PathBuf::from(std::env::var("OUT_DIR")?);
    let descriptors = out.join("descriptors");
    std::fs::create_dir_all(&descriptors)?;
    tonic_prost_build::configure()
        .build_client(false)
        .build_server(false)
        .out_dir(&descriptors)
        .file_descriptor_set_path(out.join("contracts.bin"))
        .compile_protos(&every, &["../../contracts/proto"])?;

    // The Host API's server half, so the stub test names every service, and its client half, so
    // the cross-transport vectors drive the Host listener over gRPC exactly as REST is driven;
    // every message serializes, so a gRPC answer is compared with a REST answer as one JSON.
    tonic_prost_build::configure()
        .build_client(true)
        .build_server(true)
        .type_attribute(".permguard.host.v1", "#[derive(serde::Serialize)]")
        .compile_protos(&protos, &["../../contracts/proto"])?;

    Ok(())
}
