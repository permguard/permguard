// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Generates the selected contracts of `contracts/proto`, once for the whole workspace.
//!
//! Each contract is a feature: its messages are generated when it is on, the client stubs of its
//! services with `<contract>-client`, the server stubs with `<contract>-server`. Before this
//! package the client library, each server, the Host and the conformance crate generated their own
//! copies, so one message was a different Rust type in each.

use std::error::Error;
use std::path::{Path, PathBuf};

/// The contracts: the feature, as Cargo spells it in the environment, the files, and whether the
/// `serde` feature makes its messages serialize.
const CONTRACTS: &[(&str, &[&str], bool)] = &[
    (
        "CONTROL",
        &[
            "permguard/control/v1/control_plane.proto",
            "permguard/control/v1/notp.proto",
            "permguard/control/v1/decisions.proto",
            "permguard/control/v1/events.proto",
        ],
        false,
    ),
    (
        "DATA",
        &[
            "permguard/data/v1/data_plane.proto",
            "permguard/data/v1/pdp.proto",
        ],
        false,
    ),
    ("HOST", &["permguard/host/v1/host.proto"], true),
    (
        "AUTHORITY",
        &["permguard/authority/v1/authority.proto"],
        true,
    ),
    ("HEALTH", &["grpc/health/v1/health.proto"], false),
];

fn on(feature: &str) -> bool {
    std::env::var_os(format!("CARGO_FEATURE_{feature}")).is_some()
}

fn main() -> Result<(), Box<dyn Error>> {
    let root = Path::new("../../contracts/proto");
    println!("cargo:rerun-if-changed={}", root.display());

    for (feature, files, serializes) in CONTRACTS {
        let protos: Vec<PathBuf> = files.iter().map(|file| root.join(file)).collect();
        for proto in &protos {
            if !proto.exists() {
                return Err(format!("a contract is not at {}", proto.display()).into());
            }
        }
        if !on(feature) {
            continue;
        }
        let mut builder = tonic_prost_build::configure()
            .build_client(on(&format!("{feature}_CLIENT")))
            .build_server(on(&format!("{feature}_SERVER")));
        if *serializes && on("SERDE") {
            builder = builder.type_attribute(".", "#[derive(serde::Serialize)]");
        }
        builder.compile_protos(&protos, &[root.to_path_buf()])?;
    }

    if on("DESCRIPTORS") {
        // Every Permguard contract, whatever is selected: the set describes the contracts, not
        // this build. Generated apart, so it adds no type to the library.
        let out = PathBuf::from(std::env::var("OUT_DIR")?);
        let scratch = out.join("descriptors");
        std::fs::create_dir_all(&scratch)?;
        let every: Vec<PathBuf> = CONTRACTS
            .iter()
            .filter(|(feature, _, _)| *feature != "HEALTH")
            .flat_map(|(_, files, _)| files.iter().map(|file| root.join(file)))
            .collect();
        tonic_prost_build::configure()
            .build_client(false)
            .build_server(false)
            .out_dir(&scratch)
            .file_descriptor_set_path(out.join("contracts.bin"))
            .compile_protos(&every, &[root.to_path_buf()])?;
    }

    Ok(())
}
