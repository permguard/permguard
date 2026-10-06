// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The checked-in contracts under `contracts/`: the protobuf of every gRPC surface, the OpenAPI of
//! every REST surface, the CBOR label registries and the stable-code ownership report.
//!
//! The planes compile their own protobuf; this module compiles what no plane serves yet, the Host
//! API stub, and gives the contract tests the path of the `contracts/` root.

use std::path::{Path, PathBuf};

/// The generated halves of the Host API, `permguard.host.v1`: the servers, so the stub test
/// names every service, and the clients, so the vectors drive the listener over gRPC.
#[allow(clippy::all, missing_docs)]
pub mod host_v1 {
    tonic::include_proto!("permguard.host.v1");
}

/// The repository's `contracts/` directory.
pub fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../contracts")
}

/// The descriptor set of every checked-in proto, written by the build script.
pub fn descriptors() -> prost_types::FileDescriptorSet {
    use prost::Message;
    prost_types::FileDescriptorSet::decode(
        &include_bytes!(concat!(env!("OUT_DIR"), "/contracts.bin"))[..],
    )
    .expect("the build script wrote a descriptor set")
}

/// The fields of the message `full_name` (`package.Message`, nested types as `Outer.Inner`), or
/// `None` when no checked-in proto declares it.
pub fn message_fields(
    set: &prost_types::FileDescriptorSet,
    full_name: &str,
) -> Option<Vec<String>> {
    fn find<'a>(
        prefix: &str,
        messages: &'a [prost_types::DescriptorProto],
        full_name: &str,
    ) -> Option<&'a prost_types::DescriptorProto> {
        for message in messages {
            let name = format!("{prefix}.{}", message.name());
            if name == full_name {
                return Some(message);
            }
            if let Some(found) = find(&name, &message.nested_type, full_name) {
                return Some(found);
            }
        }
        None
    }
    set.file.iter().find_map(|file| {
        find(file.package(), &file.message_type, full_name).map(|message| {
            message
                .field
                .iter()
                .map(|field| field.name().to_owned())
                .collect()
        })
    })
}
