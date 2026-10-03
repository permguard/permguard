// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

use std::process::ExitCode;

use permguard_core::{ProductIdentity, brand, build};
use permguard_server::plane::{PlaneServer, addresses_for_plane, build_settings};

const BINARY_NAME: &str = "permguard-data-plane";
const PRODUCT_NAME: &str = "Permguard Data Plane";
const PRODUCT_ABOUT: &str = "Permguard data plane";

fn main() -> ExitCode {
    // A process started as a supervised evaluation worker answers frames and exits — before a
    // runtime starts a thread per core it would never use, each charged to its address-space limit.
    permguard_data_plane::serve_if_worker();
    permguard_data_plane::report_panics_without_their_words();

    serve()
}

#[tokio::main]
async fn serve() -> ExitCode {
    let identity = ProductIdentity::new(
        BINARY_NAME,
        PRODUCT_NAME,
        brand::PERMGUARD_TAGLINE,
        PRODUCT_ABOUT,
        brand::PERMGUARD_ART,
    );

    PlaneServer::new(identity, build_settings(build::VERSION))
        .with_plane(
            permguard_data_plane::module(),
            addresses_for_plane("data").expect("data plane addresses are known"),
        )
        .run()
        .await
}
