// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

use std::process::ExitCode;

use permguard_core::{ProductIdentity, brand, build};
use permguard_server::plane::{PlaneServer, addresses_for_plane, build_settings};

const BINARY_NAME: &str = "permguard-authority-plane";
const PRODUCT_NAME: &str = "Permguard Authority Plane";
const PRODUCT_ABOUT: &str = "Permguard authority plane";

#[tokio::main]
async fn main() -> ExitCode {
    let identity = ProductIdentity::new(
        BINARY_NAME,
        PRODUCT_NAME,
        brand::PERMGUARD_TAGLINE,
        PRODUCT_ABOUT,
        brand::PERMGUARD_ART,
    );

    PlaneServer::new(identity, build_settings(build::VERSION))
        // The postgresql-s3 backend, when the configuration names it (iteration 03, WP-28.1).
        .with_shared_backend(permguard_s3::backend::open)
        .with_plane(
            permguard_authority_plane_server::module(),
            addresses_for_plane("authority").expect("authority plane addresses are known"),
        )
        .run()
        .await
}
