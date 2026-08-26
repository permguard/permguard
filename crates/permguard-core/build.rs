// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Cargo does not track the environment variables an `option_env!` reads, so
//! without this a binary rebuilt after the release stamp changed would quietly
//! keep the previous answer. `build::VERSION` and `build::COMMIT` are the two
//! that are stamped, and this is what makes them observable.

fn main() {
    println!("cargo::rerun-if-env-changed=PERMGUARD_BUILD_VERSION");
    println!("cargo::rerun-if-env-changed=PERMGUARD_BUILD_COMMIT");
}
