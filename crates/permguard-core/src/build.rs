// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What build this is — the two facts every Permguard binary reports about itself.
//!
//! Both are stamped by whoever builds the release and default to something
//! honest when nobody did. `Cargo.toml` does *not* carry the released version:
//! the tag does. A workspace whose version moves per release means a commit per
//! release, a lockfile churned per release, and four files that have to agree
//! before a tag can exist — all to restate a number the tag already states. So
//! the workspace version stays put, GoReleaser passes the tag in, and a build
//! nobody stamped says the workspace version, which is exactly what a build
//! from a working tree is.
//!
//! `build.rs` tells Cargo to rebuild this crate when either variable changes,
//! so a rebuilt binary never keeps the previous build's answer.

/// The version this binary reports: the release tag, or the workspace version
/// for anything built outside a release.
pub const VERSION: &str = stamped(
    option_env!("PERMGUARD_BUILD_VERSION"),
    env!("CARGO_PKG_VERSION"),
);

/// The commit this binary was built from, or `unknown` for a build nothing stamped.
pub const COMMIT: &str = stamped(option_env!("PERMGUARD_BUILD_COMMIT"), "unknown");

/// The stamp, or the fallback when nobody stamped — where "nobody" includes a
/// build that exported the variable empty.
///
/// `option_env!` answers `Some("")` for a variable that is set to nothing, and
/// that is exactly what a `Dockerfile` whose `ARG` defaults to `""` exports:
/// every image the compose lab built reported an empty version and an empty
/// commit, and the fallback was never reached. Empty is not a version, so it
/// is read as absent.
const fn stamped(value: Option<&'static str>, fallback: &'static str) -> &'static str {
    match value {
        Some(value) if !value.is_empty() => value,
        _ => fallback,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_an_unstamped_build_falls_back_to_something_true() {
        // Nothing stamps a `cargo test`, so both constants are on their
        // fallback path — which is the path every developer machine takes.
        assert_eq!(VERSION, env!("CARGO_PKG_VERSION"));
        assert_eq!(COMMIT, "unknown");
    }

    #[test]
    fn test_an_empty_stamp_is_no_stamp() {
        // What a `Dockerfile` exports when its `ARG` was left at `""`: set, and empty.
        assert_eq!(stamped(Some(""), "fallback"), "fallback");
        assert_eq!(stamped(None, "fallback"), "fallback");
        assert_eq!(stamped(Some("v1.2.3"), "fallback"), "v1.2.3");
    }
}
