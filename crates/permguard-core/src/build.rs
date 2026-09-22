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

/// A Docker `ARG` left at its `""` default and forwarded to `ENV` unconditionally is *set*, not
/// absent — `option_env!` sees `Some("")`, so the fallback below never ran for a plane built by
/// `docker-compose.lab.yml`, which passes no build args at all. Empty is absence too.
const fn stamped_or(value: Option<&'static str>, fallback: &'static str) -> &'static str {
    match value {
        Some(stamped) if !stamped.is_empty() => stamped,
        _ => fallback,
    }
}

/// The version this binary reports: the release tag, or the workspace version
/// for anything built outside a release.
pub const VERSION: &str = stamped_or(option_env!("PERMGUARD_BUILD_VERSION"), env!("CARGO_PKG_VERSION"));

/// The commit this binary was built from, or `unknown` for a build nothing stamped.
pub const COMMIT: &str = stamped_or(option_env!("PERMGUARD_BUILD_COMMIT"), "unknown");

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
    fn test_a_build_arg_left_at_its_empty_default_is_absence_too() {
        // docker-compose.lab.yml passes no PERMGUARD_BUILD_* args, but the
        // Dockerfile's `ARG …=""` is forwarded to `ENV` regardless, so the
        // binary is built with the variable *set* to "" — not unset. A
        // plane built that way must still report the honest fallback, not
        // a blank field nobody can read (BUG-6).
        assert_eq!(stamped_or(Some(""), "fallback"), "fallback");
        assert_eq!(stamped_or(None, "fallback"), "fallback");
        assert_eq!(stamped_or(Some("v1.2.3"), "fallback"), "v1.2.3");
    }
}
