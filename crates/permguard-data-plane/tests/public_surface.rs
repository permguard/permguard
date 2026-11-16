// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The supported surface of the embedded Data Plane is an allow-list
//! (`11-refactoring/1-dependencies.md`, The public surface is too broad for a published SDK): the
//! `embedded` module and the names the library root exports. Every other module is public for the
//! server adapter alone, hidden from the documentation, so adding one cannot make it an accidental
//! commitment.

#![allow(clippy::expect_used)]

/// The modules an application may build against.
const SUPPORTED: &[&str] = &["embedded"];

#[test]
fn every_module_outside_the_supported_surface_is_hidden() {
    let source = include_str!("../src/lib.rs");
    let lines: Vec<&str> = source.lines().collect();
    let mut modules = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        let Some(name) = line
            .strip_prefix("pub mod ")
            .and_then(|rest| rest.strip_suffix(';'))
        else {
            continue;
        };
        let hidden = index > 0 && lines[index - 1] == "#[doc(hidden)]";
        assert_eq!(
            hidden,
            !SUPPORTED.contains(&name),
            "`{name}`: a module is supported and documented, or the domain's own and hidden"
        );
        modules.push(name);
    }
    for name in SUPPORTED {
        assert!(modules.contains(name), "`{name}` is exported");
    }
    assert!(
        modules.len() > SUPPORTED.len(),
        "the check reads the library root: it found {modules:?}"
    );
}

/// The facade names every type of its signatures itself: an application imports them from
/// `embedded` and from nowhere the documentation does not show.
#[test]
fn the_facade_exports_the_types_its_signatures_name() {
    use permguard_data_plane::embedded::{
        Actor, Builder, Capabilities, CheckRequest, CheckResponse, DataPlane, Engine, Health,
        Refused, Runtime, Shutdown, StartError, SubmitRequest, SubmitResponse, TraceContext,
    };

    fn named<T>() -> &'static str {
        std::any::type_name::<T>()
    }
    let names = [
        named::<Actor>(),
        named::<Builder>(),
        named::<Capabilities>(),
        named::<CheckRequest>(),
        named::<CheckResponse>(),
        named::<DataPlane>(),
        named::<Engine>(),
        named::<Health>(),
        named::<Refused>(),
        named::<Runtime>(),
        named::<Shutdown>(),
        named::<StartError>(),
        named::<SubmitRequest>(),
        named::<SubmitResponse>(),
        named::<TraceContext>(),
    ];
    assert_eq!(names.len(), 15);
}
