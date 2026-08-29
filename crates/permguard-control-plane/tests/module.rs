// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#[test]
fn module_metadata_identifies_control_plane() {
    let module = permguard_control_plane::module();

    assert_eq!(module.id(), "control");
    assert_eq!(module.component(), "control-plane");
    assert_eq!(module.description(), "control plane");
}

/// The event store takes two switches, and one is not enough.
///
/// # What this is actually about
///
/// The control plane's gate has to be the same shape as the data plane's, because the two ends are
/// one contract: a deployment where the producer ships and the receiver refuses, or the reverse, is
/// a deployment that discovers its mistake as unattributable batches piling up in a spool. So both
/// ends read the same experimental switch alongside their own, and the half-said combination stops
/// the process rather than starting one that answers nothing.
#[test]
fn the_event_store_needs_both_switches_and_says_so_when_it_has_one() {
    use permguard_core::config::{SETTING_EVENT_STORE_ENABLED, SETTING_EXPERIMENTAL_DOGWOOD};

    let module = permguard_control_plane::module();

    let settings = |extra: &[(&str, &str)]| {
        permguard_core::Config::from_layers(
            permguard_server::plane::build_settings("0.0.0-test"),
            vec![permguard_server::plane::SETTING_RUNTIME_PLANES],
            permguard_core::config::Layers {
                file: extra
                    .iter()
                    .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
                    .collect(),
                ..Default::default()
            },
        )
        .expect("the test configuration builds")
    };

    assert!(module.startup_check(&settings(&[])).is_ok());

    let half = settings(&[(SETTING_EVENT_STORE_ENABLED, "true")]);
    let refused = module
        .startup_check(&half)
        .expect_err("a plane configured half-way does not start");
    let said = refused.to_string();
    assert!(said.contains("experimental.dogwood.enabled"), "{said}");
    assert!(said.contains("controlPlane.events.enabled"), "{said}");

    let both = settings(&[
        (SETTING_EVENT_STORE_ENABLED, "true"),
        (SETTING_EXPERIMENTAL_DOGWOOD, "true"),
    ]);
    assert!(module.startup_check(&both).is_ok());
}
