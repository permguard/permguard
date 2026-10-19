// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#[test]
fn module_metadata_identifies_control_plane() {
    let module = permguard_control_plane::module();

    assert_eq!(module.id(), "control");
    assert_eq!(module.component(), "control-plane");
    assert_eq!(module.description(), "control plane");
}

/// Enabling the decision store is a startup promise: its durable state and a
/// producer trust source must exist as configuration before the plane binds.
#[test]
fn the_decision_store_is_preflighted_instead_of_disappearing_behind_health() {
    use permguard_core::config::{
        SETTING_DECISION_STORE_DIRECTORY, SETTING_DECISION_STORE_ENABLED, SETTING_WORKING_DIR,
    };

    let module = permguard_control_plane::module();
    let root =
        std::env::temp_dir().join(format!("permguard-decision-module-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).expect("the test volume exists");
    let configured = |directory: &str| {
        permguard_core::Config::from_layers(
            permguard_server::plane::build_settings("0.0.0-test"),
            vec![permguard_server::plane::SETTING_RUNTIME_PLANES],
            permguard_core::config::Layers {
                file: [
                    (SETTING_DECISION_STORE_ENABLED.to_owned(), "true".to_owned()),
                    (SETTING_WORKING_DIR.to_owned(), root.display().to_string()),
                    (
                        SETTING_DECISION_STORE_DIRECTORY.to_owned(),
                        directory.to_owned(),
                    ),
                ]
                .into_iter()
                .collect(),
                ..Default::default()
            },
        )
        .expect("the test configuration builds")
    };

    let no_trust = configured("decisions");
    let refused = module
        .startup_check(&no_trust)
        .expect_err("an enabled receiver with no producer authority does not start");
    assert!(refused.to_string().contains("producer_keys"), "{refused}");

    // The producer may publish its file after this process: the facade mounts
    // fail-closed and reloads it, but the configured path is enough to state
    // where that authority will come from.
    let waiting =
        no_trust.with_decision_producer_keys([permguard_core::decisions::DecisionProducerSource {
            path: "producer.jwks".to_owned(),
            pdp: "plane-a".to_owned(),
        }]);
    module
        .startup_check(&waiting)
        .expect("a usable store and a declared trust source start");
    assert!(root.join("decisions/CURSOR_KEY").is_file());

    let blocked = root.join("blocked");
    std::fs::write(&blocked, b"not a directory").expect("the path is blocked");
    let broken = configured("blocked").with_decision_producer_keys([
        permguard_core::decisions::DecisionProducerSource {
            path: "producer.jwks".to_owned(),
            pdp: "plane-a".to_owned(),
        },
    ]);
    let refused = module
        .startup_check(&broken)
        .expect_err("an unusable configured store stops startup");
    assert!(refused.to_string().contains("decision store"), "{refused}");

    let _ = std::fs::remove_dir_all(root);
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

    // Both switches, and no key file: events arrive over the Host's `events.ship` (WP-6.2b).
    let both = settings(&[
        (SETTING_EVENT_STORE_ENABLED, "true"),
        (SETTING_EXPERIMENTAL_DOGWOOD, "true"),
    ]);
    assert!(module.startup_check(&both).is_ok());
}

/// WP-6.2b (owner decision of 2026-10-18): the event producer key files are retired, and a
/// configuration still naming one is refused rather than believed in force.
#[test]
fn a_declared_event_producer_key_set_is_refused_as_retired() {
    use permguard_core::config::{SETTING_EVENT_STORE_ENABLED, SETTING_EXPERIMENTAL_DOGWOOD};

    let module = permguard_control_plane::module();
    let base = permguard_core::Config::from_layers(
        permguard_server::plane::build_settings("0.0.0-test"),
        vec![permguard_server::plane::SETTING_RUNTIME_PLANES],
        permguard_core::config::Layers {
            file: [
                (SETTING_EVENT_STORE_ENABLED.to_owned(), "true".to_owned()),
                (SETTING_EXPERIMENTAL_DOGWOOD.to_owned(), "true".to_owned()),
            ]
            .into_iter()
            .collect(),
            ..Default::default()
        },
    )
    .expect("the test configuration builds");
    let bound = base.with_event_producer_keys([permguard_core::decisions::EventProducerSource {
        path: "keys/data-plane-events.jwks".to_owned(),
        producer: "data-plane-test".to_owned(),
        zone: "*".to_owned(),
        ledger: "*".to_owned(),
    }]);
    let refused = module
        .startup_check(&bound)
        .expect_err("a retired setting is refused");
    assert!(refused.to_string().contains("is retired"), "{refused}");
}
