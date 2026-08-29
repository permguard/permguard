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
    let waiting = no_trust.with_decision_producer_keys(["producer.jwks".to_owned()]);
    module
        .startup_check(&waiting)
        .expect("a usable store and a declared trust source start");
    assert!(root.join("decisions/CURSOR_KEY").is_file());

    let blocked = root.join("blocked");
    std::fs::write(&blocked, b"not a directory").expect("the path is blocked");
    let broken = configured("blocked").with_decision_producer_keys(["producer.jwks".to_owned()]);
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

    let both_without_trust = settings(&[
        (SETTING_EVENT_STORE_ENABLED, "true"),
        (SETTING_EXPERIMENTAL_DOGWOOD, "true"),
    ]);
    let refused = module
        .startup_check(&both_without_trust)
        .expect_err("an event receiver with no producer authority does not start");
    assert!(
        refused
            .to_string()
            .contains("controlPlane.events.producer_keys"),
        "{refused}"
    );

    let key_set = std::env::temp_dir().join(format!(
        "permguard-event-module-producer-{}.jwks",
        std::process::id()
    ));
    std::fs::write(
        &key_set,
        r#"{"keys":[{"kid":"test","kty":"OKP","crv":"Ed25519","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","alg":"EdDSA","use":"sig"}]}"#,
    )
    .expect("the test producer publishes a key");
    let both = both_without_trust.with_event_producer_keys([
        permguard_core::decisions::EventProducerSource {
            path: key_set.display().to_string(),
            producer: "data-plane-test".to_owned(),
            zone: "*".to_owned(),
            ledger: "*".to_owned(),
        },
    ]);
    assert!(module.startup_check(&both).is_ok());
    let _ = std::fs::remove_file(key_set);
}

/// A trust source that is not published yet is a plane still coming up, not a misconfiguration.
///
/// # What this is actually about
///
/// The producer writes its own public keys, on the cadence its ring rotates, into a volume both
/// planes see. On a clean volume nobody has written them yet, so an all-in-one — or a control plane
/// scheduled before its data plane — would refuse to boot over a file that was about to exist. That
/// turns a deployment which converges in seconds into one that never starts.
///
/// Waiting loosens nothing, because ingest is fail-closed per batch: a producer whose keys this
/// plane does not hold has its batches refused as unattributable either way. So absence waits, and
/// everything an operator could mistake for a trust source that is *in force* — a file that exists
/// but cannot be parsed, or one that carries no key — still stops the process.
#[test]
fn an_unpublished_producer_key_set_waits_while_a_broken_one_refuses() {
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

    let bound = |path: &std::path::Path| {
        base.clone()
            .with_event_producer_keys([permguard_core::decisions::EventProducerSource {
                path: path.display().to_string(),
                producer: "data-plane-test".to_owned(),
                zone: "*".to_owned(),
                ledger: "*".to_owned(),
            }])
    };

    let directory =
        std::env::temp_dir().join(format!("permguard-producer-pending-{}", std::process::id()));
    std::fs::create_dir_all(&directory).expect("the test volume exists");

    // Not written yet: the plane starts and says so.
    let unpublished = directory.join("data-plane-events.jwks");
    assert!(
        module.startup_check(&bound(&unpublished)).is_ok(),
        "a producer that has not published yet must not stop the receiver from starting"
    );

    // Written, and empty of keys: an operator believes this is in force, and it is not.
    let empty = directory.join("empty.jwks");
    std::fs::write(&empty, r#"{"keys":[]}"#).expect("the empty set is written");
    let refused = module
        .startup_check(&bound(&empty))
        .expect_err("a published but keyless trust source does not start");
    assert!(
        refused.to_string().contains("publishes no keys"),
        "{refused}"
    );

    // Written, and not a key set at all.
    let broken = directory.join("broken.jwks");
    std::fs::write(&broken, "not json").expect("the broken set is written");
    let refused = module
        .startup_check(&bound(&broken))
        .expect_err("a published but unreadable trust source does not start");
    assert!(
        refused.to_string().contains("data-plane-test"),
        "the refusal names the producer: {refused}"
    );

    let _ = std::fs::remove_dir_all(&directory);
}
