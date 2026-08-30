// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The configurations the server refuses to start with.
//!
//! Every case here is a deployment that would have worked — served requests, answered probes, looked
//! healthy — while being wrong in a way nobody would have noticed until it mattered. That is exactly
//! the class of mistake a startup check is for, and the class most worth having tests for: a
//! validation rule that stops being enforced fails silently by definition.

use permguard_core::config::*;
use permguard_core::{BuildSettings, Config};

/// The extra-settings layer of a build that declares none.
const NO_DECLARED: [&str; 0] = [];

/// Builds a config from one layer of settings.
fn config(settings: &[(&str, &str)]) -> Config {
    Config::from_layers(
        BuildSettings::new("1.2.3", "2026", "Build Holder"),
        NO_DECLARED,
        Layers::new().with_file(
            settings
                .iter()
                .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
                .collect::<Vec<_>>(),
        ),
    )
    .expect("the layers build a config")
}

/// The least a configuration needs before any of the rules below are the reason it fails.
fn serving(extra: &[(&str, &str)]) -> Config {
    let mut settings = vec![(SETTING_PUBLIC_HTTP_ADDR, "0.0.0.0:6443")];
    settings.extend_from_slice(extra);

    config(&settings)
}

/// Returns why a configuration was refused, failing the test if it was not.
fn refusal(config: &Config) -> String {
    format!(
        "{:#}",
        config
            .validate()
            .expect_err("this configuration is refused")
    )
}

#[test]
fn test_generating_material_is_refused_to_a_deployment_that_has_not_said_it_is_a_laptop() {
    let refused = serving(&[(SETTING_AUTOGENERATE, "true")]);

    assert!(refusal(&refused).contains("development"));

    // With both, it is a decision somebody wrote down twice.
    serving(&[
        (SETTING_AUTOGENERATE, "true"),
        (SETTING_DEVELOPMENT_MODE, "true"),
    ])
    .validate()
    .expect("a development deployment may generate what it is missing");
}

#[test]
fn test_an_administrative_surface_the_world_can_reach_must_demand_a_certificate() {
    // The configuration that reads as fine and hands administration to anyone who can route to it.
    let exposed = serving(&[(SETTING_ADMIN_ADDR, "0.0.0.0:6443")]);
    let why = refusal(&exposed);

    assert!(why.contains("0.0.0.0:6443"));
    assert!(why.contains("client_ca"));
}

#[test]
fn test_the_same_surface_on_loopback_is_allowed() {
    for address in ["127.0.0.1:6443", "localhost:6443", "[::1]:6443"] {
        serving(&[(SETTING_ADMIN_ADDR, address)])
            .validate()
            .unwrap_or_else(|error| panic!("{address} was refused: {error:#}"));
    }
}

#[test]
fn test_mutual_tls_without_a_list_of_peers_is_refused_outside_development() {
    // Real files, because validation checks the material before it checks the policy and this test
    // is about the policy.
    // Unique per process and per thread: a fixed name is shared with every other run.
    let volume = std::env::temp_dir().join(format!(
        "permguard-refusals-mtls-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    std::fs::create_dir_all(volume.join("tls")).expect("the fixture directory is created");
    for name in ["server.pem", "server.key", "ca.pem"] {
        std::fs::write(volume.join("tls").join(name), "placeholder")
            .expect("the fixture is written");
    }
    let volume = volume.to_str().expect("a UTF-8 path");

    let mutual = [
        (SETTING_WORKING_DIR, volume),
        (SETTING_ADMIN_ADDR, "0.0.0.0:6443"),
        (SETTING_ADMIN_TLS_CERT, "tls/server.pem"),
        (SETTING_ADMIN_TLS_KEY, "tls/server.key"),
        (SETTING_ADMIN_TLS_CLIENT_CA, "tls/ca.pem"),
    ];

    // Mutual TLS answers "who is this". It does not answer "may they", and a deployment that
    // believes otherwise has granted administration to every client its authority ever signed.
    let why = refusal(&serving(&mutual));
    assert!(why.contains("admin.allow"), "{why}");

    let mut listed = mutual.to_vec();
    listed.push((SETTING_ADMIN_ALLOW, "cn:local-operator"));
    serving(&listed)
        .validate()
        .expect("naming a peer is what the rule asked for");

    // Saying this is a laptop is the other way to satisfy it, and it is the only other way.
    let mut development = mutual.to_vec();
    development.push((SETTING_DEVELOPMENT_MODE, "true"));
    serving(&development)
        .validate()
        .expect("a development deployment may admit whatever its own authority signed");
}

#[test]
fn test_a_list_of_peers_is_read_one_entry_per_line() {
    let listed = serving(&[(
        SETTING_ADMIN_ALLOW,
        // A distinguished name contains commas, which is why lines separate the entries.
        "cn:first\ndn:CN=second,O=Permguard\n\n",
    )]);

    assert_eq!(listed.admin_allow().len(), 2);
    assert_eq!(listed.admin_allow()[0].to_string(), "cn:first");
    assert_eq!(
        listed.admin_allow()[1].to_string(),
        "dn:CN=second,O=Permguard"
    );
}

#[test]
fn test_a_peer_that_cannot_be_read_stops_the_start_rather_than_being_skipped() {
    // Silently dropping an unreadable entry would produce a shorter allowlist than the one written,
    // which is a configuration that denies people for reasons nobody can see.
    let error = Config::from_layers(
        BuildSettings::new("1.2.3", "2026", "Build Holder"),
        NO_DECLARED,
        Layers::new().with_file(vec![(
            SETTING_ADMIN_ALLOW.to_owned(),
            "sha256:nonsense".to_owned(),
        )]),
    )
    .expect_err("an unreadable entry is refused");

    assert!(format!("{error:#}").contains("64 hexadecimal"));
}

#[test]
fn test_a_key_that_would_never_get_a_turn_is_refused() {
    // Published for a day, replaced after an hour: the successor is superseded before it signs, and
    // the deployment would discover it a month later.
    let backwards = serving(&[
        (SETTING_KEYS_ENABLED, "true"),
        (SETTING_KEYS_PUBLISH_AHEAD, "1d"),
        (SETTING_KEYS_ROTATE_EVERY, "1h"),
        (SETTING_KEYS_RETAIN, "30d"),
    ]);

    assert!(refusal(&backwards).contains("never get a turn"));
}

#[test]
fn test_a_retention_shorter_than_the_rotation_is_refused() {
    // Keys replaced every thirty days and kept for one leaves twenty-nine days of signatures with no
    // published key to verify against — which is indistinguishable from forgery to whoever holds one.
    let forgetful = serving(&[
        (SETTING_KEYS_ENABLED, "true"),
        (SETTING_KEYS_PUBLISH_AHEAD, "1h"),
        (SETTING_KEYS_ROTATE_EVERY, "30d"),
        (SETTING_KEYS_RETAIN, "1d"),
    ]);

    assert!(refusal(&forgetful).contains("no published key"));
}

#[test]
fn test_an_enabled_ring_whose_lifecycle_was_never_stated_is_refused() {
    // Signing policy is security, so it must be stated, not defaulted: an operations ring turned on
    // without a lifecycle would otherwise rotate on windows nobody chose. The refusal names the first
    // knob it is missing rather than inventing one.
    let undeclared = serving(&[(SETTING_KEYS_ENABLED, "true")]);
    assert!(
        refusal(&undeclared).contains("`operations.keys.publish_ahead` is not set"),
        "{}",
        refusal(&undeclared)
    );

    // Stating two of the three is still short: each knob is required on its own.
    let partial = serving(&[
        (SETTING_KEYS_ENABLED, "true"),
        (SETTING_KEYS_PUBLISH_AHEAD, "1h"),
        (SETTING_KEYS_ROTATE_EVERY, "30d"),
    ]);
    assert!(
        refusal(&partial).contains("`operations.keys.retain` is not set"),
        "{}",
        refusal(&partial)
    );
}

#[test]
fn test_a_sound_key_lifecycle_is_accepted() {
    serving(&[
        (SETTING_KEYS_ENABLED, "true"),
        (SETTING_KEYS_PUBLISH_AHEAD, "1h"),
        (SETTING_KEYS_ROTATE_EVERY, "30d"),
        (SETTING_KEYS_RETAIN, "365d"),
    ])
    .validate()
    .expect("the defaults a deployment would write are accepted");
}

#[test]
fn test_a_revocation_list_with_nothing_to_revoke_against_is_refused() {
    // Naming a list without a client authority reads as stricter than it is: the file is configured,
    // nobody is checked against it, and the deployment believes otherwise.
    let pointless = serving(&[
        (SETTING_PUBLIC_TLS_CERT, "tls/server.pem"),
        (SETTING_PUBLIC_TLS_KEY, "tls/server.key"),
        (SETTING_PUBLIC_TLS_CRL, "tls/ca.crl"),
    ]);

    assert!(refusal(&pointless).contains("no client authority"));
}

#[test]
fn test_durations_are_read_in_the_units_a_deployment_writes_them_in() {
    let written = serving(&[
        (SETTING_KEYS_ENABLED, "true"),
        (SETTING_KEYS_PUBLISH_AHEAD, "90m"),
        (SETTING_KEYS_ROTATE_EVERY, "2d"),
        (SETTING_KEYS_RETAIN, "8760h"),
        (SETTING_AUDIT_RETENTION, "90d"),
        (SETTING_TLS_RELOAD_INTERVAL, "45"),
    ]);

    assert_eq!(written.keys_publish_ahead().as_secs(), 90 * 60);
    assert_eq!(written.keys_rotate_every().as_secs(), 2 * 86_400);
    assert_eq!(written.keys_retain().as_secs(), 8_760 * 3_600);
    assert_eq!(written.audit_retention().as_secs(), 90 * 86_400);
    // No suffix means seconds, which is what every other tool assumes.
    assert_eq!(written.tls_reload_interval().as_secs(), 45);
}

#[test]
fn test_transport_material_is_re_read_unless_a_deployment_says_otherwise() {
    let default = serving(&[
        (SETTING_PUBLIC_TLS_CERT, "tls/server.pem"),
        (SETTING_PUBLIC_TLS_KEY, "tls/server.key"),
    ]);

    // On by default: the failure mode of not reloading is a certificate that expires on a Sunday.
    assert!(default.tls_reload());
    assert!(default.public_tls().and_then(|tls| tls.reload()).is_some());

    let pinned = serving(&[
        (SETTING_PUBLIC_TLS_CERT, "tls/server.pem"),
        (SETTING_PUBLIC_TLS_KEY, "tls/server.key"),
        (SETTING_TLS_RELOAD, "false"),
    ]);

    assert!(pinned.public_tls().and_then(|tls| tls.reload()).is_none());
}

#[test]
fn test_the_volume_is_where_everything_the_configuration_names_resolves() {
    let deployed = serving(&[
        (SETTING_WORKING_DIR, "/var/lib/permguard"),
        (SETTING_KEYS_ENABLED, "true"),
        (SETTING_AUDIT_SINK, "file"),
        (SETTING_PUBLIC_TLS_CERT, "tls/server.pem"),
        (SETTING_PUBLIC_TLS_KEY, "tls/server.key"),
    ]);

    assert_eq!(
        deployed.keys_directory(),
        std::path::Path::new("/var/lib/permguard/operations/keys")
    );
    assert_eq!(
        deployed.audit_directory(),
        std::path::Path::new("/var/lib/permguard/operations/audit")
    );
    assert_eq!(
        deployed.secrets_directory(),
        std::path::Path::new("/var/lib/permguard/operations/secrets")
    );
    assert_eq!(
        deployed
            .public_tls()
            .expect("it is configured")
            .certificate(),
        std::path::Path::new("/var/lib/permguard/tls/server.pem")
    );
}
