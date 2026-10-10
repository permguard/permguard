// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Configuration classes (WP-2.9): every setting has a class and a value in force, the image
//! default included; an unknown `PERMGUARD_*` variable fails startup. F-27, two replicas sharing
//! one static file, is `permguard-host/tests/replicas.rs`: it claims real volumes.

#![allow(clippy::expect_used)]

use permguard_core::config::*;
use permguard_core::{BuildSettings, Config};

fn build() -> BuildSettings {
    BuildSettings::new("1.2.3", "2026", "Build Holder")
}

fn config(file: &[(&str, &str)], environment: &[(&str, &str)]) -> Config {
    let pairs = |pairs: &[(&str, &str)]| {
        pairs
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect::<Vec<_>>()
    };
    Config::from_layers(
        build(),
        ["PERMGUARD_DATA_HTTP_ADDR"],
        Layers::new()
            .with_file(pairs(file))
            .with_environment(pairs(environment)),
    )
    .expect("the layers build a config")
}

#[test]
fn every_setting_is_listed_with_its_value_in_force_and_the_default_says_so() {
    let config = config(
        &[(SETTING_SHUTDOWN_TIMEOUT, "45s")],
        &[(SETTING_LOG_LEVEL, "debug")],
    );
    let settings = config.effective_settings();
    let find = |key: &str| {
        settings
            .iter()
            .find(|setting| setting.key == key)
            .unwrap_or_else(|| panic!("{key} is listed"))
    };
    let supplied = find(SETTING_SHUTDOWN_TIMEOUT);
    assert_eq!(supplied.value.as_deref(), Some("45s"));
    assert_eq!(supplied.origin, Some(SettingOrigin::File));
    assert_eq!(
        find(SETTING_LOG_LEVEL).origin,
        Some(SettingOrigin::Environment)
    );

    // Not supplied: the image default, rendered as a configuration writes it.
    let drain = find(SETTING_SHUTDOWN_DRAIN_TIMEOUT);
    assert_eq!(drain.value.as_deref(), Some("25s"));
    assert_eq!(drain.origin, None);
    assert_eq!(
        find(SETTING_ASSURANCE_PROFILE).value.as_deref(),
        Some("production")
    );
    assert_eq!(find(SETTING_KEYS_ENABLED).value.as_deref(), Some("false"));
    // Unset with no default: listed, with no value.
    assert_eq!(find(SETTING_ADMIN_ADDR).value, None);
    // A setting the build declared and nobody supplied: listed, its default is the declaring
    // crate's.
    let declared = find("PERMGUARD_DATA_HTTP_ADDR");
    assert_eq!((declared.value.as_deref(), declared.origin), (None, None));
    assert_eq!(declared.class, SettingClass::Startup);
}

/// Under the defaults every core setting carries the value in force, except the ones whose absence
/// is itself the default: a listener, a TLS block or a key reference not configured, an empty
/// list. A rendering arm forgotten for a new setting shows up here as an unexpected absence.
#[test]
fn every_core_setting_renders_under_the_defaults() {
    let settings = Config::from_layers(build(), Vec::<String>::new(), Layers::new())
        .expect("defaults")
        .effective_settings();
    let absent: Vec<&str> = settings
        .iter()
        .filter(|setting| setting.value.is_none())
        .map(|setting| setting.key.as_str())
        .collect();
    assert_eq!(
        absent,
        vec![
            SETTING_ADMIN_ADDR,
            SETTING_ADMIN_ADVERTISED_URL,
            SETTING_ADMIN_ALLOW,
            SETTING_ADMIN_TLS_CERT,
            SETTING_ADMIN_TLS_CLIENT_CA,
            SETTING_ADMIN_TLS_CRL,
            SETTING_ADMIN_TLS_KEY,
            SETTING_ADMIN_TLS_MIN_VERSION,
            SETTING_ASSURANCE_ADDED_CONTROLS,
            SETTING_AUDIT_PSEUDONYM_KEY_REF,
            SETTING_HOST_IDENTITY_SUITE,
            SETTING_HOST_IDENTITY_WITNESS,
            SETTING_HOST_PEERS,
            SETTING_ISSUER,
            SETTING_KEYS_KEK_REF,
            SETTING_KEYS_KMS_ADDRESS,
            SETTING_KEYS_KMS_CA,
            SETTING_KEYS_KMS_TOKEN_REF,
            SETTING_KEYS_PKCS11_MODULE,
            SETTING_KEYS_PKCS11_PIN_REF,
            SETTING_KEYS_PKCS11_TOKEN_LABEL,
            SETTING_KEYS_PREVIOUS_KEK_REF,
            SETTING_KEYS_PREVIOUS_KEK_VERSION,
            SETTING_LIMITS_CONNECTION_LIFETIME,
            SETTING_LIMITS_PEER_EXEMPT,
            SETTING_MEMBERSHIP_APPRAISAL_CONTROLS,
            SETTING_MIRRORS_EXPIRE_AFTER,
            SETTING_MIRRORS_STALE_AFTER,
            SETTING_PUBLIC_GRPC_ADDR,
            SETTING_PUBLIC_HTTP_ADDR,
            SETTING_PUBLIC_TLS_ALLOW,
            SETTING_PUBLIC_TLS_CERT,
            SETTING_PUBLIC_TLS_CLIENT_CA,
            SETTING_PUBLIC_TLS_CRL,
            SETTING_PUBLIC_TLS_KEY,
            SETTING_PUBLIC_TLS_MIN_VERSION,
            SETTING_SECRETS_COORDINATOR_ROOT_REF,
            SETTING_TELEMETRY_ADDR,
            SETTING_TELEMETRY_ADVERTISED_URL,
            SETTING_TELEMETRY_TLS_CERT,
            SETTING_TELEMETRY_TLS_KEY,
            SETTING_TELEMETRY_TLS_MIN_VERSION,
        ]
    );
    assert!(settings.iter().all(|setting| setting.origin.is_none()));
}

#[test]
fn binds_volume_paths_tls_bootstrap_references_and_instance_ids_are_startup_settings() {
    for key in [
        SETTING_WORKING_DIR,
        SETTING_PUBLIC_HTTP_ADDR,
        SETTING_ADMIN_ADDR,
        SETTING_AUDIT_DIRECTORY,
        SETTING_ADMIN_TLS_CERT,
        SETTING_AUDIT_PSEUDONYM_KEY_REF,
        SETTING_LOG_PDP_ID,
        SETTING_EVENTS_PRODUCER_ID,
        "PERMGUARD_CONTROL_HTTP_ADDR",
        "PERMGUARD_DATA_GRPC_TLS_KEY",
    ] {
        assert_eq!(setting_class(key), SettingClass::Startup, "{key}");
    }
    for key in [
        SETTING_ASSURANCE_PROFILE,
        SETTING_SHUTDOWN_TIMEOUT,
        SETTING_AUDIT_RETENTION,
        SETTING_KEYS_ROTATE_EVERY,
        "PERMGUARD_RUNTIME_PLANES",
    ] {
        assert_eq!(setting_class(key), SettingClass::Static, "{key}");
    }
}

#[test]
fn an_unknown_permguard_variable_fails_startup_by_name_and_build_variables_pass() {
    let config = config(&[], &[]);
    config
        .check_environment([
            "PATH",
            SETTING_LOG_LEVEL,
            "PERMGUARD_DATA_HTTP_ADDR",
            "PERMGUARD_BUILD_COMMIT",
            "PERMGUARD_COPYRIGHT_YEAR",
            "PERMGUARD_EXPERIMENTAL_SOMETHING_ENABLED",
        ])
        .expect("settings, declared settings, build variables and experimental switches pass");
    let refused = config
        .check_environment(["PERMGUARD_SHUTDOWN_TIMOUT"])
        .expect_err("a typo");
    assert!(
        format!("{refused}").contains("PERMGUARD_SHUTDOWN_TIMOUT"),
        "{refused}"
    );
}

/// The `environment` secret provider resolves `<prefix>_<NAME>`: the server's prefix and every
/// realm's pass the check, a name that only resembles one does not.
#[test]
fn the_secret_provider_variables_pass_under_the_server_and_realm_prefixes() {
    let realm = permguard_core::realm::RealmInput {
        name: "acme".to_owned(),
        issuer: Some("https://acme.example.com".to_owned()),
        secrets_env_prefix: Some("PERMGUARD_TENANT_ACME".to_owned()),
        token_keys_publish_ahead: Some("1h".to_owned()),
        token_keys_rotate_every: Some("30d".to_owned()),
        token_keys_retain: Some("400d".to_owned()),
        token_lifetime: Some("1h".to_owned()),
        ..permguard_core::realm::RealmInput::default()
    };
    let config = config(&[], &[])
        .with_realms([realm])
        .expect("the realm resolves");
    config
        .check_environment([
            "PERMGUARD_SECRET_AUDIT_PSEUDONYM",
            "PERMGUARD_TENANT_ACME_SIGNING",
        ])
        .expect("the server's and the realm's secret variables");
    for typo in ["PERMGUARD_SECRETX", "PERMGUARD_TENANT_ACMEX"] {
        let refused = config.check_environment([typo]).expect_err(typo);
        assert!(format!("{refused}").contains(typo), "{refused}");
    }
}

/// An experimental switch is a setting the build reads: listed with its value and origin.
#[test]
fn an_experimental_switch_is_listed_with_its_origin() {
    let key = experimental_setting_key("cedar-next");
    let config = config(&[], &[(key.as_str(), "true")]);
    let listed = config
        .effective_settings()
        .into_iter()
        .find(|setting| setting.key == key)
        .expect("listed");
    assert_eq!(listed.value.as_deref(), Some("true"));
    assert_eq!(listed.origin, Some(SettingOrigin::Environment));
    assert_eq!(listed.class, SettingClass::Static);
}
