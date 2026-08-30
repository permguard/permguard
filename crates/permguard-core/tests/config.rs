// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! How the configuration layers resolve, driven from outside the crate.
//!
//! Here rather than beside the code because precedence is the kind of thing that needs a table of
//! cases to be convincing: five layers, each overwriting only what it actually declares. Every case
//! is three lines, and there are thirty of them.

use std::time::Duration;

use permguard_core::config::*;
use permguard_core::{
    BuildSettings, ClaimMapping, Config, EXCHANGE_ON_UNMATCHED_SCOPE_REJECT,
    EXCHANGE_SOURCE_FORMAT_JWT, EXCHANGE_SOURCE_OAUTH_ACCESS_TOKEN, ExchangeProfileClaims,
    ExchangeProfileConfig, ExchangeProfilePrivileges, ExchangeProfileSource,
    ExchangeTokenValidation, LogFormat, LogLevel, PrivilegeEmit, PrivilegeRule, RealmInput,
    TlsVersion, TokenInitialExpiryPolicy, TrustedAttesterConfig,
};

/// The extra-settings layer of a build that declares none.
const NO_DECLARED: [&str; 0] = [];
const CONTROL_HTTP_ADDR: &str = "PERMGUARD_CONTROL_HTTP_ADDR";
const CONTROL_HTTP_ENABLED: &str = "PERMGUARD_CONTROL_HTTP_ENABLED";

fn pairs(entries: &[(&str, &str)]) -> Vec<(String, String)> {
    entries
        .iter()
        .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
        .collect()
}

fn build_settings() -> BuildSettings {
    BuildSettings::new("1.2.3", "2026", "Build Holder")
}

/// Builds a config from the three input layers, failing the test on an unreadable value.
///
/// The parameters are in precedence order — file, then environment, then command line — so a call
/// reads the same way the layers apply.
fn config(file: &[(&str, &str)], env: &[(&str, &str)], cli: &[(&str, &str)]) -> Config {
    Config::from_layers(
        build_settings(),
        NO_DECLARED,
        Layers::new()
            .with_file(pairs(file))
            .with_environment(pairs(env))
            .with_command_line(pairs(cli)),
    )
    .expect("the layers build a config")
}

/// Builds a config for a build that declares extra setting keys.
fn declaring(
    declared: &[&str],
    file: &[(&str, &str)],
    env: &[(&str, &str)],
    cli: &[(&str, &str)],
) -> Config {
    Config::from_layers(
        build_settings(),
        declared.to_vec(),
        Layers::new()
            .with_file(pairs(file))
            .with_environment(pairs(env))
            .with_command_line(pairs(cli)),
    )
    .expect("the layers build a config")
}

fn servable() -> Config {
    config(&[(SETTING_PUBLIC_HTTP_ADDR, "0.0.0.0:5556")], &[], &[])
}

#[test]
fn test_from_layers_uses_build_metadata_after_defaults() {
    let config = config(&[], &[], &[]);

    assert_eq!(config.version(), "1.2.3");
    assert_eq!(config.copyright_year(), "2026");
    assert_eq!(config.copyright_holder(), "Build Holder");
}

#[test]
fn test_absent_values_do_not_overwrite_existing_values() {
    let config = config(&[], &[(SETTING_COPYRIGHT_HOLDER, "Env Holder")], &[]);

    assert_eq!(config.version(), "1.2.3");
    assert_eq!(config.copyright_year(), "2026");
    assert_eq!(config.copyright_holder(), "Env Holder");
}

#[test]
fn test_layers_are_applied_in_default_build_file_environment_cli_order() {
    // One setting declared by every layer at once, so the winner names the order outright. The build
    // metadata supplies the version, and each layer after it overwrites what the one before said.
    let every_layer = config(
        &[(SETTING_VERSION, "from-the-file")],
        &[(SETTING_VERSION, "from-the-environment")],
        &[(SETTING_VERSION, "from-the-command-line")],
    );
    assert_eq!(every_layer.version(), "from-the-command-line");

    // Take the last layer away, and the one before it wins — down to the build metadata.
    let without_cli = config(
        &[(SETTING_VERSION, "from-the-file")],
        &[(SETTING_VERSION, "from-the-environment")],
        &[],
    );
    assert_eq!(without_cli.version(), "from-the-environment");

    let file_only = config(&[(SETTING_VERSION, "from-the-file")], &[], &[]);
    assert_eq!(file_only.version(), "from-the-file");

    let nothing = config(&[], &[], &[]);
    assert_eq!(
        nothing.version(),
        "1.2.3",
        "the build metadata is the floor"
    );
}

#[test]
fn test_the_environment_overwrites_the_file_and_is_overwritten_by_the_command_line() {
    // The rule that matters in practice: a file travels with the build — baked into an image, copied
    // between environments — and the environment is set by whoever is running this instance. When
    // they disagree, the one that knows something the other could not is the environment.
    let config = config(
        &[
            (SETTING_VERSION, "file-version"),
            (SETTING_COPYRIGHT_HOLDER, "File Holder"),
        ],
        &[(SETTING_VERSION, "env-version")],
        &[(SETTING_COPYRIGHT_HOLDER, "CLI Holder")],
    );

    assert_eq!(config.version(), "env-version");
    assert_eq!(config.copyright_year(), "2026");
    assert_eq!(config.copyright_holder(), "CLI Holder");
}

#[test]
fn test_unknown_inputs_do_not_change_typed_config() {
    let with_noise = config(
        &[("unknown", "file")],
        &[("PATH", "/usr/bin")],
        &[("other", "cli")],
    );
    let without = config(&[], &[], &[]);

    assert_eq!(with_noise.version(), without.version());
    assert_eq!(with_noise.copyright_holder(), without.copyright_holder());
    assert_eq!(with_noise.public_http_addr(), without.public_http_addr());
    assert_eq!(with_noise.admin_addr(), without.admin_addr());
    assert_eq!(with_noise.log_level(), without.log_level());
    assert_eq!(with_noise.log_format(), without.log_format());
}

#[test]
fn test_a_registered_section_reads_back_as_its_own_type() {
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    struct Feature {
        enabled: bool,
    }

    impl permguard_core::ConfigSection for Feature {
        const NAME: &'static str = "feature";
    }

    let plain = config(&[], &[], &[]);
    assert!(plain.section::<Feature>().is_none());

    let with_section = plain.with_section(Feature { enabled: true });
    assert!(
        with_section
            .section::<Feature>()
            .expect("the section is kept")
            .enabled
    );
    assert_eq!(
        with_section.section_names().collect::<Vec<_>>(),
        vec!["feature"]
    );
}

#[test]
fn test_listen_addresses_have_no_built_in_default() {
    let config = config(&[], &[], &[]);

    assert_eq!(config.public_http_addr(), None);
    assert_eq!(config.telemetry_addr(), None);
    assert_eq!(config.admin_addr(), None);
}

#[test]
fn test_command_line_addresses_override_the_configuration_file() {
    let config = config(
        &[
            (SETTING_PUBLIC_HTTP_ADDR, "0.0.0.0:5556"),
            (SETTING_PUBLIC_GRPC_ADDR, "0.0.0.0:5556"),
            (SETTING_ADMIN_ADDR, "127.0.0.1:5557"),
        ],
        &[],
        &[
            (SETTING_PUBLIC_HTTP_ADDR, "127.0.0.1:9999"),
            (SETTING_PUBLIC_GRPC_ADDR, "127.0.0.1:9998"),
        ],
    );

    assert_eq!(config.public_http_addr(), Some("127.0.0.1:9999"));
    assert_eq!(config.public_grpc_addr(), Some("127.0.0.1:9998"));
    assert_eq!(config.admin_addr(), Some("127.0.0.1:5557"));
}

#[test]
fn test_public_http_and_grpc_can_be_served_independently() {
    let split = config(
        &[
            (SETTING_PUBLIC_HTTP_ADDR, "0.0.0.0:5556"),
            (SETTING_PUBLIC_GRPC_ADDR, "0.0.0.0:5557"),
        ],
        &[],
        &[],
    );

    assert_eq!(split.public_http_addr(), Some("0.0.0.0:5556"));
    assert_eq!(split.public_grpc_addr(), Some("0.0.0.0:5557"));
    assert!(split.validate().is_ok());

    let grpc_only = config(
        &[
            (SETTING_PUBLIC_HTTP_ENABLED, "false"),
            (SETTING_PUBLIC_GRPC_ADDR, "0.0.0.0:5557"),
        ],
        &[],
        &[],
    );

    assert_eq!(grpc_only.public_http_addr(), None);
    assert_eq!(grpc_only.public_grpc_addr(), Some("0.0.0.0:5557"));
    assert!(grpc_only.validate().is_ok());
}

#[test]
fn test_validate_accepts_a_config_with_a_public_address() {
    assert!(servable().validate().is_ok());
}

#[test]
fn test_validate_rejects_a_config_with_no_public_address() {
    let config = config(&[(SETTING_ADMIN_ADDR, "127.0.0.1:5557")], &[], &[]);

    let error = config.validate().expect_err("no public address is invalid");
    assert!(format!("{error}").contains("public listen address"));
}

#[test]
fn test_validate_accepts_a_declared_plane_address() {
    let config = declaring(
        &[CONTROL_HTTP_ADDR],
        &[(CONTROL_HTTP_ADDR, "127.0.0.1:6443")],
        &[],
        &[],
    );

    config.validate().expect("the plane address is servable");
}

#[test]
fn test_validate_rejects_a_disabled_declared_plane_address() {
    let config = declaring(
        &[CONTROL_HTTP_ENABLED, CONTROL_HTTP_ADDR],
        &[
            (CONTROL_HTTP_ENABLED, "false"),
            (CONTROL_HTTP_ADDR, "127.0.0.1:6443"),
        ],
        &[],
        &[],
    );

    assert!(config.validate().is_err());
}

#[test]
fn test_the_public_surface_has_one_address_and_tls_is_a_property_of_it() {
    // There is no second address for "the same surface, but encrypted": whether it is HTTP or HTTPS
    // is decided by `public.tls`. A surface that accepted an https address and never bound it would be
    // a configuration that looks served and is not.
    let plain = config(&[(SETTING_PUBLIC_HTTP_ADDR, "0.0.0.0:5556")], &[], &[]);
    assert!(plain.validate().is_ok());
    assert!(plain.public_tls().is_none());

    let secured = config(
        &[
            (SETTING_PUBLIC_HTTP_ADDR, "0.0.0.0:5556"),
            (SETTING_PUBLIC_TLS_CERT, "/nonexistent/server.pem"),
            (SETTING_PUBLIC_TLS_KEY, "/nonexistent/server.key"),
        ],
        &[],
        &[],
    );
    assert_eq!(secured.public_http_addr(), Some("0.0.0.0:5556"));
    assert!(secured.public_tls().is_some());
}

#[test]
fn test_validate_rejects_a_blank_declared_address() {
    let config = config(
        &[
            (SETTING_PUBLIC_HTTP_ADDR, "0.0.0.0:5556"),
            (SETTING_ADMIN_ADDR, "   "),
        ],
        &[],
        &[],
    );

    let error = config.validate().expect_err("a blank address is invalid");
    assert!(format!("{error}").contains("admin"));
}

#[test]
fn test_the_shutdown_budget_defaults_to_what_kubernetes_gives_a_pod() {
    assert_eq!(
        config(&[], &[], &[]).shutdown_timeout(),
        Duration::from_secs(30)
    );
}

#[test]
fn test_a_shutdown_budget_is_read_in_seconds_minutes_or_hours() {
    let cases = [("45", 45), ("45s", 45), ("2m", 120), ("1h", 3600)];

    for (written, seconds) in cases {
        assert_eq!(
            config(&[(SETTING_SHUTDOWN_TIMEOUT, written)], &[], &[]).shutdown_timeout(),
            Duration::from_secs(seconds),
            "reading {written}"
        );
    }
}

#[test]
fn test_an_unreadable_shutdown_budget_is_an_error() {
    // The empty string is absent, not unreadable: that case is covered above.
    for written in ["soon", "0", "-5", "   "] {
        assert!(
            Config::from_layers(
                build_settings(),
                NO_DECLARED,
                Layers::new()
                    .with_file(pairs(&[(SETTING_SHUTDOWN_TIMEOUT, written)]))
                    .with_environment(pairs(&[]))
                    .with_command_line(pairs(&[])),
            )
            .is_err(),
            "`{written}` should not be a budget"
        );
    }
}

#[test]
fn test_without_an_issuer_a_public_url_is_the_path_itself() {
    let config = config(&[], &[], &[]);

    assert!(config.issuer().is_none());
    assert_eq!(
        config.public_url("/.well-known/jwks.json"),
        "/.well-known/jwks.json"
    );
    assert_eq!(config.public_path_prefix(), "");
}

#[test]
fn test_an_issuer_makes_public_urls_absolute() {
    let config = config(
        &[(SETTING_ISSUER, "https://login.example.com/permguard")],
        &[],
        &[],
    );

    assert_eq!(
        config.public_url("/.well-known/jwks.json"),
        "https://login.example.com/permguard/.well-known/jwks.json"
    );
}

#[test]
fn test_a_trailing_slash_on_the_issuer_never_doubles_up() {
    let config = config(&[(SETTING_ISSUER, "https://login.example.com/")], &[], &[]);

    assert_eq!(
        config.public_url("/.well-known/jwks.json"),
        "https://login.example.com/.well-known/jwks.json"
    );
}

#[test]
fn test_an_issuer_that_offers_no_protection_is_refused() {
    // The issuer is a public identity clients fetch keys from — RFC 8414 requires https — so a
    // plaintext one is refused outside development, and loopback is not an exception: nobody
    // advertises a loopback issuer to real clients.
    for plaintext in ["http://login.example.com", "http://localhost:6443"] {
        let refused = config(
            &[
                (SETTING_PUBLIC_HTTP_ADDR, "0.0.0.0:5556"),
                (SETTING_ISSUER, plaintext),
            ],
            &[],
            &[],
        );
        let error = refused
            .validate()
            .expect_err("a plaintext issuer is refused in production");
        assert!(format!("{error}").contains("not https"), "{error}");
    }

    // Development mode is the single switch that relaxes it, the same one every other relaxation is
    // justified against — a local run over http on localhost is exactly what it is for.
    let local = config(
        &[
            (SETTING_PUBLIC_HTTP_ADDR, "0.0.0.0:5556"),
            (SETTING_ISSUER, "http://localhost:6443"),
            (SETTING_DEVELOPMENT_MODE, "true"),
        ],
        &[],
        &[],
    );
    assert!(local.validate().is_ok(), "development mode permits http");
}

#[test]
fn test_a_realm_issuer_is_held_to_the_same_https_rule_as_the_server() {
    // A realm's own issuer is a public identity too, so a plaintext one is refused in production —
    // the check reaches each realm, not only the deployment's public URL.
    let refused = servable()
        .with_realms([RealmInput {
            name: "acme".to_owned(),
            issuer: Some("http://acme.example.com".to_owned()),
            token_keys_publish_ahead: Some("1h".to_owned()),
            token_keys_rotate_every: Some("30d".to_owned()),
            token_keys_retain: Some("400d".to_owned()),
            token_lifetime: Some("1h".to_owned()),
            ..RealmInput::default()
        }])
        .expect("the realm resolves");
    let error = refused
        .validate()
        .expect_err("a plaintext realm issuer is refused");
    let error = format!("{error}");
    assert!(error.contains("realm `acme`"), "{error}");
    assert!(error.contains("not https"), "{error}");
}

#[test]
fn test_a_path_prefix_has_to_look_like_a_path() {
    let config = config(
        &[
            (SETTING_PUBLIC_HTTP_ADDR, "0.0.0.0:5556"),
            (SETTING_PUBLIC_PATH_PREFIX, "permguard"),
        ],
        &[],
        &[],
    );

    let error = config.validate().expect_err("a prefix without a slash");
    assert!(format!("{error}").contains("does not start with a slash"));
}

#[test]
fn test_an_empty_value_means_the_setting_was_never_supplied() {
    // How a Taskfile or a container manifest expresses "not this time" for an optional setting.
    let config = config(
        &[],
        &[
            (SETTING_PUBLIC_TLS_CERT, ""),
            (SETTING_PUBLIC_TLS_KEY, ""),
            (SETTING_LOG_LEVEL, ""),
        ],
        &[],
    );

    assert!(config.public_tls().is_none());
    assert_eq!(config.log_level(), LogLevel::Info, "the default survives");
}

#[test]
fn test_whitespace_is_not_empty_because_it_is_a_typo() {
    let config = config(
        &[
            (SETTING_PUBLIC_HTTP_ADDR, "0.0.0.0:5556"),
            (SETTING_ADMIN_ADDR, "   "),
        ],
        &[],
        &[],
    );

    assert!(
        config.validate().is_err(),
        "a blank address should be reported, not quietly dropped"
    );
}

#[test]
fn test_a_surface_without_tls_settings_serves_in_the_clear() {
    let config = config(&[], &[], &[]);

    assert!(config.public_tls().is_none());
    assert!(config.admin_tls().is_none());
    assert!(config.telemetry_tls().is_none());
}

#[test]
fn test_tls_material_is_read_per_surface_and_defaults_to_the_modern_floor() {
    let config = config(
        &[
            (SETTING_PUBLIC_TLS_CERT, "/tls/public.pem"),
            (SETTING_PUBLIC_TLS_KEY, "/tls/public.key"),
            (SETTING_ADMIN_TLS_CERT, "/tls/admin.pem"),
            (SETTING_ADMIN_TLS_KEY, "/tls/admin.key"),
            (SETTING_ADMIN_TLS_CLIENT_CA, "/tls/clients.pem"),
        ],
        &[],
        &[],
    );

    let public = config
        .public_tls()
        .expect("the public surface has material");
    assert_eq!(
        public.certificate(),
        std::path::Path::new("/tls/public.pem")
    );
    assert_eq!(public.min_version(), TlsVersion::V1_3);
    assert!(!public.is_mutual());

    let admin = config.admin_tls().expect("the admin surface has material");
    assert!(admin.is_mutual(), "a client CA is what makes it mutual");
}

#[test]
fn test_a_certificate_without_its_key_is_refused_rather_than_ignored() {
    let only_cert = Config::from_layers(
        build_settings(),
        NO_DECLARED,
        Layers::new()
            .with_file(pairs(&[(SETTING_PUBLIC_TLS_CERT, "/tls/public.pem")]))
            .with_environment(pairs(&[]))
            .with_command_line(pairs(&[])),
    );
    assert!(
        only_cert.is_err(),
        "serving in the clear here would be silent"
    );

    let only_key = Config::from_layers(
        build_settings(),
        NO_DECLARED,
        Layers::new()
            .with_file(pairs(&[(SETTING_ADMIN_TLS_KEY, "/tls/admin.key")]))
            .with_environment(pairs(&[]))
            .with_command_line(pairs(&[])),
    );
    assert!(only_key.is_err());
}

#[test]
fn test_the_protocol_floor_can_be_lowered_by_naming_it() {
    let config = config(
        &[
            (SETTING_PUBLIC_TLS_CERT, "/tls/public.pem"),
            (SETTING_PUBLIC_TLS_KEY, "/tls/public.key"),
            (SETTING_PUBLIC_TLS_MIN_VERSION, "1.2"),
        ],
        &[],
        &[],
    );

    assert_eq!(
        config
            .public_tls()
            .expect("the public surface has material")
            .min_version(),
        TlsVersion::V1_2
    );
}

#[test]
fn test_telemetry_is_offered_tls_but_never_a_client_authority() {
    let config = config(
        &[
            (SETTING_TELEMETRY_TLS_CERT, "/tls/telemetry.pem"),
            (SETTING_TELEMETRY_TLS_KEY, "/tls/telemetry.key"),
        ],
        &[],
        &[],
    );

    let telemetry = config
        .telemetry_tls()
        .expect("the telemetry surface has material");
    assert!(
        !telemetry.is_mutual(),
        "a scrape and a kubelet probe have no client identity to present"
    );
}

#[test]
fn test_material_that_names_missing_files_stops_validation() {
    let config = config(
        &[
            (SETTING_PUBLIC_HTTP_ADDR, "0.0.0.0:5556"),
            (SETTING_PUBLIC_TLS_CERT, "/nonexistent/public.pem"),
            (SETTING_PUBLIC_TLS_KEY, "/nonexistent/public.key"),
        ],
        &[],
        &[],
    );

    let error = config.validate().expect_err("the files are not there");
    assert!(format!("{error:#}").contains("/nonexistent/public.pem"));
}

#[test]
fn test_logging_defaults_to_the_production_settings() {
    let config = config(&[], &[], &[]);

    assert_eq!(config.log_level(), LogLevel::Info);
    assert_eq!(config.log_format(), LogFormat::Json);
}

#[test]
fn test_logging_settings_travel_through_the_same_layers() {
    let config = config(
        &[(SETTING_LOG_LEVEL, "warn")],
        &[
            (SETTING_LOG_LEVEL, "error"),
            (SETTING_LOG_FORMAT, "terminal"),
        ],
        &[(SETTING_LOG_LEVEL, "debug")],
    );

    assert_eq!(config.log_level(), LogLevel::Debug);
    assert_eq!(config.log_format(), LogFormat::Terminal);
}

#[test]
fn test_an_unreadable_log_level_is_an_error_not_a_silent_default() {
    let error = Config::from_layers(
        build_settings(),
        NO_DECLARED,
        Layers::new()
            .with_file(pairs(&[]))
            .with_environment(pairs(&[(SETTING_LOG_LEVEL, "verbose")]))
            .with_command_line(pairs(&[])),
    )
    .expect_err("`verbose` is not a level");

    let message = format!("{error:#}");
    assert!(message.contains(SETTING_LOG_LEVEL));
    assert!(message.contains("verbose"));
}

#[test]
fn test_an_unreadable_log_format_is_an_error_not_a_silent_default() {
    let error = Config::from_layers(
        build_settings(),
        NO_DECLARED,
        Layers::new()
            .with_file(pairs(&[(SETTING_LOG_FORMAT, "xml")]))
            .with_environment(pairs(&[]))
            .with_command_line(pairs(&[])),
    )
    .expect_err("`xml` is not a format");

    let message = format!("{error:#}");
    assert!(message.contains(SETTING_LOG_FORMAT));
    assert!(message.contains("xml"));
}

#[test]
fn test_a_declared_setting_travels_through_every_layer() {
    // A setting a build added obeys the same precedence as a typed one: no capability gets its own
    // rules about which layer wins.
    let config = declaring(
        &["PERMGUARD_SSO_ISSUER"],
        &[("PERMGUARD_SSO_ISSUER", "file")],
        &[("PERMGUARD_SSO_ISSUER", "env")],
        &[],
    );

    assert_eq!(config.setting("PERMGUARD_SSO_ISSUER"), Some("env"));
    assert_eq!(
        config.declared_settings().collect::<Vec<_>>(),
        vec!["PERMGUARD_SSO_ISSUER"]
    );
}

#[test]
fn test_an_undeclared_setting_never_reaches_the_config() {
    let config = config(&[], &[("PERMGUARD_SSO_ISSUER", "env")], &[]);

    assert_eq!(config.setting("PERMGUARD_SSO_ISSUER"), None);
}

#[test]
fn test_a_declared_setting_no_layer_supplies_stays_absent() {
    let config = declaring(&["PERMGUARD_SSO_ISSUER"], &[], &[], &[]);

    assert_eq!(config.setting("PERMGUARD_SSO_ISSUER"), None);
}

#[test]
fn test_a_deployment_with_no_realms_is_a_plain_server() {
    // The ordinary single-issuer case: nothing declared, nothing to enumerate, everything at root.
    let config = servable();

    assert!(config.realms().is_empty());
    config.validate().expect("a server with no realms is valid");
}

/// A minimal realm override: it names itself and states the token-signing lifecycle every realm must
/// (signing policy is security, never inherited from the server nor defaulted). Everything else —
/// operations keys, trail, secrets — still inherits the server.
fn realm(name: &str) -> RealmInput {
    RealmInput {
        name: name.to_owned(),
        token_keys_publish_ahead: Some("1h".to_owned()),
        token_keys_rotate_every: Some("30d".to_owned()),
        token_keys_retain: Some("400d".to_owned()),
        token_lifetime: Some("1h".to_owned()),
        ..RealmInput::default()
    }
}

fn exchange_profile() -> ExchangeProfileConfig {
    ExchangeProfileConfig {
        id: "corporate-oauth-to-pic".to_owned(),
        source: ExchangeProfileSource {
            token_type: EXCHANGE_SOURCE_OAUTH_ACCESS_TOKEN.to_owned(),
            format: EXCHANGE_SOURCE_FORMAT_JWT.to_owned(),
            issuer: "https://idp.example.com".to_owned(),
            discovery_url: None,
            audience: "permguard".to_owned(),
            validation: ExchangeTokenValidation {
                allowed_algorithms: vec!["ES256".to_owned()],
                require_expiration: true,
                require_token_type: Some("at+jwt".to_owned()),
            },
        },
        claims: ExchangeProfileClaims {
            identity_context: [
                (
                    "type".to_owned(),
                    ClaimMapping {
                        value: Some("user".to_owned()),
                        ..ClaimMapping::default()
                    },
                ),
                (
                    "id".to_owned(),
                    ClaimMapping {
                        from: Some("sub".to_owned()),
                        ..ClaimMapping::default()
                    },
                ),
            ]
            .into_iter()
            .collect(),
            scopes: ClaimMapping {
                from: Some("scope".to_owned()),
                value_type: Some("set".to_owned()),
                encoding: Some("space-delimited".to_owned()),
                ..ClaimMapping::default()
            },
        },
        privileges: ExchangeProfilePrivileges {
            source: "scopes".to_owned(),
            rules: vec![
                PrivilegeRule {
                    name: "resource-instance".to_owned(),
                    priority: 10,
                    pattern: "^(?<resourceType>[a-z][a-z0-9_-]*):(?<operation>[a-z][a-z0-9_-]*):(?<resourceId>[a-zA-Z0-9_-]+)$".to_owned(),
                    emit: PrivilegeEmit {
                        scope: "${raw}".to_owned(),
                        operation: "${operation}".to_owned(),
                        resource_type: "${resourceType}".to_owned(),
                        resource_id: "${resourceId}".to_owned(),
                    },
                },
                PrivilegeRule {
                    name: "resource-collection".to_owned(),
                    priority: 1,
                    pattern: "^(?<resourceType>[a-z][a-z0-9_-]*):(?<operation>[a-z][a-z0-9_-]*)$"
                        .to_owned(),
                    emit: PrivilegeEmit {
                        scope: "${raw}".to_owned(),
                        operation: "${operation}".to_owned(),
                        resource_type: "${resourceType}".to_owned(),
                        resource_id: "*".to_owned(),
                    },
                },
            ],
        },
        on_unmatched_scope: EXCHANGE_ON_UNMATCHED_SCOPE_REJECT.to_owned(),
    }
}

fn trusted_attester() -> TrustedAttesterConfig {
    TrustedAttesterConfig {
        id: "corporate-por-attester".to_owned(),
        issuer: "https://attestation.example.com".to_owned(),
        jwks_uri: "https://attestation.example.com/jwks.json".to_owned(),
        proof_types: vec!["sd-jwt".to_owned()],
        formats: vec!["sd-jwt".to_owned()],
    }
}

#[test]
fn test_a_realm_gets_its_own_resource_directories_under_the_volume() {
    // Isolation is on disk: a realm's keys, trail and secrets never share a directory with the
    // server's or with another realm's.
    let config = config(
        &[
            (SETTING_PUBLIC_HTTP_ADDR, "0.0.0.0:5556"),
            (SETTING_WORKING_DIR, "/var/lib/permguard"),
        ],
        &[],
        &[],
    )
    .with_realms([realm("acme")])
    .expect("the realm resolves");

    assert_eq!(
        config.realm_keys_directory("acme"),
        std::path::PathBuf::from("/var/lib/permguard/realms/acme/operations/keys")
    );
    assert_eq!(
        config.realm_audit_directory("acme"),
        std::path::PathBuf::from("/var/lib/permguard/realms/acme/operations/audit")
    );
    assert_eq!(
        config.realm_secrets_directory("acme"),
        std::path::PathBuf::from("/var/lib/permguard/realms/acme/operations/secrets")
    );
    // The realm's token-signing ring is separate, at the realm's top level.
    assert_eq!(
        config.realm_token_keys_directory("acme"),
        std::path::PathBuf::from("/var/lib/permguard/realms/acme/keys")
    );
    // And the mount path is derived, not configured.
    assert_eq!(config.realms()[0].mount_path(), "/realms/acme");
}

#[test]
fn test_a_realm_keeps_its_exchange_profiles_in_the_resolved_config() {
    let mut input = realm("acme");
    input.exchange_profiles = vec![exchange_profile()];
    let config = servable().with_realms([input]).expect("the realm resolves");

    let profiles = config.realms()[0].exchange_profiles();
    assert_eq!(profiles.len(), 1);
    assert_eq!(profiles[0].id, "corporate-oauth-to-pic");
    config
        .validate()
        .expect("a complete exchange profile is valid");
}

#[test]
fn test_invalid_exchange_profiles_are_refused() {
    let mut missing_algorithms = exchange_profile();
    missing_algorithms
        .source
        .validation
        .allowed_algorithms
        .clear();
    let mut input = realm("acme");
    input.exchange_profiles = vec![missing_algorithms];
    let config = servable().with_realms([input]).expect("the realm resolves");
    let error = config
        .validate()
        .expect_err("a profile without allowed algorithms is refused");
    assert!(format!("{error}").contains("algorithms"), "{error}");

    let mut duplicate_priorities = exchange_profile();
    duplicate_priorities.privileges.rules[1].priority = 10;
    let mut input = realm("beta");
    input.exchange_profiles = vec![duplicate_priorities];
    let config = servable().with_realms([input]).expect("the realm resolves");
    let error = config
        .validate()
        .expect_err("ambiguous rule order is refused");
    assert!(format!("{error}").contains("priority"), "{error}");
}

#[test]
fn test_a_realm_keeps_its_trusted_attesters_in_the_resolved_config() {
    let mut input = realm("acme");
    input.trusted_attesters = vec![trusted_attester()];
    let config = servable().with_realms([input]).expect("the realm resolves");

    let attesters = config.realms()[0].trusted_attesters();
    assert_eq!(attesters.len(), 1);
    assert_eq!(attesters[0].id, "corporate-por-attester");
    assert_eq!(attesters[0].formats, vec!["sd-jwt"]);
    config.validate().expect("the attester metadata is valid");
}

#[test]
fn test_invalid_trusted_attesters_are_refused() {
    let mut no_proof_types = trusted_attester();
    no_proof_types.proof_types.clear();
    let mut input = realm("acme");
    input.trusted_attesters = vec![no_proof_types];
    let config = servable().with_realms([input]).expect("the realm resolves");
    let error = config
        .validate()
        .expect_err("an attester without proof types is refused");
    assert!(format!("{error}").contains("proof types"), "{error}");

    let mut unsupported = trusted_attester();
    unsupported.formats = vec!["jwt".to_owned()];
    let mut input = realm("beta");
    input.trusted_attesters = vec![unsupported];
    let config = servable().with_realms([input]).expect("the realm resolves");
    let error = config
        .validate()
        .expect_err("an attester without sd-jwt format is refused");
    assert!(format!("{error}").contains("sd-jwt"), "{error}");
}

#[test]
fn test_a_realm_inherits_the_servers_policy_and_overrides_only_what_it_states() {
    let config = config(
        &[
            (SETTING_PUBLIC_HTTP_ADDR, "0.0.0.0:5556"),
            (SETTING_KEYS_ROTATE_EVERY, "30d"),
            (SETTING_KEYS_RETAIN, "400d"),
        ],
        &[],
        &[],
    )
    .with_realms([
        // acme overrides only its operations rotation cadence; retention must inherit the server's 400d.
        RealmInput {
            name: "acme".to_owned(),
            operations_keys_rotate_every: Some("90d".to_owned()),
            token_keys_publish_ahead: Some("1h".to_owned()),
            token_keys_rotate_every: Some("30d".to_owned()),
            token_keys_retain: Some("400d".to_owned()),
            token_lifetime: Some("1h".to_owned()),
            ..RealmInput::default()
        },
        // globex states nothing about keys, so it inherits both.
        realm("globex"),
    ])
    .expect("the realms resolve");

    let acme = &config.realms()[0];
    assert_eq!(
        acme.operations_keys_rotate_every(),
        std::time::Duration::from_secs(90 * 86_400)
    );
    assert_eq!(
        acme.operations_keys_retain(),
        std::time::Duration::from_secs(400 * 86_400)
    );

    let globex = &config.realms()[1];
    assert_eq!(
        globex.operations_keys_rotate_every(),
        std::time::Duration::from_secs(30 * 86_400)
    );
    assert_eq!(
        globex.operations_keys_retain(),
        std::time::Duration::from_secs(400 * 86_400)
    );
    assert_eq!(
        globex.key_cache_stale_for(),
        std::time::Duration::from_secs(3_600)
    );
    assert_eq!(
        globex.token_initial_expiry_policy(),
        TokenInitialExpiryPolicy::Later
    );
}

#[test]
fn test_a_realm_may_configure_the_token_initial_expiry_policy() {
    let config = servable()
        .with_realms([RealmInput {
            name: "acme".to_owned(),
            token_initial_expiry_policy: Some("oauth".to_owned()),
            token_keys_publish_ahead: Some("1h".to_owned()),
            token_keys_rotate_every: Some("30d".to_owned()),
            token_keys_retain: Some("400d".to_owned()),
            token_lifetime: Some("1h".to_owned()),
            ..RealmInput::default()
        }])
        .expect("the realm resolves");

    assert_eq!(
        config.realms()[0].token_initial_expiry_policy(),
        TokenInitialExpiryPolicy::OAuth
    );
}

#[test]
fn test_an_unknown_token_initial_expiry_policy_is_refused() {
    let error = servable()
        .with_realms([RealmInput {
            name: "acme".to_owned(),
            token_initial_expiry_policy: Some("tomorrowish".to_owned()),
            token_keys_publish_ahead: Some("1h".to_owned()),
            token_keys_rotate_every: Some("30d".to_owned()),
            token_keys_retain: Some("400d".to_owned()),
            token_lifetime: Some("1h".to_owned()),
            ..RealmInput::default()
        }])
        .expect_err("an unknown expiry policy is refused");
    assert!(
        format!("{error:#}").contains("later, pic or oauth"),
        "{error:#}"
    );
}

#[test]
fn test_a_realm_may_configure_the_upstream_key_cache_stale_window() {
    let config = servable()
        .with_realms([RealmInput {
            name: "acme".to_owned(),
            key_cache_stale_for: Some("10m".to_owned()),
            token_keys_publish_ahead: Some("1h".to_owned()),
            token_keys_rotate_every: Some("30d".to_owned()),
            token_keys_retain: Some("400d".to_owned()),
            token_lifetime: Some("1h".to_owned()),
            ..RealmInput::default()
        }])
        .expect("the realm resolves");

    assert_eq!(
        config.realms()[0].key_cache_stale_for(),
        Duration::from_secs(600)
    );
}

#[test]
fn test_a_realm_may_fail_closed_on_upstream_key_cache_refresh_failure() {
    let config = servable()
        .with_realms([RealmInput {
            name: "acme".to_owned(),
            key_cache_stale_for: Some("0s".to_owned()),
            token_keys_publish_ahead: Some("1h".to_owned()),
            token_keys_rotate_every: Some("30d".to_owned()),
            token_keys_retain: Some("400d".to_owned()),
            token_lifetime: Some("1h".to_owned()),
            ..RealmInput::default()
        }])
        .expect("the realm resolves");

    assert_eq!(config.realms()[0].key_cache_stale_for(), Duration::ZERO);
}

#[test]
fn test_a_realm_may_pseudonymise_from_the_environment_under_its_own_prefix() {
    let config = servable()
        .with_realms([RealmInput {
            name: "acme".to_owned(),
            audit_pseudonym_enabled: Some("true".to_owned()),
            audit_pseudonym_key_ref: Some("audit-pseudonym".to_owned()),
            secrets_provider: Some("environment".to_owned()),
            token_keys_publish_ahead: Some("1h".to_owned()),
            token_keys_rotate_every: Some("30d".to_owned()),
            token_keys_retain: Some("400d".to_owned()),
            token_lifetime: Some("1h".to_owned()),
            ..RealmInput::default()
        }])
        .expect("the realm resolves");

    let acme = &config.realms()[0];
    assert!(acme.audit_pseudonym_enabled());
    // The default per-realm prefix carries the realm name, so two realms cannot collide.
    assert_eq!(acme.secrets_env_prefix(), "PERMGUARD_SECRET_ACME");
    config
        .validate()
        .expect("a realm with a provider and a key ref is valid");
}

#[test]
fn test_a_realm_that_pseudonymises_without_a_provider_is_refused() {
    let config = servable()
        .with_realms([RealmInput {
            name: "acme".to_owned(),
            audit_pseudonym_enabled: Some("true".to_owned()),
            audit_pseudonym_key_ref: Some("audit-pseudonym".to_owned()),
            secrets_provider: Some("none".to_owned()),
            token_keys_publish_ahead: Some("1h".to_owned()),
            token_keys_rotate_every: Some("30d".to_owned()),
            token_keys_retain: Some("400d".to_owned()),
            token_lifetime: Some("1h".to_owned()),
            ..RealmInput::default()
        }])
        .expect("the realm resolves");

    let error = config.validate().expect_err("no provider is refused");
    assert!(format!("{error}").contains("nowhere"), "{error}");
}

#[test]
fn test_a_realm_rotation_that_would_strand_its_signatures_is_refused() {
    // The same overlap arithmetic as the server's, per realm: retain shorter than rotate.
    let config = servable()
        .with_realms([RealmInput {
            name: "acme".to_owned(),
            operations_keys_enabled: Some("true".to_owned()),
            operations_keys_rotate_every: Some("30d".to_owned()),
            operations_keys_retain: Some("1d".to_owned()),
            token_keys_publish_ahead: Some("1h".to_owned()),
            token_keys_rotate_every: Some("30d".to_owned()),
            token_keys_retain: Some("400d".to_owned()),
            token_lifetime: Some("1h".to_owned()),
            ..RealmInput::default()
        }])
        .expect("the realm resolves");

    let error = config
        .validate()
        .expect_err("a stranding lifecycle is refused");
    assert!(format!("{error}").contains("realm `acme`"), "{error}");
}

#[test]
fn test_a_token_signing_realm_that_states_no_key_lifecycle_is_refused() {
    // Signing policy is security: a realm that signs tokens (the default) must state its own token
    // ring's lifecycle. It is never inherited from the server's operations keys, and this build
    // defaults none, so a realm that names only itself is refused when it resolves.
    let error = servable()
        .with_realms([RealmInput {
            name: "acme".to_owned(),
            ..RealmInput::default()
        }])
        .expect_err("a token-signing realm with no key lifecycle is refused");
    let error = format!("{error}");
    assert!(error.contains("realm `acme`"), "{error}");
    assert!(error.contains("signs tokens"), "{error}");

    // A realm that turns its token ring off, on the other hand, needs no lifecycle.
    servable()
        .with_realms([RealmInput {
            name: "quiet".to_owned(),
            token_keys_enabled: Some("false".to_owned()),
            ..RealmInput::default()
        }])
        .expect("a realm that signs no tokens needs no token-key lifecycle");
}

#[test]
fn test_two_realms_with_the_same_name_are_refused() {
    // Which key signs, which trail records, is not a question to answer by insertion order.
    let config = servable()
        .with_realms([realm("acme"), realm("acme")])
        .expect("the realms resolve");

    let error = config
        .validate()
        .expect_err("a duplicate realm name is refused");
    assert!(format!("{error}").contains("unique"), "{error}");
}

#[test]
fn test_a_realm_name_that_could_escape_a_path_or_a_directory_is_refused() {
    for bad in ["../etc", "a/b", "ACME", "has space", "-lead", "trail-", ""] {
        let config = servable()
            .with_realms([realm(bad)])
            .expect("the realm resolves");

        assert!(
            config.validate().is_err(),
            "the realm name `{bad}` was accepted"
        );
    }
}

#[test]
fn test_listed_defaults_to_closed_and_is_opt_in() {
    // Fail-closed: a realm is enumerable only if it said so.
    let config = servable()
        .with_realms([
            realm("hidden"),
            RealmInput {
                name: "shown".to_owned(),
                listed: Some("true".to_owned()),
                token_keys_publish_ahead: Some("1h".to_owned()),
                token_keys_rotate_every: Some("30d".to_owned()),
                token_keys_retain: Some("400d".to_owned()),
                token_lifetime: Some("1h".to_owned()),
                ..RealmInput::default()
            },
        ])
        .expect("the realms resolve");

    assert!(!config.realms()[0].listed());
    assert!(config.realms()[1].listed());
}

#[test]
fn test_the_peer_bounds_are_read_from_settings() {
    let bounded = config(
        &[
            (SETTING_LIMITS_CONNECTIONS_PER_PEER, "8"),
            (SETTING_LIMITS_PEER_EXEMPT, "10.0.0.0/8, ::1"),
            (SETTING_LIMITS_CONNECTION_LIFETIME, "1h"),
            (SETTING_LIMITS_WRITE_STALL_TIMEOUT, "15s"),
        ],
        &[],
        &[],
    );
    let limits = bounded.limits();

    assert_eq!(limits.connections_per_peer(), 8);
    assert!(limits.is_peer_exempt("10.9.8.7".parse().expect("an address")));
    assert!(limits.is_peer_exempt("::1".parse().expect("an address")));
    assert!(!limits.is_peer_exempt("203.0.113.7".parse().expect("an address")));
    assert_eq!(
        limits.connection_lifetime(),
        Some(std::time::Duration::from_secs(3600))
    );
    assert_eq!(
        limits.write_stall_timeout(),
        std::time::Duration::from_secs(15)
    );
}

#[test]
fn test_zero_switches_the_per_peer_bound_and_the_lifetime_off() {
    // Zero is the documented "off" for both: a per-peer bound of zero admits everything, and a
    // lifetime of zero is no lifetime — unlike the pool limit, where zero would accept nothing and
    // is refused.
    let off = config(
        &[
            (SETTING_LIMITS_CONNECTIONS_PER_PEER, "0"),
            (SETTING_LIMITS_CONNECTION_LIFETIME, "0s"),
        ],
        &[],
        &[],
    );

    assert_eq!(off.limits().connections_per_peer(), 0);
    assert_eq!(off.limits().connection_lifetime(), None);
}

#[test]
fn test_an_exempt_entry_that_is_not_an_address_is_refused() {
    let refused = Config::from_layers(
        BuildSettings::new("1.2.3", "2022", "Testing Co."),
        Vec::<String>::new(),
        Layers {
            file: vec![(
                SETTING_LIMITS_PEER_EXEMPT.to_owned(),
                "10.0.0.0/8, not-an-address".to_owned(),
            )],
            environment: Vec::new(),
            command_line: Vec::new(),
        },
    );

    assert!(refused.is_err(), "an unreadable exemption was accepted");
}

/// A list with no identity to check it against is a list nothing can satisfy — a misconfiguration,
/// refused at startup rather than discovered as every client getting 403.
#[test]
fn test_an_allow_list_without_a_client_authority_is_refused() {
    let config = config(
        &[
            (SETTING_PUBLIC_TLS_CERT, "tls/server.pem"),
            (SETTING_PUBLIC_TLS_KEY, "tls/server.key"),
            (SETTING_PUBLIC_TLS_ALLOW, "cn:the-billing-service"),
            (SETTING_PUBLIC_HTTP_ADDR, "127.0.0.1:6443"),
        ],
        &[],
        &[],
    );

    let refused = config.validate();

    assert!(
        refused.is_err(),
        "an allow list with no client_ca was accepted"
    );
    assert!(
        format!("{:#}", refused.expect_err("refused")).contains("client certificate"),
        "the refusal does not say what is missing"
    );
}

#[test]
fn test_the_allow_list_reads_every_entry_form() {
    let config = config(
        &[
            (SETTING_PUBLIC_TLS_CERT, "tls/server.pem"),
            (SETTING_PUBLIC_TLS_KEY, "tls/server.key"),
            (SETTING_PUBLIC_TLS_CLIENT_CA, "tls/clients.pem"),
            (
                SETTING_PUBLIC_TLS_ALLOW,
                "cn:the-billing-service\ndn:CN=batch,O=Example\nsha256:0000000000000000000000000000000000000000000000000000000000000000",
            ),
        ],
        &[],
        &[],
    );
    let tls = config.public_tls().expect("the public surface has TLS");

    assert_eq!(tls.allow().len(), 3);
}

#[test]
fn test_build_disclosure_is_on_unless_switched_off() {
    let default = config(&[], &[], &[]);

    assert!(default.disclose_build());

    let hidden = config(&[(SETTING_PUBLIC_DISCLOSE_BUILD, "false")], &[], &[]);

    assert!(!hidden.disclose_build());
}

/// Explicit configuration wins; without one, the development flag decides — and the safe posture is
/// the one a deployment gets by saying nothing.
#[test]
fn test_error_detail_follows_the_deployment() {
    use permguard_core::Disclosure;

    let silent = config(&[], &[], &[]);
    assert_eq!(silent.error_detail(), Disclosure::Minimal);

    let development = config(&[(SETTING_DEVELOPMENT_MODE, "true")], &[], &[]);
    assert_eq!(development.error_detail(), Disclosure::Full);

    // Explicit beats derived, in both directions.
    let hardened_dev = config(
        &[
            (SETTING_DEVELOPMENT_MODE, "true"),
            (SETTING_PUBLIC_ERROR_DETAIL, "minimal"),
        ],
        &[],
        &[],
    );
    assert_eq!(hardened_dev.error_detail(), Disclosure::Minimal);

    let refused = Config::from_layers(
        BuildSettings::new("1.2.3", "2022", "Testing Co."),
        Vec::<String>::new(),
        Layers {
            file: vec![(
                SETTING_PUBLIC_ERROR_DETAIL.to_owned(),
                "everything".to_owned(),
            )],
            environment: Vec::new(),
            command_line: Vec::new(),
        },
    );
    assert!(refused.is_err(), "an unreadable detail level was accepted");
}

#[test]
fn test_audit_refusals_default_off_and_readable() {
    assert!(
        !config(&[], &[], &[]).audit_refusals(),
        "the default must be the quiet trail"
    );
    assert!(config(&[(SETTING_AUDIT_REFUSALS, "true")], &[], &[]).audit_refusals());
}

#[test]
fn test_mirror_freshness_bounds_parse_and_zero_means_unbounded() {
    let bounded = config(
        &[
            ("PERMGUARD_MIRRORS_STALE_AFTER", "5m"),
            ("PERMGUARD_MIRRORS_EXPIRE_AFTER", "1h"),
        ],
        &[],
        &[],
    );
    assert_eq!(
        bounded.mirrors_stale_after(),
        Some(std::time::Duration::from_secs(300))
    );
    assert_eq!(
        bounded.mirrors_expire_after(),
        Some(std::time::Duration::from_secs(3600))
    );

    let unbounded = config(
        &[
            ("PERMGUARD_MIRRORS_STALE_AFTER", "0s"),
            ("PERMGUARD_MIRRORS_EXPIRE_AFTER", "0s"),
        ],
        &[],
        &[],
    );
    assert_eq!(unbounded.mirrors_stale_after(), None, "0s is no bound");
    assert_eq!(unbounded.mirrors_expire_after(), None);
}

#[test]
fn test_a_mirror_cannot_expire_before_it_is_stale() {
    let refused = Config::from_layers(
        build_settings(),
        NO_DECLARED,
        Layers::new().with_file(pairs(&[
            ("PERMGUARD_MIRRORS_STALE_AFTER", "1h"),
            ("PERMGUARD_MIRRORS_EXPIRE_AFTER", "5m"),
        ])),
    );

    assert!(
        refused.is_err(),
        "expire_after below stale_after is a lie about the deployment"
    );
}

/// Durations are read in the units the settings are actually written in.
///
/// The `ms` case is the one that mattered: [`DEFAULT_EVENTS_GROUP_COMMIT_DELAY`] is five
/// milliseconds, and until the parser learned the suffix, that default could not be written down in
/// the file that configures it — the shipped `config.local-experimental.yml` said `5ms` and the plane
/// refused to start reading its own configuration.
#[test]
fn a_duration_is_read_in_every_unit_a_setting_is_written_in() {
    let cases: &[(&str, Duration)] = &[
        ("5ms", Duration::from_millis(5)),
        ("500MS", Duration::from_millis(500)),
        ("30s", Duration::from_secs(30)),
        ("2m", Duration::from_secs(120)),
        ("1h", Duration::from_secs(3_600)),
        ("90d", Duration::from_secs(90 * 86_400)),
        // No suffix still means seconds: the settings that predate the units keep their meaning.
        ("45", Duration::from_secs(45)),
    ];

    for (written, expected) in cases {
        let config = config(&[(SETTING_EVENTS_GROUP_COMMIT_DELAY, written)], &[], &[]);
        assert_eq!(
            config.events_group_commit_delay(),
            *expected,
            "`{written}` should read as {expected:?}"
        );
    }
}

/// The default of the sub-second setting is expressible in its own configuration format.
#[test]
fn the_group_commit_default_can_be_written_down() {
    let defaulted = config(&[], &[], &[]);
    assert_eq!(
        defaulted.events_group_commit_delay(),
        DEFAULT_EVENTS_GROUP_COMMIT_DELAY
    );

    let written = config(&[(SETTING_EVENTS_GROUP_COMMIT_DELAY, "5ms")], &[], &[]);
    assert_eq!(
        written.events_group_commit_delay(),
        DEFAULT_EVENTS_GROUP_COMMIT_DELAY,
        "writing the default explicitly must mean the same as leaving it out"
    );
}

/// `ms` is tested before `s`, so a millisecond value is never read as a broken second value.
#[test]
fn a_millisecond_value_is_not_mistaken_for_a_malformed_second_value() {
    let refused = Config::from_layers(
        build_settings(),
        NO_DECLARED,
        Layers::new().with_file(pairs(&[(SETTING_EVENTS_GROUP_COMMIT_DELAY, "5xs")])),
    )
    .expect_err("`5xs` is not a duration");
    let message = format!("{refused:#}");
    assert!(
        message.contains("5ms"),
        "the refusal names the units it accepts: {message}"
    );
}

/// Event producers are their own identity-bound trust policy, never an unbound fallback.
///
/// `controlPlane.events.producer_keys` was a field the configuration file accepted and nothing
/// read: an operator who narrowed the event producers got a plane that went on accepting every
/// decision producer, and nothing said so.
#[test]
fn the_event_producers_are_named_in_their_own_right() {
    let events = permguard_core::decisions::EventProducerSource {
        path: "events.jwks".to_owned(),
        producer: "plane-a".to_owned(),
        zone: "acme".to_owned(),
        ledger: "main".to_owned(),
    };
    let both = config(&[], &[], &[])
        .with_decision_producer_keys(["decisions.jwks".to_owned()])
        .with_event_producer_keys([events.clone()]);
    assert_eq!(both.event_producer_keys(), [events]);
    assert_eq!(both.decision_producer_keys(), ["decisions.jwks"]);
    assert!(both.event_producer_keys_declared());

    // An event signature proves bytes, not authorization to claim a producer or tenant. The
    // decision key list has no such bindings and therefore cannot stand in.
    let inherited =
        config(&[], &[], &[]).with_decision_producer_keys(["decisions.jwks".to_owned()]);
    assert!(inherited.event_producer_keys().is_empty());
    assert!(
        !inherited.event_producer_keys_declared(),
        "and the deployment can tell the fallback from a choice"
    );

    // Neither: nothing is accepted, which is what fail-closed means here.
    let neither = config(&[], &[], &[]);
    assert!(neither.event_producer_keys().is_empty());
}
