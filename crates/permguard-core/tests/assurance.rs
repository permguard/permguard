// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The assurance framework at Bootstrap (WP-2.8): the profile a configuration states, the controls
//! it adds, the relaxations its values amount to, and what `Config::validate` refuses.

#![allow(clippy::expect_used)]

use permguard_core::assurance::{AssuranceProfile, EvidenceClass, Relaxation};
use permguard_core::config::*;
use permguard_core::{BuildSettings, Config};

fn config(settings: &[(&str, &str)]) -> Config {
    // A stated key lifecycle, so a test that enables a ring reaches the profile's judgement and
    // not the lifecycle rule, which runs first.
    let mut all = vec![
        (SETTING_PUBLIC_HTTP_ADDR, "0.0.0.0:6443"),
        (SETTING_KEYS_PUBLISH_AHEAD, "1h"),
        (SETTING_KEYS_ROTATE_EVERY, "30d"),
        (SETTING_KEYS_RETAIN, "365d"),
    ];
    all.extend_from_slice(settings);
    Config::from_layers(
        BuildSettings::new("1.2.3", "2026", "Build Holder"),
        ["PERMGUARD_DATA_HTTP_TLS_MIN_VERSION"],
        Layers::new().with_file(
            all.iter()
                .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
                .collect::<Vec<_>>(),
        ),
    )
    .expect("the layers build a config")
}

/// What `regulated` keeps the identity and operations keys in (WP-3.2): a PKCS#11 token.
const IN_A_TOKEN: &[(&str, &str)] = &[
    (SETTING_KEYS_IDENTITY_CUSTODY, "pkcs11"),
    (SETTING_KEYS_OPERATIONS_CUSTODY, "pkcs11"),
    (
        SETTING_KEYS_PKCS11_MODULE,
        "/usr/lib/softhsm/libsofthsm2.so",
    ),
    (SETTING_KEYS_PKCS11_TOKEN_LABEL, "permguard"),
    (SETTING_KEYS_PKCS11_PIN_REF, "hsm-pin"),
];

/// `settings` under `regulated`, its keys in a token.
fn regulated(settings: &[(&str, &str)]) -> Config {
    let mut all = vec![(SETTING_ASSURANCE_PROFILE, "regulated")];
    all.extend_from_slice(IN_A_TOKEN);
    all.extend_from_slice(settings);
    config(&all)
}

fn refusal(config: &Config) -> String {
    format!("{:#}", config.validate().expect_err("refused at Bootstrap"))
}

#[test]
fn a_configuration_that_states_no_profile_is_production() {
    let config = config(&[]);
    assert_eq!(config.assurance().profile(), AssuranceProfile::Production);
    config.validate().expect("nothing relaxed, nothing refused");
    let report = config.assurance().report(&config.relaxations_in_force());
    assert_eq!(report.profile, "production");
    assert_eq!(report.enforcement, "local");
    assert!(report.added_controls.is_empty() && report.relaxations.is_empty());
}

#[test]
fn the_profile_is_one_of_three_words() {
    for (word, profile) in [
        ("development", AssuranceProfile::Development),
        ("production", AssuranceProfile::Production),
        ("regulated", AssuranceProfile::Regulated),
    ] {
        assert_eq!(
            config(&[(SETTING_ASSURANCE_PROFILE, word)])
                .assurance()
                .profile(),
            profile
        );
    }
    let refused = Config::from_layers(
        BuildSettings::new("1.2.3", "2026", "Build Holder"),
        Vec::<String>::new(),
        Layers::new().with_file(vec![(
            SETTING_ASSURANCE_PROFILE.to_owned(),
            "high-assurance".to_owned(),
        )]),
    )
    .expect_err("a retired spelling is not a profile");
    assert!(format!("{refused:#}").contains("PERMGUARD_ASSURANCE_PROFILE"));
}

/// Row `TLS`: 1.2 is a published relaxation under `development` and `production`, refused under
/// `regulated` and wherever `tls.1_3_only` was added.
#[test]
fn a_tls_1_2_minimum_is_a_published_relaxation_below_regulated_and_refused_at_it() {
    for profile in ["development", "production"] {
        let relaxed = config(&[
            (SETTING_ASSURANCE_PROFILE, profile),
            ("PERMGUARD_DATA_HTTP_TLS_MIN_VERSION", "1.2"),
        ]);
        relaxed.validate().expect("permitted");
        // Under `development` the identity key is plaintext too (WP-3.2): its custody defaults
        // to `development` there.
        let (expected, published) = if profile == "development" {
            (
                vec![Relaxation::Tls12Compat, Relaxation::CustodyPlaintext],
                vec!["custody.plaintext", "tls.1_2_compat"],
            )
        } else {
            (vec![Relaxation::Tls12Compat], vec!["tls.1_2_compat"])
        };
        assert_eq!(relaxed.relaxations_in_force(), expected);
        assert_eq!(
            relaxed
                .assurance()
                .report(&relaxed.relaxations_in_force())
                .relaxations,
            published,
            "published under {profile}"
        );
    }
    let regulated = regulated(&[("PERMGUARD_DATA_HTTP_TLS_MIN_VERSION", "1.2")]);
    let why = refusal(&regulated);
    assert!(
        why.contains("tls.1_2_compat") && why.contains("tls.1_3_only"),
        "{why}"
    );

    let ratcheted = config(&[
        (SETTING_ASSURANCE_ADDED_CONTROLS, "tls.1_3_only"),
        ("PERMGUARD_DATA_HTTP_TLS_MIN_VERSION", "1.2"),
    ]);
    assert!(refusal(&ratcheted).contains("tls.1_2_compat"));
    let clean = config(&[(SETTING_ASSURANCE_ADDED_CONTROLS, "tls.1_3_only")]);
    clean.validate().expect("1.3 everywhere");
    assert_eq!(
        clean.assurance().report(&[]).added_controls,
        vec!["tls.1_3_only"]
    );
}

/// Row `private key custody`: a key ring kept in plaintext files is permitted and published under
/// `development` and refused at Bootstrap from `production` (owner decision, 2026-10-07).
#[test]
fn plaintext_key_custody_is_published_in_development_and_refused_from_production() {
    for ring in [
        SETTING_KEYS_ENABLED,
        SETTING_CONTROL_KEYS_ENABLED,
        SETTING_DATA_KEYS_ENABLED,
    ] {
        let development = config(&[(SETTING_ASSURANCE_PROFILE, "development"), (ring, "true")]);
        assert_eq!(
            development.relaxations_in_force(),
            vec![Relaxation::CustodyPlaintext],
            "{ring}"
        );
        for profile in ["production", "regulated"] {
            // Stated: outside development the custody defaults to `file` (WP-3.2).
            let why = refusal(&config(&[
                (SETTING_ASSURANCE_PROFILE, profile),
                (SETTING_KEYS_CUSTODY, "development"),
                (ring, "true"),
            ]));
            assert!(
                why.contains("custody.plaintext") && why.contains("custody.encrypted"),
                "{ring} under {profile}: {why}"
            );
        }
    }
}

/// A realm's rings are key rings too: its token ring is on by default, so a realm under
/// `production` is refused until custody providers exist (WP-3.2), and published under
/// `development`.
#[test]
fn a_realm_key_ring_is_plaintext_custody_too() {
    let realm = permguard_core::realm::RealmInput {
        name: "acme".to_owned(),
        issuer: Some("https://acme.example.com".to_owned()),
        token_keys_publish_ahead: Some("1h".to_owned()),
        token_keys_rotate_every: Some("30d".to_owned()),
        token_keys_retain: Some("400d".to_owned()),
        token_lifetime: Some("1h".to_owned()),
        ..permguard_core::realm::RealmInput::default()
    };
    let production = config(&[(SETTING_ASSURANCE_PROFILE, "production")])
        .with_realms([realm.clone()])
        .expect("the realm resolves");
    assert_eq!(
        production.relaxations_in_force(),
        vec![Relaxation::CustodyPlaintext]
    );
    assert!(refusal(&production).contains("custody.plaintext"));
    let development = config(&[(SETTING_ASSURANCE_PROFILE, "development")])
        .with_realms([realm])
        .expect("the realm resolves");
    assert_eq!(
        development
            .assurance()
            .report(&development.relaxations_in_force())
            .relaxations,
        vec!["custody.plaintext"]
    );
}

/// Row `experimental runtimes`: opted into below `regulated`, never served at it.
#[test]
fn an_experimental_runtime_is_never_opted_into_under_regulated() {
    let key = experimental_setting_key("dogwood");
    config(&[
        (SETTING_ASSURANCE_PROFILE, "production"),
        (key.as_str(), "true"),
    ])
    .validate()
    .expect("the language gate decides below regulated");
    let why = refusal(&regulated(&[(key.as_str(), "true")]));
    assert!(
        why.contains("dogwood") && why.contains("runtime.experimental_forbidden"),
        "{why}"
    );
    let ratcheted = config(&[
        (
            SETTING_ASSURANCE_ADDED_CONTROLS,
            "runtime.experimental_forbidden",
        ),
        (key.as_str(), "true"),
    ]);
    assert!(refusal(&ratcheted).contains("runtime.experimental_forbidden"));
}

/// The ratchet: a control is added by name and never removed; an unknown name is refused when the
/// configuration is read, and a control of the own profile is in force without being listed.
#[test]
fn added_controls_are_read_by_name_and_an_unknown_one_is_refused() {
    let added = config(&[
        (SETTING_ASSURANCE_PROFILE, "production"),
        (
            SETTING_ASSURANCE_ADDED_CONTROLS,
            "tls.1_3_only,\nruntime.experimental_forbidden, schema.partition",
        ),
    ]);
    assert_eq!(
        added.assurance().report(&[]).added_controls,
        vec!["runtime.experimental_forbidden", "tls.1_3_only"]
    );
    let refused = Config::from_layers(
        BuildSettings::new("1.2.3", "2026", "Build Holder"),
        Vec::<String>::new(),
        Layers::new().with_file(vec![(
            SETTING_ASSURANCE_ADDED_CONTROLS.to_owned(),
            "tls.1_2_compat".to_owned(),
        )]),
    )
    .expect_err("a relaxation is not a control, and nothing disables one");
    assert!(format!("{refused:#}").contains("not an assurance control"));
}

/// The ratchet never lists a control as in force that nothing enforces: a control this build
/// enforces only at its floor cannot be added below it.
#[test]
fn a_control_enforced_only_at_its_floor_cannot_be_added_below_it() {
    for control in [
        "custody.hsm",
        "schema.rego_input",
        "operations.dual_control",
    ] {
        let why = refusal(&config(&[
            (SETTING_ASSURANCE_PROFILE, "production"),
            (SETTING_ASSURANCE_ADDED_CONTROLS, control),
        ]));
        assert!(why.contains(control) && why.contains("regulated"), "{why}");
    }
    // At its own floor it is in force anyway, so naming it changes nothing and is accepted.
    regulated(&[(SETTING_ASSURANCE_ADDED_CONTROLS, "custody.hsm")])
        .validate()
        .expect("a control of the own profile");
    // `custody.encrypted` is enforced at Bootstrap, so a development machine may add it.
    let why = refusal(&config(&[
        (SETTING_ASSURANCE_PROFILE, "development"),
        (SETTING_ASSURANCE_ADDED_CONTROLS, "custody.encrypted"),
        (SETTING_KEYS_ENABLED, "true"),
    ]));
    assert!(why.contains("custody.plaintext"), "{why}");
}

#[test]
fn the_file_carries_the_profile_and_the_added_controls() {
    let file = permguard_core::ConfigFile::parse(
        "assurance:\n  profile: regulated\n  added_controls: [custody.hsm, tls.1_3_only]\n",
    )
    .expect("the file parses");
    let settings = file.settings();
    assert!(settings.contains(&(SETTING_ASSURANCE_PROFILE.to_owned(), "regulated".to_owned())));
    assert!(settings.contains(&(
        SETTING_ASSURANCE_ADDED_CONTROLS.to_owned(),
        "custody.hsm,tls.1_3_only".to_owned()
    )));
}

/// WP-4.2: the evidence classes are a threshold, weakest first, by their stable names.
#[test]
fn the_evidence_classes_are_ordered_weakest_first_by_their_stable_names() {
    assert!(EvidenceClass::Declared < EvidenceClass::OperatorApproved);
    assert!(EvidenceClass::OperatorApproved < EvidenceClass::Attested);
    for (class, name) in [
        (EvidenceClass::Declared, "declared"),
        (EvidenceClass::OperatorApproved, "operator-approved"),
        (EvidenceClass::Attested, "attested"),
    ] {
        assert_eq!(class.as_str(), name);
        assert_eq!(name.parse::<EvidenceClass>(), Ok(class));
    }
    assert!("approved".parse::<EvidenceClass>().is_err());
}
