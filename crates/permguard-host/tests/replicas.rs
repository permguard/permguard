// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! F-27 (WP-2.9): two fresh replicas share one byte-identical static file and differ only through
//! their volume and bootstrap. Every setting whose value differs between them is a `startup`
//! setting (the directories derived from the working directory among them), and each claims a
//! volume with an identity of its own.

#![allow(clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::PathBuf;

use permguard_core::config::{Layers, SETTING_LOG_PDP_ID, SETTING_WORKING_DIR, SettingClass};
use permguard_core::{BuildSettings, Config, ConfigFile};
use permguard_host::storage::volume::Volume;

/// The one file every replica mounts.
const STATIC_FILE: &str = "\
assurance:
  profile: development
log:
  level: info
shutdown:
  timeout: 40s
  drain_timeout: 30s
operations:
  audit:
    retention: 90d
";

/// A setting a Plane crate declares, supplied per replica the way an orchestrator does.
const DECLARED: &str = "PERMGUARD_DATA_HTTP_ADDR";

fn replica(name: &str, port: u16) -> (PathBuf, Config) {
    let volume =
        std::env::temp_dir().join(format!("permguard-host-f27-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&volume);
    let file = ConfigFile::parse(STATIC_FILE).expect("the shared file parses");
    let config = Config::from_layers(
        BuildSettings::new("1.2.3", "2026", "Build Holder"),
        [DECLARED],
        Layers::new()
            .with_file(file.settings())
            .with_environment(vec![
                (
                    SETTING_WORKING_DIR.to_owned(),
                    volume.to_string_lossy().into_owned(),
                ),
                (DECLARED.to_owned(), format!("127.0.0.1:{port}")),
                (SETTING_LOG_PDP_ID.to_owned(), format!("pdp-{name}")),
            ]),
    )
    .expect("the replica's configuration builds");
    config.validate().expect("the replica validates");
    (volume, config)
}

fn settings(config: &Config) -> BTreeMap<String, (Option<String>, SettingClass)> {
    config
        .effective_settings()
        .into_iter()
        .map(|setting| (setting.key, (setting.value, setting.class)))
        .collect()
}

#[test]
fn f27_two_replicas_share_one_static_file_and_differ_only_in_startup_settings() {
    let (volume_a, a) = replica("a", 7443);
    let (volume_b, b) = replica("b", 7444);
    let (listed_a, listed_b) = (settings(&a), settings(&b));
    assert_eq!(
        listed_a.keys().collect::<Vec<_>>(),
        listed_b.keys().collect::<Vec<_>>(),
        "one build, one list of settings"
    );

    let differing: Vec<&String> = listed_a
        .iter()
        .filter(|(key, (value, _))| listed_b[*key].0 != *value)
        .map(|(key, _)| key)
        .collect();
    for key in [DECLARED, SETTING_LOG_PDP_ID, SETTING_WORKING_DIR] {
        assert!(
            differing.iter().any(|differs| *differs == key),
            "{key} is supplied per replica"
        );
    }
    for key in differing {
        assert_eq!(
            listed_a[key].1,
            SettingClass::Startup,
            "`{key}` differs between replicas and is not a startup setting"
        );
    }
    // The shared file is in force identically on both.
    for key in ["PERMGUARD_SHUTDOWN_TIMEOUT", "PERMGUARD_AUDIT_RETENTION"] {
        assert_eq!(listed_a[key], listed_b[key], "{key}");
        assert_eq!(listed_a[key].1, SettingClass::Static, "{key}");
    }

    // Bootstrap: each replica claims its own fresh volume, each with an identity of its own.
    let claimed_a = Volume::claim(a.working_dir(), a.assurance().profile()).expect("a claims");
    let claimed_b = Volume::claim(b.working_dir(), b.assurance().profile()).expect("b claims");
    assert_ne!(
        claimed_a.id(),
        claimed_b.id(),
        "two volumes, two identities"
    );
    drop((claimed_a, claimed_b));
    let _ = std::fs::remove_dir_all(volume_a);
    let _ = std::fs::remove_dir_all(volume_b);
}
