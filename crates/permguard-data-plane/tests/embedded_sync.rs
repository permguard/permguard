// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The Data Plane embedded in an application synchronizes (`11-refactoring/1-dependencies.md`,
//! Embedded public API and lifecycle): with no Plane listener of its own and on the test's Tokio
//! runtime, it mirrors the ledgers a real Control Plane lists over the `policy.mirror` task
//! sessions of the Host the application composed, then shuts down in order.
//!
//! A binary of its own: the evaluation path is composed once per process.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use permguard_core::config::{
    SETTING_ASSURANCE_PROFILE, SETTING_MIRRORS_ENABLED, SETTING_MIRRORS_INTERVAL,
    SETTING_WORKING_DIR,
};
use permguard_core::{BuildSettings, Config, Layers, Metrics};
use permguard_data_plane::embedded::{Capabilities, DataPlane};
use permguard_data_plane::mirrors::layout;
use permguard_host::composition::{Authorization, Host};

mod support;

use support::plane::{self, provision};
use support::tasks;

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "pg-embedded-sync-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch directory is created");
    dir
}

/// Owner's plan, RD-5: the application's Host serves a `policy.mirror` task of a coordinator
/// whose Control Plane lists two ledgers; the embedded Data Plane mirrors both over the task's
/// session, under the coordinator's authority, with no listener of its own.
#[tokio::test(flavor = "multi_thread")]
async fn an_embedded_data_plane_mirrors_what_its_hosts_tasks_list() {
    let volume = scratch("mirrors");
    let control = plane::start(&volume.join("control")).await;
    provision(&control.url, "acme", &["main-ledger", "staging"]);
    let working = volume.join("embedded");
    std::fs::create_dir_all(&working).expect("the working directory");
    let config = Config::from_layers(
        BuildSettings::new("9.9.9", "2026", "Test Holder"),
        Vec::<String>::new(),
        Layers::new().with_file(
            [
                (SETTING_ASSURANCE_PROFILE, "development"),
                (SETTING_MIRRORS_ENABLED, "true"),
                (SETTING_MIRRORS_INTERVAL, "1s"),
                (SETTING_WORKING_DIR, working.to_str().expect("a path")),
            ]
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect::<Vec<(String, String)>>(),
        ),
    )
    .expect("the configuration builds");
    let root = config.mirrors_directory();
    let coordinator = [0x11; 16];
    let host = Host::builder()
        .host_id([2; 16])
        .authorization(Arc::new(Authorization::permissive()))
        .mirror_tasks(Arc::new(tasks::Held {
            tasks: vec![tasks::task(coordinator, 1, "mirror", true)],
            url: control.url.clone(),
            silent: Vec::new(),
            asked: Arc::default(),
            only: Vec::new(),
            incomplete: false,
            partial: Vec::new(),
            unpinned: Vec::new(),
            reported: Default::default(),
            slow: None,
        }))
        .build();

    let runtime = DataPlane::builder(Capabilities {
        identity: permguard_core::ProductIdentity::new(
            "an-embedding-application",
            "Permguard",
            "",
            "",
            "",
        ),
        config,
        host,
        storage: Arc::new(permguard_std::storage::MemoryStorage::new()),
        audit: Arc::new(permguard_std::audit::RecordingAuditSink::new()),
        metrics: Metrics::none(),
    })
    .start()
    .await
    .expect("the embedded Data Plane starts");

    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let mut held = Vec::new();
    while std::time::Instant::now() < deadline {
        held = layout::on_disk(&root).unwrap_or_default();
        if held.len() == 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(held.len(), 2, "both ledgers mirrored: {held:?}");
    let authority = layout::authority_name(&coordinator);
    for mirror in &held {
        assert_eq!(
            mirror.authority.as_deref(),
            Some(authority.as_str()),
            "mirrored under the coordinator's authority"
        );
    }

    let shutdown = runtime.shutdown(Duration::from_secs(10)).await;
    assert!(
        shutdown.unfinished.is_empty(),
        "everything drained: {:?}",
        shutdown.unfinished
    );
}
