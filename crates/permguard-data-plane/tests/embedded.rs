// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The Data Plane embedded in an application (`11-refactoring/1-dependencies.md`, Embedded public
//! API and lifecycle): on the test's own Tokio runtime and with no Plane listener, it decides the
//! repository's examples against their verified mirror as their cases say, records each decision
//! on the stream of the Host the application composed, and shuts down in order. Started outside
//! a runtime, it refuses.
//!
//! A binary of its own: the evaluation path and the decision log are composed once per process.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::future::Future as _;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use permguard_core::authz::{Actor, Resource};
use permguard_core::config::{
    SETTING_ASSURANCE_PROFILE, SETTING_AUDIT_PSEUDONYM_ENABLED, SETTING_AUDIT_PSEUDONYM_KEY_REF,
    SETTING_LOG_ENABLED, SETTING_SECRETS_COORDINATOR_ROOT_REF, SETTING_WORKING_DIR,
};
use permguard_core::keys::{Jwk, PublicSet, Sign, Signature};
use permguard_core::lifecycle::{HOST, Phase};
use permguard_core::{BuildSettings, Config, KeyId, KeyManager, Layers, Maintenance, Metrics};
use permguard_data_plane::embedded::{Capabilities, DataPlane, StartError};
use permguard_host::composition::{
    Authorization, BuildRecords, DATA_ATTEST, Host, StreamAppender, StreamEngine, StreamPosition,
    StreamReceipt,
};
use permguard_host::secrets::{Coordinator, KeyVersion, Root, ZoneHandle, ZonePurpose};

mod support;

use support::examples;

/// The Data Plane's signing ring, as the Host composes it: a key that signs whatever it is given.
struct Ring;

impl Sign for Ring {
    fn active_key_id(&self) -> permguard_core::keys::Result<KeyId> {
        Ok(KeyId::new("data"))
    }

    fn sign(&self, payload: &[u8]) -> permguard_core::keys::Result<Signature> {
        Ok(Signature::new(
            KeyId::new("data"),
            "EdDSA",
            payload.to_vec(),
        ))
    }
}

impl PublicSet for Ring {
    fn public_keys(&self) -> permguard_core::keys::Result<Vec<Jwk>> {
        Ok(vec![Jwk::okp("data", "Ed25519", "EdDSA", "x")])
    }
}

impl KeyManager for Ring {
    fn name(&self) -> &'static str {
        "data"
    }

    fn maintain(&self) -> permguard_core::keys::Result<Maintenance> {
        Ok(Maintenance::default())
    }
}

/// The Host's stream engine as the application composed it, keeping every record it was handed,
/// by the resource it was appended under.
#[derive(Default)]
struct Recording {
    records: Mutex<BTreeMap<String, Vec<Vec<u8>>>>,
}

impl Recording {
    fn count(&self) -> usize {
        self.records.lock().unwrap().values().map(Vec::len).sum()
    }
}

impl StreamAppender for Recording {
    fn append(&self, resource: &Resource, record: &[u8]) -> Result<StreamReceipt, String> {
        let mut records = self.records.lock().unwrap();
        let held = records.entry(resource.to_string()).or_default();
        held.push(record.to_vec());
        Ok(StreamReceipt {
            run_id: [7; 16],
            seq: held.len() as u64,
        })
    }

    fn append_with(
        &self,
        resource: &Resource,
        build: BuildRecords<'_>,
    ) -> Result<StreamReceipt, String> {
        let mut records = self.records.lock().unwrap();
        let held = records.entry(resource.to_string()).or_default();
        let built = build(StreamPosition {
            run_id: [7; 16],
            seq: held.len() as u64 + 1,
            prev: [0; 32],
        })?;
        held.extend(built);
        Ok(StreamReceipt {
            run_id: [7; 16],
            seq: held.len() as u64,
        })
    }

    fn pressure(&self, _: &Resource, _: u64, _: u64) -> Result<Option<&'static str>, String> {
        Ok(None)
    }
}

/// The engine hands the one recording appender to every stream it serves.
struct Engine(Arc<Recording>);

impl StreamEngine for Engine {
    fn producer(&self, _: &str) -> Option<Arc<dyn StreamAppender>> {
        Some(Arc::clone(&self.0) as Arc<dyn StreamAppender>)
    }
}

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "pg-embedded-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch directory is created");
    dir
}

fn config(working: &std::path::Path) -> Config {
    Config::from_layers(
        BuildSettings::new("9.9.9", "2026", "Test Holder"),
        Vec::<String>::new(),
        Layers::new().with_file(
            [
                // The profile the repository's examples are written for: their partitions list no
                // `interfaces`, which `production` requires.
                (SETTING_ASSURANCE_PROFILE, "development"),
                (SETTING_LOG_ENABLED, "true"),
                (SETTING_SECRETS_COORDINATOR_ROOT_REF, "coordinator-root"),
                (SETTING_AUDIT_PSEUDONYM_ENABLED, "true"),
                (SETTING_AUDIT_PSEUDONYM_KEY_REF, "audit-pseudonym"),
                (SETTING_WORKING_DIR, working.to_str().expect("a path")),
            ]
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect::<Vec<(String, String)>>(),
        ),
    )
    .expect("the configuration builds")
}

/// The Host the application composes: its id, its stream engine, the Data Plane's ring, the zone
/// keys its decision log commits and pseudonymizes with, and an authorization that admits the
/// application's own caller, who is the subject of this suite rather than its authorization.
fn host(streams: Arc<Recording>) -> Host {
    let coordinator = Coordinator::new(
        Root::from_material(&[9u8; 32], KeyVersion::new(1).expect("v1")).expect("a root"),
        [1; 16],
    );
    Host::builder()
        .host_id([1; 16])
        .streams(Arc::new(Engine(streams)))
        .ring(DATA_ATTEST, Arc::new(Ring))
        .zone_key(ZoneHandle::coordinated(
            ZonePurpose::DecisionCommitment,
            coordinator.clone(),
        ))
        .zone_key(ZoneHandle::coordinated(
            ZonePurpose::AuditPseudonym,
            coordinator,
        ))
        .authorization(Arc::new(Authorization::permissive()))
        .build()
}

fn capabilities(config: Config, streams: Arc<Recording>) -> Capabilities {
    Capabilities {
        identity: permguard_core::ProductIdentity::new(
            "an-embedding-application",
            "Permguard",
            "",
            "",
            "",
        ),
        config,
        host: host(streams),
        storage: Arc::new(permguard_std::storage::MemoryStorage::new()),
        audit: Arc::new(permguard_std::audit::RecordingAuditSink::new()),
        metrics: Metrics::none(),
    }
}

/// Owner's plan, RD-5: an application embeds the Data Plane on its own runtime and with no
/// listener; every case of the repository's examples is decided as the case says, each decision
/// is recorded on the Host's stream, and the shutdown drains and stops every service.
#[tokio::test(flavor = "multi_thread")]
async fn an_embedded_data_plane_decides_records_and_shuts_down_in_order() {
    let working = scratch("decides");
    let config = config(&working);
    // The ids the decision log keys its tags and pseudonyms by are UUIDs, as a catalog gives them.
    examples::provision_as(
        &config.mirrors_directory(),
        "basics",
        "01a1a166-5743-7014-b7bf-197ed0437363",
        "01a1a166-5747-7d8c-a96a-6e17f5281a37",
    );
    let streams = Arc::new(Recording::default());

    let runtime = DataPlane::builder(capabilities(config, Arc::clone(&streams)))
        .start()
        .await
        .expect("the embedded Data Plane starts");
    assert!(runtime.health().is_ready(), "ready once its services run");

    let mut decided = 0;
    for (name, case) in examples::cases("basics") {
        let Some(wanted) = case.expect.decision.as_deref() else {
            continue;
        };
        let answer = runtime
            .evaluate(&Actor::Anonymous, examples::request(&name, &case), None)
            .await
            .unwrap_or_else(|refused| panic!("{name}/{}: refused: {refused:?}", case.name));
        assert_eq!(
            answer.decision,
            wanted == "permit",
            "{name}/{}: expected {wanted}",
            case.name
        );
        decided += 1;
    }
    assert!(decided > 0, "the example claims decisions");

    // The decision log appends on the Host's stream, off the decision's own path.
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while streams.count() < decided && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        streams.count() >= decided,
        "every decision recorded on the Host's stream: {} of {decided}",
        streams.count()
    );

    let health = runtime.health();
    let shutdown = runtime.shutdown(Duration::from_secs(10)).await;
    assert!(
        shutdown.unfinished.is_empty(),
        "everything drained: {:?}",
        shutdown.unfinished
    );
    assert_eq!(health.lifecycle().phase(HOST), Some(Phase::Stopped));
    assert_eq!(health.lifecycle().phase("data"), Some(Phase::Stopped));
    assert!(!health.is_ready(), "a stopped plane takes no work");
}

/// The application owns the runtime: started outside one, the Data Plane refuses at once and
/// leaves nothing running.
#[test]
fn an_embedded_data_plane_refuses_to_start_outside_a_runtime() {
    let working = scratch("no-runtime");
    let start = DataPlane::builder(capabilities(
        config(&working),
        Arc::new(Recording::default()),
    ))
    .start();
    let mut start = std::pin::pin!(start);
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    match start.as_mut().poll(&mut context) {
        std::task::Poll::Ready(Err(StartError::NoRuntime)) => {}
        std::task::Poll::Ready(Err(other)) => panic!("refused for another reason: {other}"),
        std::task::Poll::Ready(Ok(_)) => panic!("started outside a runtime"),
        std::task::Poll::Pending => panic!("waited instead of refusing"),
    }
}
