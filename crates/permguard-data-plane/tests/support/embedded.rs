// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What an application composes to embed the Data Plane, for the suites that start it: the Host
//! with a stream engine that keeps what it is handed, the Data Plane's ring, its zone keys, and
//! the configuration the repository's examples are written for.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use permguard_core::authz::Resource;
use permguard_core::config::{
    SETTING_ASSURANCE_PROFILE, SETTING_AUDIT_PSEUDONYM_ENABLED, SETTING_AUDIT_PSEUDONYM_KEY_REF,
    SETTING_LOG_ENABLED, SETTING_SECRETS_COORDINATOR_ROOT_REF, SETTING_WORKING_DIR,
};
use permguard_core::keys::{Jwk, PublicSet, Sign, Signature};
use permguard_core::{BuildSettings, Config, KeyId, KeyManager, Layers, Maintenance, Metrics};
use permguard_data_plane::embedded::Capabilities;
use permguard_host::composition::{
    Authorization, BuildRecords, DATA_ATTEST, Host, StreamAppender, StreamEngine, StreamPosition,
    StreamReceipt,
};
use permguard_host::secrets::{Coordinator, KeyVersion, Root, ZoneHandle, ZonePurpose};

/// The Data Plane's signing ring, as the Host composes it: a key that signs whatever it is given.
pub struct Ring;

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
pub struct Recording {
    records: Mutex<BTreeMap<String, Vec<Vec<u8>>>>,
}

impl Recording {
    pub fn count(&self) -> usize {
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
pub struct Engine(Arc<Recording>);

impl StreamEngine for Engine {
    fn producer(&self, _: &str) -> Option<Arc<dyn StreamAppender>> {
        Some(Arc::clone(&self.0) as Arc<dyn StreamAppender>)
    }
}

pub fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "pg-embedded-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch directory is created");
    dir
}

/// The configuration of an embedded Data Plane on `working`, with `extra` settings over the
/// suite's own.
pub fn config(working: &std::path::Path, extra: &[(&str, &str)]) -> Config {
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
            .chain(extra)
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect::<Vec<(String, String)>>(),
        ),
    )
    .expect("the configuration builds")
}

/// The Host the application composes: its id, its stream engine, the Data Plane's ring, the zone
/// keys its decision log commits and pseudonymizes with, and an authorization that admits the
/// application's own caller, who is the subject of this suite rather than its authorization.
pub fn host(streams: Arc<Recording>) -> Host {
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

pub fn capabilities(config: Config, streams: Arc<Recording>) -> Capabilities {
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
