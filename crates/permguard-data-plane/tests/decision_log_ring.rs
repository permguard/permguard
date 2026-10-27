// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The decision log refuses to start without the plane's signing ring (WP-6.1).
//!
//! A binary of its own: the log is composed once per process (`decisions::host_log`), so a test
//! beside it that composed the plane first would hand this one its cached log, or its absence, and
//! the refusal under test would never be reached.

#![allow(clippy::expect_used)]

use std::sync::Arc;

use permguard_core::config::{
    SETTING_AUDIT_PSEUDONYM_ENABLED, SETTING_AUDIT_PSEUDONYM_KEY_REF, SETTING_LOG_ENABLED,
    SETTING_SECRETS_COORDINATOR_ROOT_REF,
};
use permguard_core::keys::{Jwk, PublicSet, Sign, Signature};
use permguard_core::{BuildSettings, Config, KeyId, KeyManager, Layers, Maintenance};
use permguard_host::composition::{DATA_ATTEST, Host};
use permguard_host::secrets::{Coordinator, KeyVersion, Root, ZoneHandle, ZonePurpose};

struct Ring(&'static str);

impl Sign for Ring {
    fn active_key_id(&self) -> permguard_core::keys::Result<KeyId> {
        Ok(KeyId::new(self.0))
    }

    fn sign(&self, payload: &[u8]) -> permguard_core::keys::Result<Signature> {
        Ok(Signature::new(
            KeyId::new(self.0),
            "EdDSA",
            payload.to_vec(),
        ))
    }
}

impl PublicSet for Ring {
    fn public_keys(&self) -> permguard_core::keys::Result<Vec<Jwk>> {
        Ok(vec![Jwk::okp(self.0, "Ed25519", "EdDSA", "x")])
    }
}

impl KeyManager for Ring {
    fn name(&self) -> &'static str {
        "ring"
    }

    fn maintain(&self) -> permguard_core::keys::Result<Maintenance> {
        Ok(Maintenance::default())
    }
}

fn config(settings: &[(&str, &str)]) -> Config {
    Config::from_layers(
        BuildSettings::new("9.9.9", "2026", "Test Holder"),
        Vec::<String>::new(),
        Layers::new().with_file(
            settings
                .iter()
                .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
                .collect::<Vec<(String, String)>>(),
        ),
    )
    .expect("the config builds")
}

/// An engine serving the decision stream, which owes nothing and takes nothing: enough for the
/// plane to compose its decision log.
struct Engine;

impl permguard_host::composition::StreamAppender for Engine {
    fn append(
        &self,
        _: &permguard_core::authz::Resource,
        _: &[u8],
    ) -> Result<permguard_host::composition::StreamReceipt, String> {
        Err("not in this test".to_owned())
    }

    fn append_with(
        &self,
        _: &permguard_core::authz::Resource,
        _: permguard_host::composition::BuildRecords<'_>,
    ) -> Result<permguard_host::composition::StreamReceipt, String> {
        Err("not in this test".to_owned())
    }

    fn pressure(
        &self,
        _: &permguard_core::authz::Resource,
        _: u64,
        _: u64,
    ) -> Result<Option<&'static str>, String> {
        Ok(None)
    }
}

impl permguard_host::composition::StreamEngine for Engine {
    fn producer(&self, _: &str) -> Option<Arc<dyn permguard_host::composition::StreamAppender>> {
        Some(Arc::new(Engine))
    }
}

/// WP-6.1, after the review: a plane keeping a decision log refuses to start without its
/// `data.attest` ring, which seals what the Host's stream ships; with it, the log starts.
#[tokio::test]
async fn the_decision_log_refuses_to_start_without_its_signing_ring() {
    use permguard_core::PlaneTask as _;

    let working = std::env::temp_dir().join(format!(
        "permguard-data-plane-log-ring-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&working);
    std::fs::create_dir_all(&working).expect("a working directory");
    let logging = config(&[
        (SETTING_LOG_ENABLED, "true"),
        (SETTING_SECRETS_COORDINATOR_ROOT_REF, "coordinator-root"),
        (SETTING_AUDIT_PSEUDONYM_ENABLED, "true"),
        (SETTING_AUDIT_PSEUDONYM_KEY_REF, "audit-pseudonym"),
        (
            permguard_core::config::SETTING_WORKING_DIR,
            working.to_str().expect("a path"),
        ),
    ]);
    let coordinator = Coordinator::new(
        Root::from_material(&[9u8; 32], KeyVersion::new(1).expect("v1")).expect("a root"),
        [1; 16],
    );
    let composed = |ring: bool| {
        let builder = Host::builder()
            .streams(Arc::new(Engine))
            .host_id([1; 16])
            .zone_key(ZoneHandle::coordinated(
                ZonePurpose::DecisionCommitment,
                coordinator.clone(),
            ))
            .zone_key(ZoneHandle::coordinated(
                ZonePurpose::AuditPseudonym,
                coordinator.clone(),
            ));
        let builder = if ring {
            builder.ring(DATA_ATTEST, Arc::new(Ring("data")))
        } else {
            builder
        };
        builder
            .build()
            .register(permguard_data_plane::module().declaration(&logging))
            .expect("registers")
    };
    let identity =
        permguard_core::ProductIdentity::new("permguard-data-plane", "Permguard", "", "", "");
    let storage = permguard_std::storage::MemoryStorage::new();
    let audit = permguard_std::audit::RecordingAuditSink::new();

    let server = permguard_core::ServerContext::new(identity, &logging, &storage, &audit)
        .with_plane_handles("data", Arc::new(composed(false)));
    let service = permguard_data_plane::decisions::DecisionService::new();
    let refused = service
        .start(&permguard_core::PlaneContext::new(&server, "data"))
        .await
        .expect_err("no ring, no log");
    assert!(refused.to_string().contains("signing ring"), "{refused:#}");

    let server = permguard_core::ServerContext::new(identity, &logging, &storage, &audit)
        .with_plane_handles("data", Arc::new(composed(true)));
    let context = permguard_core::PlaneContext::new(&server, "data");
    service.start(&context).await.expect("the log starts");
    service.stop(&context).await.expect("it stops");
}
