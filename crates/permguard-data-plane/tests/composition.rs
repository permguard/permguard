// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The data plane's composition (WP-2.1, P1): what it declares to the Host, and that it gets those
//! handles and nothing else.
//!
//! The plane signs its evidence through two typed signers, records through its own audit schema
//! and tags inputs and pseudonymizes subjects through zone key handles that never show a key; it
//! holds no key manager, audit recorder, secret store or root. The zone keys are declared only when
//! the decision log is on (WP-3.3).

#![allow(clippy::expect_used)]

use std::sync::Arc;

use permguard_core::config::{
    SETTING_AUDIT_PSEUDONYM_ENABLED, SETTING_AUDIT_PSEUDONYM_KEY_REF, SETTING_LOG_ENABLED,
    SETTING_SECRETS_COORDINATOR_ROOT_REF,
};
use permguard_core::keys::{Jwk, PublicSet, Sign, Signature};
use permguard_core::{BuildSettings, Config, KeyId, KeyManager, Layers, Maintenance};
use permguard_host::composition::{
    CONTROL_ATTEST, CompositionError, DATA_ATTEST, DecisionBatchV1, EventBatchV1, HeadStatementV1,
    Host,
};
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

fn host() -> Host {
    Host::builder()
        .ring(CONTROL_ATTEST, Arc::new(Ring("control")))
        .ring(DATA_ATTEST, Arc::new(Ring("data")))
        .build()
}

#[test]
fn the_data_plane_signs_its_evidence_and_nothing_else() {
    let registration = host()
        .register(permguard_data_plane::module().declaration(&config(&[])))
        .expect("registers");
    for signer in [
        registration
            .signer::<DecisionBatchV1>()
            .map(|signer| signer.is_some()),
        registration
            .signer::<EventBatchV1>()
            .map(|signer| signer.is_some()),
    ] {
        assert_eq!(signer, Ok(true));
    }
    assert_eq!(
        registration
            .signer::<DecisionBatchV1>()
            .expect("declared")
            .expect("composed")
            .active_key_id()
            .expect("a key")
            .as_str(),
        "data",
        "the data plane's ring, never another"
    );
    let refused = registration.signer::<HeadStatementV1>().map(|_| ());
    assert!(
        matches!(refused, Err(CompositionError::Undeclared { .. })),
        "{refused:?}"
    );
    let refused = registration.public_keys(CONTROL_ATTEST).map(|_| ());
    assert!(
        matches!(refused, Err(CompositionError::Undeclared { .. })),
        "{refused:?}"
    );
    for purpose in [ZonePurpose::DecisionCommitment, ZonePurpose::AuditPseudonym] {
        let refused = registration.zone_key(purpose).map(|_| ());
        assert!(
            matches!(refused, Err(CompositionError::Undeclared { .. })),
            "no decision log, no zone key: {refused:?}"
        );
    }
    // WP-6.1: no decision log, no decision stream.
    let refused = registration
        .stream_producer(permguard_decisions::stream::STREAM)
        .map(|_| ());
    assert!(
        matches!(refused, Err(CompositionError::Undeclared { .. })),
        "{refused:?}"
    );
}

#[test]
fn the_zone_keys_are_held_by_the_host_and_never_shown() {
    let logging = config(&[
        (SETTING_LOG_ENABLED, "true"),
        (SETTING_SECRETS_COORDINATOR_ROOT_REF, "coordinator-root"),
        // A decision log needs pseudonymised subjects; the configuration refuses one without.
        (SETTING_AUDIT_PSEUDONYM_ENABLED, "true"),
        (SETTING_AUDIT_PSEUDONYM_KEY_REF, "audit-pseudonym"),
    ]);
    let coordinator = Coordinator::new(
        Root::from_material(&[9u8; 32], KeyVersion::new(1).expect("v1")).expect("a root"),
        [1; 16],
    );
    let registration = Host::builder()
        .ring(DATA_ATTEST, Arc::new(Ring("data")))
        .zone_key(ZoneHandle::coordinated(
            ZonePurpose::DecisionCommitment,
            coordinator.clone(),
        ))
        .zone_key(ZoneHandle::coordinated(
            ZonePurpose::AuditPseudonym,
            coordinator.clone(),
        ))
        .build()
        .register(permguard_data_plane::module().declaration(&logging))
        .expect("registers");
    let tags = registration
        .zone_key(ZonePurpose::DecisionCommitment)
        .expect("declared while the log is on")
        .expect("held");
    // WP-6.1: the plane produces its decision stream on the Host's engine, absent when none is
    // composed.
    assert!(
        registration
            .stream_producer(permguard_decisions::stream::STREAM)
            .expect("declared while the log is on")
            .is_none(),
        "no engine composed in this test"
    );
    assert_eq!(
        format!("{tags:?}"),
        "ZoneHandle(decision.commitment, v1, redacted)",
        "never shown"
    );

    // The production path tags through the handle, per ledger, exactly as the ledger's key would.
    let (zone, ledger, other) = ([2u8; 16], [3u8; 16], [4u8; 16]);
    let value = serde_json::json!({"principal": {"id": "alice", "type": "user"}});
    let through_handle = permguard_decisions::Commitment::with_scoped_mac("v1", {
        let tags = Arc::clone(&tags);
        move |(zone, ledger), parts| tags.mac(zone, ledger, parts)
    });
    let with_the_key = permguard_decisions::Commitment::new(
        coordinator
            .distributed(ZonePurpose::DecisionCommitment, &zone, &ledger)
            .expect("derived")
            .to_vec(),
        "v1",
    );
    let tagged = through_handle
        .commit_in(Some(&(zone, ledger)), &value)
        .expect("committed");
    assert_eq!(tagged, with_the_key.commit(&value).expect("committed"));
    assert_ne!(
        tagged,
        through_handle
            .commit_in(Some(&(zone, other)), &value)
            .expect("committed"),
        "another ledger, another key"
    );
    assert!(
        through_handle
            .commit_in(None, &value)
            .expect("committed")
            .ends_with("unavailable"),
        "no scope, no tag"
    );

    // Without the zone keys composed the handles are absent, never another purpose's.
    let without = host()
        .register(permguard_data_plane::module().declaration(&logging))
        .expect("registers");
    assert!(
        without
            .zone_key(ZonePurpose::DecisionCommitment)
            .expect("declared")
            .is_none()
    );
}

/// WP-2.12: with the Host's clock in anomaly the data plane's evidence keeps signing — decision and
/// event batches order by sequence, not by the clock — and the head statements it never signs stay
/// refused as undeclared.
#[test]
fn a_clock_anomaly_leaves_the_data_planes_evidence_signing() {
    use permguard_host::time::{ManualClock, ManualMonotonic, TimeGuard};

    let wall = Arc::new(ManualClock::at(1_800_000_000));
    let time = Arc::new(TimeGuard::new(
        wall.clone(),
        Arc::new(ManualMonotonic::default()),
        std::time::Duration::from_secs(30),
    ));
    let registration = Host::builder()
        .ring(DATA_ATTEST, Arc::new(Ring("data")))
        .time(Arc::clone(&time))
        .build()
        .register(permguard_data_plane::module().declaration(&config(&[])))
        .expect("registers");
    wall.jump(-3_600);
    time.tick();
    assert!(
        time.anomaly().is_some(),
        "the anomaly is open before anything signs"
    );
    let decisions = registration
        .signer::<DecisionBatchV1>()
        .expect("declared")
        .expect("composed");
    let events = registration
        .signer::<EventBatchV1>()
        .expect("declared")
        .expect("composed");
    use permguard_host::composition::Jws;
    for sequence in 1..=3u8 {
        decisions
            .sign(&Jws::<DecisionBatchV1>::new(&[sequence]))
            .expect("decision evidence signs in anomaly");
        events
            .sign(&Jws::<EventBatchV1>::new(&[sequence]))
            .expect("event evidence signs in anomaly");
    }
    assert!(time.trusted_now().is_err(), "the anomaly is still in force");
}

/// WP-2.3: only the Host identity signs a session proof, an identity document, a succession or
/// a ring binding; the data plane's ring declaring one as its artifact is refused, and its own
/// declaration names none.
#[test]
fn the_data_plane_cannot_declare_what_only_the_host_identity_signs() {
    use permguard_host::composition::{Artifact, CompositionError, Declaration, HOST_RESERVED};

    struct ForgedBinding;

    impl Artifact for ForgedBinding {
        const TYPE: &'static str = permguard_core::domains::protected::HOST_RING_BINDING;
        const RING: permguard_host::composition::RingId = DATA_ATTEST;
        const TIME_SENSITIVE: bool = false;
    }

    let Err(refused) = host().register(Declaration::new("data").signs::<ForgedBinding>()) else {
        panic!("a ring binding is no plane's artifact");
    };
    assert!(
        matches!(&refused, CompositionError::Reserved { artifact, .. } if artifact == ForgedBinding::TYPE),
        "{refused}"
    );
    for reserved in HOST_RESERVED {
        assert!(reserved.starts_with("permguard.host."), "{reserved}");
    }
    host()
        .register(permguard_data_plane::module().declaration(&config(&[])))
        .expect("the data plane declares nothing reserved");
}

/// WP-2.11: the composed binary, under the default `production` profile, refuses a public listener
/// serving in the clear on every interface before it binds anything, naming the listener and the
/// two ways out.
#[test]
fn the_composed_binary_refuses_a_public_listener_in_the_clear_beyond_loopback() {
    let dir = std::env::temp_dir().join(format!(
        "permguard-data-plane-clear-listener-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch directory is created");
    let config = dir.join("config.yml");
    std::fs::write(
        &config,
        format!(
            "working_dir: {}\ndataPlane:\n  public:\n    http:\n      addr: 0.0.0.0:0\n",
            dir.display()
        ),
    )
    .expect("the configuration is written");
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_permguard-data-plane"));
    for (variable, _) in std::env::vars_os() {
        if variable.to_string_lossy().starts_with("PERMGUARD_") {
            command.env_remove(variable);
        }
    }
    let mut child = command
        .arg(&config)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("the binary runs");
    // A process that did not refuse would serve until stopped: bounded, then failed.
    let started = std::time::Instant::now();
    while child.try_wait().expect("waitable").is_none() {
        if started.elapsed() > std::time::Duration::from_secs(30) {
            let _ = child.kill();
            panic!("the binary started serving a public listener in the clear");
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let output = child.wait_with_output().expect("its output");
    assert!(!output.status.success(), "{output:?}");
    let text = String::from_utf8_lossy(&output.stderr).into_owned()
        + String::from_utf8_lossy(&output.stdout).as_ref();
    assert!(text.contains("the data-http listener"), "{text}");
    assert!(
        text.contains(permguard_core::domains::assurance::RELAX_TLS_TERMINATED_UPSTREAM),
        "{text}"
    );
    assert!(!text.contains("panicked"), "{text}");
    let _ = std::fs::remove_dir_all(&dir);
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

/// WP-6.2c2b1: a shared mode reads the origins the Host imports through the consumer of the event
/// stream, so the plane declares that read then and only then.
#[test]
fn the_data_plane_reads_the_event_consumer_only_under_a_shared_mode() {
    use permguard_core::config::{
        SETTING_EVENTS_ENABLED, SETTING_EVENTS_PULL_MODE, SETTING_EXPERIMENTAL_DOGWOOD,
    };

    for (mode, reads) in [
        ("local", false),
        ("shared-eventual", true),
        ("shared-bounded", true),
    ] {
        let registration = host()
            .register(permguard_data_plane::module().declaration(&config(&[
                (SETTING_EVENTS_ENABLED, "true"),
                (SETTING_EXPERIMENTAL_DOGWOOD, "true"),
                (SETTING_EVENTS_PULL_MODE, mode),
            ])))
            .expect("registers");
        let consumer = registration.stream_consumer(permguard_events::stream::STREAM);
        assert_eq!(
            consumer.is_ok(),
            reads,
            "{mode}: declared exactly when shared"
        );
    }
}
