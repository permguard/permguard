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
    SETTING_LOG_PDP_ID, SETTING_SECRETS_COORDINATOR_ROOT_REF,
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
}

#[test]
fn the_zone_keys_are_held_by_the_host_and_never_shown() {
    let logging = config(&[
        (SETTING_LOG_ENABLED, "true"),
        (SETTING_SECRETS_COORDINATOR_ROOT_REF, "coordinator-root"),
        // A decision log needs pseudonymised subjects; the configuration refuses one without.
        (SETTING_AUDIT_PSEUDONYM_ENABLED, "true"),
        (SETTING_AUDIT_PSEUDONYM_KEY_REF, "audit-pseudonym"),
        (SETTING_LOG_PDP_ID, "data-plane-7f3a"),
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
    for sequence in 1..=3u8 {
        decisions
            .sign(&[sequence])
            .expect("decision evidence signs in anomaly");
        events
            .sign(&[sequence])
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
