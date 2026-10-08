// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The data plane's composition (WP-2.1, P1): what it declares to the Host, and that it gets those
//! handles and nothing else.
//!
//! The plane signs its evidence through two typed signers, records through its own audit schema
//! and commits to inputs through a secret handle that never shows the key; it holds no key manager,
//! audit recorder or secret store. The commitment key is declared only when the decision log is on.

#![allow(clippy::expect_used)]

use std::sync::Arc;

use permguard_core::config::{
    SETTING_AUDIT_PSEUDONYM_ENABLED, SETTING_AUDIT_PSEUDONYM_KEY_REF,
    SETTING_LOG_COMMITMENT_KEY_REF, SETTING_LOG_ENABLED, SETTING_LOG_PDP_ID,
};
use permguard_core::keys::{Jwk, PublicSet, Sign, Signature};
use permguard_core::secrets::{Secret, SecretRef, SecretStore};
use permguard_core::{BuildSettings, Config, KeyId, KeyManager, Layers, Maintenance};
use permguard_data_plane::handles::DecisionCommitment;
use permguard_host::composition::{
    CONTROL_ATTEST, CompositionError, DATA_ATTEST, DecisionBatchV1, EventBatchV1, HeadStatementV1,
    Host,
};

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

struct Store(usize);

impl SecretStore for Store {
    fn name(&self) -> &'static str {
        "store"
    }

    fn resolve(&self, _: &SecretRef) -> permguard_core::secrets::Result<Secret> {
        Ok(Secret::new(vec![9u8; self.0]))
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
        .register(
            permguard_data_plane::module().declaration(&config(&[])),
            None,
        )
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
    let refused = registration.secret::<DecisionCommitment>().map(|_| ());
    assert!(
        matches!(refused, Err(CompositionError::Undeclared { .. })),
        "no decision log, no commitment key: {refused:?}"
    );
}

#[test]
fn the_commitment_key_is_resolved_by_the_host_and_never_shown() {
    let logging = config(&[
        (SETTING_LOG_ENABLED, "true"),
        (SETTING_LOG_COMMITMENT_KEY_REF, "decisions-commitment"),
        // A decision log needs pseudonymised subjects; the configuration refuses one without.
        (SETTING_AUDIT_PSEUDONYM_ENABLED, "true"),
        (SETTING_AUDIT_PSEUDONYM_KEY_REF, "audit-pseudonym"),
        (SETTING_LOG_PDP_ID, "data-plane-7f3a"),
    ]);
    let registration = host()
        .register(
            permguard_data_plane::module().declaration(&logging),
            Some(&Store(32)),
        )
        .expect("registers");
    let secret = registration
        .secret::<DecisionCommitment>()
        .expect("declared while the log is on");
    assert!(!format!("{secret:?}").contains("09"), "never shown");

    // The production path commits through the handle's HMAC, and commits exactly as the key would.
    let value = serde_json::json!({"principal": {"id": "alice", "type": "user"}});
    let through_handle = permguard_decisions::Commitment::with_mac(secret.version(), {
        let secret = secret.clone();
        move |parts| secret.mac(parts)
    });
    let with_the_key = permguard_decisions::Commitment::new(vec![9u8; 32], secret.version());
    assert_eq!(
        through_handle.commit(&value).expect("committed"),
        with_the_key.commit(&value).expect("committed")
    );
    assert!(
        !through_handle
            .commit(&value)
            .expect("committed")
            .ends_with("unavailable")
    );

    let short = host()
        .register(
            permguard_data_plane::module().declaration(&logging),
            Some(&Store(16)),
        )
        .expect_err("a 16-byte key is too short to commit with");
    assert!(matches!(short, CompositionError::Secret { .. }), "{short}");
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
        .register(
            permguard_data_plane::module().declaration(&config(&[])),
            None,
        )
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

    let Err(refused) = host().register(Declaration::new("data").signs::<ForgedBinding>(), None)
    else {
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
        .register(
            permguard_data_plane::module().declaration(&config(&[])),
            None,
        )
        .expect("the data plane declares nothing reserved");
}
