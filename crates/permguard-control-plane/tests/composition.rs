// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The control plane's composition (WP-2.1, P1): what it declares to the Host, and that it gets
//! those handles and nothing else.
//!
//! The plane holds no key manager, audit recorder or secret store: its declaration is what reaches
//! the Host, and the registration answers typed handles for what it declared. A handle it did not
//! declare is refused, and a declaration that collides with another plane's stops the start.

#![allow(clippy::expect_used)]

use std::sync::Arc;

use permguard_core::keys::{Jwk, PublicSet, Sign, Signature};
use permguard_core::{BuildSettings, Config, KeyId, KeyManager, Layers, Maintenance};
use permguard_host::composition::{
    CompositionError, DATA_ATTEST, DecisionBatchV1, Declaration, HOST_OPERATIONS, HeadStatementV1,
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

fn config() -> Config {
    Config::from_layers(
        BuildSettings::new("9.9.9", "2026", "Test Holder"),
        Vec::<String>::new(),
        Layers::new(),
    )
    .expect("the config builds")
}

fn host() -> Host {
    Host::builder()
        .ring(
            permguard_host::composition::CONTROL_ATTEST,
            Arc::new(Ring("control")),
        )
        .ring(DATA_ATTEST, Arc::new(Ring("data")))
        .ring(HOST_OPERATIONS, Arc::new(Ring("operations")))
        .build()
}

#[test]
fn both_planes_register_on_one_host_without_colliding() {
    let host = host();
    let config = config();
    host.register(permguard_control_plane::module().declaration(&config))
        .expect("the control plane registers");
    host.register(permguard_data_plane::module().declaration(&config))
        .expect("the data plane registers beside it");
}

#[test]
fn the_control_plane_gets_what_it_declared_and_nothing_else() {
    let registration = host()
        .register(permguard_control_plane::module().declaration(&config()))
        .expect("registers");

    let signer = registration
        .signer::<HeadStatementV1>()
        .expect("declared")
        .expect("the ring is composed");
    assert_eq!(signer.active_key_id().expect("a key").as_str(), "control");
    registration
        .public_keys(DATA_ATTEST)
        .expect("declared")
        .expect("composed");

    for refused in [
        registration.signer::<DecisionBatchV1>().map(|_| ()),
        registration.public_keys(HOST_OPERATIONS).map(|_| ()),
        registration
            .audit::<permguard_data_plane::handles::DataPlaneAudit>()
            .map(|_| ()),
    ] {
        assert!(
            matches!(refused, Err(CompositionError::Undeclared { .. })),
            "{refused:?}"
        );
    }
}

#[test]
fn a_declaration_colliding_with_the_control_planes_fails_registration() {
    let host = host();
    let config = config();
    host.register(permguard_control_plane::module().declaration(&config))
        .expect("registers");

    let twice = host
        .register(permguard_control_plane::module().declaration(&config))
        .expect_err("a plane registers once");
    assert!(
        matches!(twice, CompositionError::AlreadyRegistered(_)),
        "{twice}"
    );

    let rival = host
        .register(Declaration::new("rival").signs::<HeadStatementV1>())
        .expect_err("another plane signing head statements");
    assert!(
        matches!(&rival, CompositionError::Collision { first, .. } if first == "control"),
        "{rival}"
    );
}

/// WP-2.12: with the Host's clock in anomaly the control plane's head statements, which carry
/// `signed_at`, are not signed; once the wall clock catches up they are again.
#[test]
fn a_clock_anomaly_stops_the_control_planes_head_statements() {
    use permguard_host::time::{ManualClock, ManualMonotonic, TimeGuard};
    use permguard_objects::digest::Digest;
    use permguard_objects::statement::{HeadStatement, SignedHead};

    const START: i64 = 1_800_000_000;
    let wall = Arc::new(ManualClock::at(START));
    let time = Arc::new(TimeGuard::new(
        wall.clone(),
        Arc::new(ManualMonotonic::default()),
        std::time::Duration::from_secs(30),
    ));
    let host = Host::builder()
        .ring(
            permguard_host::composition::CONTROL_ATTEST,
            Arc::new(Ring("control")),
        )
        .time(time)
        .build();
    let registration = host
        .register(permguard_control_plane::module().declaration(&config()))
        .expect("the control plane registers");
    let signer = registration
        .signer::<HeadStatementV1>()
        .expect("declared")
        .expect("composed");
    let statement = HeadStatement {
        zone: "0198f2aa-0000-7000-8000-000000000001".into(),
        ledger: "0198f3bb-0000-7000-8000-000000000002".into(),
        r#ref: "main".into(),
        digest: Digest::compute(b"commit"),
        counter: 1,
        signed_at: START,
    };
    let sign = |statement: &HeadStatement| {
        SignedHead::sign_with(statement, b"control", |bytes| {
            signer
                .sign(bytes)
                .map(|signature| signature.bytes().to_vec())
                .map_err(|error| {
                    permguard_objects::statement::StatementError::Signer(error.to_string())
                })
        })
    };
    sign(&statement).expect("a sound clock signs");

    wall.jump(-3_600);
    let refused = sign(&statement).expect_err("in anomaly");
    assert!(refused.to_string().contains("anomaly"), "{refused}");

    wall.jump(3_600);
    sign(&statement).expect("the wall clock caught up");
}

/// WP-2.3: only the Host identity signs a session proof, an identity document, a succession or
/// a ring binding; the control plane's ring declaring one as its artifact is refused, and its own
/// declaration names none.
#[test]
fn the_control_plane_cannot_declare_what_only_the_host_identity_signs() {
    use permguard_host::composition::{Artifact, HOST_RESERVED};

    struct ForgedProof;

    impl Artifact for ForgedProof {
        const TYPE: &'static str = permguard_core::domains::protected::HOST_PROOF;
        const RING: permguard_host::composition::RingId =
            permguard_host::composition::CONTROL_ATTEST;
        const TIME_SENSITIVE: bool = false;
    }

    let Err(refused) = host().register(Declaration::new("control").signs::<ForgedProof>()) else {
        panic!("a Host proof is no plane's artifact");
    };
    assert!(
        matches!(&refused, CompositionError::Reserved { artifact, .. } if artifact == ForgedProof::TYPE),
        "{refused}"
    );
    assert!(HOST_RESERVED.contains(&permguard_core::domains::protected::HOST_RING_BINDING));
    host()
        .register(permguard_control_plane::module().declaration(&config()))
        .expect("the control plane declares nothing reserved");
}
