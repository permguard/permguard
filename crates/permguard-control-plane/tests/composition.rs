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
    host.register(permguard_control_plane::module().declaration(&config), None)
        .expect("the control plane registers");
    host.register(permguard_data_plane::module().declaration(&config), None)
        .expect("the data plane registers beside it");
}

#[test]
fn the_control_plane_gets_what_it_declared_and_nothing_else() {
    let registration = host()
        .register(
            permguard_control_plane::module().declaration(&config()),
            None,
        )
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
    host.register(permguard_control_plane::module().declaration(&config), None)
        .expect("registers");

    let twice = host
        .register(permguard_control_plane::module().declaration(&config), None)
        .expect_err("a plane registers once");
    assert!(
        matches!(twice, CompositionError::AlreadyRegistered(_)),
        "{twice}"
    );

    let rival = host
        .register(Declaration::new("rival").signs::<HeadStatementV1>(), None)
        .expect_err("another plane signing head statements");
    assert!(
        matches!(&rival, CompositionError::Collision { first, .. } if first == "control"),
        "{rival}"
    );
}
