// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! `GET /host/v1/keys` under `keys.read`, and `GET /host/v1/keys/{ring}`: one ring's public set
//! with its digest and cache policy, public without a grant, being public keys (owner decision,
//! 2026-10-06). `epoch` and `binding` arrive with the ring bindings (WP-2.3) and are `null`
//! until then; rotate and revoke arrive with the key packages.

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use permguard_core::authz::{Actor, operations};
use permguard_core::keys::{Jwk, KEY_SET_MAX_AGE, KeyManager};
use permguard_core::{ErrorClass, codes};

use super::{HostApi, Refusal};

/// One ring in the list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RingSummary {
    /// The ring id: `host.operations`, `control.attest`, `data.attest`.
    pub ring: String,
    /// How many public keys it publishes.
    pub keys: u32,
    /// The digest of its public set.
    pub digest: String,
}

/// `GET /host/v1/keys`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rings {
    pub rings: Vec<RingSummary>,
}

/// One public key, as RFC 7517 spells it; the private half is never expressed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyView {
    pub kid: String,
    pub kty: String,
    pub crv: Option<String>,
    pub x: String,
    pub y: Option<String>,
    pub alg: String,
    #[serde(rename = "use")]
    pub usage: String,
}

impl From<Jwk> for KeyView {
    fn from(jwk: Jwk) -> Self {
        Self {
            kid: jwk.kid,
            kty: jwk.kty,
            crv: jwk.crv,
            x: jwk.x,
            y: jwk.y,
            alg: jwk.alg,
            usage: jwk.usage,
        }
    }
}

/// `GET /host/v1/keys/{ring}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RingView {
    pub ring: String,
    /// The ring epoch, once the bindings carry one (WP-2.3).
    pub epoch: Option<u64>,
    /// SHA-256 over the public set as published, hex: what a cache compares.
    pub digest: String,
    /// The signed binding of this ring to the Host identity (WP-2.3).
    pub binding: Option<String>,
    /// How long a client may cache the set, in seconds.
    pub cache_max_age: u32,
    pub keys: Vec<KeyView>,
}

impl HostApi {
    /// `GET /host/v1/keys`.
    pub fn rings(&self, actor: &Actor) -> Result<Rings, Refusal> {
        let _admitted = self.admit(actor, operations::KEYS_READ)?;
        let mut rings = Vec::with_capacity(self.rings.len());
        for (name, keys) in &self.rings {
            let published = read(name, keys.as_ref())?;
            rings.push(RingSummary {
                ring: name.clone(),
                keys: u32::try_from(published.len()).unwrap_or(u32::MAX),
                digest: digest(&published),
            });
        }
        Ok(Rings { rings })
    }

    /// `GET /host/v1/keys/{ring}`: public, no grant is checked.
    pub fn ring(&self, name: &str) -> Result<RingView, Refusal> {
        let Some((ring, keys)) = self.rings.iter().find(|(held, _)| held == name) else {
            return Err(Refusal::new(
                ErrorClass::NotFound,
                codes::host::RING_UNKNOWN,
                format!("no key ring `{name}` is composed in this process"),
            ));
        };
        let published = read(ring, keys.as_ref())?;
        Ok(RingView {
            ring: ring.clone(),
            epoch: None,
            digest: digest(&published),
            binding: None,
            cache_max_age: u32::try_from(KEY_SET_MAX_AGE.as_secs()).unwrap_or(u32::MAX),
            keys: published.into_iter().map(Into::into).collect(),
        })
    }
}

/// The public set of `keys`, or `ring_unreadable`: never an empty set dressed as an answer.
fn read(ring: &str, keys: &dyn KeyManager) -> Result<Vec<Jwk>, Refusal> {
    keys.public_keys().map_err(|error| {
        tracing::warn!(
            event.name = "host.keys.unreadable",
            component = super::COMPONENT,
            ring = ring,
            error = %error,
            "a key ring could not be read"
        );
        Refusal::Api(
            permguard_core::ApiError::new(
                ErrorClass::Unavailable,
                codes::host::RING_UNREADABLE,
                format!("the key ring `{ring}` could not be read"),
            )
            .with_internal(error.to_string()),
        )
    })
}

/// SHA-256 over the JWKS document as the set serializes, hex.
fn digest(published: &[Jwk]) -> String {
    let bytes = serde_json::to_vec(&permguard_core::keys::JwkSet::new(published.to_vec()))
        .unwrap_or_default();
    let mut text = String::with_capacity(64);
    for byte in Sha256::digest(&bytes) {
        text.push_str(&format!("{byte:02x}"));
    }
    text
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::sync::Arc;

    use super::*;
    use crate::api::testing::{actor, admin, facade_with};
    use permguard_core::keys::{KeyId, Maintenance, PublicSet, Sign};

    struct Fixed(Vec<Jwk>);

    impl Sign for Fixed {
        fn active_key_id(&self) -> permguard_core::keys::Result<KeyId> {
            unreachable!("the Host API never signs")
        }

        fn sign(&self, _: &[u8]) -> permguard_core::keys::Result<permguard_core::keys::Signature> {
            unreachable!("the Host API never signs")
        }
    }

    impl PublicSet for Fixed {
        fn public_keys(&self) -> permguard_core::keys::Result<Vec<Jwk>> {
            Ok(self.0.clone())
        }
    }

    impl KeyManager for Fixed {
        fn name(&self) -> &'static str {
            "fixed"
        }

        fn maintain(&self) -> permguard_core::keys::Result<Maintenance> {
            unreachable!("the Host API never maintains")
        }
    }

    #[test]
    fn the_ring_is_public_and_the_list_is_gated() {
        let ring: Arc<dyn KeyManager> =
            Arc::new(Fixed(vec![Jwk::okp("k1", "Ed25519", "EdDSA", "AAAA")]));
        let api = facade_with(
            "keys",
            vec![("host.operations".to_owned(), Arc::clone(&ring))],
        );
        let view = api.ring("host.operations").expect("public");
        assert_eq!(view.keys.len(), 1);
        assert_eq!(view.keys[0].kid, "k1");
        assert_eq!(view.cache_max_age, 300);
        assert!(view.epoch.is_none() && view.binding.is_none());
        assert_eq!(view.digest.len(), 64);
        let unknown = api.ring("nope").expect_err("unknown");
        assert_eq!(
            unknown.error().expect("refusal").code(),
            codes::host::RING_UNKNOWN
        );
        let rings = api.rings(&admin()).expect("the administrator lists");
        assert_eq!(rings.rings[0].digest, view.digest);
        assert_eq!(rings.rings[0].keys, 1);
        // `keys.read` is public on the test facade too: the list admits anonymous.
        assert!(api.rings(&Actor::Anonymous).is_ok());
        assert!(api.rings(&actor("spiffe://acme/other")).is_ok());
    }
}
