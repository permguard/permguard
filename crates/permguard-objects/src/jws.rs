// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The JWS framing of a signed artifact (RFC 7515): the protected header, the signing input
//! `protected || "." || payload`, and the three base64url parts.
//!
//! One function writes it, for whoever signs: the Host's typed signer, which frames every JWS
//! artifact of a Plane through it, and an evidence model signing a batch under a ring its caller
//! holds. A batch therefore has one framing, and a verifier one header to expect.
//!
//! | Header                      | Bytes                           | Signed as                        |
//! | --------------------------- | ------------------------------- | -------------------------------- |
//! | [`Header::Bare`]            | `{"alg":…,"kid":…}`             | a decision batch                 |
//! | [`Header::Typed`]           | `{"alg":…,"typ":…,"kid":…}`     | an event batch                   |
//! | [`Header::Canonical`]       | `{"alg":…,"kid":…,"typ":…}`     | a token, a signed response (JCS) |
//!
//! The algorithm is the one the artifact declares, never one the ring chooses: a ring that signs
//! with another is refused, and so is a key that rotated between the header and the signature.

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use permguard_core::KeyError;
use permguard_core::keys::Sign;

/// The members of a protected header, and their order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Header {
    /// `{"alg","kid"}`.
    Bare,
    /// `{"alg","typ","kid"}`, declaring the type.
    Typed(&'static str),
    /// The JCS form, members in code-point order: `{"alg","kid","typ"}`.
    Canonical(&'static str),
}

/// How one kind of artifact is framed: the algorithm its header declares, the only one its
/// signature may be made with, and the header's members.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Framing {
    /// The JOSE algorithm.
    pub algorithm: &'static str,
    /// The protected header.
    pub header: Header,
}

/// A decision batch: `{"alg":"EdDSA","kid"}`.
pub const DECISION_BATCH: Framing = Framing {
    algorithm: "EdDSA",
    header: Header::Bare,
};

/// An event batch: `{"alg":"EdDSA","typ","kid"}`.
pub const EVENT_BATCH: Framing = Framing {
    algorithm: "EdDSA",
    header: Header::Typed(permguard_core::domains::protected::EVENT_BATCH),
};

/// A signed JWS's three parts, base64url.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parts {
    /// The protected header.
    pub protected: String,
    /// The payload.
    pub payload: String,
    /// The signature over `protected || "." || payload`.
    pub signature: String,
}

/// Why a JWS was not signed.
#[derive(Debug)]
pub enum JwsError {
    /// The ring did not sign.
    Key(KeyError),
    /// The ring signed with an algorithm the artifact's header does not declare.
    Algorithm(String),
}

impl fmt::Display for JwsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Key(error) => write!(f, "{error}"),
            Self::Algorithm(found) => write!(f, "the ring signed with `{found}`"),
        }
    }
}

impl std::error::Error for JwsError {}

/// A JSON string, as the header spells it.
fn quoted(value: &str) -> Result<String, JwsError> {
    serde_json::to_string(value).map_err(|error| {
        JwsError::Key(KeyError::backend(format!(
            "writing the protected header: {error}"
        )))
    })
}

impl Framing {
    /// The protected header naming `kid`, as the bytes that are signed.
    fn protected(&self, kid: &str) -> Result<String, JwsError> {
        let alg = quoted(self.algorithm)?;
        let kid = quoted(kid)?;
        Ok(match self.header {
            Header::Bare => format!(r#"{{"alg":{alg},"kid":{kid}}}"#),
            Header::Typed(typ) => {
                format!(r#"{{"alg":{alg},"typ":{},"kid":{kid}}}"#, quoted(typ)?)
            }
            Header::Canonical(typ) => {
                format!(r#"{{"alg":{alg},"kid":{kid},"typ":{}}}"#, quoted(typ)?)
            }
        })
    }
}

/// Signs `payload` as a JWS framed by `framing`, under `keys`' active key.
pub fn sign(framing: &Framing, payload: &[u8], keys: &dyn Sign) -> Result<Parts, JwsError> {
    let kid = keys.active_key_id().map_err(JwsError::Key)?;
    let protected = B64.encode(framing.protected(kid.as_str())?);
    let payload = B64.encode(payload);
    let signature = keys
        .sign(format!("{protected}.{payload}").as_bytes())
        .map_err(JwsError::Key)?;
    if signature.algorithm() != framing.algorithm {
        return Err(JwsError::Algorithm(signature.algorithm().to_owned()));
    }
    if signature.key_id() != &kid {
        return Err(JwsError::Key(KeyError::backend(
            "the signing key rotated mid-signature",
        )));
    }
    Ok(Parts {
        protected,
        payload,
        signature: B64.encode(signature.bytes()),
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use permguard_core::keys::{KeyId, Result, Signature};

    use super::*;

    /// A ring that signs nothing real: the framing is what is under test.
    struct Ring {
        kid: &'static str,
        algorithm: &'static str,
        signs_as: &'static str,
    }

    impl Sign for Ring {
        fn active_key_id(&self) -> Result<KeyId> {
            Ok(KeyId::new(self.kid))
        }

        fn sign(&self, payload: &[u8]) -> Result<Signature> {
            Ok(Signature::new(
                KeyId::new(self.signs_as),
                self.algorithm,
                payload.to_vec(),
            ))
        }
    }

    fn ring(kid: &'static str) -> Ring {
        Ring {
            kid,
            algorithm: "EdDSA",
            signs_as: kid,
        }
    }

    fn header(parts: &Parts) -> String {
        String::from_utf8(B64.decode(&parts.protected).expect("base64url")).expect("utf-8")
    }

    #[test]
    fn each_header_is_the_bytes_its_artifact_was_always_signed_with() {
        let keys = ring("data.attest:abc");
        let bare = sign(&DECISION_BATCH, b"payload", &keys).expect("signed");
        assert_eq!(header(&bare), r#"{"alg":"EdDSA","kid":"data.attest:abc"}"#);

        let typed = sign(&EVENT_BATCH, b"payload", &keys).expect("signed");
        assert_eq!(
            header(&typed),
            format!(
                r#"{{"alg":"EdDSA","typ":"{}","kid":"data.attest:abc"}}"#,
                permguard_core::domains::protected::EVENT_BATCH
            )
        );

        let canonical = sign(
            &Framing {
                algorithm: "EdDSA",
                header: Header::Canonical("at+jwt"),
            },
            b"payload",
            &keys,
        )
        .expect("signed");
        assert_eq!(
            header(&canonical),
            r#"{"alg":"EdDSA","kid":"data.attest:abc","typ":"at+jwt"}"#
        );
    }

    #[test]
    fn the_signature_covers_the_header_and_the_payload() {
        let parts = sign(&DECISION_BATCH, b"payload", &ring("k")).expect("signed");
        assert_eq!(parts.payload, B64.encode(b"payload"));
        assert_eq!(
            B64.decode(&parts.signature).expect("base64url"),
            format!("{}.{}", parts.protected, parts.payload).into_bytes()
        );
    }

    #[test]
    fn a_kid_is_written_as_a_json_string() {
        let parts = sign(&DECISION_BATCH, b"p", &ring("a\"b\\c")).expect("signed");
        let read: serde_json::Value = serde_json::from_str(&header(&parts)).expect("json");
        assert_eq!(read["kid"], "a\"b\\c");
    }

    #[test]
    fn a_ring_that_signs_with_another_algorithm_is_refused() {
        let keys = Ring {
            kid: "k",
            algorithm: "ES256",
            signs_as: "k",
        };
        assert!(matches!(
            sign(&DECISION_BATCH, b"p", &keys),
            Err(JwsError::Algorithm(found)) if found == "ES256"
        ));
    }

    #[test]
    fn a_key_that_rotated_mid_signature_is_refused() {
        let keys = Ring {
            kid: "before",
            algorithm: "EdDSA",
            signs_as: "after",
        };
        assert!(matches!(
            sign(&DECISION_BATCH, b"p", &keys),
            Err(JwsError::Key(_))
        ));
    }
}
