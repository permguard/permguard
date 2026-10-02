// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The cryptographic profile, as code: the primitives every party computes identically.
//!
//! A signature, a key identifier, a derived key or a sealed blob is only useful if the side that
//! checks it agrees byte for byte with the side that made it. These modules are therefore
//! normative in the same sense as the canonical CBOR profile beside them: one implementation, no
//! negotiation, and a set of vectors in `tests/vectors/crypto.json` that another implementation
//! must reproduce before it is trusted to interoperate.
//!
//! | Module          | Decides                                                                        |
//! | --------------- | ------------------------------------------------------------------------------ |
//! | [`random`]      | the one source of randomness and the one way it fails: fatally, with no fallback |
//! | [`suite`]       | the two signature suites, their JWS and COSE names, and the low-S rule for P-256 |
//! | [`thumbprint`]  | RFC 7638 key identifiers, the ring-prefixed `kid`, the key-set digest           |
//! | [`kdf`]         | HKDF-SHA-256 with deterministic-CBOR `info` tuples; no string concatenation     |
//! | [`mac`]         | HMAC-SHA-256 with a domain prefix and constant-time verification                |
//! | [`seal`]        | envelope encryption: one DEK per blob, AES-256-GCM, the DEK wrapped by a KEK    |
//!
//! Nothing here chooses an algorithm from untrusted input. A verifier is told which suite a ring
//! uses and refuses anything else; a reader of a sealed blob checks the algorithm names it carries
//! against the ones this profile allows.

pub mod kdf;
pub mod mac;
pub mod random;
pub mod seal;
pub mod suite;
pub mod thumbprint;

pub use random::{Entropy, EntropyUnavailable, SystemEntropy};
pub use seal::{Binding, KeyWrap, LocalKeyWrap, SealedKey};
pub use suite::{SignatureError, SigningKey, Suite};
