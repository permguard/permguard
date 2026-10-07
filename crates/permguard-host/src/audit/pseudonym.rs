// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Resource-derived pseudonyms (WP-3.5):
//!
//! ```text
//! pseudonym = <version> || ":" ||
//!             HMAC-SHA256(derived_audit_key(resource, identifier_type),
//!                         "permguard.audit.pseudonym.v1\n" || normalized_identifier)[0..16]
//! ```
//!
//! `derived_audit_key` is HKDF-SHA256 from the `audit.pseudonym` HMAC root, with no salt and the
//! info `digest::AUDIT_PSEUDONYM ‖ SHA-256(resource) ‖ identifier_type` (owner decision of
//! 2026-10-07). One identifier has one pseudonym per resource: trails of two tenants do not
//! correlate. The normalized identifier is the identifier with surrounding white space removed;
//! its case is kept, since principals are compared byte for byte. The version is written as
//! configured, `v1` giving `v1:…`. A derivation that fails answers no pseudonym, and the record
//! is refused rather than written under a key of zeros.

use permguard_core::domains::digest::AUDIT_PSEUDONYM;
use permguard_objects::digest::Digest;
use ring::{hkdf, hmac};
use zeroize::Zeroizing;

use super::record::hex;

/// The pseudonymiser of one root and version.
pub struct ResourcePseudonyms {
    root: Zeroizing<Vec<u8>>,
    version: String,
}

impl std::fmt::Debug for ResourcePseudonyms {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResourcePseudonyms")
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

/// The length HKDF expands to: an HMAC-SHA256 key.
struct KeyLength;

impl hkdf::KeyType for KeyLength {
    fn len(&self) -> usize {
        32
    }
}

impl ResourcePseudonyms {
    /// Over the HMAC root `root`, whose pseudonyms name `version`.
    pub fn new(root: &[u8], version: &str) -> Self {
        Self {
            root: Zeroizing::new(root.to_vec()),
            version: version.to_owned(),
        }
    }

    /// The pseudonym of `identifier`, of the type `identifier_type`, in the trails of `resource`.
    pub fn pseudonym(
        &self,
        resource: &str,
        identifier_type: &str,
        identifier: &str,
    ) -> Option<String> {
        let key = self.derived_key(resource, identifier_type)?;
        let key = hmac::Key::new(hmac::HMAC_SHA256, &key[..]);
        let mut context = hmac::Context::with_key(&key);
        context.update(AUDIT_PSEUDONYM.as_bytes());
        context.update(identifier.trim().as_bytes());
        let tag = context.sign();
        Some(format!("{}:{}", self.version, hex(&tag.as_ref()[..16])))
    }

    fn derived_key(&self, resource: &str, identifier_type: &str) -> Option<Zeroizing<Vec<u8>>> {
        let resource_digest = Digest::compute(resource.as_bytes());
        let info: [&[u8]; 3] = [
            AUDIT_PSEUDONYM.as_bytes(),
            resource_digest.raw(),
            identifier_type.as_bytes(),
        ];
        let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &[]).extract(&self.root);
        let mut key = Zeroizing::new(vec![0u8; 32]);
        prk.expand(&info, KeyLength).ok()?.fill(&mut key).ok()?;
        Some(key)
    }
}
