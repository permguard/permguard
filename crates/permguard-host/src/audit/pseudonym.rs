// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Resource-derived pseudonyms of the Host's trails (WP-3.5, derivation of WP-3.3):
//!
//! ```text
//! key       = derive_host_local(audit.pseudonym root, owner = host_id, "audit.pseudonym",
//!                               authority = host_id, resource, N)
//! pseudonym = "vN:" || hex(HMAC-SHA256(key, "permguard.audit.pseudonym.v1\n" ||
//!                                      det-CBOR([identifier_type, normalized_identifier]))[0..16])
//! ```
//!
//! One identifier has one pseudonym per resource, and another on every Host: trails of two
//! tenants do not correlate, and neither do two Hosts' (owner decisions of 2026-10-07 and
//! 2026-10-08). The normalized identifier is the identifier with surrounding white space removed;
//! its case is kept, since principals are compared byte for byte. A derivation that fails answers
//! no pseudonym, and the record is refused rather than written under a key of zeros.

use crate::secrets::{HostLocal, HostPurpose, host_pseudonym};

/// The pseudonymiser of one Host-local root and version.
pub struct ResourcePseudonyms {
    local: HostLocal,
}

impl std::fmt::Debug for ResourcePseudonyms {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResourcePseudonyms")
            .field("version", &self.local.version())
            .finish_non_exhaustive()
    }
}

impl ResourcePseudonyms {
    /// Over the Host-local `audit.pseudonym` root `local`.
    pub fn new(local: HostLocal) -> Self {
        Self { local }
    }

    /// The pseudonym of `identifier`, of the type `identifier_type`, in the trails of `resource`.
    pub fn pseudonym(
        &self,
        resource: &str,
        identifier_type: &str,
        identifier: &str,
    ) -> Option<String> {
        let key = self.local.key(HostPurpose::AuditPseudonym, resource).ok()?;
        host_pseudonym(&key, self.local.version(), identifier_type, identifier)
    }
}
