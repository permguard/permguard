// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The key documents a verification reads (BUG-0038, BUG-0165): one or more `--keys` files, each
//! a `keys export` of the producers' `data.attest` ring, published keys and retained ones, or a
//! plain JWKS. One parser for every command, the one `streams verify` reads with, so a batch an old
//! key signed verifies after the key left the published set, and a key a ring revoked is named.

use permguard_core::keys::Jwk;

use crate::args::Globals;
use crate::failure::Failure;

/// What `--keys` gave, every file together: the keys, one producer's or several, and the
/// revocations their rings recorded, so a batch a revoked key signed is judged by when it was
/// signed, never trusted silently.
pub type KeyDocument = permguard_stream::engine::verify::Keys;

/// The ring the decision and event batches are signed under.
const RING: &str = permguard_host::keys::ring::DATA_ATTEST;

/// Reads every file of `paths`, relative to `-w`, into one key document; nothing when none.
pub fn read(globals: &Globals, paths: &[String]) -> Result<Option<KeyDocument>, Failure> {
    if paths.is_empty() {
        return Ok(None);
    }
    let mut document = KeyDocument::default();
    for path in paths {
        let named = crate::session::rooted(globals, path);
        let text = std::fs::read_to_string(&named).map_err(|error| {
            Failure::usage(format!("reading {}: {error}", named.display()))
                .named("validation", permguard_core::codes::client::KEYS_UNREADABLE)
        })?;
        let malformed = |detail: String| {
            Failure::usage(format!(
                "{} is not a key document: {detail}",
                named.display()
            ))
            .named("validation", permguard_core::codes::client::KEYS_MALFORMED)
        };
        // A bare array of keys is a JWKS too.
        let parsed: serde_json::Value =
            serde_json::from_str(&text).map_err(|error| malformed(error.to_string()))?;
        let read = if parsed.is_array() {
            let keys: Vec<Jwk> =
                serde_json::from_value(parsed).map_err(|error| malformed(error.to_string()))?;
            KeyDocument {
                keys,
                revoked: Default::default(),
            }
        } else {
            permguard_stream::engine::verify::Keys::from_document(&text, RING).map_err(
                |detail| {
                    if detail == "the key document holds no key" {
                        Failure::usage(format!(
                            "{} publishes no verification keys",
                            named.display()
                        ))
                        .named("validation", permguard_core::codes::client::KEYS_EMPTY)
                    } else {
                        malformed(detail)
                    }
                },
            )?
        };
        if read.keys.is_empty() {
            return Err(Failure::usage(format!(
                "{} publishes no verification keys",
                named.display()
            ))
            .named("validation", permguard_core::codes::client::KEYS_EMPTY));
        }
        for key in read.keys {
            if !document.keys.iter().any(|held| held.kid == key.kid) {
                document.keys.push(key);
            }
        }
        // The same key revoked in two documents: the earlier boundary, the stricter answer; none
        // at all is the strictest, every signature then compromised.
        for (kid, revocation) in read.revoked {
            let held = document.revoked.get(&kid).map(|held| held.boundary());
            let stricter = match (held, revocation.boundary()) {
                (None, _) => true,
                (Some(None), _) => false,
                (Some(Some(_)), None) => true,
                (Some(Some(held)), Some(other)) => other < held,
            };
            if stricter {
                document.revoked.insert(kid, revocation);
            }
        }
    }
    Ok(Some(document))
}
