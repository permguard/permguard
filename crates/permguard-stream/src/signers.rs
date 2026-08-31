// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Which key signed which stretch of a stream — kept beside the stream, keys included.
//!
//! # The problem this answers
//!
//! A signed stream outlives its signing keys: producers rotate, and a consumer holding a million
//! records holds batches signed under several generations of key. Verifying a range therefore
//! needs the answer to one question — *which public keys cover these offsets* — and the places
//! that can answer it from a live JWKS are exactly the places a verifier cannot always reach: a
//! coordinator validating what a member shipped has no business depending on that member being
//! up, and a forensic read happens after the producer is gone.
//!
//! So the mapping travels **with the stream**. Each span says "from this offset on, this key",
//! and carries the public key itself — `kid` *and* the JWK — because a name without the key it
//! names sends the verifier right back to the unreachable producer.
//!
//! # Why spans, not per-batch entries
//!
//! A stream of a million batches signed by three keys is three facts, not a million. A span is
//! appended only when the signing key actually changes, so the manifest stays readable at a
//! glance and costs one comparison per signed batch. From 0 to 1&nbsp;000&nbsp;000 under one key
//! and onward under the next is two lines, whatever the traffic was.
//!
//! # What is refused, and what is amended
//!
//! A span starting before the last span already on file is a rewrite of who signed the past, and
//! the past does not change: it is refused, not repaired. A different key at the last span's own
//! starting offset is not that — an unshipped stretch is legitimately rebuilt and re-signed, and
//! its signed evidence on disk is overwritten by the same round — so the last span is **amended**
//! to the new key rather than refused, which would stall the shipper forever on a rotation that
//! landed between two attempts at the same batch.

use std::fmt;
use std::fs;
use std::io::Write as _;
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The file a stream's signer manifest is kept in, inside the stream's own directory.
pub const SIGNERS_FILE: &str = "signers.json";

/// The most signer spans one API response may carry for one stream.
///
/// A caller needing a longer rotation history narrows the inclusive sequence range and pages that
/// history deliberately instead of making one response grow with the age of the deployment.
pub const MAX_SIGNER_SPANS: usize = 1_024;

/// One stretch of a stream and the key that signed it.
///
/// A span covers `[from, next span's from)`; the last span covers everything from its `from`
/// onward. The JWK is the public half only — this file is meant to travel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignerSpan {
    /// The first offset this key signed.
    pub from: u64,
    /// The name the batch signatures carry.
    pub kid: String,
    /// The public key itself, as the producer published it.
    pub jwk: Value,
}

/// Why an observation could not be recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignerError {
    /// A span may not start before the one already on file: history does not change.
    Regression { held: u64, offered: u64 },
    /// One name, two keys: a `kid` seen with different material is a substitution, not a rotation.
    KeyMismatch { kid: String },
}

impl fmt::Display for SignerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Regression { held, offered } => write!(
                formatter,
                "the manifest already covers from offset {held}, and a span may not start \
                 earlier, at {offered}: who signed the past does not change"
            ),
            Self::KeyMismatch { kid } => write!(
                formatter,
                "`{kid}` already names a different public key in this manifest: one name, two \
                 keys is a substitution, not a rotation"
            ),
        }
    }
}

impl std::error::Error for SignerError {}

/// The manifest: every signing-key change a stream has seen, in offset order.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signers {
    spans: Vec<SignerSpan>,
}

impl Signers {
    /// A manifest that has seen nothing.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Records that `kid` signed the batch starting at `from`.
    ///
    /// Returns whether the manifest changed: `false` is the common case — the same key kept
    /// signing — and costs one comparison. A caller persists only on `true`.
    ///
    /// A different key at the **last span's own** starting offset amends that span: the stretch
    /// was rebuilt and re-signed before anything extended past it, and the signed evidence beside
    /// this file was overwritten by the same round. Anything earlier is refused.
    pub fn observe(&mut self, from: u64, kid: &str, jwk: &Value) -> Result<bool, SignerError> {
        // One name, one key, across the whole manifest: a `kid` returning with different
        // material is how a substituted key would inherit an honest name's history, and the
        // amendment below must never be reachable by that route.
        if self
            .spans
            .iter()
            .any(|span| span.kid == kid && &span.jwk != jwk)
        {
            return Err(SignerError::KeyMismatch {
                kid: kid.to_owned(),
            });
        }

        let Some(last) = self.spans.last_mut() else {
            self.spans.push(SignerSpan {
                from,
                kid: kid.to_owned(),
                jwk: jwk.clone(),
            });

            return Ok(true);
        };

        if from < last.from {
            return Err(SignerError::Regression {
                held: last.from,
                offered: from,
            });
        }
        if last.kid == kid {
            // The same key signing at or after its own span began: the span already covers it.
            return Ok(false);
        }
        if from == last.from {
            // The same stretch, re-signed: the new key supersedes the one nothing was shipped
            // under.
            last.kid = kid.to_owned();
            last.jwk = jwk.clone();

            return Ok(true);
        }

        self.spans.push(SignerSpan {
            from,
            kid: kid.to_owned(),
            jwk: jwk.clone(),
        });

        Ok(true)
    }

    /// Checks whether an observation could be recorded without changing this manifest.
    ///
    /// Evidence stores use this before writing records or replacing a signed envelope. The later
    /// [`observe`](Self::observe) then cannot discover a semantic conflict after durable evidence
    /// has already changed; only an I/O failure can still interrupt the commit.
    pub fn check_observation(&self, from: u64, kid: &str, jwk: &Value) -> Result<(), SignerError> {
        let mut proposed = self.clone();
        proposed.observe(from, kid, jwk).map(|_| ())
    }

    /// The spans whose stretch intersects `[from, until]`, in offset order.
    ///
    /// These are the keys a verifier needs for that range — no more, so a range signed by one key
    /// out of ten downloads one key.
    pub fn covering(&self, from: u64, until: u64) -> &[SignerSpan] {
        if self.spans.is_empty() || until < from {
            return &[];
        }

        // The first span that could reach `from` is the last one starting at or before it; when
        // every span starts after `from`, coverage begins at the first span within range.
        let start = self
            .spans
            .iter()
            .rposition(|span| span.from <= from)
            .unwrap_or_default();
        let end = self
            .spans
            .iter()
            .position(|span| span.from > until)
            .unwrap_or(self.spans.len());

        if start >= end {
            return &[];
        }

        &self.spans[start..end]
    }

    /// The span currently signing, when anything ever signed.
    pub fn current(&self) -> Option<&SignerSpan> {
        self.spans.last()
    }

    /// Every span, in offset order — the whole history, for a verifier that wants all of it.
    pub fn spans(&self) -> &[SignerSpan] {
        &self.spans
    }

    /// Reads a manifest back, treating an absent file as a stream nothing has signed yet.
    pub fn load(path: &Path) -> std::io::Result<Self> {
        let text = match fs::read(path) {
            Ok(text) => text,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::empty());
            }
            Err(error) => return Err(error),
        };

        serde_json::from_slice(&text).map_err(std::io::Error::other)
    }

    /// Writes the manifest durably: to a sibling first, synced, then renamed over the target.
    ///
    /// The rename is what makes a crash leave either the old manifest or the new one, never a
    /// torn one — the same discipline every journal here follows, because this file makes claims
    /// about signed history and a half-written claim is worse than a stale one.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let rendered = serde_json::to_vec_pretty(self).map_err(std::io::Error::other)?;

        let staged = path.with_extension("json.next");
        {
            let mut file = fs::File::create(&staged)?;
            file.write_all(&rendered)?;
            file.sync_all()?;
        }
        fs::rename(&staged, path)?;

        if let Some(directory) = path.parent() {
            // The rename itself must survive the crash, and that is the directory's business.
            fs::File::open(directory)?.sync_all()?;
        }

        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use serde_json::json;

    use super::*;

    fn key(name: &str) -> Value {
        json!({"kid": name, "kty": "OKP", "crv": "Ed25519", "x": "AAAA", "alg": "EdDSA", "use": "sig"})
    }

    #[test]
    fn the_same_key_signing_on_changes_nothing() {
        let mut signers = Signers::empty();

        assert!(signers.observe(0, "k1", &key("k1")).unwrap());
        assert!(!signers.observe(500, "k1", &key("k1")).unwrap());
        assert!(!signers.observe(999, "k1", &key("k1")).unwrap());

        assert_eq!(signers.spans().len(), 1, "one key is one fact");
    }

    #[test]
    fn a_rotation_is_one_new_span() {
        let mut signers = Signers::empty();
        signers.observe(0, "k1", &key("k1")).unwrap();
        assert!(signers.observe(1_000_000, "k2", &key("k2")).unwrap());

        assert_eq!(signers.spans().len(), 2);
        assert_eq!(signers.current().unwrap().kid, "k2");
    }

    #[test]
    fn a_key_may_return_and_is_a_new_span_when_it_does() {
        // k1, then k2, then k1 again: three stretches, three facts. Adjacent compression must
        // not merge the two k1 spans across the k2 one.
        let mut signers = Signers::empty();
        signers.observe(0, "k1", &key("k1")).unwrap();
        signers.observe(100, "k2", &key("k2")).unwrap();
        assert!(signers.observe(200, "k1", &key("k1")).unwrap());

        assert_eq!(signers.spans().len(), 3);
    }

    #[test]
    fn history_does_not_change() {
        let mut signers = Signers::empty();
        signers.observe(100, "k1", &key("k1")).unwrap();
        signers.observe(200, "k2", &key("k2")).unwrap();

        // A different key starting before the frontier is a rewrite of who signed the past.
        assert_eq!(
            signers.observe(150, "k3", &key("k3")),
            Err(SignerError::Regression {
                held: 200,
                offered: 150
            })
        );
        // The same key is refused below the frontier too: nothing re-signs the closed past.
        assert_eq!(
            signers.observe(150, "k2", &key("k2")),
            Err(SignerError::Regression {
                held: 200,
                offered: 150
            })
        );
    }

    #[test]
    fn one_name_never_carries_two_keys() {
        let mut signers = Signers::empty();
        signers.observe(0, "k1", &key("k1")).unwrap();

        // The same kid arriving with different material is refused wherever it lands: extending
        // the current span, starting a new one, or amending the tail.
        let mut forged = key("k1");
        forged["x"] = serde_json::json!("BBBB");
        assert_eq!(
            signers.observe(100, "k1", &forged),
            Err(SignerError::KeyMismatch {
                kid: "k1".to_owned()
            })
        );

        // And a kid deeper in history is protected too, not only the last span.
        signers.observe(100, "k2", &key("k2")).unwrap();
        assert_eq!(
            signers.observe(200, "k1", &forged),
            Err(SignerError::KeyMismatch {
                kid: "k1".to_owned()
            })
        );
        // While the honest key returning is still a rotation.
        assert!(signers.observe(200, "k1", &key("k1")).unwrap());
    }

    #[test]
    fn a_rebuilt_stretch_amends_its_own_span_instead_of_stalling() {
        // A batch fails to ship, the key rotates, and the same stretch is rebuilt and re-signed:
        // the signed evidence on disk was overwritten by the same round, and the manifest follows
        // it. Refusing here would defer the shipper forever over a rotation it cannot undo.
        let mut signers = Signers::empty();
        signers.observe(0, "k1", &key("k1")).unwrap();
        signers.observe(100, "k2", &key("k2")).unwrap();

        assert!(signers.observe(100, "k3", &key("k3")).unwrap());
        assert_eq!(signers.spans().len(), 2, "amended, not appended");
        assert_eq!(signers.current().unwrap().kid, "k3");
        assert_eq!(
            signers
                .current()
                .unwrap()
                .jwk
                .get("kid")
                .and_then(Value::as_str),
            Some("k3"),
            "the key travels with the amendment"
        );
        // The stretch before it is untouched.
        assert_eq!(signers.spans()[0].kid, "k1");
    }

    #[test]
    fn covering_returns_exactly_the_keys_a_range_needs() {
        let mut signers = Signers::empty();
        signers.observe(0, "k1", &key("k1")).unwrap();
        signers.observe(1_000, "k2", &key("k2")).unwrap();
        signers.observe(2_000, "k3", &key("k3")).unwrap();

        // Entirely inside the first span.
        let one = signers.covering(10, 500);
        assert_eq!(
            one.iter().map(|span| span.kid.as_str()).collect::<Vec<_>>(),
            ["k1"]
        );

        // Straddling the first rotation.
        let two = signers.covering(900, 1_100);
        assert_eq!(
            two.iter().map(|span| span.kid.as_str()).collect::<Vec<_>>(),
            ["k1", "k2"]
        );

        // The open tail belongs to the last key.
        let tail = signers.covering(5_000, u64::MAX);
        assert_eq!(
            tail.iter()
                .map(|span| span.kid.as_str())
                .collect::<Vec<_>>(),
            ["k3"]
        );

        // Everything.
        assert_eq!(signers.covering(0, u64::MAX).len(), 3);

        // An inverted range is nothing rather than a panic.
        assert!(signers.covering(10, 5).is_empty());
    }

    #[test]
    fn a_range_before_the_first_span_still_names_the_spans_within_it() {
        // A stream whose first signed batch started at 100, asked about [0, 150]: offsets below
        // 100 have no signer, and the span from 100 is what covers the rest.
        let mut signers = Signers::empty();
        signers.observe(100, "k1", &key("k1")).unwrap();

        let spans = signers.covering(0, 150);
        assert_eq!(spans.len(), 1);
        assert_eq!(spans[0].kid, "k1");

        // And a range that ends before anything was signed is empty.
        assert!(signers.covering(0, 50).is_empty());
    }

    #[test]
    fn the_manifest_round_trips_through_its_file() {
        let directory = std::env::temp_dir().join(format!("signers-test-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join(SIGNERS_FILE);

        let mut signers = Signers::empty();
        signers.observe(0, "k1", &key("k1")).unwrap();
        signers.observe(1_000, "k2", &key("k2")).unwrap();
        signers.save(&path).unwrap();

        let read = Signers::load(&path).unwrap();
        assert_eq!(read, signers);

        // An absent file is a stream nothing has signed yet, not an error.
        let absent = Signers::load(&directory.join("elsewhere.json")).unwrap();
        assert_eq!(absent, Signers::empty());

        std::fs::remove_dir_all(&directory).ok();
    }
}
