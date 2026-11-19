// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The `host-batch-v1` entries of a read's `proof[]` (WP-6.2b, owner decision of 2026-10-19): the
//! batch the producing Host's stream engine sealed, `{format, signature}`. `decisions` and `events`
//! both read them when they verify a page, beside the legacy store's JWS entries.

use permguard_core::Jwk;
use permguard_stream::engine::batch::{Jws, envelope_of, verify_signature};
use permguard_stream::engine::verify::{Keys, Standing};
use serde_json::Value;

/// The format a Host entry names.
pub const HOST_FORMAT: &str = "host-batch-v1";

/// What a Host entry attests: the run of one Host's stream, a range of it, and the Merkle root
/// its records' inclusion paths reach.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostBatch {
    /// The producing Host's `host_id`, 32 lowercase hex digits.
    pub producer: String,
    /// The run, 32 lowercase hex digits.
    pub run: String,
    pub first_seq: u64,
    pub last_seq: u64,
    /// The digest of the record at `last_seq`.
    pub head: String,
    pub merkle_root: String,
    /// The resource the batch's stream belongs to, the canonical text it signs.
    pub resource: String,
    /// The head the batch continues: the digest of the record before `first_seq`.
    pub previous_head: String,
    /// When it was signed, RFC 3339.
    pub created_at: String,
    /// The key it names as its signer.
    pub kid: String,
}

impl HostBatch {
    /// Whether this batch covers `seq` of the run `producer`/`run`, whichever spelling of the ids
    /// each side uses: the envelope names its producer as UUID text, a record as 32 hex digits
    /// (BUG-0112, BUG-0113).
    pub fn covers(&self, producer: &str, run: &str, seq: u64) -> bool {
        same_id(&self.producer, producer)
            && same_id(&self.run, run)
            && (self.first_seq..=self.last_seq).contains(&seq)
    }
}

/// Whether two ids name the same thing, as 32 hex digits or as UUID text, in either case.
pub fn same_id(left: &str, right: &str) -> bool {
    let plain = |id: &str| id.replace('-', "").to_ascii_lowercase();
    plain(left) == plain(right)
}

/// `None` when `value` is not a Host entry; otherwise its batch, its signature verified under
/// `keys` and `typ` when keys are given, or `Err` when it does not hold. Without keys the batch is
/// read for its arithmetic only, never as attributed.
pub fn host_batch(value: &Value, keys: Option<&[Jwk]>, typ: &str) -> Option<Result<HostBatch, ()>> {
    if value.get("format").and_then(Value::as_str) != Some(HOST_FORMAT) {
        return None;
    }
    let Some(signature) = value
        .get("signature")
        .cloned()
        .and_then(|signature| serde_json::from_value::<Jws>(signature).ok())
    else {
        return Some(Err(()));
    };
    let envelope = match keys {
        Some(keys) => verify_signature(&signature, keys, typ),
        None => envelope_of(&signature),
    };
    let kid = kid_of(&signature).unwrap_or_default();
    Some(
        envelope
            .map(|envelope| batch_of(envelope, kid))
            .map_err(|_| ()),
    )
}

fn batch_of(envelope: permguard_stream::engine::batch::Envelope, kid: String) -> HostBatch {
    HostBatch {
        producer: envelope.stream_key.producer_host_id,
        run: envelope.run,
        first_seq: envelope.first_seq,
        last_seq: envelope.last_seq,
        head: envelope.head,
        merkle_root: envelope.merkle_root,
        resource: envelope.stream_key.resource,
        previous_head: envelope.previous_head,
        created_at: envelope.created_at,
        kid,
    }
}

/// The `kid` a batch signature's protected header names.
fn kid_of(signature: &Jws) -> Option<String> {
    use base64::Engine as _;

    let protected = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(&signature.protected)
        .ok()?;
    Some(
        serde_json::from_slice::<Value>(&protected)
            .ok()?
            .get("kid")?
            .as_str()?
            .to_owned(),
    )
}

/// The Host batches whose signatures verified, screened against the revocations of the key
/// documents given (BUG-0165, BUG-0166), the rule `streams verify` applies: a batch signed at or
/// after its key's `compromised_at` (or, with none, its revocation) is compromised, unless a later
/// batch of the same run, signed by a key not compromised, chains over it.
#[derive(Debug, Default)]
pub struct Screened {
    /// The batches that stand.
    pub kept: Vec<HostBatch>,
    /// The batches that do not, each with why.
    pub compromised: Vec<(HostBatch, String)>,
    /// What stands and is worth saying: a batch signed by a revoked key before the boundary, or
    /// excused by a later one.
    pub notes: Vec<String>,
}

pub fn screen(batches: Vec<HostBatch>, keys: &Keys) -> Screened {
    let standings: Vec<Standing> = batches
        .iter()
        .map(|batch| keys.standing(&batch.kid, &batch.created_at))
        .collect();
    let mut screened = Screened::default();
    for (index, batch) in batches.iter().enumerate() {
        let named = format!(
            "batch {}-{} of {}/{}",
            batch.first_seq, batch.last_seq, batch.producer, batch.run
        );
        match &standings[index] {
            Standing::Sound => screened.kept.push(batch.clone()),
            Standing::Before(detail) => {
                screened
                    .notes
                    .push(format!("{named} is {detail}; it stands"));
                screened.kept.push(batch.clone());
            }
            Standing::Compromised(detail) => match vouched(&batches, &standings, index) {
                Some(later) => {
                    screened.notes.push(format!(
                        "{named} is {detail}; it stands, as batch {}-{}, signed by a key not \
                         compromised, chains over it",
                        later.first_seq, later.last_seq
                    ));
                    screened.kept.push(batch.clone());
                }
                None => screened.compromised.push((
                    batch.clone(),
                    format!(
                        "{named} is {detail}, and no later batch signed by a key not compromised \
                         chains over it"
                    ),
                )),
            },
        }
    }
    screened
}

/// The first batch not compromised that continues the chain from `batches[index]`, batch by
/// batch, each one's `previous_head` the head of the one before.
fn vouched<'a>(
    batches: &'a [HostBatch],
    standings: &[Standing],
    index: usize,
) -> Option<&'a HostBatch> {
    let mut current = &batches[index];
    // Each step moves past `current.last_seq`, so the walk ends.
    loop {
        let (next, standing) = batches.iter().zip(standings).find(|(next, _)| {
            same_id(&next.producer, &current.producer)
                && same_id(&next.run, &current.run)
                && next.first_seq == current.last_seq + 1
                && next.previous_head == current.head
        })?;
        if !standing.is_compromised() {
            return Some(next);
        }
        current = next;
    }
}

/// A Host entry `keys` cannot judge: signed by a key whose `kid` none of them carries. Its batch,
/// read for its range and never attributed, and the `kid`, so a verification reports a key not
/// given rather than a signature that failed (BUG-0114).
pub fn unkeyed_batch(value: &Value, keys: &[Jwk]) -> Option<(HostBatch, String)> {
    if value.get("format").and_then(Value::as_str) != Some(HOST_FORMAT) {
        return None;
    }
    let signature = serde_json::from_value::<Jws>(value.get("signature")?.clone()).ok()?;
    let kid = kid_of(&signature)?;
    if keys.iter().any(|key| key.kid == kid) {
        return None;
    }
    let envelope = envelope_of(&signature).ok()?;
    Some((batch_of(envelope, kid.clone()), kid))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use super::*;
    use permguard_stream::engine::verify::Revocation;

    fn batch(first: u64, last: u64, previous: &str, head: &str, kid: &str) -> HostBatch {
        HostBatch {
            producer: "01".repeat(16),
            run: "07".repeat(16),
            first_seq: first,
            last_seq: last,
            head: head.to_owned(),
            merkle_root: String::new(),
            resource: String::new(),
            previous_head: previous.to_owned(),
            created_at: "2026-10-19T10:00:00Z".to_owned(),
            kid: kid.to_owned(),
        }
    }

    fn revoked(kid: &str, compromised_at: &str) -> Keys {
        Keys {
            keys: Vec::new(),
            revoked: [(
                kid.to_owned(),
                Revocation {
                    at: permguard_core::time::from_rfc3339("2026-10-20T00:00:00Z"),
                    compromised_at: permguard_core::time::from_rfc3339(compromised_at),
                    reason: None,
                },
            )]
            .into(),
        }
    }

    /// BUG-0166: a compromised batch stands only when a later batch by a key not compromised
    /// chains over it, batch by batch; a gap in the chain leaves it compromised.
    #[test]
    fn a_compromised_batch_stands_only_under_a_later_sound_one() {
        let keys = revoked("old", "2026-10-19T09:00:00Z");
        let chained = vec![
            batch(1, 2, "g", "h2", "old"),
            batch(3, 4, "h2", "h4", "old"),
            batch(5, 6, "h4", "h6", "new"),
        ];
        let screened = screen(chained, &keys);
        assert!(screened.compromised.is_empty(), "{screened:?}");
        assert_eq!(screened.kept.len(), 3);
        assert_eq!(screened.notes.len(), 2, "{screened:?}");

        let broken = vec![
            batch(1, 2, "g", "h2", "old"),
            batch(3, 4, "other", "h4", "new"),
        ];
        let screened = screen(broken, &keys);
        assert_eq!(screened.compromised.len(), 1, "{screened:?}");
        assert_eq!(screened.kept.len(), 1);

        let last = vec![
            batch(1, 2, "g", "h2", "new"),
            batch(3, 4, "h2", "h4", "old"),
        ];
        let screened = screen(last, &keys);
        assert_eq!(
            screened.compromised.len(),
            1,
            "nothing later vouches for it"
        );
        assert_eq!(screened.compromised[0].0.first_seq, 3);

        // Signed before the compromise: it stands, noted.
        let screened = screen(
            vec![batch(1, 2, "g", "h2", "old")],
            &revoked("old", "2026-10-19T11:00:00Z"),
        );
        assert!(screened.compromised.is_empty());
        assert!(
            screened.notes[0].contains("before it was revoked"),
            "{screened:?}"
        );
    }
}
