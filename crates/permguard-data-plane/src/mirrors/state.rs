// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! A task mirror's verified state, switched through one journal (WP-7.2c,
//! `3-data-plane/3-data-plane-mirrors-notp.md`, atomic checkpoint).
//!
//! ```text
//! FORMAT              the mirror's layout version, a storage view written with its first switch
//!                     (WP-7.2d); a mirror of another layout is refused, never read as this one
//! objects/            land first: immutable, content-addressed, harmless when unreferenced
//! journal.cborseq     one canonical item per advance — the append is the switch
//!   {1 v, 2 revision, 3 authority, 4 zone, 5 ledger, 6 ref, 7 head, 8 counter, 9 ref_digest,
//!    10 ring_epoch, 11 key_set_digest, 12 verified_at, 13 closure_digest,
//!    14 verified, 15 ring_binding}
//! VERIFIED.cose       views of the last item, written after it, rewritten from it whenever
//! RING-BINDING.cose   they differ: a crash between the append and the views leaves the journal
//! CHECKPOINT.cbor     authoritative and the views behind it, never ahead
//! refs/main           the JSON checkpoint the pull and the decision path read
//! ```
//!
//! A crash before the append leaves the previous item authoritative and the objects already
//! fetched in place for the next round.

use std::path::Path;

use permguard_control_client::checkpoint::{self, Checkpoint};
use permguard_control_client::store::FsStore;
use permguard_host::storage::{Dir, format, sequence, write};
use permguard_objects::cbor::{self, Value};
use permguard_objects::digest::Digest;

/// The journal of a task mirror's verified states.
pub const JOURNAL: &str = "journal.cborseq";
/// The exact signed head statement of the state in force.
pub const VERIFIED: &str = "VERIFIED.cose";
/// The state in force without its two signed artifacts.
pub const CHECKPOINT: &str = "CHECKPOINT.cbor";
/// The mirror's layout version (WP-7.2d).
pub const FORMAT: &str = "FORMAT";
/// The layout this build writes and reads.
const LAYOUT: u64 = 1;
/// The JSON checkpoint the pull and the decision path read.
const REFS_MAIN: &str = "refs/main";
/// The largest item the journal reads: a head statement and a binding are each a few hundred
/// bytes.
const MAX_ITEM: usize = 1 << 20;
/// The record version this build writes and reads.
const VERSION: i64 = 1;
/// How many items the journal holds before it is compacted.
const MAX_ITEMS: usize = 64;
/// How many of the latest items a compaction keeps, the new one among them.
const KEPT_ITEMS: usize = 16;

/// One verified state of a task mirror.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MirrorState {
    /// The task's revision: the epoch of the manifest it was read from.
    pub revision: u64,
    pub authority: [u8; 16],
    pub zone: String,
    pub ledger: String,
    pub reference: String,
    pub head: Digest,
    pub counter: u64,
    pub ref_digest: Digest,
    pub ring_epoch: u64,
    pub key_set_digest: [u8; 32],
    /// When this plane verified it, unix seconds.
    pub verified_at: u64,
    /// [`closure_digest`] of every object reachable from the head.
    pub closure_digest: Digest,
    /// The exact signed head statement.
    pub verified: Vec<u8>,
    /// The exact identity-signed binding of the `control.attest` set it verified under.
    pub ring_binding: Vec<u8>,
}

/// The digest a state names its closure by: SHA-256 over the domain and the sorted raw digests.
pub fn closure_digest(closure: &[Digest]) -> Digest {
    let mut raws: Vec<&[u8; 32]> = closure.iter().map(Digest::raw).collect();
    raws.sort();
    raws.dedup();
    let mut bytes = permguard_core::domains::digest::MIRROR_CLOSURE
        .as_bytes()
        .to_vec();
    for raw in raws {
        bytes.extend_from_slice(raw);
    }
    Digest::compute(&bytes)
}

fn uint(value: u64, what: &str) -> Result<Value, String> {
    i64::try_from(value)
        .map(Value::Int)
        .map_err(|_| format!("the mirror state's {what} is out of range"))
}

impl MirrorState {
    /// The checkpoint's members, labels 1 to 13 in order.
    fn checkpoint_pairs(&self) -> Result<Vec<(Value, Value)>, String> {
        Ok(vec![
            (Value::Int(1), Value::Int(VERSION)),
            (Value::Int(2), uint(self.revision, "revision")?),
            (Value::Int(3), Value::Bytes(self.authority.to_vec())),
            (Value::Int(4), Value::Text(self.zone.clone())),
            (Value::Int(5), Value::Text(self.ledger.clone())),
            (Value::Int(6), Value::Text(self.reference.clone())),
            (Value::Int(7), Value::Text(self.head.to_string())),
            (Value::Int(8), uint(self.counter, "counter")?),
            (Value::Int(9), Value::Text(self.ref_digest.to_string())),
            (Value::Int(10), uint(self.ring_epoch, "ring epoch")?),
            (Value::Int(11), Value::Bytes(self.key_set_digest.to_vec())),
            (Value::Int(12), uint(self.verified_at, "verification time")?),
            (Value::Int(13), Value::Text(self.closure_digest.to_string())),
        ])
    }

    /// The journal item: the checkpoint and both signed artifacts.
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        let mut pairs = self.checkpoint_pairs()?;
        pairs.push((Value::Int(14), Value::Bytes(self.verified.clone())));
        pairs.push((Value::Int(15), Value::Bytes(self.ring_binding.clone())));
        cbor::encode(&Value::Map(pairs)).map_err(|error| error.to_string())
    }

    /// `CHECKPOINT.cbor`: the item without its signed artifacts.
    pub fn checkpoint(&self) -> Result<Vec<u8>, String> {
        cbor::encode(&Value::Map(self.checkpoint_pairs()?)).map_err(|error| error.to_string())
    }

    /// One journal item, closed: every label of the version, none other.
    pub fn decode(value: &Value) -> Result<Self, String> {
        let Value::Map(pairs) = value else {
            return Err("a mirror state is a map".to_owned());
        };
        // The version first: an item another build wrote is said to be one, not mistaken for a
        // damaged item of this version.
        match pairs.iter().find(|(key, _)| *key == Value::Int(1)) {
            Some((_, Value::Int(version))) if *version == VERSION => {}
            Some((_, Value::Int(version))) => {
                return Err(format!(
                    "a mirror state of version {version}, which this build does not read"
                ));
            }
            _ => return Err("a mirror state names no version".to_owned()),
        }
        let labels: Vec<i64> = pairs
            .iter()
            .map(|(key, _)| match key {
                Value::Int(label) => Ok(*label),
                _ => Err("a mirror state's labels are integers".to_owned()),
            })
            .collect::<Result<_, _>>()?;
        if labels != (1..=15).collect::<Vec<i64>>() {
            return Err("a mirror state holds exactly labels 1 to 15, in order".to_owned());
        }
        let at = |label: usize| &pairs[label - 1].1;
        let int = |label: usize, what: &str| match at(label) {
            Value::Int(value) if *value >= 0 => Ok(*value as u64),
            _ => Err(format!(
                "the mirror state's {what} is not an unsigned integer"
            )),
        };
        let text = |label: usize, what: &str| match at(label) {
            Value::Text(value) => Ok(value.clone()),
            _ => Err(format!("the mirror state's {what} is not text")),
        };
        let bytes = |label: usize, what: &str| match at(label) {
            Value::Bytes(value) => Ok(value.clone()),
            _ => Err(format!("the mirror state's {what} is not bytes")),
        };
        let digest = |label: usize, what: &str| {
            Digest::parse(&text(label, what)?).map_err(|error| format!("{what}: {error}"))
        };
        Ok(Self {
            revision: int(2, "revision")?,
            authority: bytes(3, "authority")?
                .try_into()
                .map_err(|_| "the mirror state's authority is not 16 bytes".to_owned())?,
            zone: text(4, "zone")?,
            ledger: text(5, "ledger")?,
            reference: text(6, "ref")?,
            head: digest(7, "head")?,
            counter: int(8, "counter")?,
            ref_digest: digest(9, "ref digest")?,
            ring_epoch: int(10, "ring epoch")?,
            key_set_digest: bytes(11, "key-set digest")?
                .try_into()
                .map_err(|_| "the mirror state's key-set digest is not 32 bytes".to_owned())?,
            verified_at: int(12, "verification time")?,
            closure_digest: digest(13, "closure digest")?,
            verified: bytes(14, "statement")?,
            ring_binding: bytes(15, "ring binding")?,
        })
    }

    /// The JSON checkpoint the pull and the decision path read, as this state names it.
    fn json(&self) -> Checkpoint {
        Checkpoint {
            head: self.head.to_string(),
            counter: self.counter,
            ref_digest: Some(self.ref_digest.to_string()),
            authority_host_id: Some(permguard_host::identity::record::uuid_text(&self.authority)),
            reference: Some(self.reference.clone()),
            ring_epoch: Some(self.ring_epoch),
            key_set_digest: Some(Digest::from_raw(self.key_set_digest).to_string()),
        }
    }
}

fn storage(error: impl std::fmt::Display) -> String {
    format!("the mirror's state: {error}")
}

/// Checks the mirror's layout is this build's, writing it when `create` and it names none.
fn layout(dir: &Dir, create: bool) -> Result<(), String> {
    match write::read_view(dir, FORMAT, format::VIEW).map_err(storage)? {
        Some(body) if body == LAYOUT.to_be_bytes() => Ok(()),
        Some(body) => Err(format!(
            "the mirror's layout is {}, which this build does not read",
            <[u8; 8]>::try_from(body.as_slice())
                .map(|version| u64::from_be_bytes(version).to_string())
                .unwrap_or_else(|_| "unreadable".to_owned())
        )),
        None if create => {
            write::replace_view(dir, FORMAT, format::VIEW, &LAYOUT.to_be_bytes()).map_err(storage)
        }
        None => Ok(()),
    }
}

/// Switches `mirror` to `state`: the journal item appended and flushed, then the views. A state
/// that only re-verifies the one in force — every member but `verified_at` the same — appends
/// nothing, so a mirror that does not move does not grow its journal every round; how recently it
/// was confirmed is the `SYNCED` marker's to say.
///
/// The journal stays bounded: past [`MAX_ITEMS`] items it is rewritten, atomically, holding the
/// latest [`KEPT_ITEMS`] with the new one last; that replacement is then the switch.
pub fn commit(mirror: &Path, state: &MirrorState) -> Result<(), String> {
    let dir = Dir::open(mirror).map_err(storage)?;
    layout(&dir, true)?;
    let journal = if dir.exists(JOURNAL).map_err(storage)? {
        sequence::recover(&dir, JOURNAL, MAX_ITEM).map_err(storage)?
    } else {
        sequence::Sequence::default()
    };
    if let Some(last) = journal.items.last()
        && let Ok(held) = MirrorState::decode(last)
        && (MirrorState {
            verified_at: state.verified_at,
            ..held.clone()
        }) == *state
    {
        return materialize(mirror, &dir, &held);
    }
    unrewound(&FsStore::new(mirror), state)?;
    let item = state.encode()?;
    if journal.items.len() + 1 > MAX_ITEMS {
        let mut kept = Vec::new();
        for value in &journal.items[journal.items.len() + 1 - KEPT_ITEMS..] {
            kept.extend(cbor::encode(value).map_err(|error| error.to_string())?);
        }
        kept.extend(&item);
        write::replace_bytes(&dir, JOURNAL, &kept).map_err(storage)?;
    } else {
        sequence::append(&dir, JOURNAL, &item).map_err(storage)?;
    }
    materialize(mirror, &dir, state)
}

/// The state in force, the last item of the journal, a torn final item cut; the views rewritten
/// from it wherever they differ. `None` for a mirror that has never switched.
pub fn recover(mirror: &Path) -> Result<Option<MirrorState>, String> {
    let dir = Dir::open(mirror).map_err(storage)?;
    layout(&dir, false)?;
    if !dir.exists(JOURNAL).map_err(storage)? {
        return Ok(None);
    }
    let journal = sequence::recover(&dir, JOURNAL, MAX_ITEM).map_err(storage)?;
    let Some(last) = journal.items.last() else {
        return Ok(None);
    };
    let state = MirrorState::decode(last)?;
    materialize(mirror, &dir, &state)?;
    Ok(Some(state))
}

/// The state in force, read only (WP-7.2d): the last whole item, nothing cut and no view
/// written — what a reader beside a switch in flight may call, where [`recover`] would cut that
/// switch's item as torn.
pub fn peek(mirror: &Path) -> Result<Option<MirrorState>, String> {
    let dir = Dir::open(mirror).map_err(storage)?;
    layout(&dir, false)?;
    if !dir.exists(JOURNAL).map_err(storage)? {
        return Ok(None);
    }
    let journal = sequence::read(&dir, JOURNAL, MAX_ITEM).map_err(storage)?;
    journal.items.last().map(MirrorState::decode).transpose()
}

/// Writes each view of `state` that does not already hold it.
fn materialize(mirror: &Path, dir: &Dir, state: &MirrorState) -> Result<(), String> {
    let store = FsStore::new(mirror);
    let held = unrewound(&store, state)?;
    for (name, bytes) in [
        (VERIFIED, state.verified.clone()),
        (super::task::RING_BINDING, state.ring_binding.clone()),
        (CHECKPOINT, state.checkpoint()?),
    ] {
        if dir.read(name).map_err(storage)?.as_deref() != Some(bytes.as_slice()) {
            write::replace_bytes(dir, name, &bytes).map_err(storage)?;
        }
    }
    let json = state.json();
    if held.as_ref() != Some(&json) {
        checkpoint::write(&store, REFS_MAIN, &json)?;
    }
    Ok(())
}

/// The JSON checkpoint the mirror holds, refused when it is ahead of `state`.
///
/// The journal is the authority, and a JSON checkpoint ahead of it was written by no switch: no
/// view is ever rewritten backwards from it, which would reopen a rollback window.
fn unrewound(store: &FsStore, state: &MirrorState) -> Result<Option<Checkpoint>, String> {
    let held = checkpoint::read(store, REFS_MAIN)?;
    if let Some(ahead) = held.as_ref().filter(|held| held.counter > state.counter) {
        return Err(format!(
            "the mirror's checkpoint is at counter {}, ahead of its journal at {}",
            ahead.counter, state.counter
        ));
    }
    Ok(held)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    fn scratch(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "pg-mirror-state-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("the scratch directory");
        dir
    }

    fn state(counter: u64) -> MirrorState {
        MirrorState {
            revision: 3,
            authority: [0x11; 16],
            zone: "zone-id".into(),
            ledger: "ledger-id".into(),
            reference: "main".into(),
            head: Digest::compute(&counter.to_be_bytes()),
            counter,
            ref_digest: Digest::compute(b"ref"),
            ring_epoch: 2,
            key_set_digest: [7; 32],
            verified_at: 1_700_000_000,
            closure_digest: closure_digest(&[Digest::compute(b"a")]),
            verified: b"statement".to_vec(),
            ring_binding: b"binding".to_vec(),
        }
    }

    /// WP-7.2c: a state round trips, closed to its fifteen labels in order.
    #[test]
    fn a_state_round_trips_and_is_closed() {
        let held = state(4);
        let bytes = held.encode().expect("it encodes");
        let value = cbor::decode_canonical(&bytes).expect("canonical");
        assert_eq!(MirrorState::decode(&value).expect("it decodes"), held);

        let Value::Map(mut pairs) = value else {
            panic!("a map");
        };
        pairs.push((Value::Int(16), Value::Int(0)));
        assert!(
            MirrorState::decode(&Value::Map(pairs.clone())).is_err(),
            "a label more"
        );
        pairs.truncate(14);
        assert!(
            MirrorState::decode(&Value::Map(pairs.clone())).is_err(),
            "a label less"
        );
        pairs[0].1 = Value::Int(2);
        let other = MirrorState::decode(&Value::Map(pairs)).expect_err("another version");
        assert!(other.contains("version 2"), "{other}");

        let checkpoint =
            cbor::decode_canonical(&held.checkpoint().expect("encodes")).expect("canonical");
        let Value::Map(pairs) = checkpoint else {
            panic!("a map");
        };
        assert_eq!(pairs.len(), 13, "the checkpoint holds no signed artifact");
    }

    /// WP-7.2c: the closure digest is SHA-256 over its domain and the sorted raw digests, a
    /// known answer computed apart; never the bare digests.
    #[test]
    fn the_closure_digest_is_its_domain_over_the_sorted_digests() {
        let (a, b) = (Digest::compute(b"a"), Digest::compute(b"b"));
        let (low, high) = if a.raw() < b.raw() {
            (&a, &b)
        } else {
            (&b, &a)
        };
        let mut expected = b"permguard.mirror.closure.v1\n".to_vec();
        expected.extend_from_slice(low.raw());
        expected.extend_from_slice(high.raw());
        assert_eq!(
            closure_digest(&[b.clone(), a.clone()]),
            Digest::compute(&expected)
        );
        let mut bare = a.raw().to_vec();
        bare.extend_from_slice(b.raw());
        assert_ne!(closure_digest(&[a, b]), Digest::compute(&bare));
    }

    /// WP-7.2c: the closure digest names the set, whatever the order, and only that set.
    #[test]
    fn the_closure_digest_names_the_set() {
        let (a, b) = (Digest::compute(b"a"), Digest::compute(b"b"));
        assert_eq!(
            closure_digest(&[a.clone(), b.clone()]),
            closure_digest(&[b.clone(), a.clone()])
        );
        assert_ne!(
            closure_digest(std::slice::from_ref(&a)),
            closure_digest(&[a, b])
        );
    }

    /// WP-7.2c: a commit switches every view; the last item is the state in force; views a
    /// crash left behind are rewritten from it, and a torn final item is cut, the one before it
    /// staying in force.
    #[test]
    fn the_journal_is_the_switch_and_the_views_follow_it() {
        let mirror = scratch("switch");
        assert_eq!(recover(&mirror).expect("reads"), None, "never switched");

        commit(&mirror, &state(1)).expect("switched");
        commit(&mirror, &state(2)).expect("switched");
        assert_eq!(recover(&mirror).expect("reads"), Some(state(2)));
        // The same state verified again later appends nothing.
        let mut again = state(2);
        again.verified_at += 30;
        commit(&mirror, &again).expect("re-verified");
        let items = |mirror: &Path| {
            sequence::read(&Dir::open(mirror).expect("opens"), JOURNAL, MAX_ITEM)
                .expect("reads")
                .items
                .len()
        };
        assert_eq!(items(&mirror), 2, "one item per advance, none per round");
        let views = |name: &str| std::fs::read(mirror.join(name)).expect("a view");
        assert_eq!(views(VERIFIED), b"statement".to_vec());
        assert_eq!(views(super::super::task::RING_BINDING), b"binding".to_vec());
        assert_eq!(views(CHECKPOINT), state(2).checkpoint().expect("encodes"));
        let json = checkpoint::read(&FsStore::new(&mirror), REFS_MAIN)
            .expect("reads")
            .expect("held");
        assert_eq!(json.counter, 2);
        assert_eq!(json.ring_epoch, Some(2));

        // A crash after the append and before the views: the views are behind, and the journal
        // is what holds.
        let mut ahead = state(3);
        ahead.verified = b"newer statement".to_vec();
        let dir = Dir::open(&mirror).expect("opens");
        sequence::append(&dir, JOURNAL, &ahead.encode().expect("encodes")).expect("appended");
        assert_eq!(views(VERIFIED), b"statement".to_vec(), "behind");
        assert_eq!(recover(&mirror).expect("reads"), Some(ahead.clone()));
        assert_eq!(views(VERIFIED), b"newer statement".to_vec(), "rewritten");
        assert_eq!(
            checkpoint::read(&FsStore::new(&mirror), REFS_MAIN)
                .expect("reads")
                .expect("held")
                .counter,
            3
        );

        // A torn final item: cut, and the one before it is in force.
        let mut torn = std::fs::read(mirror.join(JOURNAL)).expect("the journal");
        torn.extend_from_slice(&state(4).encode().expect("encodes")[..20]);
        std::fs::write(mirror.join(JOURNAL), torn).expect("a torn write");
        assert_eq!(recover(&mirror).expect("reads"), Some(ahead));
    }

    fn recover_items(mirror: &Path) -> usize {
        sequence::read(&Dir::open(mirror).expect("opens"), JOURNAL, MAX_ITEM)
            .expect("reads")
            .items
            .len()
    }

    /// WP-7.2c: the journal stays bounded, the latest items kept and the newest in force.
    #[test]
    fn the_journal_is_compacted_past_its_bound() {
        let mirror = scratch("compact");
        for counter in 1..=MAX_ITEMS as u64 {
            commit(&mirror, &state(counter)).expect("switched");
        }
        assert_eq!(recover_items(&mirror), MAX_ITEMS, "full, not yet compacted");
        // The switch that compacts: the latest items kept, itself the last.
        commit(&mirror, &state(MAX_ITEMS as u64 + 1)).expect("switched");
        assert_eq!(recover_items(&mirror), KEPT_ITEMS);
        assert_eq!(
            recover(&mirror).expect("reads"),
            Some(state(MAX_ITEMS as u64 + 1)),
            "the compacting switch is in force"
        );
        for counter in MAX_ITEMS as u64 + 2..=MAX_ITEMS as u64 + 5 {
            commit(&mirror, &state(counter)).expect("switched");
        }
        let items = recover_items(&mirror);
        assert!(items <= MAX_ITEMS, "{items} items");
        assert!(items >= KEPT_ITEMS, "{items} items");
        assert_eq!(
            recover(&mirror).expect("reads"),
            Some(state(MAX_ITEMS as u64 + 5)),
            "the newest is in force"
        );
    }

    /// WP-7.2c: a re-verification that appends nothing still repairs a damaged view.
    #[test]
    fn an_unchanged_switch_repairs_its_views() {
        let mirror = scratch("repair");
        commit(&mirror, &state(2)).expect("switched");
        std::fs::write(mirror.join(VERIFIED), b"damaged").expect("damaged");
        let again = MirrorState {
            verified_at: 1_800_000_000,
            ..state(2)
        };
        commit(&mirror, &again).expect("re-verified");
        assert_eq!(recover_items(&mirror), 1, "nothing appended");
        assert_eq!(
            std::fs::read(mirror.join(VERIFIED)).expect("a view"),
            state(2).verified,
            "the view is the journal's again"
        );
    }

    /// WP-7.2d: a peek reads the state in force and changes nothing: a torn tail stays as it is,
    /// for the switch that may still be writing it, and no view is rewritten.
    #[test]
    fn a_peek_reads_the_state_in_force_and_writes_nothing() {
        let mirror = scratch("peek");
        assert_eq!(peek(&mirror).expect("reads"), None);
        commit(&mirror, &state(1)).expect("switched");
        commit(&mirror, &state(2)).expect("switched again");
        let mut torn = std::fs::read(mirror.join(JOURNAL)).expect("the journal");
        torn.extend_from_slice(&state(3).encode().expect("encodes")[..20]);
        std::fs::write(mirror.join(JOURNAL), &torn).expect("a torn write");
        std::fs::write(mirror.join(VERIFIED), b"behind").expect("a view behind");

        assert_eq!(
            peek(&mirror).expect("reads"),
            Some(state(2)),
            "the last whole item"
        );
        assert_eq!(
            std::fs::read(mirror.join(JOURNAL)).expect("the journal"),
            torn,
            "nothing cut"
        );
        assert_eq!(
            std::fs::read(mirror.join(VERIFIED)).expect("a view"),
            b"behind",
            "no view rewritten"
        );
    }

    /// WP-7.2d: the first switch writes the mirror's layout version; a mirror of another layout is
    /// refused by both the switch and the recovery, its journal left untouched.
    #[test]
    fn a_mirror_of_another_layout_is_refused() {
        let mirror = scratch("layout");
        commit(&mirror, &state(1)).expect("switched");
        let dir = Dir::open(&mirror).expect("opens");
        assert_eq!(
            write::read_view(&dir, FORMAT, format::VIEW).expect("reads"),
            Some(LAYOUT.to_be_bytes().to_vec())
        );
        write::replace_view(&dir, FORMAT, format::VIEW, &2u64.to_be_bytes()).expect("written");
        let refused = recover(&mirror).expect_err("another layout");
        assert!(refused.contains("layout is 2"), "{refused}");
        let refused = commit(&mirror, &state(2)).expect_err("another layout");
        assert!(refused.contains("layout is 2"), "{refused}");
        assert_eq!(recover_items(&mirror), 1, "nothing appended");
        write::replace_view(&dir, FORMAT, format::VIEW, b"one").expect("written");
        let refused = recover(&mirror).expect_err("not a layout");
        assert!(refused.contains("layout is unreadable"), "{refused}");
    }

    /// WP-7.2c: a JSON checkpoint ahead of the journal is never rewritten backwards.
    #[test]
    fn a_checkpoint_ahead_of_the_journal_is_never_rewound() {
        let mirror = scratch("ahead");
        commit(&mirror, &state(2)).expect("switched");
        let store = FsStore::new(&mirror);
        checkpoint::write(&store, REFS_MAIN, &state(9).json()).expect("written");
        let views = std::fs::read(mirror.join(CHECKPOINT)).expect("a view");
        let refused = recover(&mirror).expect_err("ahead of the journal");
        assert!(refused.contains("ahead of its journal"), "{refused}");
        let refused = commit(&mirror, &state(3)).expect_err("ahead of the switch");
        assert!(refused.contains("ahead of its journal"), "{refused}");
        assert_eq!(
            recover_items(&mirror),
            1,
            "nothing appended behind a checkpoint ahead"
        );
        assert_eq!(
            std::fs::read(mirror.join(CHECKPOINT)).expect("a view"),
            views,
            "no view rewound"
        );
        assert_eq!(
            checkpoint::read(&store, REFS_MAIN)
                .expect("reads")
                .expect("held")
                .counter,
            9,
            "left as it is"
        );
    }
}
