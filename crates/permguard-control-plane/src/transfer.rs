// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Durable transfer sessions (WP-7.12; owner decisions of 2026-10-14).
//!
//! A negotiation opens a session that every later message of the transfer names by its
//! `transfer_id`. The session binds who opened it and what for, reserves the bytes a push may
//! land, and pins the objects the transfer may touch, so garbage collection keeps them.
//!
//! ```text
//! <ledger>/transfers/<transfer_id hex>.cbor     one closed CBOR record per session
//!
//!   open ──commit──▶ committed ─┐
//!     │                         ├─ grace (`storage.gc.grace`) ─▶ removed: pins and answer released
//!     ├──refused────▶ aborted ──┤
//!     └──expiry─────▶ expired ──┘
//! ```
//!
//! Every transition replaces the record atomically, under the ledger's transfer lock, before it is
//! answered. Nothing about a session lives only in memory: the reservation and the pins are read
//! from the records whenever they are needed, so a restart recovers them by reading the directory,
//! and a garbage-collection pass sees the sessions every other process left. A pull session holds no
//! reservation and keeps no answer, so it is removed at its expiry without a grace.
//!
//! | Label | Field               | Type                                      |
//! | ----: | ------------------- | ----------------------------------------- |
//! |     1 | `transfer_id`       | 16 bytes                                  |
//! |     2 | `direction`         | 1 push, 2 pull                            |
//! |     3 | `principal`         | text                                      |
//! |     4 | `authority_host_id` | 16 bytes                                  |
//! |     5 | `zone`              | text, the zone id                         |
//! |     6 | `ledger`            | text, the ledger id                       |
//! |     7 | `ref`               | text                                      |
//! |     8 | `request_id`        | text, empty for a pull                    |
//! |     9 | `parameters`        | digest of the normalized request          |
//! |    10 | `new_head`          | digest, a push's                          |
//! |    11 | `expected_ref`      | `{1 counter, 2 digest}`, optional         |
//! |    12 | `max_batch_bytes`   | uint                                      |
//! |    13 | `max_batch_objects` | uint                                      |
//! |    14 | `reservation`       | uint, bytes                               |
//! |    15 | `landed`            | uint, bytes                               |
//! |    16 | `expiry`            | uint, unix seconds                        |
//! |    17 | `state`             | 1 open, 2 committed, 3 aborted, 4 expired |
//! |    18 | `closed_at`         | uint, unix seconds, optional              |
//! |    19 | `pins`              | array of digests, sorted, unique          |
//! |    20 | `result`            | bytes, a committed answer, optional       |

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::MutexGuard;
use std::time::Duration;

use permguard_notp::ExpectedRef;
use permguard_objects::cbor::{self, Value};
use permguard_objects::digest::Digest;

use crate::store::{FileObjectStore, StoreError};

/// The directory below the ledger.
pub const DIRECTORY: &str = "transfers";
/// The most sessions one ledger keeps open at once.
pub const MAX_OPEN: usize = 256;
/// The most pushes one principal keeps open on one ledger.
pub const MAX_OPEN_PER_PRINCIPAL: usize = 32;
/// The most closed pushes one principal's records keep on one ledger, the oldest retired first:
/// a closed push is kept for a retry, never past what a retry needs.
pub const KEEP_CLOSED_PER_PRINCIPAL: usize = 64;
/// The largest record a session may take: its pins dominate it.
pub const MAX_RECORD_BYTES: usize = 32 * 1024 * 1024;

/// Which way a transfer moves objects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Push,
    Pull,
}

/// Where a session stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Open,
    Committed,
    Aborted,
    Expired,
}

/// One transfer session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub transfer_id: [u8; 16],
    pub direction: Direction,
    pub principal: String,
    pub authority_host_id: [u8; 16],
    pub zone: String,
    pub ledger: String,
    pub r#ref: String,
    pub request_id: String,
    pub parameters: Digest,
    pub new_head: Option<Digest>,
    pub expected_ref: Option<ExpectedRef>,
    pub max_batch_bytes: u64,
    pub max_batch_objects: u64,
    pub reservation: u64,
    pub landed: u64,
    pub expiry: u64,
    pub state: State,
    pub closed_at: Option<u64>,
    pub pins: Vec<Digest>,
    pub result: Option<Vec<u8>>,
}

impl Session {
    /// Whether it is open and its expiry has not come.
    pub fn live(&self, now: u64) -> bool {
        self.state == State::Open && now < self.expiry
    }

    /// What its reservation still holds back from the ledger's quota.
    pub fn unlanded(&self) -> u64 {
        if self.state == State::Open {
            self.reservation.saturating_sub(self.landed)
        } else {
            0
        }
    }

    /// Whether `digest` is one the transfer may move.
    pub fn pinned(&self, digest: &Digest) -> bool {
        self.pins.binary_search(digest).is_ok()
    }

    /// The closed CBOR record.
    pub fn encode(&self) -> Result<Vec<u8>, StoreError> {
        let uint = |value: u64| {
            i64::try_from(value)
                .map(Value::Int)
                .map_err(|_| invalid("a session value is past the signed 64-bit range"))
        };
        let mut pairs = vec![
            (1, Value::Bytes(self.transfer_id.to_vec())),
            (
                2,
                Value::Int(match self.direction {
                    Direction::Push => 1,
                    Direction::Pull => 2,
                }),
            ),
            (3, Value::Text(self.principal.clone())),
            (4, Value::Bytes(self.authority_host_id.to_vec())),
            (5, Value::Text(self.zone.clone())),
            (6, Value::Text(self.ledger.clone())),
            (7, Value::Text(self.r#ref.clone())),
            (8, Value::Text(self.request_id.clone())),
            (9, Value::Text(self.parameters.to_string())),
            (12, uint(self.max_batch_bytes)?),
            (13, uint(self.max_batch_objects)?),
            (14, uint(self.reservation)?),
            (15, uint(self.landed)?),
            (16, uint(self.expiry)?),
            (
                17,
                Value::Int(match self.state {
                    State::Open => 1,
                    State::Committed => 2,
                    State::Aborted => 3,
                    State::Expired => 4,
                }),
            ),
            (
                19,
                Value::Array(
                    self.pins
                        .iter()
                        .map(|digest| Value::Text(digest.to_string()))
                        .collect(),
                ),
            ),
        ];
        if let Some(head) = &self.new_head {
            pairs.push((10, Value::Text(head.to_string())));
        }
        if let Some(expected) = &self.expected_ref {
            pairs.push((
                11,
                Value::Map(vec![
                    (Value::Int(1), uint(expected.counter)?),
                    (Value::Int(2), Value::Text(expected.digest.to_string())),
                ]),
            ));
        }
        if let Some(at) = self.closed_at {
            pairs.push((18, uint(at)?));
        }
        if let Some(result) = &self.result {
            pairs.push((20, Value::Bytes(result.clone())));
        }
        cbor::encode(&Value::Map(
            pairs
                .into_iter()
                .map(|(key, value)| (Value::Int(key), value))
                .collect(),
        ))
        .map_err(|error| invalid(format!("encoding a session: {error}")))
    }

    /// Reads a record, refusing one that is not canonical, carries a label this build does not
    /// know, or lacks one it needs.
    pub fn decode(bytes: &[u8]) -> Result<Self, StoreError> {
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(invalid("a session record is past its bound"));
        }
        let Value::Map(map) = cbor::decode_canonical(bytes)
            .map_err(|error| invalid(format!("a session record: {error}")))?
        else {
            return Err(invalid("a session record is a map"));
        };
        const KNOWN: [i64; 20] = [
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
        ];
        if map
            .iter()
            .any(|(key, _)| !matches!(key, Value::Int(label) if KNOWN.contains(label)))
        {
            return Err(invalid("a session record carries an unknown label"));
        }
        let field = |label: i64| {
            map.iter()
                .find(|(key, _)| *key == Value::Int(label))
                .map(|(_, value)| value)
        };
        let need =
            |label: i64| field(label).ok_or_else(|| invalid("a session record misses a field"));
        let text = |label: i64| match need(label)? {
            Value::Text(text) => Ok(text.clone()),
            _ => Err(invalid("a session field is text")),
        };
        let uint = |value: &Value| match value {
            Value::Int(int) => {
                u64::try_from(*int).map_err(|_| invalid("a session field is unsigned"))
            }
            _ => Err(invalid("a session field is an integer")),
        };
        let digest = |value: &Value| match value {
            Value::Text(text) => {
                Digest::parse(text).map_err(|_| invalid("a session field is a digest"))
            }
            _ => Err(invalid("a session field is a digest")),
        };
        let id = |label: i64| match need(label)? {
            Value::Bytes(bytes) => <[u8; 16]>::try_from(bytes.as_slice())
                .map_err(|_| invalid("a session id is 16 bytes")),
            _ => Err(invalid("a session id is bytes")),
        };
        let pins = match need(19)? {
            Value::Array(items) => items.iter().map(digest).collect::<Result<Vec<_>, _>>()?,
            _ => return Err(invalid("a session's pins are an array")),
        };
        if !pins.windows(2).all(|pair| pair[0] < pair[1]) {
            return Err(invalid("a session's pins are sorted, each once"));
        }
        let expected_ref = match field(11) {
            None => None,
            Some(Value::Map(pairs)) => {
                let member = |label: i64| {
                    pairs
                        .iter()
                        .find(|(key, _)| *key == Value::Int(label))
                        .map(|(_, value)| value)
                        .ok_or_else(|| invalid("an expected ref misses a field"))
                };
                if pairs.len() != 2 {
                    return Err(invalid("an expected ref is {counter, digest}"));
                }
                Some(ExpectedRef {
                    counter: uint(member(1)?)?,
                    digest: digest(member(2)?)?,
                })
            }
            Some(_) => return Err(invalid("an expected ref is a map")),
        };
        let session = Self {
            transfer_id: id(1)?,
            direction: match uint(need(2)?)? {
                1 => Direction::Push,
                2 => Direction::Pull,
                _ => return Err(invalid("a session's direction is 1 or 2")),
            },
            principal: text(3)?,
            authority_host_id: id(4)?,
            zone: text(5)?,
            ledger: text(6)?,
            r#ref: text(7)?,
            request_id: text(8)?,
            parameters: digest(need(9)?)?,
            new_head: field(10).map(digest).transpose()?,
            expected_ref,
            max_batch_bytes: uint(need(12)?)?,
            max_batch_objects: uint(need(13)?)?,
            reservation: uint(need(14)?)?,
            landed: uint(need(15)?)?,
            expiry: uint(need(16)?)?,
            state: match uint(need(17)?)? {
                1 => State::Open,
                2 => State::Committed,
                3 => State::Aborted,
                4 => State::Expired,
                _ => return Err(invalid("a session's state is 1 to 4")),
            },
            closed_at: field(18).map(uint).transpose()?,
            pins,
            result: match field(20) {
                None => None,
                Some(Value::Bytes(bytes)) => Some(bytes.clone()),
                Some(_) => return Err(invalid("a session's result is bytes")),
            },
        };
        if (session.state == State::Open) == session.closed_at.is_some() {
            return Err(invalid("a session is closed exactly when it is not open"));
        }
        Ok(session)
    }
}

fn invalid(detail: impl Into<String>) -> StoreError {
    StoreError::Backend {
        detail: detail.into(),
    }
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// What one sweep of a ledger's sessions did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Swept {
    /// Open sessions past their expiry, closed `expired`.
    pub expired: usize,
    /// Records removed: terminal pushes past the grace, pulls past their expiry.
    pub removed: usize,
}

/// One ledger's sessions, read and written under its transfer lock.
pub struct Transfers<'a> {
    root: PathBuf,
    store: &'a FileObjectStore,
    _guard: MutexGuard<'a, ()>,
}

impl<'a> Transfers<'a> {
    pub(crate) fn new(store: &'a FileObjectStore, guard: MutexGuard<'a, ()>) -> Self {
        Self {
            root: store.root().to_path_buf(),
            store,
            _guard: guard,
        }
    }

    fn directory(&self) -> PathBuf {
        self.root.join(DIRECTORY)
    }

    fn name(transfer_id: &[u8; 16]) -> String {
        format!("{}.cbor", hex(transfer_id))
    }

    /// The session `transfer_id` names, when this ledger keeps one.
    pub fn get(&self, transfer_id: &[u8; 16]) -> Result<Option<Session>, StoreError> {
        let path = self.directory().join(Self::name(transfer_id));
        match std::fs::read(&path) {
            Ok(bytes) => {
                let session = Session::decode(&bytes)?;
                if session.transfer_id != *transfer_id {
                    return Err(invalid(format!("{} holds another session", path.display())));
                }
                Ok(Some(session))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(invalid(format!("reading a session: {error}"))),
        }
    }

    /// Every session this ledger keeps. A record that does not read stops the listing: a
    /// reservation or a pin it may hold is not one to forget.
    pub fn list(&self) -> Result<Vec<Session>, StoreError> {
        let entries = match std::fs::read_dir(self.directory()) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(invalid(format!("listing sessions: {error}"))),
        };
        let mut sessions = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|error| invalid(format!("listing sessions: {error}")))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            // The storage library's temporaries are swept with the ledger's.
            if !name.ends_with(".cbor") {
                continue;
            }
            let bytes = std::fs::read(entry.path())
                .map_err(|error| invalid(format!("reading a session: {error}")))?;
            sessions.push(Session::decode(&bytes)?);
        }
        sessions.sort_by_key(|session| session.transfer_id);
        Ok(sessions)
    }

    /// Writes `session`, durably, replacing what it was.
    pub fn put(&self, session: &Session) -> Result<(), StoreError> {
        let bytes = session.encode()?;
        crate::store::write_durable(
            &self.root,
            &format!("{DIRECTORY}/{}", Self::name(&session.transfer_id)),
            &bytes,
        )
    }

    /// Removes the record of `transfer_id`, and with it what it pins.
    pub fn remove(&self, transfer_id: &[u8; 16]) -> Result<(), StoreError> {
        let dir = permguard_host::storage::Dir::create_root(&self.root)
            .and_then(|root| root.subdir(DIRECTORY, true))
            .map_err(|error| invalid(format!("opening the sessions: {error}")))?;
        dir.unlink(&Self::name(transfer_id))
            .map_err(|error| invalid(format!("removing a session: {error}")))?;
        Ok(())
    }

    /// The session `principal` opened in `direction` with `request_id`, when it is still kept.
    pub fn find_request(
        &self,
        principal: &str,
        direction: Direction,
        request_id: &str,
    ) -> Result<Option<Session>, StoreError> {
        Ok(self.list()?.into_iter().find(|session| {
            session.direction == direction
                && session.principal == principal
                && session.request_id == request_id
        }))
    }

    /// Closes what expired and removes what its grace no longer keeps. An open session past its
    /// expiry is written `expired` before anything it reserved is released; a push's terminal
    /// record is kept for `grace`, so a retry learns the same answer and its pins hold.
    pub fn sweep(&self, now: u64, grace: Duration) -> Result<Swept, StoreError> {
        let mut swept = Swept::default();
        for mut session in self.list()? {
            if session.state == State::Open && now >= session.expiry {
                if session.direction == Direction::Pull {
                    self.remove(&session.transfer_id)?;
                    swept.removed += 1;
                    continue;
                }
                session.state = State::Expired;
                session.closed_at = Some(now);
                self.put(&session)?;
                swept.expired += 1;
                continue;
            }
            if let Some(closed) = session.closed_at
                && now >= closed.saturating_add(grace.as_secs())
            {
                self.remove(&session.transfer_id)?;
                swept.removed += 1;
            }
        }
        Ok(swept)
    }

    /// Retires `principal`'s closed records past the `keep` most recent: a retry is answered
    /// from a recent one, and a caller's closed pushes do not grow without bound.
    pub fn retire(&self, principal: &str, keep: usize) -> Result<usize, StoreError> {
        let mut closed: Vec<Session> = self
            .list()?
            .into_iter()
            .filter(|session| session.principal == principal && session.closed_at.is_some())
            .collect();
        if closed.len() <= keep {
            return Ok(0);
        }
        closed.sort_by_key(|session| session.closed_at);
        let surplus = closed.len() - keep;
        for session in &closed[..surplus] {
            self.remove(&session.transfer_id)?;
        }
        Ok(surplus)
    }

    /// What the open pushes still hold back from the ledger's quota.
    pub fn reserved(&self) -> Result<u64, StoreError> {
        Ok(self
            .list()?
            .iter()
            .map(Session::unlanded)
            .fold(0u64, u64::saturating_add))
    }

    /// Every object a kept session pins: what garbage collection may not remove.
    pub fn pins(&self) -> Result<BTreeSet<Digest>, StoreError> {
        Ok(self
            .list()?
            .into_iter()
            .flat_map(|session| session.pins)
            .collect())
    }

    /// The store the sessions belong to.
    pub fn store(&self) -> &FileObjectStore {
        self.store
    }

    /// Where they live, for a test.
    pub fn root(&self) -> &Path {
        &self.root
    }
}

/// The current unix time, in seconds, from a clock that answers signed seconds.
pub fn unix_now(clock: &dyn permguard_core::time::Clock) -> u64 {
    u64::try_from(clock.now()).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "permguard-transfer-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    pub(crate) fn push(id: u8, principal: &str, request_id: &str) -> Session {
        Session {
            transfer_id: [id; 16],
            direction: Direction::Push,
            principal: principal.to_owned(),
            authority_host_id: [1; 16],
            zone: "zone".to_owned(),
            ledger: "ledger".to_owned(),
            r#ref: "main".to_owned(),
            request_id: request_id.to_owned(),
            parameters: Digest::compute(b"parameters"),
            new_head: Some(Digest::compute(b"head")),
            expected_ref: Some(ExpectedRef {
                counter: 3,
                digest: Digest::compute(b"state"),
            }),
            max_batch_bytes: 1024,
            max_batch_objects: 10,
            reservation: 500,
            landed: 120,
            expiry: 1_000,
            state: State::Open,
            closed_at: None,
            pins: {
                let mut pins = vec![Digest::compute(b"a"), Digest::compute(b"b")];
                pins.sort();
                pins
            },
            result: None,
        }
    }

    #[test]
    fn a_session_round_trips_and_refuses_what_it_does_not_know() {
        let mut session = push(7, "alice", "push-1");
        assert_eq!(
            Session::decode(&session.encode().unwrap()).unwrap(),
            session
        );
        session.state = State::Committed;
        session.closed_at = Some(900);
        session.result = Some(b"answer".to_vec());
        session.expected_ref = None;
        assert_eq!(
            Session::decode(&session.encode().unwrap()).unwrap(),
            session
        );

        let Value::Map(mut map) = cbor::decode_canonical(&session.encode().unwrap()).unwrap()
        else {
            unreachable!()
        };
        map.push((Value::Int(21), Value::Int(1)));
        let unknown = cbor::encode(&Value::Map(map)).unwrap();
        assert!(Session::decode(&unknown).is_err());

        // Open with a closing time, or closed without one, is no state.
        let mut torn = push(7, "alice", "push-1");
        torn.closed_at = Some(1);
        assert!(Session::decode(&torn.encode().unwrap()).is_err());
        // Pins out of order are refused: the record has one spelling.
        let mut unsorted = push(7, "alice", "push-1");
        unsorted.pins.reverse();
        assert!(Session::decode(&unsorted.encode().unwrap()).is_err());
    }

    #[test]
    fn sessions_are_kept_reserved_pinned_expired_and_released() {
        let store = FileObjectStore::new(scratch("lifecycle"));
        let transfers = store.transfers().unwrap();
        transfers.put(&push(1, "alice", "push-1")).unwrap();
        let mut pull = push(2, "bob", "");
        pull.direction = Direction::Pull;
        pull.reservation = 0;
        pull.landed = 0;
        pull.new_head = None;
        pull.expected_ref = None;
        transfers.put(&pull).unwrap();

        assert_eq!(transfers.reserved().unwrap(), 380);
        assert_eq!(transfers.pins().unwrap().len(), 2);
        assert_eq!(
            transfers
                .find_request("alice", Direction::Push, "push-1")
                .unwrap()
                .map(|session| session.transfer_id),
            Some([1; 16])
        );
        assert!(
            transfers
                .find_request("mallory", Direction::Push, "push-1")
                .unwrap()
                .is_none()
        );

        // Before the expiry nothing moves.
        assert_eq!(
            transfers.sweep(999, Duration::from_secs(60)).unwrap(),
            Swept::default()
        );
        // At it, the push is closed `expired` and keeps its pins; the pull is gone.
        assert_eq!(
            transfers.sweep(1_000, Duration::from_secs(60)).unwrap(),
            Swept {
                expired: 1,
                removed: 1
            }
        );
        let expired = transfers.get(&[1; 16]).unwrap().unwrap();
        assert_eq!(
            (expired.state, expired.closed_at),
            (State::Expired, Some(1_000))
        );
        assert_eq!(
            transfers.reserved().unwrap(),
            0,
            "the reservation is released"
        );
        assert_eq!(
            transfers.pins().unwrap().len(),
            2,
            "the pins hold for the grace"
        );
        // Past the grace the record goes, and its pins with it.
        assert_eq!(
            transfers.sweep(1_059, Duration::from_secs(60)).unwrap(),
            Swept::default()
        );
        assert_eq!(
            transfers.sweep(1_060, Duration::from_secs(60)).unwrap(),
            Swept {
                expired: 0,
                removed: 1
            }
        );
        assert!(transfers.get(&[1; 16]).unwrap().is_none());
        assert!(transfers.pins().unwrap().is_empty());
    }

    /// A caller's closed records are kept to a bound, the oldest retired first; another
    /// caller's and the open ones are not touched.
    #[test]
    fn closed_records_are_retired_oldest_first() {
        let store = FileObjectStore::new(scratch("retire"));
        let transfers = store.transfers().unwrap();
        for at in 1..=5u8 {
            let mut closed = push(at, "alice", &format!("push-{at}"));
            closed.state = State::Aborted;
            closed.closed_at = Some(u64::from(at));
            transfers.put(&closed).unwrap();
        }
        transfers.put(&push(9, "alice", "open")).unwrap();
        let mut other = push(10, "bob", "push-1");
        other.state = State::Committed;
        other.closed_at = Some(1);
        transfers.put(&other).unwrap();

        assert_eq!(transfers.retire("alice", 2).unwrap(), 3);
        let kept: Vec<[u8; 16]> = transfers
            .list()
            .unwrap()
            .into_iter()
            .map(|session| session.transfer_id)
            .collect();
        assert_eq!(kept, vec![[4; 16], [5; 16], [9; 16], [10; 16]]);
    }

    /// A record that does not read stops the listing rather than being skipped: what it reserved
    /// and pinned is not forgotten.
    #[test]
    fn a_damaged_record_stops_the_listing() {
        let store = FileObjectStore::new(scratch("damaged"));
        let transfers = store.transfers().unwrap();
        transfers.put(&push(1, "alice", "push-1")).unwrap();
        std::fs::write(
            transfers
                .root()
                .join(DIRECTORY)
                .join(format!("{}.cbor", hex(&[9; 16]))),
            b"rot",
        )
        .unwrap();
        assert!(transfers.list().is_err());
        assert!(transfers.pins().is_err());
    }
}
