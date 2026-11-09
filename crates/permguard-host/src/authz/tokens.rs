// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The IAM Host's access tokens and their status lists (iteration 02, WP-11.5, `2-security/9`
//! The list): every token issued is recorded with the list entry its status is read from, and
//! every status change is a transition of the same journal.
//!
//! ```text
//! host/authz/tokens/journal/     one frame per transition, kind 1, a TokenTransition
//! ```
//!
//! A transition is a closed CBOR map with integer labels (`contracts/cbor/tokens.json`):
//!
//! | Label | Member          | Type          | In                                                    |
//! | ----- | --------------- | ------------- | ----------------------------------------------------- |
//! | 1     | `kind`          | text          | every transition                                      |
//! | 2     | `revision`      | uint          | every transition                                      |
//! | 3     | `at`            | uint, seconds | every transition                                      |
//! | 4     | `by`            | text          | every transition: who made it                         |
//! | 5     | `operation_id`  | bytes, 16     | optional: the security mutation that made it          |
//! | 6     | `list_id`       | bytes, 16     | `list.open`, `list.retire`, `token.issue`             |
//! | 7     | `index`         | uint          | `token.issue`: the entry of the list                  |
//! | 8     | `jti`           | bytes, 16     | `token.issue`, `token.status`                         |
//! | 9     | `subject`       | text          | `token.issue`: `sa:<name>`, `user:<name>` or `oidc:…` |
//! | 10    | `client_id`     | text          | `token.issue`                                         |
//! | 11    | `family`        | text          | `token.issue`: `application` or `administration`      |
//! | 12    | `audience`      | array of text | `token.issue`                                         |
//! | 13    | `scope`         | text          | `token.issue`: the operations, space separated        |
//! | 14    | `expires_at`    | uint, seconds | `token.issue`                                         |
//! | 15    | `status`        | uint          | `token.status`: 0 valid, 1 invalid, 2 suspended       |
//! | 16    | `account`       | text          | optional, `token.issue`: the service account          |
//! | 17    | `credential_id` | bytes, 16     | optional, `token.issue`: the credential it proved     |
//! | 18    | `role`          | text          | optional, `token.issue`: the role it was elevated to  |
//!
//! An index is drawn at random among the free entries of the open list and never drawn again in
//! that list. A list is open until half its entries are drawn; it retires once every token it
//! holds has expired, and its tokens are forgotten with it. `INVALID` is terminal.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError, RwLock};

use permguard_objects::cbor::{self, Value};
use permguard_objects::status_list::{ENTRIES, StatusList};
use ring::rand::SecureRandom as _;

use super::record::{Labelled, RecordError, texts, uint};
use crate::identity::record::{uuid_text, uuid_v7};
use crate::operations::journal::OperationId;
use crate::operations::mutation::Applying;
use crate::storage::StorageError;
use crate::storage::journal::{Journal, Options, Recovery};
use crate::storage::volume::Volume;

/// The registry's folder below `host/authz/`.
pub const TOKENS: &str = "tokens";
/// Its journal's folder.
pub const JOURNAL: &str = "journal";
/// The one frame kind: a [`TokenTransition`].
pub const FRAME_TRANSITION: u16 = 1;
/// A transition larger than this is refused before it is parsed.
pub const MAX_TRANSITION_BYTES: usize = 16 * 1024;
/// Bits per entry of every list.
pub const BITS: u8 = 2;
/// A list stays open until this many of its entries are drawn.
pub const OPEN_UNTIL: usize = ENTRIES / 2;
/// The most audience entries a token names.
pub const MAX_AUDIENCE: usize = 16;

/// The values of an entry.
pub mod status {
    pub const VALID: u8 = 0;
    /// Revoked: terminal.
    pub const INVALID: u8 = 1;
    /// Its service account is suspended.
    pub const SUSPENDED: u8 = 2;

    /// The value's name.
    pub fn name(value: u8) -> &'static str {
        match value {
            VALID => "valid",
            INVALID => "invalid",
            SUSPENDED => "suspended",
            _ => "unknown",
        }
    }
}

/// The kinds of transition.
pub mod kinds {
    pub const LIST_OPEN: &str = "list.open";
    pub const LIST_RETIRE: &str = "list.retire";
    pub const TOKEN_ISSUE: &str = "token.issue";
    pub const TOKEN_STATUS: &str = "token.status";
    /// Every kind, as the journal spells it.
    pub const ALL: &[&str] = &[LIST_OPEN, LIST_RETIRE, TOKEN_ISSUE, TOKEN_STATUS];
}

/// One transition, as the journal holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenTransition {
    pub kind: String,
    pub revision: u64,
    pub at: u64,
    pub by: String,
    pub operation_id: Option<OperationId>,
    pub list_id: Option<[u8; 16]>,
    pub index: Option<u64>,
    pub jti: Option<[u8; 16]>,
    pub subject: Option<String>,
    pub client_id: Option<String>,
    pub family: Option<String>,
    pub audience: Option<Vec<String>>,
    pub scope: Option<String>,
    pub expires_at: Option<u64>,
    pub status: Option<u64>,
    pub account: Option<String>,
    pub credential_id: Option<[u8; 16]>,
    pub role: Option<String>,
}

fn id16(bytes: Vec<u8>, what: &str) -> Result<[u8; 16], RecordError> {
    <[u8; 16]>::try_from(bytes.as_slice())
        .map_err(|_| RecordError::Malformed(format!("{what} is 16 bytes")))
}

impl TokenTransition {
    /// A transition of `kind`, with nothing else set.
    pub fn new(kind: &str) -> Self {
        Self {
            kind: kind.to_owned(),
            revision: 0,
            at: 0,
            by: String::new(),
            operation_id: None,
            list_id: None,
            index: None,
            jti: None,
            subject: None,
            client_id: None,
            family: None,
            audience: None,
            scope: None,
            expires_at: None,
            status: None,
            account: None,
            credential_id: None,
            role: None,
        }
    }

    /// The canonical bytes.
    pub fn encode(&self) -> Result<Vec<u8>, RecordError> {
        let mut pairs = vec![
            (Value::Int(1), Value::Text(self.kind.clone())),
            (Value::Int(2), uint(self.revision)?),
            (Value::Int(3), uint(self.at)?),
            (Value::Int(4), Value::Text(self.by.clone())),
        ];
        let bytes = |label: i64, value: &Option<[u8; 16]>| {
            value.map(|value| (Value::Int(label), Value::Bytes(value.to_vec())))
        };
        let text = |label: i64, value: &Option<String>| {
            value
                .as_ref()
                .map(|value| (Value::Int(label), Value::Text(value.clone())))
        };
        pairs.extend(
            self.operation_id
                .map(|id| (Value::Int(5), Value::Bytes(id.as_bytes().to_vec()))),
        );
        pairs.extend(bytes(6, &self.list_id));
        if let Some(index) = self.index {
            pairs.push((Value::Int(7), uint(index)?));
        }
        pairs.extend(bytes(8, &self.jti));
        pairs.extend(text(9, &self.subject));
        pairs.extend(text(10, &self.client_id));
        pairs.extend(text(11, &self.family));
        if let Some(audience) = &self.audience {
            pairs.push((Value::Int(12), texts(audience)));
        }
        pairs.extend(text(13, &self.scope));
        if let Some(expires_at) = self.expires_at {
            pairs.push((Value::Int(14), uint(expires_at)?));
        }
        if let Some(status) = self.status {
            pairs.push((Value::Int(15), uint(status)?));
        }
        pairs.extend(text(16, &self.account));
        pairs.extend(bytes(17, &self.credential_id));
        pairs.extend(text(18, &self.role));
        cbor::encode(&Value::Map(pairs)).map_err(|error| RecordError::Cbor(error.to_string()))
    }

    /// Reads the canonical bytes, refusing an unknown label, a missing required one, a value of
    /// another type, an unknown kind, or more than [`MAX_TRANSITION_BYTES`].
    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        if bytes.len() > MAX_TRANSITION_BYTES {
            return Err(RecordError::TooLarge(bytes.len()));
        }
        let value =
            cbor::decode_canonical(bytes).map_err(|error| RecordError::Cbor(error.to_string()))?;
        let mut map = Labelled::new(value, 18)?;
        let transition = Self {
            kind: map.text(1)?,
            revision: map.uint(2)?,
            at: map.uint(3)?,
            by: map.text(4)?,
            operation_id: map.optional_operation_id(5)?,
            list_id: map
                .optional_bytes(6)?
                .map(|bytes| id16(bytes, "a list id"))
                .transpose()?,
            index: map.optional_uint(7)?,
            jti: map
                .optional_bytes(8)?
                .map(|bytes| id16(bytes, "a jti"))
                .transpose()?,
            subject: map.optional_text(9)?,
            client_id: map.optional_text(10)?,
            family: map.optional_text(11)?,
            audience: map.optional_texts(12)?,
            scope: map.optional_text(13)?,
            expires_at: map.optional_uint(14)?,
            status: map.optional_uint(15)?,
            account: map.optional_text(16)?,
            credential_id: map
                .optional_bytes(17)?
                .map(|bytes| id16(bytes, "a credential id"))
                .transpose()?,
            role: map.optional_text(18)?,
        };
        map.finish()?;
        if !kinds::ALL.contains(&transition.kind.as_str()) {
            return Err(RecordError::Malformed(format!(
                "`{}` is not a token transition",
                transition.kind
            )));
        }
        Ok(transition)
    }
}

/// Why the registry refused or failed.
#[derive(Debug)]
pub enum TokenError {
    Storage(StorageError),
    Record(RecordError),
    /// A request the registry never writes.
    Invalid(String),
    /// What it names is not held.
    NotFound(String),
    /// The OS random source failed.
    Random,
}

impl std::fmt::Display for TokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Storage(error) => write!(f, "the token journal: {error}"),
            Self::Record(error) => write!(f, "a token transition: {error}"),
            Self::Invalid(detail) | Self::NotFound(detail) => f.write_str(detail),
            Self::Random => f.write_str("the OS random source failed"),
        }
    }
}

impl std::error::Error for TokenError {}

impl From<StorageError> for TokenError {
    fn from(error: StorageError) -> Self {
        Self::Storage(error)
    }
}

impl From<RecordError> for TokenError {
    fn from(error: RecordError) -> Self {
        Self::Record(error)
    }
}

/// What a token is issued for: everything the journal records of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenDraft {
    pub subject: String,
    pub client_id: String,
    pub family: String,
    pub audience: Vec<String>,
    pub scope: String,
    pub expires_at: u64,
    pub account: Option<String>,
    pub credential_id: Option<[u8; 16]>,
    /// The role the subject elevated to, as `role:<name>`.
    pub role: Option<String>,
}

/// One token the registry holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedToken {
    pub jti: [u8; 16],
    pub list_id: [u8; 16],
    pub index: u64,
    pub subject: String,
    pub client_id: String,
    pub family: String,
    pub audience: Vec<String>,
    pub scope: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub account: Option<String>,
    pub credential_id: Option<[u8; 16]>,
    /// The role the subject elevated to, as `role:<name>`.
    pub role: Option<String>,
    pub status: u8,
}

impl IssuedToken {
    /// Its id, as a UUID.
    pub fn jti_text(&self) -> String {
        uuid_text(&self.jti)
    }
}

/// One list the registry holds.
#[derive(Clone)]
struct ListState {
    list: StatusList,
    /// The entries drawn, one bit each.
    drawn: Vec<u64>,
    count: usize,
    /// The latest expiry of a token it holds.
    latest_expiry: u64,
    /// The revision of its last change: what a signed list token is fresh against.
    changed_at: u64,
}

impl ListState {
    fn new() -> Result<Self, TokenError> {
        Ok(Self {
            list: StatusList::new(BITS, ENTRIES)
                .map_err(|error| TokenError::Invalid(error.to_string()))?,
            drawn: vec![0; ENTRIES / 64],
            count: 0,
            latest_expiry: 0,
            changed_at: 0,
        })
    }

    fn is_drawn(&self, index: usize) -> bool {
        self.drawn[index / 64] & (1 << (index % 64)) != 0
    }

    fn draw(&mut self, index: usize) {
        self.drawn[index / 64] |= 1 << (index % 64);
        self.count += 1;
    }
}

#[derive(Clone, Default)]
struct State {
    revision: u64,
    lists: BTreeMap<[u8; 16], ListState>,
    /// The list new tokens draw from.
    open: Option<[u8; 16]>,
    tokens: BTreeMap<[u8; 16], IssuedToken>,
    /// The revision each operation produced and what it named.
    operations: BTreeMap<OperationId, (u64, String)>,
}

/// A list as it stands: what a status list token signs.
#[derive(Debug, Clone)]
pub struct ListView {
    pub list_id: [u8; 16],
    pub list: StatusList,
    /// The registry revision of its last change.
    pub changed_at: u64,
}

/// The IAM Host's token registry of one volume.
pub struct TokenRegistry {
    journal: Mutex<Journal>,
    state: RwLock<State>,
}

impl std::fmt::Debug for TokenRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenRegistry")
            .field("revision", &self.read().revision)
            .finish_non_exhaustive()
    }
}

fn random<const N: usize>() -> Result<[u8; N], TokenError> {
    let mut bytes = [0u8; N];
    ring::rand::SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| TokenError::Random)?;
    Ok(bytes)
}

impl TokenRegistry {
    /// Opens the registry of `volume`, replaying its journal. A transition the replay cannot
    /// apply is corruption, never skipped.
    pub fn open(volume: &Volume) -> Result<(Arc<Self>, Recovery), TokenError> {
        let dir = volume
            .host()
            .subdir(super::store::DIRECTORY, true)?
            .subdir(TOKENS, true)?;
        let (journal, recovery) = Journal::open(
            dir.subdir(JOURNAL, true)?,
            volume.journal_options(Options::default()),
        )?;
        let state = rebuilt(&journal)?;
        Ok((
            Arc::new(Self {
                journal: Mutex::new(journal),
                state: RwLock::new(state),
            }),
            recovery,
        ))
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, State> {
        self.state.read().unwrap_or_else(PoisonError::into_inner)
    }

    /// The registry revision: the number of transitions applied.
    pub fn revision(&self) -> u64 {
        self.read().revision
    }

    /// Writes `transitions` in order. Each is applied to the state, which refuses what the replay
    /// would, then journaled. The state is not copied first: a token write is the hot path and a
    /// list holds `2^20` entries. On any failure the state is read again from the journal, so the
    /// memory never holds what the journal does not.
    fn write(
        &self,
        journal: &mut Journal,
        state: &mut State,
        transitions: Vec<TokenTransition>,
    ) -> Result<(), TokenError> {
        let written = (|| {
            for mut transition in transitions {
                transition.revision = state.revision + 1;
                let bytes = transition.encode()?;
                replay(state, &transition)?;
                journal.append(FRAME_TRANSITION, &bytes)?;
            }
            Ok(())
        })();
        if written.is_err() {
            *state = rebuilt(journal)?;
        }
        written
    }

    /// Records a token for `draft`, issued by `by` at `now`: its `jti` and the list entry its
    /// status is read from. The list is opened, when needed, in the same write.
    pub fn issue(&self, draft: TokenDraft, by: &str, now: u64) -> Result<IssuedToken, TokenError> {
        if draft.audience.is_empty() || draft.audience.len() > MAX_AUDIENCE {
            return Err(TokenError::Invalid(format!(
                "a token names 1 to {MAX_AUDIENCE} audiences"
            )));
        }
        if draft.expires_at <= now {
            return Err(TokenError::Invalid(
                "a token expires after it is issued".to_owned(),
            ));
        }
        let mut journal = self.journal.lock().unwrap_or_else(PoisonError::into_inner);
        let mut state = self.state.write().unwrap_or_else(PoisonError::into_inner);
        let mut transitions = Vec::new();
        let open = match state.open {
            Some(open)
                if state
                    .lists
                    .get(&open)
                    .is_some_and(|list| list.count < OPEN_UNTIL) =>
            {
                open
            }
            _ => {
                let list_id = uuid_v7(now.saturating_mul(1000), random()?);
                let mut opened = TokenTransition::new(kinds::LIST_OPEN);
                opened.at = now;
                opened.by = by.to_owned();
                opened.list_id = Some(list_id);
                transitions.push(opened);
                list_id
            }
        };
        // Drawn at random among the free entries: a list under half full takes two draws on
        // average, and a bound of draws keeps a failing random source from spinning.
        let index = {
            let list = state.lists.get(&open);
            let mut drawn = None;
            for _ in 0..256 {
                let candidate = (u32::from_le_bytes(random()?) as usize) % ENTRIES;
                if !list.is_some_and(|list| list.is_drawn(candidate)) {
                    drawn = Some(candidate);
                    break;
                }
            }
            drawn.ok_or_else(|| {
                TokenError::Invalid("no free entry was drawn in 256 tries".to_owned())
            })?
        };
        let jti = uuid_v7(now.saturating_mul(1000), random()?);
        let mut issued = TokenTransition::new(kinds::TOKEN_ISSUE);
        issued.at = now;
        issued.by = by.to_owned();
        issued.list_id = Some(open);
        issued.index = Some(index as u64);
        issued.jti = Some(jti);
        issued.subject = Some(draft.subject);
        issued.client_id = Some(draft.client_id);
        issued.family = Some(draft.family);
        issued.audience = Some(draft.audience);
        issued.scope = Some(draft.scope);
        issued.expires_at = Some(draft.expires_at);
        issued.account = draft.account;
        issued.credential_id = draft.credential_id;
        issued.role = draft.role;
        transitions.push(issued);
        self.write(&mut journal, &mut state, transitions)?;
        state
            .tokens
            .get(&jti)
            .cloned()
            .ok_or_else(|| TokenError::NotFound("the token just issued".to_owned()))
    }

    /// Sets the status of every live token `matches` selects, at `now`, inside the operation
    /// `applying` names when one does: an `INVALID` token stays so. Answers how many changed.
    pub fn set_status(
        &self,
        applying: Option<&Applying<'_>>,
        matches: impl Fn(&IssuedToken) -> bool,
        value: u8,
        by: &str,
        now: u64,
    ) -> Result<usize, TokenError> {
        if !matches!(value, status::VALID | status::INVALID | status::SUSPENDED) {
            return Err(TokenError::Invalid(format!(
                "{value} is not a token status"
            )));
        }
        let mut journal = self.journal.lock().unwrap_or_else(PoisonError::into_inner);
        let mut state = self.state.write().unwrap_or_else(PoisonError::into_inner);
        let transitions: Vec<TokenTransition> = state
            .tokens
            .values()
            .filter(|token| {
                // A member accepts a token a clock skew past its `exp`: until then it can be
                // revoked, and its list kept.
                token
                    .expires_at
                    .saturating_add(crate::authz::access_tokens::CLOCK_SKEW)
                    > now
                    && token.status != status::INVALID
                    && token.status != value
                    && matches(token)
            })
            .enumerate()
            .map(|(position, token)| {
                let mut transition = TokenTransition::new(kinds::TOKEN_STATUS);
                transition.at = now;
                transition.by = by.to_owned();
                transition.jti = Some(token.jti);
                transition.status = Some(u64::from(value));
                // One operation names its first transition: what recovery observes.
                if position == 0 {
                    transition.operation_id = applying.map(Applying::operation_id);
                }
                transition
            })
            .collect();
        let changed = transitions.len();
        if changed > 0 {
            self.write(&mut journal, &mut state, transitions)?;
        }
        Ok(changed)
    }

    /// Retires every list but the open one whose tokens have all expired at `now`, forgetting
    /// them. Answers the lists retired.
    pub fn retire_expired(&self, by: &str, now: u64) -> Result<usize, TokenError> {
        let mut journal = self.journal.lock().unwrap_or_else(PoisonError::into_inner);
        let mut state = self.state.write().unwrap_or_else(PoisonError::into_inner);
        let transitions: Vec<TokenTransition> = state
            .lists
            .iter()
            .filter(|(id, list)| {
                Some(**id) != state.open
                    && list
                        .latest_expiry
                        .saturating_add(crate::authz::access_tokens::CLOCK_SKEW)
                        < now
            })
            .map(|(id, _)| {
                let mut transition = TokenTransition::new(kinds::LIST_RETIRE);
                transition.at = now;
                transition.by = by.to_owned();
                transition.list_id = Some(*id);
                transition
            })
            .collect();
        let retired = transitions.len();
        if retired > 0 {
            self.write(&mut journal, &mut state, transitions)?;
        }
        Ok(retired)
    }

    /// The token `jti` names, while the registry holds it.
    pub fn token(&self, jti: &[u8; 16]) -> Option<IssuedToken> {
        self.read().tokens.get(jti).cloned()
    }

    /// Every token not yet expired at `now`, newest first.
    pub fn live_tokens(&self, now: u64) -> Vec<IssuedToken> {
        let mut tokens: Vec<IssuedToken> = self
            .read()
            .tokens
            .values()
            .filter(|token| token.expires_at > now)
            .cloned()
            .collect();
        tokens.sort_by_key(|token| std::cmp::Reverse(token.jti));
        tokens
    }

    /// Every list held, as it stands.
    pub fn lists(&self) -> Vec<ListView> {
        self.read()
            .lists
            .iter()
            .map(|(list_id, list)| ListView {
                list_id: *list_id,
                list: list.list.clone(),
                changed_at: list.changed_at,
            })
            .collect()
    }

    /// Every list's id, without its entries.
    pub fn list_ids(&self) -> Vec<[u8; 16]> {
        self.read().lists.keys().copied().collect()
    }

    /// The registry revision of `list_id`'s last change, without its entries.
    pub fn changed_at(&self, list_id: &[u8; 16]) -> Option<u64> {
        self.read().lists.get(list_id).map(|list| list.changed_at)
    }

    /// The list `list_id` names, as it stands.
    pub fn list(&self, list_id: &[u8; 16]) -> Option<ListView> {
        self.read().lists.get(list_id).map(|list| ListView {
            list_id: *list_id,
            list: list.list.clone(),
            changed_at: list.changed_at,
        })
    }

    /// The revision `operation_id` produced and what it named, when the journal holds it.
    pub fn operation(&self, operation_id: &OperationId) -> Option<(u64, String)> {
        self.read().operations.get(operation_id).cloned()
    }
}

/// The state the journal holds, replayed from its first frame.
fn rebuilt(journal: &Journal) -> Result<State, TokenError> {
    let mut state = State::default();
    for frame in journal.frames()? {
        if frame.kind != FRAME_TRANSITION {
            return Err(TokenError::Invalid(format!(
                "the token journal holds a frame of kind {}",
                frame.kind
            )));
        }
        replay(&mut state, &TokenTransition::decode(&frame.payload)?)?;
    }
    Ok(state)
}

/// Applies one journaled transition to `state`: at start, and before every write. A transition
/// out of order, or naming what is not there, is refused; what it changed of `state` by then is
/// undone by the writer, which reads the state again from the journal.
fn replay(state: &mut State, transition: &TokenTransition) -> Result<(), TokenError> {
    let at = transition.revision;
    let corrupt = |detail: String| {
        TokenError::Invalid(format!("the token journal at revision {at}: {detail}"))
    };
    if at != state.revision + 1 {
        return Err(corrupt(format!("it follows revision {}", state.revision)));
    }
    let named =
        match transition.kind.as_str() {
            kinds::LIST_OPEN => {
                let list_id = transition
                    .list_id
                    .ok_or_else(|| corrupt("a list opened with no id".to_owned()))?;
                if state.lists.contains_key(&list_id) {
                    return Err(corrupt(format!("the list {} exists", uuid_text(&list_id))));
                }
                let mut list = ListState::new()?;
                list.changed_at = at;
                state.lists.insert(list_id, list);
                state.open = Some(list_id);
                uuid_text(&list_id)
            }
            kinds::LIST_RETIRE => {
                let list_id = transition
                    .list_id
                    .ok_or_else(|| corrupt("a list retired with no id".to_owned()))?;
                if state.lists.remove(&list_id).is_none() {
                    return Err(corrupt(format!(
                        "the list {} does not exist",
                        uuid_text(&list_id)
                    )));
                }
                if state.open == Some(list_id) {
                    state.open = None;
                }
                state.tokens.retain(|_, token| token.list_id != list_id);
                uuid_text(&list_id)
            }
            kinds::TOKEN_ISSUE => {
                let missing = |what: &str| corrupt(format!("an issued token names no {what}"));
                let list_id = transition.list_id.ok_or_else(|| missing("list"))?;
                let jti = transition.jti.ok_or_else(|| missing("jti"))?;
                let index = transition.index.ok_or_else(|| missing("index"))?;
                let expires_at = transition.expires_at.ok_or_else(|| missing("expiry"))?;
                let position = usize::try_from(index)
                    .ok()
                    .filter(|index| *index < ENTRIES)
                    .ok_or_else(|| corrupt(format!("index {index} is past the list")))?;
                if state.tokens.contains_key(&jti) {
                    return Err(corrupt(format!("the token {} exists", uuid_text(&jti))));
                }
                let list = state.lists.get_mut(&list_id).ok_or_else(|| {
                    corrupt(format!("the list {} is not held", uuid_text(&list_id)))
                })?;
                if list.is_drawn(position) {
                    return Err(corrupt(format!("index {index} was drawn already")));
                }
                list.draw(position);
                list.latest_expiry = list.latest_expiry.max(expires_at);
                state.tokens.insert(
                    jti,
                    IssuedToken {
                        jti,
                        list_id,
                        index,
                        subject: transition
                            .subject
                            .clone()
                            .ok_or_else(|| missing("subject"))?,
                        client_id: transition
                            .client_id
                            .clone()
                            .ok_or_else(|| missing("client"))?,
                        family: transition.family.clone().ok_or_else(|| missing("family"))?,
                        audience: transition
                            .audience
                            .clone()
                            .ok_or_else(|| missing("audience"))?,
                        scope: transition.scope.clone().ok_or_else(|| missing("scope"))?,
                        issued_at: transition.at,
                        expires_at,
                        account: transition.account.clone(),
                        credential_id: transition.credential_id,
                        role: transition.role.clone(),
                        status: status::VALID,
                    },
                );
                uuid_text(&jti)
            }
            kinds::TOKEN_STATUS => {
                let jti = transition
                    .jti
                    .ok_or_else(|| corrupt("a status names no token".to_owned()))?;
                let value = transition
                    .status
                    .and_then(|value| u8::try_from(value).ok())
                    .filter(|value| {
                        matches!(*value, status::VALID | status::INVALID | status::SUSPENDED)
                    })
                    .ok_or_else(|| corrupt("a status names no value".to_owned()))?;
                let token = state
                    .tokens
                    .get_mut(&jti)
                    .ok_or_else(|| corrupt(format!("the token {} is not held", uuid_text(&jti))))?;
                if token.status == status::INVALID {
                    return Err(corrupt(format!(
                        "the token {} is invalid, which is terminal",
                        uuid_text(&jti)
                    )));
                }
                token.status = value;
                let (list_id, index) = (token.list_id, token.index);
                let list = state.lists.get_mut(&list_id).ok_or_else(|| {
                    corrupt(format!("the list {} is not held", uuid_text(&list_id)))
                })?;
                list.list
                    .set(usize::try_from(index).unwrap_or(usize::MAX), value)
                    .map_err(|error| corrupt(error.to_string()))?;
                list.changed_at = at;
                uuid_text(&jti)
            }
            other => return Err(corrupt(format!("`{other}` is not a token transition"))),
        };
    state.revision = at;
    if let Some(operation_id) = transition.operation_id {
        state.operations.insert(operation_id, (at, named));
    }
    Ok(())
}

/// The domain name token revocations carry.
pub const MUTATION_DOMAIN: &str = "tokens";

/// The registry, as recovery of the mutation journal sees it.
pub struct Recovering<'a>(pub &'a TokenRegistry);

impl crate::operations::mutation::Domain for Recovering<'_> {
    fn name(&self) -> &'static str {
        MUTATION_DOMAIN
    }

    fn observe(
        &self,
        operation_id: &OperationId,
        _target: Option<&str>,
    ) -> Option<crate::operations::mutation::Observed> {
        self.0.operation(operation_id).map(|(revision, target)| {
            crate::operations::mutation::Observed {
                revision,
                target: Some(target),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use permguard_core::assurance::AssuranceProfile;

    const NOW: u64 = 1_800_000_000;

    fn scratch(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "pg-authz-tokens-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("the scratch directory is created");
        dir
    }

    fn open(root: &std::path::Path) -> Arc<TokenRegistry> {
        let volume = Volume::claim(root, AssuranceProfile::Development).expect("claimed");
        TokenRegistry::open(&volume).expect("opens").0
    }

    fn draft(account: &str, expires_at: u64) -> TokenDraft {
        TokenDraft {
            subject: format!("sa:{account}"),
            client_id: "0198f2aa-0000-7000-8000-000000000001".to_owned(),
            family: "application".to_owned(),
            audience: vec!["member:0198f2aa-0000-7000-8000-000000000002".to_owned()],
            scope: "decision.evaluate".to_owned(),
            expires_at,
            account: Some(account.to_owned()),
            credential_id: Some([1; 16]),
            role: None,
        }
    }

    /// WP-11.5: a token is recorded with a list entry, every entry `VALID`; a reopen replays
    /// the same tokens and the same lists.
    #[test]
    fn issued_tokens_and_their_lists_survive_a_reopen() {
        let root = scratch("reopen");
        let (first, second) = {
            let registry = open(&root);
            let first = registry
                .issue(draft("billing", NOW + 3_600), "issuer", NOW)
                .expect("one");
            let second = registry
                .issue(draft("reports", NOW + 60), "issuer", NOW)
                .expect("two");
            (first, second)
        };
        assert_eq!(first.list_id, second.list_id, "one open list");
        assert_ne!(first.index, second.index, "an index is drawn once");
        assert_ne!(first.jti, second.jti);
        let registry = open(&root);
        assert_eq!(registry.token(&first.jti), Some(first.clone()));
        assert_eq!(registry.revision(), 3, "the list, then the two tokens");
        let list = registry.list(&first.list_id).expect("held");
        assert_eq!(list.list.len(), ENTRIES);
        assert_eq!(
            list.list.get(usize::try_from(first.index).expect("small")),
            Ok(0)
        );
    }

    /// Suspending and resuming swap `SUSPENDED` and `VALID`; `INVALID` is terminal, and an
    /// expired token is never written again.
    #[test]
    fn a_status_change_writes_the_list_and_invalid_is_terminal() {
        let registry = open(&scratch("status"));
        let token = registry
            .issue(draft("billing", NOW + 3_600), "issuer", NOW)
            .expect("one");
        let other = registry
            .issue(draft("reports", NOW + 3_600), "issuer", NOW)
            .expect("two");
        let entry = |registry: &TokenRegistry, token: &IssuedToken| {
            registry
                .list(&token.list_id)
                .expect("held")
                .list
                .get(usize::try_from(token.index).expect("small"))
                .expect("in range")
        };
        let billing = |token: &IssuedToken| token.account.as_deref() == Some("billing");
        assert_eq!(
            registry
                .set_status(None, billing, status::SUSPENDED, "admin", NOW + 1)
                .expect("suspended"),
            1
        );
        assert_eq!(entry(&registry, &token), status::SUSPENDED);
        assert_eq!(
            entry(&registry, &other),
            status::VALID,
            "another account untouched"
        );
        let before = registry.list(&token.list_id).expect("held").changed_at;
        assert_eq!(
            registry
                .set_status(None, billing, status::VALID, "admin", NOW + 2)
                .expect("resumed"),
            1
        );
        assert!(registry.list(&token.list_id).expect("held").changed_at > before);
        let jti = token.jti;
        registry
            .set_status(
                None,
                |held| held.jti == jti,
                status::INVALID,
                "admin",
                NOW + 3,
            )
            .expect("revoked");
        assert_eq!(entry(&registry, &token), status::INVALID);
        assert_eq!(
            registry
                .set_status(None, billing, status::VALID, "admin", NOW + 4)
                .expect("nothing"),
            0,
            "invalid is terminal"
        );
        assert_eq!(
            registry
                .set_status(None, |_| true, status::SUSPENDED, "admin", NOW + 7_200)
                .expect("nothing"),
            0,
            "an expired token is never written"
        );
        assert!(
            registry
                .set_status(None, |_| true, 3, "admin", NOW)
                .is_err(),
            "0x03 is never written"
        );
    }

    /// A list whose every token expired retires, its tokens forgotten; the open list stays.
    #[test]
    fn a_list_retires_once_every_token_expired() {
        let root = scratch("retire");
        let registry = open(&root);
        let token = registry
            .issue(draft("billing", NOW + 60), "issuer", NOW)
            .expect("one");
        assert_eq!(
            registry.retire_expired("host", NOW + 120).expect("none"),
            0,
            "open"
        );
        // The open list never retires. Drawing half its 2^20 entries is what closes it; the test
        // closes it by hand instead.
        let retired = {
            let mut state = registry.state.write().expect("unpoisoned");
            state.open = None;
            drop(state);
            // A member accepts a token a clock skew past its `exp`: its list stays until then.
            assert_eq!(
                registry.retire_expired("host", NOW + 120).expect("kept"),
                0,
                "within the clock skew"
            );
            registry.retire_expired("host", NOW + 121).expect("retired")
        };
        assert_eq!(retired, 1);
        assert!(registry.token(&token.jti).is_none());
        assert!(registry.list(&token.list_id).is_none());
        let next = registry
            .issue(draft("billing", NOW + 600), "issuer", NOW + 130)
            .expect("new");
        assert_ne!(next.list_id, token.list_id, "a new list opens");
        let reopened = open(&root);
        assert!(reopened.token(&token.jti).is_none());
        assert_eq!(reopened.token(&next.jti), Some(next));
    }

    #[test]
    fn a_draft_the_registry_never_writes_is_refused() {
        let registry = open(&scratch("refused"));
        assert!(
            registry
                .issue(draft("billing", NOW), "issuer", NOW)
                .is_err(),
            "expired"
        );
        let mut wide = draft("billing", NOW + 60);
        wide.audience = (0..17).map(|n| format!("member:{n}")).collect();
        assert!(registry.issue(wide, "issuer", NOW).is_err(), "17 audiences");
        let mut none = draft("billing", NOW + 60);
        none.audience.clear();
        assert!(registry.issue(none, "issuer", NOW).is_err(), "no audience");
        assert_eq!(registry.revision(), 0);
    }

    /// Indices are drawn at random: a hundred tokens take a hundred distinct entries spread over
    /// the list, not the first hundred.
    #[test]
    fn indices_are_drawn_at_random_and_never_twice() {
        let registry = open(&scratch("random"));
        let indices: std::collections::BTreeSet<u64> = (0..100)
            .map(|_| {
                registry
                    .issue(draft("billing", NOW + 60), "issuer", NOW)
                    .expect("issued")
                    .index
            })
            .collect();
        assert_eq!(indices.len(), 100);
        assert!(indices.iter().any(|index| *index >= 100), "{indices:?}");
    }

    #[test]
    fn a_transition_round_trips_and_an_unknown_label_or_kind_is_refused() {
        let mut transition = TokenTransition::new(kinds::TOKEN_ISSUE);
        transition.revision = 2;
        transition.at = NOW;
        transition.by = "issuer".to_owned();
        transition.list_id = Some([2; 16]);
        transition.index = Some(42);
        transition.jti = Some([3; 16]);
        transition.subject = Some("sa:billing".to_owned());
        transition.client_id = Some("c".to_owned());
        transition.family = Some("application".to_owned());
        transition.audience = Some(vec!["member:m".to_owned()]);
        transition.scope = Some("decision.evaluate".to_owned());
        transition.expires_at = Some(NOW + 60);
        transition.account = Some("billing".to_owned());
        transition.credential_id = Some([4; 16]);
        transition.role = Some("role:dp.01a1bc76-7028-717c-8b19-c470f894a0dd".to_owned());
        let bytes = transition.encode().expect("encodes");
        assert_eq!(
            TokenTransition::decode(&bytes).expect("decodes"),
            transition
        );
        let Value::Map(mut pairs) = cbor::decode_canonical(&bytes).expect("canonical") else {
            panic!("a map")
        };
        pairs.push((Value::Int(19), Value::Text("x".to_owned())));
        let extended = cbor::encode(&Value::Map(pairs)).expect("encodes");
        assert!(TokenTransition::decode(&extended).is_err());
        let unknown = TokenTransition::new("token.promote")
            .encode()
            .expect("encodes");
        assert!(TokenTransition::decode(&unknown).is_err());
    }
}
