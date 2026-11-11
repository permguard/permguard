// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The tokens the Authority Plane issued and the status lists they are read in (`2-security/9`
//! The list): every token issued is recorded with the list entry its status is read from, and
//! every status change is a transition of the same journal.
//!
//! ```text
//! planes/authority/tokens/journal/     one frame per transition, a TokenTransition
//! ```
//!
//! A transition is a closed CBOR map with integer labels (`contracts/cbor/authority.json`):
//!
//! | Label | Member         | Type          | In                                          |
//! | ----- | -------------- | ------------- | ------------------------------------------- |
//! | 1     | `kind`         | text          | every transition                            |
//! | 2     | `revision`     | uint          | every transition                            |
//! | 3     | `at`           | uint, seconds | every transition                            |
//! | 4     | `by`           | text          | every transition: who made it               |
//! | 5     | `operation_id` | bytes, 16     | optional: the security mutation that made it |
//! | 6     | `list_id`      | bytes, 16     | `list.open`, `list.retire`, `token.issue`   |
//! | 7     | `index`        | uint          | `token.issue`: the entry of the list        |
//! | 8     | `jti`          | bytes, 16     | `token.issue`, `token.status`               |
//! | 9     | `account`      | text          | `token.issue`: the service account          |
//! | 10    | `access_key`   | text          | `token.issue`: the key it was obtained with |
//! | 11    | `scopes`       | array of `{1 operations, 2 selector}` | `token.issue`       |
//! | 12    | `expires_at`   | uint, seconds | `token.issue`                               |
//! | 13    | `status`       | uint          | `token.status`: 0 valid, 1 invalid, 2 suspended |
//!
//! An index is drawn at random among the free entries of the open list and never drawn again in
//! that list. A list is open until half its entries are drawn; it retires once every token it
//! holds has expired, and its tokens are forgotten with it. `INVALID` is terminal.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError, RwLock};

use permguard_core::authz::{Selector, TokenScope};
use permguard_host::authz::access_tokens::CLOCK_SKEW;
use permguard_host::identity::record::{uuid_text, uuid_v7};
use permguard_host::operations::journal::OperationId;
use permguard_host::operations::mutation::{Applying, Domain, Observed};
use permguard_host::storage::StorageError;
use permguard_host::storage::dir::Dir;
use permguard_host::storage::journal::{Journal, Options, Recovery};
use permguard_objects::cbor::Value;
use permguard_objects::status_list::{ENTRIES, StatusList};
use ring::rand::SecureRandom as _;

use crate::cbor::{self, RecordError};

/// The registry's folder below `planes/authority/`.
pub const DIRECTORY: &str = "tokens";
const JOURNAL: &str = "journal";
const FRAME_TRANSITION: u16 = 1;
/// The bits per entry of every list.
pub const BITS: u8 = permguard_host::authz::status_lists::BITS;
/// A list stays open until half its entries are drawn: a draw at random then takes two tries on
/// average.
pub const OPEN_UNTIL: usize = ENTRIES / 2;
/// The domain token revocations run in.
pub const DOMAIN: &str = "authority.tokens";

/// The entry values (`2-security/9` The list).
pub mod status {
    pub const VALID: u8 = 0;
    /// Terminal.
    pub const INVALID: u8 = 1;
    pub const SUSPENDED: u8 = 2;

    /// The value's name, as the API answers it.
    pub fn name(value: u8) -> &'static str {
        match value {
            VALID => "valid",
            INVALID => "invalid",
            SUSPENDED => "suspended",
            _ => "unknown",
        }
    }

    /// The value a name answers to.
    pub fn parse(name: &str) -> Option<u8> {
        match name {
            "valid" => Some(VALID),
            "invalid" => Some(INVALID),
            "suspended" => Some(SUSPENDED),
            _ => None,
        }
    }
}

/// The transition kinds.
pub mod kinds {
    pub const LIST_OPEN: &str = "list.open";
    pub const LIST_RETIRE: &str = "list.retire";
    pub const TOKEN_ISSUE: &str = "token.issue";
    pub const TOKEN_STATUS: &str = "token.status";
}

/// The id `text` names, as a UUID's text.
pub fn parse_id(text: &str) -> Option<[u8; 16]> {
    let hex: String = text.chars().filter(|c| *c != '-').collect();
    if hex.len() != 32 || text.len() != 36 {
        return None;
    }
    let mut id = [0u8; 16];
    for (at, byte) in id.iter_mut().enumerate() {
        *byte = u8::from_str_radix(hex.get(at * 2..at * 2 + 2)?, 16).ok()?;
    }
    (uuid_text(&id) == text.to_ascii_lowercase()).then_some(id)
}

/// One journaled transition.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TokenTransition {
    pub kind: String,
    pub revision: u64,
    pub at: u64,
    pub by: String,
    pub operation_id: Option<OperationId>,
    pub list_id: Option<[u8; 16]>,
    pub index: Option<u64>,
    pub jti: Option<[u8; 16]>,
    pub account: Option<String>,
    pub access_key: Option<String>,
    pub scopes: Option<Vec<TokenScope>>,
    pub expires_at: Option<u64>,
    pub status: Option<u64>,
}

fn scope_value(scope: &TokenScope) -> Value {
    cbor::map(vec![
        (1, Some(cbor::texts(scope.operations.iter()))),
        (2, Some(Value::Text(scope.selector.to_string()))),
    ])
}

fn scope_of(value: Value) -> Result<TokenScope, RecordError> {
    let mut read = cbor::Labelled::new(value, 2)?;
    let operations = read.array(1, cbor::text_of)?.into_iter().collect();
    let selector = Selector::parse(&read.text(2)?)
        .map_err(|error| RecordError::Malformed(format!("a scope's selector: {error}")))?;
    read.finish()?;
    Ok(TokenScope {
        operations,
        selector,
    })
}

impl TokenTransition {
    /// A transition of `kind`, everything else to be filled.
    pub fn new(kind: &str) -> Self {
        Self {
            kind: kind.to_owned(),
            ..Self::default()
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, RecordError> {
        let id = |id: Option<[u8; 16]>| id.map(|id| Value::Bytes(id.to_vec()));
        cbor::encode(&cbor::map(vec![
            (1, Some(Value::Text(self.kind.clone()))),
            (2, Some(cbor::uint(self.revision)?)),
            (3, Some(cbor::uint(self.at)?)),
            (4, Some(Value::Text(self.by.clone()))),
            (5, id(self.operation_id.map(|op| *op.as_bytes()))),
            (6, id(self.list_id)),
            (7, self.index.map(cbor::uint).transpose()?),
            (8, id(self.jti)),
            (9, self.account.clone().map(Value::Text)),
            (10, self.access_key.clone().map(Value::Text)),
            (
                11,
                self.scopes
                    .as_ref()
                    .map(|scopes| Value::Array(scopes.iter().map(scope_value).collect())),
            ),
            (12, self.expires_at.map(cbor::uint).transpose()?),
            (13, self.status.map(cbor::uint).transpose()?),
        ]))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        let mut read = cbor::decode(bytes, 13)?;
        let transition = Self {
            kind: read.text(1)?,
            revision: read.uint(2)?,
            at: read.uint(3)?,
            by: read.text(4)?,
            operation_id: read.optional_operation_id(5)?,
            list_id: read.optional_id(6)?,
            index: read.optional_uint(7)?,
            jti: read.optional_id(8)?,
            account: read.optional_text(9)?,
            access_key: read.optional_text(10)?,
            scopes: {
                let scopes = read.array(11, scope_of)?;
                (!scopes.is_empty()).then_some(scopes)
            },
            expires_at: read.optional_uint(12)?,
            status: read.optional_uint(13)?,
        };
        read.finish()?;
        Ok(transition)
    }
}

/// What the registry refuses.
#[derive(Debug)]
pub enum TokenError {
    Invalid(String),
    NotFound(String),
    Random,
    Storage(StorageError),
    Record(RecordError),
}

impl std::fmt::Display for TokenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(detail) | Self::NotFound(detail) => f.write_str(detail),
            Self::Random => f.write_str("the system's random generator failed"),
            Self::Storage(error) => write!(f, "{error}"),
            Self::Record(error) => write!(f, "{error}"),
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

/// What a token is issued for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenDraft {
    pub account: String,
    pub access_key: String,
    pub scopes: Vec<TokenScope>,
    pub expires_at: u64,
}

/// One token the registry holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuedToken {
    pub jti: [u8; 16],
    pub list_id: [u8; 16],
    pub index: u64,
    pub account: String,
    pub access_key: String,
    pub scopes: Vec<TokenScope>,
    pub issued_at: u64,
    pub expires_at: u64,
    pub status: u8,
}

impl IssuedToken {
    /// Its id, as a UUID.
    pub fn jti_text(&self) -> String {
        uuid_text(&self.jti)
    }
}

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

/// The token registry of one Authority Plane.
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
    /// Opens the registry under `dir`, the plane's directory, replaying its journal. A
    /// transition the replay cannot apply is corruption, never skipped.
    pub fn open(dir: &Dir, options: Options) -> Result<(Arc<Self>, Recovery), TokenError> {
        let journal_dir = dir.subdir(DIRECTORY, true)?.subdir(JOURNAL, true)?;
        let (journal, recovery) = Journal::open(journal_dir, options)?;
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

    /// Writes `transitions` in order, each applied to the state, which refuses what the replay
    /// would, then journaled. On any failure the state is read again from the journal, so the
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

    /// Records a token for `draft`, issued at `now`: its `jti` and the list entry its status is
    /// read from. The list is opened, when needed, in the same write.
    pub fn issue(&self, draft: TokenDraft, now: u64) -> Result<IssuedToken, TokenError> {
        if draft.expires_at <= now {
            return Err(TokenError::Invalid(
                "a token expires after it is issued".to_owned(),
            ));
        }
        if draft.scopes.is_empty() {
            return Err(TokenError::Invalid("a token carries a scope".to_owned()));
        }
        let mut journal = self.journal.lock().unwrap_or_else(PoisonError::into_inner);
        let mut state = self.state.write().unwrap_or_else(PoisonError::into_inner);
        let mut transitions = Vec::new();
        let by = crate::accounts::principal_of(&draft.account);
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
                opened.by.clone_from(&by);
                opened.list_id = Some(list_id);
                transitions.push(opened);
                list_id
            }
        };
        // Drawn at random among the free entries; a bound of draws keeps a failing random source
        // from spinning.
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
        issued.by = by;
        issued.list_id = Some(open);
        issued.index = Some(index as u64);
        issued.jti = Some(jti);
        issued.account = Some(draft.account);
        issued.access_key = Some(draft.access_key);
        issued.scopes = Some(draft.scopes);
        issued.expires_at = Some(draft.expires_at);
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
                // A Plane accepts a token a clock skew past its `exp`: until then it can be
                // revoked, and its list kept.
                token.expires_at.saturating_add(CLOCK_SKEW) > now
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
                Some(**id) != state.open && list.latest_expiry.saturating_add(CLOCK_SKEW) < now
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

    /// When `access_key` last obtained a token the registry still holds.
    pub fn last_used(&self, access_key: &str) -> Option<u64> {
        self.read()
            .tokens
            .values()
            .filter(|token| token.access_key == access_key)
            .map(|token| token.issued_at)
            .max()
    }

    /// The list `list_id` names, as it stands.
    pub fn list(&self, list_id: &[u8; 16]) -> Option<ListView> {
        self.read().lists.get(list_id).map(|list| ListView {
            list_id: *list_id,
            list: list.list.clone(),
            changed_at: list.changed_at,
        })
    }

    /// Every list's id.
    pub fn list_ids(&self) -> Vec<[u8; 16]> {
        self.read().lists.keys().copied().collect()
    }

    /// The registry revision of `list_id`'s last change, without its entries.
    pub fn changed_at(&self, list_id: &[u8; 16]) -> Option<u64> {
        self.read().lists.get(list_id).map(|list| list.changed_at)
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
/// out of order, or naming what is not there, is refused.
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
                        account: transition
                            .account
                            .clone()
                            .ok_or_else(|| missing("account"))?,
                        access_key: transition
                            .access_key
                            .clone()
                            .ok_or_else(|| missing("access key"))?,
                        scopes: transition.scopes.clone().ok_or_else(|| missing("scope"))?,
                        issued_at: transition.at,
                        expires_at,
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

/// The registry, as recovery of the mutation journal sees it.
pub struct Recovering<'a>(pub &'a TokenRegistry);

impl Domain for Recovering<'_> {
    fn name(&self) -> &'static str {
        DOMAIN
    }

    fn observe(&self, operation_id: &OperationId, _target: Option<&str>) -> Option<Observed> {
        self.0
            .operation(operation_id)
            .map(|(revision, named)| Observed {
                revision,
                target: Some(named),
            })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    const NOW: u64 = 1_800_000_000;

    fn scratch(tag: &str) -> Dir {
        let root =
            std::env::temp_dir().join(format!("pg-authority-tokens-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("scratch");
        Dir::open(&root).expect("a directory")
    }

    fn draft(account: &str) -> TokenDraft {
        TokenDraft {
            account: account.to_owned(),
            access_key: "pgak_AAAAAAAAAAAAAAAAAAAA".to_owned(),
            scopes: vec![TokenScope {
                operations: std::iter::once("decision.evaluate".to_owned()).collect(),
                selector: Selector::parse("plane/data/*").expect("a selector"),
            }],
            expires_at: NOW + 3_600,
        }
    }

    #[test]
    fn a_token_draws_an_entry_its_status_changes_and_both_survive_a_reopen() {
        let dir = scratch("issue");
        let (registry, _) = TokenRegistry::open(&dir, Options::default()).expect("opens");
        let first = registry.issue(draft("billing"), NOW).expect("issued");
        let second = registry.issue(draft("payroll"), NOW).expect("issued");
        assert_eq!(first.list_id, second.list_id, "one open list");
        assert_ne!(first.index, second.index);
        assert_eq!(registry.list_ids().len(), 1);
        assert_eq!(
            registry
                .set_status(
                    None,
                    |token| token.account == "billing",
                    status::SUSPENDED,
                    "t",
                    NOW
                )
                .expect("set"),
            1
        );
        assert_eq!(
            registry
                .set_status(
                    None,
                    |token| token.account == "billing",
                    status::INVALID,
                    "t",
                    NOW
                )
                .expect("set"),
            1
        );
        assert_eq!(
            registry
                .set_status(
                    None,
                    |token| token.account == "billing",
                    status::VALID,
                    "t",
                    NOW
                )
                .expect("nothing"),
            0,
            "INVALID is terminal"
        );
        assert_eq!(registry.last_used("pgak_AAAAAAAAAAAAAAAAAAAA"), Some(NOW));
        drop(registry);
        let (reopened, _) = TokenRegistry::open(&dir, Options::default()).expect("reopens");
        let held = reopened.token(&first.jti).expect("held");
        assert_eq!(held.status, status::INVALID);
        let list = reopened.list(&first.list_id).expect("the list");
        assert_eq!(
            list.list
                .get(usize::try_from(first.index).expect("an index"))
                .expect("in range"),
            status::INVALID
        );
        assert_eq!(reopened.live_tokens(NOW).len(), 2);
        assert!(
            reopened.issue(draft("x"), NOW + 3_600).is_err(),
            "a token expires after it is issued"
        );
        // The open list never retires, whatever expired in it.
        let later = NOW + 3_600 + CLOCK_SKEW + 1;
        assert_eq!(reopened.retire_expired("t", later).expect("retired"), 0);
        assert_eq!(reopened.live_tokens(later).len(), 0);
    }

    #[test]
    fn a_transition_round_trips_and_ids_read_as_uuids() {
        let mut transition = TokenTransition::new(kinds::TOKEN_ISSUE);
        transition.revision = 3;
        transition.at = NOW;
        transition.by = "sa:billing".to_owned();
        transition.list_id = Some([1; 16]);
        transition.index = Some(7);
        transition.jti = Some([2; 16]);
        transition.account = Some("billing".to_owned());
        transition.access_key = Some("pgak_AAAAAAAAAAAAAAAAAAAA".to_owned());
        transition.scopes = Some(draft("billing").scopes);
        transition.expires_at = Some(NOW + 1);
        let bytes = transition.encode().expect("encoded");
        assert_eq!(
            TokenTransition::decode(&bytes).expect("decoded"),
            transition
        );
        let text = uuid_text(&[0xab; 16]);
        assert_eq!(parse_id(&text), Some([0xab; 16]));
        assert_eq!(parse_id("../x"), None);
        assert_eq!(parse_id(&text.replace('-', "")), None);
    }
}
