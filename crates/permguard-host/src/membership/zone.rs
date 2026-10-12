// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The `zone.secrets` task, contract version 1 (WP-4.7; owner decisions of 2026-10-12).
//!
//! ```text
//! member       task session over `plane/<p>/zone/<z>` or `…/ledger/<l>`, within the task's selector
//!   ─▶ { action: "deliver" }
//! coordinator  the tuples the task grants for that resource: each purpose its `resource_types`
//!              name that the resource takes, at the coordinator root's version
//!   ─▶ { keys: [{ purpose, zone, scope, version, key }] }      kept nowhere, never in the window
//! member       stores each key (`ZoneKeys`, witnessed per tuple), then confirms
//!   ─▶ { action: "confirm", confirmations: [{ purpose, zone, scope, version, mac }] }
//! coordinator  verifies every MAC, keeps the receipt: the tuples and the transcript digest only
//!   ─▶ { epoch, confirmed_at, transcript_digest, tuples }
//! ```
//!
//! | Record             | Shape                                                                     |
//! | ------------------ | ------------------------------------------------------------------------- |
//! | zone_request       | {1 action, 2? confirmations}                                              |
//! | zone_delivery      | {1 keys}: each {1 purpose, 2 zone, 3 scope, 4 version, 5 key}             |
//! | zone_confirmation  | {1 purpose, 2 zone, 3 scope, 4 version, 5 mac}                            |
//! | zone_receipt       | {1 epoch, 2 confirmed_at, 3 transcript_digest, 4 tuples, 5 resource}: answered, and kept per resource as `progress/<membership_id>/<task_id>.<sha256(resource)>.zone` on both sides |
//!
//! A zone resource grants the zone's shared pseudonym key (`audit.pseudonym`, its scope the zone),
//! a ledger resource that ledger's input-tag key (`decision.commitment`, its scope the ledger).
//! The MAC is HMAC-SHA256 under the key `zone-confirm` derives from the delivered key, over
//! det-CBOR `[membership_id, task_id, manifest_epoch, purpose, scope, version, session_nonce]`; the
//! nonce is the channel binding of the session's lease, so a confirmation answers one connection
//! alone. The transcript digest covers the tuples, the nonce and the MACs, never a key.

use std::sync::Arc;

use hmac::{Hmac, KeyInit, Mac as _};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use permguard_core::authz::Resource;
use permguard_core::codes;
use permguard_core::domains::digest;
use permguard_objects::cbor::{self, Value};
use permguard_objects::crypto::kdf::{self, KEY_LEN};

use super::member::Member;
use super::record::{Task, TaskType};
use super::task::{TaskContext, TaskHandler};
use super::{MembershipError, Store};
use crate::identity::record::{Labelled, RecordError, encode, uint, uuid_text};
use crate::operations::journal::Initiator;
use crate::secrets::{self, KeyVersion, ZoneKeys, ZonePurpose, ZoneTuple, parse_uuid};
use crate::session::Refusal;
use crate::storage::format;
use crate::storage::write::{read_view, replace_view};
use crate::time::TimeGuard;

/// The contract version this module speaks.
pub const VERSION: u64 = 1;
/// The request a member opens a delivery with.
pub const DELIVER: &str = "deliver";
/// The request a member confirms what it stored with.
pub const CONFIRM: &str = "confirm";
/// The most tuples one delivery, confirmation or receipt carries.
pub const MAX_TUPLES: usize = 64;
/// The most bytes one `zone.secrets` record takes.
const MAX_ZONE_BYTES: usize = 16 * 1024;
/// The suffix of a receipt in a membership's progress directory.
const RECEIPT: &str = "zone";
/// The longest resource a receipt names.
const MAX_RESOURCE_BYTES: usize = 512;

/// One delivered key's coordinates: what a grant names, a key carries and a receipt keeps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Tuple {
    pub purpose: ZonePurpose,
    pub zone: [u8; 16],
    pub scope: [u8; 16],
    pub version: u64,
}

impl Tuple {
    fn fields(&self) -> Result<Vec<(Value, Value)>, RecordError> {
        Ok(vec![
            (Value::Int(1), Value::Text(self.purpose.as_str().to_owned())),
            (Value::Int(2), Value::Bytes(self.zone.to_vec())),
            (Value::Int(3), Value::Bytes(self.scope.to_vec())),
            (Value::Int(4), uint(self.version)?),
        ])
    }

    fn read(map: &mut Labelled) -> Result<Self, RecordError> {
        let purpose = map.text(1)?;
        let purpose = ZonePurpose::parse(&purpose)
            .ok_or_else(|| RecordError(format!("`{purpose}` is not a zone purpose")))?;
        let tuple = Self {
            purpose,
            zone: map.id(2)?,
            scope: map.id(3)?,
            version: map.uint(4)?,
        };
        if tuple.version == 0 || !tuple.purpose.takes(&tuple.zone, &tuple.scope) {
            return Err(RecordError(
                "a zone tuple names a version of at least 1 and a scope its purpose takes"
                    .to_owned(),
            ));
        }
        Ok(tuple)
    }

    fn value(&self) -> Result<Value, RecordError> {
        Ok(Value::Map(self.fields()?))
    }

    /// The tuple as the member's store keeps it, under `authority`.
    pub fn stored(&self, authority: [u8; 16]) -> Result<ZoneTuple, MembershipError> {
        Ok(ZoneTuple {
            authority,
            zone: self.zone,
            purpose: self.purpose,
            scope: self.scope,
            version: KeyVersion::new(self.version).ok_or_else(|| {
                MembershipError::Invalid("a zone version is at least 1".to_owned())
            })?,
        })
    }

    /// The order a receipt and a transcript take: purpose, zone, scope and version.
    fn key(&self) -> (&'static str, [u8; 16], [u8; 16], u64) {
        (self.purpose.as_str(), self.zone, self.scope, self.version)
    }
}

fn sorted<T>(mut items: Vec<T>, tuple: impl Fn(&T) -> &Tuple) -> Vec<T> {
    items.sort_by(|left, right| tuple(left).key().cmp(&tuple(right).key()));
    items
}

fn bounded(bytes: &[u8], what: &str) -> Result<(), RecordError> {
    if bytes.len() > MAX_ZONE_BYTES {
        return Err(RecordError(format!("{what} is out of its bound")));
    }
    Ok(())
}

fn tuples<T>(
    values: Vec<Value>,
    what: &'static str,
    read: impl Fn(&mut Labelled) -> Result<T, RecordError>,
    tuple: impl Fn(&T) -> &Tuple,
) -> Result<Vec<T>, RecordError> {
    if values.len() > MAX_TUPLES {
        return Err(RecordError(format!("{what}s number at most {MAX_TUPLES}")));
    }
    let mut read_all = Vec::with_capacity(values.len());
    for value in values {
        let mut map = Labelled::from_value(value, what)?;
        let item = read(&mut map)?;
        map.finish()?;
        read_all.push(item);
    }
    if !read_all
        .windows(2)
        .all(|pair| tuple(&pair[0]).key() < tuple(&pair[1]).key())
    {
        return Err(RecordError(format!("{what}s are in order, each once")));
    }
    Ok(read_all)
}

/// One confirmed tuple: the MAC under the key derived from the one delivered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Confirmation {
    pub tuple: Tuple,
    pub mac: [u8; 32],
}

/// What a member asks on a `zone.secrets` session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    Deliver,
    Confirm(Vec<Confirmation>),
}

impl Request {
    pub fn encode(&self) -> Result<Vec<u8>, RecordError> {
        match self {
            Self::Deliver => encode(vec![(Value::Int(1), Value::Text(DELIVER.to_owned()))]),
            Self::Confirm(confirmations) => {
                let confirmations = sorted(confirmations.clone(), |c| &c.tuple);
                encode(vec![
                    (Value::Int(1), Value::Text(CONFIRM.to_owned())),
                    (
                        Value::Int(2),
                        Value::Array(
                            confirmations
                                .iter()
                                .map(|c| {
                                    let mut fields = c.tuple.fields()?;
                                    fields.push((Value::Int(5), Value::Bytes(c.mac.to_vec())));
                                    Ok(Value::Map(fields))
                                })
                                .collect::<Result<_, RecordError>>()?,
                        ),
                    ),
                ])
            }
        }
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        bounded(bytes, "a zone request")?;
        let mut map = Labelled::read(bytes, "a zone request")?;
        let action = map.text(1)?;
        let request = match action.as_str() {
            DELIVER => Self::Deliver,
            CONFIRM => Self::Confirm(tuples(
                map.array(2)?,
                "a zone confirmation",
                |map| {
                    Ok(Confirmation {
                        tuple: Tuple::read(map)?,
                        mac: map.fixed(5)?,
                    })
                },
                |c| &c.tuple,
            )?),
            other => {
                return Err(RecordError(format!(
                    "`{other}` is not a zone request action"
                )));
            }
        };
        map.finish()?;
        Ok(request)
    }
}

/// The keys a coordinator delivers: never displayed, zeroized when dropped.
pub struct Delivery {
    pub keys: Vec<(Tuple, Zeroizing<[u8; KEY_LEN]>)>,
}

impl std::fmt::Debug for Delivery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list()
            .entries(self.keys.iter().map(|(tuple, _)| tuple))
            .finish()
    }
}

impl Delivery {
    /// A delivery of `keys`, each held zeroized from here on.
    pub fn of(keys: impl IntoIterator<Item = (Tuple, [u8; KEY_LEN])>) -> Self {
        Self {
            keys: keys
                .into_iter()
                .map(|(tuple, key)| (tuple, Zeroizing::new(key)))
                .collect(),
        }
    }

    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, RecordError> {
        let mut keys: Vec<&(Tuple, Zeroizing<[u8; KEY_LEN]>)> = self.keys.iter().collect();
        keys.sort_by(|left, right| left.0.key().cmp(&right.0.key()));
        Ok(Zeroizing::new(encode(vec![(
            Value::Int(1),
            Value::Array(
                keys.iter()
                    .map(|(tuple, key)| {
                        let mut fields = tuple.fields()?;
                        fields.push((Value::Int(5), Value::Bytes(key.to_vec())));
                        Ok(Value::Map(fields))
                    })
                    .collect::<Result<_, RecordError>>()?,
            ),
        )])?))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        bounded(bytes, "a zone delivery")?;
        let mut map = Labelled::read(bytes, "a zone delivery")?;
        let keys = tuples(
            map.array(1)?,
            "a zone key",
            |map| {
                let tuple = Tuple::read(map)?;
                let key = Zeroizing::new(map.fixed::<KEY_LEN>(5)?);
                Ok((tuple, key))
            },
            |(tuple, _)| tuple,
        )?;
        map.finish()?;
        Ok(Self { keys })
    }
}

/// What a confirmation leaves: the tuples confirmed at one epoch, when, and the transcript's
/// digest. Answered to the member and kept by both sides; never a key, witness or MAC.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receipt {
    pub epoch: u64,
    pub confirmed_at: u64,
    pub transcript_digest: [u8; 32],
    pub tuples: Vec<Tuple>,
    /// The session's resource, canonical: a receipt is kept per resource (owner decision, after
    /// the review).
    pub resource: String,
}

impl Receipt {
    pub fn encode(&self) -> Result<Vec<u8>, RecordError> {
        let tuples = sorted(self.tuples.clone(), |tuple| tuple);
        encode(vec![
            (Value::Int(1), uint(self.epoch)?),
            (Value::Int(2), uint(self.confirmed_at)?),
            (Value::Int(3), Value::Bytes(self.transcript_digest.to_vec())),
            (
                Value::Int(4),
                Value::Array(
                    tuples
                        .iter()
                        .map(Tuple::value)
                        .collect::<Result<_, RecordError>>()?,
                ),
            ),
            (Value::Int(5), Value::Text(self.resource.clone())),
        ])
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        bounded(bytes, "a zone receipt")?;
        let mut map = Labelled::read(bytes, "a zone receipt")?;
        let receipt = Self {
            epoch: map.uint(1)?,
            confirmed_at: map.uint(2)?,
            transcript_digest: map.fixed(3)?,
            tuples: tuples(map.array(4)?, "a zone tuple", Tuple::read, |tuple| tuple)?,
            resource: canonical_resource(map.text(5)?)?,
        };
        map.finish()?;
        Ok(receipt)
    }
}

/// `text` when it is a resource in its canonical form, of at most [`MAX_RESOURCE_BYTES`].
fn canonical_resource(text: String) -> Result<String, RecordError> {
    let canonical = text.len() <= MAX_RESOURCE_BYTES
        && Resource::parse(&text).is_ok_and(|resource| resource.to_string() == text);
    if !canonical {
        return Err(RecordError(
            "a zone receipt names a canonical resource".to_owned(),
        ));
    }
    Ok(text)
}

/// The file a receipt of `resource` of `task_id` is kept in.
fn receipt_name(task_id: &str, resource: &str) -> String {
    let digest: [u8; 32] = Sha256::digest(resource.as_bytes()).into();
    let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    format!("{task_id}.{hex}.{RECEIPT}")
}

/// The tuples `task` grants over `resource` at `version` (owner decision): the purposes its
/// `resource_types` name that the resource takes, a zone its shared pseudonym key and a ledger its
/// input-tag key.
pub fn grant(task: &Task, resource: &Resource, version: u64) -> Result<Vec<Tuple>, String> {
    let id = |text: &str| parse_uuid(text).ok_or_else(|| format!("`{text}` is not a UUID"));
    let (purpose, zone, scope) = match resource {
        Resource::Zone { zone_id, .. } => {
            let zone = id(zone_id)?;
            (ZonePurpose::AuditPseudonym, zone, zone)
        }
        Resource::Ledger {
            zone_id, ledger_id, ..
        } => (
            ZonePurpose::DecisionCommitment,
            id(zone_id)?,
            id(ledger_id)?,
        ),
        _ => return Err("a zone key is granted over a zone or a ledger".to_owned()),
    };
    if task.task_type != TaskType::ZoneSecrets {
        return Err("only a `zone.secrets` task grants zone keys".to_owned());
    }
    if !task
        .resource_types
        .iter()
        .any(|named| named == purpose.as_str())
    {
        return Err(format!(
            "the task grants no `{}` key over this resource",
            purpose.as_str()
        ));
    }
    if !purpose.takes(&zone, &scope) {
        return Err("the resource's scope is not one its purpose takes".to_owned());
    }
    Ok(vec![Tuple {
        purpose,
        zone,
        scope,
        version,
    }])
}

/// Who a confirmation is for: the session's membership, task, manifest epoch and nonce.
#[derive(Debug, Clone, Copy)]
pub struct Session<'a> {
    pub authority: [u8; 16],
    pub membership_id: [u8; 16],
    pub task_id: &'a str,
    pub epoch: u64,
    /// The channel binding of the session's lease (owner decision).
    pub nonce: [u8; 32],
}

fn confirming_mac(
    key: &[u8; KEY_LEN],
    session: &Session<'_>,
    tuple: &Tuple,
) -> Result<Hmac<Sha256>, MembershipError> {
    let confirm = kdf::derive_zone_confirm(
        &key[..],
        &session.authority,
        tuple.purpose.as_str(),
        &tuple.zone,
        &tuple.scope,
        tuple.version,
    )
    .map_err(|error| MembershipError::Invalid(error.to_string()))?;
    let message = cbor::encode(&Value::Array(vec![
        Value::Bytes(session.membership_id.to_vec()),
        Value::Text(session.task_id.to_owned()),
        uint(session.epoch)?,
        Value::Text(tuple.purpose.as_str().to_owned()),
        Value::Bytes(tuple.scope.to_vec()),
        uint(tuple.version)?,
        Value::Bytes(session.nonce.to_vec()),
    ]))
    .map_err(|_| MembershipError::Invalid("the confirmed tuple does not encode".to_owned()))?;
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&confirm[..])
        .map_err(|_| MembershipError::Invalid("the confirmation key".to_owned()))?;
    mac.update(&message);
    Ok(mac)
}

/// The MAC confirming the key of `tuple` in `session`.
pub fn confirmation(
    key: &[u8; KEY_LEN],
    session: &Session<'_>,
    tuple: &Tuple,
) -> Result<[u8; 32], MembershipError> {
    Ok(confirming_mac(key, session, tuple)?
        .finalize()
        .into_bytes()
        .into())
}

/// Whether `mac` confirms the key of `tuple` in `session`, compared in constant time.
pub fn confirms(
    key: &[u8; KEY_LEN],
    session: &Session<'_>,
    tuple: &Tuple,
    mac: &[u8; 32],
) -> Result<bool, MembershipError> {
    Ok(confirming_mac(key, session, tuple)?
        .verify_slice(&mac[..])
        .is_ok())
}

/// The digest of a confirmation's transcript: the session, the nonce and each tuple with its
/// MAC, in order, under `permguard.membership.zone-transcript.v1`.
pub fn transcript_digest(
    session: &Session<'_>,
    confirmations: &[Confirmation],
) -> Result<[u8; 32], MembershipError> {
    let confirmations = sorted(confirmations.to_vec(), |c| &c.tuple);
    let transcript = cbor::encode(&Value::Array(vec![
        Value::Bytes(session.membership_id.to_vec()),
        Value::Text(session.task_id.to_owned()),
        uint(session.epoch)?,
        Value::Bytes(session.nonce.to_vec()),
        Value::Array(
            confirmations
                .iter()
                .map(|c| {
                    Ok(Value::Array(vec![
                        Value::Text(c.tuple.purpose.as_str().to_owned()),
                        Value::Bytes(c.tuple.zone.to_vec()),
                        Value::Bytes(c.tuple.scope.to_vec()),
                        uint(c.tuple.version)?,
                        Value::Bytes(c.mac.to_vec()),
                    ]))
                })
                .collect::<Result<_, RecordError>>()?,
        ),
    ]))
    .map_err(|_| MembershipError::Invalid("the transcript does not encode".to_owned()))?;
    let mut hasher = Sha256::new();
    hasher.update(digest::MEMBERSHIP_ZONE_TRANSCRIPT.as_bytes());
    hasher.update(&transcript);
    Ok(hasher.finalize().into())
}

impl Store {
    /// Keeps `receipt` of `task_id` of `id`, replacing the one before for its resource.
    pub fn keep_zone_receipt(
        &self,
        id: &[u8; 16],
        task_id: &str,
        receipt: &Receipt,
    ) -> Result<(), MembershipError> {
        let dir = self
            .progress_dir(id, true)?
            .ok_or_else(|| MembershipError::Storage("the progress directory".to_owned()))?;
        replace_view(
            &dir,
            &receipt_name(task_id, &receipt.resource),
            format::VIEW,
            &receipt.encode()?,
        )?;
        Ok(())
    }

    /// The last receipt of `task_id` of `id` for `resource`.
    pub fn zone_receipt(
        &self,
        id: &[u8; 16],
        task_id: &str,
        resource: &str,
    ) -> Result<Option<Receipt>, MembershipError> {
        let Some(dir) = self.progress_dir(id, false)? else {
            return Ok(None);
        };
        read_view(&dir, &receipt_name(task_id, resource), format::VIEW)?
            .map(|bytes| Receipt::decode(&bytes).map_err(MembershipError::from))
            .transpose()
    }

    /// Every receipt of `task_id` of `id`, one per resource, in resource order.
    pub fn zone_receipts(
        &self,
        id: &[u8; 16],
        task_id: &str,
    ) -> Result<Vec<Receipt>, MembershipError> {
        let Some(dir) = self.progress_dir(id, false)? else {
            return Ok(Vec::new());
        };
        let prefix = format!("{task_id}.");
        let suffix = format!(".{RECEIPT}");
        let mut receipts = Vec::new();
        for name in dir.names()? {
            // `<task_id>.<64 hex>.zone`: another task's name never matches its digest's length.
            let Some(middle) = name
                .strip_prefix(&prefix)
                .and_then(|rest| rest.strip_suffix(&suffix))
            else {
                continue;
            };
            if middle.len() != 64 || !middle.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                continue;
            }
            if let Some(bytes) = read_view(&dir, &name, format::VIEW)? {
                receipts.push(Receipt::decode(&bytes)?);
            }
        }
        receipts.sort_by(|left, right| left.resource.cmp(&right.resource));
        Ok(receipts)
    }
}

impl Store {
    /// The handles of the zone keys this Host received as a member, one per purpose, at the
    /// highest version its receipts confirm (owner decision, after the review): what the server
    /// hands its Data Plane at start. A purpose received from more than one coordinator gets no
    /// handle, which leaves it not ready rather than guessing.
    pub fn delivered_handles(
        &self,
        keys: &ZoneKeys,
    ) -> Result<Vec<secrets::ZoneHandle>, MembershipError> {
        let mut by_purpose: std::collections::BTreeMap<
            ZonePurpose,
            std::collections::BTreeMap<[u8; 16], u64>,
        > = std::collections::BTreeMap::new();
        for (id, held) in self.memberships() {
            if held.role != super::record::Role::Member
                || held.status != super::record::Status::Active
            {
                continue;
            }
            let Some((manifest, ..)) = &held.manifest else {
                continue;
            };
            for task in manifest
                .tasks
                .iter()
                .filter(|task| task.task_type == TaskType::ZoneSecrets)
            {
                for receipt in self.zone_receipts(&id, &task.task_id)? {
                    for tuple in receipt.tuples {
                        let version = by_purpose
                            .entry(tuple.purpose)
                            .or_default()
                            .entry(manifest.coordinator.host_id)
                            .or_default();
                        *version = (*version).max(tuple.version);
                    }
                }
            }
        }
        let mut handles = Vec::new();
        for (purpose, authorities) in by_purpose {
            let mut authorities = authorities.into_iter();
            let (Some((authority, version)), None) = (authorities.next(), authorities.next())
            else {
                tracing::warn!(
                    event.name = "host.membership.zone_keys_ambiguous",
                    component = "host",
                    purpose = purpose.as_str(),
                    "zone keys of one purpose were received from several coordinators: none is used"
                );
                continue;
            };
            let version = KeyVersion::new(version).ok_or_else(|| {
                MembershipError::Invalid("a zone version is at least 1".to_owned())
            })?;
            handles.push(
                secrets::ZoneHandle::delivered(purpose, &authority, version, keys)
                    .map_err(|error| MembershipError::Storage(error.to_string()))?,
            );
        }
        Ok(handles)
    }
}

/// The coordinator's handler of `zone.secrets`, version 1: the Host is its provider.
pub struct ZoneSecrets {
    pub coordinator: secrets::Coordinator,
    pub store: Arc<Store>,
    pub time: Arc<TimeGuard>,
}

impl std::fmt::Debug for ZoneSecrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZoneSecrets")
            .field("coordinator", &self.coordinator)
            .finish_non_exhaustive()
    }
}

fn invalid(reason: impl Into<String>) -> Refusal {
    Refusal {
        code: codes::common::INVALID_ARGUMENT,
        reason: reason.into(),
    }
}

fn unavailable(reason: impl Into<String>) -> Refusal {
    Refusal {
        code: codes::common::UNAVAILABLE,
        reason: reason.into(),
    }
}

impl ZoneSecrets {
    /// The tuples the session's task grants over its resource, at the root's version.
    fn granted(&self, context: &TaskContext) -> Result<Vec<Tuple>, Refusal> {
        let held = self
            .store
            .membership(&context.membership_id)
            .ok_or_else(|| invalid("no such membership"))?;
        let task = held
            .manifest
            .as_ref()
            .and_then(|(manifest, ..)| {
                manifest
                    .tasks
                    .iter()
                    .find(|task| task.task_id == context.task_id)
                    .cloned()
            })
            .ok_or_else(|| invalid("the manifest grants no such task"))?;
        let resource =
            Resource::parse(&context.resource).map_err(|error| invalid(error.to_string()))?;
        grant(&task, &resource, self.coordinator.version().get()).map_err(invalid)
    }

    fn key_of(&self, tuple: &Tuple) -> Result<Zeroizing<[u8; KEY_LEN]>, Refusal> {
        self.coordinator
            .distributed(tuple.purpose, &tuple.zone, &tuple.scope)
            .map_err(|error| unavailable(error.to_string()))
    }
}

impl TaskHandler for ZoneSecrets {
    fn handle(&self, context: &TaskContext, body: &[u8]) -> Result<Vec<u8>, Refusal> {
        let granted = self.granted(context)?;
        match Request::decode(body).map_err(|error| invalid(error.0))? {
            Request::Deliver => {
                let keys = granted
                    .iter()
                    .map(|tuple| Ok((*tuple, self.key_of(tuple)?)))
                    .collect::<Result<_, Refusal>>()?;
                let delivery = Delivery { keys }
                    .encode()
                    .map_err(|error| unavailable(error.0))?;
                Ok(delivery.to_vec())
            }
            Request::Confirm(confirmations) => {
                // Exactly the tuples granted, each confirmed under this session's nonce.
                if confirmations.iter().map(|c| c.tuple).collect::<Vec<_>>()
                    != sorted(granted, |tuple| tuple)
                {
                    return Err(invalid(
                        "a confirmation names exactly the tuples the task grants",
                    ));
                }
                let session = Session {
                    authority: self.coordinator.authority(),
                    membership_id: context.membership_id,
                    task_id: &context.task_id,
                    epoch: context.epoch,
                    nonce: context.channel_binding,
                };
                // Every MAC checked before the answer, whichever fails.
                let mut verified = true;
                for confirmation in &confirmations {
                    let key = self.key_of(&confirmation.tuple)?;
                    verified &= confirms(&key, &session, &confirmation.tuple, &confirmation.mac)
                        .map_err(|error| unavailable(error.to_string()))?;
                }
                if !verified {
                    return Err(invalid("a confirmation does not verify for this session"));
                }
                let receipt = Receipt {
                    epoch: context.epoch,
                    confirmed_at: self.time.now_secs(),
                    transcript_digest: transcript_digest(&session, &confirmations)
                        .map_err(|error| unavailable(error.to_string()))?,
                    tuples: confirmations.iter().map(|c| c.tuple).collect(),
                    resource: context.resource.clone(),
                };
                // Kept before it is answered: what the member view shows.
                self.store
                    .keep_zone_receipt(&context.membership_id, &context.task_id, &receipt)
                    .map_err(|error| unavailable(error.to_string()))?;
                receipt.encode().map_err(|error| unavailable(error.0))
            }
        }
    }

    /// Its delivery carries keys, which the replay window must never keep (owner decision): a
    /// repeat is answered again, the keys derived anew and the receipt rewritten.
    fn keeps_answers(&self) -> bool {
        false
    }
}

impl Member<'_> {
    /// Receives the keys `task_id` of `id` grants over `resource`: stores each in `keys`, witnessed
    /// per tuple, then confirms them on the same session and keeps the receipt (WP-4.7). A key
    /// the store refuses, changed under a tuple it holds, is never confirmed.
    pub async fn receive_zone_keys(
        &self,
        initiator: Initiator,
        id: &[u8; 16],
        task_id: &str,
        resource: &str,
        keys: &ZoneKeys,
    ) -> Result<Receipt, MembershipError> {
        let held = self.store.membership(id).ok_or_else(|| {
            MembershipError::Unknown(format!("no membership `{}`", uuid_text(id)))
        })?;
        let Some((manifest, ..)) = &held.manifest else {
            return Err(MembershipError::Invalid("no manifest held".to_owned()));
        };
        let task = manifest
            .tasks
            .iter()
            .find(|task| task.task_id == task_id)
            .cloned()
            .ok_or_else(|| {
                MembershipError::Invalid("the manifest grants no such task".to_owned())
            })?;
        let authority = manifest.coordinator.host_id;
        let parsed = Resource::parse(resource)
            .map_err(|error| MembershipError::Invalid(error.to_string()))?;
        let mut session = self
            .open_task(initiator, id, task_id, resource, Vec::new())
            .await?;
        let answer = session
            .send(
                &format!("zone-deliver-{}", session.lease.epoch),
                Request::Deliver.encode()?,
            )
            .await?;
        let answer = Zeroizing::new(answer);
        let delivery = Delivery::decode(&answer)?;
        // Exactly what the task grants, at the one version the coordinator holds.
        let Some(version) = delivery.keys.first().map(|(tuple, _)| tuple.version) else {
            return Err(MembershipError::Invalid(
                "the coordinator delivered no key".to_owned(),
            ));
        };
        let expected = grant(&task, &parsed, version).map_err(MembershipError::Invalid)?;
        if delivery
            .keys
            .iter()
            .map(|(tuple, _)| *tuple)
            .collect::<Vec<_>>()
            != sorted(expected, |tuple| tuple)
        {
            return Err(MembershipError::Invalid(
                "the coordinator delivered other keys than the task grants".to_owned(),
            ));
        }
        // Durable first: every key stored, witnessed, before any is confirmed.
        for (tuple, key) in &delivery.keys {
            keys.store(&tuple.stored(authority)?, key)
                .map_err(|error| MembershipError::Storage(error.to_string()))?;
        }
        let context = Session {
            authority,
            membership_id: *id,
            task_id,
            epoch: session.lease.epoch,
            nonce: session.lease.channel_binding,
        };
        let confirmations = delivery
            .keys
            .iter()
            .map(|(tuple, key)| {
                Ok(Confirmation {
                    tuple: *tuple,
                    mac: confirmation(key, &context, tuple)?,
                })
            })
            .collect::<Result<Vec<_>, MembershipError>>()?;
        let answer = session
            .send(
                &format!("zone-confirm-{}", session.lease.epoch),
                Request::Confirm(confirmations.clone()).encode()?,
            )
            .await?;
        let receipt = Receipt::decode(&answer)?;
        if receipt.transcript_digest != transcript_digest(&context, &confirmations)?
            || receipt.epoch != context.epoch
            || receipt.tuples != sorted(confirmations.iter().map(|c| c.tuple).collect(), |t| t)
            || receipt.resource != resource
        {
            return Err(MembershipError::Unverified(
                "the receipt is not of this confirmation".to_owned(),
            ));
        }
        self.store.keep_zone_receipt(id, task_id, &receipt)?;
        Ok(receipt)
    }

    /// Receives the keys of every `zone.secrets` task of this Host's active memberships as a
    /// member whose receipt is not of the manifest's epoch, over the task selector's prefix when it
    /// names a zone or a ledger: the server's periodic pass. Answers how many it received; one
    /// that fails is logged and tried again at the next pass.
    pub async fn zone_due(&self, initiator: Initiator, keys: &ZoneKeys) -> usize {
        let mut done = 0;
        for (id, held) in self.store.memberships() {
            if held.role != super::record::Role::Member
                || held.status != super::record::Status::Active
            {
                continue;
            }
            let Some((manifest, ..)) = &held.manifest else {
                continue;
            };
            for task in manifest
                .tasks
                .iter()
                .filter(|task| task.task_type == TaskType::ZoneSecrets)
            {
                let resource = task.selector.prefix();
                if !matches!(resource, Resource::Zone { .. } | Resource::Ledger { .. }) {
                    tracing::debug!(
                        event.name = "host.membership.zone_keys_unasked",
                        component = "host",
                        membership_id = %uuid_text(&id),
                        task_id = %task.task_id,
                        "a zone.secrets task over neither a zone nor a ledger: no key is asked"
                    );
                    continue;
                }
                let current = self
                    .store
                    .zone_receipt(&id, &task.task_id, &resource.to_string())
                    .ok()
                    .flatten()
                    .is_some_and(|receipt| receipt.epoch == manifest.epoch);
                if current {
                    continue;
                }
                match self
                    .receive_zone_keys(
                        initiator.clone(),
                        &id,
                        &task.task_id,
                        &resource.to_string(),
                        keys,
                    )
                    .await
                {
                    Ok(_) => done += 1,
                    Err(error) => tracing::warn!(
                        event.name = "host.membership.zone_keys_failed",
                        component = "host",
                        membership_id = %uuid_text(&id),
                        task_id = %task.task_id,
                        error = %error,
                        "the zone keys could not be received: the next pass tries again"
                    ),
                }
            }
        }
        done
    }
}

#[cfg(test)]
mod tests;
