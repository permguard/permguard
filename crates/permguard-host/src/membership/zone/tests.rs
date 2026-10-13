// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::expect_used)]

use std::sync::Arc;
use std::time::Duration;

use permguard_core::authz::Selector;

use super::*;
use crate::membership::member::Connector;
use crate::membership::record::{Limits, Role, Status};
use crate::membership::task::TaskHandlers;
use crate::membership::tests::protocol::{Loopback, Side, join_of, move_to};
use crate::membership::tests::{Host, offered_nothing};
use crate::membership::{Capabilities, NewInvite};
use crate::operations::mutation::Applying;
use crate::secrets::{Coordinator, Root};

const ZONE: [u8; 16] = [
    0x01, 0xa3, 0x18, 0x5c, 0x50, 0x00, 0x73, 0x33, 0xb3, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
];
const LEDGER: [u8; 16] = [
    0x01, 0xa3, 0x18, 0x5c, 0x50, 0x00, 0x74, 0x44, 0xc4, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
];
const TASK: &str = "zone-keys";
const PSEUDONYM: &str = permguard_core::domains::kdf::AUDIT_PSEUDONYM;
const TAGS: &str = permguard_core::domains::kdf::DECISION_COMMITMENT;

fn who() -> Initiator {
    Initiator::Principal("spiffe://acme/operators/member".to_owned())
}

fn loopback<'a>(m: &'a Side, c: &'a Side) -> Loopback<'a> {
    Loopback {
        member: m,
        coordinator: c,
        tamper: false,
    }
}

fn zone_resource() -> String {
    format!("plane/data/zone/{}", uuid_text(&ZONE))
}

fn ledger_resource() -> String {
    format!("{}/ledger/{}", zone_resource(), uuid_text(&LEDGER))
}

/// A `zone.secrets` task over the zone and its ledgers, granting `purposes`.
fn zone_task(purposes: &[&str]) -> Task {
    Task {
        version: 1,
        task_id: TASK.to_owned(),
        task_type: TaskType::ZoneSecrets,
        selector: Selector::parse(&format!("{}/*", zone_resource())).expect("a selector"),
        resource_types: purposes
            .iter()
            .map(|purpose| (*purpose).to_owned())
            .collect(),
        required: true,
        limits: Limits {
            max_body_bytes: 64 * 1024,
            max_concurrency: 4,
            max_rate_per_minute: 600,
            max_batch_records: 1,
            retention_seconds: 86_400,
        },
        assurance_requirements: Vec::new(),
    }
}

/// The member side of `side` as a server builds it: the Host's own contracts, both sides.
fn hosting<'a>(side: &'a Side, connector: &'a dyn Connector) -> Member<'a> {
    Member {
        store: &side.host.store,
        mutations: &side.mutations,
        identity: &side.host.identity,
        rings: &side.host.rings,
        capabilities: Box::leak(Box::new(Capabilities::host())),
        connector,
        declared_assurance: permguard_core::assurance::AssuranceProfile::Production,
        time: &side.context.time,
        streams: None,
    }
}

/// The coordinator root of `host`, at version 1.
fn coordinator_of(host: &Host) -> Coordinator {
    Coordinator::new(
        Root::from_material(&[0x42; 32], KeyVersion::new(1).expect("a version")).expect("a root"),
        host.identity.host_id(),
    )
}

/// A coordinator serving `zone.secrets` from its root.
fn serving(tag: &str) -> Side {
    let time = Arc::new(TimeGuard::system(Duration::from_secs(30)));
    Side::handling(Host::new(tag), true, time, |host, time| {
        TaskHandlers::default()
            .register(
                TaskType::ZoneSecrets,
                VERSION,
                Arc::new(ZoneSecrets {
                    coordinator: coordinator_of(host),
                    store: Arc::clone(&host.store),
                    time: Arc::clone(time),
                }),
            )
            .expect("one handler")
    })
}

/// A membership of `m` with `c` granting `task`, approved under the Host's own contracts and
/// synced: active on both sides.
async fn zoned(c: &Side, m: &Side, task: Task) -> [u8; 16] {
    let now = crate::authz::store::now();
    let (invitation, token) = c
        .host
        .store
        .invite(
            &Applying::for_tests(1),
            NewInvite {
                selector: Selector::parse("plane/data/*").expect("a selector"),
                tasks: vec![task.clone()],
                expires: None,
                expected_fingerprint: Some(m.host.identity.first_fingerprint().to_owned()),
                min_assurance: None,
            },
            "operator",
            now,
        )
        .expect("invited");
    let connector = loopback(m, c);
    let joining = hosting(m, &connector);
    let id = joining
        .join(
            who(),
            crate::membership::member::Join {
                tasks: vec![task],
                ..join_of(c, &invitation, &token)
            },
        )
        .await
        .expect("joined")
        .request
        .membership_id;
    let (manifest, _, _) = c
        .host
        .store
        .check_approve(
            &c.host.coordinator(),
            &Capabilities::host(),
            &id,
            None,
            None,
            &offered_nothing(),
            None,
            now,
        )
        .expect("approvable");
    c.host
        .store
        .approve(
            &Applying::for_tests(43),
            &c.host.coordinator(),
            &manifest,
            now,
        )
        .expect("approved");
    joining.sync(who(), &id).await.expect("synced");
    id
}

/// The context of a task message on `zone.secrets` of `id`, on a connection bound by `nonce`.
fn context(c: &Side, id: &[u8; 16], resource: &str, nonce: [u8; 32]) -> TaskContext {
    let held = c.host.store.membership(id).expect("held");
    TaskContext {
        membership_id: *id,
        task_id: TASK.to_owned(),
        task_type: TaskType::ZoneSecrets,
        version: VERSION,
        epoch: held.epoch(),
        resource: resource.to_owned(),
        member: held.request.member.host_id,
        request_id: "r-1".to_owned(),
        limits: zone_task(&[]).limits,
        channel_binding: nonce,
    }
}

fn handler(c: &Side) -> ZoneSecrets {
    ZoneSecrets {
        coordinator: coordinator_of(&c.host),
        store: Arc::clone(&c.host.store),
        time: Arc::clone(&c.context.time),
    }
}

/// WP-4.7, owner decision: a zone resource grants the zone's shared pseudonym key, a ledger
/// resource that ledger's input-tag key, each only when the task's `resource_types` name its
/// purpose; nothing else is granted.
#[test]
fn a_member_receives_only_the_keys_its_task_and_resource_grant() {
    let both = zone_task(&[PSEUDONYM, TAGS]);
    let zone = Resource::parse(&zone_resource()).expect("a resource");
    let ledger = Resource::parse(&ledger_resource()).expect("a resource");
    assert_eq!(
        grant(&both, &zone, 1).expect("granted"),
        vec![Tuple {
            purpose: ZonePurpose::AuditPseudonym,
            zone: ZONE,
            scope: ZONE,
            version: 1,
        }]
    );
    assert_eq!(
        grant(&both, &ledger, 2).expect("granted"),
        vec![Tuple {
            purpose: ZonePurpose::DecisionCommitment,
            zone: ZONE,
            scope: LEDGER,
            version: 2,
        }]
    );
    // A purpose the task does not name is never granted.
    assert!(grant(&zone_task(&[TAGS]), &zone, 1).is_err());
    assert!(grant(&zone_task(&[PSEUDONYM]), &ledger, 1).is_err());
    // Neither another resource level, nor an id that is no UUID, nor another task type.
    assert!(grant(&both, &Resource::plane("data"), 1).is_err());
    assert!(grant(&both, &Resource::zone("data", "acme"), 1).is_err());
    let mut other = both.clone();
    other.task_type = TaskType::DecisionsShip;
    assert!(grant(&other, &zone, 1).is_err());
}

/// WP-4.7: a member asks, stores what it receives witnessed per tuple, confirms it on the same
/// session, and both sides keep the same receipt; its keys are the coordinator's derivation, and
/// the session resolves to the Host's handler.
#[tokio::test]
async fn a_member_stores_its_keys_then_confirms_them() {
    let (c, m) = (serving("zone-c"), Side::new("zone-m", false));
    let id = zoned(&c, &m, zone_task(&[PSEUDONYM, TAGS])).await;
    let keys = ZoneKeys::open(m.host.volume()).expect("the store");
    let connector = loopback(&m, &c);
    let acting = hosting(&m, &connector);
    for (resource, purpose, scope) in [
        (zone_resource(), ZonePurpose::AuditPseudonym, ZONE),
        (ledger_resource(), ZonePurpose::DecisionCommitment, LEDGER),
    ] {
        let receipt = acting
            .receive_zone_keys(who(), &id, TASK, &resource, &keys)
            .await
            .expect("received");
        let tuple = Tuple {
            purpose,
            zone: ZONE,
            scope,
            version: 1,
        };
        assert_eq!(receipt.tuples, vec![tuple]);
        assert_eq!(receipt.epoch, 1);
        let stored = keys
            .load(&tuple.stored(c.host.identity.host_id()).expect("a tuple"))
            .expect("read")
            .expect("stored");
        let derived = coordinator_of(&c.host)
            .distributed(purpose, &ZONE, &scope)
            .expect("derived");
        assert_eq!(&stored[..], &derived[..], "the coordinator's derivation");
        assert_eq!(receipt.resource, resource);
        assert_eq!(
            c.host
                .store
                .zone_receipt(&id, TASK, &resource)
                .expect("read"),
            Some(receipt.clone()),
            "the coordinator keeps the receipt"
        );
        assert_eq!(
            m.host
                .store
                .zone_receipt(&id, TASK, &resource)
                .expect("read"),
            Some(receipt),
            "the member keeps the same"
        );
    }
    // One receipt per resource: the ledger's did not replace the zone's (owner decision).
    for store in [&c.host.store, &m.host.store] {
        let receipts = store.zone_receipts(&id, TASK).expect("read");
        assert_eq!(
            receipts
                .iter()
                .map(|receipt| receipt.resource.clone())
                .collect::<Vec<_>>(),
            vec![zone_resource(), ledger_resource()]
        );
    }
}

/// WP-4.7, owner decision: the keys travel on the session alone; the coordinator writes them
/// nowhere, not in the replay window, its receipts or its trail.
#[tokio::test]
async fn a_delivered_key_is_kept_nowhere_at_the_coordinator() {
    let (c, m) = (serving("nowhere-c"), Side::new("nowhere-m", false));
    let id = zoned(&c, &m, zone_task(&[PSEUDONYM])).await;
    let keys = ZoneKeys::open(m.host.volume()).expect("the store");
    let connector = loopback(&m, &c);
    hosting(&m, &connector)
        .receive_zone_keys(who(), &id, TASK, &zone_resource(), &keys)
        .await
        .expect("received");
    let key = coordinator_of(&c.host)
        .distributed(ZonePurpose::AuditPseudonym, &ZONE, &ZONE)
        .expect("derived");
    let mut files = vec![c.host.volume().host().path().to_path_buf()];
    let mut seen = 0;
    while let Some(path) = files.pop() {
        if path.is_dir() {
            for entry in std::fs::read_dir(&path).expect("a directory") {
                files.push(entry.expect("an entry").path());
            }
        } else if let Ok(bytes) = std::fs::read(&path) {
            seen += 1;
            assert!(
                !bytes.windows(KEY_LEN).any(|window| window == &key[..]),
                "{} holds a delivered key",
                path.display()
            );
        }
    }
    assert!(seen > 0, "the coordinator's volume was read");
    let hex: String = key.iter().map(|byte| format!("{byte:02x}")).collect();
    for (_, facts) in c.trail.facts.lock().expect("lock").iter() {
        assert!(facts.iter().all(|(_, value)| !value.contains(&hex)));
    }
}

/// WP-4.7, owner decision: the confirmation's nonce is the channel binding of the session's
/// lease, so a confirmation made on one connection is refused on another and keeps nothing.
#[tokio::test]
async fn a_confirmation_cannot_be_replayed_in_another_session() {
    let (c, m) = (serving("replay-c"), Side::new("replay-m", false));
    let id = zoned(&c, &m, zone_task(&[PSEUDONYM])).await;
    let handler = handler(&c);
    let first = context(&c, &id, &zone_resource(), [1; 32]);
    let delivery = Delivery::decode(
        &handler
            .handle(&first, &Request::Deliver.encode().expect("encodes"))
            .expect("delivered"),
    )
    .expect("a delivery");
    let (tuple, key) = &delivery.keys[0];
    let session = Session {
        authority: c.host.identity.host_id(),
        membership_id: id,
        task_id: TASK,
        epoch: first.epoch,
        nonce: first.channel_binding,
    };
    let confirm = Request::Confirm(vec![Confirmation {
        tuple: *tuple,
        mac: confirmation(key, &session, tuple).expect("a MAC"),
    }])
    .encode()
    .expect("encodes");
    let other = context(&c, &id, &zone_resource(), [2; 32]);
    let refused = handler
        .handle(&other, &confirm)
        .expect_err("another session");
    assert_eq!(refused.code, codes::common::INVALID_ARGUMENT);
    assert_eq!(
        c.host
            .store
            .zone_receipt(&id, TASK, &zone_resource())
            .expect("read"),
        None
    );
    let receipt = Receipt::decode(&handler.handle(&first, &confirm).expect("its own session"))
        .expect("a receipt");
    assert_eq!(
        receipt.transcript_digest,
        transcript_digest(
            &session,
            &[Confirmation {
                tuple: *tuple,
                mac: confirmation(key, &session, tuple).expect("a MAC"),
            }]
        )
        .expect("a digest")
    );
}

/// WP-4.7: a MAC under another key, a tuple the task does not grant, or a confirmation of only
/// part of the grant is refused, and no receipt is kept.
#[tokio::test]
async fn a_wrong_confirmation_is_refused_and_nothing_kept() {
    let (c, m) = (serving("wrong-c"), Side::new("wrong-m", false));
    let id = zoned(&c, &m, zone_task(&[PSEUDONYM])).await;
    let handler = handler(&c);
    let at = context(&c, &id, &zone_resource(), [3; 32]);
    let session = Session {
        authority: c.host.identity.host_id(),
        membership_id: id,
        task_id: TASK,
        epoch: at.epoch,
        nonce: at.channel_binding,
    };
    let granted = Tuple {
        purpose: ZonePurpose::AuditPseudonym,
        zone: ZONE,
        scope: ZONE,
        version: 1,
    };
    let other_zone = Tuple {
        zone: LEDGER,
        scope: LEDGER,
        ..granted
    };
    for confirmations in [
        vec![Confirmation {
            tuple: granted,
            mac: confirmation(&[9; KEY_LEN], &session, &granted).expect("a MAC"),
        }],
        vec![Confirmation {
            tuple: other_zone,
            mac: [0; 32],
        }],
        Vec::new(),
    ] {
        let refused = handler
            .handle(
                &at,
                &Request::Confirm(confirmations).encode().expect("encodes"),
            )
            .expect_err("refused");
        assert_eq!(refused.code, codes::common::INVALID_ARGUMENT);
    }
    assert_eq!(
        c.host
            .store
            .zone_receipt(&id, TASK, &zone_resource())
            .expect("read"),
        None
    );
}

/// WP-4.7: the member's witness refuses another key under a tuple it holds; such a key is never
/// confirmed, and the coordinator keeps no receipt.
#[tokio::test]
async fn a_changed_key_under_a_held_tuple_is_refused_and_not_confirmed() {
    let (c, m) = (serving("changed-c"), Side::new("changed-m", false));
    let id = zoned(&c, &m, zone_task(&[PSEUDONYM])).await;
    let keys = ZoneKeys::open(m.host.volume()).expect("the store");
    let tuple = Tuple {
        purpose: ZonePurpose::AuditPseudonym,
        zone: ZONE,
        scope: ZONE,
        version: 1,
    };
    keys.store(
        &tuple.stored(c.host.identity.host_id()).expect("a tuple"),
        &[0x77; KEY_LEN],
    )
    .expect("another key held");
    let connector = loopback(&m, &c);
    let refused = hosting(&m, &connector)
        .receive_zone_keys(who(), &id, TASK, &zone_resource(), &keys)
        .await
        .expect_err("changed");
    assert!(
        matches!(refused, MembershipError::Storage(_)),
        "{refused:?}"
    );
    assert_eq!(
        c.host
            .store
            .zone_receipt(&id, TASK, &zone_resource())
            .expect("read"),
        None
    );
    assert_eq!(
        m.host
            .store
            .zone_receipt(&id, TASK, &zone_resource())
            .expect("read"),
        None
    );
}

/// WP-4.7: a revoked membership's `zone.secrets` task is fenced at once: no key is delivered.
#[tokio::test]
async fn a_revoked_member_receives_no_key() {
    let (c, m) = (serving("revoked-c"), Side::new("revoked-m", false));
    let id = zoned(&c, &m, zone_task(&[PSEUDONYM])).await;
    move_to(&c, &id, Status::Revoked, 61);
    let keys = ZoneKeys::open(m.host.volume()).expect("the store");
    let connector = loopback(&m, &c);
    let refused = hosting(&m, &connector)
        .receive_zone_keys(who(), &id, TASK, &zone_resource(), &keys)
        .await
        .expect_err("revoked");
    // Its pin is gone with the membership: the coordinator refuses the session itself.
    assert!(
        matches!(&refused, MembershipError::Remote { code, .. } if code == codes::host::SESSION_REFUSED),
        "{refused:?}"
    );
    let tuple = Tuple {
        purpose: ZonePurpose::AuditPseudonym,
        zone: ZONE,
        scope: ZONE,
        version: 1,
    };
    assert_eq!(
        keys.load(&tuple.stored(c.host.identity.host_id()).expect("a tuple"))
            .expect("read"),
        None
    );
    assert_eq!(
        c.host
            .store
            .zone_receipt(&id, TASK, &zone_resource())
            .expect("read"),
        None
    );
}

/// WP-4.7: the member's pass receives the keys of each task whose receipt is not of the
/// manifest's epoch, once; a new epoch asks again.
#[tokio::test]
async fn the_pass_receives_once_per_epoch() {
    let (c, m) = (serving("pass-c"), Side::new("pass-m", false));
    let id = zoned(&c, &m, zone_task(&[PSEUDONYM])).await;
    let keys = ZoneKeys::open(m.host.volume()).expect("the store");
    let connector = loopback(&m, &c);
    let acting = hosting(&m, &connector);
    assert_eq!(acting.zone_due(who(), &keys).await, 1);
    assert_eq!(
        acting.zone_due(who(), &keys).await,
        0,
        "the receipt is current"
    );
    move_to(&c, &id, Status::Active, 62);
    acting.sync(who(), &id).await.expect("synced");
    assert_eq!(acting.zone_due(who(), &keys).await, 1, "a new epoch");
    assert_eq!(
        m.host
            .store
            .zone_receipt(&id, TASK, &zone_resource())
            .expect("read")
            .expect("kept")
            .epoch,
        2
    );
}

/// WP-4.7: the coordinator's member view shows a task's receipt, the versions confirmed and the
/// transcript digest, never a key.
#[tokio::test]
async fn the_member_view_shows_receipts_never_keys() {
    let (c, m) = (serving("view-c"), Side::new("view-m", false));
    let id = zoned(&c, &m, zone_task(&[PSEUDONYM])).await;
    let keys = ZoneKeys::open(m.host.volume()).expect("the store");
    let connector = loopback(&m, &c);
    let receipt = hosting(&m, &connector)
        .receive_zone_keys(who(), &id, TASK, &zone_resource(), &keys)
        .await
        .expect("received");
    let manifest = c
        .host
        .store
        .membership(&id)
        .expect("held")
        .manifest
        .expect("a manifest")
        .0;
    let observed = c
        .host
        .store
        .observed(&manifest, c.context.time.now_secs())
        .expect("observed");
    assert_eq!(observed.len(), 1);
    assert_eq!(observed[0].zone_receipts, vec![receipt]);
    assert_eq!(manifest.member.host_id, m.host.identity.host_id());
    assert_eq!(
        c.host.store.membership(&id).expect("held").role,
        Role::Coordinator
    );
}

/// The records' shapes: what decodes encodes back, and the bounds are the decoders'.
#[test]
fn the_zone_records_read_back_and_refuse_what_they_forbid() {
    let tuple = Tuple {
        purpose: ZonePurpose::DecisionCommitment,
        zone: ZONE,
        scope: LEDGER,
        version: 1,
    };
    let confirm = Request::Confirm(vec![Confirmation {
        tuple,
        mac: [1; 32],
    }]);
    assert_eq!(
        Request::decode(&confirm.encode().expect("encodes")).expect("decodes"),
        confirm
    );
    let receipt = Receipt {
        epoch: 2,
        confirmed_at: 1_800_000_000,
        transcript_digest: [2; 32],
        tuples: vec![tuple],
        resource: ledger_resource(),
    };
    assert_eq!(
        Receipt::decode(&receipt.encode().expect("encodes")).expect("decodes"),
        receipt
    );
    let delivery = Delivery::of([(tuple, [3; KEY_LEN])]);
    let bytes = delivery.encode().expect("encodes");
    assert_eq!(Delivery::decode(&bytes).expect("decodes").keys[0].0, tuple);
    assert_eq!(
        format!("{delivery:?}"),
        format!("{:?}", [tuple]),
        "the tuples only, never a key"
    );
    // A pseudonym key whose scope is not its zone, a version 0, an unknown action, two tuples
    // out of order.
    let bad_scope = Receipt {
        tuples: vec![Tuple {
            purpose: ZonePurpose::AuditPseudonym,
            ..tuple
        }],
        ..receipt.clone()
    };
    assert!(Receipt::decode(&bad_scope.encode().expect("encodes")).is_err());
    let zero = Receipt {
        tuples: vec![Tuple {
            version: 0,
            ..tuple
        }],
        ..receipt.clone()
    };
    assert!(Receipt::decode(&zero.encode().expect("encodes")).is_err());
    let loose = Receipt {
        resource: format!("{}/", zone_resource()),
        ..receipt.clone()
    };
    assert!(Receipt::decode(&loose.encode().expect("encodes")).is_err());
    assert!(
        Request::decode(
            &encode(vec![(Value::Int(1), Value::Text("steal".to_owned()))]).expect("encodes")
        )
        .is_err()
    );
    let second = Tuple {
        purpose: ZonePurpose::AuditPseudonym,
        zone: ZONE,
        scope: ZONE,
        version: 1,
    };
    let unordered = encode(vec![
        (Value::Int(1), uint(2).expect("a uint")),
        (Value::Int(2), uint(1).expect("a uint")),
        (Value::Int(3), Value::Bytes(vec![2; 32])),
        (
            Value::Int(4),
            Value::Array(vec![
                tuple.value().expect("a value"),
                second.value().expect("a value"),
            ]),
        ),
    ])
    .expect("encodes");
    assert!(Receipt::decode(&unordered).is_err());
}

/// A coordinator's handler that answers what its task does not grant, or a receipt of another
/// transcript.
struct Tampering {
    inner: ZoneSecrets,
    mode: Tamper,
}

/// What a tampering coordinator alters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tamper {
    /// A key the task does not grant, in the delivery.
    ExtraKey,
    /// The receipt's transcript digest.
    Digest,
    /// The receipt's resource.
    Resource,
}

impl TaskHandler for Tampering {
    fn handle(&self, context: &TaskContext, body: &[u8]) -> Result<Vec<u8>, Refusal> {
        let answer = self.inner.handle(context, body)?;
        match Request::decode(body).expect("a request") {
            Request::Deliver if self.mode == Tamper::ExtraKey => {
                let mut delivery = Delivery::decode(&answer).expect("a delivery");
                delivery.keys.push((
                    Tuple {
                        purpose: ZonePurpose::DecisionCommitment,
                        zone: ZONE,
                        scope: LEDGER,
                        version: 1,
                    },
                    Zeroizing::new([0x66; KEY_LEN]),
                ));
                Ok(delivery.encode().expect("encodes").to_vec())
            }
            Request::Confirm(_) if self.mode != Tamper::ExtraKey => {
                let mut receipt = Receipt::decode(&answer).expect("a receipt");
                if self.mode == Tamper::Digest {
                    receipt.transcript_digest = [0; 32];
                } else {
                    receipt.resource = ledger_resource();
                }
                Ok(receipt.encode().expect("encodes"))
            }
            _ => Ok(answer),
        }
    }

    fn keeps_answers(&self) -> bool {
        false
    }
}

/// WP-4.7: the member checks what it receives against its own grant and its own transcript: a
/// key the task does not grant is refused before anything is stored, and a receipt of another
/// transcript is never kept.
#[tokio::test]
async fn a_member_refuses_an_ungranted_key_and_a_receipt_of_another_transcript() {
    for mode in [Tamper::ExtraKey, Tamper::Digest, Tamper::Resource] {
        let time = Arc::new(TimeGuard::system(Duration::from_secs(30)));
        let c = Side::handling(Host::new("tamper-c"), true, time, |host, time| {
            TaskHandlers::default()
                .register(
                    TaskType::ZoneSecrets,
                    VERSION,
                    Arc::new(Tampering {
                        inner: ZoneSecrets {
                            coordinator: coordinator_of(host),
                            store: Arc::clone(&host.store),
                            time: Arc::clone(time),
                        },
                        mode,
                    }),
                )
                .expect("one handler")
        });
        let m = Side::new("tamper-m", false);
        let id = zoned(&c, &m, zone_task(&[PSEUDONYM, TAGS])).await;
        let keys = ZoneKeys::open(m.host.volume()).expect("the store");
        let connector = loopback(&m, &c);
        let refused = hosting(&m, &connector)
            .receive_zone_keys(who(), &id, TASK, &zone_resource(), &keys)
            .await
            .expect_err("tampered");
        let tuple = Tuple {
            purpose: ZonePurpose::AuditPseudonym,
            zone: ZONE,
            scope: ZONE,
            version: 1,
        };
        let held = keys
            .load(&tuple.stored(c.host.identity.host_id()).expect("a tuple"))
            .expect("read");
        if mode == Tamper::ExtraKey {
            assert!(
                matches!(refused, MembershipError::Invalid(_)),
                "{refused:?}"
            );
            assert_eq!(held, None, "nothing stored before the grant is checked");
        } else {
            assert!(
                matches!(refused, MembershipError::Unverified(_)),
                "{refused:?}"
            );
        }
        assert_eq!(
            m.host
                .store
                .zone_receipt(&id, TASK, &zone_resource())
                .expect("read"),
            None
        );
    }
}

/// WP-4.7, end to end: each task connection reports its own exporter, so a confirmation captured
/// on one session is refused on the next and nothing is kept.
#[tokio::test]
async fn a_confirmation_captured_on_one_connection_is_refused_on_the_next() {
    let (c, m) = (serving("capture-c"), Side::new("capture-m", false));
    let id = zoned(&c, &m, zone_task(&[PSEUDONYM])).await;
    let connector = loopback(&m, &c);
    let acting = hosting(&m, &connector);
    let resource = zone_resource();
    let open = |exporter: [u8; 32]| {
        crate::membership::tests::TASK_EXPORTER.with(|cell| cell.set(Some(exporter)));
        acting.open_task(who(), &id, TASK, &resource, Vec::new())
    };
    let mut first = open([0xA1; 32]).await.expect("leased");
    let delivery = Delivery::decode(
        &first
            .send("deliver", Request::Deliver.encode().expect("encodes"))
            .await
            .expect("delivered"),
    )
    .expect("a delivery");
    let (tuple, key) = &delivery.keys[0];
    let session = Session {
        authority: c.host.identity.host_id(),
        membership_id: id,
        task_id: TASK,
        epoch: first.lease.epoch,
        nonce: first.lease.channel_binding,
    };
    let captured = Request::Confirm(vec![Confirmation {
        tuple: *tuple,
        mac: confirmation(key, &session, tuple).expect("a MAC"),
    }])
    .encode()
    .expect("encodes");
    drop(first);
    let mut second = open([0xA2; 32]).await.expect("leased again");
    crate::membership::tests::TASK_EXPORTER.with(|cell| cell.set(None));
    assert_ne!(
        second.lease.channel_binding, session.nonce,
        "another connection"
    );
    let refused = second
        .send("confirm", captured)
        .await
        .expect_err("replayed");
    assert!(
        matches!(&refused, MembershipError::Remote { code, .. } if code == codes::common::INVALID_ARGUMENT),
        "{refused:?}"
    );
    assert_eq!(
        c.host
            .store
            .zone_receipt(&id, TASK, &zone_resource())
            .expect("read"),
        None
    );
}

/// WP-4.7: one handler per contract: a second registration of `zone.secrets` version 1 is
/// refused rather than replacing the first.
#[test]
fn a_contract_takes_one_handler() {
    let host = Host::new("one-handler");
    let handler = || {
        Arc::new(ZoneSecrets {
            coordinator: coordinator_of(&host),
            store: Arc::clone(&host.store),
            time: Arc::new(TimeGuard::system(Duration::from_secs(30))),
        })
    };
    let handlers = TaskHandlers::default()
        .register(TaskType::ZoneSecrets, VERSION, handler())
        .expect("the first");
    assert!(handlers.serves(TaskType::ZoneSecrets, VERSION));
    assert!(!handlers.serves(TaskType::ZoneSecrets, 2));
    assert!(
        handlers
            .register(TaskType::ZoneSecrets, VERSION, handler())
            .is_err()
    );
}

/// WP-4.7, owner decision after the review: the keys a member received become, at start, one
/// handle per purpose at the highest version its receipts confirm, which MACs as the
/// coordinator's own; a purpose received from two coordinators gets no handle.
#[tokio::test]
async fn the_keys_received_become_a_planes_handle_and_two_authorities_none() {
    let (c, m) = (serving("handle-c"), Side::new("handle-m", false));
    let id = zoned(&c, &m, zone_task(&[PSEUDONYM])).await;
    let keys = ZoneKeys::open(m.host.volume()).expect("the store");
    assert!(
        m.host
            .store
            .delivered_handles(&keys)
            .expect("read")
            .is_empty(),
        "nothing received yet"
    );
    let connector = loopback(&m, &c);
    hosting(&m, &connector)
        .receive_zone_keys(who(), &id, TASK, &zone_resource(), &keys)
        .await
        .expect("received");
    let handles = m.host.store.delivered_handles(&keys).expect("read");
    assert_eq!(handles.len(), 1);
    assert_eq!(handles[0].purpose(), ZonePurpose::AuditPseudonym);
    assert_eq!(handles[0].version().get(), 1);
    let coordinated =
        secrets::ZoneHandle::coordinated(ZonePurpose::AuditPseudonym, coordinator_of(&c.host));
    assert_eq!(
        handles[0].mac(&ZONE, &ZONE, &[b"alice"]),
        coordinated.mac(&ZONE, &ZONE, &[b"alice"]),
        "the member MACs as its coordinator"
    );
    assert!(handles[0].mac(&LEDGER, &LEDGER, &[b"alice"]).is_none());
    // A second coordinator delivering the same purpose: ambiguous, so no handle at all.
    let other = serving("handle-c2");
    let second = zoned(&other, &m, zone_task(&[PSEUDONYM])).await;
    let connector = loopback(&m, &other);
    hosting(&m, &connector)
        .receive_zone_keys(who(), &second, TASK, &zone_resource(), &keys)
        .await
        .expect("received");
    assert!(
        m.host
            .store
            .delivered_handles(&keys)
            .expect("read")
            .is_empty()
    );
}
