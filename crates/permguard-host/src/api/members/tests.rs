// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::expect_used)]

use super::*;
use crate::api::testing::{actor, admin, reopen, scratch};
use crate::identity::verify_published;
use crate::keys::ring::{DATA_ATTEST, HOST_OPERATIONS};
use crate::membership::record::{EnrollRequest, Pending};
use crate::membership::tests::{EXPORTER, Host, decisions};
use crate::membership::{Enrolling, token_proof};
use crate::operations::mutation::Applying;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn json_of(value: &impl serde::Serialize) -> String {
    serde_json::to_string(value).expect("serializes")
}

fn code(refusal: &Refusal) -> &str {
    refusal.error().expect("a domain refusal").code()
}

fn now() -> u64 {
    crate::authz::store::now()
}

pub(crate) fn task_view() -> TaskView {
    TaskView::from(&decisions("plane/data/*"))
}

fn create(request_id: &str, member: Option<&Host>) -> CreateInvite {
    CreateInvite {
        request_id: request_id.to_owned(),
        selector: "plane/data/*".to_owned(),
        tasks: vec![task_view()],
        expires: None,
        expected_fingerprint: member.map(|m| m.identity.first_fingerprint().to_owned()),
        min_assurance: Some("production".to_owned()),
        max_uses: 1,
    }
}

fn change(request_id: &str, expected_revision: u64) -> ChangeMember {
    ChangeMember {
        request_id: request_id.to_owned(),
        expected_revision,
        reason: None,
    }
}

/// Invites `member` through the facade and enrolls it as the coordinator's session would: the
/// pending membership's id, and the request the member's store records.
pub(crate) async fn enrolled(api: &HostApi, member: &Host, request_id: &str) -> (String, Pending) {
    enrolled_requiring(api, member, request_id, &[]).await
}

/// [`enrolled`], the task requiring `controls` (WP-4.2).
pub(crate) async fn enrolled_requiring(
    api: &HostApi,
    member: &Host,
    request_id: &str,
    controls: &[&str],
) -> (String, Pending) {
    let mut task = decisions("plane/data/*");
    task.assurance_requirements = controls.iter().map(|name| (*name).to_owned()).collect();
    let created = api
        .create_invite(
            &admin(),
            CreateInvite {
                tasks: vec![TaskView::from(&task)],
                ..create(request_id, Some(member))
            },
        )
        .await
        .expect("invited");
    let token = URL_SAFE_NO_PAD.decode(&created.token).expect("base64url");
    let identity = api.identity.as_deref().expect("an identity");
    let coordinator = Coordinator {
        identity,
        rings: api.keys.rings(),
    };
    let request = EnrollRequest {
        invite_id: id_of(&created.invite_id).expect("an id"),
        token_proof: token_proof(
            &token,
            &identity.host_id(),
            &member.identity.host_id(),
            &EXPORTER,
        ),
        selector: selector("plane/data/*").expect("a selector"),
        tasks: vec![task],
        member: member.host_ref(),
        ring_statements: vec![member.statement(DATA_ATTEST)],
    };
    let store = &api.memberships.as_deref().expect("memberships").store;
    let pending = store
        .check_enroll(
            &coordinator,
            &Enrolling {
                peer: &member.verified(),
                presentation: &member.presentation(),
                declared_assurance: AssuranceProfile::Production,
                exporter: &EXPORTER,
            },
            &request,
            now(),
        )
        .expect("the enrollment checks");
    store
        .enroll(&Applying::for_tests(70), &pending, now())
        .expect("enrolled");
    (uuid_text(&pending.membership_id), pending)
}

/// Every file under `root`.
fn files(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut found = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir).expect("readable").flatten() {
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else {
                found.push(path);
            }
        }
    }
    found
}

#[tokio::test]
async fn an_invitation_shows_its_token_once_lists_by_hash_and_keeps_it_in_no_file() {
    let root = scratch("members-invite");
    let (api, _, _volume) = reopen(&root, vec![HOST_OPERATIONS]);
    let created = api
        .create_invite(&admin(), create("invite-1", None))
        .await
        .expect("invited");
    let token = URL_SAFE_NO_PAD.decode(&created.token).expect("base64url");
    assert_eq!(token.len(), 32);

    let listed = api.invites(&admin()).expect("listed");
    assert_eq!(listed.invites.len(), 1);
    assert_eq!(listed.invites[0].invite_id, created.invite_id);
    // Listed by id: nothing in a listing signs an enrollment.
    assert!(!json_of(&listed).contains(&hex(&token)));
    assert_eq!(listed.invites[0].status, "issued");
    assert_eq!(listed.invites[0].created_by, crate::api::testing::ADMIN);
    let json = serde_json::to_string(&listed).expect("serializes");
    assert!(!json.contains(&created.token));

    // A retry is answered from the replay window, which holds no token: refused, not re-shown.
    let retried = api
        .create_invite(&admin(), create("invite-1", None))
        .await
        .expect_err("the token was shown once");
    assert_eq!(code(&retried), codes::host::INVITE_TOKEN_SHOWN);
    assert_eq!(api.invites(&admin()).expect("listed").invites.len(), 1);

    // No file of the volume carries the token, in any spelling.
    let spellings = [
        token.clone(),
        created.token.clone().into_bytes(),
        hex(&token).into_bytes(),
    ];
    for path in files(&root) {
        let bytes = std::fs::read(&path).expect("readable");
        for spelling in &spellings {
            assert!(
                !bytes
                    .windows(spelling.len())
                    .any(|w| w == spelling.as_slice()),
                "{} carries the token",
                path.display()
            );
        }
    }

    api.delete_invite(&admin(), &created.invite_id, "invite-2".to_owned())
        .await
        .expect("deleted");
    assert_eq!(
        api.invites(&admin()).expect("listed").invites[0].status,
        "revoked"
    );
    let unknown = api
        .delete_invite(&admin(), &uuid_text(&[0x11; 16]), "invite-3".to_owned())
        .await
        .expect_err("no such invitation");
    assert_eq!(code(&unknown), codes::host::INVITE_UNKNOWN);

    let wide = api
        .create_invite(
            &admin(),
            CreateInvite {
                max_uses: 2,
                ..create("invite-4", None)
            },
        )
        .await
        .expect_err("used once");
    assert_eq!(code(&wide), codes::common::INVALID_ARGUMENT);
}

#[tokio::test]
async fn a_membership_walks_its_lifecycle_and_every_manifest_verifies_at_the_member() {
    let root = scratch("members-lifecycle");
    let (api, _, _volume) = reopen(&root, vec![HOST_OPERATIONS]);
    let member = Host::new("api-lifecycle-member");
    let (id, pending) = enrolled(&api, &member, "life-1").await;

    let listed = api.members(&admin(), None).expect("listed");
    assert_eq!(listed.members.len(), 1);
    let view = &listed.members[0];
    assert_eq!(
        (view.status.as_str(), view.role.as_str(), view.epoch),
        ("pending", "coordinator", 0)
    );
    assert!(view.manifest.is_none() && view.lease_policy.is_none());
    let revision = view.revision;

    // A lost race names the current revision.
    match api
        .approve_member(
            &admin(),
            &id,
            ApproveMember {
                request_id: "life-2".to_owned(),
                expected_revision: revision + 1,
                narrow: None,
                lease_policy: None,
                assurance: None,
            },
        )
        .await
    {
        Err(Refusal::Conflict {
            revision: current, ..
        }) => assert_eq!(current, revision),
        other => panic!("a conflict, not {other:?}"),
    }
    // An approval never widens the request.
    let widened = api
        .approve_member(
            &admin(),
            &id,
            ApproveMember {
                request_id: "life-3".to_owned(),
                expected_revision: revision,
                narrow: Some(NarrowView {
                    selector: "plane/data/*".to_owned(),
                    tasks: vec![TaskView {
                        limits: LimitsView {
                            max_concurrency: 1000,
                            ..task_view().limits
                        },
                        ..task_view()
                    }],
                }),
                lease_policy: None,
                assurance: None,
            },
        )
        .await
        .expect_err("wider than the request");
    assert_eq!(code(&widened), codes::host::MEMBERSHIP_WIDENED);

    let approved = api
        .approve_member(
            &admin(),
            &id,
            ApproveMember {
                request_id: "life-4".to_owned(),
                expected_revision: revision,
                narrow: None,
                lease_policy: Some(LeasePolicyView {
                    max_session_seconds: 1800,
                    offline_grace_seconds: 300,
                    clock_skew_seconds: 30,
                    dormant_after_seconds: 3600,
                    revoke_after_seconds: 7200,
                }),
                assurance: None,
            },
        )
        .await
        .expect("approved");
    assert_eq!((approved.status.as_str(), approved.epoch), ("active", 1));
    let view = api.member(&admin(), &id).expect("read");
    assert_eq!(view.lease_policy.expect("signed").max_session_seconds, 1800);
    assert_eq!(view.manifest.as_deref(), Some(approved.manifest.as_str()));

    let suspended = api
        .suspend_member(&admin(), &id, change("life-5", view.revision))
        .await
        .expect("suspended");
    assert_eq!(
        (suspended.status.as_str(), suspended.epoch),
        ("suspended", 2)
    );
    let fenced = api
        .fence_member(&admin(), &id, change("life-6", suspended.receipt.revision))
        .await
        .expect_err("a suspended membership is not fenced");
    assert_eq!(code(&fenced), codes::host::MEMBERSHIP_TRANSITION_REFUSED);
    let resumed = api
        .resume_member(&admin(), &id, change("life-7", suspended.receipt.revision))
        .await
        .expect("resumed");
    assert_eq!((resumed.status.as_str(), resumed.epoch), ("active", 3));
    let fenced = api
        .fence_member(&admin(), &id, change("life-8", resumed.receipt.revision))
        .await
        .expect("fenced");
    assert_eq!((fenced.status.as_str(), fenced.epoch), ("active", 4));
    let again = api
        .resume_member(&admin(), &id, change("life-9", fenced.receipt.revision))
        .await
        .expect_err("an active membership is not resumed");
    assert_eq!(code(&again), codes::host::MEMBERSHIP_TRANSITION_REFUSED);

    // The revocation is planned, then run with the plan's digest.
    let planned = api
        .plan_member_revoke(
            &admin(),
            &id,
            PlanMemberRevoke {
                request_id: "life-10".to_owned(),
                reason: "decommissioned".to_owned(),
                expected_revision: Some(fenced.receipt.revision),
            },
        )
        .await
        .expect("planned");
    let mismatch = api
        .run_member_revoke(
            &admin(),
            &id,
            RunMemberRevoke {
                request_id: "life-11".to_owned(),
                plan_id: planned.plan_id.clone(),
                plan_digest: "00".repeat(32),
            },
        )
        .await
        .expect_err("another digest");
    assert_eq!(code(&mismatch), codes::host::PLAN_DIGEST_MISMATCH);
    let revoked = api
        .run_member_revoke(
            &admin(),
            &id,
            RunMemberRevoke {
                request_id: "life-12".to_owned(),
                plan_id: planned.plan_id.clone(),
                plan_digest: planned.plan_digest.clone(),
            },
        )
        .await
        .expect("revoked");
    assert_eq!((revoked.status.as_str(), revoked.epoch), ("revoked", 5));
    let twice = api
        .run_member_revoke(
            &admin(),
            &id,
            RunMemberRevoke {
                request_id: "life-13".to_owned(),
                plan_id: planned.plan_id,
                plan_digest: planned.plan_digest,
            },
        )
        .await
        .expect_err("a plan runs once");
    assert_eq!(code(&twice), codes::host::PLAN_EXPIRED);

    assert_eq!(
        api.members(&admin(), Some("revoked"))
            .expect("listed")
            .members
            .len(),
        1
    );
    assert!(
        api.members(&admin(), Some("active"))
            .expect("listed")
            .members
            .is_empty()
    );
    let bogus = api
        .members(&admin(), Some("gone"))
        .expect_err("not a status");
    assert_eq!(code(&bogus), codes::common::INVALID_ARGUMENT);

    // The member accepts every manifest the facade issued, each the successor of the last.
    member
        .store
        .join(
            &Applying::for_tests(71),
            &Pending {
                coordinator_address: Some("https://coordinator:7443".to_owned()),
                ..pending
            },
            now(),
        )
        .expect("joined");
    let identity = api.identity.as_deref().expect("an identity");
    let coordinator = Coordinator {
        identity,
        rings: api.keys.rings(),
    };
    let membership_id = id_of(&id).expect("an id");
    let answer = api
        .memberships
        .as_deref()
        .expect("memberships")
        .store
        .answer(
            &coordinator,
            &membership_id,
            &member.identity.host_id(),
            Some(0),
        )
        .expect("answered");
    let verified = verify_published(
        &identity.document(),
        &identity.successions(),
        identity.first_public_key(),
    )
    .expect("the coordinator verifies");
    let accepted = member
        .store
        .check_sync(&membership_id, &verified, &answer, now())
        .expect("every manifest verifies");
    assert_eq!(accepted.len(), 5);
    for (manifest, envelope, digest) in accepted {
        member
            .store
            .accept(
                &Applying::for_tests(72),
                &manifest,
                &envelope,
                &digest,
                now(),
            )
            .expect("accepted");
    }
    assert_eq!(
        member
            .store
            .membership(&membership_id)
            .expect("held")
            .status,
        Status::Revoked
    );
}

#[tokio::test]
async fn a_pending_membership_is_rejected_by_a_genesis_and_is_never_resumed_into_activity() {
    let root = scratch("members-reject");
    let (api, _, _volume) = reopen(&root, vec![HOST_OPERATIONS]);
    let member = Host::new("api-reject-member");
    let (id, _) = enrolled(&api, &member, "reject-1").await;
    let revision = api.member(&admin(), &id).expect("read").revision;

    for refused in [
        api.resume_member(&admin(), &id, change("reject-2", revision))
            .await
            .expect_err("a pending membership is approved, never resumed"),
        api.fence_member(&admin(), &id, change("reject-3", revision))
            .await
            .expect_err("a pending membership has no epoch to fence"),
        api.suspend_member(&admin(), &id, change("reject-4", revision))
            .await
            .expect_err("a pending membership is not suspended"),
    ] {
        assert_eq!(code(&refused), codes::host::MEMBERSHIP_TRANSITION_REFUSED);
    }
    let rejected = api
        .reject_member(&admin(), &id, change("reject-5", revision))
        .await
        .expect("rejected");
    assert_eq!((rejected.status.as_str(), rejected.epoch), ("rejected", 1));
    let after = api
        .approve_member(
            &admin(),
            &id,
            ApproveMember {
                request_id: "reject-6".to_owned(),
                expected_revision: rejected.receipt.revision,
                narrow: None,
                lease_policy: None,
                assurance: None,
            },
        )
        .await
        .expect_err("a rejected membership stays rejected");
    assert_eq!(code(&after), codes::host::MEMBERSHIP_TRANSITION_REFUSED);
}

#[tokio::test]
async fn the_routes_are_gated_and_the_member_side_needs_a_connector() {
    let root = scratch("members-gates");
    let (api, _, _volume) = reopen(&root, vec![HOST_OPERATIONS]);
    let stranger = actor("spiffe://acme/operators/stranger");
    assert!(matches!(api.invites(&stranger), Err(Refusal::Denied(_))));
    assert!(matches!(
        api.members(&stranger, None),
        Err(Refusal::Denied(_))
    ));
    assert!(matches!(
        api.create_invite(&stranger, create("gate-1", None)).await,
        Err(Refusal::Denied(_))
    ));
    assert!(api.invites(&admin()).expect("listed").invites.is_empty());

    let malformed = api.member(&admin(), "not-an-id").expect_err("not an id");
    assert_eq!(code(&malformed), codes::common::INVALID_ARGUMENT);
    let unknown = api
        .member(&admin(), &uuid_text(&[0x22; 16]))
        .expect_err("no such membership");
    assert_eq!(code(&unknown), codes::host::MEMBERSHIP_UNKNOWN);
    assert_eq!(
        code(&api.enroll_over_rest()),
        codes::host::PEER_SESSIONS_UNSERVEABLE
    );

    let join = JoinMembership {
        request_id: "gate-2".to_owned(),
        coordinator: CoordinatorView {
            address: "https://coordinator:7443".to_owned(),
            host_id: uuid_text(&[0x33; 16]),
            fingerprint: format!("sha256:{}", "ab".repeat(32)),
        },
        invite_id: uuid_text(&[0x44; 16]),
        token: URL_SAFE_NO_PAD.encode([7u8; 32]),
        requested: NarrowView {
            selector: "plane/data/*".to_owned(),
            tasks: vec![task_view()],
        },
    };
    let unconfigured = api
        .join_membership(&admin(), join)
        .await
        .expect_err("no outbound client");
    assert_eq!(code(&unconfigured), codes::host::PEER_CLIENT_UNCONFIGURED);
}

#[test]
fn a_task_view_refuses_roles_its_type_does_not_have() {
    let mut view = task_view();
    assert_eq!(view.provider_role.as_deref(), Some("member"));
    assert_eq!(view.task().expect("reads"), decisions("plane/data/*"));
    view.provider_role = Some("coordinator".to_owned());
    assert_eq!(
        code(&view.task().expect_err("swapped roles")),
        codes::common::INVALID_ARGUMENT
    );
    let mut unknown = task_view();
    unknown.task_type = "policy.push".to_owned();
    assert!(unknown.task().is_err());
    assert!(id_of("0190a5c3-0000-7000-8000-00000000000G").is_err());
    let id = [0x5a; 16];
    assert_eq!(id_of(&uuid_text(&id)).expect("reads back"), id);
}

/// Every item of the bundle for `resource`, one page, with its manifest.
fn bundle_of(api: &HostApi, resource: &str) -> (Vec<u8>, Vec<Vec<u8>>) {
    let page = api
        .key_bundle(
            &admin(),
            &crate::api::KeyBundleQuery {
                resource: resource.to_owned(),
                frontier: None,
                cursor: None,
                limit: Some(500),
            },
        )
        .expect("the bundle reads");
    assert!(page.next_cursor.is_none(), "one page");
    (
        URL_SAFE_NO_PAD.decode(&page.manifest).expect("base64url"),
        page.items
            .iter()
            .map(|item| URL_SAFE_NO_PAD.decode(item).expect("base64url"))
            .collect(),
    )
}

/// WP-4.1's done-when: one bundle verifies two pinned producers. A bundle for a resource an
/// active membership's task covers carries its member, verified offline from this Host's pin
/// alone, and the member's `data.attest` key verifies what the member signs.
#[tokio::test]
async fn one_bundle_verifies_the_coordinator_and_its_pinned_member() {
    use permguard_core::keys::Sign as _;

    use crate::keys::bundle::{self, BundleError, Item};

    let root = scratch("members-bundle");
    let (api, _, _volume) = reopen(&root, vec![HOST_OPERATIONS]);
    // The bundles of the Planes' resources are read under grants on them.
    for (request_id, selector) in [
        ("grant-data", "plane/data/*"),
        ("grant-control", "plane/control/*"),
    ] {
        api.create_grant(
            &admin(),
            crate::api::CreateGrant {
                request_id: request_id.to_owned(),
                expected_revision: None,
                principal: crate::api::testing::ADMIN.to_owned(),
                operations: vec![permguard_core::authz::operations::KEYS_READ.to_owned()],
                selector: selector.to_owned(),
                resource_types: Vec::new(),
                constraints: Default::default(),
                expires_at: None,
            },
        )
        .await
        .expect("granted");
    }
    let member = Host::new("api-bundle-member");
    let (id, _) = enrolled(&api, &member, "bundle-1").await;
    let pin = api
        .identity
        .as_deref()
        .expect("an identity")
        .first_fingerprint()
        .to_owned();

    // Pending: no peer yet.
    let (manifest, items) = bundle_of(&api, "plane/data");
    let verified = bundle::verify(&manifest, &items, &pin, "plane/data").expect("verifies");
    assert!(verified.peers.is_empty());

    let revision = api.member(&admin(), &id).expect("read").revision;
    api.approve_member(
        &admin(),
        &id,
        ApproveMember {
            request_id: "bundle-2".to_owned(),
            expected_revision: revision,
            narrow: None,
            lease_policy: None,
            assurance: None,
        },
    )
    .await
    .expect("approved");

    let (manifest, items) = bundle_of(&api, "plane/data");
    let verified = bundle::verify(&manifest, &items, &pin, "plane/data").expect("verifies");
    assert_eq!(verified.peers.len(), 1);
    let peer = &verified.peers[0];
    assert_eq!(uuid_text(&peer.membership_id), id);
    assert_eq!(peer.identity.host_id, member.identity.host_id());
    assert_eq!(peer.rings.len(), 1);
    assert_eq!(peer.rings[0].ring, DATA_ATTEST);

    // The second producer: what the member's ring signs verifies under the key the bundle
    // carries for it.
    let ring = member
        .rings
        .iter()
        .find(|ring| ring.id() == DATA_ATTEST)
        .expect("the member's ring");
    let signature = ring.sign(b"a decision the member ships").expect("signed");
    let jwk: permguard_core::keys::Jwk = peer.rings[0]
        .keys
        .iter()
        .map(|key| serde_json::from_str::<permguard_core::keys::Jwk>(key).expect("a jwk"))
        .find(|jwk| jwk.kid == signature.key_id().as_str())
        .expect("the signing key is carried");
    let public = URL_SAFE_NO_PAD.decode(&jwk.x).expect("base64url");
    permguard_objects::crypto::suite::Suite::Ed25519Sha256V1
        .verify(&public, b"a decision the member ships", signature.bytes())
        .expect("the member's signature verifies under the bundle's key");

    // A bundle for a resource no task covers carries no peer.
    let (manifest, items) = bundle_of(&api, "plane/control");
    let verified = bundle::verify(&manifest, &items, &pin, "plane/control").expect("verifies");
    assert!(verified.peers.is_empty());

    // Forged bundles, their manifest signed again by this Host's operations key, so each reaches
    // the peer checks and nothing else refuses it first.
    let (manifest, items) = bundle_of(&api, "plane/data");
    let base = bundle::Manifest::decode(
        permguard_objects::cose::Sign1::decode(&manifest)
            .expect("cose")
            .payload_unverified(),
    )
    .expect("a manifest");
    let ring = api.keys.ring(HOST_OPERATIONS).expect("the operations ring");
    let resign = |mut forged: Vec<Vec<u8>>| -> (Vec<u8>, Vec<Vec<u8>>) {
        forged.sort_by_key(|bytes| bundle::item_digest(bytes));
        let digests: Vec<[u8; 32]> = forged
            .iter()
            .map(|bytes| bundle::item_digest(bytes))
            .collect();
        let built = bundle::Built {
            manifest: bundle::Manifest {
                items: forged.len() as u64,
                bundle_digest: bundle::bundle_digest(&digests),
                ..base.clone()
            },
            items: forged.clone(),
            signer: Some(ring.active_key_id().expect("active").as_str().to_owned()),
        };
        (bundle::sign(ring, &built).expect("signed"), forged)
    };
    let edit = |change: &dyn Fn(Item) -> Option<Item>| -> Vec<Vec<u8>> {
        items
            .iter()
            .filter_map(|bytes| match Item::decode(bytes).expect("an item") {
                item @ (Item::Peer { .. } | Item::Peers { .. }) => {
                    change(item).map(|item| item.encode().expect("encodes"))
                }
                _ => Some(bytes.clone()),
            })
            .collect()
    };
    let refused = |forged: Vec<Vec<u8>>| {
        let (manifest, forged) = resign(forged);
        bundle::verify(&manifest, &forged, &pin, "plane/data").expect_err("forged")
    };
    // The unchanged items, signed again, still verify: the forgeries below fail for what they
    // change and nothing else.
    let (again, kept) = resign(items.clone());
    assert_eq!(
        bundle::verify(&again, &kept, &pin, "plane/data")
            .expect("verifies")
            .peers
            .len(),
        1
    );
    // A peer left out of the list the frontier names.
    assert!(matches!(
        refused(edit(&|item| match item {
            Item::Peer { .. } => None,
            other => Some(other),
        })),
        BundleError::Digest(_)
    ));
    // The list changed under the frontier's digest.
    assert!(matches!(
        refused(edit(&|item| match item {
            Item::Peers { mut entries } => {
                entries[0].epoch += 1;
                Some(Item::Peers { entries })
            }
            other => Some(other),
        })),
        BundleError::Digest(_)
    ));
    // Another Host's identity presented for the member.
    let impostor = Host::new("api-bundle-impostor").presentation();
    assert!(matches!(
        refused(edit(&|item| match item {
            Item::Peer {
                manifest,
                statements,
                coordinator,
                ..
            } => Some(Item::Peer {
                manifest,
                presentation: impostor.clone(),
                statements,
                coordinator,
            }),
            other => Some(other),
        })),
        BundleError::Anchor(_)
    ));
    // A ring the manifest does not pin carried beside the pinned one.
    assert!(matches!(
        refused(edit(&|item| match item {
            Item::Peer {
                manifest,
                presentation,
                mut statements,
                coordinator,
            } => {
                let mut extra = statements[0].clone();
                extra.ring = "control.attest".to_owned();
                statements.push(extra);
                Some(Item::Peer {
                    manifest,
                    presentation,
                    statements,
                    coordinator,
                })
            }
            other => Some(other),
        })),
        BundleError::Malformed(_)
    ));
    // A pinned ring's statement whose binding is not the member's.
    let other = Host::new("api-bundle-other");
    let other_binding = other.statement(DATA_ATTEST).binding;
    let other_statement = other.statement(DATA_ATTEST);
    assert!(matches!(
        refused(edit(&|item| match item {
            Item::Peer {
                manifest,
                presentation,
                mut statements,
                coordinator,
            } => {
                statements[0].binding = other_binding.clone();
                Some(Item::Peer {
                    manifest,
                    presentation,
                    statements,
                    coordinator,
                })
            }
            other => Some(other),
        })),
        BundleError::Signature(_)
    ));

    // The coordinator's operations statement left out: the signer's set is not shown.
    assert!(matches!(
        refused(edit(&|item| match item {
            Item::Peer {
                manifest,
                presentation,
                statements,
                coordinator,
            } => Some(Item::Peer {
                manifest,
                presentation,
                statements,
                coordinator: coordinator
                    .into_iter()
                    .filter(|statement| statement.ring != HOST_OPERATIONS)
                    .chain(std::iter::once(other_statement.clone()))
                    .collect(),
            }),
            other => Some(other),
        })),
        BundleError::Unbound(_)
    ));
    // A set whose keys are another ring's under this binding: the signer is not in it.
    assert!(matches!(
        refused(edit(&|item| match item {
            Item::Peer {
                manifest,
                presentation,
                statements,
                mut coordinator,
            } => {
                for statement in &mut coordinator {
                    if statement.ring == HOST_OPERATIONS {
                        statement.keys = other_statement.keys.clone();
                    }
                }
                Some(Item::Peer {
                    manifest,
                    presentation,
                    statements,
                    coordinator,
                })
            }
            other => Some(other),
        })),
        BundleError::Signature(_)
    ));

    // Suspended, the membership projects no peer: a new frontier carries none.
    let revision = api.member(&admin(), &id).expect("read").revision;
    api.suspend_member(&admin(), &id, change("bundle-3", revision))
        .await
        .expect("suspended");
    let (manifest, items) = bundle_of(&api, "plane/data");
    assert!(
        bundle::verify(&manifest, &items, &pin, "plane/data")
            .expect("verifies")
            .peers
            .is_empty()
    );
}

#[tokio::test]
async fn every_admin_route_is_denied_without_membership_admin() {
    let root = scratch("members-denied");
    let (api, _, _volume) = reopen(&root, vec![HOST_OPERATIONS]);
    let member = Host::new("api-denied-member");
    let (id, _) = enrolled(&api, &member, "denied-1").await;
    const READER: &str = "spiffe://acme/operators/reader";
    api.create_grant(
        &admin(),
        crate::api::CreateGrant {
            request_id: "grant-reader".to_owned(),
            expected_revision: None,
            principal: READER.to_owned(),
            operations: vec![permguard_core::authz::operations::MEMBERSHIP_READ.to_owned()],
            selector: "host".to_owned(),
            resource_types: Vec::new(),
            constraints: Default::default(),
            expires_at: None,
        },
    )
    .await
    .expect("granted");
    let reader = actor(READER);
    // The reader reads.
    assert_eq!(api.members(&reader, None).expect("listed").members.len(), 1);
    api.member(&reader, &id).expect("read");
    api.invites(&reader).expect("listed");
    for who in [reader, actor("spiffe://acme/operators/stranger")] {
        let denied = |result: Result<(), Refusal>| {
            assert!(matches!(result, Err(Refusal::Denied(_))), "{result:?}");
        };
        denied(
            api.approve_member(
                &who,
                &id,
                ApproveMember {
                    request_id: "x".to_owned(),
                    expected_revision: 1,
                    narrow: None,
                    lease_policy: None,
                    assurance: None,
                },
            )
            .await
            .map(|_| ()),
        );
        denied(
            api.reject_member(&who, &id, change("x", 1))
                .await
                .map(|_| ()),
        );
        denied(
            api.suspend_member(&who, &id, change("x", 1))
                .await
                .map(|_| ()),
        );
        denied(
            api.resume_member(&who, &id, change("x", 1))
                .await
                .map(|_| ()),
        );
        denied(
            api.fence_member(&who, &id, change("x", 1))
                .await
                .map(|_| ()),
        );
        denied(
            api.plan_member_revoke(
                &who,
                &id,
                PlanMemberRevoke {
                    request_id: "x".to_owned(),
                    reason: "r".to_owned(),
                    expected_revision: None,
                },
            )
            .await
            .map(|_| ()),
        );
        denied(
            api.run_member_revoke(
                &who,
                &id,
                RunMemberRevoke {
                    request_id: "x".to_owned(),
                    plan_id: "11".repeat(16),
                    plan_digest: "00".repeat(32),
                },
            )
            .await
            .map(|_| ()),
        );
        denied(api.create_invite(&who, create("x", None)).await.map(|_| ()));
        denied(
            api.delete_invite(&who, &id, "x".to_owned())
                .await
                .map(|_| ()),
        );
        denied(
            api.sync_membership(
                &who,
                &id,
                SyncMembership {
                    request_id: "x".to_owned(),
                },
            )
            .await
            .map(|_| ()),
        );
    }
    // Nothing moved.
    assert_eq!(api.member(&admin(), &id).expect("read").status, "pending");
}

/// A later page rebuilds the frontier's peers whatever the memberships did since: the one it
/// projected suspended and another enrolled between the pages change nothing it carries.
#[tokio::test]
async fn a_later_page_rebuilds_the_same_peers_after_the_memberships_moved() {
    use crate::keys::bundle;

    let root = scratch("members-pages");
    let (api, _, _volume) = reopen(&root, vec![HOST_OPERATIONS]);
    api.create_grant(
        &admin(),
        crate::api::CreateGrant {
            request_id: "grant-data".to_owned(),
            expected_revision: None,
            principal: crate::api::testing::ADMIN.to_owned(),
            operations: vec![permguard_core::authz::operations::KEYS_READ.to_owned()],
            selector: "plane/data/*".to_owned(),
            resource_types: Vec::new(),
            constraints: Default::default(),
            expires_at: None,
        },
    )
    .await
    .expect("granted");
    let member = Host::new("api-pages-member");
    let (id, _) = enrolled(&api, &member, "pages-1").await;
    let revision = api.member(&admin(), &id).expect("read").revision;
    api.approve_member(
        &admin(),
        &id,
        ApproveMember {
            request_id: "pages-2".to_owned(),
            expected_revision: revision,
            narrow: None,
            lease_policy: None,
            assurance: None,
        },
    )
    .await
    .expect("approved");
    let query = |frontier: Option<&str>, cursor: Option<&str>| crate::api::KeyBundleQuery {
        resource: "plane/data".to_owned(),
        frontier: frontier.map(str::to_owned),
        cursor: cursor.map(str::to_owned),
        limit: Some(2),
    };
    let first = api
        .key_bundle(&admin(), &query(None, None))
        .expect("the first page");
    assert!(first.next_cursor.is_some(), "more than one page");
    // Between the pages: the projected membership suspended, another enrolled.
    let revision = api.member(&admin(), &id).expect("read").revision;
    api.suspend_member(&admin(), &id, change("pages-3", revision))
        .await
        .expect("suspended");
    let later = Host::new("api-pages-later");
    enrolled(&api, &later, "pages-4").await;
    let mut items = first.items.clone();
    let mut cursor = first.next_cursor.clone();
    while let Some(next) = cursor {
        let page = api
            .key_bundle(&admin(), &query(Some(&first.manifest), Some(&next)))
            .expect("a later page");
        assert_eq!(
            page.manifest, first.manifest,
            "one manifest, the same bytes"
        );
        items.extend(page.items);
        cursor = page.next_cursor;
    }
    let items: Vec<Vec<u8>> = items
        .iter()
        .map(|item| URL_SAFE_NO_PAD.decode(item).expect("base64url"))
        .collect();
    let manifest = URL_SAFE_NO_PAD.decode(&first.manifest).expect("base64url");
    let pin = api
        .identity
        .as_deref()
        .expect("an identity")
        .first_fingerprint()
        .to_owned();
    let verified = bundle::verify(&manifest, &items, &pin, "plane/data").expect("verifies");
    assert_eq!(verified.peers.len(), 1, "the frontier's peer, as it stood");
    assert_eq!(uuid_text(&verified.peers[0].membership_id), id);
}

/// WP-4.2: an approval of a task requiring a control stands only on the evidence the policy
/// wants, refused and audited otherwise; the operator's approval is audited whole and signed by
/// digest; the member view shows the binding and the appraisal state; `appraise` renews and
/// revokes, each a new epoch.
#[tokio::test]
async fn an_approval_without_the_evidence_its_tasks_need_is_refused_and_audited() {
    let root = scratch("members-assurance");
    let trail = std::sync::Arc::new(crate::api::testing::Recording::default());
    let (api, _, _volume) = crate::api::testing::reopen_with(
        &root,
        vec![HOST_OPERATIONS],
        std::sync::Arc::clone(&trail),
    );
    let member = Host::new("assurance-api-m");
    let (id, _) = enrolled_requiring(
        &api,
        &member,
        "enrol-1",
        &[permguard_core::domains::assurance::OPERATIONS_DUAL_CONTROL],
    )
    .await;

    // Pending: the appraisal state names what the policy wants and that the declaration falls
    // short, and the nonce evidence would bind to.
    let pending = api.member(&admin(), &id).expect("read");
    let appraisal = pending.appraisal.clone().expect("an appraisal state");
    assert_eq!(
        appraisal.requirements,
        [RequirementView {
            control: permguard_core::domains::assurance::OPERATIONS_DUAL_CONTROL.to_owned(),
            wants: Some("operator-approved".to_owned()),
            declared: false,
        }]
    );
    assert_eq!(
        appraisal.policy_revision,
        crate::membership::appraisal::tests::policy()
            .revision()
            .to_string()
    );
    assert_eq!(
        URL_SAFE_NO_PAD
            .decode(&appraisal.nonce)
            .expect("base64url")
            .len(),
        32
    );
    assert!(pending.assurance.is_none());

    let approve = |request_id: &str, assurance: Option<AssuranceOffer>| ApproveMember {
        request_id: request_id.to_owned(),
        expected_revision: pending.revision,
        narrow: None,
        lease_policy: None,
        assurance,
    };
    // A control's name is spelled exactly.
    let spaced = api
        .approve_member(
            &admin(),
            &id,
            approve(
                "approve-0",
                Some(AssuranceOffer {
                    approvals: vec![ApprovalView {
                        control: format!(
                            " {}",
                            permguard_core::domains::assurance::OPERATIONS_DUAL_CONTROL
                        ),
                        reason: "spaced".to_owned(),
                        expires_at: rfc3339(now() + 600),
                    }],
                    evidence: Vec::new(),
                }),
            ),
        )
        .await
        .expect_err("not a control's name");
    assert_eq!(code(&spaced), codes::common::INVALID_ARGUMENT);
    let refused = api
        .approve_member(&admin(), &id, approve("approve-1", None))
        .await
        .expect_err("no approval of the control");
    assert_eq!(code(&refused), codes::host::ASSURANCE_REFUSED);
    let failed: Vec<_> = trail
        .events
        .lock()
        .expect("lock")
        .iter()
        .filter(|(action, ..)| action == AUDIT_APPROVED)
        .map(|(_, _, _, phase)| *phase)
        .collect();
    assert_eq!(
        failed,
        [Some("intent"), Some("failed")],
        "refused and audited"
    );

    let reason = "dual control witnessed under change ticket 42";
    let expires = now() + 7 * 86_400;
    let approved = api
        .approve_member(
            &admin(),
            &id,
            approve(
                "approve-2",
                Some(AssuranceOffer {
                    approvals: vec![ApprovalView {
                        control: permguard_core::domains::assurance::OPERATIONS_DUAL_CONTROL
                            .to_owned(),
                        reason: reason.to_owned(),
                        expires_at: rfc3339(expires),
                    }],
                    evidence: Vec::new(),
                }),
            ),
        )
        .await
        .expect("approved");
    assert_eq!(approved.epoch, 1);
    // The operator's approval in the audit: principal, scope, reason and expiry, inside the
    // operation, before its change.
    let facts = trail.facts.lock().expect("lock").clone();
    let (_, recorded) = facts
        .iter()
        .find(|(action, _)| action == AUDIT_ASSURANCE_APPROVED)
        .expect("the approval is audited");
    let fact = |name: &str| {
        recorded
            .iter()
            .find(|(fact, _)| fact == name)
            .map(|(_, value)| value.clone())
            .expect(name)
    };
    assert_eq!(
        fact("control"),
        permguard_core::domains::assurance::OPERATIONS_DUAL_CONTROL
    );
    assert_eq!(fact("tasks"), "decisions");
    assert_eq!(fact("reason"), reason);
    assert_eq!(fact("expires_at"), expires.to_string());
    let events = trail.events.lock().expect("lock").clone();
    let at = events
        .iter()
        .position(|(action, ..)| action == AUDIT_ASSURANCE_APPROVED)
        .expect("recorded");
    assert_eq!(
        events[at].1,
        format!("principal:{}", crate::api::testing::ADMIN)
    );
    assert_eq!(events[at].2.as_deref(), Some(id.as_str()));
    assert_eq!(events[at + 1].0, AUDIT_APPROVED);
    assert_eq!(events[at + 1].3, Some("applied"));

    // The manifest signs the binding; the member view shows it, and the record by digest only.
    let active = api.member(&admin(), &id).expect("read");
    let assurance = active.assurance.clone().expect("a binding");
    assert_eq!(assurance.verdict, "accepted");
    assert!(assurance.current);
    assert_eq!(assurance.task_ids, ["decisions"]);
    assert_eq!(
        assurance.claims,
        [ClaimView {
            control: permguard_core::domains::assurance::OPERATIONS_DUAL_CONTROL.to_owned(),
            class: "operator-approved".to_owned(),
            by: crate::api::testing::ADMIN.to_owned(),
        }]
    );
    assert_eq!(assurance.expires_at, rfc3339(expires));
    assert!(!json_of(&active).contains(reason));
    let manifest = URL_SAFE_NO_PAD
        .decode(active.manifest.as_deref().expect("a manifest"))
        .expect("base64url");
    let payload = Sign1::decode(&manifest).expect("COSE");
    let signed = Manifest::decode(payload.payload_unverified()).expect("decodes");
    let binding = signed.assurance_binding.expect("signed in the manifest");
    assert_eq!(
        assurance.binding_digest,
        binding.digest().expect("digested").to_string()
    );
    // Still appraisable while active: the nonce is now the manifest's.
    let nonce = active.appraisal.clone().expect("an appraisal state").nonce;
    assert_ne!(nonce, appraisal.nonce, "another revision, another nonce");

    // Renewed by an appraisal: a new epoch.
    let renewed = api
        .appraise_member(
            &admin(),
            &id,
            AppraiseMember {
                request_id: "appraise-1".to_owned(),
                expected_revision: active.revision,
                approvals: vec![ApprovalView {
                    control: permguard_core::domains::assurance::OPERATIONS_DUAL_CONTROL.to_owned(),
                    reason: "renewed".to_owned(),
                    expires_at: rfc3339(expires + 86_400),
                }],
                evidence: Vec::new(),
                revoke: None,
            },
        )
        .await
        .expect("renewed");
    assert_eq!(renewed.epoch, 2);
    let after = api.member(&admin(), &id).expect("read");
    assert_eq!(
        after.assurance.as_ref().expect("a binding").expires_at,
        rfc3339(expires + 86_400)
    );

    // An appraisal bringing nothing the policy accepts changes nothing.
    let short = api
        .appraise_member(
            &admin(),
            &id,
            AppraiseMember {
                request_id: "appraise-2".to_owned(),
                expected_revision: after.revision,
                approvals: Vec::new(),
                evidence: Vec::new(),
                revoke: None,
            },
        )
        .await
        .expect_err("nothing offered");
    assert_eq!(code(&short), codes::host::ASSURANCE_REFUSED);
    assert_eq!(api.member(&admin(), &id).expect("read").epoch, 2);

    // Revoked: a new epoch, the binding admits nothing.
    let revoked = api
        .appraise_member(
            &admin(),
            &id,
            AppraiseMember {
                request_id: "appraise-3".to_owned(),
                expected_revision: after.revision,
                approvals: Vec::new(),
                evidence: Vec::new(),
                revoke: Some(RevokeBinding {
                    reason: "the HSM was decommissioned".to_owned(),
                }),
            },
        )
        .await
        .expect("revoked");
    assert_eq!(revoked.epoch, 3);
    // The revocation in the audit: its principal, its reason and the controls it revoked.
    let facts = trail.facts.lock().expect("lock").clone();
    let (_, recorded) = facts
        .iter()
        .find(|(action, _)| action == AUDIT_ASSURANCE_REVOKED)
        .expect("the revocation is audited");
    assert!(recorded.contains(&("reason".to_owned(), "the HSM was decommissioned".to_owned())));
    assert!(recorded.contains(&(
        "controls".to_owned(),
        permguard_core::domains::assurance::OPERATIONS_DUAL_CONTROL.to_owned()
    )));
    let events = trail.events.lock().expect("lock").clone();
    let at = events
        .iter()
        .position(|(action, ..)| action == AUDIT_ASSURANCE_REVOKED)
        .expect("recorded");
    assert_eq!(
        events[at].1,
        format!("principal:{}", crate::api::testing::ADMIN)
    );
    let assurance = api
        .member(&admin(), &id)
        .expect("read")
        .assurance
        .expect("a binding");
    assert_eq!(assurance.verdict, "revoked");
    assert!(!assurance.current);

    // A suspended membership is not appraised: an appraisal would otherwise resume it.
    let current = api.member(&admin(), &id).expect("read");
    api.suspend_member(&admin(), &id, change("suspend-1", current.revision))
        .await
        .expect("suspended");
    let suspended = api.member(&admin(), &id).expect("read");
    let refused = api
        .appraise_member(
            &admin(),
            &id,
            AppraiseMember {
                request_id: "appraise-4".to_owned(),
                expected_revision: suspended.revision,
                approvals: vec![ApprovalView {
                    control: permguard_core::domains::assurance::OPERATIONS_DUAL_CONTROL.to_owned(),
                    reason: "while suspended".to_owned(),
                    expires_at: rfc3339(expires),
                }],
                evidence: Vec::new(),
                revoke: None,
            },
        )
        .await
        .expect_err("not while suspended");
    assert_eq!(code(&refused), codes::host::MEMBERSHIP_TRANSITION_REFUSED);
    assert_eq!(api.member(&admin(), &id).expect("read").status, "suspended");
}

/// WP-4.2: evidence names a registered verifier and is bound to the revision's nonce; a verifier
/// the Host does not know is `assurance_unavailable`.
#[tokio::test]
async fn attested_evidence_is_appraised_against_the_nonce_the_member_view_shows() {
    let root = scratch("members-attested");
    let (api, _, _volume) = reopen(&root, vec![HOST_OPERATIONS]);
    let member = Host::new("attested-api-m");
    let (id, _) = enrolled_requiring(
        &api,
        &member,
        "enrol-1",
        &[permguard_core::domains::assurance::CUSTODY_HSM],
    )
    .await;
    let pending = api.member(&admin(), &id).expect("read");
    let nonce: [u8; 32] = URL_SAFE_NO_PAD
        .decode(&pending.appraisal.expect("an appraisal state").nonce)
        .expect("base64url")
        .try_into()
        .expect("32 bytes");
    let offer = |verifier: &str, nonce: &[u8; 32]| AssuranceOffer {
        approvals: Vec::new(),
        evidence: vec![EvidenceView {
            verifier: verifier.to_owned(),
            evidence: URL_SAFE_NO_PAD.encode(crate::membership::appraisal::tests::evidence(
                nonce,
                &[Control::CustodyHsm],
            )),
        }],
    };
    let approve = |request_id: &str, assurance: AssuranceOffer| ApproveMember {
        request_id: request_id.to_owned(),
        expected_revision: pending.revision,
        narrow: None,
        lease_policy: None,
        assurance: Some(assurance),
    };
    let unknown = api
        .approve_member(&admin(), &id, approve("a-1", offer("tpm", &nonce)))
        .await
        .expect_err("no such verifier");
    assert_eq!(code(&unknown), codes::host::ASSURANCE_UNAVAILABLE);
    let verifier = crate::membership::appraisal::tests::VERIFIER;
    let stale = api
        .approve_member(&admin(), &id, approve("a-2", offer(verifier, &[0; 32])))
        .await
        .expect_err("another nonce");
    assert_eq!(code(&stale), codes::host::ASSURANCE_REFUSED);
    api.approve_member(&admin(), &id, approve("a-3", offer(verifier, &nonce)))
        .await
        .expect("approved on fresh evidence");
    let assurance = api
        .member(&admin(), &id)
        .expect("read")
        .assurance
        .expect("a binding");
    assert_eq!(assurance.claims[0].class, "attested");
    assert_eq!(assurance.claims[0].by, verifier);
}

/// WP-4.3: the open task sessions of a membership this Host coordinates, with the boot ids of
/// both incarnations; read under `membership.read`.
#[tokio::test]
async fn the_live_sessions_of_a_membership_name_their_boot_ids() {
    let root = scratch("members-sessions");
    let (api, _, _volume) = reopen(&root, vec![HOST_OPERATIONS]);
    let member = Host::new("sessions-api-m");
    let (id, pending) = enrolled(&api, &member, "enrol-1").await;
    let memberships = api.memberships.as_deref().expect("memberships");
    assert!(
        api.member_sessions(&admin(), &id)
            .expect("listed")
            .sessions
            .is_empty()
    );
    let opened = memberships
        .live
        .open(
            pending.membership_id,
            crate::membership::task::Live {
                task_id: "decisions".to_owned(),
                epoch: 1,
                member_boot_id: [0xB1; 16],
                coordinator_boot_id: [0xB0; 16],
                opened_at: 1_800_000_000,
                expires_at: 1_800_003_600,
            },
            1_800_000_000,
        )
        .expect("opened");
    let listed = api.member_sessions(&admin(), &id).expect("listed").sessions;
    assert_eq!(
        listed,
        [SessionView {
            task_id: "decisions".to_owned(),
            epoch: 1,
            member_boot_id: "b1".repeat(16),
            coordinator_boot_id: "b0".repeat(16),
            opened_at: rfc3339(1_800_000_000),
            expires_at: rfc3339(1_800_003_600),
        }]
    );
    drop(opened);
    assert!(
        api.member_sessions(&admin(), &id)
            .expect("listed")
            .sessions
            .is_empty()
    );
    // A connection whose lease ran out serves nothing: not listed.
    let _stale = memberships
        .live
        .open(
            pending.membership_id,
            crate::membership::task::Live {
                task_id: "decisions".to_owned(),
                epoch: 1,
                member_boot_id: [0xB2; 16],
                coordinator_boot_id: [0xB0; 16],
                opened_at: 1_000,
                expires_at: 2_000,
            },
            1_000,
        )
        .expect("opened");
    assert!(
        api.member_sessions(&admin(), &id)
            .expect("listed")
            .sessions
            .is_empty()
    );
    // Under `membership.read`, and only for a membership held.
    assert!(matches!(
        api.member_sessions(&actor("spiffe://acme/strangers/x"), &id),
        Err(Refusal::Denied(_))
    ));
    assert_eq!(
        code(
            &api.member_sessions(&admin(), "0190a5c3-0000-7000-8000-000000000099")
                .expect_err("unknown")
        ),
        codes::host::MEMBERSHIP_UNKNOWN
    );
}

/// WP-4.3: a membership held for review shows the epoch it was held at.
#[tokio::test]
async fn a_held_membership_shows_the_epoch_it_was_held_at() {
    let root = scratch("members-held");
    let (api, _, _volume) = reopen(&root, vec![HOST_OPERATIONS]);
    let member = Host::new("held-api-m");
    let (id, pending) = enrolled(&api, &member, "enrol-1").await;
    let revision = api.member(&admin(), &id).expect("read").revision;
    api.approve_member(
        &admin(),
        &id,
        ApproveMember {
            request_id: "approve-1".to_owned(),
            expected_revision: revision,
            narrow: None,
            lease_policy: None,
            assurance: None,
        },
    )
    .await
    .expect("approved");
    assert_eq!(api.member(&admin(), &id).expect("read").held_epoch, None);
    api.memberships
        .as_deref()
        .expect("memberships")
        .store
        .hold(&Applying::for_tests(74), &pending.membership_id, 4, now())
        .expect("held");
    let view = api.member(&admin(), &id).expect("read");
    assert_eq!(view.held_epoch, Some(4));
    assert_eq!(view.status, "active", "held, not suspended by a manifest");
}
