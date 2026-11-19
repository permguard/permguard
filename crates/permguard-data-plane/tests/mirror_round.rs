// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! A synchronization round against a real control plane, in process, over `policy.mirror` task
//! sessions.
//!
//! What is asserted is the behaviour an operator depends on: only what the
//! file follows is mirrored, a mirror that is already current does not move,
//! a mirror its task stops listing is removed — and, the one that matters
//! most, **a coordinator that does not answer never causes a deletion**.
//! Losing a connection is not a reason to lose a policy. A mirror of a
//! configured URL, retired (WP-7.7), is never served and goes at the first
//! round.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use permguard_core::Metrics;
use permguard_data_plane::mirrors::layout::{self, Mirror};
use permguard_data_plane::mirrors::{round, source};

mod support;

use support::plane::{self, provision};
use support::tasks;

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "pg-sync-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch directory is created");
    dir
}

#[test]
fn a_mirror_of_an_empty_ledger_is_not_a_failure() {
    // An empty ledger has no head yet: the first `apply` creates its history.
    // A mirror of it holds nothing and must not read as a failure — otherwise
    // every freshly created ledger would page somebody.
    let mirror = Mirror {
        authority: None,
        zone_id: "z-1".to_owned(),
        ledger_id: "l-1".to_owned(),
    };
    assert_eq!(mirror.label(), "z-1/l-1");
}

fn over_tasks(root: &std::path::Path, held: tasks::Held) -> Arc<round::Context> {
    over_tasks_with_grace(root, held, Duration::ZERO)
}

/// [`over_tasks`], its reap grace `grace`.
fn over_tasks_with_grace(
    root: &std::path::Path,
    held: tasks::Held,
    grace: Duration,
) -> Arc<round::Context> {
    over_tasks_with(root, held, grace, None)
}

/// [`over_tasks`], its reap grace `grace` and its staleness bound `stale_after`.
fn over_tasks_with(
    root: &std::path::Path,
    held: tasks::Held,
    grace: Duration,
    stale_after: Option<Duration>,
) -> Arc<round::Context> {
    Arc::new(round::Context {
        tasks: Some(Arc::new(held)),
        selections: Default::default(),
        decider: None,
        root: root.to_path_buf(),
        deadline: Duration::from_secs(30),
        stale_after,
        reap_grace: grace,
        holds: Default::default(),
        parallelism: 2,
        permits: std::sync::Arc::new(tokio::sync::Semaphore::new(4)),
        metrics: Metrics::none(),
    })
}

/// WP-7.2a, F-16: a Host's `policy.mirror` tasks are mirrored over their sessions, under the
/// coordinator's authority: listed by the session, named in their identity, attributed to one
/// source however many tasks of one coordinator name a ledger, and read over the session rather
/// than any URL.
#[tokio::test(flavor = "multi_thread")]
async fn a_membership_task_is_mirrored_under_its_authority_over_its_session() {
    let volume = scratch("over-tasks");
    let plane = plane::start(&volume).await;
    let url = plane.url.clone();
    provision(&url, "acme", &["main-ledger", "staging"]);
    let root = volume.join("mirrors");
    let coordinator = [0x11; 16];
    let asked = Arc::new(std::sync::Mutex::new(Vec::new()));

    let outcome = round::run(over_tasks(
        &root,
        tasks::Held {
            // Two memberships of one coordinator: one source (F-16).
            tasks: vec![
                tasks::task(coordinator, 1, "mirror", true),
                tasks::task(coordinator, 2, "mirror-again", false),
            ],
            url: url.clone(),
            silent: Vec::new(),
            asked: Arc::clone(&asked),
            only: Vec::new(),
            incomplete: false,
            partial: Vec::new(),
            unpinned: Vec::new(),
            reported: Default::default(),
            slow: None,
        },
    ))
    .await;

    assert_eq!((outcome.unreachable, outcome.failed), (0, 0), "{outcome:?}");
    assert_eq!(outcome.contested, 0, "one coordinator is one source");
    let authority = layout::authority_name(&coordinator);
    assert_eq!(
        outcome.coordinators,
        vec![(round::source_key(&authority), true)],
        "one source, required because one of its tasks is"
    );
    let held = layout::on_disk(&root).expect("the mirrors list");
    assert_eq!(held.len(), 2, "{held:?}");
    for mirror in &held {
        assert_eq!(mirror.authority.as_deref(), Some(authority.as_str()));
        assert!(mirror.path(&root).starts_with(root.join(&authority)));
        let identity = permguard_data_plane::authz::store::identity_of(&mirror.path(&root))
            .expect("the identity is recorded");
        assert_eq!(identity.authority.as_deref(), Some(authority.as_str()));
        assert_eq!(identity.server, round::source_key(&authority));
    }
    let found = permguard_data_plane::authz::store::find(&root, "acme", "main-ledger")
        .expect("served by name");
    assert_eq!(
        found.identity.authority.as_deref(),
        Some(authority.as_str())
    );

    // Every read went over a session: the listings, then a negotiation per ledger.
    let asked = asked.lock().expect("the log").clone();
    let operations: Vec<_> = asked.iter().map(|(_, operation)| *operation).collect();
    assert_eq!(
        operations
            .iter()
            .filter(|operation| **operation == permguard_notp::MirrorOperation::ListLedgers)
            .count(),
        2,
        "each task listed once: {asked:?}"
    );
    assert_eq!(
        operations
            .iter()
            .filter(|operation| **operation == permguard_notp::MirrorOperation::NegotiatePull)
            .count(),
        2,
        "each ledger negotiated once, over one of the sessions: {asked:?}"
    );
}

/// WP-7.2a: a coordinator whose session cannot be opened is unreachable for the round, and costs
/// nothing it already serves.
#[tokio::test(flavor = "multi_thread")]
async fn a_coordinator_that_does_not_answer_costs_none_of_its_mirrors() {
    let volume = scratch("silent-coordinator");
    let plane = plane::start(&volume).await;
    let url = plane.url.clone();
    provision(&url, "acme", &["main-ledger"]);
    let root = volume.join("mirrors");
    let coordinator = [0x11; 16];
    let held = |silent: Vec<[u8; 16]>| tasks::Held {
        tasks: vec![tasks::task(coordinator, 1, "mirror", true)],
        url: url.clone(),
        silent,
        asked: Arc::new(std::sync::Mutex::new(Vec::new())),
        only: Vec::new(),
        incomplete: false,
        partial: Vec::new(),
        unpinned: Vec::new(),
        reported: Default::default(),
        slow: None,
    };

    round::run(over_tasks(&root, held(Vec::new()))).await;
    let before = layout::on_disk(&root).expect("lists");
    assert_eq!(before.len(), 1);

    let outcome = round::run(over_tasks(&root, held(vec![coordinator]))).await;
    assert_eq!(outcome.unreachable, 1);
    assert_eq!(outcome.reaped, 0, "nothing is removed on its account");
    assert_eq!(layout::on_disk(&root).expect("lists"), before);
    let reported = outcome
        .sources
        .iter()
        .find(|source| source.url == round::source_key(&layout::authority_name(&coordinator)))
        .expect("the coordinator is reported");
    assert!(!reported.answered && !reported.succeeded());
}

/// One `policy.mirror` task of each of `coordinators`, answered from the control plane at `url`.
fn held_from(url: &str, coordinators: &[[u8; 16]], silent: Vec<[u8; 16]>) -> tasks::Held {
    tasks::Held {
        tasks: coordinators
            .iter()
            .enumerate()
            .map(|(at, coordinator)| tasks::task(*coordinator, at as u8 + 1, "mirror", true))
            .collect(),
        url: url.to_owned(),
        silent,
        asked: Arc::new(std::sync::Mutex::new(Vec::new())),
        only: Vec::new(),
        incomplete: false,
        partial: Vec::new(),
        unpinned: Vec::new(),
        reported: Default::default(),
        slow: None,
    }
}

/// WP-7.2a: two coordinators listing a ledger of the same names land in two directories under
/// their authorities, and a request naming it is answered from neither: no list order picks whose
/// policy is served; each stays reachable by its ids.
#[tokio::test(flavor = "multi_thread")]
async fn a_ledger_two_coordinators_list_is_served_from_neither_by_its_names() {
    let volume = scratch("two-coordinators");
    let plane = plane::start(&volume).await;
    let url = plane.url.clone();
    provision(&url, "acme", &["main-ledger"]);
    let root = volume.join("mirrors");

    let outcome = round::run(over_tasks(
        &root,
        held_from(&url, &[[0x11; 16], [0x22; 16]], Vec::new()),
    ))
    .await;
    let held = layout::on_disk(&root).expect("lists");
    assert_eq!(held.len(), 2, "one mirror under each authority");
    assert_eq!(outcome.contested, 1, "every round says so");
    assert!(
        permguard_data_plane::authz::store::find(&root, "acme", "main-ledger").is_none(),
        "two mirrors answer to one name: neither is chosen"
    );
    assert_eq!(
        permguard_data_plane::authz::store::contested(&root, "acme", "main-ledger").len(),
        2,
        "and the refusal can say why"
    );
}

/// WP-7.2a: with two coordinators, one that does not answer costs none of its mirrors, and the
/// other's stay as they were: absence is evidence only for the coordinator asked.
#[tokio::test(flavor = "multi_thread")]
async fn one_silent_coordinator_does_not_cost_another_its_mirrors() {
    let volume = scratch("two-one-silent");
    let plane = plane::start(&volume).await;
    let url = plane.url.clone();
    provision(&url, "acme", &["main-ledger"]);
    let root = volume.join("mirrors");
    let both = [[0x11; 16], [0x22; 16]];

    round::run(over_tasks(&root, held_from(&url, &both, Vec::new()))).await;
    let before = layout::on_disk(&root).expect("lists");
    assert_eq!(before.len(), 2);

    let outcome = round::run(over_tasks(&root, held_from(&url, &both, vec![both[1]]))).await;
    assert_eq!(outcome.unreachable, 1, "one coordinator is silent");
    assert_eq!(
        outcome.reaped, 0,
        "and nothing is removed on anybody's account"
    );
    assert_eq!(layout::on_disk(&root).expect("lists"), before);
}

/// A second round over the same task moves nothing and removes nothing.
#[tokio::test(flavor = "multi_thread")]
async fn a_second_round_is_idempotent() {
    let volume = scratch("again");
    let plane = plane::start(&volume).await;
    let url = plane.url.clone();
    provision(&url, "acme", &["main-ledger"]);
    let root = volume.join("mirrors");

    let first = round::run(over_tasks(
        &root,
        held_from(&url, &[[0x11; 16]], Vec::new()),
    ))
    .await;
    let second = round::run(over_tasks(
        &root,
        held_from(&url, &[[0x11; 16]], Vec::new()),
    ))
    .await;

    assert_eq!(first.failed, 0);
    assert_eq!(second.failed, 0);
    assert_eq!(second.reaped, 0, "nothing to remove the second time");
    assert_eq!(layout::on_disk(&root).expect("lists").len(), 1);
}

/// WP-7.7: a mirror of a configured URL, in the first shape a release up to v0.1.6 left on the
/// volume, is never served, and the first round removes it, recorded, whatever the coordinators
/// answered; one a hold names stays.
#[tokio::test(flavor = "multi_thread")]
async fn a_mirror_of_a_configured_url_is_never_served_and_the_first_round_removes_it() {
    let volume = scratch("retired-url");
    let root = volume.join("mirrors");
    let legacy = root.join("zone-id").join("ledger-id");
    std::fs::create_dir_all(&legacy).expect("the URL-shaped mirror");
    permguard_data_plane::authz::store::record(
        &legacy,
        &permguard_data_plane::authz::store::Identity {
            task: None,
            authority: None,
            zone_id: "zone-id".to_owned(),
            zone_name: "acme".to_owned(),
            ledger_id: "ledger-id".to_owned(),
            ledger_name: "main-ledger".to_owned(),
            server: "http://127.0.0.1:6443".to_owned(),
        },
    )
    .expect("its identity");
    assert!(
        permguard_data_plane::authz::store::find(&root, "acme", "main-ledger").is_none(),
        "never served, even before a round"
    );
    assert!(
        permguard_data_plane::authz::store::find(&root, "zone-id", "ledger-id").is_none(),
        "by its ids neither"
    );
    assert_eq!(layout::on_disk(&root).expect("lists").len(), 1);

    // The only coordinator does not answer: the URL mirror goes all the same.
    let outcome = round::run(over_tasks(
        &root,
        held_from("http://127.0.0.1:1", &[[0x11; 16]], vec![[0x11; 16]]),
    ))
    .await;
    assert_eq!(outcome.reaped, 1);
    assert_eq!(
        outcome.candidacy,
        vec![("mirror.reaped", "zone-id/ledger-id".to_owned())],
        "recorded for the audit trail"
    );
    assert!(layout::on_disk(&root).expect("lists").is_empty());
    assert!(
        !root.join("zone-id").exists(),
        "its zone directory goes with it"
    );
}

/// WP-7.2a: the file narrows the tasks it follows by membership and task ids with anchored
/// patterns; a task it does not name is neither opened nor listed.
#[tokio::test(flavor = "multi_thread")]
async fn the_file_narrows_the_tasks_followed_by_membership_task_and_pattern() {
    let volume = scratch("narrowed-tasks");
    let plane = plane::start(&volume).await;
    let url = plane.url.clone();
    provision(&url, "acme", &["main-ledger", "staging"]);
    let root = volume.join("mirrors");
    let asked = Arc::new(std::sync::Mutex::new(Vec::new()));
    let selections = source::TaskSelections::compile(
        &[permguard_core::mirrors::MirrorTaskSelection {
            membership: permguard_host::identity::record::uuid_text(&[1; 16]),
            task: "mirror".to_owned(),
            zones: vec!["acme".to_owned()],
            ledgers: vec!["main-ledger".to_owned()],
        }],
        None,
    )
    .expect("the patterns compile");

    let outcome = round::run(Arc::new(round::Context {
        tasks: Some(Arc::new(tasks::Held {
            tasks: vec![
                tasks::task([0x11; 16], 1, "mirror", true),
                tasks::task([0x22; 16], 2, "elsewhere", true),
            ],
            url: url.clone(),
            silent: Vec::new(),
            asked: Arc::clone(&asked),
            only: Vec::new(),
            incomplete: false,
            partial: Vec::new(),
            unpinned: Vec::new(),
            reported: Default::default(),
            slow: None,
        })),
        selections,
        decider: None,
        root: root.clone(),
        deadline: Duration::from_secs(30),
        stale_after: None,
        reap_grace: std::time::Duration::ZERO,
        holds: Default::default(),
        parallelism: 2,
        permits: std::sync::Arc::new(tokio::sync::Semaphore::new(4)),
        metrics: Metrics::none(),
    }))
    .await;

    assert_eq!((outcome.unreachable, outcome.failed), (0, 0), "{outcome:?}");
    let held = layout::on_disk(&root).expect("lists");
    assert_eq!(held.len(), 1, "only `acme/main-ledger`: {held:?}");
    assert_eq!(
        outcome.coordinators,
        vec![
            (
                round::source_key(&layout::authority_name(&[0x11; 16])),
                true
            ),
            (
                round::source_key(&layout::authority_name(&[0x22; 16])),
                true
            ),
        ],
        "the task the file leaves out is not followed, and still counts for readiness: it is \
         required by its signed manifest"
    );
    assert!(
        asked
            .lock()
            .expect("the log")
            .iter()
            .all(|(task, _)| task == "mirror"),
        "nothing was asked over the task left out"
    );
}

fn held_by(
    url: &str,
    tasks: Vec<permguard_host::composition::MirrorTask>,
    only: Vec<(&str, Vec<&str>)>,
    incomplete: bool,
) -> tasks::Held {
    tasks::Held {
        tasks,
        url: url.to_owned(),
        silent: Vec::new(),
        asked: Arc::new(std::sync::Mutex::new(Vec::new())),
        only: only
            .into_iter()
            .map(|(task, names)| {
                (
                    task.to_owned(),
                    names.into_iter().map(ToOwned::to_owned).collect(),
                )
            })
            .collect(),
        incomplete,
        partial: Vec::new(),
        unpinned: Vec::new(),
        reported: Default::default(),
        slow: None,
    }
}

/// WP-7.2a, WP-7.2d: a ledger gone from its task's complete listing is tombstoned, and removed
/// from under its authority by the next complete listing without it, the directories it leaves
/// empty going with it; one gone from an incomplete listing stays, the listing proving nothing
/// absent.
#[tokio::test(flavor = "multi_thread")]
async fn only_a_complete_listing_of_its_own_task_removes_a_task_mirror() {
    let volume = scratch("task-reap");
    let plane = plane::start(&volume).await;
    let url = plane.url.clone();
    provision(&url, "acme", &["main-ledger", "staging"]);
    let root = volume.join("mirrors");
    let coordinator = [0x11; 16];
    let authority = layout::authority_name(&coordinator);
    let task = || vec![tasks::task(coordinator, 1, "mirror", true)];

    round::run(over_tasks(&root, held_by(&url, task(), Vec::new(), false))).await;
    assert_eq!(layout::on_disk(&root).expect("lists").len(), 2);

    // Cut short: `staging` is missing from a listing that says it is not whole.
    let outcome = round::run(over_tasks(
        &root,
        held_by(&url, task(), vec![("mirror", vec!["main-ledger"])], true),
    ))
    .await;
    assert_eq!(outcome.reaped, 0, "an incomplete listing removes nothing");
    let reported = outcome
        .sources
        .iter()
        .find(|source| source.url == round::source_key(&authority))
        .expect("reported");
    assert!(
        !reported.answered,
        "an incomplete listing is no answer for reaping"
    );
    assert_eq!(layout::on_disk(&root).expect("lists").len(), 2);

    // Whole, and without `staging`: a candidate, still on the volume.
    let staging = layout::on_disk(&root)
        .expect("lists")
        .into_iter()
        .find(|mirror| {
            permguard_data_plane::authz::store::identity_of(&mirror.path(&root))
                .is_some_and(|identity| identity.ledger_name == "staging")
        })
        .expect("staging");
    let outcome = round::run(over_tasks(
        &root,
        held_by(&url, task(), vec![("mirror", vec!["main-ledger"])], false),
    ))
    .await;
    assert_eq!(outcome.reaped, 0, "one complete listing removes nothing");
    assert_eq!(
        outcome.candidacy,
        vec![("mirror.tombstoned", staging.label())]
    );
    assert!(
        staging
            .path(&root)
            .join(permguard_data_plane::mirrors::tombstone::TOMBSTONE)
            .exists()
    );
    // The second, the grace past: it goes.
    let outcome = round::run(over_tasks(
        &root,
        held_by(&url, task(), vec![("mirror", vec!["main-ledger"])], false),
    ))
    .await;
    assert_eq!(outcome.reaped, 1);
    assert_eq!(outcome.candidacy, vec![("mirror.reaped", staging.label())]);
    let reported = outcome
        .sources
        .iter()
        .find(|source| source.url == round::source_key(&authority))
        .expect("reported");
    assert!(reported.answered && reported.succeeded());
    assert_eq!(layout::on_disk(&root).expect("lists").len(), 1);

    // Whole and empty, twice: the last one goes, and the authority's directory with its zone.
    for reaped in [0, 1] {
        let outcome = round::run(over_tasks(
            &root,
            held_by(&url, task(), vec![("mirror", Vec::new())], false),
        ))
        .await;
        assert_eq!(outcome.reaped, reaped);
    }
    assert!(layout::on_disk(&root).expect("lists").is_empty());
    assert!(
        !root.join(&authority).exists(),
        "nothing of the authority is left"
    );
}

/// WP-7.2a: a mirror is its own task's to remove. A task this round does not list — its
/// membership suspended — removes nothing, however whole another task of the same coordinator
/// lists.
#[tokio::test(flavor = "multi_thread")]
async fn a_suspended_task_costs_none_of_its_mirrors_to_another_task_of_its_coordinator() {
    let volume = scratch("task-suspended");
    let plane = plane::start(&volume).await;
    let url = plane.url.clone();
    provision(&url, "acme", &["main-ledger", "staging"]);
    let root = volume.join("mirrors");
    let coordinator = [0x11; 16];

    // Membership 1's task lists `main-ledger`, membership 2's `staging`.
    round::run(over_tasks(
        &root,
        held_by(
            &url,
            vec![
                tasks::task(coordinator, 1, "first", true),
                tasks::task(coordinator, 2, "second", true),
            ],
            vec![("first", vec!["main-ledger"]), ("second", vec!["staging"])],
            false,
        ),
    ))
    .await;
    assert_eq!(layout::on_disk(&root).expect("lists").len(), 2);

    // Membership 2 suspended: its task is not held this round, and membership 1's lists whole.
    let outcome = round::run(over_tasks(
        &root,
        held_by(
            &url,
            vec![tasks::task(coordinator, 1, "first", true)],
            vec![("first", vec!["main-ledger"])],
            false,
        ),
    ))
    .await;
    assert_eq!(outcome.reaped, 0, "`staging` is its own task's to remove");
    assert_eq!(layout::on_disk(&root).expect("lists").len(), 2);
}

/// WP-7.2a: a task listing whole removes what it no longer lists, even while another task of the
/// same coordinator lists only in part: each task's mirrors are its own to remove.
#[tokio::test(flavor = "multi_thread")]
async fn a_whole_task_reaps_its_own_while_a_sibling_task_lists_in_part() {
    let volume = scratch("task-sibling");
    let plane = plane::start(&volume).await;
    let url = plane.url.clone();
    provision(&url, "acme", &["main-ledger", "staging"]);
    let root = volume.join("mirrors");
    let coordinator = [0x11; 16];
    let both = || {
        vec![
            tasks::task(coordinator, 1, "first", true),
            tasks::task(coordinator, 2, "second", true),
        ]
    };

    round::run(over_tasks(
        &root,
        held_by(
            &url,
            both(),
            vec![("first", vec!["main-ledger"]), ("second", vec!["staging"])],
            false,
        ),
    ))
    .await;
    assert_eq!(layout::on_disk(&root).expect("lists").len(), 2);

    // `first` lists whole and without `main-ledger`; `second` lists only in part.
    let mut held = held_by(
        &url,
        both(),
        vec![("first", Vec::new()), ("second", vec!["staging"])],
        false,
    );
    held.partial = vec!["second".to_owned()];
    let again = held.clone();
    let outcome = round::run(over_tasks(&root, held)).await;
    assert_eq!(outcome.reaped, 0, "a candidate first");
    let outcome = round::run(over_tasks(&root, again)).await;
    assert_eq!(outcome.reaped, 1, "`first` removes what it no longer lists");
    let left = layout::on_disk(&root).expect("lists");
    assert_eq!(left.len(), 1, "`second`'s mirror stays: {left:?}");
}

/// WP-7.2d: a candidate is kept while its grace runs, however many complete listings leave it out,
/// keeps serving, and a listing that names it again ends its candidacy; the grace is counted from
/// the first absence, never restarted by a later one.
#[tokio::test(flavor = "multi_thread")]
async fn a_reap_candidate_waits_out_its_grace_and_a_listing_restores_it() {
    let volume = scratch("task-grace");
    let plane = plane::start(&volume).await;
    let url = plane.url.clone();
    provision(&url, "acme", &["main-ledger", "staging"]);
    let root = volume.join("mirrors");
    let task = || vec![tasks::task([0x11; 16], 1, "mirror", true)];
    let hour = Duration::from_secs(3600);

    round::run(over_tasks_with_grace(
        &root,
        held_by(&url, task(), Vec::new(), false),
        hour,
    ))
    .await;
    let staging = layout::on_disk(&root)
        .expect("lists")
        .into_iter()
        .find(|mirror| {
            permguard_data_plane::authz::store::identity_of(&mirror.path(&root))
                .is_some_and(|identity| identity.ledger_name == "staging")
        })
        .expect("staging");
    let without = || held_by(&url, task(), vec![("mirror", vec!["main-ledger"])], false);

    for candidacy in [vec![("mirror.tombstoned", staging.label())], Vec::new()] {
        let outcome = round::run(over_tasks_with_grace(&root, without(), hour)).await;
        assert_eq!(outcome.reaped, 0, "within its grace");
        assert_eq!(outcome.candidacy, candidacy);
    }
    let tombstone = permguard_data_plane::mirrors::tombstone::read(&staging.path(&root))
        .expect("reads")
        .expect("a candidate");
    assert_eq!(tombstone.revision, 1);
    assert!(tombstone.task.ends_with("/mirror"), "{tombstone:?}");
    assert!(
        permguard_data_plane::authz::store::find(&root, "acme", "staging").is_some(),
        "a candidate is still served"
    );

    // Named again: no longer a candidate.
    let outcome = round::run(over_tasks_with_grace(
        &root,
        held_by(&url, task(), Vec::new(), false),
        hour,
    ))
    .await;
    assert_eq!(
        outcome.candidacy,
        vec![("mirror.restored", staging.label())]
    );
    assert_eq!(
        permguard_data_plane::mirrors::tombstone::read(&staging.path(&root)).expect("reads"),
        None
    );

    // A first absence an hour and more ago: the next complete listing without it reaps it.
    permguard_data_plane::mirrors::tombstone::write(
        &staging.path(&root),
        &permguard_data_plane::mirrors::tombstone::Tombstone {
            first_absent_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("after the epoch")
                .as_secs()
                - 3601,
            ..tombstone
        },
    )
    .expect("written");
    let outcome = round::run(over_tasks_with_grace(&root, without(), hour)).await;
    assert_eq!(outcome.reaped, 1);
    assert_eq!(outcome.candidacy, vec![("mirror.reaped", staging.label())]);
}

/// Regression over the task session (round, per-ledger timeout and concurrency): a ledger whose
/// reads stall past the deadline is abandoned for the round, which ends without waiting for it,
/// and its permit stays with the work that is still running until that work ends — the permit is
/// never released by the wait.
#[tokio::test(flavor = "multi_thread")]
async fn a_stalled_ledger_is_abandoned_at_its_deadline_and_its_permit_stays_with_the_work() {
    let volume = scratch("stalled");
    let plane = plane::start(&volume).await;
    let url = plane.url.clone();
    provision(&url, "acme", &["main-ledger"]);
    let root = volume.join("mirrors");
    let mut held = held_by(
        &url,
        vec![tasks::task([0x11; 16], 1, "mirror", true)],
        Vec::new(),
        false,
    );
    held.slow = Some(Duration::from_millis(1500));
    let mut context = Arc::try_unwrap(over_tasks(&root, held)).unwrap_or_else(|_| panic!("one"));
    context.deadline = Duration::from_millis(200);
    context.permits = Arc::new(tokio::sync::Semaphore::new(1));
    let permits = Arc::clone(&context.permits);

    let started = std::time::Instant::now();
    let outcome = round::run(Arc::new(context)).await;
    assert!(
        started.elapsed() < Duration::from_millis(1400),
        "the round ended at the deadline, not with the stall: {:?}",
        started.elapsed()
    );
    assert_eq!(outcome.failed, 1, "{outcome:?}");
    assert_eq!(
        permits.available_permits(),
        0,
        "the abandoned work still holds its permit"
    );
    tokio::time::timeout(Duration::from_secs(20), async {
        while permits.available_permits() == 0 {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the work ends, and its permit with it");
}

/// F-14 (WP-7.2d): cut the coordinator; staleness grows from the last verified synchronization of
/// every mirror it served, and the alarm fires at the bound for each, named required with its
/// task — the round that reached nothing still measures what it holds.
#[tokio::test(flavor = "multi_thread")]
async fn a_cut_coordinator_leaves_its_mirrors_alarmed_stale_at_the_bound() {
    let volume = scratch("stale-outage");
    let plane = plane::start(&volume).await;
    let url = plane.url.clone();
    provision(&url, "acme", &["main-ledger"]);
    let root = volume.join("mirrors");
    let coordinator = [0x11; 16];
    let bound = Some(Duration::from_secs(3600));
    let task = || vec![tasks::task(coordinator, 1, "mirror", true)];

    let outcome = round::run(over_tasks_with(
        &root,
        held_by(&url, task(), Vec::new(), false),
        Duration::ZERO,
        bound,
    ))
    .await;
    assert!(outcome.stale.is_empty(), "just verified: {outcome:?}");
    let mirror = layout::on_disk(&root).expect("lists").remove(0);

    // The coordinator is cut, and its last verified synchronization grows past the bound.
    let mut cut = held_by(&url, task(), Vec::new(), false);
    cut.silent = vec![coordinator];
    let within = round::run(over_tasks_with(&root, cut.clone(), Duration::ZERO, bound)).await;
    assert_eq!(within.unreachable, 1);
    assert!(within.stale.is_empty(), "within the bound: {within:?}");
    std::fs::File::options()
        .write(true)
        .open(
            mirror
                .path(&root)
                .join(permguard_data_plane::authz::store::SYNCED_FILE),
        )
        .expect("the marker")
        .set_modified(std::time::SystemTime::now() - Duration::from_secs(3601))
        .expect("aged");
    use permguard_core::Recorder as _;
    let registry = Arc::new(permguard_std::metrics::Registry::new());
    let mut measured = Arc::try_unwrap(over_tasks_with(&root, cut.clone(), Duration::ZERO, bound))
        .unwrap_or_else(|_| panic!("one owner"));
    measured.metrics = Metrics::new(Arc::clone(&registry) as Arc<dyn permguard_core::Recorder>);
    let past = round::run(Arc::new(measured)).await;
    assert_eq!(past.unreachable, 1);
    assert_eq!(
        past.stale,
        vec![(mirror.label(), true)],
        "the alarm, required"
    );
    let gauge: Vec<f64> = registry
        .snapshot()
        .into_iter()
        .filter(|sample| sample.metric.name() == "permguard_sync_mirrors_stale")
        .map(|sample| match sample.reading {
            permguard_core::metrics::Reading::Value(value) => value,
            permguard_core::metrics::Reading::Distribution { sum, .. } => sum,
        })
        .collect();
    assert_eq!(gauge, vec![1.0], "the gauge the alarm is written against");

    // The same mirror of a task that is not required is alarmed, and named so.
    let mut optional = cut;
    optional.tasks = vec![tasks::task(coordinator, 1, "mirror", false)];
    let past = round::run(over_tasks_with(&root, optional, Duration::ZERO, bound)).await;
    assert_eq!(past.stale, vec![(mirror.label(), false)]);
    // No bound, no alarm.
    let unbounded = round::run(over_tasks_with(
        &root,
        held_by(&url, task(), Vec::new(), false),
        Duration::ZERO,
        None,
    ))
    .await;
    assert!(unbounded.stale.is_empty());
}

/// WP-7.2b: a task whose membership pins no `control.attest` set has nothing its statements could
/// verify under: its coordinator fails the round, and none of its ledgers is mirrored.
#[tokio::test(flavor = "multi_thread")]
async fn a_task_whose_membership_pins_no_ring_is_not_mirrored() {
    let volume = scratch("unpinned");
    let plane = plane::start(&volume).await;
    let url = plane.url.clone();
    provision(&url, "acme", &["main-ledger"]);
    let root = volume.join("mirrors");
    let mut held = held_by(
        &url,
        vec![tasks::task([0x11; 16], 1, "mirror", true)],
        Vec::new(),
        false,
    );
    held.unpinned = vec!["mirror".to_owned()];

    let outcome = round::run(over_tasks(&root, held)).await;
    assert_eq!(
        outcome.unreachable, 1,
        "the coordinator failed: {outcome:?}"
    );
    assert!(layout::on_disk(&root).expect("lists").is_empty());
}

/// WP-7.2 follow-up (WP-7.3c holds): a mirror whose ledger a hold in force names is never reaped,
/// however long its task leaves it out; released, the next complete listing reaps it; a plane
/// handed no hold store reaps nothing, since what a hold keeps is never guessed.
#[tokio::test(flavor = "multi_thread")]
async fn a_held_ledger_keeps_its_mirror() {
    use permguard_host::holds::{Deadline, HoldStore, NewHold};
    use permguard_host::operations::journal::Initiator;

    let volume = scratch("held");
    let plane = plane::start(&volume).await;
    let url = plane.url.clone();
    provision(&url, "acme", &["main-ledger", "staging"]);
    let root = volume.join("mirrors");
    let task = || vec![tasks::task([0x11; 16], 1, "mirror", true)];
    round::run(over_tasks(&root, held_by(&url, task(), Vec::new(), false))).await;
    let staging = layout::on_disk(&root)
        .expect("lists")
        .into_iter()
        .find(|mirror| {
            permguard_data_plane::authz::store::identity_of(&mirror.path(&root))
                .is_some_and(|identity| identity.ledger_name == "staging")
        })
        .expect("staging");

    let host = scratch("held-host");
    let claimed = permguard_host::storage::volume::Volume::claim(
        &host,
        permguard_core::assurance::AssuranceProfile::Development,
    )
    .expect("the Host's volume");
    let store = Arc::new(HoldStore::open(&claimed).expect("the holds"));
    let mutations = permguard_host::operations::mutation::Mutations::open_offline(&claimed, "test")
        .expect("the transaction");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("after the epoch")
        .as_secs();
    let hold = permguard_host::holds::add(
        &mutations,
        &store,
        Initiator::System("test".to_owned()),
        NewHold {
            resource: format!(
                "plane/control/zone/{}/ledger/{}",
                staging.zone_id, staging.ledger_id
            ),
            owner: "legal".to_owned(),
            reason: "litigation".to_owned(),
            deadline: Deadline::Review(now + 3600),
        },
        now,
    )
    .expect("held");
    let with = |holds: round::Holds| {
        let mut context = Arc::try_unwrap(over_tasks(
            &root,
            held_by(&url, task(), vec![("mirror", vec!["main-ledger"])], false),
        ))
        .unwrap_or_else(|_| panic!("one owner"));
        context.holds = holds;
        Arc::new(context)
    };
    for _ in 0..3 {
        let outcome = round::run(with(round::Holds::Store(Arc::clone(&store)))).await;
        assert_eq!(outcome.reaped, 0, "held: {outcome:?}");
    }
    assert!(staging.path(&root).exists());
    let outcome = round::run(with(round::Holds::Unavailable)).await;
    assert_eq!(outcome.reaped, 0, "no hold store, nothing removed");
    permguard_host::holds::release(
        &mutations,
        &store,
        Initiator::System("test".to_owned()),
        &hold.id,
    )
    .expect("released");
    let outcome = round::run(with(round::Holds::Store(store))).await;
    assert_eq!(outcome.reaped, 1, "released: {outcome:?}");
    assert!(!staging.path(&root).exists());
}

/// The held tasks of `inner`, and memberships that ended (BUG-0190).
struct Ending {
    inner: tasks::Held,
    ended: Vec<String>,
}

impl permguard_host::composition::MirrorTasks for Ending {
    fn mirror_tasks(&self) -> Vec<permguard_host::composition::MirrorTask> {
        self.inner.mirror_tasks()
    }

    fn ended_memberships(&self) -> Vec<String> {
        self.ended.clone()
    }

    fn open_mirror<'a>(
        &'a self,
        task: &'a permguard_host::composition::MirrorTask,
    ) -> permguard_core::BoxFuture<
        'a,
        Result<
            Box<dyn permguard_host::composition::MirrorSession>,
            permguard_host::composition::MirrorRefusal,
        >,
    > {
        self.inner.open_mirror(task)
    }

    fn watch_mirror<'a>(
        &'a self,
        task: &'a permguard_host::composition::MirrorTask,
        positions: Vec<(String, u64)>,
    ) -> permguard_core::BoxFuture<
        'a,
        Result<
            Box<dyn permguard_host::composition::MirrorWatch>,
            permguard_host::composition::MirrorRefusal,
        >,
    > {
        self.inner.watch_mirror(task, positions)
    }
}

/// A round over `tasks`, its grace an hour, its selections `selections`.
fn ending_round(
    root: &std::path::Path,
    tasks: Arc<dyn permguard_host::composition::MirrorTasks>,
    selections: source::TaskSelections,
) -> Arc<round::Context> {
    Arc::new(round::Context {
        tasks: Some(tasks),
        selections,
        decider: None,
        root: root.to_path_buf(),
        deadline: Duration::from_secs(30),
        stale_after: None,
        reap_grace: Duration::from_secs(3600),
        holds: Default::default(),
        parallelism: 2,
        permits: std::sync::Arc::new(tokio::sync::Semaphore::new(4)),
        metrics: Metrics::none(),
    })
}

/// BUG-0190: once the membership a mirror was followed under ended, its ledgers are no longer
/// served, at once, whatever the grace: tombstoned and reaped, audited both. A membership whose
/// tasks are merely not listed this round, a suspended one, keeps its mirrors.
#[tokio::test(flavor = "multi_thread")]
async fn a_revoked_membership_stops_its_mirrors_at_once() {
    let volume = scratch("membership-ended");
    let plane = plane::start(&volume).await;
    let url = plane.url.clone();
    provision(&url, "acme", &["main-ledger"]);
    let root = volume.join("mirrors");
    let task = || vec![tasks::task([0x11; 16], 1, "mirror", true)];
    let membership = permguard_host::identity::record::uuid_text(&[1; 16]);

    round::run(ending_round(
        &root,
        Arc::new(held_by(&url, task(), Vec::new(), false)),
        Default::default(),
    ))
    .await;
    assert!(permguard_data_plane::authz::store::find(&root, "acme", "main-ledger").is_some());

    // Suspended: its task is not listed, nothing ends it.
    let outcome = round::run(ending_round(
        &root,
        Arc::new(held_by(&url, Vec::new(), Vec::new(), false)),
        Default::default(),
    ))
    .await;
    assert_eq!(outcome.reaped, 0, "{outcome:?}");
    assert!(permguard_data_plane::authz::store::find(&root, "acme", "main-ledger").is_some());

    // Revoked: ended for good.
    let outcome = round::run(ending_round(
        &root,
        Arc::new(Ending {
            inner: held_by(&url, Vec::new(), Vec::new(), false),
            ended: vec![membership],
        }),
        Default::default(),
    ))
    .await;
    assert_eq!(outcome.reaped, 1, "{outcome:?}");
    assert!(
        outcome
            .candidacy
            .iter()
            .any(|(action, _)| *action == "mirror.tombstoned")
            && outcome
                .candidacy
                .iter()
                .any(|(action, _)| *action == "mirror.reaped"),
        "{outcome:?}"
    );
    assert!(
        permguard_data_plane::authz::store::find(&root, "acme", "main-ledger").is_none(),
        "no longer served"
    );
}

/// BUG-0193: a ledger the configuration no longer follows is not served from the round that
/// excludes it, whatever the grace; a mistyped selection does not keep it served either.
#[tokio::test(flavor = "multi_thread")]
async fn a_ledger_the_configuration_excludes_is_not_served_at_once() {
    let volume = scratch("narrowed-at-once");
    let plane = plane::start(&volume).await;
    let url = plane.url.clone();
    provision(&url, "acme", &["main-ledger", "staging"]);
    let root = volume.join("mirrors");
    let task = || vec![tasks::task([0x11; 16], 1, "mirror", true)];
    let selecting = |task: &str, ledgers: &[&str]| {
        source::TaskSelections::compile(
            &[permguard_core::mirrors::MirrorTaskSelection {
                membership: permguard_host::identity::record::uuid_text(&[1; 16]),
                task: task.to_owned(),
                zones: vec!["acme".to_owned()],
                ledgers: ledgers.iter().map(|ledger| (*ledger).to_owned()).collect(),
            }],
            None,
        )
        .expect("the patterns compile")
    };

    round::run(ending_round(
        &root,
        Arc::new(held_by(&url, task(), Vec::new(), false)),
        Default::default(),
    ))
    .await;
    assert_eq!(layout::on_disk(&root).expect("lists").len(), 2);

    let outcome = round::run(ending_round(
        &root,
        Arc::new(held_by(&url, task(), Vec::new(), false)),
        selecting("mirror", &["main-ledger"]),
    ))
    .await;
    assert_eq!(outcome.reaped, 1, "{outcome:?}");
    assert!(permguard_data_plane::authz::store::find(&root, "acme", "staging").is_none());
    assert!(permguard_data_plane::authz::store::find(&root, "acme", "main-ledger").is_some());

    // A mistyped task name follows nothing of this task: nothing of it stays served.
    let outcome = round::run(ending_round(
        &root,
        Arc::new(held_by(&url, task(), Vec::new(), false)),
        selecting("mirorr", &[".*"]),
    ))
    .await;
    assert_eq!(outcome.reaped, 1, "{outcome:?}");
    assert!(layout::on_disk(&root).expect("lists").is_empty());
}

/// BUG-0192: a ledger deleted and recreated under the same name replaces its predecessor at once:
/// the old mirror is removed in the round that lists the new one, which is served with no contest.
#[tokio::test(flavor = "multi_thread")]
async fn a_recreated_ledger_replaces_its_deleted_namesake_at_once() {
    let volume = scratch("recreated");
    let plane = plane::start(&volume).await;
    let url = plane.url.clone();
    provision(&url, "acme", &["main-ledger"]);
    let root = volume.join("mirrors");
    let task = || vec![tasks::task([0x11; 16], 1, "mirror", true)];
    round::run(ending_round(
        &root,
        Arc::new(held_by(&url, task(), Vec::new(), false)),
        Default::default(),
    ))
    .await;
    let before = permguard_data_plane::authz::store::identity_of(
        &layout::on_disk(&root).expect("lists")[0].path(&root),
    )
    .expect("an identity");

    let catalog = permguard_client::catalog::client(
        &url,
        &permguard_client::TlsOptions::default(),
        Box::new(permguard_client::narrate::Silent),
    )
    .expect("the catalog client connects");
    let ledger = catalog
        .list_ledgers(&before.zone_id, None, None)
        .expect("listed")
        .into_iter()
        .find(|ledger| ledger.name == "main-ledger")
        .expect("the ledger");
    catalog
        .delete_ledger(&before.zone_id, &ledger.id, ledger.revision)
        .expect("deleted");
    catalog
        .create_ledger(&before.zone_id, "main-ledger")
        .expect("recreated");

    let outcome = round::run(ending_round(
        &root,
        Arc::new(held_by(&url, task(), Vec::new(), false)),
        Default::default(),
    ))
    .await;
    assert_eq!(outcome.contested, 0, "{outcome:?}");
    let held = layout::on_disk(&root).expect("lists");
    assert_eq!(held.len(), 1, "{held:?}");
    let after =
        permguard_data_plane::authz::store::identity_of(&held[0].path(&root)).expect("an identity");
    assert_ne!(after.ledger_id, before.ledger_id, "the new one is served");
}
