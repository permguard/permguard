// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The drain controller's decisions (TD-2), over a cluster and a coordinator held in memory, with
//! real drain receipts (`tests/fixtures/drain-receipts.json`, written by permguard-host): a claim is
//! deleted only with a receipt that verifies under the member's pin the coordinator holds, of the
//! Job's own claim generation, every stream of it acknowledged by the coordinator through its last
//! sequence; anything less, a failed or timed-out Job above all, keeps it.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::cell::RefCell;
use std::collections::BTreeMap;

use super::*;

const FIXTURES: &str = include_str!("../../../tests/fixtures/drain-receipts.json");
const WORKLOAD: &str = "pg-permguard-data-plane-billing";
const SELECTOR: &str = "app.kubernetes.io/instance=pg,app.kubernetes.io/component=data-plane";
const TEMPLATE_JSON: &str = r#"{"apiVersion":"batch/v1","kind":"Job","metadata":{"name":"__JOB__","labels":{"ordinal":"__ORDINAL__"}},"spec":{"template":{"spec":{"volumes":[{"name":"state","persistentVolumeClaim":{"claimName":"__CLAIM__"}}]}}}}"#;

fn fixture(name: &str) -> Value {
    let all: Value = serde_json::from_str(FIXTURES).expect("the fixtures are JSON");
    all[name].clone()
}

fn receipt_line(name: &str) -> String {
    serde_json::json!({ "drain_receipt": fixture(name)["export"] }).to_string()
}

/// The volume the fixtures' receipts name.
const VOLUME: &str = "07070707070707070707070707070707";

fn claim_log(generation: u64) -> String {
    claim_log_of(VOLUME, generation)
}

fn claim_log_of(volume: &str, generation: u64) -> String {
    format!(
        "the volume at /var/lib/permguard/volume (id {volume}) is claimed at generation {generation} (was {})\n",
        generation - 1
    )
}

#[derive(Default)]
struct FakeCluster {
    replicas: RefCell<u32>,
    claims: Vec<Claim>,
    pods: Vec<String>,
    jobs: BTreeMap<String, JobState>,
    logs: BTreeMap<(String, String), String>,
    created: RefCell<Vec<Value>>,
    deleted_claims: RefCell<Vec<(String, String)>>,
    deleted_jobs: RefCell<Vec<String>>,
    /// The replicas the workload has by the time the delete is checked again.
    replicas_at_delete: Option<u32>,
}

impl FakeCluster {
    fn with_claims(replicas: u32, ordinals: &[u32]) -> Self {
        Self {
            replicas: RefCell::new(replicas),
            claims: ordinals
                .iter()
                .map(|ordinal| Claim {
                    name: format!("state-{WORKLOAD}-{ordinal}"),
                    uid: format!("uid-{ordinal}"),
                    deleting: false,
                })
                .collect(),
            ..Self::default()
        }
    }

    fn succeeded(mut self, ordinal: u32, claim: String, served: String) -> Self {
        let job = job_name(WORKLOAD, ordinal);
        self.jobs.insert(job.clone(), JobState::Succeeded);
        self.logs.insert((job.clone(), "claim".to_owned()), claim);
        self.logs.insert((job, "data-plane".to_owned()), served);
        self
    }
}

impl Cluster for FakeCluster {
    fn workloads(&self, selector: &str) -> Result<Vec<Workload>, String> {
        assert_eq!(selector, SELECTOR);
        Ok(vec![Workload {
            name: WORKLOAD.to_owned(),
            replicas: *self.replicas.borrow(),
        }])
    }
    fn workload(&self, name: &str) -> Result<Option<Workload>, String> {
        assert_eq!(name, WORKLOAD);
        if let Some(replicas) = self.replicas_at_delete {
            *self.replicas.borrow_mut() = replicas;
        }
        Ok(Some(Workload {
            name: WORKLOAD.to_owned(),
            replicas: *self.replicas.borrow(),
        }))
    }
    fn claims(&self, _: &str) -> Result<Vec<Claim>, String> {
        Ok(self.claims.clone())
    }
    fn pod_exists(&self, name: &str) -> Result<bool, String> {
        Ok(self.pods.iter().any(|pod| pod == name))
    }
    fn job(&self, name: &str) -> Result<Option<JobState>, String> {
        Ok(self.jobs.get(name).cloned())
    }
    fn create_job(&self, manifest: &Value) -> Result<(), String> {
        self.created.borrow_mut().push(manifest.clone());
        Ok(())
    }
    fn job_log(&self, job: &str, container: &str) -> Result<String, String> {
        Ok(self
            .logs
            .get(&(job.to_owned(), container.to_owned()))
            .cloned()
            .unwrap_or_default())
    }
    fn delete_claim(&self, name: &str, uid: &str) -> Result<(), String> {
        self.deleted_claims
            .borrow_mut()
            .push((name.to_owned(), uid.to_owned()));
        Ok(())
    }
    fn delete_job(&self, name: &str) -> Result<(), String> {
        self.deleted_jobs.borrow_mut().push(name.to_owned());
        Ok(())
    }
}

/// A coordinator pinning `pins` and acknowledging `(producer, run) → through`.
#[derive(Default)]
struct FakeCoordinator {
    pins: BTreeMap<String, String>,
    acks: BTreeMap<(String, String), u64>,
}

impl FakeCoordinator {
    /// The coordinator of the `shipped` fixture's Host, acknowledging its runs through `through`.
    fn of_shipped(through: u64) -> Self {
        let shipped = fixture("shipped");
        let producer = shipped["host_id_hex"].as_str().unwrap().to_owned();
        Self {
            pins: BTreeMap::from([(
                shipped["host_id"].as_str().unwrap().to_owned(),
                shipped["pin"].as_str().unwrap().to_owned(),
            )]),
            acks: BTreeMap::from([
                (
                    (
                        producer.clone(),
                        "0a0b0a0b0a0b0a0b0a0b0a0b0a0b0a0b".to_owned(),
                    ),
                    through,
                ),
                ((producer, "0c0d0c0d0c0d0c0d0c0d0c0d0c0d0c0d".to_owned()), 7),
            ]),
        }
    }
}

impl Coordinator for FakeCoordinator {
    fn pin_of(&self, host_id: &str) -> Result<Option<String>, String> {
        Ok(self.pins.get(host_id).cloned())
    }
    fn acknowledged(
        &self,
        plane: &str,
        stream_type: &str,
        resource: &str,
        producer: &str,
        run: &str,
    ) -> Result<Option<u64>, String> {
        assert_eq!((plane, stream_type), ("data", "decisions"));
        assert_eq!(resource, "plane/data/zone/acme/ledger/main");
        Ok(self
            .acks
            .get(&(producer.to_owned(), run.to_owned()))
            .copied())
    }
}

fn pass(cluster: &FakeCluster, coordinator: &FakeCoordinator) -> Vec<(String, Outcome)> {
    reclaim(cluster, coordinator, SELECTOR, TEMPLATE_JSON).expect("one pass")
}

fn claim(ordinal: u32) -> String {
    format!("state-{WORKLOAD}-{ordinal}")
}

#[test]
fn a_retained_claim_above_the_replicas_gets_a_fenced_drain_job() {
    let cluster = FakeCluster::with_claims(1, &[0, 1, 2]);
    let outcomes = pass(&cluster, &FakeCoordinator::default());

    assert_eq!(
        outcomes,
        vec![
            (claim(1), Outcome::DrainStarted(job_name(WORKLOAD, 1))),
            (claim(2), Outcome::DrainStarted(job_name(WORKLOAD, 2))),
        ],
        "ordinal 0 is within the replicas and untouched"
    );
    let created = cluster.created.borrow();
    assert_eq!(created.len(), 2);
    assert_eq!(created[0]["metadata"]["name"], job_name(WORKLOAD, 1));
    assert_eq!(created[0]["metadata"]["labels"]["ordinal"], "1");
    assert_eq!(
        created[0]["spec"]["template"]["spec"]["volumes"][0]["persistentVolumeClaim"]["claimName"],
        claim(1)
    );
    assert!(cluster.deleted_claims.borrow().is_empty());
}

#[test]
fn a_claim_is_deleted_only_with_a_verified_receipt_and_the_coordinator_frontier() {
    let cluster =
        FakeCluster::with_claims(1, &[0, 1]).succeeded(1, claim_log(3), receipt_line("shipped"));
    let outcomes = pass(&cluster, &FakeCoordinator::of_shipped(12));

    let shipped = fixture("shipped");
    assert_eq!(
        outcomes,
        vec![(
            claim(1),
            Outcome::Reclaimed {
                host_id: shipped["host_id"].as_str().unwrap().to_owned(),
                streams: 2,
            }
        )]
    );
    assert_eq!(
        *cluster.deleted_claims.borrow(),
        vec![(claim(1), "uid-1".to_owned())],
        "the delete carries the claim's UID"
    );
    assert_eq!(*cluster.deleted_jobs.borrow(), vec![job_name(WORKLOAD, 1)]);
}

#[test]
fn a_receipt_the_coordinator_does_not_acknowledge_keeps_the_claim() {
    // One run acknowledged through 11 of 12.
    let cluster =
        FakeCluster::with_claims(1, &[1]).succeeded(1, claim_log(3), receipt_line("shipped"));
    let outcomes = pass(&cluster, &FakeCoordinator::of_shipped(11));
    let [(_, Outcome::Kept(why))] = outcomes.as_slice() else {
        panic!("{outcomes:?}")
    };
    assert!(why.contains("through 11 of 12"), "{why}");
    assert!(cluster.deleted_claims.borrow().is_empty());

    // A run the coordinator never received.
    let mut coordinator = FakeCoordinator::of_shipped(12);
    coordinator
        .acks
        .retain(|(_, run), _| run != "0c0d0c0d0c0d0c0d0c0d0c0d0c0d0c0d");
    let cluster =
        FakeCluster::with_claims(1, &[1]).succeeded(1, claim_log(3), receipt_line("shipped"));
    let outcomes = pass(&cluster, &coordinator);
    let [(_, Outcome::Kept(why))] = outcomes.as_slice() else {
        panic!("{outcomes:?}")
    };
    assert!(
        why.contains("holds no run 0c0d0c0d0c0d0c0d0c0d0c0d0c0d0c0d"),
        "{why}"
    );
    assert!(cluster.deleted_claims.borrow().is_empty());
}

#[test]
fn a_forged_or_foreign_receipt_keeps_the_claim() {
    let kept = |served: String, coordinator: &FakeCoordinator| {
        let cluster = FakeCluster::with_claims(1, &[1]).succeeded(1, claim_log(3), served);
        let outcomes = pass(&cluster, coordinator);
        assert!(cluster.deleted_claims.borrow().is_empty(), "{outcomes:?}");
        match outcomes.as_slice() {
            [(_, Outcome::Kept(why))] => why.clone(),
            other => panic!("{other:?}"),
        }
    };
    // The coordinator holds no membership of the Host the receipt names.
    let why = kept(receipt_line("shipped"), &FakeCoordinator::default());
    assert!(why.contains("holds no membership"), "{why}");

    // The coordinator pins another identity for that Host: the bundle does not verify under it.
    let mut coordinator = FakeCoordinator::of_shipped(12);
    let other_pin = fixture("other")["pin"].as_str().unwrap().to_owned();
    for pin in coordinator.pins.values_mut() {
        *pin = other_pin.clone();
    }
    let why = kept(receipt_line("shipped"), &coordinator);
    assert!(why.contains("does not verify"), "{why}");

    // The receipt's own bytes changed.
    let mut export = fixture("shipped")["export"].clone();
    let mut bytes = B64.decode(export["receipt"].as_str().unwrap()).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    export["receipt"] = Value::String(B64.encode(bytes));
    let forged = serde_json::json!({ "drain_receipt": export }).to_string();
    let why = kept(forged, &FakeCoordinator::of_shipped(12));
    assert!(why.contains("does not verify"), "{why}");

    // Another Host's receipt and bundle, under the shipped Host's pin.
    let why = kept(receipt_line("other"), &FakeCoordinator::of_shipped(12));
    assert!(why.contains("holds no membership"), "{why}");
}

#[test]
fn a_failed_or_timed_out_job_never_authorizes_deletion() {
    for reason in ["DeadlineExceeded", "BackoffLimitExceeded"] {
        let mut cluster = FakeCluster::with_claims(1, &[1]);
        cluster
            .jobs
            .insert(job_name(WORKLOAD, 1), JobState::Failed(reason.to_owned()));
        // Even with a receipt somehow in its log.
        cluster.logs.insert(
            (job_name(WORKLOAD, 1), "data-plane".to_owned()),
            receipt_line("shipped"),
        );
        let outcomes = pass(&cluster, &FakeCoordinator::of_shipped(12));
        let [(_, Outcome::Kept(why))] = outcomes.as_slice() else {
            panic!("{outcomes:?}")
        };
        assert!(
            why.contains(reason) && why.contains("never authorizes"),
            "{why}"
        );
        assert!(cluster.deleted_claims.borrow().is_empty());
        assert!(
            cluster.deleted_jobs.borrow().is_empty(),
            "kept for inspection"
        );
    }
}

#[test]
fn a_receipt_of_another_claim_generation_keeps_the_claim() {
    let cluster =
        FakeCluster::with_claims(1, &[1]).succeeded(1, claim_log(4), receipt_line("shipped"));
    let outcomes = pass(&cluster, &FakeCoordinator::of_shipped(12));
    let [(_, Outcome::Kept(why))] = outcomes.as_slice() else {
        panic!("{outcomes:?}")
    };
    assert!(why.contains("not this run's"), "{why}");
    assert!(cluster.deleted_claims.borrow().is_empty());
}

#[test]
fn a_receipt_of_another_volume_keeps_the_claim() {
    let cluster = FakeCluster::with_claims(1, &[1]).succeeded(
        1,
        claim_log_of("08080808080808080808080808080808", 3),
        receipt_line("shipped"),
    );
    let outcomes = pass(&cluster, &FakeCoordinator::of_shipped(12));
    let [(_, Outcome::Kept(why))] = outcomes.as_slice() else {
        panic!("{outcomes:?}")
    };
    assert!(why.contains("not this claim's"), "{why}");
    assert!(cluster.deleted_claims.borrow().is_empty());
}

#[test]
fn a_job_without_its_logs_keeps_the_claim() {
    let cluster = FakeCluster::with_claims(1, &[1]).succeeded(1, String::new(), String::new());
    let outcomes = pass(&cluster, &FakeCoordinator::of_shipped(12));
    let [(_, Outcome::Kept(why))] = outcomes.as_slice() else {
        panic!("{outcomes:?}")
    };
    assert!(why.contains("no claim of its volume"), "{why}");
    let cluster = FakeCluster::with_claims(1, &[1]).succeeded(1, claim_log(3), "{}".to_owned());
    let outcomes = pass(&cluster, &FakeCoordinator::of_shipped(12));
    let [(_, Outcome::Kept(why))] = outcomes.as_slice() else {
        panic!("{outcomes:?}")
    };
    assert!(why.contains("no drain receipt"), "{why}");
}

#[test]
fn a_claim_the_group_needs_again_is_never_deleted() {
    // A Pod of the ordinal exists.
    let mut cluster = FakeCluster::with_claims(1, &[1]);
    cluster.pods.push(format!("{WORKLOAD}-1"));
    assert_eq!(
        pass(&cluster, &FakeCoordinator::default()),
        vec![(claim(1), Outcome::InUse)]
    );
    assert!(cluster.created.borrow().is_empty());

    // The group scaled back up between the proof and the delete.
    let mut cluster =
        FakeCluster::with_claims(1, &[1]).succeeded(1, claim_log(3), receipt_line("shipped"));
    cluster.replicas_at_delete = Some(2);
    assert_eq!(
        pass(&cluster, &FakeCoordinator::of_shipped(12)),
        vec![(claim(1), Outcome::InUse)]
    );
    assert!(cluster.deleted_claims.borrow().is_empty());

    // A running Job is waited for; a claim already being deleted is left alone.
    let mut cluster = FakeCluster::with_claims(1, &[1, 2]);
    cluster.claims[1].deleting = true;
    cluster
        .jobs
        .insert(job_name(WORKLOAD, 1), JobState::Running);
    assert_eq!(
        pass(&cluster, &FakeCoordinator::default()),
        vec![
            (claim(1), Outcome::Draining(job_name(WORKLOAD, 1))),
            (claim(2), Outcome::Deleting),
        ]
    );
}

#[test]
fn an_ordinal_is_read_from_its_own_workloads_claims_only() {
    assert_eq!(ordinal("state-pg-dp-a-2", "pg-dp-a"), Some(2));
    assert_eq!(ordinal("state-pg-dp-a-b-2", "pg-dp-a"), None);
    assert_eq!(ordinal("state-pg-dp-a-x", "pg-dp-a"), None);
    assert_eq!(ordinal("other-pg-dp-a-2", "pg-dp-a"), None);
}

#[test]
fn the_claim_generation_and_the_receipt_are_read_from_the_logs() {
    assert_eq!(
        claimed_volume(&claim_log(7)),
        Some(Claimed {
            volume_id: VOLUME.to_owned(),
            generation: 7
        })
    );
    assert_eq!(claimed_volume("nothing here"), None);
    // The line `volume claim` printed before it named the volume is no proof.
    assert_eq!(
        claimed_volume("the volume at /v is claimed at generation 7 (was 6)\n"),
        None
    );
    assert!(printed_receipt("{\"timestamp\":1}\n{\"drain_receipt\": 3}\n").is_none());
    assert!(
        printed_receipt(&format!(
            "{{\"timestamp\":1}}\n{}\n",
            receipt_line("shipped")
        ))
        .is_some()
    );
}

#[test]
fn a_selector_is_escaped_for_the_query() {
    assert_eq!(
        query("app.kubernetes.io/instance=pg,permguard.com/group in (a)"),
        "app.kubernetes.io%2Finstance%3Dpg%2Cpermguard.com%2Fgroup%20in%20%28a%29"
    );
}
