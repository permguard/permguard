// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The streams' garbage collection (WP-5.6b, owner decisions of 2026-10-15 and 2026-10-17): at
//! start and every hour, every producer and consumer the engine serves runs one bounded pass on a
//! blocking thread, never on a request path. Each stream's pass is a `host.stream.pruned`
//! security record, written after its anchor and before anything goes; a record the trail
//! refuses deletes nothing.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use permguard_core::authz::Resource;
use permguard_core::{AuditEvent, AuditOutcome, Fact, Subject};
use permguard_host::audit::Engine;
use permguard_host::membership::record::{Manifest, TaskType};
use permguard_host::time::TimeGuard;
use permguard_stream::engine::retention::{Prunable, Pruned, RetentionSource};

/// How often a pass runs; the first is at start.
pub const PASS: Duration = Duration::from_secs(3600);

/// The audit action of a pass over one stream.
pub const AUDIT_PRUNED: &str = "host.stream.pruned";

/// The periodic passes, stopped when this is dropped.
pub struct Pruning(tokio::task::JoinHandle<()>);

impl Drop for Pruning {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// The record of `pruned`, written into `engine`'s trail.
pub fn record(engine: &Engine, pruned: &Pruned) -> Result<(), String> {
    let run: String = pruned
        .run
        .map(|run| run.iter().map(|byte| format!("{byte:02x}")).collect())
        .unwrap_or_default();
    engine
        .append(
            &AuditEvent::new(AUDIT_PRUNED, Subject::System("stream-gc"))
                .on(&pruned.stream)
                .with_outcome(AuditOutcome::Ok)
                .with_facts(&[
                    ("stream", Fact::Text(&pruned.stream)),
                    ("role", Fact::Text(pruned.role)),
                    ("run", Fact::Text(&run)),
                    ("through", Fact::Uint(pruned.through)),
                    ("batches", Fact::Uint(pruned.batches)),
                ]),
            None,
        )
        .map_err(|refused| refused.to_string())
}

/// One pass of every handle at `now`: what each deleted, in order; a handle that failed or found
/// a pass of its own running is logged and skipped.
pub fn pass(prunables: &[Arc<dyn Prunable>], engine: &Engine, now: u64) -> Vec<Pruned> {
    let mut deleted = Vec::new();
    for prunable in prunables {
        match prunable.run(now, &|pruned| record(engine, pruned)) {
            Ok(Some(pruned)) => deleted.extend(pruned),
            Ok(None) => tracing::warn!(
                event.name = "host.stream.prune_skipped",
                component = "host",
                handle = %prunable.name(),
                "a pass of this handle is still running; it runs again within the hour"
            ),
            Err(error) => tracing::error!(
                event.name = "host.stream.prune_failed",
                component = "host",
                handle = %prunable.name(),
                error = %error,
                "a garbage collection pass failed; it runs again within the hour"
            ),
        }
    }
    deleted
}

/// Runs a pass over `prunables` now and every [`PASS`] until the handle is dropped.
pub fn drive(
    prunables: Vec<Arc<dyn Prunable>>,
    engine: Arc<Engine>,
    time: Arc<TimeGuard>,
) -> Pruning {
    Pruning(tokio::spawn(async move {
        let mut interval = tokio::time::interval(PASS);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            let (prunables, engine, now) =
                (prunables.clone(), Arc::clone(&engine), time.now_secs());
            match tokio::task::spawn_blocking(move || pass(&prunables, &engine, now)).await {
                Ok(deleted) => {
                    let batches: u64 = deleted.iter().map(|pruned| pruned.batches).sum();
                    if batches > 0 {
                        tracing::info!(
                            event.name = "host.stream.pruned",
                            component = "host",
                            batches,
                            "stream batches past retention deleted"
                        );
                    }
                }
                Err(error) => tracing::error!(
                    event.name = "host.stream.prune_failed",
                    component = "host",
                    error = %error,
                    "the garbage collection stopped; it runs again within the hour"
                ),
            }
        }
    }))
}

/// A consumer's retention: the longest `retention_seconds` of the tasks of type `task` whose
/// membership's member is the producer and whose selector holds the resource (WP-5.6b). The
/// memberships are bound once the server opened them; before, and with no such task, nothing.
pub struct ShipRetention {
    pub members: Arc<OnceLock<Arc<permguard_host::membership::Store>>>,
    pub task: TaskType,
}

impl RetentionSource for ShipRetention {
    fn retention_seconds(&self, resource: &str, producer: &[u8; 16]) -> Option<u64> {
        let members = self.members.get()?;
        let manifests: Vec<Manifest> = members
            .memberships()
            .into_iter()
            .filter_map(|(_, held)| held.manifest.map(|(manifest, ..)| manifest))
            .collect();
        retention_of(&manifests, self.task, resource, producer)
    }
}

/// The retention of the event consumer (WP-6.2c2b1): what a ship task says of a run shipped to
/// this Host; for an origin this Host imports over `events.import`, none of its own once the Data
/// Plane registered its floor, so the windows it loaded bound those runs alone; before it does,
/// and for any other run, what [`ShipRetention`] says.
pub struct EventRetention {
    pub ship: ShipRetention,
    /// The event consumer, bound once it is built.
    pub consumer: OnceLock<
        std::sync::Weak<permguard_stream::engine::Consumer<permguard_events::stream::Codec>>,
    >,
}

impl RetentionSource for EventRetention {
    fn retention_seconds(&self, resource: &str, producer: &[u8; 16]) -> Option<u64> {
        if let Some(seconds) = self.ship.retention_seconds(resource, producer) {
            return Some(seconds);
        }
        let consumer = self.consumer.get()?.upgrade()?;
        if !consumer.plane_floor_registered() {
            return None;
        }
        let members = self.ship.members.get()?;
        let manifests: Vec<Manifest> = members
            .memberships()
            .into_iter()
            .filter(|(_, held)| {
                held.role == permguard_host::membership::record::Role::Member
                    && held.status == permguard_host::membership::record::Status::Active
            })
            .filter_map(|(_, held)| held.manifest.map(|(manifest, ..)| manifest))
            .collect();
        imported(&manifests, resource).then_some(0)
    }
}

/// Whether one of `manifests`, a member's, imports `resource` over `events.import`.
pub fn imported(manifests: &[Manifest], resource: &str) -> bool {
    let Ok(resource) = Resource::parse(resource) else {
        return false;
    };
    manifests.iter().any(|manifest| {
        manifest.selector.contains(&resource)
            && manifest.tasks.iter().any(|task| {
                task.task_type == TaskType::EventsImport && task.selector.contains(&resource)
            })
    })
}

/// The longest `retention_seconds` among `manifests`' tasks of type `task` that ship `resource`
/// from `producer`: the manifest's member is the producer, and both its selector and the task's
/// hold the resource.
pub fn retention_of(
    manifests: &[Manifest],
    task: TaskType,
    resource: &str,
    producer: &[u8; 16],
) -> Option<u64> {
    let resource = Resource::parse(resource).ok()?;
    manifests
        .iter()
        .filter(|manifest| {
            manifest.member.host_id == *producer && manifest.selector.contains(&resource)
        })
        .flat_map(|manifest| &manifest.tasks)
        .filter(|held| held.task_type == task && held.selector.contains(&resource))
        .map(|held| held.limits.retention_seconds)
        .max()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use permguard_core::assurance::AssuranceProfile;
    use permguard_core::authz::Selector;
    use permguard_host::membership::record::{HostRef, LeasePolicy, Limits, Status, Task};

    const PRODUCER: [u8; 16] = [7; 16];

    fn task(task_type: TaskType, selector: &str, retention_seconds: u64) -> Task {
        Task {
            task_id: format!("{}-{retention_seconds}", task_type.as_str()),
            task_type,
            selector: Selector::parse(selector).expect("a selector"),
            resource_types: Vec::new(),
            required: true,
            limits: Limits {
                max_body_bytes: 1024,
                max_concurrency: 1,
                max_rate_per_minute: 60,
                max_batch_records: 100,
                retention_seconds,
            },
            assurance_requirements: Vec::new(),
            version: 1,
        }
    }

    fn manifest(member: [u8; 16], selector: &str, tasks: Vec<Task>) -> Manifest {
        let host = |host_id| HostRef {
            host_id,
            epoch: 1,
            fingerprint: "sha256:00".to_owned(),
        };
        Manifest {
            membership_id: [1; 16],
            coordinator: host([2; 16]),
            member: host(member),
            selector: Selector::parse(selector).expect("a selector"),
            tasks,
            member_assurance: AssuranceProfile::Development,
            min_assurance: None,
            assurance_binding: None,
            ring_pins: Vec::new(),
            epoch: 1,
            lease_policy: LeasePolicy {
                max_session_seconds: 3600,
                offline_grace_seconds: 86_400,
                clock_skew_seconds: 30,
                dormant_after_seconds: 2_592_000,
                revoke_after_seconds: 7_776_000,
            },
            previous: None,
            issued_at: 1,
            not_after: 2,
            status: Status::Active,
        }
    }

    /// WP-5.6b: a consumer keeps a stream as long as the longest task of its type shipping that
    /// resource from that producer says; another producer, type or resource gives nothing.
    /// WP-6.2c2b1: a member's manifest with an `events.import` task covering a ledger is what makes
    /// the ledger's imported runs bounded by the Data Plane's floor alone.
    #[test]
    fn a_ledger_is_imported_when_a_members_import_task_covers_it() {
        let resource = "plane/data/zone/z/ledger/l";
        let importing = manifest(
            [3; 16],
            "plane/data/*",
            vec![task(TaskType::EventsImport, "plane/data/zone/z/*", 0)],
        );
        assert!(imported(std::slice::from_ref(&importing), resource));
        assert!(!imported(
            std::slice::from_ref(&importing),
            "plane/data/zone/other/ledger/l"
        ));
        let shipping = manifest(
            [3; 16],
            "plane/data/*",
            vec![task(TaskType::EventsShip, "plane/data/*", 60)],
        );
        assert!(
            !imported(&[shipping], resource),
            "shipping is not importing"
        );
        let narrow = manifest(
            [3; 16],
            "plane/data/zone/other/*",
            vec![task(TaskType::EventsImport, "plane/data/*", 0)],
        );
        assert!(
            !imported(&[narrow], resource),
            "the manifest's selector too"
        );
        assert!(!imported(&[importing], "not a resource"));
    }

    /// Before the consumer is bound, or with no ship task, nothing is deleted.
    #[test]
    fn the_event_retention_waits_for_its_consumer_and_its_members() {
        let retention = EventRetention {
            ship: ShipRetention {
                members: Arc::new(OnceLock::new()),
                task: TaskType::EventsShip,
            },
            consumer: OnceLock::new(),
        };
        assert_eq!(
            retention.retention_seconds("plane/data/zone/z/ledger/l", &PRODUCER),
            None
        );
    }

    #[test]
    fn a_consumers_retention_is_the_longest_task_shipping_its_stream() {
        let resource = "plane/data/zone/z/ledger/l";
        let manifests = vec![
            manifest(
                PRODUCER,
                "plane/data/*",
                vec![
                    task(TaskType::DecisionsShip, "plane/data/*", 60),
                    task(TaskType::DecisionsShip, "plane/data/zone/z/*", 600),
                    task(TaskType::DecisionsShip, "plane/data/zone/other/*", 6000),
                    task(TaskType::EventsShip, "plane/data/*", 60_000),
                ],
            ),
            manifest(
                [9; 16],
                "plane/data/*",
                vec![task(TaskType::DecisionsShip, "plane/data/*", 1)],
            ),
            manifest(
                PRODUCER,
                "plane/control",
                vec![task(TaskType::DecisionsShip, "plane/data/*", 9)],
            ),
        ];
        assert_eq!(
            retention_of(&manifests, TaskType::DecisionsShip, resource, &PRODUCER),
            Some(600)
        );
        assert_eq!(
            retention_of(&manifests, TaskType::EventsShip, resource, &PRODUCER),
            Some(60_000)
        );
        assert_eq!(
            retention_of(&manifests, TaskType::DecisionsShip, resource, &[8; 16]),
            None
        );
        assert_eq!(
            retention_of(
                &manifests,
                TaskType::DecisionsShip,
                "not a resource",
                &PRODUCER
            ),
            None
        );
        // Before the memberships are bound, nothing.
        let unbound = ShipRetention {
            members: Arc::new(OnceLock::new()),
            task: TaskType::DecisionsShip,
        };
        assert_eq!(unbound.retention_seconds(resource, &PRODUCER), None);
    }

    struct Fixed(Result<Option<Vec<Pruned>>, ()>, &'static str);

    impl Prunable for Fixed {
        fn name(&self) -> String {
            self.1.to_owned()
        }

        fn plan(&self, _: u64) -> Result<Vec<Pruned>, permguard_stream::engine::StreamError> {
            Ok(Vec::new())
        }

        fn run(
            &self,
            _: u64,
            audit: permguard_stream::engine::retention::Audit<'_>,
        ) -> Result<Option<Vec<Pruned>>, permguard_stream::engine::StreamError> {
            match &self.0 {
                Ok(Some(pruned)) => {
                    for record in pruned {
                        audit(record).map_err(permguard_stream::engine::StreamError::Invalid)?;
                    }
                    Ok(Some(pruned.clone()))
                }
                Ok(None) => Ok(None),
                Err(()) => Err(permguard_stream::engine::StreamError::Invalid(
                    "down".to_owned(),
                )),
            }
        }
    }

    /// WP-5.6b: a pass runs every handle, records each stream's `host.stream.pruned` in the
    /// security trail, and goes on past a handle that failed or found its own pass running.
    #[test]
    fn a_pass_records_every_stream_and_goes_on_past_a_failure() {
        let root =
            std::env::temp_dir().join(format!("permguard-server-stream-gc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let volume =
            permguard_host::storage::volume::Volume::claim(&root, AssuranceProfile::Development)
                .expect("claimed");
        let time = Arc::new(TimeGuard::system(Duration::from_secs(30)));
        let engine = Engine::open(
            &volume,
            permguard_host::audit::Stamp {
                host_id: [1; 16],
                boot_id: [2; 16],
                build: "0.0.0".to_owned(),
                config_revision: permguard_host::audit::config_revision([("a", Some("b"))]),
            },
            time,
            None,
        )
        .expect("the engine opens");
        let deleted = Pruned {
            stream: "data/decisions/abc/def".to_owned(),
            role: "producer",
            run: Some([3; 16]),
            through: 12,
            batches: 6,
        };
        let nothing = Pruned {
            stream: "data/events/abc/def".to_owned(),
            role: "consumer",
            run: None,
            through: 0,
            batches: 0,
        };
        let prunables: Vec<Arc<dyn Prunable>> = vec![
            Arc::new(Fixed(Err(()), "failing")),
            Arc::new(Fixed(Ok(None), "busy")),
            Arc::new(Fixed(
                Ok(Some(vec![deleted.clone(), nothing.clone()])),
                "working",
            )),
        ];
        assert_eq!(pass(&prunables, &engine, 1), vec![deleted, nothing]);
        let page = engine
            .read(
                permguard_host::audit::Class::Security,
                permguard_host::audit::HOST,
                &permguard_host::audit::query::Query::default(),
            )
            .expect("read");
        let pruned: Vec<_> = page
            .records
            .iter()
            .filter(|record| record.action == AUDIT_PRUNED)
            .collect();
        assert_eq!(pruned.len(), 2);
        assert_eq!(pruned[0].target.as_deref(), Some("data/decisions/abc/def"));
        let facts = &pruned[0].facts;
        assert_eq!(facts.len(), 5);
        assert!(format!("{facts:?}").contains("03030303030303030303030303030303"));
    }
}
