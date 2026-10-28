// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The two evidence streams as the Host's stream engine registers them, pinned to the table of
//! `3-control-plane-evidence-stores.md` ("Stream registrations"): identity, record domain, batch
//! type, retention class, provider task and producer identity. A value that drifts from the
//! contract fails here, not in a reader that trusted it.

use permguard_host::membership::record::TaskType;
use permguard_stream::engine::{Descriptor, ResourceShape, Retention};

/// One column of the table.
struct Registration {
    descriptor: Descriptor,
    identity: (&'static str, &'static str, u32),
    record_domain: &'static str,
    batch_typ: &'static str,
    retention: Retention,
    task: TaskType,
    task_name: &'static str,
}

fn registrations() -> [Registration; 2] {
    [
        Registration {
            descriptor: permguard_decisions::stream::descriptor(),
            identity: ("data", "decisions", 1),
            record_domain: "permguard.decision.v1\n",
            batch_typ: "permguard.decision.batch.v1",
            retention: Retention::Evidence,
            task: TaskType::DecisionsShip,
            task_name: "decisions.ship",
        },
        Registration {
            descriptor: permguard_events::stream::descriptor(),
            identity: ("data", "events", 1),
            record_domain: "permguard.event.record.v1\n",
            batch_typ: "permguard.event.batch.v1",
            retention: Retention::History,
            task: TaskType::EventsShip,
            task_name: "events.ship",
        },
    ]
}

#[test]
fn the_decision_and_event_streams_are_registered_as_the_contract_states() {
    for expected in registrations() {
        let held = &expected.descriptor;
        let name = format!("{}.{}.v{}", held.plane, held.stream_type, held.version);
        assert_eq!(
            (held.plane.as_str(), held.stream_type.as_str(), held.version),
            expected.identity,
            "{name}: stream identity"
        );
        assert_eq!(
            held.record_domain, expected.record_domain,
            "{name}: record domain"
        );
        assert_eq!(held.batch_typ, expected.batch_typ, "{name}: batch type");
        assert_eq!(
            held.retention, expected.retention,
            "{name}: retention class"
        );
        assert_eq!(held.task, Some(expected.task), "{name}: provider task");
        assert_eq!(
            expected.task.as_str(),
            expected.task_name,
            "{name}: task name"
        );
        // The producer identity is the member Host: records belong to a ledger, signed by the
        // data plane's attest ring, and a required subscription holds truncation.
        assert_eq!(
            held.resource_shape,
            ResourceShape::Ledger,
            "{name}: resource"
        );
        assert_eq!(
            held.ring,
            permguard_host::keys::ring::DATA_ATTEST,
            "{name}: ring"
        );
        assert!(held.subscription_required, "{name}: subscription");
    }
}

#[test]
fn a_signature_for_one_stream_cannot_be_taken_for_the_other() {
    let [decisions, events] = registrations().map(|registration| registration.descriptor);
    assert_ne!(decisions.record_domain, events.record_domain);
    assert_ne!(decisions.batch_typ, events.batch_typ);
    assert_ne!(decisions.task, events.task);
    assert_ne!(decisions.stream_type, events.stream_type);
}
