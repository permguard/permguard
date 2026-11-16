// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! An application that decides in its own process with the Permguard evaluator and nothing
//! else: no Host, no server, no ledger, no store, no listener.
//!
//! It names one Permguard package, `permguard-evaluator`, with the language its build selects,
//! and, when it keeps records of what it decided or of what happened, the evidence model of
//! each: `permguard-decisions`, `permguard-events`. The tests are the profiles' proof; what each
//! profile links is `scripts/check-evaluator-fixture.sh`'s to read.

#![forbid(unsafe_code)]

use permguard_evaluator::{Action, Entity, Request};

/// Who asks to do what to what.
pub fn asks(principal: &str, action: &str, resource: &str) -> Request {
    Request {
        principal: Entity {
            kind: "User".to_owned(),
            id: principal.to_owned(),
            ..Entity::default()
        },
        action: Action {
            name: action.to_owned(),
            ..Action::default()
        },
        resource: Entity {
            kind: "Document".to_owned(),
            id: resource.to_owned(),
            ..Entity::default()
        },
        ..Request::default()
    }
}

/// The record of one decision the application made: the evaluator's answer, and what only the
/// application knows about the question.
#[cfg(feature = "decisions")]
pub fn decision_record(
    decision: &permguard_evaluator::Decision,
    request: &Request,
    seq: u64,
    prev: &str,
) -> permguard_decisions::Record {
    use permguard_decisions::answer::Answer;
    use permguard_decisions::record::{
        ActionRef, Body, Build, DecisionBody, Inputs, Party, Reason, Record, StoreRef, Stream,
        VERSION,
    };

    let party = |entity: &Entity| Party {
        kind: entity.kind.clone(),
        id: entity.id.clone(),
        properties: None,
    };
    let mut body = DecisionBody {
        id: format!("decision-{seq}"),
        pdp: Build {
            version: env!("CARGO_PKG_VERSION").to_owned(),
            build: None,
            engines: None,
        },
        store: StoreRef {
            zone: "application".to_owned(),
            ledger: "embedded".to_owned(),
            commit: "sha256:0000".to_owned(),
            counter: 0,
            profile: "default".to_owned(),
        },
        subject: party(&request.principal),
        resource: party(&request.resource),
        action: ActionRef {
            name: request.action.name.clone(),
        },
        principal: None,
        inputs: Inputs::default(),
        // The five members below are the evaluator's to say: written by the conversion.
        decision: false,
        outcome: None,
        causes: None,
        policies: Vec::new(),
        reason: Reason {
            code: String::new(),
        },
        trace: None,
        request_id: None,
        context: None,
        latency_us: 0,
        event: None,
        interface: None,
        actor: None,
        question: None,
        descriptors: None,
        token_status: None,
    };
    Answer::from(decision).write(&mut body);

    Record {
        v: VERSION,
        stream: Stream::new("application", "run-1"),
        seq,
        prev: prev.to_owned(),
        at: "2026-11-17T10:00:00Z".to_owned(),
        body: Body::Decision(Box::new(body)),
    }
}

/// The record of one occurrence the application observed: it needs no decision.
#[cfg(feature = "events")]
pub fn event_record(
    seq: u64,
    prev: &str,
    event: serde_json::Value,
) -> permguard_events::record::Record {
    use permguard_events::record::{
        GENESIS, Producer, RECORD_TYPE, Record, Stream, VERSION, occurrence_digest_of,
    };

    Record {
        v: VERSION,
        record_type: RECORD_TYPE.to_owned(),
        stream: Stream::new(
            Producer::data_plane("application", "run-1"),
            "application",
            "embedded",
        ),
        seq,
        prev: prev.to_owned(),
        event_type: "application.login.v1".to_owned(),
        event_id: format!("event-{seq}"),
        source: None,
        token_status: None,
        occurrence_digest: occurrence_digest_of(&event).unwrap_or_else(|_| GENESIS.to_owned()),
        kind: "request".to_owned(),
        profile: "default".to_owned(),
        policy_partitions: vec!["app".to_owned()],
        commit: "sha256:0000".to_owned(),
        history_key: None,
        occurred_at: "2026-11-17T10:00:00Z".to_owned(),
        observed_at: "2026-11-17T10:00:01Z".to_owned(),
        event,
    }
}
