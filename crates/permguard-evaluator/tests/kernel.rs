// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The decision alone (`11-refactoring/1-dependencies.md`, The evaluator): an application registers
//! an engine, loads policies its language validates, and asks who may do what to what, with no
//! Host, no store, no ledger and no log anywhere in the build.
//!
//! | What is done                          | What it proves                                      |
//! | ------------------------------------- | --------------------------------------------------- |
//! | policies loaded, a question asked     | validated, compiled, decided: permit, deny, default |
//! | a policy its language refuses         | it loads nothing, and says which policy and why     |
//! | engines registered in either order    | one fixed order, one answer                         |
//! | one language registered twice         | refused: nothing is replaced                        |
//! | policies with no engine, or none      | refused, by name                                    |
//! | a language that decides on history    | refused: this evaluator keeps no past               |
//! | the provenance of what it decides on  | validated by the application, never a verified ledger |

#![allow(clippy::expect_used)]

use permguard_evaluator::{
    Action, Entity, Evaluator, Policies, Provenance, Refused, Request, Resolution,
};

const READERS: &str = r#"permit (
    principal == User::"alice",
    action == Action::"read",
    resource == Document::"budget"
);"#;
const NOBODY_DELETES: &str = r#"forbid (principal, action == Action::"delete", resource);"#;
const GATEWAY: &str = "package gateway\nimport rego.v1\ndefault allow := false\nallow if { input.subject.id == \"alice\" }\n";

fn entity(kind: &str, id: &str) -> Entity {
    Entity {
        kind: kind.to_owned(),
        id: id.to_owned(),
        ..Entity::default()
    }
}

fn asks(principal: &str, action: &str) -> Request {
    Request {
        principal: entity("User", principal),
        action: Action {
            name: action.to_owned(),
            ..Action::default()
        },
        resource: entity("Document", "budget"),
        ..Request::default()
    }
}

fn cedar() -> Evaluator {
    Evaluator::builder()
        .engine(permguard_language_cedar::engine())
        .load(
            Policies::of("cedar")
                .policy("readers", READERS)
                .policy("nobody-deletes", NOBODY_DELETES),
        )
        .expect("Cedar reads its policies")
        .build()
        .expect("they compile")
}

#[test]
fn test_policies_are_validated_compiled_and_decide_who_may_do_what_to_what() {
    let evaluator = cedar();
    assert_eq!(evaluator.languages(), ["cedar"]);
    assert_eq!(evaluator.policies().len(), 2);

    let allowed = evaluator.evaluate(&asks("alice", "read")).expect("asked");
    assert!(allowed.permitted());
    assert_eq!(allowed.resolution(), Resolution::Permit);
    assert_eq!(allowed.permits(), ["readers"], "the policy that decided it");
    assert!(allowed.denials().is_empty() && allowed.errors().is_empty());

    // Nothing permits it: denied by default, with nothing to cite.
    let silent = evaluator.evaluate(&asks("bob", "read")).expect("asked");
    assert!(!silent.permitted());
    assert_eq!(silent.resolution(), Resolution::DenyByDefault);
    assert!(silent.permits().is_empty() && silent.denials().is_empty());

    // A policy refuses it: a deny, and the policy that said no.
    let refused = evaluator.evaluate(&asks("alice", "delete")).expect("asked");
    assert_eq!(refused.resolution(), Resolution::Deny);
    assert_eq!(refused.denials(), ["nobody-deletes"]);
}

#[test]
fn test_the_context_of_a_request_is_what_a_policy_reads() {
    let evaluator = Evaluator::builder()
        .engine(permguard_language_cedar::engine())
        .load(Policies::of("cedar").policy(
            "office-hours",
            r#"permit (principal, action, resource) when { context.office == true };"#,
        ))
        .expect("loaded")
        .build()
        .expect("built");
    let mut request = asks("alice", "read");

    request.context.insert("office".to_owned(), true.into());
    assert!(evaluator.evaluate(&request).expect("asked").permitted());

    request.context.insert("office".to_owned(), false.into());
    assert!(!evaluator.evaluate(&request).expect("asked").permitted());
}

#[test]
fn test_a_policy_its_language_refuses_loads_nothing_and_says_which() {
    let refused = Evaluator::builder()
        .engine(permguard_language_cedar::engine())
        .load(
            Policies::of("cedar")
                .policy("readers", READERS)
                .policy("broken", "permit (principal"),
        )
        .err()
        .expect("not a Cedar policy");

    let Refused::Invalid { policy, reason } = &refused else {
        panic!("refused for another reason: {refused}");
    };
    assert_eq!(policy, "broken");
    assert!(!reason.is_empty());
}

#[test]
fn test_engines_keep_one_order_whatever_order_they_were_registered_in() {
    let built = |cedar_first: bool| {
        let builder = Evaluator::builder();
        let builder = if cedar_first {
            builder
                .engine(permguard_language_cedar::engine())
                .engine(permguard_language_rego::engine())
        } else {
            builder
                .engine(permguard_language_rego::engine())
                .engine(permguard_language_cedar::engine())
        };
        let (first, second) = (
            Policies::of("rego").policy("gateway", GATEWAY),
            Policies::of("cedar").policy("readers", READERS),
        );
        let builder = if cedar_first {
            builder.load(second).expect("loaded").load(first)
        } else {
            builder.load(first).expect("loaded").load(second)
        };
        builder.expect("loaded").build().expect("built")
    };
    let (one, other) = (built(true), built(false));

    assert_eq!(one.languages(), ["cedar", "rego"]);
    assert_eq!(one.languages(), other.languages());
    assert_eq!(one.policies(), other.policies());
    for request in [asks("alice", "read"), asks("bob", "read")] {
        assert_eq!(
            one.evaluate(&request).expect("asked"),
            other.evaluate(&request).expect("asked")
        );
    }
    // Both languages answer one question, and both are cited.
    let allowed = one.evaluate(&asks("alice", "read")).expect("asked");
    assert!(allowed.permitted());
    assert_eq!(allowed.permits().len(), 2, "{:?}", allowed.permits());
}

#[test]
fn test_a_language_registered_twice_is_refused_and_nothing_is_replaced() {
    let twice = || {
        Evaluator::builder()
            .engine(permguard_language_cedar::engine())
            .engine(permguard_language_cedar::engine())
    };

    // Refused where it is first needed: when its policies are loaded.
    let at_load = twice()
        .load(Policies::of("cedar").policy("readers", READERS))
        .err()
        .expect("two engines for one language");
    assert_eq!(at_load, Refused::DuplicateEngine("cedar".to_owned()));
    assert!(
        at_load.to_string().contains("none is replaced"),
        "{at_load}"
    );

    // And when the evaluator is built, wherever the duplicate sits.
    let at_build = twice()
        .engine(permguard_language_rego::engine())
        .load(Policies::of("rego").policy("gateway", GATEWAY))
        .expect("Rego has one engine")
        .build()
        .err()
        .expect("two engines for Cedar");
    assert_eq!(at_build, Refused::DuplicateEngine("cedar".to_owned()));
}

#[test]
fn test_policies_with_no_engine_none_at_all_or_loaded_twice_are_refused_by_name() {
    let no_engine = Evaluator::builder()
        .engine(permguard_language_cedar::engine())
        .load(Policies::of("rego").policy("gateway", GATEWAY))
        .err()
        .expect("no engine evaluates Rego here");
    assert_eq!(no_engine, Refused::NoEngine("rego".to_owned()));

    let nothing = Evaluator::builder()
        .engine(permguard_language_cedar::engine())
        .build()
        .err()
        .expect("nothing to decide with");
    assert_eq!(nothing, Refused::NothingLoaded);

    let twice = Evaluator::builder()
        .engine(permguard_language_cedar::engine())
        .load(Policies::of("cedar").policy("readers", READERS))
        .expect("loaded")
        .load(Policies::of("cedar").policy("nobody-deletes", NOBODY_DELETES))
        .err()
        .expect("one set of policies a language");
    assert_eq!(twice, Refused::DuplicateLanguage("cedar".to_owned()));
}

#[test]
fn test_a_language_that_decides_on_history_is_refused_by_an_evaluator_that_keeps_none() {
    let refused = Evaluator::builder()
        .engine(permguard_language_dogwood::engine())
        .load(
            Policies::of("dogwood")
                .policy("read-after-login", "permit (principal, action, resource);"),
        )
        .err()
        .expect("Dogwood decides against a past");

    assert_eq!(refused, Refused::Temporal("dogwood".to_owned()));
    assert!(
        refused.to_string().contains("keeps no history"),
        "{refused}"
    );
}

/// Policies an application validated are never reported as a ledger the Permguard protocol
/// verified: there is one provenance here, and no way to state another.
#[test]
fn test_what_an_application_loads_is_validated_and_never_a_verified_ledger() {
    let evaluator = cedar();

    assert_eq!(evaluator.provenance(), Provenance::Validated);
    assert_eq!(
        evaluator
            .evaluate(&asks("alice", "read"))
            .expect("asked")
            .provenance(),
        Provenance::Validated
    );
}
