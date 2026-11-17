// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! An evaluation has no side effect: it reads the compiled policies and the request, writes
//! nothing, and asked again answers the same.
//!
//! One test, in a file of its own: it moves the process into an empty directory, which is the
//! process's and not a thread's, and looks at what is there afterwards.

#![allow(clippy::expect_used)]

use permguard_evaluator::{Action, Entity, Evaluator, Policies, Request};

#[test]
fn test_an_evaluation_writes_nothing_and_asked_again_answers_the_same() {
    let directory = std::env::temp_dir().join(format!(
        "permguard-evaluator-no-side-effect-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).expect("an empty directory");
    std::env::set_current_dir(&directory).expect("the process moves into it");

    let evaluator = Evaluator::builder()
        .engine(permguard_language_cedar::engine())
        .load(Policies::of("cedar").policy(
            "readers",
            r#"permit (principal == User::"alice", action == Action::"read", resource);"#,
        ))
        .expect("loaded")
        .build()
        .expect("built");
    let request = Request {
        principal: Entity {
            kind: "User".to_owned(),
            id: "alice".to_owned(),
            ..Entity::default()
        },
        action: Action {
            name: "read".to_owned(),
            ..Action::default()
        },
        resource: Entity {
            kind: "Document".to_owned(),
            id: "budget".to_owned(),
            ..Entity::default()
        },
        ..Request::default()
    };

    // Shared across threads, immutable: the evaluator is asked through a shared reference.
    fn shared<T: Send + Sync>(_: &T) {}
    shared(&evaluator);

    let first = evaluator.evaluate(&request).expect("asked");
    for _ in 0..100 {
        assert_eq!(evaluator.evaluate(&request).expect("asked"), first);
    }
    assert!(first.permitted());
    assert_eq!(evaluator.policies(), ["readers"]);

    let left: Vec<_> = std::fs::read_dir(&directory)
        .expect("the directory is read")
        .filter_map(Result::ok)
        .map(|entry| entry.file_name())
        .collect();
    assert!(left.is_empty(), "an evaluation wrote {left:?}");
}
