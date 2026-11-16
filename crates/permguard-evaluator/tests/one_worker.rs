// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The one-worker profile (the crate boundaries refactoring, RD-17): a deployment configured for
//! one evaluation at a time bounds the pool this process decides on before anything decides, and
//! that pool then holds no worker and starts no thread.
//!
//! One test, in a file of its own: the bound is the process's, set once, so nothing else may build
//! the shared pool first.

#![allow(clippy::expect_used)]

use permguard_evaluator::fanout::Fanout;

#[test]
fn test_a_process_bound_to_one_evaluation_decides_on_the_calling_thread_alone() {
    assert!(Fanout::bound_shared(1), "nothing bound the pool before");
    // The first bound holds: a later one changes nothing.
    assert!(!Fanout::bound_shared(8));

    let pool = Fanout::shared();
    assert_eq!(pool.workers(), 0, "a one-worker profile holds no worker");

    let caller = std::thread::current().id();
    let jobs: Vec<Box<dyn FnOnce() -> bool + Send + 'static>> = (0..4)
        .map(|_| {
            Box::new(move || std::thread::current().id() == caller)
                as Box<dyn FnOnce() -> bool + Send + 'static>
        })
        .collect();
    assert_eq!(
        pool.run(jobs).expect("every partition answered"),
        vec![true; 4],
        "a partition was evaluated off the calling thread"
    );
}
