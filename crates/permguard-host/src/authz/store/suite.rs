// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The conformance suite of [`BootstrapStore`]: what every backend of the contract does the same
//! way (`1-architecture/8` Store contracts).
//!
//! [`run`] takes how a backend makes one empty store and runs every case on a store of its own.
//! A case panics with what it expected, as a test does. A backend proves what only it can, that
//! its commitment survives its own restart and what it does of one damaged at rest, in its own
//! tests.
//!
//! | Case                               | Rule of the contract                                      |
//! | ---------------------------------- | --------------------------------------------------------- |
//! | `an_empty_store`                   | no commitment is held                                     |
//! | `a_commitment_is_written_once`     | the same certificate again is the first commitment        |
//! | `another_certificate_is_refused`   | and changes nothing; so is what is not a fingerprint      |
//! | `commitments_together_write_one`   | of those that arrive together one is written, one is held |

#![allow(clippy::expect_used, clippy::panic)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};

use super::{AuthzError, Bootstrap, BootstrapStore};
use crate::operations::mutation::Applying;

const NOW: u64 = 1_800_000_000;

/// How a suite runs something inside one operation of the mutation engine: the token it is
/// given is one the engine built, a new operation at every call, from any thread.
pub type Operate<'a> = &'a (dyn Fn(&mut dyn FnMut(&Applying<'_>)) + Sync);

/// The fingerprint of the certificate `n`.
fn fingerprint(n: u8) -> String {
    format!("{n:02x}").repeat(32)
}

/// Commits to the certificate `n` at `now`, in an operation of its own.
fn committed<S: BootstrapStore + ?Sized>(
    store: &S,
    operate: Operate<'_>,
    fingerprint: &str,
    now: u64,
) -> Result<(Bootstrap, bool), AuthzError> {
    let mut said = None;
    operate(&mut |applying| said = Some(store.commit(applying, fingerprint, now)));
    said.expect("the operation ran")
}

/// Runs every case, each on a store `make` has just made empty; `operate` runs what it is given
/// inside one operation of the grants' domain.
pub fn run<S: BootstrapStore + ?Sized>(make: &dyn Fn() -> Arc<S>, operate: Operate<'_>) {
    an_empty_store(&*make());
    a_commitment_is_written_once(&*make(), operate);
    another_certificate_is_refused(&*make(), operate);
    commitments_together_write_one(make, operate);
}

fn an_empty_store<S: BootstrapStore + ?Sized>(store: &S) {
    assert_eq!(store.bootstrap().expect("the commitment reads"), None);
}

fn a_commitment_is_written_once<S: BootstrapStore + ?Sized>(store: &S, operate: Operate<'_>) {
    let upper = fingerprint(0xab).to_ascii_uppercase();
    let (commitment, written) = committed(store, operate, &upper, NOW).expect("committed");
    assert!(written);
    assert_eq!(
        commitment.principal.as_str(),
        format!("cert:sha256:{}", fingerprint(0xab))
    );
    assert_eq!(commitment.created_at, NOW);
    assert_eq!(
        store.bootstrap().expect("the commitment reads"),
        Some(commitment.clone())
    );
    // The same certificate, written another way and later: the first commitment, not written.
    let (again, written) = committed(
        store,
        operate,
        &format!("sha256:{}", fingerprint(0xab)),
        NOW + 60,
    )
    .expect("the same certificate again");
    assert!(!written);
    assert_eq!(again, commitment, "the first, with the time it was made at");
    assert_eq!(
        store.bootstrap().expect("the commitment reads"),
        Some(commitment)
    );
}

fn another_certificate_is_refused<S: BootstrapStore + ?Sized>(store: &S, operate: Operate<'_>) {
    assert!(
        matches!(
            committed(store, operate, "nonsense", NOW),
            Err(AuthzError::Invalid(_))
        ),
        "what is not a fingerprint commits to nothing"
    );
    assert_eq!(store.bootstrap().expect("the commitment reads"), None);
    let (held, _) = committed(store, operate, &fingerprint(1), NOW).expect("committed");
    assert!(matches!(
        committed(store, operate, &fingerprint(2), NOW + 1),
        Err(AuthzError::Invalid(_))
    ));
    assert_eq!(
        store.bootstrap().expect("the commitment reads"),
        Some(held),
        "the refusal changed nothing"
    );
}

fn commitments_together_write_one<S: BootstrapStore + ?Sized>(
    make: &dyn Fn() -> Arc<S>,
    operate: Operate<'_>,
) {
    const THREADS: u8 = 8;
    const ROUNDS: usize = 4;
    // Each to a certificate of its own, then all to one: one is written either way.
    for same in [false, true] {
        for _ in 0..ROUNDS {
            let store = make();
            let store = &*store;
            let wrote = AtomicUsize::new(0);
            let together = Barrier::new(usize::from(THREADS));
            std::thread::scope(|scope| {
                for thread in 0..THREADS {
                    let (wrote, together) = (&wrote, &together);
                    scope.spawn(move || {
                        let named = fingerprint(if same { 7 } else { thread + 1 });
                        // An engine may run the operation again when its unit of work kept
                        // nothing of a first run: the threads are released together once, and
                        // what counts is what the last run was answered.
                        let mut released = false;
                        let mut answered = None;
                        operate(&mut |applying| {
                            if !released {
                                released = true;
                                together.wait();
                            }
                            answered = Some(store.commit(applying, &named, NOW));
                        });
                        match answered.expect("the operation ran") {
                            Ok((held, written)) => {
                                assert_eq!(
                                    held.fingerprint, named,
                                    "a commitment answered is to the certificate asked"
                                );
                                if written {
                                    wrote.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                            Err(AuthzError::Invalid(_)) => assert!(!same, "one certificate"),
                            Err(other) => panic!("a commitment answered {other}"),
                        }
                    });
                }
            });
            assert_eq!(
                wrote.load(Ordering::Relaxed),
                1,
                "one commitment is written"
            );
            assert!(store.bootstrap().expect("the commitment reads").is_some());
        }
    }
}
