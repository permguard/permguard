// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The client of the object store against a server.
//!
//! The tests need an S3 server, as `permguard_s3::testing` says, and are skipped without one.

#![allow(clippy::expect_used, clippy::panic)]

use std::sync::Barrier;
use std::time::Duration;

use permguard_s3::testing::{config, roots, scratch};
use permguard_s3::{Bucket, Put, S3Error, Tls};

#[test]
fn an_object_is_published_once_and_read_whole() {
    let Some(bucket) = scratch("an_object_is_published_once_and_read_whole") else {
        return;
    };
    bucket.ready().expect("the bucket answers");
    assert_eq!(bucket.get("objects/ab/cd", 64).expect("answered"), None);
    assert_eq!(bucket.head("objects/ab/cd").expect("answered"), None);

    assert_eq!(
        bucket
            .put_new("objects/ab/cd", b"the first")
            .expect("answered"),
        Put::Written
    );
    // Without replacement: the key holds what it held.
    assert_eq!(
        bucket
            .put_new("objects/ab/cd", b"another")
            .expect("answered"),
        Put::Exists
    );
    assert_eq!(
        bucket
            .get("objects/ab/cd", 64)
            .expect("answered")
            .as_deref(),
        Some(&b"the first"[..])
    );
    assert_eq!(bucket.head("objects/ab/cd").expect("answered"), Some(9));
    // An object past the caller's bound is not read.
    assert!(matches!(
        bucket.get("objects/ab/cd", 4),
        Err(S3Error::Unavailable(_))
    ));
    // An empty object is an object.
    assert_eq!(
        bucket.put_new("objects/empty", b"").expect("answered"),
        Put::Written
    );
    assert_eq!(bucket.head("objects/empty").expect("answered"), Some(0));
    assert_eq!(
        bucket
            .get("objects/empty", 64)
            .expect("answered")
            .as_deref(),
        Some(&b""[..])
    );

    bucket.delete("objects/ab/cd").expect("removed");
    bucket.delete("objects/ab/cd").expect("nothing to remove");
    assert_eq!(bucket.get("objects/ab/cd", 64).expect("answered"), None);
    // A key that was freed takes an object again.
    assert_eq!(
        bucket
            .put_new("objects/ab/cd", b"another")
            .expect("answered"),
        Put::Written
    );
}

#[test]
fn a_listing_is_whole_and_of_its_prefix() {
    let Some(bucket) = scratch("a_listing_is_whole_and_of_its_prefix") else {
        return;
    };
    assert!(bucket.list("").expect("listed").is_empty());
    // More than one page of the store's listing.
    const OBJECTS: usize = 1100;
    std::thread::scope(|scope| {
        for part in 0..10 {
            let bucket = &bucket;
            scope.spawn(move || {
                for n in (0..OBJECTS).filter(|n| n % 10 == part) {
                    let put = bucket
                        .put_new(&format!("objects/{n:04}"), format!("{n}").as_bytes())
                        .expect("answered");
                    assert_eq!(put, Put::Written);
                }
            });
        }
    });
    bucket.put_new("refs/main", b"elsewhere").expect("answered");

    let listed = bucket.list("objects/").expect("listed");
    assert_eq!(listed.len(), OBJECTS);
    let keys: Vec<&str> = listed.iter().map(|object| object.key.as_str()).collect();
    let mut sorted = keys.clone();
    sorted.sort_unstable();
    assert_eq!(keys, sorted, "in the order of the keys");
    assert_eq!(keys[0], "objects/0000");
    assert_eq!(listed[7].bytes, 1);
    assert_eq!(listed[1099].bytes, 4);
    let now = permguard_core::time::unix_now();
    assert!(
        listed
            .iter()
            .all(|object| object.modified.abs_diff(now) < 600),
        "each says when it was written"
    );
    assert_eq!(bucket.list("").expect("listed").len(), OBJECTS + 1);
    assert_eq!(bucket.list("refs/").expect("listed").len(), 1);
    assert!(bucket.list("nothing/").expect("listed").is_empty());
}

#[test]
fn publications_of_one_key_together_write_one() {
    let Some(bucket) = scratch("publications_of_one_key_together_write_one") else {
        return;
    };
    const TOGETHER: usize = 8;
    for round in 0..6 {
        let key = format!("objects/{round}");
        let barrier = Barrier::new(TOGETHER);
        let written: usize = std::thread::scope(|scope| {
            let running: Vec<_> = (0..TOGETHER)
                .map(|caller| {
                    let (bucket, key, barrier) = (&bucket, &key, &barrier);
                    scope.spawn(move || {
                        barrier.wait();
                        bucket
                            .put_new(key, format!("caller {caller}").as_bytes())
                            .expect("answered")
                    })
                })
                .collect();
            running
                .into_iter()
                .map(|caller| caller.join().expect("a caller finished"))
                .filter(|put| *put == Put::Written)
                .count()
        });
        assert_eq!(written, 1, "one publication writes the key {key}");
    }
}

#[test]
fn clients_under_two_prefixes_share_nothing() {
    let (Some(one), Some(other)) = (
        scratch("clients_under_two_prefixes_share_nothing"),
        scratch("clients_under_two_prefixes_share_nothing"),
    ) else {
        return;
    };
    one.put_new("objects/a", b"of one").expect("answered");
    assert_eq!(other.get("objects/a", 64).expect("answered"), None);
    assert!(other.list("").expect("listed").is_empty());
    assert_eq!(
        other
            .put_new("objects/a", b"of the other")
            .expect("answered"),
        Put::Written
    );
    other.delete("objects/a").expect("removed");
    assert_eq!(
        one.get("objects/a", 64).expect("answered").as_deref(),
        Some(&b"of one"[..])
    );
}

#[test]
fn a_request_runs_from_inside_a_runtime() {
    let Some(bucket) = scratch("a_request_runs_from_inside_a_runtime") else {
        return;
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("a runtime");
    runtime.block_on(async {
        assert_eq!(
            bucket.put_new("objects/a", b"x").expect("answered"),
            Put::Written
        );
        assert_eq!(bucket.head("objects/a").expect("answered"), Some(1));
        // And the client may be let go there.
        drop(bucket);
    });
}

#[test]
fn a_wrong_secret_an_unknown_authority_and_a_silent_store_are_told_apart() {
    let test = "a_wrong_secret_an_unknown_authority_and_a_silent_store_are_told_apart";
    let tls = || roots().map_or(Tls::Disabled, Tls::Verified);
    let Some(mut wrong) = config(test, "t-refused/", tls()) else {
        return;
    };
    wrong.secret = zeroize::Zeroizing::new("not the secret of this run".to_owned());
    let refused = Bucket::connect(wrong)
        .expect("a client")
        .put_new("objects/a", b"x");
    assert!(
        matches!(refused, Err(S3Error::Refused { status: 403, .. })),
        "a signature made with another secret is refused: {refused:?}"
    );

    if roots().is_some() {
        let unknown = config(
            test,
            "t-refused/",
            Tls::Verified(std::sync::Arc::new(rustls::RootCertStore::empty())),
        )
        .expect("a server");
        let refused = Bucket::connect(unknown).expect("a client").ready();
        assert!(
            matches!(refused, Err(S3Error::Unavailable(_))),
            "a certificate of an unknown authority is not trusted: {refused:?}"
        );
    }

    let mut silent = config(test, "t-refused/", Tls::Disabled).expect("a server");
    silent.host = "127.0.0.1".to_owned();
    // A port nothing listens on.
    silent.port = 1;
    silent.timeout = Duration::from_secs(2);
    let answered = Bucket::connect(silent).expect("a client").ready();
    assert!(
        matches!(answered, Err(S3Error::Unavailable(_))),
        "{answered:?}"
    );
}
