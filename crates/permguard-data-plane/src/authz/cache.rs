// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What stays in memory between decisions, and what is dropped when it will
//! not fit.
//!
//! # Why a cache at all
//!
//! Compiling a partition means reading every object of a subtree off the
//! volume, parsing every policy, building the engine's program and checking it
//! against the schema. That is milliseconds. Answering a request from an
//! already-compiled program is microseconds. A PDP that recompiled per request
//! would be a PDP nobody puts on a hot path.
//!
//! # What is keyed by what
//!
//! ```text
//! (zone-id, ledger-id, commit)              ──► the head: manifest + counter
//! (zone-id, ledger-id, commit, partition)   ──► one compiled partition
//! ```
//!
//! The commit is **part of the key**, which is what makes this correct rather
//! than merely fast: a synchronization that advances a ledger does not
//! invalidate anything — it asks for a key that is not there yet, compiles it,
//! and the old entries fall out as the least recently used. Nothing serves a
//! commit that has been replaced, and nothing has to remember to flush.
//!
//! # The two bounds
//!
//! `authz.cache.partitions` bounds how many entries are held;
//! `authz.cache.bytes` bounds what they weigh. Whichever is reached first, the
//! least recently used entry is evicted. Both are configuration, because how
//! many ledgers a plane serves and how big their policy sets are is a
//! deployment's fact, not ours.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use super::snapshot::{Head, Partition};

/// What a cached entry is.
#[derive(Clone)]
enum Held {
    Head(Arc<Head>),
    Partition(Arc<Partition>),
}

impl Held {
    fn footprint(&self) -> usize {
        match self {
            // A manifest is small and bounded by the object model; charging it
            // a flat estimate keeps the accounting honest without pretending
            // to measure a decoded structure.
            Self::Head(_) => 4 * 1024,
            Self::Partition(partition) => partition.footprint,
        }
    }
}

/// One thing the cache holds, and when it was last wanted.
struct Entry {
    held: Held,
    used: u64,
}

/// The bounded, shared store of compiled programs.
pub struct Cache {
    max_entries: usize,
    max_bytes: u64,
    inner: Mutex<Inner>,
    clock: AtomicU64,
    /// Counters, so an operator can see whether the bounds are the right ones.
    pub hits: AtomicU64,
    pub misses: AtomicU64,
    pub evictions: AtomicU64,
}

#[derive(Default)]
struct Inner {
    entries: HashMap<String, Entry>,
    bytes: u64,
}

impl Cache {
    /// A cache with the deployment's two bounds.
    pub fn new(max_entries: usize, max_bytes: u64) -> Self {
        Self {
            max_entries: max_entries.max(1),
            max_bytes: max_bytes.max(1),
            inner: Mutex::new(Inner::default()),
            clock: AtomicU64::new(0),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            evictions: AtomicU64::new(0),
        }
    }

    /// The key of a ledger's head at a commit.
    pub fn head_key(zone_id: &str, ledger_id: &str, commit: &str) -> String {
        format!("{zone_id}/{ledger_id}@{commit}")
    }

    /// The key of one compiled partition of that commit.
    pub fn partition_key(zone_id: &str, ledger_id: &str, commit: &str, partition: &str) -> String {
        format!("{zone_id}/{ledger_id}@{commit}#{partition}")
    }

    /// The head under this key, if it is held.
    pub fn head(&self, key: &str) -> Option<Arc<Head>> {
        match self.take(key)? {
            Held::Head(head) => Some(head),
            Held::Partition(_) => None,
        }
    }

    /// The compiled partition under this key, if it is held.
    pub fn partition(&self, key: &str) -> Option<Arc<Partition>> {
        match self.take(key)? {
            Held::Partition(partition) => Some(partition),
            Held::Head(_) => None,
        }
    }

    /// Keeps a head.
    pub fn keep_head(&self, key: String, head: Arc<Head>) {
        self.keep(key, Held::Head(head));
    }

    /// Keeps a compiled partition.
    pub fn keep_partition(&self, key: String, partition: Arc<Partition>) {
        self.keep(key, Held::Partition(partition));
    }

    /// How many entries and how many bytes are held, for the gauges.
    pub fn holdings(&self) -> (usize, u64) {
        match self.inner.lock() {
            Ok(inner) => (inner.entries.len(), inner.bytes),
            // A poisoned lock means a panic elsewhere; a gauge is not the
            // place to make that worse.
            Err(_) => (0, 0),
        }
    }

    fn take(&self, key: &str) -> Option<Held> {
        let mut inner = self.inner.lock().ok()?;
        let now = self.clock.fetch_add(1, Ordering::Relaxed);
        let entry = inner.entries.get_mut(key);
        match entry {
            Some(entry) => {
                entry.used = now;
                self.hits.fetch_add(1, Ordering::Relaxed);
                Some(entry.held.clone())
            }
            None => {
                self.misses.fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }

    fn keep(&self, key: String, held: Held) {
        let Ok(mut inner) = self.inner.lock() else {
            // Nothing is cached, everything still works — slower. That is the
            // right failure for a cache.
            return;
        };
        let now = self.clock.fetch_add(1, Ordering::Relaxed);
        let footprint = held.footprint() as u64;
        if let Some(replaced) = inner.entries.insert(key, Entry { held, used: now }) {
            inner.bytes = inner.bytes.saturating_sub(replaced.held.footprint() as u64);
        }
        inner.bytes = inner.bytes.saturating_add(footprint);

        // Prune to both bounds, least recently used first — but never to
        // nothing: one entry heavier than the whole bound is still better held
        // than recompiled on every request, and a cache that empties itself
        // would thrash instead of degrading.
        while inner.entries.len() > self.max_entries
            || (inner.bytes > self.max_bytes && inner.entries.len() > 1)
        {
            let Some(oldest) = inner
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.used)
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            if let Some(dropped) = inner.entries.remove(&oldest) {
                inner.bytes = inner.bytes.saturating_sub(dropped.held.footprint() as u64);
                self.evictions.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use permguard_languages::{Evaluator, Query, Verdict};

    struct Nothing(usize);

    impl Evaluator for Nothing {
        fn evaluate(&self, _query: &Query) -> Verdict {
            Verdict::deny(Vec::new())
        }
        fn footprint(&self) -> usize {
            self.0
        }
        fn policies(&self) -> Vec<String> {
            Vec::new()
        }
    }

    fn partition(name: &str, footprint: usize) -> Arc<Partition> {
        Arc::new(Partition::for_test(
            name,
            footprint,
            Box::new(Nothing(footprint)),
        ))
    }

    #[test]
    fn what_was_kept_comes_back() {
        let cache = Cache::new(8, 1024 * 1024);
        let key = Cache::partition_key("z", "l", "sha256:abc", "app");
        assert!(
            cache.partition(&key).is_none(),
            "a cold cache holds nothing"
        );

        cache.keep_partition(key.clone(), partition("app", 128));
        assert_eq!(
            cache.partition(&key).expect("it is held").name,
            "app".to_owned()
        );
        assert_eq!(cache.hits.load(Ordering::Relaxed), 1);
        assert_eq!(cache.misses.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn the_commit_is_part_of_the_key_so_a_sync_replaces_nothing() {
        let cache = Cache::new(8, 1024 * 1024);
        let old = Cache::partition_key("z", "l", "sha256:old", "app");
        let new = Cache::partition_key("z", "l", "sha256:new", "app");

        cache.keep_partition(old.clone(), partition("app", 64));
        assert!(
            cache.partition(&new).is_none(),
            "the new commit is simply not there yet"
        );
        cache.keep_partition(new.clone(), partition("app", 64));
        assert!(cache.partition(&new).is_some());
    }

    #[test]
    fn the_entry_bound_evicts_the_least_recently_used() {
        let cache = Cache::new(2, 1024 * 1024);
        for name in ["a", "b"] {
            cache.keep_partition(
                Cache::partition_key("z", "l", "sha256:c", name),
                partition(name, 16),
            );
        }
        // Touch `a`, so `b` becomes the oldest.
        assert!(
            cache
                .partition(&Cache::partition_key("z", "l", "sha256:c", "a"))
                .is_some()
        );
        cache.keep_partition(
            Cache::partition_key("z", "l", "sha256:c", "c"),
            partition("c", 16),
        );

        assert!(
            cache
                .partition(&Cache::partition_key("z", "l", "sha256:c", "a"))
                .is_some(),
            "the one that was wanted stays"
        );
        assert!(
            cache
                .partition(&Cache::partition_key("z", "l", "sha256:c", "b"))
                .is_none(),
            "the one that was not, goes"
        );
        assert_eq!(cache.evictions.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn the_byte_bound_evicts_too() {
        let cache = Cache::new(100, 1_000);
        cache.keep_partition(
            Cache::partition_key("z", "l", "sha256:c", "big"),
            partition("big", 900),
        );
        cache.keep_partition(
            Cache::partition_key("z", "l", "sha256:c", "other"),
            partition("other", 900),
        );

        let (entries, bytes) = cache.holdings();
        assert_eq!(entries, 1, "two of those do not fit");
        assert!(bytes <= 1_000, "and the accounting says so: {bytes}");
    }

    #[test]
    fn one_entry_larger_than_the_whole_bound_is_still_served() {
        // Better one thing held than a cache that thrashes on every request.
        let cache = Cache::new(4, 100);
        let key = Cache::partition_key("z", "l", "sha256:c", "huge");
        cache.keep_partition(key.clone(), partition("huge", 10_000));

        assert!(cache.partition(&key).is_some());
    }
}
