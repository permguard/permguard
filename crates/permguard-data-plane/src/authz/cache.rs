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
//! # The bounds, for the whole cache and for each zone
//!
//! `authz.cache.partitions` bounds how many entries are held;
//! `authz.cache.bytes` bounds what they weigh. Whichever is reached first, the
//! least recently used entry is evicted. Both are configuration, because how
//! many ledgers a plane serves and how big their policy sets are is a
//! deployment's fact, not ours.
//!
//! The cache's tenant is the zone. `authz.cache.zone_partitions` and
//! `authz.cache.zone_bytes` bound each zone — by default a quarter of the whole
//! — and a zone over its bound evicts its **own** least recently used entries
//! first, never another zone's: one zone with a large or churning policy set
//! cannot empty the cache for every other. Only the whole cache's bound evicts
//! across zones.
//!
//! # The runtime is part of the key
//!
//! A partition's key names the descriptor digest of the runtime that compiled it
//! (`permguard_languages::descriptor`), so a build with another engine, another
//! feature or another limit compiles anew rather than serving a program compiled
//! by a different one.

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

/// One thing the cache holds, when it was last wanted, and the zone it is charged to — a
/// compiled partition's; a ledger head is not a partition and is charged to none.
struct Entry {
    held: Held,
    used: u64,
    zone: Option<String>,
}

/// The bounded, shared store of compiled programs.
pub struct Cache {
    max_entries: usize,
    max_bytes: u64,
    zone_entries: usize,
    zone_bytes: u64,
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
    /// What each zone holds: entries and bytes.
    zones: HashMap<String, (usize, u64)>,
}

impl Inner {
    /// Drops one entry and every count it was part of.
    fn drop_entry(&mut self, key: &str) -> bool {
        let Some(dropped) = self.entries.remove(key) else {
            return false;
        };
        let footprint = dropped.held.footprint() as u64;
        self.bytes = self.bytes.saturating_sub(footprint);
        if let Some(zone) = &dropped.zone
            && let Some((entries, bytes)) = self.zones.get_mut(zone)
        {
            *entries = entries.saturating_sub(1);
            *bytes = bytes.saturating_sub(footprint);
            if *entries == 0 {
                self.zones.remove(zone);
            }
        }
        true
    }

    /// The least recently used entry, among those `only` admits.
    fn oldest(&self, only: impl Fn(&Entry) -> bool) -> Option<String> {
        self.entries
            .iter()
            .filter(|(_, entry)| only(entry))
            .min_by_key(|(_, entry)| entry.used)
            .map(|(key, _)| key.clone())
    }
}

impl Cache {
    /// A cache with the deployment's two bounds, and no zone bound tighter than them.
    pub fn new(max_entries: usize, max_bytes: u64) -> Self {
        Self {
            max_entries: max_entries.max(1),
            max_bytes: max_bytes.max(1),
            zone_entries: max_entries.max(1),
            zone_bytes: max_bytes.max(1),
            inner: Mutex::new(Inner::default()),
            clock: AtomicU64::new(0),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            evictions: AtomicU64::new(0),
        }
    }

    /// The same cache, with each zone bounded to `entries` and `bytes` of it.
    #[must_use]
    pub fn with_zone_bounds(mut self, entries: usize, bytes: u64) -> Self {
        self.zone_entries = entries.clamp(1, self.max_entries);
        self.zone_bytes = bytes.clamp(1, self.max_bytes);
        self
    }

    /// The key of a ledger's head at a commit.
    pub fn head_key(zone_id: &str, ledger_id: &str, commit: &str) -> String {
        format!("{zone_id}/{ledger_id}@{commit}")
    }

    /// The key of one compiled partition of that commit, compiled by the runtime whose descriptor
    /// digest is `descriptor`.
    pub fn partition_key(
        zone_id: &str,
        ledger_id: &str,
        commit: &str,
        partition: &str,
        descriptor: &str,
    ) -> String {
        format!("{zone_id}/{ledger_id}@{commit}#{partition}~{descriptor}")
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
    ///
    /// A head is not a partition: it counts against the whole cache, never against its zone's
    /// partition bound.
    pub fn keep_head(&self, key: String, head: Arc<Head>) {
        self.keep(key, None, Held::Head(head));
    }

    /// Keeps a compiled partition, charged to its zone.
    pub fn keep_partition(&self, key: String, zone: &str, partition: Arc<Partition>) {
        self.keep(key, Some(zone), Held::Partition(partition));
    }

    /// How many entries and how many bytes one zone holds.
    pub fn zone_holdings(&self, zone: &str) -> (usize, u64) {
        match self.inner.lock() {
            Ok(inner) => inner.zones.get(zone).copied().unwrap_or_default(),
            Err(_) => (0, 0),
        }
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

    fn keep(&self, key: String, zone: Option<&str>, held: Held) {
        let Ok(mut inner) = self.inner.lock() else {
            // Nothing is cached, everything still works — slower. That is the
            // right failure for a cache.
            return;
        };
        let now = self.clock.fetch_add(1, Ordering::Relaxed);
        let footprint = held.footprint() as u64;
        inner.drop_entry(&key);
        inner.entries.insert(
            key,
            Entry {
                held,
                used: now,
                zone: zone.map(ToOwned::to_owned),
            },
        );
        inner.bytes = inner.bytes.saturating_add(footprint);
        if let Some(zone) = zone {
            let usage = inner.zones.entry(zone.to_owned()).or_default();
            usage.0 += 1;
            usage.1 = usage.1.saturating_add(footprint);
        }

        // The zone first, and only the zone's own entries: one zone over its bound
        // never makes room by evicting another's. Never to nothing: one entry
        // heavier than the whole bound is still better held than recompiled on
        // every request, and a cache that empties itself would thrash instead of
        // degrading.
        while let Some(zone) = zone {
            let (entries, bytes) = inner.zones.get(zone).copied().unwrap_or_default();
            if entries <= self.zone_entries && (bytes <= self.zone_bytes || entries <= 1) {
                break;
            }
            let Some(oldest) = inner.oldest(|entry| entry.zone.as_deref() == Some(zone)) else {
                break;
            };
            if inner.drop_entry(&oldest) {
                self.evictions.fetch_add(1, Ordering::Relaxed);
            }
        }
        // Then the whole cache, least recently used first, whichever zone.
        while inner.entries.len() > self.max_entries
            || (inner.bytes > self.max_bytes && inner.entries.len() > 1)
        {
            let Some(oldest) = inner.oldest(|_| true) else {
                break;
            };
            if inner.drop_entry(&oldest) {
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
            Arc::new(Nothing(footprint)),
        ))
    }

    #[test]
    fn what_was_kept_comes_back() {
        let cache = Cache::new(8, 1024 * 1024);
        let key = Cache::partition_key("z", "l", "sha256:abc", "app", "sha256:d");
        assert!(
            cache.partition(&key).is_none(),
            "a cold cache holds nothing"
        );

        cache.keep_partition(key.clone(), "z", partition("app", 128));
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
        let old = Cache::partition_key("z", "l", "sha256:old", "app", "sha256:d");
        let new = Cache::partition_key("z", "l", "sha256:new", "app", "sha256:d");

        cache.keep_partition(old.clone(), "z", partition("app", 64));
        assert!(
            cache.partition(&new).is_none(),
            "the new commit is simply not there yet"
        );
        cache.keep_partition(new.clone(), "z", partition("app", 64));
        assert!(cache.partition(&new).is_some());
    }

    #[test]
    fn the_entry_bound_evicts_the_least_recently_used() {
        let cache = Cache::new(2, 1024 * 1024);
        for name in ["a", "b"] {
            cache.keep_partition(
                Cache::partition_key("z", "l", "sha256:c", name, "sha256:d"),
                "z",
                partition(name, 16),
            );
        }
        // Touch `a`, so `b` becomes the oldest.
        assert!(
            cache
                .partition(&Cache::partition_key("z", "l", "sha256:c", "a", "sha256:d"))
                .is_some()
        );
        cache.keep_partition(
            Cache::partition_key("z", "l", "sha256:c", "c", "sha256:d"),
            "z",
            partition("c", 16),
        );

        assert!(
            cache
                .partition(&Cache::partition_key("z", "l", "sha256:c", "a", "sha256:d"))
                .is_some(),
            "the one that was wanted stays"
        );
        assert!(
            cache
                .partition(&Cache::partition_key("z", "l", "sha256:c", "b", "sha256:d"))
                .is_none(),
            "the one that was not, goes"
        );
        assert_eq!(cache.evictions.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn the_byte_bound_evicts_too() {
        let cache = Cache::new(100, 1_000);
        cache.keep_partition(
            Cache::partition_key("z", "l", "sha256:c", "big", "sha256:d"),
            "z",
            partition("big", 900),
        );
        cache.keep_partition(
            Cache::partition_key("z", "l", "sha256:c", "other", "sha256:d"),
            "z",
            partition("other", 900),
        );

        let (entries, bytes) = cache.holdings();
        assert_eq!(entries, 1, "two of those do not fit");
        assert!(bytes <= 1_000, "and the accounting says so: {bytes}");
    }

    /// A zone over its bound makes room from its own entries, never from another zone's.
    #[test]
    fn a_zone_over_its_bound_evicts_only_its_own() {
        let cache = Cache::new(8, 1024 * 1024).with_zone_bounds(2, 1024 * 1024);
        let key =
            |zone: &str, name: &str| Cache::partition_key(zone, "l", "sha256:c", name, "sha256:d");
        cache.keep_partition(key("quiet", "q"), "quiet", partition("q", 16));
        for name in ["a", "b", "c"] {
            cache.keep_partition(key("busy", name), "busy", partition(name, 16));
        }

        assert!(
            cache.partition(&key("quiet", "q")).is_some(),
            "the quiet zone keeps its entry"
        );
        assert!(
            cache.partition(&key("busy", "a")).is_none(),
            "the busy zone's oldest went"
        );
        assert!(cache.partition(&key("busy", "c")).is_some());
        assert_eq!(cache.zone_holdings("busy"), (2, 32));
        assert_eq!(cache.zone_holdings("quiet"), (1, 16));
    }

    /// The zone's byte bound works the same way, and one entry larger than it is still kept and
    /// charged to its zone.
    #[test]
    fn a_zone_byte_bound_evicts_its_own_and_keeps_one_oversized_entry() {
        let cache = Cache::new(8, 10_000).with_zone_bounds(8, 1_000);
        let key =
            |zone: &str, name: &str| Cache::partition_key(zone, "l", "sha256:c", name, "sha256:d");
        cache.keep_partition(key("other", "o"), "other", partition("o", 500));
        cache.keep_partition(key("heavy", "a"), "heavy", partition("a", 600));
        cache.keep_partition(key("heavy", "b"), "heavy", partition("b", 600));

        assert!(
            cache.partition(&key("heavy", "a")).is_none(),
            "two do not fit in the zone"
        );
        assert!(
            cache.partition(&key("other", "o")).is_some(),
            "and the other zone pays nothing"
        );

        cache.keep_partition(key("heavy", "huge"), "heavy", partition("huge", 5_000));
        assert!(
            cache.partition(&key("heavy", "huge")).is_some(),
            "better held than thrashed"
        );
        assert_eq!(cache.zone_holdings("heavy"), (1, 5_000));
    }

    /// A ledger head is not a partition: it is never charged to, nor evicted by, its zone's bound.
    #[test]
    fn a_ledger_head_is_not_counted_against_its_zone() {
        let cache = Cache::new(8, 1024 * 1024).with_zone_bounds(1, 1024 * 1024);
        let partition_key = Cache::partition_key("z", "l", "sha256:c", "app", "sha256:d");
        cache.keep_partition(partition_key.clone(), "z", partition("app", 16));
        cache.keep_head(
            Cache::head_key("z", "l", "sha256:c"),
            Arc::new(Head::for_test()),
        );

        assert!(
            cache.partition(&partition_key).is_some(),
            "the head did not evict it"
        );
        assert_eq!(
            cache.zone_holdings("z"),
            (1, 16),
            "only the partition is the zone's"
        );
        assert_eq!(cache.holdings().0, 2, "both count against the whole cache");
    }

    /// The runtime is part of the key: another descriptor is another program.
    #[test]
    fn another_runtime_descriptor_is_another_key() {
        let cache = Cache::new(8, 1024 * 1024);
        let ours = Cache::partition_key("z", "l", "sha256:c", "app", "sha256:engine-a");
        let theirs = Cache::partition_key("z", "l", "sha256:c", "app", "sha256:engine-b");
        cache.keep_partition(ours.clone(), "z", partition("app", 16));

        assert_ne!(ours, theirs);
        assert!(
            cache.partition(&theirs).is_none(),
            "nothing compiled by another engine is served"
        );
    }

    #[test]
    fn one_entry_larger_than_the_whole_bound_is_still_served() {
        // Better one thing held than a cache that thrashes on every request.
        let cache = Cache::new(4, 100);
        let key = Cache::partition_key("z", "l", "sha256:c", "huge", "sha256:d");
        cache.keep_partition(key.clone(), "z", partition("huge", 10_000));

        assert!(cache.partition(&key).is_some());
    }
}
