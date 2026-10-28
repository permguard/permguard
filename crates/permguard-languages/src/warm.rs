// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The warm state of temporal partitions, bounded by bytes (DOGWOOD-02, LANG-09).
//!
//! A temporal partition keeps one engine per history, and each engine holds a lowered policy set
//! and the events it observed. Memory is then a function of how many histories callers create and
//! how much they record, so the bound is on bytes — per compiled partition, per zone (the tenant)
//! and per Host — never on a count of histories. Owner decision of 2026-10-21:
//! `dataPlane.events.warm.bytes`, `dataPlane.events.warm.zone_bytes` and
//! `dataPlane.events.warm.partition_bytes`.
//!
//! # Why eviction is safe
//!
//! The durable journal is the authority and a warm engine is disposable derived state: a history
//! evicted here is replayed from the journal before it decides again. Eviction costs a replay and
//! never changes a verdict.
//!
//! # One ledger of what is held, many owners
//!
//! The bytes are counted here, in one place, because a zone's bound and the Host's span every
//! partition: an owner charging its own history may push the zone over, and the coldest history of
//! the zone may belong to another partition. The budget therefore chooses victims across owners and
//! hands them back to the caller, which evicts them once every lock is released — an owner's lock
//! is never taken under the budget's, so two owners charging at once cannot deadlock.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex, Weak};

/// The Host's default bound on warm temporal state.
pub const DEFAULT_HOST_BYTES: u64 = permguard_core::config::DEFAULT_EVENTS_WARM_BYTES;

/// The default bound on one compiled partition's warm state.
pub const DEFAULT_PARTITION_BYTES: u64 =
    permguard_core::config::DEFAULT_EVENTS_WARM_PARTITION_BYTES;

/// The three bounds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Every warm history of the Host.
    pub host: u64,
    /// Every warm history of one zone.
    pub zone: u64,
    /// Every warm history of one compiled partition.
    pub partition: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            host: DEFAULT_HOST_BYTES,
            zone: DEFAULT_HOST_BYTES / 4,
            partition: DEFAULT_PARTITION_BYTES,
        }
    }
}

/// What a budget asks an owner to drop.
pub trait Evict: Send + Sync {
    /// Drops the warm engine of `history`, if this owner still holds one.
    fn evict(&self, history: &str);
}

/// One history an owner must drop, chosen by the budget.
pub struct Victim {
    owner: Weak<dyn Evict>,
    history: String,
}

impl Victim {
    /// Drops it. Called with no lock held.
    pub fn evict(self) {
        if let Some(owner) = self.owner.upgrade() {
            owner.evict(&self.history);
        }
    }
}

/// Evicts every victim; the caller holds no lock.
pub fn evict_all(victims: Vec<Victim>) {
    for victim in victims {
        victim.evict();
    }
}

/// One warm history, as the budget counts it.
struct Entry {
    owner: u64,
    zone: String,
    bytes: u64,
    /// Its place in the recency order.
    tick: u64,
}

#[derive(Default)]
struct Ledger {
    next_owner: u64,
    tick: u64,
    owners: HashMap<u64, (Weak<dyn Evict>, u64)>,
    entries: HashMap<(u64, String), Entry>,
    /// Least recently used first.
    order: BTreeMap<u64, (u64, String)>,
    zones: HashMap<String, u64>,
    host: u64,
}

impl Ledger {
    fn remove(&mut self, key: &(u64, String)) -> Option<Entry> {
        let entry = self.entries.remove(key)?;
        self.order.remove(&entry.tick);
        self.host = self.host.saturating_sub(entry.bytes);
        if let Some(zone) = self.zones.get_mut(&entry.zone) {
            *zone = zone.saturating_sub(entry.bytes);
            if *zone == 0 {
                self.zones.remove(&entry.zone);
            }
        }
        if let Some((_, held)) = self.owners.get_mut(&entry.owner) {
            *held = held.saturating_sub(entry.bytes);
        }

        Some(entry)
    }

    /// The coldest history other than `except` that `within` admits.
    fn coldest(
        &self,
        except: &(u64, String),
        within: impl Fn(&Entry) -> bool,
    ) -> Option<(u64, String)> {
        self.order
            .values()
            .filter(|key| *key != except)
            .find(|key| self.entries.get(*key).is_some_and(&within))
            .cloned()
    }
}

/// The bytes every warm temporal history of a Host holds, and the bounds they are held to.
pub struct Budget {
    limits: Limits,
    ledger: Mutex<Ledger>,
}

impl Budget {
    /// A budget under `limits`.
    pub fn new(limits: Limits) -> Arc<Self> {
        Arc::new(Self {
            limits,
            ledger: Mutex::new(Ledger::default()),
        })
    }

    /// The bounds.
    pub fn limits(&self) -> Limits {
        self.limits
    }

    /// Registers an owner of warm histories, and returns the id it charges under.
    pub fn register(&self, owner: Weak<dyn Evict>) -> u64 {
        let Ok(mut ledger) = self.ledger.lock() else {
            return u64::MAX;
        };
        ledger.next_owner += 1;
        let id = ledger.next_owner;
        ledger.owners.insert(id, (owner, 0));

        id
    }

    /// Forgets an owner and everything it held: a compiled partition the cache dropped.
    pub fn release(&self, owner: u64) {
        let Ok(mut ledger) = self.ledger.lock() else {
            return;
        };
        let keys: Vec<(u64, String)> = ledger
            .entries
            .keys()
            .filter(|(held, _)| *held == owner)
            .cloned()
            .collect();
        for key in keys {
            ledger.remove(&key);
        }
        ledger.owners.remove(&owner);
    }

    /// Forgets one history an owner dropped on its own.
    pub fn forget(&self, owner: u64, history: &str) {
        if let Ok(mut ledger) = self.ledger.lock() {
            ledger.remove(&(owner, history.to_owned()));
        }
    }

    /// Records that `owner` holds `bytes` for `history` in `zone`, as its most recently used, and
    /// returns the colder histories that must go for every bound to hold again.
    ///
    /// The history just charged is never its own victim: it is the one being decided against. A
    /// single history larger than a bound is therefore held while it is used, and is the first to
    /// go once anything else is charged; the replay plan bounds how large one can grow.
    ///
    /// A victim is evicted after this returns, so an owner re-charging it in between loses the
    /// engine it just used while this ledger no longer counts it: one spurious replay, never an
    /// undercount. A victim is found by scanning the recency order, linear in the warm histories
    /// held, which the byte bounds keep to thousands.
    pub fn charge(&self, owner: u64, zone: &str, history: &str, bytes: u64) -> Vec<Victim> {
        let Ok(mut ledger) = self.ledger.lock() else {
            return Vec::new();
        };
        let key = (owner, history.to_owned());
        ledger.remove(&key);
        ledger.tick += 1;
        let tick = ledger.tick;
        ledger.order.insert(tick, key.clone());
        ledger.entries.insert(
            key.clone(),
            Entry {
                owner,
                zone: zone.to_owned(),
                bytes,
                tick,
            },
        );
        ledger.host = ledger.host.saturating_add(bytes);
        *ledger.zones.entry(zone.to_owned()).or_default() += bytes;
        if let Some((_, held)) = ledger.owners.get_mut(&owner) {
            *held = held.saturating_add(bytes);
        }

        let mut victims = Vec::new();
        loop {
            let owner_held = ledger.owners.get(&owner).map_or(0, |(_, held)| *held);
            let zone_held = ledger.zones.get(zone).copied().unwrap_or(0);
            let victim = if owner_held > self.limits.partition {
                ledger.coldest(&key, |entry| entry.owner == owner)
            } else if zone_held > self.limits.zone {
                ledger.coldest(&key, |entry| entry.zone == zone)
            } else if ledger.host > self.limits.host {
                ledger.coldest(&key, |_| true)
            } else {
                None
            };
            let Some(victim) = victim else {
                break;
            };
            ledger.remove(&victim);
            if let Some((evictor, _)) = ledger.owners.get(&victim.0) {
                victims.push(Victim {
                    owner: evictor.clone(),
                    history: victim.1,
                });
            }
        }

        victims
    }

    /// The bytes held by the Host, by one zone, and by one owner.
    pub fn held(&self, zone: &str, owner: u64) -> (u64, u64, u64) {
        let Ok(ledger) = self.ledger.lock() else {
            return (0, 0, 0);
        };

        (
            ledger.host,
            ledger.zones.get(zone).copied().unwrap_or(0),
            ledger.owners.get(&owner).map_or(0, |(_, held)| *held),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An owner that records what it was asked to drop.
    #[derive(Default)]
    struct Recorder(Mutex<Vec<String>>);

    impl Evict for Recorder {
        fn evict(&self, history: &str) {
            self.0.lock().expect("the record").push(history.to_owned());
        }
    }

    fn owner(budget: &Budget) -> (Arc<Recorder>, u64) {
        let recorder = Arc::new(Recorder::default());
        let weak: Weak<dyn Evict> = Arc::downgrade(&recorder) as Weak<dyn Evict>;
        let id = budget.register(weak);
        (recorder, id)
    }

    fn evicted(recorder: &Recorder) -> Vec<String> {
        recorder.0.lock().expect("the record").clone()
    }

    #[test]
    fn a_partition_over_its_bound_drops_its_own_coldest_history() {
        let budget = Budget::new(Limits {
            host: 1000,
            zone: 1000,
            partition: 100,
        });
        let (first, a) = owner(&budget);
        let (second, b) = owner(&budget);
        evict_all(budget.charge(b, "acme", "other", 60));
        evict_all(budget.charge(a, "acme", "h1", 40));
        evict_all(budget.charge(a, "acme", "h2", 40));
        evict_all(budget.charge(a, "acme", "h3", 40));

        assert_eq!(evicted(&first), ["h1"], "its coldest, and only its own");
        assert!(evicted(&second).is_empty());
        assert_eq!(budget.held("acme", a), (140, 140, 80));
    }

    #[test]
    fn a_zone_over_its_bound_drops_its_coldest_history_whoever_holds_it() {
        let budget = Budget::new(Limits {
            host: 1000,
            zone: 100,
            partition: 1000,
        });
        let (first, a) = owner(&budget);
        let (second, b) = owner(&budget);
        let (third, c) = owner(&budget);
        evict_all(budget.charge(a, "acme", "h1", 50));
        evict_all(budget.charge(c, "other", "x", 500));
        evict_all(budget.charge(b, "acme", "h2", 40));
        evict_all(budget.charge(b, "acme", "h3", 40));

        assert_eq!(evicted(&first), ["h1"], "the zone's coldest");
        assert!(evicted(&second).is_empty());
        assert!(evicted(&third).is_empty(), "another zone is not touched");
        assert_eq!(budget.held("acme", b).1, 80);
    }

    #[test]
    fn the_host_over_its_bound_drops_its_coldest_history_in_any_zone() {
        let budget = Budget::new(Limits {
            host: 100,
            zone: 100,
            partition: 100,
        });
        let (first, a) = owner(&budget);
        let (_, b) = owner(&budget);
        evict_all(budget.charge(a, "acme", "h1", 60));
        evict_all(budget.charge(b, "other", "h2", 60));

        assert_eq!(evicted(&first), ["h1"]);
        assert_eq!(budget.held("other", b).0, 60);
    }

    #[test]
    fn using_a_history_makes_it_the_last_to_go_and_the_one_charged_never_goes() {
        let budget = Budget::new(Limits {
            host: 100,
            zone: 100,
            partition: 100,
        });
        let (first, a) = owner(&budget);
        evict_all(budget.charge(a, "acme", "h1", 40));
        evict_all(budget.charge(a, "acme", "h2", 40));
        // h1 used again: h2 is now the coldest.
        evict_all(budget.charge(a, "acme", "h1", 40));
        evict_all(budget.charge(a, "acme", "h3", 40));
        assert_eq!(evicted(&first), ["h2"]);

        // One history larger than every bound is held while it is the one charged.
        evict_all(budget.charge(a, "acme", "huge", 500));
        assert_eq!(evicted(&first), ["h2", "h1", "h3"]);
        assert_eq!(budget.held("acme", a), (500, 500, 500));
    }

    #[test]
    fn a_released_owner_and_a_forgotten_history_hold_nothing() {
        let budget = Budget::new(Limits::default());
        let (_, a) = owner(&budget);
        let (_, b) = owner(&budget);
        evict_all(budget.charge(a, "acme", "h1", 10));
        evict_all(budget.charge(a, "acme", "h2", 10));
        evict_all(budget.charge(b, "acme", "h1", 5));
        budget.forget(a, "h2");
        assert_eq!(budget.held("acme", a), (15, 15, 10));
        budget.release(a);
        assert_eq!(budget.held("acme", a), (5, 5, 0));
    }
}
