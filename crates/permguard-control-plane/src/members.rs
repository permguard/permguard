// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The members a read names (owner decision of 2026-11-15). A decision's `stream.id` and an
//! event's `stream.producer.id` are the Host id of the data plane that answered: the identity the
//! record was signed under, global and stable. The member id and the name are the Control Plane's
//! to know, bound to that Host id at the first approval, so the page carries them beside its
//! records and outside them, `members`: each Host id of the page a membership of this Host names,
//! to the member's id and name. The record is untouched: what the producer signed is what every
//! reader verifies, and a reader with no members list of its own still names the plane.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

pub use permguard_host::composition::MemberName;
use permguard_host::composition::Registration;
use permguard_host::membership::record::TaskType;
use serde_json::Value;

/// Names the member a Host id belongs to.
pub trait NamesMembers: Send + Sync {
    /// The member whose Host id is `host_id`; `None` for one no membership names.
    fn member_named(&self, host_id: &[u8; 16]) -> Option<MemberName>;
}

/// The Host's registration, naming the members this Plane coordinates under `task`.
pub struct Registered {
    pub registration: Arc<Registration>,
    pub task: TaskType,
}

impl NamesMembers for Registered {
    fn member_named(&self, host_id: &[u8; 16]) -> Option<MemberName> {
        self.registration.member_named(self.task, host_id)
    }
}

/// The Host id a decision record carries: its `stream.id`.
pub fn decision_host(record: &Value) -> Option<&str> {
    record.get("stream")?.get("id")?.as_str()
}

/// The Host id an event record carries: its `stream.producer.id`.
pub fn event_host(record: &Value) -> Option<&str> {
    record.get("stream")?.get("producer")?.get("id")?.as_str()
}

/// A Host id as a record writes it, 32 lowercase hex digits, as bytes.
fn host_id_of(text: &str) -> Option<[u8; 16]> {
    if text.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 16];
    for (index, pair) in text.as_bytes().chunks(2).enumerate() {
        bytes[index] = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(bytes)
}

/// The `members` of a page: every distinct Host id of `records`, as `host_of` reads it, that
/// `names` names; one lookup per Host id, none without a namer.
pub fn members_of<'a>(
    records: impl IntoIterator<Item = &'a Value>,
    host_of: fn(&Value) -> Option<&str>,
    names: Option<&dyn NamesMembers>,
) -> BTreeMap<String, MemberName> {
    let mut members = BTreeMap::new();
    let Some(names) = names else {
        return members;
    };
    let mut unnamed = BTreeSet::new();
    for record in records {
        let Some(host_id) = host_of(record) else {
            continue;
        };
        if members.contains_key(host_id) || unnamed.contains(host_id) {
            continue;
        }
        match host_id_of(host_id).and_then(|bytes| names.member_named(&bytes)) {
            Some(member) => {
                members.insert(host_id.to_owned(), member);
            }
            None => {
                unnamed.insert(host_id.to_owned());
            }
        }
    }
    members
}

/// The page as JSON, `members` beside its block when any is named.
pub fn with_members<T: serde::Serialize>(page: &T, members: BTreeMap<String, MemberName>) -> Value {
    let mut view = serde_json::to_value(page).unwrap_or(Value::Null);
    if !members.is_empty()
        && let Some(object) = view.as_object_mut()
    {
        object.insert(
            "members".to_owned(),
            serde_json::to_value(members).unwrap_or(Value::Null),
        );
    }
    view
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Names one Host id, and counts the lookups.
    struct One(std::sync::Mutex<usize>);

    impl NamesMembers for One {
        fn member_named(&self, host_id: &[u8; 16]) -> Option<MemberName> {
            *self.0.lock().expect("lock") += 1;
            (host_id[0] == 0xab).then(|| MemberName {
                member_id: "01a1b9de-8738-736e-9fff-609509b3fcbb".to_owned(),
                name: "lab-a".to_owned(),
            })
        }
    }

    #[test]
    fn a_page_names_each_host_id_once_and_only_the_named_ones() {
        let named = "ab".repeat(16);
        let other = "cd".repeat(16);
        let records = [
            json!({"stream": {"id": named}, "seq": 1}),
            json!({"stream": {"id": named}, "seq": 2}),
            json!({"stream": {"id": other}, "seq": 3}),
            json!({"stream": {"id": other}, "seq": 4}),
            json!({"stream": {"id": "not-a-host-id"}, "seq": 5}),
            json!({"seq": 6}),
        ];
        let names = One(std::sync::Mutex::new(0));
        let members = members_of(records.iter(), decision_host, Some(&names));
        assert_eq!(members.len(), 1);
        assert_eq!(members[&named].name, "lab-a");
        assert_eq!(*names.0.lock().expect("lock"), 2, "one lookup per Host id");
        assert!(members_of(records.iter(), decision_host, None).is_empty());
    }

    #[test]
    fn an_event_names_its_producer_and_the_page_carries_the_members_beside_its_block() {
        let named = "ab".repeat(16);
        let records = [json!({"stream": {"producer": {"id": named, "instance": "run"}}})];
        let names = One(std::sync::Mutex::new(0));
        let members = members_of(records.iter(), event_host, Some(&names));
        let page = json!({"records": records, "next": "n", "more": false});
        let view = with_members(&page, members);
        assert_eq!(
            view["members"][&named]["member_id"],
            "01a1b9de-8738-736e-9fff-609509b3fcbb"
        );
        assert_eq!(view["members"][&named]["name"], "lab-a");
        assert_eq!(view["next"], "n");
        let bare = with_members(&page, BTreeMap::new());
        assert!(
            bare.get("members").is_none(),
            "no member named, no key: {bare}"
        );
    }

    #[test]
    fn a_host_id_reads_as_32_hex_digits_and_nothing_else() {
        assert_eq!(host_id_of(&"ab".repeat(16)), Some([0xab; 16]));
        assert_eq!(host_id_of("ab"), None);
        assert_eq!(host_id_of(&"zz".repeat(16)), None);
    }
}
