// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What a store accepts in clear: a record measured against `controlPlane.decisions.accept`.
//!
//! A producer decides what it records in clear; the store that keeps the records decides what it
//! is willing to hold. The store cannot trim a record that carries more, because the record is
//! digest-chained and its batch is signed, so a record beyond the ceiling refuses its batch. Every
//! ingest path asks the same question here, so the HTTP and gRPC ingest and the Host's coordinator
//! cannot disagree about what crossed.

use permguard_core::decisions::IncludeSection;
use serde_json::Value;

/// The first member `record` carries in clear beyond `ceiling`, named as `list.member`, or `None`
/// when everything it carries in clear is accepted.
///
/// Only a decision carries caller attributes in clear; a marker or a discontinuity never does. A
/// principal's properties have no list of their own, since no producer records them: any is
/// beyond the ceiling.
pub fn beyond(record: &Value, ceiling: &IncludeSection) -> Option<String> {
    if record.get("kind").and_then(Value::as_str) != Some("decision") {
        return None;
    }
    let members = |at: &str| {
        record
            .pointer(at)
            .and_then(Value::as_object)
            .map(|map| map.keys().cloned().collect::<Vec<_>>())
            .unwrap_or_default()
    };
    let lists: [(&str, &str, &[String]); 3] = [
        (
            "subject_properties",
            "/subject/properties",
            &ceiling.subject_properties,
        ),
        (
            "resource_properties",
            "/resource/properties",
            &ceiling.resource_properties,
        ),
        ("context", "/context", &ceiling.context),
    ];
    for (list, at, accepted) in lists {
        if let Some(member) = members(at)
            .into_iter()
            .find(|member| !IncludeSection::admits(accepted, member))
        {
            return Some(format!("{list}.{member}"));
        }
    }
    members("/principal/properties")
        .into_iter()
        .next()
        .map(|member| format!("principal_properties.{member}"))
}

/// Why a batch carrying `member` is refused, in the words both ingest paths answer with.
pub fn refusal(member: &str) -> String {
    format!(
        "a decision record carries `{member}` in clear, and this store does not accept it \
         (`controlPlane.decisions.accept`): the batch is refused whole, since a chained and \
         signed record cannot be trimmed; name it in the store's `accept`, or stop including \
         it in the producer's `dataPlane.decisions.log.include`"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ceiling(context: &[&str]) -> IncludeSection {
        IncludeSection {
            subject_properties: vec!["department".to_owned()],
            resource_properties: Vec::new(),
            context: context.iter().map(|name| (*name).to_owned()).collect(),
        }
    }

    fn decision(context: Value) -> Value {
        json!({
            "kind": "decision",
            "subject": {"type": "User", "id": "t", "properties": {"department": "ops"}},
            "resource": {"type": "Doc", "id": "d"},
            "context": context,
        })
    }

    #[test]
    fn a_record_within_the_ceiling_is_accepted() {
        let record = decision(json!({"mfa": true}));
        assert_eq!(beyond(&record, &ceiling(&["mfa", "amountCents"])), None);
    }

    #[test]
    fn a_member_beyond_the_ceiling_is_named() {
        let record = decision(json!({"mfa": true, "ip": "10.0.0.1"}));
        assert_eq!(
            beyond(&record, &ceiling(&["mfa"])).as_deref(),
            Some("context.ip")
        );
        let resource = json!({
            "kind": "decision",
            "subject": {"type": "User", "id": "t"},
            "resource": {"type": "Doc", "id": "d", "properties": {"owner": "x"}},
        });
        assert_eq!(
            beyond(&resource, &ceiling(&[])).as_deref(),
            Some("resource_properties.owner")
        );
    }

    #[test]
    fn every_member_is_accepted_under_the_star_and_none_under_an_empty_ceiling() {
        let record = decision(json!({"mfa": true, "ip": "10.0.0.1"}));
        assert_eq!(beyond(&record, &ceiling(&["*"])), None);
        assert_eq!(
            beyond(&record, &IncludeSection::default()).as_deref(),
            Some("subject_properties.department")
        );
    }

    #[test]
    fn a_principal_property_is_always_beyond_and_a_marker_never_is() {
        let mut record = decision(json!({}));
        record["principal"] = json!({"type": "Principal", "id": "p", "properties": {"x": 1}});
        assert_eq!(
            beyond(&record, &ceiling(&["*"])).as_deref(),
            Some("principal_properties.x")
        );
        let marker = json!({"kind": "marker", "context": {"anything": 1}});
        assert_eq!(beyond(&marker, &IncludeSection::default()), None);
    }
}
