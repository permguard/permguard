// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! A JSON document whose objects never repeat a member name (BUG-0055, DEC-0004 option B).
//!
//! `serde_json` keeps the last of two members with one name, in a `Value` and in every open map a
//! request carries (`context`, `properties`, `partition_inputs`, a partition's `data`): a document
//! naming `"role"` twice is decided on whichever came last, and two readers of the same bytes can
//! disagree on what was asked. Such a document is refused before it is read, naming the path.

use std::collections::HashSet;
use std::fmt;

use serde::de::{DeserializeSeed, Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor};

/// The path of the first member name `text` repeats inside one object, as `subject.properties.role`
/// or `evaluations[1].context.role`; `None` when no object repeats one. A document that is not
/// JSON is not this check's to judge, and answers `None`: the reader that follows refuses it with
/// its own message.
pub fn repeated_member(text: &str) -> Option<String> {
    let mut found = None;
    let mut deserializer = serde_json::Deserializer::from_str(text);
    let walked = Walk {
        path: String::new(),
        found: &mut found,
    }
    .deserialize(&mut deserializer);
    match walked {
        Ok(()) => None,
        Err(_) => found,
    }
}

/// One value at `path`, recording the first repeated member it holds into `found`.
struct Walk<'a> {
    path: String,
    found: &'a mut Option<String>,
}

/// The error a walk stops on once it found a repeated member.
#[derive(Debug)]
struct Stop;

impl<'de> DeserializeSeed<'de> for Walk<'_> {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Walk<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value")
    }

    fn visit_bool<E>(self, _: bool) -> Result<(), E> {
        Ok(())
    }
    fn visit_i64<E>(self, _: i64) -> Result<(), E> {
        Ok(())
    }
    fn visit_u64<E>(self, _: u64) -> Result<(), E> {
        Ok(())
    }
    fn visit_f64<E>(self, _: f64) -> Result<(), E> {
        Ok(())
    }
    fn visit_str<E>(self, _: &str) -> Result<(), E> {
        Ok(())
    }
    fn visit_unit<E>(self) -> Result<(), E> {
        Ok(())
    }
    fn visit_none<E>(self) -> Result<(), E> {
        Ok(())
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        let mut index = 0;
        loop {
            let path = format!("{}[{index}]", self.path);
            let walk = Walk {
                path,
                found: &mut *self.found,
            };
            if seq.next_element_seed(walk)?.is_none() {
                return Ok(());
            }
            index += 1;
        }
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let mut seen = HashSet::new();
        while let Some(name) = map.next_key::<String>()? {
            let path = if self.path.is_empty() {
                name.clone()
            } else {
                format!("{}.{name}", self.path)
            };
            if !seen.insert(name) {
                *self.found = Some(path);
                // Stopping is the fastest way out: the rest of the document is not read.
                map.next_value::<IgnoredAny>()?;
                return Err(serde::de::Error::custom(Stop));
            }
            map.next_value_seed(Walk {
                path,
                found: &mut *self.found,
            })?;
        }
        Ok(())
    }
}

impl fmt::Display for Stop {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a member name is repeated")
    }
}

#[cfg(test)]
mod tests {
    use super::repeated_member;

    #[test]
    fn a_repeated_member_is_found_at_any_depth_and_named_by_its_path() {
        for (text, path) in [
            (r#"{"a": 1, "a": 2}"#, "a"),
            (
                r#"{"subject": {"type": "u", "id": "a", "id": "b"}}"#,
                "subject.id",
            ),
            (
                r#"{"subject": {"properties": {"role": "x", "role": "admin"}}}"#,
                "subject.properties.role",
            ),
            (
                r#"{"evaluations": [{}, {"context": {"k": 1, "k": 1}}]}"#,
                "evaluations[1].context.k",
            ),
            (
                r#"{"partition_inputs": {"p": {"data": [{"uid": 1, "uid": 2}]}}}"#,
                "partition_inputs.p.data[0].uid",
            ),
        ] {
            assert_eq!(repeated_member(text).as_deref(), Some(path), "{text}");
        }
    }

    #[test]
    fn a_document_without_repeats_or_not_json_answers_none() {
        assert_eq!(
            repeated_member(r#"{"a": {"a": 1}, "b": [{"a": 1}, {"a": 2}]}"#),
            None,
            "one name in different objects is not a repeat"
        );
        assert_eq!(repeated_member("{not json"), None);
        assert_eq!(repeated_member("[]"), None);
    }
}
