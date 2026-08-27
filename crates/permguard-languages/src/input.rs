// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The partition input registry: what a request may hand a partition, and who reads it.
//!
//! # Why this is a registry and not a field
//!
//! A request carries data a partition reads — a Cedar entity store, a Rego document. What that
//! data *is* decides which parser runs over it, which schema validates it, and which runtime is
//! handed the result. If the caller named that, the caller would be choosing the parser for bytes
//! it also supplies, and "send Cedar entities as a Rego document" would be one field away.
//!
//! So the catalogue is **fixed at build time**, exactly like the languages themselves:
//!
//! | Type | Runtime | `data` | Where it arrives |
//! | --- | --- | --- | --- |
//! | `permguard.cedar.entities.v1` | Cedar | an array of Cedar entity JSON | the entity store |
//! | `permguard.rego.data.v1` | Rego | a JSON object | `input.partition` |
//!
//! A ledger's manifest declares which of these each partition accepts. A request's own `type` is
//! an **assertion**, checked against the manifest's — never a selector. `acme.anything.v1` is not
//! a type anybody can invent: it is refused at the manifest, and refused again in the request.
//!
//! # What "addressed to a partition" means
//!
//! By name, and only by name. There is no broadcast by runtime: two Cedar partitions with
//! different schemas hold different worlds, and a graph legal in one is refused by the other. A
//! partition nobody addressed reads its type's **empty** input — an empty entity store, an empty
//! document — never another partition's.

use std::collections::BTreeMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// The registered name of the Cedar entity store input.
pub const CEDAR_ENTITIES_V1: &str = "permguard.cedar.entities.v1";
/// The registered name of the Rego document input.
pub const REGO_DATA_V1: &str = "permguard.rego.data.v1";

/// One partition input, as the wire carries it.
///
/// `type` is stated even though the manifest already fixes it, and that is deliberate: a caller
/// that believes it is addressing a Cedar partition and is in fact addressing a Rego one should
/// hear so, rather than have its entity array quietly refused as a malformed document. The
/// assertion is checked, never obeyed.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct PartitionInputBody {
    #[serde(rename = "type", default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub data: Option<Value>,
}

/// One partition's input, normalised into what its runtime actually reads.
///
/// Behind an [`Arc`] because a boxcarred batch materialises the same input once per evaluation and
/// a profile hands it to one partition: the graph is read many times and copied never.
#[derive(Debug, Clone, Default)]
pub enum PartitionData {
    /// The partition declares no input contract, so nothing was addressed to it.
    #[default]
    Absent,
    /// A Cedar entity store, in Cedar's own JSON shape.
    CedarEntities(Arc<Vec<Value>>),
    /// A Rego document, exposed as `input.partition`.
    RegoData(Arc<Map<String, Value>>),
}

impl PartitionData {
    /// The Cedar entity store this partition was given: empty when it was given nothing.
    ///
    /// A Rego document reaching here is not silently read as an empty graph — it cannot reach
    /// here: routing checks the type against the partition's runtime before anything is
    /// materialised. Empty is what *absent* means, and only that.
    pub fn cedar_entities(&self) -> &[Value] {
        match self {
            Self::CedarEntities(items) => items,
            _ => &[],
        }
    }

    /// The Rego document this partition was given, when it was given one.
    pub fn rego_data(&self) -> Option<&Map<String, Value>> {
        match self {
            Self::RegoData(data) => Some(data),
            _ => None,
        }
    }
}

/// One registered input type: what it is called, who reads it, and what shape it accepts.
pub trait InputType: Send + Sync {
    /// The registered name, version included — `permguard.cedar.entities.v1`.
    fn name(&self) -> &'static str;

    /// The version this build implements. Encoded in the name too, because a name is what a
    /// manifest and a request state, and a number nobody writes down drifts.
    fn version(&self) -> u32;

    /// The language of the runtime that can read this input.
    fn runtime(&self) -> &'static str;

    /// The JSON shape this type accepts, turned into what the runtime reads.
    ///
    /// Every refusal here is about *shape* — an array where an object belongs — and never about
    /// content: what the content must be is the partition's schema, checked once the input is
    /// materialised.
    fn normalize(&self, data: &Value) -> Result<PartitionData, String>;

    /// What a partition of this type reads when no request addressed it.
    fn empty(&self) -> PartitionData;
}

/// The Cedar entity store.
struct CedarEntitiesV1;

impl InputType for CedarEntitiesV1 {
    fn name(&self) -> &'static str {
        CEDAR_ENTITIES_V1
    }

    fn version(&self) -> u32 {
        1
    }

    fn runtime(&self) -> &'static str {
        crate::cedar::NAME
    }

    fn normalize(&self, data: &Value) -> Result<PartitionData, String> {
        let Value::Array(items) = data else {
            return Err(format!(
                "`{CEDAR_ENTITIES_V1}` carries an array of Cedar entities, and `data` is {}",
                shape(data)
            ));
        };
        if items.len() > MAX_CEDAR_ENTITIES {
            return Err(format!(
                "the entity store holds {} entities and this plane accepts {MAX_CEDAR_ENTITIES}",
                items.len()
            ));
        }
        // Entity types are not input types: `User`, `Team` and `Service` live side by side in one
        // store, and Cedar's own schema is what says which of them are legal.
        for (index, item) in items.iter().enumerate() {
            if !item.is_object() {
                return Err(format!(
                    "entity {index} is {}, and a Cedar entity is an object with `uid`",
                    shape(item)
                ));
            }
        }

        Ok(PartitionData::CedarEntities(Arc::new(items.clone())))
    }

    fn empty(&self) -> PartitionData {
        PartitionData::CedarEntities(Arc::new(Vec::new()))
    }
}

/// The Rego document.
struct RegoDataV1;

impl InputType for RegoDataV1 {
    fn name(&self) -> &'static str {
        REGO_DATA_V1
    }

    fn version(&self) -> u32 {
        1
    }

    fn runtime(&self) -> &'static str {
        crate::rego::NAME
    }

    fn normalize(&self, data: &Value) -> Result<PartitionData, String> {
        let Value::Object(document) = data else {
            return Err(format!(
                "`{REGO_DATA_V1}` carries a JSON object, and `data` is {}",
                shape(data)
            ));
        };

        Ok(PartitionData::RegoData(Arc::new(document.clone())))
    }

    fn empty(&self) -> PartitionData {
        PartitionData::RegoData(Arc::new(Map::new()))
    }
}

/// Every input type this build implements, in a fixed order.
pub fn input_types() -> &'static [&'static dyn InputType] {
    const CEDAR: &CedarEntitiesV1 = &CedarEntitiesV1;
    const REGO: &RegoDataV1 = &RegoDataV1;

    &[CEDAR, REGO]
}

/// The input type of that name, when this build implements one.
pub fn input_type(name: &str) -> Option<&'static dyn InputType> {
    input_types()
        .iter()
        .copied()
        .find(|held| held.name() == name)
}

/// What this build offers the manifest's input gate.
pub fn provided_input_types() -> Vec<permguard_objects::manifest::ProvidedInputType> {
    input_types()
        .iter()
        .map(|held| permguard_objects::manifest::ProvidedInputType {
            name: held.name().to_owned(),
            language: held.runtime().to_owned(),
        })
        .collect()
}

/// The names of every registered type, for a message that has to list them.
pub fn registered() -> String {
    input_types()
        .iter()
        .map(|held| held.name())
        .collect::<Vec<&str>>()
        .join(", ")
}

/// How many partitions one request may address.
///
/// A profile holds a handful; a request naming hundreds is not addressing partitions, it is
/// making a plane allocate. Bounded before any of them is looked at.
pub const MAX_PARTITION_INPUTS: usize = 32;

/// How deep one input's JSON may nest.
///
/// Matches the object model's own bound on decoded values, so an input that would be refused when
/// stored is refused when sent. Recursion over caller-supplied JSON is the classic way to end a
/// process without ever reaching a policy.
pub const MAX_INPUT_DEPTH: usize = 64;

/// How many JSON nodes one input may hold, counting every value at every level.
pub const MAX_INPUT_NODES: usize = 200_000;

/// How many entities one Cedar store may hold.
pub const MAX_CEDAR_ENTITIES: usize = 20_000;

/// Checks one input's size and depth, before its type ever looks at it.
///
/// Applied to every type from one place: a bound each implementation had to remember is a bound
/// one of them will forget, and the shape of the refusal would differ between them.
pub fn within_limits(data: &Value) -> Result<(), String> {
    let mut nodes = 0usize;
    measure(data, 1, &mut nodes)
}

fn measure(value: &Value, depth: usize, nodes: &mut usize) -> Result<(), String> {
    *nodes += 1;
    if *nodes > MAX_INPUT_NODES {
        return Err(format!(
            "the input holds more than {MAX_INPUT_NODES} JSON values"
        ));
    }
    if depth > MAX_INPUT_DEPTH {
        return Err(format!("the input nests deeper than {MAX_INPUT_DEPTH}"));
    }
    match value {
        Value::Array(items) => {
            for item in items {
                measure(item, depth + 1, nodes)?;
            }
        }
        Value::Object(fields) => {
            for held in fields.values() {
                measure(held, depth + 1, nodes)?;
            }
        }
        _ => {}
    }

    Ok(())
}

/// What a JSON value is, in the words an error message uses.
fn shape(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Array(_) => "an array",
        Value::Object(_) => "an object",
    }
}

/// The inputs of one request, by partition name.
pub type PartitionInputs = BTreeMap<String, PartitionInputBody>;

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use serde_json::json;

    #[test]
    fn a_type_nobody_registered_is_not_a_type() {
        assert!(input_type("acme.whatever.v1").is_none());
        assert!(input_type(CEDAR_ENTITIES_V1).is_some());
        assert!(input_type(REGO_DATA_V1).is_some());
    }

    #[test]
    fn each_type_is_written_for_exactly_one_runtime() {
        let cedar = input_type(CEDAR_ENTITIES_V1).expect("registered");
        let rego = input_type(REGO_DATA_V1).expect("registered");

        assert_eq!(cedar.runtime(), "cedar");
        assert_eq!(rego.runtime(), "rego");
        assert_ne!(cedar.runtime(), rego.runtime());
    }

    #[test]
    fn cedar_carries_an_array_and_rego_an_object() {
        let cedar = input_type(CEDAR_ENTITIES_V1).expect("registered");
        let rego = input_type(REGO_DATA_V1).expect("registered");

        assert!(cedar.normalize(&json!([])).is_ok());
        assert!(
            cedar.normalize(&json!({})).is_err(),
            "an object is not a store"
        );
        assert!(rego.normalize(&json!({})).is_ok());
        assert!(
            rego.normalize(&json!([])).is_err(),
            "an array is not a document"
        );
    }

    #[test]
    fn an_empty_input_is_the_types_own_empty_and_not_another_types() {
        let cedar = input_type(CEDAR_ENTITIES_V1).expect("registered");
        let rego = input_type(REGO_DATA_V1).expect("registered");

        assert!(cedar.empty().cedar_entities().is_empty());
        assert!(cedar.empty().rego_data().is_none());
        assert!(rego.empty().rego_data().expect("a document").is_empty());
        assert!(rego.empty().cedar_entities().is_empty());
    }

    #[test]
    fn a_cedar_entity_that_is_not_an_object_is_refused_by_position() {
        let cedar = input_type(CEDAR_ENTITIES_V1).expect("registered");
        let refused = cedar
            .normalize(&json!([{"uid": {"type": "User", "id": "alice"}}, 7]))
            .expect_err("7 is not an entity");

        assert!(refused.contains("entity 1"), "{refused}");
    }

    #[test]
    fn an_input_nested_beyond_the_bound_is_refused_rather_than_recursed_into() {
        let mut deep = json!(1);
        for _ in 0..(MAX_INPUT_DEPTH + 4) {
            deep = json!([deep]);
        }

        assert!(within_limits(&deep).is_err(), "the bound bites");
        assert!(within_limits(&json!({"a": [1, 2, {"b": true}]})).is_ok());
    }

    #[test]
    fn a_store_beyond_the_entity_bound_is_refused() {
        let cedar = input_type(CEDAR_ENTITIES_V1).expect("registered");
        let items: Vec<Value> = (0..=MAX_CEDAR_ENTITIES)
            .map(|n| json!({"uid": {"type": "User", "id": n.to_string()}}))
            .collect();

        assert!(cedar.normalize(&Value::Array(items)).is_err());
    }
}
