// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The event's version 2: one canonical field map, projected by the server (DOGWOOD-05, LANG-10).
//!
//! ```text
//! canonical fields ──▶ event-schema logged projection
//!                  └─▶ action-schema request-context projection
//! ```
//!
//! Version 1 asks the caller for the two projections, `logged` and `request_context`, and can only
//! compare the fields both carry: a field sent on one side is accepted whether or not its author
//! meant it to be. Version 2 takes one map and builds both, per action and kind (owner decisions
//! of 2026-10-21):
//!
//! - a leaf that kind's event and the action's context both declare is copied to both, so a caller
//!   can neither send two values for it nor leave one out;
//! - a leaf only one side declares is admitted only where `projections.json` declares it on that
//!   side — `history_only` or `request_only` — and the load is refused otherwise, so one-sidedness
//!   is a choice the author wrote down. A declaration licenses one-sidedness where it occurs and
//!   never stops the copy where a field is shared: `output` is one-sided in a `request` and shared
//!   in a `response` of upstream's default schema;
//! - a pin is never a field: the server derives it, as in version 1;
//! - a key of `fields` neither side declares is refused.

use std::collections::{BTreeMap, BTreeSet};

use dogwood_language::Value as DogwoodValue;
use serde::Deserialize;

use crate::temporal::Signature;

/// A dotted path, by segment.
pub type Path = Vec<String>;

/// One projection of an occurrence: `logged` or `request_context`.
pub type Bag = BTreeMap<String, DogwoodValue>;

/// The one-sided fields a partition's author declared: `projections.json`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Projections {
    pub history_only: Vec<Path>,
    pub request_only: Vec<Path>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectionsBody {
    #[serde(default)]
    history_only: Vec<String>,
    #[serde(default)]
    request_only: Vec<String>,
}

impl Projections {
    /// Reads `projections.json`: closed, every path non-empty and dotted, none repeated.
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        let value: serde_json::Value = serde_json::from_slice(bytes)
            .map_err(|error| format!("dogwood: `projections.json` does not read: {error}"))?;
        // An object and nothing else: serde would read a struct from an array too.
        if !value.is_object() {
            return Err("dogwood: `projections.json` is an object".to_owned());
        }
        let body: ProjectionsBody = serde_json::from_value(value)
            .map_err(|error| format!("dogwood: `projections.json` does not read: {error}"))?;
        let mut seen = BTreeSet::new();
        let mut paths = |side: &str, written: Vec<String>| -> Result<Vec<Path>, String> {
            written
                .into_iter()
                .map(|text| {
                    let path: Path = text.split('.').map(str::to_owned).collect();
                    // A Cedar attribute may be any string, so a segment is anything but empty.
                    if path.iter().any(String::is_empty) {
                        return Err(format!(
                            "dogwood: `projections.json` names `{text}` under `{side}`, which is \
                             not a dotted field path"
                        ));
                    }
                    if !seen.insert(path.clone()) {
                        return Err(format!(
                            "dogwood: `projections.json` names `{text}` twice: a field is one-sided \
                             on one side or the other, once"
                        ));
                    }
                    Ok(path)
                })
                .collect()
        };

        Ok(Self {
            history_only: paths("history_only", body.history_only)?,
            request_only: paths("request_only", body.request_only)?,
        })
    }
}

/// One side of a projection: its leaves, and its groups — every record, an empty one included,
/// which a caller may send as `{}` though it holds no leaf.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Side {
    pub leaves: BTreeSet<Path>,
    pub groups: BTreeSet<Path>,
}

impl Side {
    /// The event side of one kind: its leaves, and the groups above them.
    pub fn of_event(leaves: BTreeSet<Path>) -> Self {
        let groups = leaves
            .iter()
            .flat_map(|leaf| (1..leaf.len()).map(|end| leaf[..end].to_vec()))
            .collect();
        Self { leaves, groups }
    }

    /// Whether `path` is a leaf or a group of this side.
    fn has(&self, path: &Path) -> bool {
        self.leaves.contains(path) || self.groups.contains(path)
    }
}

/// The context of each action, by qualified action, read from the Cedar action schema through
/// Cedar's own parser, common types resolved.
pub fn context_leaves(action_schema: &str) -> Result<BTreeMap<String, Side>, String> {
    let (fragment, _) = cedar_policy::SchemaFragment::from_cedarschema_str(action_schema)
        .map_err(|error| format!("dogwood: the action schema is not usable: {error}"))?;
    let json = fragment
        .to_json_value()
        .map_err(|error| format!("dogwood: the action schema does not render: {error}"))?;
    let namespaces = json
        .as_object()
        .ok_or("dogwood: the action schema renders as no namespaces")?;

    // Keyed by qualified name, with the namespace each was declared in: an unqualified reference
    // resolves in the namespace it is written in, then in the empty one, as Cedar resolves it.
    let mut common: Common = BTreeMap::new();
    for (namespace, body) in namespaces {
        if let Some(types) = body
            .get("commonTypes")
            .and_then(serde_json::Value::as_object)
        {
            for (name, definition) in types {
                common.insert(
                    qualified(namespace, name),
                    (namespace.clone(), definition.clone()),
                );
            }
        }
    }

    let mut leaves = BTreeMap::new();
    for (namespace, body) in namespaces {
        let Some(actions) = body.get("actions").and_then(serde_json::Value::as_object) else {
            continue;
        };
        for (action, definition) in actions {
            let mut held = Side::default();
            if let Some(context) = definition.get("appliesTo").and_then(|to| to.get("context")) {
                collect(context, namespace, &common, &mut Vec::new(), &mut held, 0)?;
            }
            let name = if namespace.is_empty() {
                format!("Action::{action}")
            } else {
                format!("{namespace}::Action::{action}")
            };
            leaves.insert(name, held);
        }
    }

    Ok(leaves)
}

/// The common types of a schema, by qualified name, each with the namespace it was declared in.
type Common = BTreeMap<String, (String, serde_json::Value)>;

/// The common type `name` names when written in `namespace`.
fn resolve<'a>(
    common: &'a Common,
    namespace: &str,
    name: &str,
) -> Option<&'a (String, serde_json::Value)> {
    if name.contains("::") {
        return common.get(name);
    }
    common
        .get(&qualified(namespace, name))
        .or_else(|| common.get(name))
}

fn qualified(namespace: &str, name: &str) -> String {
    if namespace.is_empty() {
        name.to_owned()
    } else {
        format!("{namespace}::{name}")
    }
}

/// The leaves under `node` at `path`. A record is a group; anything else is a leaf.
fn collect(
    node: &serde_json::Value,
    namespace: &str,
    common: &Common,
    path: &mut Path,
    leaves: &mut Side,
    depth: usize,
) -> Result<(), String> {
    // Cedar refuses recursive common types; the bound is a guard, never reached by a schema
    // Cedar accepted.
    if depth > 32 {
        return Err("dogwood: the action context nests deeper than 32 levels".to_owned());
    }
    let kind = node
        .get("type")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    match kind {
        "Record" => {
            if !path.is_empty() {
                leaves.groups.insert(path.clone());
            }
            if let Some(attributes) = node
                .get("attributes")
                .and_then(serde_json::Value::as_object)
            {
                for (name, attribute) in attributes {
                    path.push(name.clone());
                    collect(attribute, namespace, common, path, leaves, depth + 1)?;
                    path.pop();
                }
            }
            Ok(())
        }
        "EntityOrCommon" => match node
            .get("name")
            .and_then(serde_json::Value::as_str)
            .and_then(|name| resolve(common, namespace, name))
        {
            Some((home, definition)) => collect(definition, home, common, path, leaves, depth + 1),
            None => {
                leaves.leaves.insert(path.clone());
                Ok(())
            }
        },
        other => match resolve(common, namespace, other) {
            Some((home, definition)) => collect(definition, home, common, path, leaves, depth + 1),
            None => {
                leaves.leaves.insert(path.clone());
                Ok(())
            }
        },
    }
}

/// The leaves one kind's event logs from its caller: every declared field but those the server
/// writes — the pins, and the two scope aliases written from the request's own roots.
pub fn event_leaves(signature: &Signature) -> BTreeSet<Path> {
    signature
        .fields
        .iter()
        .map(|field| field.path.clone())
        .filter(|path| !signature.pins.iter().any(|pin| &pin.field == path))
        .filter(|path| {
            !matches!(
                path.as_slice(),
                [only] if only == super::occurrence::CALLER_PRINCIPAL
                    || only == super::occurrence::CALLER_RESOURCE
            )
        })
        .collect()
}

/// Whether `path` is `declared` or lies inside it.
fn covered(path: &Path, declared: &[Path]) -> bool {
    declared.iter().any(|held| path.starts_with(held))
}

/// Whether `path` is a leaf of `leaves` or a group above one.
fn a_node_of(path: &Path, leaves: &BTreeSet<Path>) -> bool {
    leaves.iter().any(|leaf| leaf.starts_with(path))
}

/// The load's check: every leaf one side declares and the other does not is declared one-sided,
/// per action and kind; every declaration names a field its side has.
pub fn check_complete(
    signatures: &[Signature],
    context: &BTreeMap<String, Side>,
    projections: &Projections,
) -> Result<(), String> {
    let empty = BTreeSet::new();
    for signature in signatures {
        let event = event_leaves(signature);
        let request = context
            .get(&signature.action)
            .map_or(&empty, |side| &side.leaves);
        // A pin read from the context is not request-only: the server copies it into the history.
        let pinned_from_context: BTreeSet<Path> = signature
            .pins
            .iter()
            .filter_map(|pin| match &pin.source {
                crate::temporal::PinSource::Context(path) => Some(path.clone()),
                _ => None,
            })
            .collect();
        for leaf in event.difference(request) {
            if !covered(leaf, &projections.history_only) {
                return Err(format!(
                    "dogwood: `{}` is logged by `{}` `{}` events and is not in the action's \
                     context; a version 2 partition declares it under `history_only` in \
                     `projections.json`, or the context declares it too",
                    leaf.join("."),
                    signature.action,
                    signature.kind
                ));
            }
        }
        for leaf in request.difference(&event) {
            if pinned_from_context.contains(leaf) {
                continue;
            }
            if !covered(leaf, &projections.request_only) {
                return Err(format!(
                    "dogwood: `{}` is in the context of `{}` and not logged by its `{}` events; a \
                     version 2 partition declares it under `request_only` in `projections.json`, \
                     or the event schema logs it too",
                    leaf.join("."),
                    signature.action,
                    signature.kind
                ));
            }
        }
    }
    for path in &projections.history_only {
        if !signatures
            .iter()
            .any(|signature| a_node_of(path, &event_leaves(signature)))
        {
            return Err(format!(
                "dogwood: `projections.json` declares `{}` history-only, and no event logs it",
                path.join(".")
            ));
        }
    }
    for path in &projections.request_only {
        if !context
            .values()
            .any(|side| a_node_of(path, &side.leaves) || side.groups.contains(path))
        {
            return Err(format!(
                "dogwood: `projections.json` declares `{}` request-only, and no action's context \
                 has it",
                path.join(".")
            ));
        }
    }

    Ok(())
}

/// The two projections of one canonical field map, for one action and kind.
///
/// A leaf goes to each side that declares it; a group goes to each side with a leaf below it,
/// holding what that side declares; a key neither side declares is refused.
pub fn project(
    fields: &BTreeMap<String, DogwoodValue>,
    event: &Side,
    request: &Side,
) -> Result<(Bag, Bag), String> {
    let mut logged = BTreeMap::new();
    let mut context = BTreeMap::new();
    for (name, value) in fields {
        let mut path = vec![name.clone()];
        if let Some(held) = side(value, &mut path, event) {
            logged.insert(name.clone(), held);
        }
        if let Some(held) = side(value, &mut path, request) {
            context.insert(name.clone(), held);
        }
        unknown(value, &mut path, event, request)?;
    }

    Ok((logged, context))
}

/// What of `value` at `path` one side declares.
fn side(value: &DogwoodValue, path: &mut Path, leaves: &Side) -> Option<DogwoodValue> {
    if leaves.leaves.contains(path) {
        return Some(value.clone());
    }
    if !leaves.has(path) {
        return None;
    }
    let DogwoodValue::Object(members) = value else {
        return None;
    };
    let mut held = BTreeMap::new();
    for (name, member) in members {
        path.push(name.clone());
        if let Some(kept) = side(member, path, leaves) {
            held.insert(name.clone(), kept);
        }
        path.pop();
    }

    Some(DogwoodValue::Object(held.into_iter().collect()))
}

/// Refuses the first key of `value` at `path` that neither side declares.
fn unknown(
    value: &DogwoodValue,
    path: &mut Path,
    event: &Side,
    request: &Side,
) -> Result<(), String> {
    if event.leaves.contains(path) || request.leaves.contains(path) {
        return Ok(());
    }
    if !event.has(path) && !request.has(path) {
        return Err(format!(
            "`fields.{}` is declared by neither this kind's event nor the action's context",
            path.join(".")
        ));
    }
    let DogwoodValue::Object(members) = value else {
        return Err(format!(
            "`fields.{}` is a group of fields in the schemas, and a single value was sent",
            path.join(".")
        ));
    };
    for (name, member) in members {
        path.push(name.clone());
        unknown(member, path, event, request)?;
        path.pop();
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    const ACTION_SCHEMA: &str =
        include_str!("../../tests/fixtures/dogwood/read-login-not-logout.cedarschema");

    fn path(text: &str) -> Path {
        text.split('.').map(str::to_owned).collect()
    }

    #[test]
    fn projections_json_is_closed_its_paths_dotted_and_each_named_once() {
        let read = Projections::parse(
            br#"{"history_only": ["requestId"], "request_only": ["system.now"]}"#,
        )
        .expect("it reads");
        assert_eq!(read.history_only, [path("requestId")]);
        assert_eq!(read.request_only, [path("system.now")]);
        assert_eq!(
            Projections::parse(b"{}").expect("empty"),
            Projections::default()
        );
        for refused in [
            r#"{"history_only": [], "extra": []}"#,
            r#"{"history_only": ["a..b"]}"#,
            r#"{"history_only": ["a"], "request_only": ["a"]}"#,
            r#"{"history_only": ["a", "a"]}"#,
            "[]",
        ] {
            assert!(Projections::parse(refused.as_bytes()).is_err(), "{refused}");
        }
    }

    #[test]
    fn an_actions_context_leaves_are_read_through_cedar_with_common_types_resolved() {
        let leaves = context_leaves(ACTION_SCHEMA).expect("the schema reads");
        let read = &leaves["Drupe::Action::Read"];
        assert!(
            read.groups.contains(&path("output")),
            "an empty record is a group"
        );
        assert_eq!(
            read.leaves
                .iter()
                .map(|held| held.join("."))
                .collect::<Vec<_>>(),
            ["input.document", "input.user", "system.now"],
            "`output` is an empty record and has no leaf"
        );
        assert!(
            leaves["Drupe::Action::Mcp"]
                .leaves
                .contains(&path("system.now"))
        );
    }

    #[test]
    fn a_leaf_goes_to_each_side_that_declares_it_and_one_neither_declares_is_refused() {
        let event = Side::of_event([path("input.user"), path("requestId")].into());
        let request = Side::of_event([path("input.user"), path("system.now")].into());
        let value = |text: &str| DogwoodValue::String(text.to_owned());
        let mut fields = BTreeMap::new();
        fields.insert(
            "input".to_owned(),
            DogwoodValue::Object([("user".to_owned(), value("alice"))].into()),
        );
        fields.insert("requestId".to_owned(), value("r1"));
        fields.insert(
            "system".to_owned(),
            DogwoodValue::Object([("now".to_owned(), value("t"))].into()),
        );
        let (logged, context) = project(&fields, &event, &request).expect("it projects");
        assert_eq!(logged.keys().collect::<Vec<_>>(), ["input", "requestId"]);
        assert_eq!(context.keys().collect::<Vec<_>>(), ["input", "system"]);
        assert_eq!(
            logged["input"], context["input"],
            "a shared field is copied, once"
        );

        let mut stray = fields.clone();
        stray.insert("bogus".to_owned(), value("x"));
        let why = project(&stray, &event, &request).expect_err("neither side");
        assert!(why.contains("fields.bogus"), "{why}");
        let mut flat = fields;
        flat.insert("input".to_owned(), value("not a group"));
        assert!(
            project(&flat, &event, &request).is_err(),
            "a group sent as a value"
        );
    }

    /// After the review: an unqualified common type resolves in the namespace it is written in.
    #[test]
    fn a_common_type_resolves_in_its_own_namespace() {
        let schema = "namespace A { type Input = { a: String }; entity U; action X appliesTo { principal: [U], resource: [U], context: { input: Input } }; }\n\
                      namespace B { type Input = { b: String }; entity U; action Y appliesTo { principal: [U], resource: [U], context: { input: Input } }; }\n";
        let leaves = context_leaves(schema).expect("it reads");
        assert_eq!(
            leaves["A::Action::X"].leaves,
            [path("input.a")].into(),
            "A's own `Input`"
        );
        assert_eq!(leaves["B::Action::Y"].leaves, [path("input.b")].into());
    }

    /// After the review: a pin read from the context is shared — the server copies it into the
    /// history — and needs no `request_only` declaration.
    #[test]
    fn a_pin_read_from_the_context_is_not_request_only() {
        let signature = |pinned: bool| Signature {
            action: "A::Action::X".to_owned(),
            kind: "request".to_owned(),
            decision: true,
            fields: vec![crate::temporal::Field {
                path: path("sessionId"),
                declared: "String".to_owned(),
            }],
            pins: if pinned {
                vec![crate::temporal::Pin {
                    field: path("sessionId"),
                    source: crate::temporal::PinSource::Context(path("sessionId")),
                }]
            } else {
                Vec::new()
            },
        };
        let context: BTreeMap<String, Side> = [(
            "A::Action::X".to_owned(),
            Side::of_event([path("sessionId")].into()),
        )]
        .into();
        check_complete(&[signature(true)], &context, &Projections::default())
            .expect("the pin's source is shared");
        check_complete(&[signature(false)], &context, &Projections::default())
            .expect("an unpinned field both declare is shared too");
        let context_only: BTreeMap<String, Side> = [(
            "A::Action::X".to_owned(),
            Side::of_event([path("sessionId"), path("other")].into()),
        )]
        .into();
        assert!(
            check_complete(&[signature(true)], &context_only, &Projections::default()).is_err(),
            "any other context-only leaf still needs its declaration"
        );
    }

    /// After the review: a one-sided leaf inside a shared group, an empty record and a set.
    #[test]
    fn nested_one_sided_leaves_empty_records_and_sets_project_where_declared() {
        let event = Side::of_event([path("input.user"), path("input.trace")].into());
        let mut request = Side::of_event([path("input.user"), path("tags")].into());
        request.groups.insert(path("output"));
        let value = |text: &str| DogwoodValue::String(text.to_owned());
        let mut fields = BTreeMap::new();
        fields.insert(
            "input".to_owned(),
            DogwoodValue::Object(
                [
                    ("user".to_owned(), value("alice")),
                    ("trace".to_owned(), value("t1")),
                ]
                .into(),
            ),
        );
        fields.insert("output".to_owned(), DogwoodValue::Object(BTreeMap::new()));
        fields.insert(
            "tags".to_owned(),
            DogwoodValue::Array(vec![value("a"), value("b")]),
        );
        let (logged, context) = project(&fields, &event, &request).expect("it projects");
        let DogwoodValue::Object(logged_input) = &logged["input"] else {
            panic!("a group");
        };
        assert_eq!(
            logged_input.len(),
            2,
            "the history keeps the one-sided `trace`"
        );
        let DogwoodValue::Object(context_input) = &context["input"] else {
            panic!("a group");
        };
        assert_eq!(
            context_input.keys().collect::<Vec<_>>(),
            ["user"],
            "the request reads only what its context declares"
        );
        assert_eq!(context["output"], DogwoodValue::Object(BTreeMap::new()));
        assert!(!logged.contains_key("output") && !logged.contains_key("tags"));
        assert_eq!(context["tags"], fields["tags"], "a set is a leaf");
    }
}
