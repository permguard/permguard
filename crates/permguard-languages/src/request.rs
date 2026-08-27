// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The `permguard.pdp.v1` payloads: what a PEP sends, and what it gets back.
//!
//! # Why the payloads live beside the engines
//!
//! A data plane reads these off a socket; `permguard test` reads them off disk and
//! decides them without one. Both have to agree about what a request *is* — which
//! fields are required, which JSON types are accepted, how `evaluations[]` inherits
//! the top-level defaults, how a batch resolves — and the only way to guarantee
//! that is for there to be one definition. Written twice, the local test answers
//! where a plane refuses, and the command's whole promise is quietly false.
//!
//! So the types and [`CheckRequest::asked`] are here, next to [`Query`], and the
//! serving half — routing, tracing, disclosure — stays in the plane.
//!
//! # Lineage, stated plainly
//!
//! The shape is **OpenID AuthZEN Authorization API 1.0** — `subject`, `action`,
//! `resource`, `context` in, `{decision, context}` out, with `evaluations[]` for
//! boxcarring and `options.evaluations_semantic` for how a batch resolves. What the
//! standard leaves to the implementation, this profile fills in; what the standard
//! does not cover, this profile adds as extensions the standard itself provides for
//! (a receiver ignores what it does not know). The Search APIs are deliberately
//! **not** served, and their absence from the metadata document is — per the
//! standard's own rule — how a PEP learns that.
//!
//! We do not claim conformance. We implement the contract and say where we differ,
//! which is worth more than a badge.
//!
//! # Where we differ, and why
//!
//! | | Standard | Here |
//! | --- | --- | --- |
//! | Policy store | the URL the PEP was configured with | **`zone` and `ledger` in the payload**, required |
//! | Search APIs | optional | not served |
//! | `principal`, `entities` | — | extensions: who is asking, and the entity graph |
//! | Reasons | free-form `context` | `reason_admin` / `reason_user`, the disclosure split the whole server speaks |
//!
//! One endpoint that carries the store in the body is the choice a caller asked
//! for: a PEP that talks to several ledgers keeps one address and one connection
//! pool, and the ledger becomes data — which is also what makes a request loggable
//! and auditable as one record. A payload that names neither is **refused**, never
//! answered against a default: silently deciding against the wrong policy store is
//! the one failure mode nobody can debug.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::evaluate::{Action, Entity, Query};

/// The default profile, when a request names none.
pub const DEFAULT_PROFILE: &str = "default";

/// One entity as the wire carries it.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct EntityBody {
    #[serde(rename = "type", default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub properties: Option<Map<String, Value>>,
}

/// The action as the wire carries it.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ActionBody {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub properties: Option<Map<String, Value>>,
}

/// The Permguard `entities` extension: the entity graph, in the runtime's own
/// schema.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct EntitiesBody {
    /// Which runtime's shape the items are in. Advisory: the partition's own
    /// language is what actually reads them.
    #[serde(default)]
    pub schema: Option<String>,
    #[serde(default)]
    pub items: Vec<Value>,
}

/// How a boxcarred batch resolves.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Semantic {
    /// Run every evaluation, return every result.
    #[default]
    ExecuteAll,
    /// Stop at the first deny — the `&&` of evaluations.
    DenyOnFirstDeny,
    /// Stop at the first permit — the `||` of evaluations.
    PermitOnFirstPermit,
}

/// The `options` object.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct OptionsBody {
    #[serde(default)]
    pub evaluations_semantic: Option<Semantic>,
}

/// One entry of `evaluations[]`: whatever it declares overrides the defaults.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct EvaluationBody {
    #[serde(default)]
    pub subject: Option<EntityBody>,
    #[serde(default)]
    pub resource: Option<EntityBody>,
    #[serde(default)]
    pub action: Option<ActionBody>,
    #[serde(default)]
    pub context: Option<Map<String, Value>>,
    #[serde(default)]
    pub entities: Option<EntitiesBody>,
    #[serde(default)]
    pub request_id: Option<String>,
}

/// A decision request.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct CheckRequest {
    /// The zone — by name or by identity. Required.
    #[serde(default)]
    pub zone: Option<String>,
    /// The ledger — by name or by identity. Required.
    #[serde(default)]
    pub ledger: Option<String>,
    /// Which of the ledger's profiles to evaluate. `default` when absent.
    #[serde(default)]
    pub profile: Option<String>,
    #[serde(default)]
    pub subject: Option<EntityBody>,
    #[serde(default)]
    pub resource: Option<EntityBody>,
    #[serde(default)]
    pub action: Option<ActionBody>,
    #[serde(default)]
    pub context: Option<Map<String, Value>>,
    /// Who is *asking*, which may differ from the subject. Carried through to
    /// the audit record; policies read the subject.
    #[serde(default)]
    pub principal: Option<EntityBody>,
    #[serde(default)]
    pub entities: Option<EntitiesBody>,
    #[serde(default)]
    pub evaluations: Vec<EvaluationBody>,
    #[serde(default)]
    pub options: Option<OptionsBody>,
    #[serde(default)]
    pub request_id: Option<String>,
}

/// The two audiences of one reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reason {
    pub code: String,
    pub message: String,
}

/// What a decision carries beside the boolean.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DecisionContext {
    /// This decision's own identifier — what the audit record is found by.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// The full explanation: operator material.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_admin: Option<Reason>,
    /// The safe explanation: caller material.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason_user: Option<Reason>,
    /// The policies that decided it, by identity — the identity that survives
    /// a rename, so a decision and its audit record cite the same thing.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policies: Vec<String>,
}

/// One decision.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Decision {
    pub decision: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(skip_serializing_if = "is_empty_context")]
    pub context: Option<DecisionContext>,
}

fn is_empty_context(context: &Option<DecisionContext>) -> bool {
    match context {
        None => true,
        Some(context) => {
            context.id.is_none()
                && context.reason_admin.is_none()
                && context.reason_user.is_none()
                && context.policies.is_empty()
        }
    }
}

/// The answer to a request: one decision, and one per boxcarred evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResponse {
    pub decision: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(skip_serializing_if = "is_empty_context")]
    pub context: Option<DecisionContext>,
    /// Present exactly when the request carried `evaluations[]`, in the same
    /// order.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evaluations: Option<Vec<Decision>>,
}

/// What a request asks, once its defaults are applied and its required fields
/// checked — and before anything says which store answers it.
#[derive(Debug, Clone)]
pub struct Asked {
    pub profile: String,
    pub semantic: Semantic,
    /// One query per evaluation the caller asked for — a request with no
    /// `evaluations[]` asks exactly one.
    pub queries: Vec<(Query, Option<String>)>,
    /// Whether the caller boxcarred: the response shape follows the request's.
    pub boxcarred: bool,
}

/// What a request resolved to, once its defaults are applied and its required
/// fields checked.
#[derive(Debug, Clone)]
pub struct Resolved {
    pub zone: String,
    pub ledger: String,
    pub profile: String,
    pub semantic: Semantic,
    /// One query per evaluation the caller asked for — a request with no
    /// `evaluations[]` resolves to exactly one.
    pub queries: Vec<(Query, Option<String>)>,
    /// Whether the caller boxcarred: the response shape follows the request's.
    pub boxcarred: bool,
    pub request_id: Option<String>,
    /// Who is asking, for the audit record.
    pub principal: Option<String>,
}

/// Why a request could not even be read as one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Malformed {
    pub code: &'static str,
    pub message: String,
}

fn malformed(code: &'static str, message: impl Into<String>) -> Malformed {
    Malformed {
        code,
        message: message.into(),
    }
}

impl CheckRequest {
    /// Applies the defaults and checks what the contract requires.
    ///
    /// The top-level `subject`, `resource`, `action` and `context` are the
    /// defaults each evaluation inherits, and each evaluation overrides what it
    /// declares — the standard's boxcarring rule. A field missing from both is
    /// a refusal that names it, because a PDP that guessed would be answering a
    /// question nobody asked.
    pub fn resolve(&self, max_evaluations: usize) -> Result<Resolved, Malformed> {
        let zone = named(&self.zone).ok_or_else(|| {
            malformed(
                "zone_required",
                "the request names no zone: `zone` and `ledger` say which policy store to decide \
                 against, and there is no default",
            )
        })?;
        let ledger = named(&self.ledger).ok_or_else(|| {
            malformed(
                "ledger_required",
                "the request names no ledger: `zone` and `ledger` say which policy store to \
                 decide against, and there is no default",
            )
        })?;
        let asked = self.asked(max_evaluations)?;

        Ok(Resolved {
            zone,
            ledger,
            profile: asked.profile,
            semantic: asked.semantic,
            queries: asked.queries,
            boxcarred: asked.boxcarred,
            request_id: named(&self.request_id),
            principal: self.principal.as_ref().and_then(|principal| {
                match (&principal.kind, &principal.id) {
                    (Some(kind), Some(id)) => Some(format!("{kind}:{id}")),
                    _ => None,
                }
            }),
        })
    }

    /// What the request asks, without saying of whom.
    ///
    /// Everything `resolve` does except naming the policy store: the boxcarring rule,
    /// the inheritance of the top-level defaults, the required fields of every
    /// evaluation, and how the batch resolves. It is the half that is true of a
    /// request wherever it is decided — which is what lets `permguard test` decide the
    /// very same request off disk, against a workspace that has no zone or ledger of
    /// its own until it is checked out.
    pub fn asked(&self, max_evaluations: usize) -> Result<Asked, Malformed> {
        if self.evaluations.len() > max_evaluations {
            return Err(malformed(
                "too_many_evaluations",
                format!(
                    "the request carries {} evaluations and this plane accepts {max_evaluations}",
                    self.evaluations.len()
                ),
            ));
        }

        let boxcarred = !self.evaluations.is_empty();
        let mut queries = Vec::new();
        if boxcarred {
            for (index, evaluation) in self.evaluations.iter().enumerate() {
                queries.push((
                    self.query_of(Some(evaluation), index)?,
                    evaluation.request_id.clone(),
                ));
            }
        } else {
            queries.push((self.query_of(None, 0)?, None));
        }

        Ok(Asked {
            profile: named(&self.profile).unwrap_or_else(|| DEFAULT_PROFILE.to_owned()),
            semantic: self
                .options
                .as_ref()
                .and_then(|options| options.evaluations_semantic)
                .unwrap_or_default(),
            queries,
            boxcarred,
        })
    }

    fn query_of(
        &self,
        evaluation: Option<&EvaluationBody>,
        index: usize,
    ) -> Result<Query, Malformed> {
        let subject = pick(
            evaluation.and_then(|e| e.subject.as_ref()),
            self.subject.as_ref(),
        );
        let resource = pick(
            evaluation.and_then(|e| e.resource.as_ref()),
            self.resource.as_ref(),
        );
        let action = evaluation
            .and_then(|e| e.action.as_ref())
            .or(self.action.as_ref());
        let context = evaluation
            .and_then(|e| e.context.as_ref())
            .or(self.context.as_ref());
        let entities = evaluation
            .and_then(|e| e.entities.as_ref())
            .or(self.entities.as_ref());

        Ok(Query {
            subject: entity(subject, "subject", index)?,
            resource: entity(resource, "resource", index)?,
            action: Action {
                name: action
                    .and_then(|action| named(&action.name))
                    .ok_or_else(|| missing("action", index))?,
                properties: action
                    .and_then(|action| action.properties.clone())
                    .unwrap_or_default(),
            },
            context: context.cloned().unwrap_or_default(),
            entities: entities
                .map(|entities| entities.items.clone())
                .unwrap_or_default(),
        })
    }
}

fn pick<'a>(
    own: Option<&'a EntityBody>,
    default: Option<&'a EntityBody>,
) -> Option<&'a EntityBody> {
    own.or(default)
}

fn entity(body: Option<&EntityBody>, what: &str, index: usize) -> Result<Entity, Malformed> {
    let body = body.ok_or_else(|| missing(what, index))?;
    let kind = named(&body.kind).ok_or_else(|| missing(&format!("{what}.type"), index))?;
    let id = named(&body.id).ok_or_else(|| missing(&format!("{what}.id"), index))?;

    Ok(Entity {
        kind,
        id,
        properties: body.properties.clone().unwrap_or_default(),
    })
}

fn missing(what: &str, index: usize) -> Malformed {
    malformed(
        "field_required",
        format!(
            "`{what}` is required: state it at the top level or in evaluation {index} — top-level \
             values are the defaults each evaluation inherits"
        ),
    )
}

/// A field that is present and not just whitespace.
fn named(value: &Option<String>) -> Option<String> {
    value
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    fn parse(text: &str) -> CheckRequest {
        serde_json::from_str(text).expect("the payload parses")
    }

    const ONE: &str = r#"{
        "zone": "acme", "ledger": "main-ledger",
        "subject": {"type": "user", "id": "alice"},
        "resource": {"type": "document", "id": "budget"},
        "action": {"name": "read"},
        "context": {"time": "2026-08-24T10:00:00Z"}
    }"#;

    #[test]
    fn a_plain_request_resolves_to_one_query() {
        let resolved = parse(ONE).resolve(256).expect("it is well formed");

        assert_eq!(resolved.zone, "acme");
        assert_eq!(resolved.ledger, "main-ledger");
        assert_eq!(resolved.profile, DEFAULT_PROFILE);
        assert!(!resolved.boxcarred);
        assert_eq!(resolved.queries.len(), 1);
        assert_eq!(resolved.queries[0].0.subject.id, "alice");
        assert_eq!(resolved.queries[0].0.action.name, "read");
        assert_eq!(resolved.semantic, Semantic::ExecuteAll);
    }

    #[test]
    fn a_request_that_names_no_store_is_refused_by_name() {
        let refused = parse(r#"{"ledger": "main-ledger"}"#)
            .resolve(256)
            .expect_err("there is no default zone");
        assert_eq!(refused.code, "zone_required");

        let refused = parse(r#"{"zone": "acme"}"#)
            .resolve(256)
            .expect_err("there is no default ledger");
        assert_eq!(refused.code, "ledger_required");

        // Whitespace is not a name.
        let refused = parse(r#"{"zone": "  ", "ledger": "l"}"#)
            .resolve(256)
            .expect_err("blank is absent");
        assert_eq!(refused.code, "zone_required");
    }

    #[test]
    fn the_top_level_fields_are_the_defaults_each_evaluation_inherits() {
        let resolved = parse(
            r#"{
                "zone": "acme", "ledger": "l",
                "subject": {"type": "user", "id": "alice"},
                "action": {"name": "read"},
                "evaluations": [
                    {"resource": {"type": "document", "id": "a"}},
                    {"resource": {"type": "document", "id": "b"}, "action": {"name": "delete"}}
                ]
            }"#,
        )
        .resolve(256)
        .expect("it is well formed");

        assert!(resolved.boxcarred);
        assert_eq!(resolved.queries.len(), 2);
        assert_eq!(resolved.queries[0].0.action.name, "read", "inherited");
        assert_eq!(resolved.queries[1].0.action.name, "delete", "overridden");
        assert_eq!(resolved.queries[0].0.subject.id, "alice");
        assert_eq!(resolved.queries[1].0.resource.id, "b");
    }

    #[test]
    fn a_field_missing_from_both_places_is_refused_naming_the_evaluation() {
        let refused = parse(
            r#"{
                "zone": "acme", "ledger": "l",
                "subject": {"type": "user", "id": "alice"},
                "evaluations": [{"resource": {"type": "document", "id": "a"}}]
            }"#,
        )
        .resolve(256)
        .expect_err("no action anywhere");

        assert_eq!(refused.code, "field_required");
        assert!(refused.message.contains("`action`"), "{}", refused.message);
        assert!(
            refused.message.contains("evaluation 0"),
            "{}",
            refused.message
        );
    }

    #[test]
    fn a_batch_larger_than_the_plane_accepts_is_refused_not_attempted() {
        let mut request = parse(ONE);
        request.evaluations = vec![EvaluationBody::default(); 5];

        let refused = request.resolve(4).expect_err("five is more than four");
        assert_eq!(refused.code, "too_many_evaluations");
    }

    #[test]
    fn the_semantics_and_the_extensions_are_read() {
        let resolved = parse(
            r#"{
                "zone": "acme", "ledger": "l", "profile": "strict",
                "subject": {"type": "user", "id": "alice", "properties": {"department": "sales"}},
                "resource": {"type": "document", "id": "budget"},
                "action": {"name": "read"},
                "principal": {"type": "workload", "id": "gateway"},
                "entities": {"schema": "cedar", "items": [{"uid": {"type": "Group", "id": "g"}}]},
                "options": {"evaluations_semantic": "deny_on_first_deny"},
                "request_id": "abc"
            }"#,
        )
        .resolve(256)
        .expect("it is well formed");

        assert_eq!(resolved.profile, "strict");
        assert_eq!(resolved.semantic, Semantic::DenyOnFirstDeny);
        assert_eq!(resolved.principal.as_deref(), Some("workload:gateway"));
        assert_eq!(resolved.request_id.as_deref(), Some("abc"));
        assert_eq!(resolved.queries[0].0.entities.len(), 1);
        assert_eq!(
            resolved.queries[0].0.subject.properties["department"],
            Value::from("sales")
        );
    }

    #[test]
    fn unknown_fields_are_ignored_because_forward_compatibility_is_the_readers_duty() {
        let resolved = parse(
            r#"{"zone": "acme", "ledger": "l", "whats_this": 1,
                "subject": {"type": "user", "id": "a", "future": true},
                "resource": {"type": "d", "id": "b"}, "action": {"name": "read"}}"#,
        )
        .resolve(256)
        .expect("what we do not know, we ignore");

        assert_eq!(resolved.queries[0].0.subject.id, "a");
    }

    #[test]
    fn an_empty_context_is_not_serialized() {
        let answer = CheckResponse {
            decision: true,
            request_id: None,
            context: Some(DecisionContext::default()),
            evaluations: None,
        };

        assert_eq!(
            serde_json::to_string(&answer).expect("it serializes"),
            r#"{"decision":true}"#
        );
    }
}
