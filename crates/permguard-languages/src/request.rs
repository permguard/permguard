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

use std::collections::BTreeMap;

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

/// The Permguard `entities` extension: the entity graphs a request carries.
///
/// # Why a graph is addressed to a partition
///
/// An entity graph is written in one runtime's shape — Cedar's `uid`/`attrs`/`parents`, or whatever
/// a Rego module reads out of `data.entities` — and a profile may hold partitions in different
/// runtimes, or two partitions in the same runtime with **different schemas**. Handing one graph to
/// every partition therefore only worked while all but one of them ignored it: a Cedar partition
/// that received a Rego graph refused the request, and a second Cedar partition with another schema
/// refused entities that were legal for the first.
///
/// So a graph says who it is for. `schema` addresses a runtime; `partitions` addresses one
/// partition by name, which is the only identity that distinguishes two partitions of the same
/// language. What a caller cannot do is choose *which policies* answer: a profile decides that, and
/// an override only supplies data to a partition already in it.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct EntitySetBody {
    /// Which runtime's shape the items are in.
    ///
    /// A graph that names a runtime is delivered only to partitions running it. One that names
    /// none is ambiguous the moment a profile holds more than one runtime, and is refused there —
    /// guessing would hand a Cedar graph to a Rego module or the reverse.
    #[serde(default)]
    pub schema: Option<String>,
    #[serde(default)]
    pub items: Vec<Value>,
    /// One graph per partition, by the partition's own name.
    ///
    /// Overrides the global set for the partition it names. A name the profile does not hold is
    /// refused rather than ignored: a caller that addresses a partition by the wrong name has
    /// asked a question nobody answered, and silence would look like an answer.
    #[serde(default)]
    pub partitions: BTreeMap<String, PartitionEntitySet>,
}

/// One partition's own entity graph.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct PartitionEntitySet {
    /// The runtime shape these items are in. Checked against the partition's own runtime, so an
    /// override cannot quietly hand Cedar entities to a Rego module.
    #[serde(default)]
    pub schema: Option<String>,
    #[serde(default)]
    pub items: Vec<Value>,
}

/// A partition of the profile a request is being decided against.
///
/// The pair that decides how a request is materialised: the **name** routes an override, the
/// **language** routes the global graph and chooses the runtime's own reading of the action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartitionTarget {
    pub name: String,
    pub language: String,
}

impl PartitionTarget {
    pub fn new(name: impl Into<String>, language: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            language: language.into(),
        }
    }
}

/// One question, before any partition has been chosen.
///
/// Every input a caller stated, plus the routing that decides what each partition of the profile
/// actually sees. It is deliberately **not** a [`Query`]: a `Query` is what one evaluator reads,
/// and the same one cannot be handed to every partition — the entity graph belongs to a runtime,
/// and Cedar reads an action's properties somewhere Rego does not.
///
/// [`Asking::route`] turns one of these into one `Query` per partition, and is the only place that
/// does: the plane serving a request and the CLI deciding one offline call it, so a workspace
/// cannot be tested against a materialisation that differs from the one it will meet.
#[derive(Debug, Clone, Default)]
pub struct Asking {
    pub subject: Entity,
    pub resource: Entity,
    pub action: Action,
    /// The context a caller stated. What a runtime is *given* may be more: see `route`.
    pub context: Map<String, Value>,
    /// The graphs the request carries, and who each is for.
    pub entities: Option<EntitySetBody>,
}

/// The context key Permguard fills in from `action.properties`, and a caller may not.
///
/// Cedar cannot carry attributes on an action entity — an action is a UID and nothing else — so the
/// properties of an action reach a Cedar policy the only way anything reaches one, as context. A
/// caller that could also write `context.action` would be writing into a place Permguard writes,
/// and the two would have to be merged or ordered; both are worse than refusing.
pub const RESERVED_CONTEXT_ACTION: &str = "action";

impl Asking {
    /// One query per partition of the profile, in the order given.
    ///
    /// Validates the routing first, so a request that addresses a partition nobody has, or hands a
    /// graph to a runtime that cannot read it, is refused **before** any policy is consulted rather
    /// than denied by one of them. Then, for each partition:
    ///
    /// | | |
    /// | --- | --- |
    /// | `entities.partitions[name]` | that graph, whatever the global one says |
    /// | otherwise, a global graph naming this runtime | that graph |
    /// | otherwise, a global graph naming no runtime | that graph, when the profile holds one runtime |
    /// | otherwise | an empty graph |
    ///
    /// and Cedar additionally receives `action.properties` as `context.action`, because that is the
    /// only door into a Cedar policy. Rego receives the action unchanged: it reads
    /// `input.action.properties` where it always did.
    pub fn route(&self, partitions: &[PartitionTarget]) -> Result<Vec<Query>, Malformed> {
        self.validate_routing(partitions)?;

        Ok(partitions
            .iter()
            .map(|partition| self.materialize(partition))
            .collect())
    }

    /// The query one partition evaluates.
    pub fn materialize(&self, partition: &PartitionTarget) -> Query {
        let mut context = self.context.clone();

        // Cedar has nowhere else to read them from. Absent when there are none, so a schema that
        // never declared `context.action` keeps validating the requests it always did.
        if partition.language == crate::cedar::NAME && !self.action.properties.is_empty() {
            context.insert(
                RESERVED_CONTEXT_ACTION.to_owned(),
                Value::Object(self.action.properties.clone()),
            );
        }

        Query {
            subject: self.subject.clone(),
            resource: self.resource.clone(),
            action: self.action.clone(),
            context,
            entities: self.graph_for(partition),
        }
    }

    /// The graph this partition is given, by the table in [`Asking::route`].
    fn graph_for(&self, partition: &PartitionTarget) -> Vec<Value> {
        let Some(entities) = &self.entities else {
            return Vec::new();
        };

        if let Some(own) = entities.partitions.get(&partition.name) {
            return own.items.clone();
        }

        match &entities.schema {
            // Addressed to a runtime: only partitions running it read it.
            Some(schema) => {
                if schema == &partition.language {
                    entities.items.clone()
                } else {
                    Vec::new()
                }
            }
            // Addressed to nobody. Legal only where there is nobody else to confuse it with,
            // which `validate_routing` has already established.
            None => entities.items.clone(),
        }
    }

    fn validate_routing(&self, partitions: &[PartitionTarget]) -> Result<(), Malformed> {
        let Some(entities) = &self.entities else {
            return Ok(());
        };

        for (name, own) in &entities.partitions {
            let Some(partition) = partitions.iter().find(|held| &held.name == name) else {
                return Err(malformed(
                    "partition_unknown",
                    format!(
                        "`entities.partitions` names `{name}`, which this profile does not hold \
                         (it holds: {}). An entity set supplies data to a partition the profile \
                         already decided on; it cannot add one",
                        names(partitions)
                    ),
                ));
            };
            if let Some(schema) = &own.schema
                && schema != &partition.language
            {
                return Err(malformed(
                    "schema_mismatch",
                    format!(
                        "`entities.partitions.{name}` is written for `{schema}` and the partition \
                         runs `{}`: a graph in one runtime's shape is not readable by another",
                        partition.language
                    ),
                ));
            }
        }

        match &entities.schema {
            // A named runtime is checked whether or not the graph carries anything. An empty graph
            // for a runtime nobody runs decides nothing today and is still a configuration mistake,
            // and a validation that only fires once somebody adds an entity is a validation that
            // reports the mistake at the worst possible moment.
            Some(schema) => {
                if !partitions
                    .iter()
                    .any(|partition| &partition.language == schema)
                {
                    return Err(malformed(
                        "schema_mismatch",
                        format!(
                            "`entities.schema` is `{schema}` and no partition of this profile runs \
                             it (they run: {}): the graph would reach nothing",
                            languages(partitions)
                        ),
                    ));
                }
            }
            // A graph naming nobody is only ambiguous if it holds something.
            None if entities.items.is_empty() => {}
            None => {
                let mut runtimes: Vec<&str> = partitions
                    .iter()
                    .map(|partition| partition.language.as_str())
                    .collect();
                runtimes.sort_unstable();
                runtimes.dedup();

                if runtimes.len() > 1 {
                    return Err(malformed(
                        "schema_required",
                        format!(
                            "`entities` names no `schema` and this profile runs {}: a graph is \
                             written in one runtime's shape, and there is no safe guess between \
                             them. Name the runtime with `entities.schema`, or address a partition \
                             with `entities.partitions`",
                            languages(partitions)
                        ),
                    ));
                }
            }
        }

        Ok(())
    }
}

fn names(partitions: &[PartitionTarget]) -> String {
    partitions
        .iter()
        .map(|partition| partition.name.as_str())
        .collect::<Vec<&str>>()
        .join(", ")
}

fn languages(partitions: &[PartitionTarget]) -> String {
    let mut held: Vec<&str> = partitions
        .iter()
        .map(|partition| partition.language.as_str())
        .collect();
    held.sort_unstable();
    held.dedup();

    held.join(", ")
}

/// How a boxcarred batch resolves.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Semantic {
    /// Run every evaluation, return every result. The batch permits when all of them do.
    #[default]
    ExecuteAll,
    /// Stop at the first deny — the `&&` of evaluations.
    DenyOnFirstDeny,
    /// Stop at the first permit — the `||` of evaluations.
    PermitOnFirstPermit,
}

impl Semantic {
    /// Whether this answer ends the batch.
    ///
    /// The short-circuit of the operator the semantic names: `&&` stops at a deny because nothing
    /// after it can change the answer, `||` stops at a permit for the same reason, and
    /// `execute_all` stops for nothing because the caller asked for every result.
    pub fn stops(self, permitted: bool) -> bool {
        match self {
            Semantic::ExecuteAll => false,
            Semantic::DenyOnFirstDeny => !permitted,
            Semantic::PermitOnFirstPermit => permitted,
        }
    }

    /// The batch's own verdict, from what its evaluations decided.
    ///
    /// **The operator the semantic names, and not always the conjunction.** It was the conjunction
    /// for every semantic, which made `permit_on_first_permit` — documented here as `||` — answer
    /// `deny` for `[deny, permit]`: it stopped at the permit, as it must, and then reported the
    /// `&&` of what it had run. A short-circuit and a verdict computed by different operators is
    /// not one semantic.
    ///
    /// One function so that the plane that serves a batch, the CLI that decides one offline, and
    /// the CLI's check that a plane's answer is coherent cannot hold three opinions about what a
    /// caller asked for.
    pub fn combine(self, decisions: impl IntoIterator<Item = bool>) -> bool {
        let mut decisions = decisions.into_iter().peekable();
        if decisions.peek().is_none() {
            // Nothing decided anything. Absent means no, here as everywhere.
            return false;
        }

        match self {
            Semantic::ExecuteAll | Semantic::DenyOnFirstDeny => {
                decisions.all(|permitted| permitted)
            }
            Semantic::PermitOnFirstPermit => decisions.any(|permitted| permitted),
        }
    }
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
    pub entities: Option<EntitySetBody>,
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
    pub entities: Option<EntitySetBody>,
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
    /// The name the caller gave the request as a whole, when it gave one. What an answer has to
    /// carry back: a response bearing another request's id, or none where one was given, is not
    /// an answer to this.
    pub request_id: Option<String>,
    /// One question per evaluation the caller asked for — a request with no
    /// `evaluations[]` asks exactly one. Logical: materialised per partition by
    /// [`Asking::route`], because no single query fits every runtime of a profile.
    pub queries: Vec<(Asking, Option<String>)>,
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
    /// One question per evaluation the caller asked for — a request with no
    /// `evaluations[]` resolves to exactly one.
    pub queries: Vec<(Asking, Option<String>)>,
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
        // `principal` is the caller, recorded for the audit — it is not the Cedar principal and it
        // is not an authenticated identity. Its properties were read and thrown away, which is the
        // one thing a contract may not do with a field it accepts: somebody would state an
        // attribute, watch a policy ignore it, and conclude the policy was wrong. Refused until
        // there is something to do with them, and refused here rather than in `resolve` so that a
        // workspace tested offline is refused for it too.
        if let Some(principal) = &self.principal {
            if principal
                .properties
                .as_ref()
                .is_some_and(|properties| !properties.is_empty())
            {
                return Err(malformed(
                    "field_unsupported",
                    "`principal.properties` is not read by anything: `principal` names the caller \
                     for the audit record, not the subject a policy decides about. State the \
                     attributes a policy needs on `subject`",
                ));
            }

            // Stated whole or not at all. A `principal` with only a type resolved to nothing and
            // was dropped, so a caller who declared who was asking watched the declaration vanish
            // from the audit record with no error — the one place a silent loss is least
            // acceptable.
            for (field, value) in [("type", &principal.kind), ("id", &principal.id)] {
                if named(value).is_none() {
                    return Err(malformed(
                        "field_required",
                        format!(
                            "`principal.{field}` is required when `principal` is stated: it names \
                             the caller in the audit record, and half a name records nobody"
                        ),
                    ));
                }
            }
        }

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
            // Two evaluations under one name cannot both be answered: a caller joining the
            // answers back to its questions would match the first and lose the second, and so
            // would anything asserting on them. Refused rather than answered ambiguously.
            let mut named_once: Vec<&str> = Vec::new();
            for evaluation in &self.evaluations {
                let Some(request_id) = named(&evaluation.request_id) else {
                    continue;
                };
                if named_once.contains(&request_id.as_str()) {
                    return Err(malformed(
                        "request_id_repeated",
                        format!(
                            "two evaluations are named `{request_id}`: a `request_id` is how an \
                             answer is joined back to the question, so it has to name one"
                        ),
                    ));
                }
                named_once.push(evaluation.request_id.as_deref().unwrap_or_default().trim());
            }

            for (index, evaluation) in self.evaluations.iter().enumerate() {
                queries.push((
                    self.asking_of(Some(evaluation), index)?,
                    evaluation.request_id.clone(),
                ));
            }
        } else {
            queries.push((self.asking_of(None, 0)?, None));
        }

        Ok(Asked {
            profile: named(&self.profile).unwrap_or_else(|| DEFAULT_PROFILE.to_owned()),
            request_id: named(&self.request_id),
            semantic: self
                .options
                .as_ref()
                .and_then(|options| options.evaluations_semantic)
                .unwrap_or_default(),
            queries,
            boxcarred,
        })
    }

    fn asking_of(
        &self,
        evaluation: Option<&EvaluationBody>,
        index: usize,
    ) -> Result<Asking, Malformed> {
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

        let context = context.cloned().unwrap_or_default();

        // `context.action` is Permguard's, filled in from `action.properties` for the runtimes that
        // have nowhere else to read them. A caller writing it too would have to be merged with or
        // ordered against that, and either would make what a policy sees depend on a rule nobody
        // can see. Refused for every profile, including a Rego-only one: a contract that changed
        // shape with the profile would not be a contract.
        if context.contains_key(RESERVED_CONTEXT_ACTION) {
            return Err(malformed(
                "field_reserved",
                format!(
                    "`context.{RESERVED_CONTEXT_ACTION}` is populated from `action.properties` and \
                     may not be sent: state the properties on the action, where every runtime can \
                     read them"
                ),
            ));
        }

        Ok(Asking {
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
            context,
            entities: entities.cloned(),
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
        // The graph is still the caller's; who receives it is decided when it is materialised.
        assert_eq!(
            resolved.queries[0]
                .0
                .entities
                .as_ref()
                .expect("the request carried a graph")
                .items
                .len(),
            1
        );
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

#[cfg(test)]
mod semantic_tests {
    use super::*;

    /// The short-circuit and the verdict are the same operator, which is what makes a semantic one
    /// thing. `[deny, permit]` under `||` is the case that was wrong: the batch stopped at the
    /// permit and then reported the conjunction of what it had run.
    #[test]
    fn a_batch_resolves_by_the_operator_its_semantic_names() {
        for (semantic, decisions, expected) in [
            (Semantic::ExecuteAll, vec![true, true], true),
            (Semantic::ExecuteAll, vec![true, false], false),
            (Semantic::DenyOnFirstDeny, vec![true, true], true),
            (Semantic::DenyOnFirstDeny, vec![true, false], false),
            (Semantic::PermitOnFirstPermit, vec![false, true], true),
            (Semantic::PermitOnFirstPermit, vec![true], true),
            (Semantic::PermitOnFirstPermit, vec![false, false], false),
        ] {
            assert_eq!(
                semantic.combine(decisions.clone()),
                expected,
                "{semantic:?} of {decisions:?}"
            );
        }
    }

    #[test]
    fn a_batch_stops_where_its_operator_short_circuits() {
        assert!(!Semantic::ExecuteAll.stops(true) && !Semantic::ExecuteAll.stops(false));
        assert!(Semantic::DenyOnFirstDeny.stops(false) && !Semantic::DenyOnFirstDeny.stops(true));
        assert!(
            Semantic::PermitOnFirstPermit.stops(true)
                && !Semantic::PermitOnFirstPermit.stops(false)
        );
    }

    /// Nothing decided is a deny, for every semantic: `any` over nothing is false and `all` over
    /// nothing is true, and only one of those is an answer an authorization system may give.
    #[test]
    fn nothing_decided_is_a_deny_whatever_the_semantic() {
        for semantic in [
            Semantic::ExecuteAll,
            Semantic::DenyOnFirstDeny,
            Semantic::PermitOnFirstPermit,
        ] {
            assert!(!semantic.combine(Vec::<bool>::new()), "{semantic:?}");
        }
    }
}

#[cfg(test)]
mod routing_tests {
    use super::*;
    use serde_json::json;

    fn cedar() -> PartitionTarget {
        PartitionTarget::new("admin-cedar", "cedar")
    }

    fn rego() -> PartitionTarget {
        PartitionTarget::new("admin-rego", "rego")
    }

    fn asking(payload: serde_json::Value) -> Result<Asking, Malformed> {
        let mut payload = payload;
        let object = payload.as_object_mut().expect("an object");
        object.insert("zone".to_owned(), json!("z"));
        object.insert("ledger".to_owned(), json!("l"));
        let request: CheckRequest = serde_json::from_value(payload).expect("it parses");

        request
            .asked(256)
            .map(|asked| asked.queries.into_iter().next().expect("one question").0)
    }

    fn plain() -> serde_json::Value {
        json!({
            "subject": {"type": "User", "id": "alice"},
            "resource": {"type": "Service", "id": "payments-api"},
            "action": {"name": "release:create"}
        })
    }

    /// Cedar cannot carry attributes on an action, so it reads them as `context.action`. Rego reads
    /// `input.action.properties` where it always did — the same request, two readings.
    #[test]
    fn an_actions_properties_reach_cedar_as_context_and_rego_as_themselves() {
        let mut payload = plain();
        payload["action"]["properties"] = json!({"risk": "high"});
        payload["context"] = json!({"branch": "main"});
        let asking = asking(payload).expect("it is well formed");

        let for_cedar = asking.materialize(&cedar());
        assert_eq!(for_cedar.context["branch"], json!("main"));
        assert_eq!(
            for_cedar.context[RESERVED_CONTEXT_ACTION],
            json!({"risk": "high"}),
            "Cedar has nowhere else to read them from"
        );
        assert_eq!(
            for_cedar.action.properties["risk"],
            json!("high"),
            "and the action itself is unchanged"
        );

        let for_rego = asking.materialize(&rego());
        assert_eq!(for_rego.context["branch"], json!("main"));
        assert!(
            !for_rego.context.contains_key(RESERVED_CONTEXT_ACTION),
            "Rego's context is the caller's, and nothing else"
        );
        assert_eq!(for_rego.action.properties["risk"], json!("high"));
    }

    /// An action with no properties leaves the context alone, so a schema that never declared
    /// `context.action` keeps validating the requests it always did.
    #[test]
    fn an_action_without_properties_adds_nothing_to_the_context() {
        let asking = asking(plain()).expect("it is well formed");

        assert!(
            !asking
                .materialize(&cedar())
                .context
                .contains_key(RESERVED_CONTEXT_ACTION)
        );
    }

    /// The reserved key is refused for every profile, Rego-only included: a contract that changed
    /// shape with the profile would not be a contract.
    #[test]
    fn a_caller_may_not_write_the_reserved_context_key() {
        let mut payload = plain();
        payload["context"] = json!({"action": {"risk": "low"}});

        let refused = asking(payload).expect_err("it names a reserved key");
        assert_eq!(refused.code, "field_reserved");
        assert!(refused.message.contains("action.properties"), "{refused:?}");
    }

    /// A graph addressed to a runtime reaches the partitions running it, and nothing else.
    #[test]
    fn a_graph_reaches_only_the_runtime_it_names() {
        let mut payload = plain();
        payload["entities"] =
            json!({"schema": "cedar", "items": [{"uid": {"type": "Group", "id": "finance"}}]});
        let asking = asking(payload).expect("it is well formed");

        let queries = asking
            .route(&[cedar(), rego()])
            .expect("a graph naming a runtime this profile runs");

        assert_eq!(queries[0].entities.len(), 1, "Cedar's own shape, to Cedar");
        assert!(
            queries[1].entities.is_empty(),
            "and never to Rego, which cannot read it"
        );
    }

    /// A partition is addressed by name, because two partitions of one language are not one thing.
    #[test]
    fn an_override_addresses_one_partition_by_name() {
        let other = PartitionTarget::new("other-cedar", "cedar");
        let mut payload = plain();
        payload["entities"] = json!({
            "schema": "cedar",
            "items": [{"uid": {"type": "Group", "id": "finance"}}],
            "partitions": {
                "other-cedar": {"schema": "cedar", "items": [
                    {"uid": {"type": "Team", "id": "payments"}},
                    {"uid": {"type": "Team", "id": "platform"}}
                ]}
            }
        });
        let asking = asking(payload).expect("it is well formed");

        let queries = asking
            .route(&[cedar(), other, rego()])
            .expect("both Cedar partitions are addressed");

        assert_eq!(queries[0].entities.len(), 1, "the global graph");
        assert_eq!(
            queries[1].entities.len(),
            2,
            "its own graph, not the global"
        );
        assert!(queries[2].entities.is_empty(), "and Rego still gets none");
    }

    /// An override may supply data to a partition the profile holds. It may not name another one:
    /// that is a question nobody answered, and silence would look like an answer.
    #[test]
    fn an_override_may_not_name_a_partition_the_profile_does_not_hold() {
        let mut payload = plain();
        payload["entities"] = json!({"partitions": {"nowhere": {"schema": "cedar", "items": []}}});

        let refused = asking(payload)
            .expect("it parses")
            .route(&[cedar(), rego()])
            .expect_err("`nowhere` is not in the profile");

        assert_eq!(refused.code, "partition_unknown");
        assert!(refused.message.contains("admin-cedar"), "{refused:?}");
    }

    /// A graph in one runtime's shape is not readable by another, however it is addressed.
    #[test]
    fn a_graph_may_not_be_addressed_to_a_runtime_that_cannot_read_it() {
        let mut payload = plain();
        payload["entities"] =
            json!({"partitions": {"admin-rego": {"schema": "cedar", "items": []}}});

        let refused = asking(payload)
            .expect("it parses")
            .route(&[cedar(), rego()])
            .expect_err("a Cedar graph handed to a Rego partition");
        assert_eq!(refused.code, "schema_mismatch");

        // And a global graph naming a runtime nobody runs reaches nothing, which is a mistake
        // rather than an empty result.
        let mut payload = plain();
        payload["entities"] = json!({"schema": "cedar", "items": [{"uid": {}}]});
        let refused = asking(payload)
            .expect("it parses")
            .route(&[rego()])
            .expect_err("no partition runs Cedar");
        assert_eq!(refused.code, "schema_mismatch");
    }

    /// A graph naming no runtime is accepted where there is nobody to confuse it with, and refused
    /// the moment a profile runs more than one. Guessing would hand Cedar entities to a Rego
    /// module, which is exactly the failure the routing exists to prevent.
    #[test]
    fn a_graph_naming_no_runtime_is_ambiguous_only_where_it_could_be() {
        let mut payload = plain();
        payload["entities"] = json!({"items": [{"uid": {"type": "Group", "id": "finance"}}]});

        let queries = asking(payload.clone())
            .expect("it parses")
            .route(&[cedar()])
            .expect("one runtime, nothing to be ambiguous between");
        assert_eq!(queries[0].entities.len(), 1);

        let refused = asking(payload)
            .expect("it parses")
            .route(&[cedar(), rego()])
            .expect_err("two runtimes and no shape named");
        assert_eq!(refused.code, "schema_required");
    }

    /// A `principal` is stated whole or not at all: half a name records nobody, and it was
    /// resolved to nothing and dropped without a word.
    #[test]
    fn a_principal_is_stated_whole_or_refused() {
        for half in [
            json!({"type": "Workload"}),
            json!({"id": "gateway"}),
            json!({"type": "Workload", "id": "  "}),
            json!({}),
        ] {
            let mut payload = plain();
            payload["principal"] = half.clone();

            let refused = asking(payload).expect_err("half a principal is nobody");
            assert_eq!(refused.code, "field_required", "{half}");
            assert!(refused.message.contains("principal."), "{refused:?}");
        }

        let mut whole = plain();
        whole["principal"] = json!({"type": "Workload", "id": "gateway"});
        asking(whole).expect("a principal stated whole is accepted");
    }

    /// A graph naming a runtime is checked whether or not it carries anything: an empty graph for
    /// a runtime nobody runs decides nothing today and is still a mistake, and a validation that
    /// waited for the first entity would report it at the worst moment.
    #[test]
    fn a_declared_runtime_is_checked_even_with_nothing_in_the_graph() {
        for items in [json!([]), json!([{"uid": {"type": "Group", "id": "g"}}])] {
            let mut payload = plain();
            payload["entities"] = json!({"schema": "nowhere", "items": items});

            let refused = asking(payload)
                .expect("it parses")
                .route(&[cedar(), rego()])
                .expect_err("no partition runs `nowhere`");
            assert_eq!(refused.code, "schema_mismatch", "with items {items}");
        }

        // And a graph naming nobody is only ambiguous when it holds something.
        let mut payload = plain();
        payload["entities"] = json!({"items": []});
        asking(payload)
            .expect("it parses")
            .route(&[cedar(), rego()])
            .expect("an empty graph addressed to nobody reaches nobody, and confuses nobody");
    }

    /// `principal` names the caller for the audit record. Its properties were read and dropped,
    /// which is the one thing a contract may not do with a field it accepts.
    #[test]
    fn principal_properties_are_refused_rather_than_ignored() {
        let mut payload = plain();
        payload["principal"] =
            json!({"type": "Workload", "id": "gateway", "properties": {"role": "admin"}});

        let refused = asking(payload).expect_err("nothing reads them");
        assert_eq!(refused.code, "field_unsupported");
        assert!(refused.message.contains("subject"), "{refused:?}");
    }

    /// Boxcarring inherits the top-level action and its properties, and an evaluation that states
    /// its own action states its own properties with it — never half of each.
    #[test]
    fn a_batch_inherits_an_action_whole_and_overrides_it_whole() {
        let payload = json!({
            "subject": {"type": "User", "id": "alice"},
            "resource": {"type": "Service", "id": "payments-api"},
            "action": {"name": "release:create", "properties": {"risk": "high"}},
            "evaluations": [
                {"request_id": "inherits"},
                {"request_id": "states-its-own",
                 "action": {"name": "release:signoff", "properties": {"risk": "low"}}},
                {"request_id": "states-an-action-only", "action": {"name": "deployment:rollback"}}
            ]
        });
        let mut payload = payload;
        let object = payload.as_object_mut().expect("an object");
        object.insert("zone".to_owned(), json!("z"));
        object.insert("ledger".to_owned(), json!("l"));
        let request: CheckRequest = serde_json::from_value(payload).expect("it parses");
        let asked = request.asked(256).expect("it is well formed");

        let cedar = cedar();
        let inherited = asked.queries[0].0.materialize(&cedar);
        assert_eq!(inherited.action.name, "release:create");
        assert_eq!(
            inherited.context[RESERVED_CONTEXT_ACTION],
            json!({"risk": "high"})
        );

        let own = asked.queries[1].0.materialize(&cedar);
        assert_eq!(own.action.name, "release:signoff");
        assert_eq!(
            own.context[RESERVED_CONTEXT_ACTION],
            json!({"risk": "low"}),
            "an evaluation's action brings its own properties"
        );

        // An evaluation that names an action and no properties has none: the two travel together,
        // so a `risk` from the top level cannot end up describing a different action.
        let bare = asked.queries[2].0.materialize(&cedar);
        assert_eq!(bare.action.name, "deployment:rollback");
        assert!(!bare.context.contains_key(RESERVED_CONTEXT_ACTION));
    }

    /// Per-partition graphs work inside a boxcarred evaluation exactly as they do outside one.
    #[test]
    fn a_batch_carries_per_partition_graphs() {
        let mut payload = json!({
            "subject": {"type": "User", "id": "alice"},
            "resource": {"type": "Service", "id": "payments-api"},
            "action": {"name": "release:create"},
            "evaluations": [{
                "request_id": "one",
                "entities": {"partitions": {"admin-rego": {"schema": "rego", "items": [{"team": "payments"}]}}}
            }]
        });
        let object = payload.as_object_mut().expect("an object");
        object.insert("zone".to_owned(), json!("z"));
        object.insert("ledger".to_owned(), json!("l"));
        let request: CheckRequest = serde_json::from_value(payload).expect("it parses");
        let asked = request.asked(256).expect("it is well formed");

        let queries = asked.queries[0]
            .0
            .route(&[cedar(), rego()])
            .expect("the override names a partition of the profile");
        assert!(
            queries[0].entities.is_empty(),
            "Cedar was addressed nothing"
        );
        assert_eq!(queries[1].entities.len(), 1, "Rego was addressed its own");
    }
}
