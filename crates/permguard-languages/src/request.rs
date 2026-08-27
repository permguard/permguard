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
//! | `principal`, `partition_inputs` | — | extensions: who is asking, and what each partition of the profile is given |
//! | Reasons | free-form `context` | `reason_admin` / `reason_user`, the disclosure split the whole server speaks |
//!
//! # The one breaking change this profile has made
//!
//! `entities` — one graph for the whole request, addressed to a runtime — is **gone**, replaced by
//! `partition_inputs`, addressed to a partition by name. It could not be kept: a graph addressed
//! to "the Cedar partitions" is unanswerable the moment a profile holds two of them with different
//! schemas, because a graph legal for one is refused by the other.
//!
//! It is refused rather than ignored, and that distinction is the whole of it. A caller who sent
//! an entity graph and had it silently dropped would be answered against an empty world —
//! permitted or denied for a reason nothing on the wire explains. See [`CheckRequest::removed`],
//! which every binding calls, including the ones whose own schema has no field to carry it.
//!
//! One endpoint that carries the store in the body is the choice a caller asked
//! for: a PEP that talks to several ledgers keeps one address and one connection
//! pool, and the ledger becomes data — which is also what makes a request loggable
//! and auditable as one record. A payload that names neither is **refused**, never
//! answered against a default: silently deciding against the wrong policy store is
//! the one failure mode nobody can debug.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::evaluate::{Action, Entity, Evaluator, Query};
pub use crate::input::{PartitionData, PartitionInputBody, PartitionInputs};
use permguard_objects::manifest::InputContract;

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

/// A partition of the profile a request is being decided against, as the routing sees it.
///
/// The name routes an input — and it is the **only** thing that does. There is no addressing by
/// language: two Cedar partitions with different schemas hold different worlds, and a store legal
/// in one is refused by the other, so "every Cedar partition" was never a destination anybody
/// could mean.
#[derive(Clone, Copy)]
pub struct PartitionTarget<'a> {
    pub name: &'a str,
    /// The language its runtime speaks, which decides the runtime's own reading of the action.
    pub language: &'a str,
    /// The one kind of input it accepts, when it accepts any.
    pub input: Option<&'a InputContract>,
    /// The compiled partition, so the input can be checked against its schema before any policy
    /// is consulted. Absent where there is nothing compiled yet — a routing test, a plane that
    /// refuses the request before it reaches a ledger.
    pub evaluator: Option<&'a dyn Evaluator>,
}

impl<'a> PartitionTarget<'a> {
    /// A partition that accepts no input and has nothing compiled.
    pub fn new(name: &'a str, language: &'a str) -> Self {
        Self {
            name,
            language,
            input: None,
            evaluator: None,
        }
    }

    /// The input contract this partition's manifest declares.
    #[must_use]
    pub fn accepting(mut self, input: Option<&'a InputContract>) -> Self {
        self.input = input;

        self
    }

    /// The compiled partition that will answer, and check the input first.
    #[must_use]
    pub fn evaluated_by(mut self, evaluator: &'a dyn Evaluator) -> Self {
        self.evaluator = Some(evaluator);

        self
    }
}

/// One question, before any partition has been chosen.
///
/// Every input a caller stated, plus the routing that decides what each partition of the profile
/// actually sees. It is deliberately **not** a [`Query`]: a `Query` is what one evaluator reads,
/// and the same one cannot be handed to every partition — an input belongs to the partition it
/// names, and Cedar reads an action's properties somewhere Rego does not.
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
    /// The inputs the request carries, by the partition each is addressed to.
    ///
    /// Shared, not copied. A boxcarred request may hold 256 evaluations and most of them state no
    /// inputs of their own, so they all read the request's defaults — and a deep copy per
    /// evaluation turned a one-megabyte entity store into hundreds of megabytes before a single
    /// policy had been consulted. Each evaluation that inherits now holds a handle to the same
    /// map; only one that states its own pays for its own.
    pub partition_inputs: std::sync::Arc<PartitionInputs>,
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
    /// Everything a caller could have got wrong is settled here, **before a single policy is
    /// consulted**: an input addressed to a partition this profile does not hold, to one that
    /// accepts none, of a type nobody registered, of the wrong type for the partition, of the
    /// wrong shape for the type, or one the partition's schema refuses. Each of those is a bad
    /// request and not a deny, and telling them apart is the difference between a caller fixing
    /// their payload and a caller reading through policies that were never the problem.
    ///
    /// Then, for each partition of the profile, in the profile's own order:
    ///
    /// | | |
    /// | --- | --- |
    /// | `partition_inputs[name]` | that input, normalised into what its runtime reads |
    /// | nothing addressed to it, `required: false` | the type's empty input |
    /// | nothing addressed to it, `required: true` | **refused**, naming the partition |
    /// | no input contract at all | nothing — and anything addressed to it was already refused |
    ///
    /// Every partition receives `subject`, `resource`, `action` and `context` whole. Cedar
    /// additionally receives `action.properties` as `context.action`, because that is the only
    /// door into a Cedar policy; Rego reads them where it always did, at
    /// `input.action.properties`.
    pub fn route(&self, partitions: &[PartitionTarget<'_>]) -> Result<Vec<Query>, Malformed> {
        self.check_addressing(partitions)?;

        let mut queries = Vec::with_capacity(partitions.len());
        for target in partitions {
            let input = self.input_for(target)?;
            queries.push(self.materialize(target, input));
        }

        Ok(queries)
    }

    /// Every input the caller stated reaches a partition that can read it.
    ///
    /// Run over what the caller wrote rather than over the profile, because this is the half that
    /// is about the caller's mistakes: a name nobody holds, a type nobody registered. Silence
    /// would be the wrong answer to all of them — an input the plane ignored looks, from the
    /// caller's side, exactly like an input a policy ignored.
    fn check_addressing(&self, partitions: &[PartitionTarget<'_>]) -> Result<(), Malformed> {
        if self.partition_inputs.len() > crate::input::MAX_PARTITION_INPUTS {
            return Err(malformed(
                "partition_input_too_large",
                format!(
                    "the request addresses {} partitions and this plane accepts {}",
                    self.partition_inputs.len(),
                    crate::input::MAX_PARTITION_INPUTS
                ),
            ));
        }

        for (name, body) in self.partition_inputs.iter() {
            let Some(target) = partitions.iter().find(|held| held.name == name) else {
                return Err(malformed(
                    "partition_unknown",
                    format!(
                        "`partition_inputs` names `{name}`, which this profile does not hold (it \
                         holds: {}). An input supplies data to a partition the profile already \
                         decided on; it cannot add one",
                        names(partitions)
                    ),
                ));
            };
            let Some(contract) = target.input else {
                return Err(malformed(
                    "partition_input_unsupported",
                    format!(
                        "the partition `{name}` declares no input, and this request addresses it: \
                         what a partition reads is the ledger's decision, and a partition that \
                         asked for nothing would have nowhere to put this"
                    ),
                ));
            };
            let Some(kind) = named(&body.kind) else {
                return Err(malformed(
                    "partition_input_type_required",
                    format!(
                        "`partition_inputs.{name}.type` is required: it states what this data is, \
                         and is checked against the `{}` the ledger declares",
                        contract.r#type
                    ),
                ));
            };
            let Some(registered) = crate::input::input_type(&kind) else {
                return Err(malformed(
                    "partition_input_type_unknown",
                    format!(
                        "`{kind}` is not an input type this build implements (it implements: {}). \
                         An input type is a contract Permguard implements, not a name a caller \
                         invents",
                        crate::input::registered()
                    ),
                ));
            };
            if kind != contract.r#type {
                return Err(malformed(
                    "partition_input_type_mismatch",
                    format!(
                        "the partition `{name}` accepts `{}` and this request states `{kind}`: the \
                         type says what the data is, and it is checked, never obeyed",
                        contract.r#type
                    ),
                ));
            }
            if registered.runtime() != target.language {
                return Err(malformed(
                    "partition_input_type_incompatible",
                    format!(
                        "`{kind}` is read by `{}` and the partition `{name}` runs `{}`: an input \
                         is written for one runtime, and no other can read it",
                        registered.runtime(),
                        target.language
                    ),
                ));
            }
        }

        Ok(())
    }

    /// What one partition is given, by the table in [`Asking::route`].
    fn input_for(&self, target: &PartitionTarget<'_>) -> Result<PartitionData, Malformed> {
        // A partition that declares no input reads none. Anything addressed to it was refused by
        // `check_addressing`, so there is nothing to lose here.
        let Some(contract) = target.input else {
            return Ok(PartitionData::Absent);
        };
        let registered = crate::input::input_type(&contract.r#type).ok_or_else(|| {
            malformed(
                "partition_input_type_unknown",
                format!(
                    "the partition `{}` declares the input type `{}`, which this build does not \
                     implement",
                    target.name, contract.r#type
                ),
            )
        })?;

        let Some(body) = self.partition_inputs.get(target.name) else {
            if contract.required {
                return Err(malformed(
                    "partition_input_required",
                    format!(
                        "the partition `{}` requires an input of type `{}` and this request \
                         addresses it with none: its policies read that data, and deciding \
                         against an empty one would deny for the wrong reason",
                        target.name, contract.r#type
                    ),
                ));
            }

            return Ok(registered.empty());
        };

        let data = match &body.data {
            Some(data) if !data.is_null() => data,
            _ => {
                return Err(malformed(
                    "partition_input_malformed",
                    format!(
                        "`partition_inputs.{}.data` is required: state the data, or address the \
                         partition with nothing at all",
                        target.name
                    ),
                ));
            }
        };

        // Size and depth before shape, and shape before schema: each check is cheaper than the
        // one after it, and recursing into caller-supplied JSON to find out how deep it goes is
        // how a process ends without ever reaching a policy.
        crate::input::within_limits(data).map_err(|why| {
            malformed(
                "partition_input_too_large",
                format!("`partition_inputs.{}`: {why}", target.name),
            )
        })?;
        let normalized = registered.normalize(data).map_err(|why| {
            malformed(
                "partition_input_malformed",
                format!("`partition_inputs.{}.data`: {why}", target.name),
            )
        })?;
        if let Some(evaluator) = target.evaluator {
            evaluator.check_input(&normalized).map_err(|why| {
                malformed(
                    "partition_input_schema",
                    format!("`partition_inputs.{}`: {why}", target.name),
                )
            })?;
        }

        Ok(normalized)
    }

    /// The query one partition evaluates.
    pub fn materialize(&self, target: &PartitionTarget<'_>, input: PartitionData) -> Query {
        let mut context = self.context.clone();

        // Cedar has nowhere else to read them from. Absent when there are none, so a schema that
        // never declared `context.action` keeps validating the requests it always did.
        if target.language == crate::cedar::NAME && !self.action.properties.is_empty() {
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
            input,
        }
    }
}

fn names(partitions: &[PartitionTarget<'_>]) -> String {
    partitions
        .iter()
        .map(|partition| partition.name)
        .collect::<Vec<&str>>()
        .join(", ")
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
    /// This evaluation's own inputs. Present — even empty — it **replaces** the top-level ones
    /// whole, exactly as `subject` and `context` do: an evaluation that restates a field restates
    /// it, and merging two maps key by key would make what a partition reads depend on a rule
    /// nobody wrote down.
    #[serde(default)]
    pub partition_inputs: Option<PartitionInputs>,
    /// Accepted only to be refused. See [`CheckRequest::entities`].
    #[serde(default)]
    pub entities: Option<Value>,
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
    /// What each partition of the profile is given, by the partition's own name.
    ///
    /// The only way a request supplies runtime data, and it is addressed by name because a name is
    /// the only identity that distinguishes two partitions of the same language. What a caller
    /// cannot do is choose *which policies* answer: a profile decides that, and an input only
    /// supplies data to a partition already in it.
    #[serde(default)]
    pub partition_inputs: PartitionInputs,
    /// The removed `entities` extension, accepted **only so it can be refused**.
    ///
    /// It used to carry one graph for the whole request, addressed to a runtime, plus per-partition
    /// overrides. Ignoring it now would be the one unacceptable outcome: a caller that sent an
    /// entity graph would watch it vanish and the request be decided against an empty world —
    /// permitted or denied for a reason nothing on the wire explains. So it is read, and refused
    /// by name, and never converted into anything.
    #[serde(default)]
    pub entities: Option<Value>,
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

impl std::fmt::Display for Malformed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for Malformed {}

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

        // The removed extension, refused wherever it appears. Before anything else, because a
        // caller who sent one is asking a question about a world this contract no longer accepts,
        // and every other complaint about their payload would be beside the point.
        self.removed()?;

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
        // Cloned once, here, and shared by every evaluation that does not state its own. `asked`
        // borrows the request, so one copy is unavoidable; 256 were not.
        let defaults = std::sync::Arc::new(self.partition_inputs.clone());
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
                    self.asking_of(Some(evaluation), index, &defaults)?,
                    evaluation.request_id.clone(),
                ));
            }
        } else {
            queries.push((self.asking_of(None, 0, &defaults)?, None));
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

    /// The fields this contract used to accept and no longer does.
    ///
    /// # Why this is a function and not four lines inside `asked`
    ///
    /// A transport that cannot *carry* a removed field is a transport that silently drops it. The
    /// gRPC binding has no `entities` in its schema — the tag is reserved — so a client mapping a
    /// payload onto the generated message dropped it on the floor and the server answered a
    /// request it never saw the whole of: `permit`, against an empty world, over one transport and
    /// `field_removed` over the other. The client calls this before it converts, so both say the
    /// same sentence, and the next field this contract retires is refused on both the day it is
    /// retired here.
    pub fn removed(&self) -> Result<(), Malformed> {
        for (where_it_is, held) in std::iter::once(("the request".to_owned(), &self.entities))
            .chain(
                self.evaluations
                    .iter()
                    .enumerate()
                    .map(|(index, evaluation)| {
                        (format!("evaluation {index}"), &evaluation.entities)
                    }),
            )
        {
            if held.is_some() {
                return Err(malformed(
                    "field_removed",
                    format!(
                        "`entities` is no longer accepted ({where_it_is} carries one): address \
                         runtime-specific data through `partition_inputs`, by the name of the \
                         partition that reads it"
                    ),
                ));
            }
        }

        Ok(())
    }

    fn asking_of(
        &self,
        evaluation: Option<&EvaluationBody>,
        index: usize,
        defaults: &std::sync::Arc<PartitionInputs>,
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
        // Present, even empty, an evaluation's own map replaces the top-level one whole. The same
        // rule as every other field: what an evaluation states, it states. An evaluation that
        // states nothing shares the defaults rather than copying them.
        let partition_inputs = match evaluation.and_then(|e| e.partition_inputs.as_ref()) {
            Some(own) => std::sync::Arc::new(own.clone()),
            None => std::sync::Arc::clone(defaults),
        };

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
            partition_inputs,
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
                "partition_inputs": {
                    "admin-cedar": {
                        "type": "permguard.cedar.entities.v1",
                        "data": [{"uid": {"type": "Group", "id": "g"}}]
                    }
                },
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
        // The input is still the caller's, addressed by name; what it becomes is decided when the
        // partition it names is materialised.
        assert_eq!(resolved.queries[0].0.partition_inputs.len(), 1);
        assert!(
            resolved.queries[0]
                .0
                .partition_inputs
                .contains_key("admin-cedar")
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
    #![allow(clippy::expect_used)]

    use super::*;
    use crate::input::{CEDAR_ENTITIES_V1, REGO_DATA_V1};
    use serde_json::json;

    fn contract(kind: &str, required: bool) -> InputContract {
        InputContract {
            r#type: kind.to_owned(),
            required,
        }
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
        payload["action"] = json!({"name": "release:create", "properties": {"risk": "high"}});
        let asking = asking(payload).expect("it is well formed");

        let for_cedar = asking.materialize(
            &PartitionTarget::new("admin-cedar", "cedar"),
            PartitionData::Absent,
        );
        assert_eq!(
            for_cedar.context[RESERVED_CONTEXT_ACTION],
            json!({"risk": "high"}),
            "the only door into a Cedar policy"
        );
        assert_eq!(
            for_cedar.action.properties["risk"],
            json!("high"),
            "and still on the action itself"
        );

        let for_rego = asking.materialize(
            &PartitionTarget::new("admin-rego", "rego"),
            PartitionData::Absent,
        );
        assert!(
            !for_rego.context.contains_key(RESERVED_CONTEXT_ACTION),
            "Rego reads input.action.properties, and inventing a context key would be a second \
             place to read the same thing"
        );
        assert_eq!(for_rego.action.properties["risk"], json!("high"));
    }

    #[test]
    fn an_action_without_properties_adds_nothing_to_the_context() {
        let asking = asking(plain()).expect("it is well formed");
        let materialized = asking.materialize(
            &PartitionTarget::new("admin-cedar", "cedar"),
            PartitionData::Absent,
        );

        assert!(
            !materialized.context.contains_key(RESERVED_CONTEXT_ACTION),
            "a schema that never declared `context.action` keeps validating what it always did"
        );
    }

    #[test]
    fn a_caller_may_not_write_the_reserved_context_key() {
        let mut payload = plain();
        payload["context"] = json!({"action": {"risk": "low"}});
        let refused = asking(payload).expect_err("it is Permguard's to write");

        assert_eq!(refused.code, "field_reserved");
    }

    // --- the partition input contract -------------------------------------------------------

    #[test]
    fn each_partition_reads_the_input_addressed_to_it_and_no_other() {
        // The rule the whole contract rests on. Cedar's store and Rego's document are both here,
        // each addressed by name, and neither partition sees the other's.
        let mut payload = plain();
        payload["partition_inputs"] = json!({
            "admin-cedar": {
                "type": CEDAR_ENTITIES_V1,
                "data": [{"uid": {"type": "Team", "id": "payments"}, "attrs": {}, "parents": []}]
            },
            "admin-rego": {
                "type": REGO_DATA_V1,
                "data": {"frozen_services": ["payments-api"]}
            }
        });
        let cedar_input = contract(CEDAR_ENTITIES_V1, false);
        let rego_input = contract(REGO_DATA_V1, false);
        let queries = asking(payload)
            .expect("it is well formed")
            .route(&[
                PartitionTarget::new("admin-cedar", "cedar").accepting(Some(&cedar_input)),
                PartitionTarget::new("admin-rego", "rego").accepting(Some(&rego_input)),
            ])
            .expect("both are addressed by name");

        assert_eq!(queries[0].input.cedar_entities().len(), 1);
        assert!(
            queries[0].input.rego_data().is_none(),
            "Cedar was handed no document"
        );
        assert_eq!(
            queries[1].input.rego_data().expect("its own document")["frozen_services"],
            json!(["payments-api"])
        );
        assert!(
            queries[1].input.cedar_entities().is_empty(),
            "and Rego no store"
        );
        // And the common fields reached both, whole.
        for query in &queries {
            assert_eq!(query.subject.id, "alice");
            assert_eq!(query.resource.id, "payments-api");
            assert_eq!(query.action.name, "release:create");
        }
    }

    #[test]
    fn two_cedar_partitions_receive_two_different_stores() {
        // Same runtime, same shape, different worlds. There is no addressing by language, so the
        // only thing that could deliver these is the name — and it does, separately.
        let mut payload = plain();
        payload["partition_inputs"] = json!({
            "org-chart": {"type": CEDAR_ENTITIES_V1,
                          "data": [{"uid": {"type": "Team", "id": "payments"}}]},
            "catalogue": {"type": CEDAR_ENTITIES_V1,
                          "data": [{"uid": {"type": "Service", "id": "a"}},
                                   {"uid": {"type": "Service", "id": "b"}}]}
        });
        let input = contract(CEDAR_ENTITIES_V1, false);
        let queries = asking(payload)
            .expect("it is well formed")
            .route(&[
                PartitionTarget::new("org-chart", "cedar").accepting(Some(&input)),
                PartitionTarget::new("catalogue", "cedar").accepting(Some(&input)),
            ])
            .expect("each is addressed by its own name");

        assert_eq!(queries[0].input.cedar_entities().len(), 1);
        assert_eq!(queries[1].input.cedar_entities().len(), 2);
        assert_ne!(
            queries[0].input.cedar_entities(),
            queries[1].input.cedar_entities(),
            "neither sees the other's"
        );
    }

    #[test]
    fn a_partition_nobody_addressed_reads_its_own_types_empty_input() {
        let cedar_input = contract(CEDAR_ENTITIES_V1, false);
        let rego_input = contract(REGO_DATA_V1, false);
        let queries = asking(plain())
            .expect("it is well formed")
            .route(&[
                PartitionTarget::new("admin-cedar", "cedar").accepting(Some(&cedar_input)),
                PartitionTarget::new("admin-rego", "rego").accepting(Some(&rego_input)),
            ])
            .expect("optional inputs may be absent");

        assert!(queries[0].input.cedar_entities().is_empty());
        assert!(
            queries[1]
                .input
                .rego_data()
                .expect("an empty document")
                .is_empty(),
            "an empty document, not an absent one: a rule reading a path through it answers no"
        );
    }

    #[test]
    fn an_input_addressed_to_a_partition_the_profile_does_not_hold_is_refused() {
        let mut payload = plain();
        payload["partition_inputs"] = json!({"nowhere": {"type": CEDAR_ENTITIES_V1, "data": []}});
        let input = contract(CEDAR_ENTITIES_V1, false);
        let refused = asking(payload)
            .expect("it is well formed")
            .route(&[PartitionTarget::new("admin-cedar", "cedar").accepting(Some(&input))])
            .expect_err("nobody would have read it");

        assert_eq!(refused.code, "partition_unknown");
        assert!(
            refused.message.contains("admin-cedar"),
            "{}",
            refused.message
        );
    }

    #[test]
    fn an_input_addressed_to_a_partition_that_accepts_none_is_refused() {
        let mut payload = plain();
        payload["partition_inputs"] =
            json!({"admin-cedar": {"type": CEDAR_ENTITIES_V1, "data": []}});
        let refused = asking(payload)
            .expect("it is well formed")
            .route(&[PartitionTarget::new("admin-cedar", "cedar")])
            .expect_err("the partition declares no input");

        assert_eq!(refused.code, "partition_input_unsupported");
    }

    #[test]
    fn a_type_is_stated_registered_and_the_one_the_ledger_declares() {
        let input = contract(CEDAR_ENTITIES_V1, false);
        let target = || PartitionTarget::new("admin-cedar", "cedar").accepting(Some(&input));

        for (stated, code) in [
            (json!({"data": []}), "partition_input_type_required"),
            (
                json!({"type": "  ", "data": []}),
                "partition_input_type_required",
            ),
            (
                json!({"type": "acme.entities.v1", "data": []}),
                "partition_input_type_unknown",
            ),
            (
                // Registered, and not this partition's. The assertion is checked, never obeyed:
                // it does not switch the parser to Rego's.
                json!({"type": REGO_DATA_V1, "data": {}}),
                "partition_input_type_mismatch",
            ),
        ] {
            let mut payload = plain();
            payload["partition_inputs"] = json!({"admin-cedar": stated});
            let refused = asking(payload)
                .expect("it is well formed")
                .route(&[target()])
                .expect_err("the type does not hold up");

            assert_eq!(refused.code, code, "{}", refused.message);
        }
    }

    #[test]
    fn a_type_written_for_another_runtime_is_refused_even_when_the_ledger_declared_it() {
        // A manifest this build would have refused at the load gate. Checked again here, because
        // routing may not assume a gate it does not run itself has run.
        let input = contract(REGO_DATA_V1, false);
        let mut payload = plain();
        payload["partition_inputs"] = json!({"admin-cedar": {"type": REGO_DATA_V1, "data": {}}});
        let refused = asking(payload)
            .expect("it is well formed")
            .route(&[PartitionTarget::new("admin-cedar", "cedar").accepting(Some(&input))])
            .expect_err("Cedar cannot read a Rego document");

        assert_eq!(refused.code, "partition_input_type_incompatible");
    }

    #[test]
    fn a_required_input_that_is_absent_is_refused_naming_the_partition() {
        let input = contract(CEDAR_ENTITIES_V1, true);
        let refused = asking(plain())
            .expect("it is well formed")
            .route(&[PartitionTarget::new("admin-cedar", "cedar").accepting(Some(&input))])
            .expect_err("its policies read that store");

        assert_eq!(refused.code, "partition_input_required");
        assert!(
            refused.message.contains("admin-cedar"),
            "{}",
            refused.message
        );
    }

    #[test]
    fn the_shape_of_data_is_the_types_own_and_a_wrong_one_is_refused() {
        for (kind, language, data) in [
            (CEDAR_ENTITIES_V1, "cedar", json!({"not": "an array"})),
            (REGO_DATA_V1, "rego", json!(["not an object"])),
        ] {
            let input = contract(kind, false);
            let mut payload = plain();
            payload["partition_inputs"] = json!({"p": {"type": kind, "data": data}});
            let refused = asking(payload)
                .expect("it is well formed")
                .route(&[PartitionTarget::new("p", language).accepting(Some(&input))])
                .expect_err("the shape is the type's own");

            assert_eq!(refused.code, "partition_input_malformed");
        }
    }

    #[test]
    fn an_input_stated_with_no_data_is_refused_rather_than_read_as_empty() {
        let input = contract(REGO_DATA_V1, false);
        let mut payload = plain();
        payload["partition_inputs"] = json!({"p": {"type": REGO_DATA_V1}});
        let refused = asking(payload)
            .expect("it is well formed")
            .route(&[PartitionTarget::new("p", "rego").accepting(Some(&input))])
            .expect_err("state the data, or address nothing");

        assert_eq!(refused.code, "partition_input_malformed");
    }

    #[test]
    fn an_input_the_partitions_schema_refuses_never_reaches_a_policy() {
        // The evaluator is what holds the compiled schema, so routing asks it — before any policy
        // runs. A schema violation is a bad request, not a deny.
        struct Fussy;
        impl crate::evaluate::Evaluator for Fussy {
            fn evaluate(&self, _query: &Query) -> crate::evaluate::Verdict {
                unreachable!("routing refuses before anything is evaluated")
            }
            fn check_input(&self, input: &PartitionData) -> Result<(), String> {
                if input.cedar_entities().len() > 1 {
                    return Err("this partition declares one entity type".to_owned());
                }

                Ok(())
            }
            fn footprint(&self) -> usize {
                0
            }
            fn policies(&self) -> Vec<String> {
                Vec::new()
            }
        }

        let input = contract(CEDAR_ENTITIES_V1, false);
        let fussy = Fussy;
        let mut payload = plain();
        payload["partition_inputs"] = json!({
            "p": {"type": CEDAR_ENTITIES_V1, "data": [{"uid": {"id": "a"}}, {"uid": {"id": "b"}}]}
        });
        let refused = asking(payload)
            .expect("it is well formed")
            .route(&[PartitionTarget::new("p", "cedar")
                .accepting(Some(&input))
                .evaluated_by(&fussy)])
            .expect_err("the schema refuses it");

        assert_eq!(refused.code, "partition_input_schema");
    }

    #[test]
    fn the_partitions_answer_in_the_profiles_order_and_not_the_payloads() {
        // The JSON names them one way; the profile names them another. What comes back follows
        // the profile, because that is the order the verdicts are combined and reported in.
        let mut payload = plain();
        payload["partition_inputs"] = json!({
            "aaa": {"type": REGO_DATA_V1, "data": {"which": "aaa"}},
            "zzz": {"type": REGO_DATA_V1, "data": {"which": "zzz"}}
        });
        let input = contract(REGO_DATA_V1, false);
        let queries = asking(payload)
            .expect("it is well formed")
            .route(&[
                PartitionTarget::new("zzz", "rego").accepting(Some(&input)),
                PartitionTarget::new("aaa", "rego").accepting(Some(&input)),
            ])
            .expect("both are addressed");

        assert_eq!(
            queries[0].input.rego_data().expect("a document")["which"],
            json!("zzz")
        );
        assert_eq!(
            queries[1].input.rego_data().expect("a document")["which"],
            json!("aaa")
        );
    }

    // --- the removed extension ---------------------------------------------------------------

    #[test]
    fn the_old_entities_field_is_refused_and_not_ignored() {
        // Ignoring it is the one unacceptable outcome: the request would be decided against an
        // empty world, and nothing on the wire would say why.
        let mut payload = plain();
        payload["entities"] = json!({"schema": "cedar", "items": [{"uid": {"type": "Team"}}]});
        let refused = asking(payload).expect_err("the field is gone");

        assert_eq!(refused.code, "field_removed");
        assert!(
            refused.message.contains("partition_inputs"),
            "and it says where to put it: {}",
            refused.message
        );
    }

    #[test]
    fn the_old_entities_field_is_refused_inside_an_evaluation_too() {
        let mut payload = plain();
        payload["evaluations"] = json!([
            {"request_id": "one"},
            {"request_id": "two", "entities": {"items": []}}
        ]);
        let refused = asking(payload).expect_err("the field is gone");

        assert_eq!(refused.code, "field_removed");
        assert!(
            refused.message.contains("evaluation 1"),
            "{}",
            refused.message
        );
    }

    // --- boxcarring ---------------------------------------------------------------------------

    #[test]
    fn a_batch_inherits_an_action_whole_and_overrides_it_whole() {
        let mut payload = json!({
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
        let object = payload.as_object_mut().expect("an object");
        object.insert("zone".to_owned(), json!("z"));
        object.insert("ledger".to_owned(), json!("l"));
        let request: CheckRequest = serde_json::from_value(payload).expect("it parses");
        let asked = request.asked(256).expect("it is well formed");

        let cedar = PartitionTarget::new("admin-cedar", "cedar");
        let inherited = asked.queries[0]
            .0
            .materialize(&cedar, PartitionData::Absent);
        assert_eq!(inherited.action.name, "release:create");
        assert_eq!(
            inherited.context[RESERVED_CONTEXT_ACTION],
            json!({"risk": "high"})
        );

        let own = asked.queries[1]
            .0
            .materialize(&cedar, PartitionData::Absent);
        assert_eq!(own.action.name, "release:signoff");
        assert_eq!(
            own.context[RESERVED_CONTEXT_ACTION],
            json!({"risk": "low"}),
            "an evaluation's action brings its own properties"
        );

        // An evaluation that names an action and no properties has none: the two travel together,
        // so a `risk` from the top level cannot end up describing a different action.
        let bare = asked.queries[2]
            .0
            .materialize(&cedar, PartitionData::Absent);
        assert_eq!(bare.action.name, "deployment:rollback");
        assert!(!bare.context.contains_key(RESERVED_CONTEXT_ACTION));
    }

    #[test]
    fn an_evaluation_inherits_the_top_level_inputs_and_replaces_them_whole() {
        let mut payload = json!({
            "subject": {"type": "User", "id": "alice"},
            "resource": {"type": "Service", "id": "payments-api"},
            "action": {"name": "release:create"},
            "partition_inputs": {
                "admin-rego": {"type": REGO_DATA_V1, "data": {"from": "the top"}}
            },
            "evaluations": [
                {"request_id": "inherits"},
                {"request_id": "states-its-own",
                 "partition_inputs": {
                     "admin-rego": {"type": REGO_DATA_V1, "data": {"from": "the evaluation"}}
                 }},
                {"request_id": "states-none", "partition_inputs": {}}
            ]
        });
        let object = payload.as_object_mut().expect("an object");
        object.insert("zone".to_owned(), json!("z"));
        object.insert("ledger".to_owned(), json!("l"));
        let request: CheckRequest = serde_json::from_value(payload).expect("it parses");
        let asked = request.asked(256).expect("it is well formed");

        let input = contract(REGO_DATA_V1, false);
        let target = || PartitionTarget::new("admin-rego", "rego").accepting(Some(&input));
        let read = |index: usize| {
            asked.queries[index]
                .0
                .route(&[target()])
                .expect("it routes")
                .remove(0)
        };

        assert_eq!(
            read(0).input.rego_data().expect("a document")["from"],
            json!("the top"),
            "what an evaluation does not state, it inherits"
        );
        assert_eq!(
            read(1).input.rego_data().expect("a document")["from"],
            json!("the evaluation"),
            "and what it states, it states"
        );
        assert!(
            read(2).input.rego_data().expect("a document").is_empty(),
            "an empty map replaces the defaults whole: stating none is stating none, and merging \
             key by key would make what a partition reads depend on a rule nobody wrote"
        );
    }

    /// A batch that inherits its inputs holds **one** copy of them, not one per evaluation.
    ///
    /// Not a claim about intent — a pointer comparison. With the default of 256 evaluations, a
    /// one-megabyte entity store deep-copied per evaluation was hundreds of megabytes allocated
    /// before a single policy had been consulted, and every byte of it identical.
    #[test]
    fn evaluations_that_inherit_their_inputs_share_them() {
        let mut payload = plain();
        payload["partition_inputs"] = json!({
            "p": {"type": REGO_DATA_V1, "data": {"from": "the top"}}
        });
        payload["evaluations"] = json!([
            {"request_id": "one"},
            {"request_id": "two"},
            {"request_id": "three", "partition_inputs": {
                "p": {"type": REGO_DATA_V1, "data": {"from": "its own"}}
            }}
        ]);
        let object = payload.as_object_mut().expect("an object");
        object.insert("zone".to_owned(), json!("z"));
        object.insert("ledger".to_owned(), json!("l"));
        let request: CheckRequest = serde_json::from_value(payload).expect("it parses");
        let asked = request.asked(256).expect("it is well formed");

        assert!(
            std::sync::Arc::ptr_eq(
                &asked.queries[0].0.partition_inputs,
                &asked.queries[1].0.partition_inputs
            ),
            "two evaluations that inherit read the very same map"
        );
        assert!(
            !std::sync::Arc::ptr_eq(
                &asked.queries[0].0.partition_inputs,
                &asked.queries[2].0.partition_inputs
            ),
            "and one that states its own has its own"
        );
        // Sharing is not aliasing the wrong thing: each still reads what it should.
        assert_eq!(
            asked.queries[1].0.partition_inputs["p"]
                .data
                .as_ref()
                .expect("data")["from"],
            json!("the top")
        );
        assert_eq!(
            asked.queries[2].0.partition_inputs["p"]
                .data
                .as_ref()
                .expect("data")["from"],
            json!("its own")
        );
    }

    // --- the rest of the contract --------------------------------------------------------------

    #[test]
    fn a_principal_is_stated_whole_or_refused() {
        for half in [
            json!({"type": "workload"}),
            json!({"id": "gateway"}),
            json!({"type": "workload", "id": "   "}),
            json!({}),
        ] {
            let mut payload = plain();
            payload["principal"] = half;
            let refused = asking(payload).expect_err("half a name records nobody");

            assert_eq!(refused.code, "field_required");
        }

        let mut payload = plain();
        payload["principal"] = json!({"type": "workload", "id": "gateway"});
        assert!(asking(payload).is_ok(), "and stated whole, it is accepted");
    }

    #[test]
    fn principal_properties_are_refused_rather_than_ignored() {
        let mut payload = plain();
        payload["principal"] = json!({"type": "w", "id": "g", "properties": {"tier": 1}});
        let refused = asking(payload).expect_err("nothing reads them");

        assert_eq!(refused.code, "field_unsupported");
    }

    #[test]
    fn an_input_beyond_the_bounds_is_refused_before_it_is_walked() {
        let input = contract(REGO_DATA_V1, false);
        let mut deep = json!(1);
        for _ in 0..(crate::input::MAX_INPUT_DEPTH + 4) {
            deep = json!({"down": deep});
        }
        let mut payload = plain();
        payload["partition_inputs"] = json!({"p": {"type": REGO_DATA_V1, "data": deep}});
        let refused = asking(payload)
            .expect("it is well formed")
            .route(&[PartitionTarget::new("p", "rego").accepting(Some(&input))])
            .expect_err("it nests past the bound");

        assert_eq!(refused.code, "partition_input_too_large");
    }

    #[test]
    fn a_request_addressing_more_partitions_than_the_bound_is_refused() {
        let mut inputs = serde_json::Map::new();
        for index in 0..=crate::input::MAX_PARTITION_INPUTS {
            inputs.insert(
                format!("p{index}"),
                json!({"type": REGO_DATA_V1, "data": {}}),
            );
        }
        let mut payload = plain();
        payload["partition_inputs"] = Value::Object(inputs);
        let refused = asking(payload)
            .expect("it is well formed")
            .route(&[PartitionTarget::new("p0", "rego")])
            .expect_err("that is not addressing partitions");

        assert_eq!(refused.code, "partition_input_too_large");
    }
}
