// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The `permguard.api.pdp.native.v1` payloads: what a PEP sends, and what it gets back.
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
//! So the types and [`CheckRequest::asked`] are here, next to [`Query`](crate::evaluate::Query), and the
//! serving half — routing, tracing, disclosure — stays in the plane.
//!
//! # An interface Permguard owns
//!
//! `permguard.api.pdp.native.v1` is Permguard's **stateless** policy decision interface, and the
//! one this module describes. It is designed for
//! profile-based decisions evaluated across one or more heterogeneous policy partitions, and it is
//! **not** an implementation of, nor a compatibility claim for, any other authorization API.
//!
//! The shape will look familiar to anyone who has read an authorization API — a subject, an
//! action, a resource, a context in; a decision and a reason out — because that shape is the
//! obvious one for the question, and good designs converge. What follows from *owning* the
//! contract is that the parts nobody else specifies are specified here, and can change when
//! Permguard needs them to, without anyone having to ask whether some other document still holds:
//!
//! | | |
//! | --- | --- |
//! | policy store | **`zone` and `ledger` in the payload**, required — never the URL |
//! | which policies answer | **`profile`**, naming the partitions of the ledger |
//! | runtime data | **`partition_inputs`**, addressed to a partition by name |
//! | who is asking | **`principal`**, recorded for the audit, distinct from the subject |
//! | reasons | **`reason_admin` / `reason_user`**, the disclosure split the whole server speaks |
//! | many questions at once | **`evaluations[]`** with `options.evaluations_semantic` |
//!
//! One endpoint that carries the store in the body is the choice a caller asked for: a PEP that
//! talks to several ledgers keeps one address and one connection pool, and the ledger becomes data
//! — which is also what makes a request loggable and auditable as one record. A payload that names
//! neither is **refused**, never answered against a default: silently deciding against the wrong
//! policy store is the one failure mode nobody can debug.
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
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::evaluate::{Action, Entity};
pub use crate::input::{PartitionData, PartitionInputBody, PartitionInputs};

/// The default profile, when a request names none.
pub const DEFAULT_PROFILE: &str = "default";

/// The name of this interface, as a ledger's `profiles.<name>.type` declares it and as the
/// discovery document identifies it.
///
/// `native` says which of Permguard's two decision interfaces this is: the stateless one, which
/// answers from the request alone. The other is
/// [`crate::temporal::INTERFACE`], which answers from a durable history as well.
///
/// The former spelling, `permguard.pdp.v1`, is still *accepted* in a ledger's manifest so a
/// workspace written before the rename keeps loading — see
/// [`permguard_objects::manifest::PROFILE_PDP_V1`]. It is never generated and never advertised:
/// there is one contract here, and this is its name.
pub const INTERFACE: &str = permguard_objects::manifest::PROFILE_PDP_NATIVE_V1;

/// Where a data plane publishes what this interface offers.
///
/// Named for the interface and its version, not for a standard: what is served here is
/// this interface and nothing else, and a path that said otherwise would be promising a
/// document somebody else specifies.
pub const CONFIGURATION_PATH: &str = "/.well-known/permguard-pdp-v1-configuration";

/// Where one question is asked.
pub const EVALUATION_PATH: &str = "/access/v1/evaluation";

/// Where many are, in one exchange.
pub const EVALUATIONS_PATH: &str = "/access/v1/evaluations";

/// The largest magnitude a number may have on either transport: 2^53, what the IEEE-754 double of
/// `google.protobuf.Value` holds exactly (IFACE-06).
pub const EXACT_INTEGER: u64 = 9_007_199_254_740_992;

/// `value` in the scalar domain both transports carry exactly (IFACE-06), or the refusal.
///
/// REST carries JSON, which spells an integer of any size and `42.0` apart from `42`; gRPC
/// carries a double, which holds neither distinction. So a number past ±2^53 is refused on REST
/// as it is on gRPC, and a whole number is the integer it is: `42.0` reaches a policy as `42`
/// over both, as the gRPC adapter already reads it. A decimal spelling with more digits than a
/// double holds was already read as the nearest double, on both transports alike. Every other
/// value is unchanged.
pub fn lossless(value: Value) -> Result<Value, Malformed> {
    let refuse = |number: &serde_json::Number| Malformed {
        code: permguard_core::codes::notp::VALUE_UNREPRESENTABLE,
        message: format!(
            "`{number}` is beyond the numbers both transports carry exactly: numbers travel \
             only inside ±2^53, which is what an IEEE-754 double holds exactly; send anything \
             larger as the string it is"
        ),
    };
    Ok(match value {
        Value::Number(number) => {
            if let Some(integer) = number.as_i64() {
                if integer.unsigned_abs() > EXACT_INTEGER {
                    return Err(refuse(&number));
                }
                Value::Number(number)
            } else if let Some(integer) = number.as_u64() {
                if integer > EXACT_INTEGER {
                    return Err(refuse(&number));
                }
                Value::Number(number)
            } else {
                let double = number.as_f64().ok_or_else(|| refuse(&number))?;
                #[allow(clippy::cast_precision_loss)]
                if !double.is_finite() || double.abs() > EXACT_INTEGER as f64 {
                    return Err(refuse(&number));
                }
                if double.fract() == 0.0 {
                    // Inside ±2^53, so the conversion is exact.
                    #[allow(clippy::cast_possible_truncation)]
                    Value::Number(serde_json::Number::from(double as i64))
                } else {
                    Value::Number(number)
                }
            }
        }
        Value::Array(items) => Value::Array(
            items
                .into_iter()
                .map(lossless)
                .collect::<Result<Vec<Value>, Malformed>>()?,
        ),
        Value::Object(members) => Value::Object(
            members
                .into_iter()
                .map(|(name, value)| Ok((name, lossless(value)?)))
                .collect::<Result<Map<String, Value>, Malformed>>()?,
        ),
        other => other,
    })
}

/// The first number literal of the JSON text `bytes` that is not a whole number but whose nearest
/// IEEE-754 double is one (BUG-0181), or `None`.
///
/// Both transports carry a number as a double, and a whole double reaches a policy as the integer
/// it is. A literal such as `4.9999999999999999`, or `1e-400`, would therefore reach it as `5`, or
/// `0`: a value the caller did not write, on the far side of a threshold. Only the literal says
/// what was meant, so the check is made on the text, before the value is read; a literal that
/// denotes a whole number, `5.0`, `5e0`, `50e-1`, is the integer it is and is not this.
#[must_use]
pub fn rounded_to_whole(bytes: &[u8]) -> Option<String> {
    permguard_canonical::jcs::number_literals(bytes)
        .into_iter()
        .find(|literal| {
            !denotes_whole(literal)
                && literal
                    .parse::<f64>()
                    .is_ok_and(|double| double.is_finite() && double.fract() == 0.0)
        })
}

/// Whether a JSON number literal denotes a whole number, read as decimal digits and never through
/// a double: `5`, `5.0`, `5e0`, `50e-1` and `0.0e-999` do; `4.9999999999999999` and `1e-400` do
/// not. Text that is not a number literal is not whole.
#[must_use]
pub fn denotes_whole(literal: &str) -> bool {
    let unsigned = literal.strip_prefix('-').unwrap_or(literal);
    let (mantissa, exponent) = match unsigned.find(['e', 'E']) {
        Some(at) => (&unsigned[..at], &unsigned[at + 1..]),
        None => (unsigned, "0"),
    };
    let (integer, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    let digits: Vec<u8> = integer.bytes().chain(fraction.bytes()).collect();
    if integer.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return false;
    }
    // Zero, however it is spelled, is whole.
    let Some(last) = digits.iter().rposition(|byte| *byte != b'0') else {
        return true;
    };
    let (negative, magnitude) = match exponent.as_bytes().first() {
        Some(b'-') => (true, &exponent[1..]),
        Some(b'+') => (false, &exponent[1..]),
        _ => (false, exponent),
    };
    if magnitude.is_empty() || !magnitude.bytes().all(|byte| byte.is_ascii_digit()) {
        return false;
    }
    // The value is the digit string times 10^(exponent - fraction length); it is whole when the
    // digit string's trailing zeros cover a negative power. The magnitude is clamped well past
    // any digit count a body can hold, so a long exponent cannot overflow the arithmetic.
    let significant = magnitude.trim_start_matches('0');
    let magnitude = if significant.len() > 18 {
        i128::MAX / 4
    } else {
        significant.parse::<i128>().unwrap_or(0)
    };
    let exponent = if negative { -magnitude } else { magnitude };
    let trailing_zeros = i128::try_from(digits.len() - 1 - last).unwrap_or(i128::MAX / 4);
    let fraction = i128::try_from(fraction.len()).unwrap_or(i128::MAX / 4);
    exponent - fraction + trailing_zeros >= 0
}

/// What this interface offers, as a caller configures itself from it.
///
/// # The rule for this list
///
/// A capability is a **promise**, so each of these names something implemented here, tested here,
/// and answered identically over both transports. Nothing is listed because it is planned, and
/// nothing is listed that is only half-true: a caller that reads this document and is then refused
/// by the same server has been lied to, which is worse than a document that said less.
///
/// | URN | What it promises | Where it is proved |
/// | --- | --- | --- |
/// | `store-in-payload` | `zone` and `ledger` name the store in the body, not the URL | `a_request_that_names_no_store_is_refused_by_name` |
/// | `profile-selection` | `profile` chooses which partitions of the ledger answer | the `gateway` profile in `examples/basics` |
/// | `partition-inputs` | runtime data is addressed to a partition by name | `each_partition_reads_the_input_addressed_to_it_and_no_other` |
/// | `principal` | who is *asking*, recorded for the audit, distinct from the subject | `a_principal_is_stated_whole_or_refused` |
/// | `structured-reasons` | every decision carries `reason_admin` and `reason_user` | `a_deny_is_an_answer_and_says_why` |
/// | `boxcarring` | `evaluations[]`, resolved by `options.evaluations_semantic` | `a_batch_resolves_by_the_operator_its_semantic_names` |
pub const CAPABILITIES: [&str; 6] = [
    permguard_core::domains::capability::PDP_V1_STORE_IN_PAYLOAD,
    permguard_core::domains::capability::PDP_V1_PROFILE_SELECTION,
    permguard_core::domains::capability::PDP_V1_PARTITION_INPUTS,
    permguard_core::domains::capability::PDP_V1_PRINCIPAL,
    permguard_core::domains::capability::PDP_V1_STRUCTURED_REASONS,
    permguard_core::domains::capability::PDP_V1_BOXCARRING,
];

/// One entity as the wire carries it.
///
/// # Why this envelope refuses what it does not know
///
/// A misspelt member used to be accepted and dropped. `"propertiez"` beside `"name"` parsed, the
/// attributes vanished, and the decision was made without them — so a guardrail written to read
/// `risk` decided as though nobody had sent one. The verdict looked ordinary and was made on less
/// than the caller supplied, which is the worst shape a PDP failure can take.
///
/// So the *structural* envelope is closed and the *dynamic* containers stay open: `context`,
/// `properties` and a partition's `data` are policy data whose shape belongs to the policy
/// language, and nothing here should have an opinion about them.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EntityBody {
    #[serde(rename = "type", default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub properties: Option<Map<String, Value>>,
}

/// The action as the wire carries it.
///
/// Closed to members it does not declare, like every structural envelope here — see
/// [`EntityBody`] for what that prevents.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActionBody {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub properties: Option<Map<String, Value>>,
}

/// One question, before any partition has been chosen.
///
/// Every input a caller stated, plus the routing that decides what each partition of the profile
/// actually sees. It is deliberately **not** a [`Query`](crate::evaluate::Query): a `Query` is what one evaluator reads,
/// and the same one cannot be handed to every partition — an input belongs to the partition it
/// names, and Cedar reads an action's properties somewhere Rego does not.
///
/// `permguard_evaluator::route::Route::route` turns one of these into one `Query` per partition, and is the only place that
/// does: the plane serving a request and the CLI deciding one offline call it, so a workspace
/// cannot be tested against a materialisation that differs from the one it will meet.
#[derive(Debug, Clone, Default)]
pub struct Asking {
    pub subject: Entity,
    pub resource: Entity,
    pub action: Action,
    /// The context a caller stated. What a runtime is *given* may be more: see `route`.
    pub context: Map<String, Value>,
    /// When this request stops being worth answering. See [`Query::deadline`](crate::evaluate::Query::deadline).
    pub deadline: Option<std::time::Instant>,
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
///
/// Closed: a misspelt option is a caller asking for behaviour it will not get, and hearing so is
/// the only useful answer.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OptionsBody {
    #[serde(default)]
    pub evaluations_semantic: Option<Semantic>,
}

/// One entry of `evaluations[]`: whatever it declares overrides the defaults.
///
/// Closed, and it matters more here than at the top level: a boxcarred entry that silently lost a
/// member would be one answer of many decided on less than was sent, and the batch's other answers
/// would look identical.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
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
///
/// Closed to members it does not declare. The removed `entities` extension is still *declared*
/// below precisely so it is refused by name rather than by this rule, which would say only that
/// something unknown was sent.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
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
    /// Asks for a signed response (WP-6.6): base64url without padding, 16 to 64 bytes, unique for
    /// the verifier's replay window. Its presence is the request; a plane that cannot sign
    /// refuses rather than answer unsigned.
    #[serde(default)]
    pub request_nonce: Option<String>,
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
    /// The profile's partitions that declare an input and were addressed with none: they decided
    /// against the type's empty input. Empty when every declared input arrived — and, for a
    /// guardrail whose rules read that input, the difference between "it did not object" and
    /// "it could not have".
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub absent_inputs: Vec<String>,
    /// What became of this decision's record (WP-6.6): the exact mode and status, and where the
    /// record sits when it is durable. Absent on a batch's own context, which no record is of.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<crate::attestation::Evidence>,
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
                && context.evidence.is_none()
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
    /// The signed response, present exactly when `request_nonce` asked for one and it was made
    /// (WP-6.6b): a flattened JWS whose payload binds this answer's digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation: Option<crate::attestation::Attestation>,
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
    /// `permguard_evaluator::route::Route::route`, because no single query fits every runtime of a profile.
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
    /// declares — the interface's boxcarring rule. A field missing from both is
    /// a refusal that names it, because a PDP that guessed would be answering a
    /// question nobody asked.
    pub fn resolve(&self, max_evaluations: usize) -> Result<Resolved, Malformed> {
        let zone = verbatim(&self.zone, "zone")?.ok_or_else(|| {
            malformed(
                permguard_core::codes::pdp_native::ZONE_REQUIRED,
                "the request names no zone: `zone` and `ledger` say which policy store to decide \
                 against, and there is no default",
            )
        })?;
        let ledger = verbatim(&self.ledger, "ledger")?.ok_or_else(|| {
            malformed(
                permguard_core::codes::pdp_native::LEDGER_REQUIRED,
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
                    permguard_core::codes::pdp_native::FIELD_UNSUPPORTED,
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
                if verbatim(value, &format!("principal.{field}"))?.is_none() {
                    return Err(malformed(
                        permguard_core::codes::pdp_native::FIELD_REQUIRED,
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

        // A nonce asks for a signed response, and one the contract does not define asks for
        // nothing anybody could verify (WP-6.6).
        if let Some(nonce) = &self.request_nonce {
            crate::attestation::nonce_bytes(nonce).map_err(|message| {
                malformed(permguard_core::codes::common::INVALID_ARGUMENT, message)
            })?;
        }

        if self.evaluations.len() > max_evaluations {
            return Err(malformed(
                permguard_core::codes::pdp_native::TOO_MANY_EVALUATIONS,
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
            // A name is compared as it is echoed, never trimmed, and a present one names
            // something: an empty one is refused, on every binding (BUG-0217, DEC-0019).
            let mut named_once: Vec<&str> = Vec::new();
            for evaluation in &self.evaluations {
                let Some(request_id) = evaluation.request_id.as_deref() else {
                    continue;
                };
                if request_id.trim().is_empty() {
                    return Err(malformed(
                        permguard_core::codes::common::INVALID_ARGUMENT,
                        "an evaluation's `request_id` is empty: leave it out to name none"
                            .to_owned(),
                    ));
                }
                if named_once.contains(&request_id) {
                    return Err(malformed(
                        permguard_core::codes::pdp_native::REQUEST_ID_REPEATED,
                        format!(
                            "two evaluations are named `{request_id}`: a `request_id` is how an \
                             answer is joined back to the question, so it has to name one"
                        ),
                    ));
                }
                named_once.push(request_id);
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
            // A stated profile names one, even when empty: an empty one is no profile the ledger
            // declares, and the lookup says which it does (BUG-0012). Only an absent one is
            // `default`.
            profile: match &self.profile {
                None => DEFAULT_PROFILE.to_owned(),
                Some(stated) => {
                    verbatim(&self.profile, "profile")?.unwrap_or_else(|| stated.clone())
                }
            },
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
                    permguard_core::codes::pdp_native::FIELD_REMOVED,
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
                permguard_core::codes::pdp_native::FIELD_RESERVED,
                format!(
                    "`context.{RESERVED_CONTEXT_ACTION}` is populated from `action.properties` and \
                     may not be sent: state the properties on the action, where every runtime can \
                     read them"
                ),
            ));
        }

        Ok(Asking {
            // Set by whoever is serving a socket. A workspace decided offline answers to a person.
            deadline: None,
            subject: entity(subject, "subject", index)?,
            resource: entity(resource, "resource", index)?,
            action: Action {
                name: action
                    .map(|action| verbatim(&action.name, "action.name"))
                    .transpose()?
                    .flatten()
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
    let kind = verbatim(&body.kind, &format!("{what}.type"))?
        .ok_or_else(|| missing(&format!("{what}.type"), index))?;
    let id = verbatim(&body.id, &format!("{what}.id"))?
        .ok_or_else(|| missing(&format!("{what}.id"), index))?;

    Ok(Entity {
        kind,
        id,
        properties: body.properties.clone().unwrap_or_default(),
    })
}

fn missing(what: &str, index: usize) -> Malformed {
    malformed(
        permguard_core::codes::pdp_native::FIELD_REQUIRED,
        format!(
            "`{what}` is required: state it at the top level or in evaluation {index} — top-level \
             values are the defaults each evaluation inherits"
        ),
    )
}

/// A name as the caller sent it: `None` when absent, empty or only whitespace (it names nothing,
/// and the field's own "required" answer says so), and refused when whitespace surrounds it (DEC-0004 option B, BUG-0058, BUG-0059, BUG-0179). A request is decided on the
/// bytes sent: `"admin "` is not `admin`, and reading it as `admin` would decide something the
/// caller did not ask, while reading it as written would quietly name what no policy names. So it
/// is refused, and the PEP author learns of the bug in their own code. Whitespace inside a name,
/// and its case, stay significant.
pub fn verbatim(value: &Option<String>, path: &str) -> Result<Option<String>, Malformed> {
    match value.as_deref() {
        None => Ok(None),
        Some(text) if text.trim().is_empty() => Ok(None),
        Some(text) if text.trim() != text => Err(malformed(
            permguard_core::codes::common::INVALID_ARGUMENT,
            format!(
                "`{path}` is {text:?}, with whitespace around it: a request is decided on the \
                 bytes sent, so state the name without it"
            ),
        )),
        Some(text) => Ok(Some(text.to_owned())),
    }
}

/// A field that is present and not just whitespace.
pub fn named(value: &Option<String>) -> Option<String> {
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

    /// BUG-0181: whole is a property of the literal, read as decimal digits, never of its double.
    #[test]
    fn a_literal_is_whole_by_its_digits_not_by_its_nearest_double() {
        for whole in [
            "5",
            "-5",
            "0",
            "-0",
            "5.0",
            "5.000",
            "5e0",
            "5E+0",
            "50e-1",
            "500e-2",
            "0.5e1",
            "1e300",
            "0.0e-999",
            "0e-99999999999999999999",
            "1e99999999999999999999",
            "123.4500e2",
        ] {
            assert!(denotes_whole(whole), "{whole} is whole");
        }
        for fractional in [
            "4.5",
            "4.9999999999999999",
            "4.99999999999999999999",
            "5.0000000000000001",
            "-4.9999999999999999",
            "1e-400",
            "5e-1",
            "123.4501e2",
            "1e-99999999999999999999",
        ] {
            assert!(!denotes_whole(fractional), "{fractional} is not whole");
        }
        for not_a_number in ["", "-", ".5", "5e", "5e+", "abc", "5.x"] {
            assert!(!denotes_whole(not_a_number), "{not_a_number:?}");
        }
    }

    /// BUG-0181: a literal that is not whole but rounds to a whole double is found, at any depth
    /// and only outside strings; one that stays fractional, or is whole, is left to the rest of
    /// the interface.
    #[test]
    fn a_fraction_that_rounds_to_a_whole_double_is_found_in_the_text() {
        for (body, found) in [
            (
                r#"{"context":{"amount":4.9999999999999999}}"#,
                "4.9999999999999999",
            ),
            (
                r#"{"a":[1,{"b":5.0000000000000001}]}"#,
                "5.0000000000000001",
            ),
            (
                r#"{"n":-4.99999999999999999999}"#,
                "-4.99999999999999999999",
            ),
            (r#"{"n":1e-400}"#, "1e-400"),
        ] {
            assert_eq!(
                rounded_to_whole(body.as_bytes()).as_deref(),
                Some(found),
                "{body}"
            );
        }
        for body in [
            r#"{"n":5,"m":5.0,"o":50e-1,"p":4.5,"q":4.999999999999999,"r":0.1}"#,
            r#"{"s":"4.9999999999999999"}"#,
            r#"{"s":"\"4.9999999999999999"}"#,
            r#"{"n":1e300}"#,
        ] {
            assert_eq!(rounded_to_whole(body.as_bytes()), None, "{body}");
        }
    }

    /// IFACE-06: the scalar domain both transports carry exactly. Inside ±2^53 a number is kept,
    /// a whole number as the integer it is at any depth; beyond it, as an integer or a double, it
    /// is refused with `value_unrepresentable`, never rounded; everything else is unchanged.
    #[test]
    fn a_number_is_kept_only_where_both_transports_carry_it_exactly() {
        let exact = i64::try_from(EXACT_INTEGER).expect("2^53 fits");
        for kept in [
            serde_json::json!(0),
            serde_json::json!(-1),
            serde_json::json!(exact),
            serde_json::json!(-exact),
            serde_json::json!(1.5),
            serde_json::json!("9007199254740993"),
            serde_json::json!({"a": [true, null, "x"]}),
        ] {
            assert_eq!(lossless(kept.clone()).expect("kept"), kept);
        }
        assert_eq!(
            lossless(serde_json::json!({"n": [42.0, -0.0, 9007199254740992.0]})).expect("kept"),
            serde_json::json!({"n": [42, 0, exact]}),
            "a whole number is the integer it is, as gRPC reads it"
        );
        for refused in [
            serde_json::json!(exact + 1),
            serde_json::json!(-exact - 1),
            serde_json::json!(u64::MAX),
            serde_json::json!(1_u64 << 63),
            serde_json::json!(1e300),
            serde_json::json!({"deep": [{"n": exact + 1}]}),
        ] {
            let why = lossless(refused.clone()).expect_err("refused");
            assert_eq!(
                why.code,
                permguard_core::codes::notp::VALUE_UNREPRESENTABLE,
                "{refused}"
            );
            assert!(why.message.contains("2^53"), "{}", why.message);
        }
    }

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

    /// BUG-0058, BUG-0059, BUG-0179: a name with whitespace around it is refused before anything
    /// is decided, wherever it is stated; whitespace inside a name and its case stay significant.
    #[test]
    fn a_padded_name_is_refused_and_an_inner_space_is_significant() {
        let base: serde_json::Value = serde_json::from_str(ONE).expect("JSON");
        let with = |pointer: &str, value: &str| {
            let mut body = base.clone();
            let (parent, field) = pointer.rsplit_once('/').expect("a pointer");
            let target = if parent.is_empty() {
                &mut body
            } else {
                body.pointer_mut(parent).expect("the parent exists")
            };
            target[field] = serde_json::json!(value);
            serde_json::from_value::<CheckRequest>(body).expect("parses")
        };
        for pointer in [
            "/zone",
            "/ledger",
            "/profile",
            "/subject/type",
            "/subject/id",
            "/resource/type",
            "/resource/id",
            "/action/name",
        ] {
            for padded in [
                "admin ",
                " admin",
                "admin\t",
                "admin\n",
                "admin\r",
                "admin\u{b}",
                "admin\u{a0}",
            ] {
                let refused = with(pointer, padded)
                    .resolve(256)
                    .expect_err(&format!("{pointer} = {padded:?}"));
                assert_eq!(refused.code, "invalid_argument", "{pointer} = {padded:?}");
            }
        }
        // Inner whitespace and case are the caller's, and decided as written.
        let resolved = with("/subject/id", "ad min").resolve(256).expect("decided");
        assert_eq!(resolved.queries[0].0.subject.id, "ad min");
        let resolved = with("/action/name", "READ").resolve(256).expect("decided");
        assert_eq!(resolved.queries[0].0.action.name, "READ");
        // The offline engine reads the same request the same way.
        assert!(with("/profile", "gateway ").asked(256).is_err());
    }

    /// BUG-0012: a stated profile names one, even empty; only an absent one is `default`, so an
    /// empty one meets the lookup's `profile_unknown`, which names what the ledger declares.
    #[test]
    fn an_empty_profile_is_not_the_default() {
        let base: serde_json::Value = serde_json::from_str(ONE).expect("JSON");
        let with = |profile: Option<&str>| {
            let mut body = base.clone();
            if let Some(profile) = profile {
                body["profile"] = serde_json::json!(profile);
            }
            serde_json::from_value::<CheckRequest>(body)
                .expect("parses")
                .resolve(256)
                .expect("resolved")
                .profile
        };
        assert_eq!(with(None), DEFAULT_PROFILE);
        assert_eq!(with(Some("")), "");
        assert_eq!(with(Some("  ")), "  ");
        assert_eq!(with(Some("gateway")), "gateway");
    }

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

    /// BUG-0217: an empty evaluation `request_id` is refused, never read as no name while two
    /// equal names are refused; names are compared as they are echoed, untrimmed.
    #[test]
    fn an_empty_evaluation_name_is_refused_and_names_are_compared_as_echoed() {
        let named = |names: &[Option<&str>]| {
            let mut request = parse(ONE);
            request.evaluations = names
                .iter()
                .map(|name| EvaluationBody {
                    request_id: name.map(str::to_owned),
                    ..EvaluationBody::default()
                })
                .collect();
            request.resolve(16)
        };
        for names in [
            &[Some(""), Some("")][..],
            &[Some("  ")][..],
            &[Some("a"), Some("")][..],
        ] {
            let refused = named(names).expect_err("an empty name");
            assert_eq!(refused.code, "invalid_argument", "{names:?}");
        }
        let refused = named(&[Some("a"), Some("a")]).expect_err("a repeated name");
        assert_eq!(refused.code, "request_id_repeated");
        let resolved = named(&[Some(" a "), Some("a"), None, None]).expect("distinct as written");
        let echoed: Vec<Option<&str>> = resolved
            .queries
            .iter()
            .map(|(_, name)| name.as_deref())
            .collect();
        assert_eq!(echoed, vec![Some(" a "), Some("a"), None, None]);
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

    /// A field this interface does not know is refused, at every level of the request.
    ///
    /// # Why strictness is the right default *here*
    ///
    /// Ignoring what it does not recognise is the ordinary courtesy of a reader, and it is what
    /// this interface's *responses* do — a client reading a newer plane's answer should not break
    /// on a field added since it was written.
    ///
    /// A request is the other direction, and an authorization request most of all. Every field
    /// here narrows a decision: `context` carries what the policies test, `options` carries how a
    /// batch resolves, `partition_inputs` carries what a partition sees. A caller that writes
    /// `contxt` and is answered anyway has been given a decision made *without* the thing it
    /// believed it was sending — and the answer looks exactly like a correct one. That is not
    /// forward compatibility; it is a silent authorization bug with a typo for a cause.
    ///
    /// Forward compatibility is provided instead by the thing built for it: the interface is
    /// versioned, its identifier is in the discovery document, and a plane that adds a field adds
    /// it to a version a client asks for by name.
    #[test]
    fn a_field_this_interface_does_not_know_is_refused_rather_than_ignored() {
        let refused = serde_json::from_str::<CheckRequest>(
            r#"{"zone": "acme", "ledger": "l", "whats_this": 1,
                "subject": {"type": "user", "id": "a"},
                "resource": {"type": "d", "id": "b"}, "action": {"name": "read"}}"#,
        )
        .expect_err("a field this interface does not know is not a field to ignore");
        assert!(refused.to_string().contains("whats_this"), "{refused}");

        // And at every level, not only the top one: a misspelling inside an entity is the same
        // mistake with the same consequence.
        let refused = serde_json::from_str::<CheckRequest>(
            r#"{"zone": "acme", "ledger": "l",
                "subject": {"type": "user", "id": "a", "future": true},
                "resource": {"type": "d", "id": "b"}, "action": {"name": "read"}}"#,
        )
        .expect_err("nor inside an entity");
        assert!(refused.to_string().contains("future"), "{refused}");

        // The same payload without the stray fields is the request the caller meant.
        let resolved = parse(
            r#"{"zone": "acme", "ledger": "l",
                "subject": {"type": "user", "id": "a"},
                "resource": {"type": "d", "id": "b"}, "action": {"name": "read"}}"#,
        )
        .resolve(256)
        .expect("it is well formed");
        assert_eq!(resolved.queries[0].0.subject.id, "a");
    }

    /// A response, on the other hand, is read leniently: that direction really is the reader's
    /// duty, and a client that broke on a field added after it shipped would be a client that
    /// cannot be upgraded independently of the plane it talks to.
    #[test]
    fn a_response_carrying_a_field_this_client_does_not_know_still_reads() {
        let answer: CheckResponse =
            serde_json::from_str(r#"{"decision": true, "something_added_later": {"whatever": 1}}"#)
                .expect("a client reads what it understands and leaves the rest");

        assert!(answer.decision);
    }

    #[test]
    fn an_empty_context_is_not_serialized() {
        let answer = CheckResponse {
            decision: true,
            request_id: None,
            context: Some(DecisionContext::default()),
            evaluations: None,
            attestation: None,
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
