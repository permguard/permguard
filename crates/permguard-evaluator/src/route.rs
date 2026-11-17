// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Routing one question to the partitions of a profile: the inputs a caller addressed, checked and
//! normalized before any policy is consulted, and one query per partition.
//!
//! The question itself, [`Asking`], is the request model's; what turns it into queries reads the
//! compiled partitions that will answer, so it is the decision point's. The plane serving a request
//! and the command line deciding one offline both route through [`Route`].

use permguard_language_core::evaluate::Query;
use permguard_language_core::input::PartitionData;
use permguard_language_core::request::{Asking, Malformed, RESERVED_CONTEXT_ACTION, named};
use permguard_objects::manifest::InputContract;
use serde_json::Value;

use crate::evaluate::Evaluator;

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
    /// When the decision stops being worth making, for an input check that runs out of process.
    pub deadline: Option<std::time::Instant>,
}

impl<'a> PartitionTarget<'a> {
    /// A partition that accepts no input and has nothing compiled.
    pub fn new(name: &'a str, language: &'a str) -> Self {
        Self {
            name,
            language,
            input: None,
            evaluator: None,
            deadline: None,
        }
    }

    /// The decision's deadline, which an input check run out of process keeps to.
    #[must_use]
    pub fn until(mut self, deadline: Option<std::time::Instant>) -> Self {
        self.deadline = deadline;

        self
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

/// The routing of one question, by the table in [`Route::route`].
pub trait Route {
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
    fn route(&self, partitions: &[PartitionTarget<'_>]) -> Result<Vec<Query>, Malformed>;

    /// The partitions that declare an input and were addressed with none, in the order given.
    ///
    /// They decide against the type's empty input, which is legal when the input is optional and
    /// is exactly what an auditor has to be able to see: a guardrail whose list never arrived is
    /// not a guardrail that did not object. Reported beside the decision and in its record; a
    /// partition that declares no input is not named, because it was given nothing to miss.
    fn absent_inputs(&self, partitions: &[PartitionTarget<'_>]) -> Vec<String>;

    /// The query one partition evaluates.
    fn materialize(&self, target: &PartitionTarget<'_>, input: PartitionData) -> Query;
}

impl Route for Asking {
    fn route(&self, partitions: &[PartitionTarget<'_>]) -> Result<Vec<Query>, Malformed> {
        self.check_addressing(partitions)?;

        let mut queries = Vec::with_capacity(partitions.len());
        for target in partitions {
            let input = self.input_for(target)?;
            queries.push(self.materialize(target, input));
        }

        Ok(queries)
    }

    fn absent_inputs(&self, partitions: &[PartitionTarget<'_>]) -> Vec<String> {
        partitions
            .iter()
            .filter(|target| {
                target.input.is_some() && !self.partition_inputs.contains_key(target.name)
            })
            .map(|target| target.name.to_owned())
            .collect()
    }

    fn materialize(&self, target: &PartitionTarget<'_>, input: PartitionData) -> Query {
        let mut context = self.context.clone();

        // Cedar has nowhere else to read them from. Absent when there are none, so a schema that
        // never declared `context.action` keeps validating the requests it always did.
        if target.language == permguard_language_core::names::CEDAR
            && !self.action.properties.is_empty()
        {
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
            deadline: self.deadline,
            input,
        }
    }
}

/// What routing settles before a query is materialized: where each stated input goes, and what each
/// partition is given.
trait Settle {
    /// Every input the caller stated reaches a partition that can read it.
    ///
    /// Run over what the caller wrote rather than over the profile, because this is the half that
    /// is about the caller's mistakes: a name nobody holds, a type nobody registered. Silence
    /// would be the wrong answer to all of them — an input the plane ignored looks, from the
    /// caller's side, exactly like an input a policy ignored.
    fn check_addressing(&self, partitions: &[PartitionTarget<'_>]) -> Result<(), Malformed>;

    /// What one partition is given, by the table in [`Asking::route`].
    fn input_for(&self, target: &PartitionTarget<'_>) -> Result<PartitionData, Malformed>;
}

impl Settle for Asking {
    fn check_addressing(&self, partitions: &[PartitionTarget<'_>]) -> Result<(), Malformed> {
        if self.partition_inputs.len() > permguard_language_core::input::MAX_PARTITION_INPUTS {
            return Err(malformed(
                permguard_core::codes::pdp_native::PARTITION_INPUT_TOO_LARGE,
                format!(
                    "the request addresses {} partitions and this plane accepts {}",
                    self.partition_inputs.len(),
                    permguard_language_core::input::MAX_PARTITION_INPUTS
                ),
            ));
        }

        for (name, body) in self.partition_inputs.iter() {
            let Some(target) = partitions.iter().find(|held| held.name == name) else {
                return Err(malformed(
                    permguard_core::codes::pdp_native::PARTITION_UNKNOWN,
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
                    permguard_core::codes::pdp_native::PARTITION_INPUT_UNSUPPORTED,
                    format!(
                        "the partition `{name}` declares no input, and this request addresses it: \
                         what a partition reads is the ledger's decision, and a partition that \
                         asked for nothing would have nowhere to put this"
                    ),
                ));
            };
            let Some(kind) = named(&body.kind) else {
                return Err(malformed(
                    permguard_core::codes::pdp_native::PARTITION_INPUT_TYPE_REQUIRED,
                    format!(
                        "`partition_inputs.{name}.type` is required: it states what this data is, \
                         and is checked against the `{}` the ledger declares",
                        contract.r#type
                    ),
                ));
            };
            let Some(registered) = permguard_language_core::input::input_type(&kind) else {
                return Err(malformed(
                    permguard_core::codes::pdp_native::PARTITION_INPUT_TYPE_UNKNOWN,
                    format!(
                        "`{kind}` is not an input type this build implements (it implements: {}). \
                         An input type is a contract Permguard implements, not a name a caller \
                         invents",
                        permguard_language_core::input::registered()
                    ),
                ));
            };
            if kind != contract.r#type {
                return Err(malformed(
                    permguard_core::codes::pdp_native::PARTITION_INPUT_TYPE_MISMATCH,
                    format!(
                        "the partition `{name}` accepts `{}` and this request states `{kind}`: the \
                         type says what the data is, and it is checked, never obeyed",
                        contract.r#type
                    ),
                ));
            }
            if registered.runtime() != target.language {
                return Err(malformed(
                    permguard_core::codes::pdp_native::PARTITION_INPUT_TYPE_INCOMPATIBLE,
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

    fn input_for(&self, target: &PartitionTarget<'_>) -> Result<PartitionData, Malformed> {
        // A partition that declares no input reads none. Anything addressed to it was refused by
        // `check_addressing`, so there is nothing to lose here.
        let Some(contract) = target.input else {
            return Ok(PartitionData::Absent);
        };
        let registered = permguard_language_core::input::input_type(&contract.r#type).ok_or_else(|| {
            malformed(
                permguard_core::codes::pdp_native::PARTITION_INPUT_TYPE_UNKNOWN,
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
                    permguard_core::codes::pdp_native::PARTITION_INPUT_REQUIRED,
                    format!(
                        "the partition `{}` requires an input of type `{}` and this request \
                         addresses it with none: its policies read that data, and deciding \
                         against an empty one would deny for the wrong reason",
                        target.name, contract.r#type
                    ),
                ));
            }

            // Not required and not sent: the type's own empty input — which the partition's
            // schema still gets to see. The rules will read this input, and a schema that
            // refuses it must refuse it here, exactly as it refuses the same `{}` sent
            // explicitly: one input cannot pass by omission and fail by statement, and a
            // guardrail whose list is missing must not read as a guardrail that did not object.
            let empty = registered.empty();
            if let Some(evaluator) = target.evaluator {
                checked(target.name, || {
                    permguard_language_core::headroom::with(|| {
                        evaluator.check_input_by(&empty, target.deadline)
                    })
                })?
                .map_err(|why| {
                    malformed(
                        permguard_core::codes::pdp_native::PARTITION_INPUT_SCHEMA,
                        format!(
                            "the partition `{}` was addressed with no input, and the empty input \
                             its rules would read does not satisfy its schema: {why}. State the \
                             input, or declare it `required: true` so a request without it is \
                             refused by name",
                            target.name
                        ),
                    )
                })?;
            }

            return Ok(empty);
        };

        let data = match &body.data {
            Some(data) if !data.is_null() => data,
            _ => {
                return Err(malformed(
                    permguard_core::codes::pdp_native::PARTITION_INPUT_MALFORMED,
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
        permguard_language_core::input::within_limits(data).map_err(|why| {
            malformed(
                permguard_core::codes::pdp_native::PARTITION_INPUT_TOO_LARGE,
                format!("`partition_inputs.{}`: {why}", target.name),
            )
        })?;
        let normalized = registered.normalize(data).map_err(|why| {
            malformed(
                permguard_core::codes::pdp_native::PARTITION_INPUT_MALFORMED,
                format!("`partition_inputs.{}.data`: {why}", target.name),
            )
        })?;
        if let Some(evaluator) = target.evaluator {
            // Entered with room to recurse in: checking an entity store means deserializing it
            // in the engine, which recurses over the graph and is guarded by the engine's own
            // stack check. See `permguard_language_core::headroom`.
            checked(target.name, || {
                permguard_language_core::headroom::with(|| {
                    evaluator.check_input_by(&normalized, target.deadline)
                })
            })?
            .map_err(|why| {
                malformed(
                    permguard_core::codes::pdp_native::PARTITION_INPUT_SCHEMA,
                    format!("`partition_inputs.{}`: {why}", target.name),
                )
            })?;
        }

        Ok(normalized)
    }
}

fn names(partitions: &[PartitionTarget<'_>]) -> String {
    partitions
        .iter()
        .map(|partition| partition.name)
        .collect::<Vec<&str>>()
        .join(", ")
}

/// A partition's input check, inside the panic boundary. A check that came apart, or could not
/// run, is not the caller's mistake: it is refused as `evaluation_indeterminate` — the partition
/// could not evaluate — which the native interface answers `503`, never as a `400` about the
/// input. What is left is the check's own verdict on the input.
fn checked(
    partition: &str,
    check: impl FnOnce() -> Result<Result<(), String>, String>,
) -> Result<Result<(), String>, Malformed> {
    match permguard_language_core::guard::contained(check) {
        Ok(Ok(verdict)) => Ok(verdict),
        Ok(Err(_)) | Err(_) => Err(malformed(
            permguard_core::codes::pdp_native::EVALUATION_INDETERMINATE,
            format!("the partition `{partition}` could not check its input; this is not a deny"),
        )),
    }
}

fn malformed(code: &'static str, message: impl Into<String>) -> Malformed {
    Malformed {
        code,
        message: message.into(),
    }
}

#[cfg(test)]
mod routing_tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use permguard_language_core::input::{CEDAR_ENTITIES_V1, REGO_DATA_V1};
    use permguard_language_core::request::CheckRequest;
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
            fn evaluate(&self, _query: &Query) -> permguard_language_core::evaluate::Verdict {
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

    /// An input check that comes apart is not the caller's mistake: it is refused as
    /// `evaluation_indeterminate`, and the engine's own words stay out of the refusal.
    #[test]
    fn an_input_check_that_panics_is_indeterminate_not_a_bad_request() {
        struct Exploding;
        impl crate::evaluate::Evaluator for Exploding {
            fn evaluate(&self, _query: &Query) -> permguard_language_core::evaluate::Verdict {
                unreachable!("routing refuses before anything is evaluated")
            }
            fn check_input(&self, _input: &PartitionData) -> Result<(), String> {
                panic!("the schema engine came apart over secret input")
            }
            fn footprint(&self) -> usize {
                0
            }
            fn policies(&self) -> Vec<String> {
                Vec::new()
            }
        }

        let input = contract(CEDAR_ENTITIES_V1, false);
        let exploding = Exploding;
        let mut payload = plain();
        payload["partition_inputs"] = json!({"p": {"type": CEDAR_ENTITIES_V1, "data": []}});
        let refused = asking(payload)
            .expect("it is well formed")
            .route(&[PartitionTarget::new("p", "cedar")
                .accepting(Some(&input))
                .evaluated_by(&exploding)])
            .expect_err("the check could not run");

        assert_eq!(
            refused.code,
            permguard_core::codes::pdp_native::EVALUATION_INDETERMINATE
        );
        assert!(!refused.message.contains("secret"), "{}", refused.message);
    }

    /// The empty input a request gets by omission is the same input it could have stated, and the
    /// schema sees both: an optional document whose schema requires a field is refused when the
    /// request omits the document, not silently read as `{}`.
    #[test]
    fn an_omitted_optional_input_still_has_to_satisfy_the_schema() {
        struct Demanding;
        impl crate::evaluate::Evaluator for Demanding {
            fn evaluate(&self, _query: &Query) -> permguard_language_core::evaluate::Verdict {
                unreachable!("routing refuses before anything is evaluated")
            }
            fn check_input(&self, input: &PartitionData) -> Result<(), String> {
                match input.rego_data() {
                    Some(document) if document.contains_key("restricted") => Ok(()),
                    _ => Err("'restricted' is a required property".to_owned()),
                }
            }
            fn footprint(&self) -> usize {
                0
            }
            fn policies(&self) -> Vec<String> {
                Vec::new()
            }
        }

        let input = contract(REGO_DATA_V1, false);
        let demanding = Demanding;
        let refused = asking(plain())
            .expect("it is well formed")
            .route(&[PartitionTarget::new("p", "rego")
                .accepting(Some(&input))
                .evaluated_by(&demanding)])
            .expect_err("the empty document does not satisfy the schema");

        assert_eq!(refused.code, "partition_input_schema");
        assert!(refused.message.contains("no input"), "{}", refused.message);
        assert!(
            refused.message.contains("required: true"),
            "{}",
            refused.message
        );

        // Stated, the same schema is satisfied, and the request goes through.
        let mut payload = plain();
        payload["partition_inputs"] =
            json!({"p": {"type": REGO_DATA_V1, "data": {"restricted": []}}});
        asking(payload)
            .expect("it is well formed")
            .route(&[PartitionTarget::new("p", "rego")
                .accepting(Some(&input))
                .evaluated_by(&demanding)])
            .expect("the document satisfies the schema");
    }

    /// Which declared inputs a request left out is reported, in the profile's order, and a
    /// partition that declares none is not "missing" anything.
    #[test]
    fn the_declared_inputs_a_request_omitted_are_named_in_order() {
        let optional = contract(REGO_DATA_V1, false);
        let mut payload = plain();
        payload["partition_inputs"] = json!({"bbb": {"type": REGO_DATA_V1, "data": {}}});
        let asked = asking(payload).expect("it is well formed");
        let targets = [
            PartitionTarget::new("zzz", "rego").accepting(Some(&optional)),
            PartitionTarget::new("bbb", "rego").accepting(Some(&optional)),
            PartitionTarget::new("aaa", "rego").accepting(Some(&optional)),
            PartitionTarget::new("none", "rego"),
        ];

        assert_eq!(asked.absent_inputs(&targets), vec!["zzz", "aaa"]);
        assert!(
            asking(plain())
                .expect("it is well formed")
                .absent_inputs(&[PartitionTarget::new("none", "rego")])
                .is_empty()
        );
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
        for _ in 0..(permguard_language_core::input::MAX_INPUT_DEPTH + 4) {
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
        for index in 0..=permguard_language_core::input::MAX_PARTITION_INPUTS {
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
