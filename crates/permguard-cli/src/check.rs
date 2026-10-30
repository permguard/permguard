// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! A check: a request given the store it is about, evaluated by a Data Plane, and the report of
//! the answer. `permguard check` is this, plus the arguments that build the request, the target
//! that names the store, and the rendering; a program that embeds the CLI asks the same way.

use serde::Serialize;
use serde_json::Value;

/// Puts `store` into the request when something named one, and the profile when one is given.
///
/// The precedence is the CLI's and it is documented: the store named outside the document — by
/// flags or by a workspace — wins over the one the document states. Applying it in silence is not
/// acceptable, so a document that named another store comes back as `Some((zone, ledger))`, for
/// the caller to say so. A request that ends up naming no store is refused before the round trip,
/// with the rule the server enforces.
pub fn prepare(
    payload: &mut Value,
    store: Option<(&str, &str)>,
    profile: Option<&str>,
) -> Result<Option<(String, String)>, String> {
    let mut overridden = None;
    if let Some((zone, ledger)) = store {
        let stated = |field: &str| {
            payload
                .get(field)
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
        };
        if let (Some(stated_zone), Some(stated_ledger)) = (stated("zone"), stated("ledger"))
            && (stated_zone != zone || stated_ledger != ledger)
        {
            overridden = Some((stated_zone, stated_ledger));
        }
        payload["zone"] = Value::String(zone.to_owned());
        payload["ledger"] = Value::String(ledger.to_owned());
    }
    let named = |field: &str| {
        payload
            .get(field)
            .and_then(Value::as_str)
            .is_some_and(|value| !value.trim().is_empty())
    };
    if !(named("zone") && named("ledger")) {
        return Err(
            "this request names no zone and ledger: state them in the document, pass --zone and \
             --ledger, or run inside a workspace that tracks a ledger"
                .to_owned(),
        );
    }
    if let Some(profile) = profile {
        payload["profile"] = Value::String(profile.to_owned());
    }
    Ok(overridden)
}

/// The answer to a check: what `permguard check -o json` prints, field for field.
///
/// The server's decision, verbatim — the binary's terminal rendering says what happened
/// and cites the policies that decided it, `-o json` prints what the PDP sent.
/// A deny is a decision, not a failure, and it reads like one.
///
/// Every field is present in every answer. A consumer reads one shape whether the decision was a
/// permit, a deny, a batch or a request the policies never saw: `policies` is `[]` rather than
/// absent, `id` and `reason` are `null` rather than missing.
#[derive(Debug, Clone, Serialize)]
pub struct CheckReport {
    /// The store the question was about, and where that came from.
    pub zone: String,
    pub ledger: String,
    pub store_from: &'static str,
    /// What was asked.
    pub subject: String,
    pub action: String,
    pub resource: String,
    /// The verdict.
    pub decision: bool,
    /// Whether the policies saw the request at all. `false` is the deny a plane answers a request
    /// it could not evaluate with — a subject type the schema does not declare, a partition that
    /// failed — and `error` says why. A script that has to tell "no" from "the question never
    /// reached a policy" reads this, not the exit code: a deny is an answer either way.
    pub evaluated: bool,
    /// The decision's own identifier, for the audit trail. Absent for a batch, which is an answer
    /// about decisions rather than one of them.
    pub id: Option<String>,
    /// The policies that decided it, named the way `test` names them: by the alias their author
    /// wrote where this workspace tracks one, by identity otherwise.
    pub policies: Vec<String>,
    /// The same policies by identity alone — what the plane cited, and what the audit record
    /// carries.
    pub policy_ids: Vec<String>,
    /// The operator-facing reason, when the server sent one.
    pub reason: Option<String>,
    /// Why the request could not be evaluated, when it could not.
    pub error: Option<String>,
    /// The profile's partitions that declare an input and were addressed with none, as the plane
    /// reported them: they decided against an empty input. `[]` when every declared input
    /// arrived.
    pub absent_inputs: Vec<String>,
    /// One line per boxcarred evaluation, in the order they were asked. Empty for a plain request.
    pub evaluations: Vec<CheckLine>,
}

/// One boxcarred decision, with the same fields as the whole answer.
#[derive(Debug, Clone, Serialize)]
pub struct CheckLine {
    pub decision: bool,
    pub evaluated: bool,
    pub request_id: Option<String>,
    pub policies: Vec<String>,
    pub policy_ids: Vec<String>,
    pub reason: Option<String>,
    pub error: Option<String>,
    pub absent_inputs: Vec<String>,
}

impl CheckReport {
    /// Reads the answer beside the request that produced it.
    ///
    /// `aliases` names the policies: identity → the alias its author wrote, from the head the
    /// workspace tracks. Empty outside a checkout, where the identity is all there is.
    pub fn of(
        payload: &serde_json::Value,
        answer: &serde_json::Value,
        store_from: &'static str,
        aliases: &std::collections::BTreeMap<String, String>,
    ) -> Self {
        let text = |value: &serde_json::Value, field: &str| {
            value
                .get(field)
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_owned()
        };
        let entity = |field: &str| match payload.get(field) {
            Some(entity) => format!("{}:{}", text(entity, "type"), text(entity, "id")),
            None => String::new(),
        };
        let context = answer.get("context");
        let (reason, error) = reasons(context);
        let policy_ids = policies(context);

        Self {
            zone: text(payload, "zone"),
            ledger: text(payload, "ledger"),
            store_from,
            subject: entity("subject"),
            action: payload
                .get("action")
                .map(|action| text(action, "name"))
                .unwrap_or_default(),
            resource: entity("resource"),
            decision: answer
                .get("decision")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
            evaluated: error.is_none(),
            id: context
                .and_then(|context| context.get("id"))
                .and_then(serde_json::Value::as_str)
                .map(ToOwned::to_owned),
            policies: named(&policy_ids, aliases),
            policy_ids,
            reason,
            error,
            absent_inputs: strings(context, "absent_inputs"),
            evaluations: answer
                .get("evaluations")
                .and_then(serde_json::Value::as_array)
                .map(|entries| {
                    entries
                        .iter()
                        .map(|entry| {
                            let context = entry.get("context");
                            let (reason, error) = reasons(context);
                            let policy_ids = policies(context);

                            CheckLine {
                                decision: entry
                                    .get("decision")
                                    .and_then(serde_json::Value::as_bool)
                                    .unwrap_or(false),
                                evaluated: error.is_none(),
                                request_id: entry
                                    .get("request_id")
                                    .and_then(serde_json::Value::as_str)
                                    .map(ToOwned::to_owned),
                                policies: named(&policy_ids, aliases),
                                policy_ids,
                                reason,
                                error,
                                absent_inputs: strings(context, "absent_inputs"),
                            }
                        })
                        .collect()
                })
                .unwrap_or_default(),
        }
    }
}

fn policies(context: Option<&serde_json::Value>) -> Vec<String> {
    strings(context, "policies")
}

/// The strings under `field` of the answer's context, `[]` when it is not there.
fn strings(context: Option<&serde_json::Value>, field: &str) -> Vec<String> {
    context
        .and_then(|context| context.get(field))
        .and_then(serde_json::Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(ToOwned::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// The policies by the names a person reads: the alias where one is tracked, the identity
/// otherwise — the rule `test` names them by, so a failed case and the decision it corresponds to
/// finally share a name.
fn named(ids: &[String], aliases: &std::collections::BTreeMap<String, String>) -> Vec<String> {
    ids.iter()
        .map(|id| aliases.get(id).cloned().unwrap_or_else(|| id.clone()))
        .collect()
}

/// The operator's half of the reason, and — when its code says the request was never evaluated —
/// the error it is.
///
/// A plane of an earlier release answered an evaluation it could not perform as a deny whose
/// `reason_admin` carries code `500`, the same thing the local run calls a refusal; a plane of
/// this release refuses it instead, so no decision of its carries the code. The code used to be
/// dropped here, which left a deny nothing permitted and a deny nothing evaluated printing the
/// same way.
fn reasons(context: Option<&serde_json::Value>) -> (Option<String>, Option<String>) {
    let Some(reason) = context.and_then(|context| context.get("reason_admin")) else {
        return (None, None);
    };
    let message = reason
        .get("message")
        .and_then(serde_json::Value::as_str)
        .map(ToOwned::to_owned);
    let code = reason
        .get("code")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    let error = if code == "500" { message.clone() } else { None };

    (message, error)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_named_store_wins_and_the_one_it_replaced_is_said() {
        let mut payload = serde_json::json!({"zone": "from-file", "ledger": "from-file"});
        let overridden =
            prepare(&mut payload, Some(("acme", "orders")), Some("pdp")).expect("prepared");
        assert_eq!(
            overridden,
            Some(("from-file".to_owned(), "from-file".to_owned()))
        );
        assert_eq!(payload["zone"], "acme");
        assert_eq!(payload["ledger"], "orders");
        assert_eq!(payload["profile"], "pdp");
    }

    #[test]
    fn the_same_store_named_twice_is_not_an_override() {
        let mut payload = serde_json::json!({"zone": "acme", "ledger": "orders"});
        assert_eq!(
            prepare(&mut payload, Some(("acme", "orders")), None).expect("prepared"),
            None
        );
        assert!(payload.get("profile").is_none());
    }

    #[test]
    fn a_request_naming_no_store_is_refused() {
        let mut payload = serde_json::json!({"subject": {"type": "user", "id": "alice"}});
        let refused = prepare(&mut payload, None, None).expect_err("refused");
        assert!(refused.contains("--zone"), "{refused}");
    }

    #[test]
    fn a_report_names_the_policies_by_alias_and_keeps_their_identity() {
        let payload = serde_json::json!({
            "zone": "acme", "ledger": "orders",
            "subject": {"type": "user", "id": "alice"},
            "action": {"name": "read"},
            "resource": {"type": "document", "id": "budget"}
        });
        let answer = serde_json::json!({
            "decision": true,
            "context": {"id": "d-1", "policies": ["p-1", "p-2"]}
        });
        let aliases = std::collections::BTreeMap::from([("p-1".to_owned(), "readers".to_owned())]);
        let report = CheckReport::of(&payload, &answer, "flag", &aliases);
        assert!(report.decision && report.evaluated);
        assert_eq!(report.subject, "user:alice");
        assert_eq!(report.action, "read");
        assert_eq!(report.policies, vec!["readers", "p-2"]);
        assert_eq!(report.policy_ids, vec!["p-1", "p-2"]);
        assert_eq!(report.id.as_deref(), Some("d-1"));
    }
}
