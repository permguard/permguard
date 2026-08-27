// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Cases: what a workspace claims its own policies decide, and the check of it.
//!
//! `validate` answers *is this well formed*. This answers the question after it —
//! *does it decide what I meant* — and it answers it **from the working tree**,
//! before anything is pushed. The policies are compiled with the same plugins a
//! data plane compiles them with, evaluated with the same evaluators, and the
//! partition answers are combined with `permguard_languages::resolve`: the very
//! function the data plane calls. A case that passes here is not a rehearsal of
//! the decision — it *is* the decision, minus the transport.
//!
//! # Why the expectations are not in the request
//!
//! A request file stays a `permguard.pdp.v1` payload and nothing else, so the same
//! bytes can be sent with `permguard check -f`, piped to `curl`, or replayed
//! against a live plane. The expectations live beside it, which also lets one
//! request be asserted under two profiles, and lets a case expect a *refusal*,
//! which the wire contract has no way to express.

use std::collections::BTreeMap;

use permguard_languages::{
    self as languages, Evaluator, Semantic, StoredPolicy, registry, resolve,
};
use permguard_objects::manifest::Manifest;
use permguard_objects::object::{Blob, Object, Tree};
use permguard_objects::policy_id::ANNOTATION_POLICY_ID;
use serde::Deserialize;
use serde_json::Value;

use super::{Result, err};
use crate::engine::workspace::build::Snapshot;
use permguard_control_client::Store;

/// The directory a workspace keeps its cases in, when none is named.
pub const DEFAULT_DIRECTORY: &str = "tests";

/// What a case says must happen.
///
/// Every field is optional and every one present is checked: a case that states
/// only `decision` asserts only that, and one that also states `policies` asserts
/// *which* policies decided — the difference between "it was denied" and "the
/// guardrail denied it".
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Expectation {
    /// `permit` or `deny`.
    pub decision: Option<String>,
    /// The policies that must have decided, by alias. An empty list asserts the
    /// quiet no: nothing permitted the request, and there is nothing to cite.
    pub policies: Option<Vec<String>>,
    /// A fragment of the refusal a request that cannot be evaluated must carry.
    pub error: Option<String>,
    /// For a boxcarred request: what each evaluation must decide, by the `request_id`
    /// the caller gave it. Every one named is checked; the rest are not.
    pub evaluations: Option<BTreeMap<String, String>>,
}

/// One case, as the file spells it.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Case {
    pub name: String,
    /// The request document, relative to the case file.
    pub request: String,
    /// The profile to ask under, when the request does not name one.
    #[serde(default)]
    pub profile: Option<String>,
    pub expect: Expectation,
}

/// A case, and where it was read from.
#[derive(Debug, Clone)]
pub struct Located {
    pub case: Case,
    /// The case file, workspace-relative — what a failure names.
    pub source: String,
    /// The request document, workspace-relative.
    pub request: String,
}

/// What running one case concluded.
#[derive(Debug, Clone)]
pub struct Outcome {
    pub name: String,
    pub source: String,
    pub profile: String,
    pub passed: bool,
    /// The decision reached, absent when the request could not be evaluated.
    pub decision: Option<bool>,
    /// The policies that decided, by alias where one is authored.
    pub policies: Vec<String>,
    /// For a boxcarred request: what each evaluation decided, as `id=permit`.
    pub evaluations: Vec<String>,
    /// The refusal, when there was one.
    pub error: Option<String>,
    /// Why it failed. Empty when it passed.
    pub problems: Vec<String>,
}

/// Reads the cases named, or every case in the workspace's own directory.
///
/// A named path may be a case file or a directory of them, so that a workspace can
/// keep its cases wherever it likes and a person can run one file while working on
/// it.
pub fn collect(store: &dyn Store, paths: &[String]) -> Result<Vec<Located>> {
    let roots: Vec<String> = if paths.is_empty() {
        vec![DEFAULT_DIRECTORY.to_owned()]
    } else {
        paths.to_vec()
    };

    let mut files = Vec::new();
    for root in &roots {
        // A file reads and a directory does not, which is the only distinction the
        // store draws — `exists` answers yes to both.
        if matches!(store.read(root), Ok(Some(_))) {
            files.push(root.clone());

            continue;
        }
        let before = files.len();
        gather(store, root, &mut files)?;
        if files.len() == before && !paths.is_empty() {
            return Err(err(format!("`{root}` holds no case file, and is not one")));
        }
    }
    files.sort();
    files.dedup();

    let mut cases = Vec::new();
    for file in files {
        let bytes = store
            .read(&file)
            .map_err(err)?
            .ok_or_else(|| err(format!("{file} vanished mid-read")))?;
        let text = String::from_utf8(bytes).map_err(|_| err(format!("{file} is not UTF-8")))?;
        let read: Vec<Case> = serde_norway::from_str(&text)
            .map_err(|error| err(format!("{file}: not a list of cases: {error}")))?;

        for case in read {
            let request = beside(&file, &case.request);
            cases.push(Located {
                case,
                source: file.clone(),
                request,
            });
        }
    }

    Ok(cases)
}

/// Every `.yml`/`.yaml` under a directory, depth first.
fn gather(store: &dyn Store, directory: &str, found: &mut Vec<String>) -> Result<()> {
    for (name, is_directory) in store.list(directory).map_err(err)? {
        let path = format!("{directory}/{name}");
        if is_directory {
            gather(store, &path, found)?;

            continue;
        }
        if name.ends_with(".yml") || name.ends_with(".yaml") {
            found.push(path);
        }
    }

    Ok(())
}

/// Resolves a request path written relative to its case file, `..` included.
fn beside(case_file: &str, request: &str) -> String {
    let mut parts: Vec<&str> = case_file.split('/').collect();
    parts.pop();
    for step in request.split('/') {
        match step {
            "." | "" => {}
            ".." => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }

    parts.join("/")
}

/// The compiled partitions of the working tree, ready to answer.
pub struct Compiled {
    partitions: BTreeMap<String, Box<dyn Evaluator>>,
    /// Policy identity → the alias its author wrote, when there is one.
    aliases: BTreeMap<String, String>,
    manifest: Manifest,
}

impl Compiled {
    /// The profiles this ledger offers, for a message that has to list them.
    pub fn profiles(&self) -> Vec<String> {
        self.manifest.profiles.keys().cloned().collect()
    }
}

/// Compiles every partition of a snapshot, with the plugins a plane would use.
pub fn compile(snapshot: &Snapshot, manifest: &Manifest) -> Result<Compiled> {
    let aliases = aliases(snapshot);

    let root = tree_at(snapshot, &snapshot.root.to_string())?;
    let mut partitions: BTreeMap<String, Box<dyn Evaluator>> = BTreeMap::new();

    for entry in &root.entries {
        let Some(declared) = manifest.partitions.get(&entry.name) else {
            continue;
        };
        let runtime = manifest
            .runtimes
            .get(&declared.runtime)
            .ok_or_else(|| err(format!("partition `{}` names no runtime", entry.name)))?;
        let evaluating = registry::evaluating(&runtime.language.name).ok_or_else(|| {
            err(format!(
                "this build carries `{}` but not its evaluating half",
                runtime.language.name
            ))
        })?;

        let held = tree_at(snapshot, &entry.digest.to_string())?;
        let mut policies = Vec::new();
        let mut schema = None;

        for item in &held.entries {
            let blob = blob_at(snapshot, &item.digest.to_string())?;
            match item.annotations.get(ANNOTATION_POLICY_ID) {
                // A schema is the entry with no policy identity on it.
                None => schema = Some(blob.data),
                Some(id) => policies.push(StoredPolicy {
                    id: id.clone(),
                    alias: aliases.get(id).cloned(),
                    source: blob.data,
                }),
            }
        }

        let evaluator = evaluating
            .compile(&policies, schema.as_deref())
            .map_err(|error| err(format!("partition `{}`: {error}", entry.name)))?;
        partitions.insert(entry.name.clone(), evaluator);
    }

    Ok(Compiled {
        partitions,
        aliases,
        manifest: manifest.clone(),
    })
}

fn tree_at(snapshot: &Snapshot, digest: &str) -> Result<Tree> {
    match decode_at(snapshot, digest)? {
        Object::Tree(tree) => Ok(tree),
        other => Err(err(format!("{digest} is a {:?}, not a tree", other.kind()))),
    }
}

fn blob_at(snapshot: &Snapshot, digest: &str) -> Result<Blob> {
    match decode_at(snapshot, digest)? {
        Object::Blob(blob) => Ok(blob),
        other => Err(err(format!("{digest} is a {:?}, not a blob", other.kind()))),
    }
}

fn decode_at(snapshot: &Snapshot, digest: &str) -> Result<Object> {
    let bytes = object(snapshot, digest)?;

    permguard_objects::object::decode(&bytes)
        .map_err(|error| err(format!("{digest} does not decode: {error}")))
}

fn object(snapshot: &Snapshot, digest: &str) -> Result<Vec<u8>> {
    snapshot
        .objects
        .iter()
        .find(|(held, _)| held.to_string() == digest)
        .map(|(_, bytes)| bytes.clone())
        .ok_or_else(|| err(format!("the snapshot is missing {digest}")))
}

/// The request a case names, and the profile it is asked under.
///
/// Read out here rather than inside `run`, because `--remote` needs the same two things and
/// reading them a second way is how the local and the remote runs would start disagreeing about
/// what a case even asks.
pub fn request_of(store: &dyn Store, located: &Located) -> Result<(Value, String)> {
    let bytes = store.read(&located.request).map_err(err)?.ok_or_else(|| {
        err(format!(
            "{}: no request at {}",
            located.source, located.request
        ))
    })?;
    let payload: Value = serde_json::from_slice(&bytes)
        .map_err(|error| err(format!("{}: not JSON: {error}", located.request)))?;

    let profile = located
        .case
        .profile
        .clone()
        .or_else(|| {
            payload
                .get("profile")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        })
        .unwrap_or_else(|| "default".to_owned());

    Ok((payload, profile))
}

/// The identities of this workspace's policies, and the aliases their authors wrote.
///
/// What names a decision: a plane cites identities, and a case is written in aliases.
pub fn aliases(snapshot: &Snapshot) -> BTreeMap<String, String> {
    snapshot
        .policies
        .iter()
        .filter_map(|policy| {
            policy
                .alias
                .as_ref()
                .map(|alias| (policy.id.clone(), alias.clone()))
        })
        .collect()
}

/// Runs one case against the compiled workspace.
pub fn run(compiled: &Compiled, store: &dyn Store, located: &Located) -> Result<Outcome> {
    let (payload, profile) = request_of(store, located)?;

    // The plane answers this with `profile_unknown`, and so does this: a case that
    // expects the refusal has to pass in both modes, or the two are not the same test.
    let Some(declared) = compiled.manifest.profiles.get(&profile) else {
        return Ok(judge(
            located,
            &profile,
            Answered {
                permitted: false,
                policies: Vec::new(),
                error: Some(format!(
                    "profile_unknown: this ledger declares no profile `{profile}` \
                     (it declares: {})",
                    compiled.profiles().join(", ")
                )),
                evaluations: Vec::new(),
            },
            &compiled.aliases,
        ));
    };

    let asked = match asked(&payload) {
        Ok(asked) => asked,
        // Refused before any policy sees it, exactly as a plane refuses it. It is an
        // answer a case may expect, so it is judged rather than thrown.
        Err(refusal) => {
            return Ok(judge(
                located,
                &profile,
                Answered {
                    permitted: false,
                    policies: Vec::new(),
                    error: Some(refusal),
                    evaluations: Vec::new(),
                },
                &compiled.aliases,
            ));
        }
    };

    let mut evaluations = Vec::new();
    for (query, request_id) in &asked.queries {
        let mut verdicts = Vec::new();
        for name in &declared.partitions {
            let Some(evaluator) = compiled.partitions.get(name) else {
                return Ok(failed(
                    located,
                    &profile,
                    format!("the profile names the partition `{name}`, which holds nothing"),
                ));
            };
            verdicts.push(evaluator.evaluate(query));
        }
        let outcome = resolve(verdicts);
        let decided = Decided {
            request_id: request_id.clone(),
            permitted: outcome.permitted,
            policies: outcome.determining().to_vec(),
            error: outcome.errors.first().cloned(),
        };

        // The batch stops where the caller's semantic says it stops, so that a case
        // sees the same evaluations a plane would have run — and no more.
        let stop = match asked.semantic {
            Semantic::ExecuteAll => false,
            Semantic::DenyOnFirstDeny => !decided.permitted,
            Semantic::PermitOnFirstPermit => decided.permitted,
        };
        evaluations.push(decided);
        if stop {
            break;
        }
    }

    Ok(judge(
        located,
        &profile,
        Answered::of(evaluations),
        &compiled.aliases,
    ))
}

/// One evaluation's answer: a plain request has exactly one, a boxcarred request has
/// one per entry it asked.
#[derive(Debug, Clone, Default)]
pub struct Decided {
    /// The name the caller gave this evaluation, when it gave one.
    pub request_id: Option<String>,
    pub permitted: bool,
    /// The policies that decided, by identity.
    pub policies: Vec<String>,
    /// The refusal, when this evaluation could not be performed.
    pub error: Option<String>,
}

/// What a decision said, whoever decided it: this workspace, or a plane.
#[derive(Debug, Clone, Default)]
pub struct Answered {
    pub permitted: bool,
    /// The policies that decided, by identity.
    pub policies: Vec<String>,
    /// The refusal, when the request could not be evaluated.
    pub error: Option<String>,
    /// One per boxcarred evaluation, empty for a plain request.
    pub evaluations: Vec<Decided>,
}

impl Answered {
    /// The answer to a whole request, from what each of its evaluations decided.
    ///
    /// The overall verdict of a batch is the **conjunction** — every evaluation
    /// permitted — whatever semantic ran it, because that is what a PEP enforcing a
    /// batch has to know, and it is what the data plane answers.
    pub fn of(evaluations: Vec<Decided>) -> Self {
        let single = evaluations.len() == 1 && evaluations[0].request_id.is_none();

        Self {
            permitted: !evaluations.is_empty()
                && evaluations.iter().all(|decided| decided.permitted),
            policies: if single {
                evaluations[0].policies.clone()
            } else {
                Vec::new()
            },
            error: evaluations.iter().find_map(|decided| decided.error.clone()),
            evaluations: if single { Vec::new() } else { evaluations },
        }
    }
}

/// The aliases of the policies a decision cited, collecting any identity this workspace
/// does not contain.
///
/// A decision cites identities; a case is written in the aliases their authors wrote. An
/// identity with no alias here is not a naming problem — it is a policy these sources do
/// not have, which means what answered is not what they would apply.
fn name(
    policies: &[String],
    aliases: &BTreeMap<String, String>,
    foreign: &mut Vec<String>,
) -> Vec<String> {
    policies
        .iter()
        .map(|id| match aliases.get(id) {
            Some(alias) => alias.clone(),
            None => {
                if !foreign.contains(id) {
                    foreign.push(id.clone());
                }

                id.clone()
            }
        })
        .collect()
}

/// Compares one answer with what its case expected.
///
/// The same judgement for a decision reached here and for one a plane reached, so that
/// `--remote` cannot quietly hold the workspace to a different standard than `test` does.
///
/// `aliases` names the policies: a decision cites identities, and a case is written in the
/// aliases their authors wrote. An identity this workspace cannot name is reported as itself
/// **and** as a finding — the plane is deciding with a policy these sources do not contain,
/// which is drift, and is worth more than the mismatch it will also cause.
pub fn judge(
    located: &Located,
    profile: &str,
    answered: Answered,
    aliases: &BTreeMap<String, String>,
) -> Outcome {
    let mut problems = Vec::new();
    let mut foreign: Vec<String> = Vec::new();

    // Naming a policy is also how drift is caught, so every identity a decision cited
    // has to pass through `name` — including the ones inside a boxcarred batch, whose
    // policies the overall answer does not carry. Before this, a batch whose booleans
    // matched passed even when a plane decided it with policies these sources do not
    // contain, which is precisely the drift `--remote` exists to find.
    let decided = name(&answered.policies, aliases, &mut foreign);
    let per_evaluation: Vec<(Option<String>, bool, Vec<String>)> = answered
        .evaluations
        .iter()
        .map(|held| {
            (
                held.request_id.clone(),
                held.permitted,
                name(&held.policies, aliases, &mut foreign),
            )
        })
        .collect();

    for id in &foreign {
        problems.push(format!(
            "the decision cites `{id}`, which is no policy of this workspace — what answered is not what these sources would apply"
        ));
    }

    let error = answered.error;
    let expect = &located.case.expect;

    if let Some(wanted) = &expect.error {
        match &error {
            Some(found) if found.contains(wanted) => {}
            Some(found) => problems.push(format!(
                "expected a refusal saying `{wanted}`, got `{found}`"
            )),
            None => problems.push(format!(
                "expected a refusal saying `{wanted}`, and it was evaluated"
            )),
        }
    } else if let Some(found) = &error {
        problems.push(format!("the request could not be evaluated: {found}"));
    }

    if let Some(wanted) = &expect.decision {
        match wanted.as_str() {
            "permit" | "deny" => {
                let wanted_permit = wanted == "permit";
                if answered.permitted != wanted_permit {
                    problems.push(format!(
                        "expected {wanted}, got {}",
                        if answered.permitted { "permit" } else { "deny" }
                    ));
                }
            }
            other => problems.push(format!(
                "`{other}` is not a decision — write permit or deny"
            )),
        }
    }

    if let Some(wanted) = &expect.policies
        && &decided != wanted
    {
        problems.push(format!(
            "expected {}, decided by {}",
            cite(wanted),
            cite(&decided)
        ));
    }

    if let Some(wanted) = &expect.evaluations {
        for (request_id, decision) in wanted {
            match answered
                .evaluations
                .iter()
                .find(|held| held.request_id.as_deref() == Some(request_id.as_str()))
            {
                None => problems.push(format!(
                    "the request asked no evaluation named `{request_id}`"
                )),
                Some(held) => {
                    let got = if held.permitted { "permit" } else { "deny" };
                    if got != decision {
                        problems.push(format!("`{request_id}`: expected {decision}, got {got}"));
                    }
                }
            }
        }
    }

    Outcome {
        name: located.case.name.clone(),
        source: located.source.clone(),
        profile: profile.to_owned(),
        passed: problems.is_empty(),
        decision: if error.is_some() {
            None
        } else {
            Some(answered.permitted)
        },
        policies: decided,
        evaluations: per_evaluation
            .iter()
            .map(|(request_id, permitted, policies)| {
                let cited = if policies.is_empty() {
                    String::new()
                } else {
                    format!("({})", policies.join(", "))
                };

                format!(
                    "{}={}{cited}",
                    request_id.as_deref().unwrap_or("?"),
                    if *permitted { "permit" } else { "deny" }
                )
            })
            .collect(),
        error,
        problems,
    }
}

fn cite(policies: &[String]) -> String {
    if policies.is_empty() {
        "nothing".to_owned()
    } else {
        policies.join(", ")
    }
}

pub fn failed(located: &Located, profile: &str, problem: String) -> Outcome {
    Outcome {
        name: located.case.name.clone(),
        source: located.source.clone(),
        profile: profile.to_owned(),
        passed: false,
        decision: None,
        policies: Vec::new(),
        evaluations: Vec::new(),
        error: Some(problem.clone()),
        problems: vec![problem],
    }
}

/// What a request asks, or the refusal a data plane would have answered with.
///
/// Deserialized into `permguard_languages::request::CheckRequest` — **the type the
/// data plane deserializes into** — and then asked with the same `asked()` the plane
/// calls. Hand-written field checks were tried here twice and were partial twice:
/// they missed the JSON types, then `principal` and `options`, then boxcarring
/// altogether. One definition is the only way this stays true, so this is now the
/// deserialization and nothing else.
///
/// The two refusals a plane draws are drawn here with its own codes, so a case may
/// expect either and mean the same thing in both modes: `payload_malformed` for a
/// body its types would not read, and whatever `asked()` names for a field the
/// contract requires — `field_required`, `too_many_evaluations`.
pub fn asked(payload: &Value) -> std::result::Result<languages::Asked, String> {
    let request: languages::CheckRequest = serde_json::from_value(payload.clone())
        .map_err(|error| format!("payload_malformed: {error}"))?;

    request
        .asked(MAX_EVALUATIONS)
        .map_err(|refusal| format!("{}: {}", refusal.code, refusal.message))
}

/// As many evaluations as this plane's own default accepts. A workspace that would
/// be refused for boxcarring too much has to be refused here too.
const MAX_EVALUATIONS: usize = 256;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_path_is_read_relative_to_its_case_file() {
        assert_eq!(
            beside("tests/release.yml", "../requests/permit.json"),
            "requests/permit.json"
        );
        assert_eq!(
            beside("tests/deep/release.yml", "../../requests/permit.json"),
            "requests/permit.json"
        );
        assert_eq!(beside("tests/release.yml", "here.json"), "tests/here.json");
    }
}
