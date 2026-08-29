// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! One Dogwood partition, compiled: the artifacts of a ledger commit, lowered once.
//!
//! # What "once" means, and why it is load and not request
//!
//! Parsing an event schema, lowering a policy set to Cedar and validating it are the expensive
//! things Dogwood does, and they answer the same question every time for a given commit. They
//! happen here, when a commit is loaded, and never again — a decision path that re-lowered a
//! policy set would spend most of a request doing work whose answer had not changed since the last
//! one.
//!
//! # Why the temporal half is not the evaluating half
//!
//! A Cedar partition answers a stateless question and can answer several at once. A Dogwood
//! partition has a past: `is_authorized` observes the event into the history *and* decides against
//! it, so two occurrences of one partition have an order, and the order is what the answer depends
//! on. That is why application is serialised here rather than left to whoever calls, and why a
//! Dogwood partition refuses the stateless PDP query outright instead of answering it with the
//! history left out.

use std::collections::BTreeMap;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use cedar_policy::{Entities, EntityUid, Schema};
use dogwood_language::{
    Authorizer, EventFieldType, EventPinRoot, LoweredPolicySet, ParsedPolicySet, PolicySchema,
    ProviderDeclarations, ServiceSchema, Validator, Value as DogwoodValue,
};

use crate::artifact::Artifacts;
use crate::evaluate::{Evaluating, Evaluator, Query, StoredPolicy, Verdict};
use crate::temporal::{Applied, Checked, Contract, Field, Pin, PinSource, Refused, Signature};

use super::artifacts as registry;
use super::occurrence::Occurrence;
use super::value;

/// The default furthest-back window, when the event schema declares none.
///
/// Upstream's `DEFAULT_MAX_WINDOW`, kept crate-private there, so it is stated here and held to
/// upstream by a test that lowers a schema with a longer `within` and expects the refusal.
pub const DEFAULT_MAX_WINDOW_SECONDS: i64 = 24 * 3600;

impl Evaluating for super::Dogwood {
    fn compile(
        &self,
        policies: &[StoredPolicy],
        artifacts: &Artifacts,
    ) -> Result<Box<dyn Evaluator>, String> {
        let action_source = artifacts
            .bytes(registry::ACTION_SCHEMA)
            .ok_or_else(|| "dogwood: the partition carries no action schema".to_owned())?;
        let action_source = super::source_of(action_source, "an action schema")?;
        let schema = PolicySchema::from_cedarschema_str(action_source)
            .map_err(|error| format!("dogwood: the action schema is not usable: {error}"))?;

        let service = service_schema(artifacts)?;

        // Every policy of the partition is lowered as **one** set, because that is what a Dogwood
        // partition is: a macro defined in the library and an action declared in the schema are
        // visible to all of them, and lowering them separately would give each its own idea of
        // what the partition means.
        let mut source = String::new();
        let mut owners: Vec<String> = Vec::new();
        for stored in policies {
            let text = super::source_of(&stored.source, "a Dogwood policy")?;
            let parsed = ParsedPolicySet::parse(text, &service).map_err(|error| {
                format!("dogwood: policy {} does not parse: {error}", stored.id)
            })?;
            // Each rule of this blob is owned by this blob's identity, so a decision citing rule
            // *n* of the joined set cites the Permguard policy it came from — the identity that
            // survives a rename, not an index into a string this build happened to build.
            owners.extend(std::iter::repeat_n(
                stored.id.clone(),
                parsed.policy_count(),
            ));
            source.push_str(text);
            if !text.ends_with('\n') {
                source.push('\n');
            }
        }

        let lowered = LoweredPolicySet::from_str(&source, &service, &schema)
            .map_err(|error| format!("dogwood: the partition does not lower: {error}"))?;

        // Validation is not advisory. A set with errors is a set whose policies mean something
        // other than what they say, and serving it would be answering against a model nobody
        // agreed to.
        let result = Validator::new().validate(&lowered);
        if !result.validation_passed() {
            let errors: Vec<String> = result
                .validation_errors()
                .map(ToString::to_string)
                .collect();
            return Err(format!(
                "dogwood: the partition does not validate: {}",
                errors.join("; ")
            ));
        }

        let contract = contract_of(&lowered, artifacts)?;
        check_pins_are_injectable(&contract)?;
        // The *augmented* schema: the action schema plus what lowering added to it (the hoisted
        // `context.providers.<id>` fields). Kept beside the authorizer because an attributed
        // entity store has to be checked against it before a decision, and afterwards is too
        // late — Cedar reads an entity it does not recognise as having no attributes, so a
        // mistyped store weakens a policy rather than failing it.
        let cedar_schema = lowered.cedar_schema().clone();
        let footprint = source.len() + artifacts.footprint();
        let identities: Vec<String> = policies.iter().map(|stored| stored.id.clone()).collect();

        // Partitioned temporal evaluation whenever the schema declares a universal symmetric pin.
        // Upstream calls it an equivalent and typically much cheaper alternative to the
        // relativization rewrite; it is a no-op when there is no such pin, which is exactly the
        // case `history: { scope: global }` acknowledges.
        // Kept so a late-arriving import can be answered by rebuilding rather than by inserting
        // into an engine that has already moved past it. The three are what `LoweredPolicySet`
        // was built from, and rebuilding from them is the only route: lowering consumes the set,
        // and Dogwood's authorizer takes ownership of it.
        let inputs = Inputs {
            source,
            action_schema: action_source.to_owned(),
            artifacts: artifacts.clone(),
            partitioned: contract.is_partitioned(),
        };
        let authorizer = inputs.authorizer(lowered)?;

        // The set lowers and its authorizer builds — proven here, once, so a cold history later
        // cannot be the first time this partition discovers it does not compile. The engine itself
        // is not kept: engines belong to histories, and this partition has none yet.
        drop(authorizer);
        Ok(Box::new(CompiledDogwood {
            histories: Mutex::new(Histories::default()),
            inputs,
            cedar_schema,
            contract,
            owners,
            identities,
            footprint,
        }))
    }
}

/// The service schema: the event schema, macros and providers this partition carries.
///
/// Absence is a choice made explicitly. A partition with no event schema gets Dogwood's declared
/// defaults, which pin `callerPrincipal` on every kind — not "no schema", which would be a
/// partition whose history is scoped by nothing.
fn service_schema(artifacts: &Artifacts) -> Result<ServiceSchema, String> {
    let mut builder = ServiceSchema::builder();
    if let Some(bytes) = artifacts.bytes(registry::EVENT_SCHEMA) {
        builder = builder.event_schema_str(super::source_of(bytes, "an event schema")?);
    }
    if let Some(bytes) = artifacts.bytes(registry::MACROS) {
        builder = builder.macros_str(super::source_of(bytes, "a macro library")?);
    }
    if let Some(bytes) = artifacts.bytes(registry::PROVIDERS) {
        builder = builder.providers(provider_declarations(bytes, artifacts)?);
    }

    builder
        .build()
        .map_err(|error| format!("dogwood: the service schema does not build: {error}"))
}

/// The provider declarations, with every `scriptFile` resolved **from the ledger**.
///
/// Upstream resolves a `scriptFile` relative to the declarations file on disk. A server has no
/// such file and must not acquire one: a declaration that could name a path would be a policy
/// artifact that reads the host filesystem, and the ledger would no longer describe what runs. So
/// the reference is resolved against the provider programs the same commit carries, by name, and a
/// name that matches none of them refuses the load rather than falling back to anything.
fn provider_declarations(
    bytes: &[u8],
    artifacts: &Artifacts,
) -> Result<ProviderDeclarations, String> {
    let source = super::source_of(bytes, "provider declarations")?;
    let mut declarations = ProviderDeclarations::from_json(source)
        .map_err(|error| format!("dogwood: the provider declarations do not parse: {error}"))?;

    let programs = artifacts.all(registry::RHAI_PROVIDER);
    let mut referenced: Vec<&str> = Vec::new();
    for (name, declaration) in &mut declarations.available {
        let Some(dogwood_language::Implementation::Rhai {
            script,
            script_file,
        }) = declaration.implementation.as_mut()
        else {
            continue;
        };
        if script.is_some() {
            if let Some(file) = script_file.take() {
                return Err(format!(
                    "dogwood: the provider `{name}` states both an inline `script` and a \
                     `scriptFile` (`{file}`), and which of the two runs is not something to guess"
                ));
            }

            continue;
        }
        let Some(file) = script_file.take() else {
            return Err(format!(
                "dogwood: the provider `{name}` declares a Rhai implementation with neither a \
                 `script` nor a `scriptFile`"
            ));
        };
        // Named, never pathed: the resolution is a lookup in this partition's own artifacts, so
        // `../`, an absolute path and a symlink are not refused case by case — they are not
        // expressible, because there is no filesystem on the other side of this name.
        let Some(program) = programs.iter().find(|held| held.name == file) else {
            return Err(format!(
                "dogwood: the provider `{name}` names the script `{file}`, which this partition \
                 does not carry. Provider programs are resolved from the ledger commit, never \
                 from the host: {}",
                if programs.is_empty() {
                    "it carries none".to_owned()
                } else {
                    format!(
                        "it carries {}",
                        programs
                            .iter()
                            .map(|held| held.name.as_str())
                            .collect::<Vec<&str>>()
                            .join(", ")
                    )
                }
            ));
        };
        referenced.push(&program.name);
        *script = Some(super::source_of(&program.data, "a provider script")?.to_owned());
    }

    // A program nothing references is not harmless: it is content in the ledger that no
    // declaration accounts for, and a reader cannot tell whether it is dead or whether a
    // declaration meant to name it and misspelled the name.
    if let Some(orphan) = programs
        .iter()
        .find(|held| !referenced.contains(&held.name.as_str()))
    {
        return Err(format!(
            "dogwood: the provider script `{}` is carried by the partition and referenced by no \
             declaration",
            orphan.name
        ));
    }

    Ok(declarations)
}

/// What the loaded schemas say this partition accepts.
fn contract_of(lowered: &LoweredPolicySet, artifacts: &Artifacts) -> Result<Contract, String> {
    let mut kinds: Vec<String> = Vec::new();
    let mut signatures: Vec<Signature> = Vec::new();
    for signature in lowered.event_signatures() {
        let action = qualified(signature.namespace(), signature.action());
        if !kinds.iter().any(|held| held == signature.kind()) {
            kinds.push(signature.kind().to_owned());
        }
        signatures.push(Signature {
            action,
            kind: signature.kind().to_owned(),
            decision: signature.is_decision(),
            fields: signature
                .fields()
                .map(|field| Field {
                    path: field.path().to_vec(),
                    declared: declared_type(field.field_type()),
                })
                .collect(),
            pins: signature.pins().map(read_pin).collect(),
        });
    }
    kinds.sort();
    let mut decision_kinds: Vec<String> = lowered.decision_kinds().map(ToOwned::to_owned).collect();
    decision_kinds.sort();

    let history_pins: Vec<Vec<String>> = lowered
        .partition_keys()
        .iter()
        .map(|key| key.field_path.clone())
        .collect();

    let max_window_seconds = match artifacts.bytes(registry::EVENT_SCHEMA) {
        Some(bytes) => max_window_seconds(super::source_of(bytes, "an event schema")?)?,
        None => DEFAULT_MAX_WINDOW_SECONDS,
    };

    Ok(Contract {
        max_window_seconds,
        kinds,
        decision_kinds,
        history_pins,
        signatures,
    })
}

/// Refuses a schema whose pins Permguard cannot inject, before anything depends on them.
///
/// # The limitation this closes
///
/// A pin decides which history an event belongs to, so the server derives its value and writes it
/// into the logged record. Upstream's **public** event builder can write exactly two shapes of
/// logged field: the principal and resource aliases (`principal_for` / `resource_for`, which file
/// `callerPrincipal` and `callerResource`), and a field inside a named group (`field(group, name,
/// …)`). A logged field at any other path — a bare top-level leaf like `sessionId`, or a leaf
/// nested two groups deep — has no public setter; upstream's own trace parser reaches the event's
/// data structure directly, and that route is crate-private.
///
/// What that would mean if it were let through is the failure this whole integration exists to
/// prevent. The temporal engine routes each event to a partition by reading the pinned field; a
/// pin nobody could write reads as absent on **every** event, so every event lands in one
/// partition, and a schema that meant "a session sees only its own history" silently means "every
/// session sees every other one". The policies still evaluate, and they answer differently than
/// they read.
///
/// So it is refused at load, where an operator can see it, rather than becoming a property of the
/// verdicts. When upstream's builder gains a general setter this check is what to delete.
fn check_pins_are_injectable(contract: &Contract) -> Result<(), String> {
    for signature in &contract.signatures {
        for pin in &signature.pins {
            if injectable(&pin.field) {
                continue;
            }

            return Err(format!(
                "dogwood: the event schema pins `{}` on a `{}` event of `{}`, and this build \
                 cannot write that field. A pin decides which history an event belongs to, and one \
                 the server cannot write is absent on every event — which would put every event \
                 in one history and silently widen what a temporal predicate matches. Pin \
                 `callerPrincipal` or `callerResource`, or a field inside a group \
                 (`session.id`), which are the logged fields upstream's public event builder can \
                 write",
                pin.field.join("."),
                signature.kind,
                signature.action
            ));
        }
    }

    Ok(())
}

/// Whether a logged field at this path can be written through upstream's public builder.
fn injectable(path: &[String]) -> bool {
    match path {
        [only] => {
            only == super::occurrence::CALLER_PRINCIPAL
                || only == super::occurrence::CALLER_RESOURCE
        }
        // `field(group, name, value)` writes exactly one level inside one group.
        [_group, _name] => true,
        _ => false,
    }
}

/// The `max_window = <n><unit>` directive, or the default when the schema declares none.
///
/// # Why this is parsed here at all
///
/// Upstream parses it — `event_schema::grammar.pest`, `max_window_decl` — but keeps the module
/// `pub(crate)`, so the number never reaches a dependency. And the number is one the event store
/// needs: it is the retention floor, and a store that guessed it would either keep history nothing
/// reads or delete history a policy is still looking at.
///
/// # What it is a copy of, and how closely
///
/// The grammar, as of `dogwood-language` 1.0:
///
/// ```text
/// schema_entry    = { SOI ~ max_window_decl? ~ event_decl* ~ EOI }
/// max_window_decl = { kw_max_window ~ "=" ~ interval }
/// kw_max_window   = @{ "max_window" ~ !(ASCII_ALPHANUMERIC | "_") }
/// interval        = { integer ~ time_unit }
/// integer         = @{ ASCII_DIGIT+ }
/// time_unit       = { "s" | "m" | "h" | "d" }
/// WHITESPACE      = _{ " " | "\t" | "\r" | "\n" }
/// COMMENT         = _{ "//" ~ (!("\n" | "\r") ~ ANY)* }
/// ```
///
/// Three things follow from it that a line-by-line reading gets wrong, and did:
///
/// * `WHITESPACE` includes newlines, and `max_window_decl` and `interval` are not atomic — so
///   `max_window\n= 24h` and `max_window = 24 h` are both valid upstream. Reading one line at a
///   time refused schemas upstream compiles.
/// * `kw_max_window` is followed by a non-identifier character, so `max_window_extra` is not the
///   directive.
/// * `build_max_window` refuses a zero interval outright — "a zero window would forbid every
///   temporal `within` clause". The digits alone do not say that, so it is checked here too.
///   Accepting zero was the dangerous half: it is the retention floor, and a floor of zero says
///   every event may be deleted immediately.
///
/// Deliberately narrow otherwise: a schema whose directive this cannot read refuses the load
/// rather than falling back to a default that would silently permit a longer window than the
/// author wrote.
///
/// **Version dependency.** This mirrors a grammar it cannot import. If upstream changes
/// `max_window_decl`, this is where it diverges, and the corpus tests below are what catch it.
fn max_window_seconds(source: &str) -> Result<i64, String> {
    let mut rest = skip_trivia(source);

    // The directive is the first thing in the file or it is absent: upstream's entry rule admits
    // it only before the declarations.
    let Some(after) = rest.strip_prefix("max_window") else {
        return Ok(DEFAULT_MAX_WINDOW_SECONDS);
    };
    // `kw_max_window` ends where an identifier would carry on, so `max_window_extra` is a
    // different word and not a malformed directive.
    if after.starts_with(|character: char| character.is_ascii_alphanumeric() || character == '_') {
        return Ok(DEFAULT_MAX_WINDOW_SECONDS);
    }
    rest = skip_trivia(after);

    let Some(after) = rest.strip_prefix('=') else {
        return Err("dogwood: the event schema's `max_window` states `= <n><s|m|h|d>`".to_owned());
    };
    rest = skip_trivia(after);

    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    if digits.is_empty() {
        return Err(format!(
            "dogwood: the event schema's `max_window` states `= <n><s|m|h|d>`, and `{}` is not a \
             number",
            first_word(rest)
        ));
    }
    rest = skip_trivia(&rest[digits.len()..]);

    let seconds = match rest.chars().next() {
        Some('s') => 1,
        Some('m') => 60,
        Some('h') => 3600,
        Some('d') => 86_400,
        _ => {
            return Err(format!(
                "dogwood: the event schema's `max_window` names the unit `{}`, and the units are \
                 `s`, `m`, `h` and `d`",
                first_word(rest)
            ));
        }
    };
    let amount: i64 = digits.parse().map_err(|_| {
        format!("dogwood: the event schema's `max_window` of `{digits}` is out of range")
    })?;
    // Upstream refuses this outright, and so must this: a zero cap forbids every `within` clause,
    // and as a retention floor it says every event may be deleted the moment it lands.
    if amount == 0 {
        return Err(
            "dogwood: the event schema's `max_window` is zero, which would forbid every temporal \
             `within` clause. Omit it for the default, or state a positive interval like `24h`"
                .to_owned(),
        );
    }

    amount
        .checked_mul(seconds)
        .ok_or_else(|| format!("dogwood: the event schema's `max_window` of `{digits}` overflows"))
}

/// Skips whitespace and line comments, which upstream's grammar treats as invisible everywhere.
fn skip_trivia(source: &str) -> &str {
    let mut rest = source.trim_start();
    while let Some(after) = rest.strip_prefix("//") {
        let line_end = after.find(['\n', '\r']).unwrap_or(after.len());
        rest = after[line_end..].trim_start();
    }

    rest
}

/// As much of `rest` as is worth quoting back in a refusal.
fn first_word(rest: &str) -> &str {
    let end = rest
        .find(|character: char| character.is_whitespace())
        .unwrap_or(rest.len());

    &rest[..end.min(24)]
}

/// One of Dogwood's pins, in Permguard's own terms.
fn read_pin(pin: &dogwood_language::EventPin) -> Pin {
    let source = match (pin.root(), pin.target_path().first().map(String::as_str)) {
        (EventPinRoot::Scope, Some("resource")) => PinSource::Resource,
        (EventPinRoot::Scope, _) => PinSource::Principal,
        (EventPinRoot::Context, _) => PinSource::Context(pin.target_path().to_vec()),
    };

    Pin {
        field: pin.field_path().to_vec(),
        source,
    }
}

/// The declared type of a field, as text.
fn declared_type(field_type: &EventFieldType) -> String {
    match field_type {
        EventFieldType::Cedar(rendered) => rendered.clone(),
        // An injected `principalType(A)` field: its full declared set, not one collapsed name.
        EventFieldType::EntityTypes(types) => types.join(" | "),
    }
}

/// A namespace path and a bare action id, rejoined as a policy names them.
fn qualified(namespace: &[String], action: &str) -> String {
    if namespace.is_empty() {
        return action.to_owned();
    }

    format!("{}::{action}", namespace.join("::"))
}

/// What a fresh authorizer is built from.
///
/// Held rather than recomputed from the ledger, because a rebuild happens on the decision path and
/// reaching back to the object store there would make a late arrival cost a disk walk as well as a
/// re-lowering.
struct Inputs {
    /// Every policy of the partition, joined as they were lowered.
    source: String,
    /// The action schema, verbatim.
    action_schema: String,
    /// The rest of the partition's artifacts.
    artifacts: Artifacts,
    /// Whether the schema declares a universal symmetric pin.
    partitioned: bool,
}

impl Inputs {
    /// A fresh authorizer over an already-lowered set.
    fn authorizer(&self, lowered: LoweredPolicySet) -> Result<Authorizer, String> {
        let mut builder = Authorizer::builder(lowered);
        if self.partitioned {
            builder = builder.partition_temporal();
        }

        builder
            .build()
            .map_err(|error| format!("dogwood: the authorizer does not build: {error}"))
    }

    /// A fresh authorizer, lowered again from these inputs.
    fn rebuild(&self) -> Result<Authorizer, String> {
        let schema = PolicySchema::from_cedarschema_str(&self.action_schema)
            .map_err(|error| format!("dogwood: the action schema is not usable: {error}"))?;
        let service = service_schema(&self.artifacts)?;
        let lowered = LoweredPolicySet::from_str(&self.source, &service, &schema)
            .map_err(|error| format!("dogwood: the partition does not lower: {error}"))?;

        self.authorizer(lowered)
    }
}

/// One history partition's engine, and what it has been told.
struct Held {
    /// Serialised on purpose. `is_authorized` both observes the event into the history and decides
    /// against it, so two occurrences of one history have an order — and a history that let two
    /// through at once would be deciding one against a history that did not yet include the other,
    /// with which one that was depending on the scheduler.
    ///
    /// Per history rather than per partition, so two callers' events do not queue behind each
    /// other: they are independent histories, and serialising them together would make one busy
    /// caller everybody else's latency.
    authorizer: Mutex<Authorizer>,
    /// How many occurrences this engine has been given since it was built or last rebuilt.
    ///
    /// The plane's cue that a history is cold and has to be replayed into this engine before it
    /// answers. Counted here rather than outside, because what a rebuild replaces is the engine,
    /// and a count kept beside it would survive the thing it described.
    observed: std::sync::atomic::AtomicU64,
}

/// How many history partitions one compiled partition keeps engines for.
///
/// # Why there is a bound at all, and why eviction is safe
///
/// A schema that pins the caller has one history per caller, and a tenant has as many callers as it
/// has. Keeping an engine for each would make memory a function of the tenant's user base, which is
/// a caller-controlled allocation — the thing a multi-tenant plane must never have.
///
/// Evicting one costs a rebuild and changes no answer: the durable journal is the authority, and a
/// history that is asked for again is replayed from it before it decides. What eviction buys is
/// that the cost of a cold history is paid by the request that wanted it, rather than by the whole
/// plane running out of memory.
///
/// This is a bound on what is held *warm*, never on how many histories a ledger may have. Each one
/// held costs a lowered policy set as well as the events it has absorbed, so the number is chosen
/// to be generous for a working set and small enough that a partition's memory stays something an
/// operator can reason about.
const HOT_HISTORIES: usize = 256;

/// The history partitions this compiled partition currently holds engines for.
///
/// Least-recently-used, so what stays is what is being asked about. The recency list is kept beside
/// the map rather than inside it because an engine is handed out as an `Arc` and used without the
/// map's lock held — two callers of one history share an engine, and neither blocks the other's
/// history.
#[derive(Default)]
struct Histories {
    held: std::collections::HashMap<String, Arc<Held>>,
    /// Most recently used last.
    recency: std::collections::VecDeque<String>,
}

impl Histories {
    /// Notes that `history` was just used, and returns whatever it is holding for it.
    fn touch(&mut self, history: &str) -> Option<Arc<Held>> {
        let found = self.held.get(history).map(Arc::clone)?;
        if let Some(at) = self.recency.iter().position(|held| held == history) {
            self.recency.remove(at);
        }
        self.recency.push_back(history.to_owned());

        Some(found)
    }

    /// Installs an engine for `history`, evicting the coldest if that puts it over the bound.
    fn keep(&mut self, history: &str, engine: Arc<Held>) {
        if let Some(at) = self.recency.iter().position(|held| held == history) {
            self.recency.remove(at);
        }
        self.held.insert(history.to_owned(), engine);
        self.recency.push_back(history.to_owned());

        while self.recency.len() > HOT_HISTORIES {
            let Some(coldest) = self.recency.pop_front() else {
                break;
            };
            self.held.remove(&coldest);
        }
    }
}

/// A Dogwood partition, compiled and ready.
struct CompiledDogwood {
    /// One engine per history partition, bounded and least-recently-used.
    histories: Mutex<Histories>,
    /// What it takes to build a fresh authorizer, for a cold history or a rebuild.
    inputs: Inputs,
    /// The lowered Cedar schema, for the checks that happen before a decision.
    cedar_schema: Schema,
    contract: Contract,
    /// The Permguard policy identity owning each rule of the joined set, by rule index.
    owners: Vec<String>,
    identities: Vec<String>,
    footprint: usize,
}

impl CompiledDogwood {
    /// The engine for one history, building an empty one if this partition holds none.
    ///
    /// An engine built here has observed nothing, which is exactly what the plane reads to know it
    /// must replay before deciding. Cold and *empty* are the same state on purpose: a history this
    /// process has never held and one it evicted are indistinguishable, and both are answered from
    /// the durable record rather than from what happened to still be in memory.
    fn engine(&self, history: &str) -> Result<Arc<Held>, Refused> {
        {
            let mut histories = self.histories.lock().map_err(|_| {
                Refused::new(
                    "partition_poisoned",
                    "this partition's history is not in a state it can decide against, because an \
                     earlier evaluation of it panicked",
                )
            })?;
            if let Some(found) = histories.touch(history) {
                return Ok(found);
            }
        }

        // Built outside the map's lock: lowering a policy set is expensive, and holding the lock
        // across it would make one cold history block every other history's decisions.
        let fresh = Arc::new(Held {
            authorizer: Mutex::new(
                self.inputs
                    .rebuild()
                    .map_err(|detail| Refused::new("partition_not_rebuildable", detail))?,
            ),
            observed: std::sync::atomic::AtomicU64::new(0),
        });

        let mut histories = self.histories.lock().map_err(|_| {
            Refused::new(
                "partition_poisoned",
                "this partition's history is not in a state it can decide against, because an \
                 earlier evaluation of it panicked",
            )
        })?;
        // Another caller may have built one meanwhile. Theirs wins: two engines for one history
        // would each hold half of it.
        if let Some(found) = histories.touch(history) {
            return Ok(found);
        }
        histories.keep(history, Arc::clone(&fresh));

        Ok(fresh)
    }
}

impl Evaluator for CompiledDogwood {
    /// Refuses, which denies.
    ///
    /// Not an omission: the stateless PDP asks whether a subject may act on a resource *now*, and
    /// a Dogwood policy's answer depends on what has already happened. Answering the stateless
    /// question against an empty history would return a verdict the partition does not hold — and
    /// it would return it as an ordinary permit or deny, indistinguishable from one the policies
    /// meant.
    fn evaluate(&self, query: &Query) -> Verdict {
        let _ = query;

        Verdict::refused(
            "this is a Dogwood partition, and a Dogwood policy decides against history. Submit \
             the request as an event to the temporal interface \
             (`permguard.api.pdp.temporal.v1alpha1`); the stateless interface has no history to \
             decide it against"
                .to_owned(),
        )
    }

    fn footprint(&self) -> usize {
        self.footprint
    }

    fn policies(&self) -> Vec<String> {
        self.identities.clone()
    }

    fn temporal(&self) -> Option<&dyn crate::temporal::Temporal> {
        Some(self)
    }
}

impl crate::temporal::Temporal for CompiledDogwood {
    fn contract(&self) -> &Contract {
        &self.contract
    }

    fn check(&self, occurrence: &Occurrence) -> Result<Checked, Refused> {
        let Some(signature) = self
            .contract
            .signature(&occurrence.action, &occurrence.kind)
        else {
            return Err(unknown_event(&self.contract, occurrence));
        };
        self.check_scope(occurrence)?;
        self.check_entities(occurrence)?;

        // The logged bag is the event schema's, whole: a field it does not declare is a field no
        // temporal predicate can correlate on, so sending one is a mistake to hear about rather
        // than a value to store and never read.
        for (group, value) in &occurrence.logged {
            check_leaf(signature, "logged", &mut vec![group.clone()], value, true)?;
            // Declared is not the same as carriable. Upstream's public builder writes a logged
            // field either as one of the two scope aliases or inside a named group, so a bare
            // top-level leaf the schema declares — `requestId`, `sessionId` — has nowhere to go.
            // Accepting one and dropping it would store an event that answers differently from
            // the one that was sent; the pins that would have the same problem are refused a
            // load earlier, where an operator can act on it.
            if !matches!(value, DogwoodValue::Object(_)) && !injectable(std::slice::from_ref(group))
            {
                return Err(Refused::new(
                    "event_field_not_carriable",
                    format!(
                        "`logged.{group}` is a top-level field, and this build writes a logged \
                         field only as `{}` / `{}` or inside a group. It would be dropped rather \
                         than stored, so it is refused instead",
                        super::occurrence::CALLER_PRINCIPAL,
                        super::occurrence::CALLER_RESOURCE
                    ),
                ));
            }
        }
        // The request context is a different contract, and deliberately a looser one. The event
        // schema splices the action's `input` / `output` groups into the event, so those are
        // checked exactly as the logged bag is — but a group it does not splice (`system`, a
        // deployment's own) is Cedar-only context the event schema does not describe, and Dogwood's
        // value model cannot carry every type Cedar declares there anyway (it has no `datetime`).
        // Checking it against the event's fields would refuse context the action schema declares;
        // checking it against Cedar's own would refuse the very requests upstream accepts.
        for (group, value) in &occurrence.request_context {
            check_leaf(
                signature,
                "request_context",
                &mut vec![group.clone()],
                value,
                false,
            )?;
        }

        let mut pins = Vec::with_capacity(signature.pins.len());
        let mut injected = BTreeMap::new();
        for pin in &signature.pins {
            let value = pin_value(occurrence, pin)?;
            // If the caller also sent the pinned field, it must be the value its source says. One
            // of two different values is a lie about the request, and choosing either would decide
            // which — silently, and in the direction that happens to be cheaper to implement.
            if let Some(sent) = read_path(&occurrence.logged, &pin.field)
                && !sent.dom_eq(&value)
            {
                return Err(Refused::new(
                    "event_pin_contradicted",
                    format!(
                        "`logged.{}` was sent as {} and this partition's schema pins it to {}, \
                         which is {}. A pin decides which history the event belongs to, so it is \
                         derived from the request's authoritative roots and never taken from the \
                         caller",
                        pin.field.join("."),
                        value::render(sent),
                        pin.source.describe(),
                        value::render(&value)
                    ),
                ));
            }
            let rendered = value::canonical(&value);
            injected.insert(pin.field.clone(), rendered.clone());
            pins.push((pin.field.clone(), rendered));
        }

        Ok(Checked {
            decides: signature.decision,
            pins,
            injected,
        })
    }

    fn rebuild(&self, history: &str, occurrences: &[Occurrence]) -> Result<(), Refused> {
        // Built before any lock is taken, so a rebuild that fails leaves this history deciding
        // against what it already had rather than against nothing.
        let mut fresh = self
            .inputs
            .rebuild()
            .map_err(|detail| Refused::new("partition_not_rebuildable", detail))?;
        for occurrence in occurrences {
            let event = occurrence.to_event().map_err(|malformed| {
                Refused::new(
                    "history_not_replayable",
                    format!(
                        "the occurrence `{}` is in this partition's history and cannot be replayed \
                         into it: {malformed}",
                        occurrence.event_id
                    ),
                )
            })?;
            // The verdicts of a replay are discarded: what is being rebuilt is the *history*, and
            // a decision made now against a partial replay would be a decision nobody asked for.
            let _ = fresh.is_authorized(&event);
        }

        let engine = self.engine(history)?;
        let mut held = engine.authorizer.lock().map_err(|_| {
            Refused::new(
                "partition_poisoned",
                "this partition's history is not in a state it can be rebuilt from, because an \
                 earlier evaluation of it panicked",
            )
        })?;
        *held = fresh;
        // The count belongs to the authorizer that was just installed, not to the one it replaced.
        // Set under the same lock, so nobody can see a fresh authorizer with the old count or the
        // other way round.
        engine.observed.store(
            occurrences.len() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );

        Ok(())
    }

    fn observed(&self, history: &str) -> u64 {
        // Absent is zero, and deliberately: a history this process never held and one it evicted
        // are the same state to a caller, and both must be replayed before they decide.
        let Ok(mut histories) = self.histories.lock() else {
            return 0;
        };

        histories
            .touch(history)
            .map(|engine| engine.observed.load(std::sync::atomic::Ordering::Relaxed))
            .unwrap_or(0)
    }

    fn apply(&self, history: &str, occurrence: &Occurrence, checked: &Checked) -> Applied {
        let event = match occurrence.to_event() {
            Ok(event) => event,
            // Checked before it was journalled, so this is not a caller's mistake reaching here
            // late — it is this build disagreeing with itself, and a deny is the only answer that
            // does not depend on which of the two was right.
            Err(malformed) => {
                return Applied::Decided(Verdict::refused(malformed.to_string()));
            }
        };

        // The history this occurrence belongs to, and no other. A schema that pins the caller has
        // one history per caller, and Alice's `Login` is invisible to Bob's `Read` because the two
        // are not in the same one — not because a policy checks.
        let engine = match self.engine(history) {
            Ok(engine) => engine,
            Err(refused) => return Applied::Decided(Verdict::refused(refused.message)),
        };

        // The lock is held across the whole call because that is what makes this history ordered:
        // the event is observed and decided as one step.
        let response = match engine.authorizer.lock() {
            Ok(mut authorizer) => {
                // Counted before the call rather than after it, and under the lock: whatever
                // `is_authorized` answers, the event is in this authorizer's history once it
                // returns, and an engine that had observed something must never read as fresh.
                engine
                    .observed
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                authorizer.is_authorized(&event)
            }
            // A history whose lock a panicking thread left poisoned is one nobody can vouch for.
            // Fail closed rather than reach past the poison for the state.
            Err(_) => {
                return Applied::Decided(Verdict::refused(
                    "this Dogwood partition's history is not in a state it can decide against, \
                     because an earlier evaluation of it panicked"
                        .to_owned(),
                ));
            }
        };

        let Some(response) = response else {
            // Upstream returns `None` for a history-only kind, and that is the whole answer: the
            // event is in the history and there is no verdict to invent.
            return Applied::Observed;
        };
        if !checked.decides {
            // The contract said this kind does not decide and the runtime decided it. Two answers
            // about what an event *is* is not a thing to reconcile at request time.
            return Applied::Decided(Verdict::refused(format!(
                "the kind `{}` is not a decision kind in this partition's schema, and the runtime \
                 returned a verdict for it",
                occurrence.kind
            )));
        }

        let determining: Vec<String> = response
            .diagnostics()
            .reason()
            .filter_map(|rule| self.owners.get(rule.rule_index).cloned())
            .collect();
        let errors: Vec<&str> = response.diagnostics().errors().collect();
        if !errors.is_empty() {
            // Upstream degrades rather than aborting: a provider that could not run or an
            // unresolvable attribute is reported beside a fail-closed deny. Permguard reports it
            // as what it is — a partition that could not evaluate — so the deny is not mistaken
            // for one a policy expressed.
            return Applied::Decided(Verdict::refused(errors.join("; ")));
        }

        Applied::Decided(if response.allowed() {
            Verdict::permit(determining)
        } else {
            Verdict::deny(determining)
        })
    }
}

impl CompiledDogwood {
    /// Checks the action, the principal and the resource against the action schema.
    ///
    /// Upstream's reference authorizer builds its Cedar request with no schema at all, so an
    /// action nothing declares and a principal of a type the action does not admit both reach the
    /// policies and are answered with an implicit deny — indistinguishable from a policy deciding
    /// so. Neither is a decision anyone made, and both are mistakes worth hearing about.
    fn check_scope(&self, occurrence: &Occurrence) -> Result<(), Refused> {
        let action = EntityUid::from_str(&action_uid(&occurrence.action)).map_err(|error| {
            Refused::new(
                "event_action_malformed",
                format!(
                    "`{}` is not an action reference: {error}",
                    occurrence.action
                ),
            )
        })?;
        let Some(principals) = self.cedar_schema.principals_for_action(&action) else {
            return Err(Refused::new(
                "event_action_undeclared",
                format!(
                    "this partition's action schema declares no action `{}`",
                    occurrence.action
                ),
            ));
        };
        let admitted: Vec<String> = principals.map(ToString::to_string).collect();
        if !admitted.contains(&occurrence.principal.kind) {
            return Err(Refused::new(
                "event_principal_not_admitted",
                format!(
                    "`{}` does not act on `{}` in this partition's action schema; it admits {}",
                    occurrence.principal.kind,
                    occurrence.action,
                    admitted.join(", ")
                ),
            ));
        }
        let admitted: Vec<String> = self
            .cedar_schema
            .resources_for_action(&action)
            .map(|held| held.map(ToString::to_string).collect())
            .unwrap_or_default();
        if !admitted.contains(&occurrence.resource.kind) {
            return Err(Refused::new(
                "event_resource_not_admitted",
                format!(
                    "`{}` is not a resource of `{}` in this partition's action schema; it admits \
                     {}",
                    occurrence.resource.kind,
                    occurrence.action,
                    admitted.join(", ")
                ),
            ));
        }

        Ok(())
    }

    /// Checks the attributed entity store against the augmented action schema.
    ///
    /// Before authorization, because afterwards there is nothing to see: Cedar reads an entity it
    /// was not given as one with no attributes, so a store whose types are wrong does not fail a
    /// policy — it makes `principal.role == "admin"` quietly unresolvable, and a rule meant to
    /// restrict stops restricting.
    fn check_entities(&self, occurrence: &Occurrence) -> Result<(), Refused> {
        if occurrence.entities.is_empty() {
            return Ok(());
        }
        let store: Vec<serde_json::Value> = occurrence
            .entities
            .iter()
            .map(|entity| {
                serde_json::json!({
                    "uid": {"type": entity.uid.kind, "id": entity.uid.id},
                    "attrs": entity
                        .attrs
                        .iter()
                        .map(|(name, held)| (name.clone(), value::to_json(held)))
                        .collect::<serde_json::Map<String, serde_json::Value>>(),
                    "parents": entity
                        .parents
                        .iter()
                        .map(|parent| serde_json::json!({"type": parent.kind, "id": parent.id}))
                        .collect::<Vec<serde_json::Value>>(),
                })
            })
            .collect();

        Entities::from_json_value(serde_json::Value::Array(store), Some(&self.cedar_schema))
            .map(|_| ())
            .map_err(|error| {
                Refused::new(
                    "event_entities_rejected",
                    format!(
                        "the attributed entity store does not conform to this partition's action \
                         schema: {error}"
                    ),
                )
            })
    }
}

/// The refusal for an `(action, kind)` the schema does not derive.
fn unknown_event(contract: &Contract, occurrence: &Occurrence) -> Refused {
    let kinds_for_action: Vec<&str> = contract
        .signatures
        .iter()
        .filter(|held| held.action == occurrence.action)
        .map(|held| held.kind.as_str())
        .collect();

    if kinds_for_action.is_empty() {
        return Refused::new(
            "event_action_undeclared",
            format!(
                "this partition's schema declares no action `{}`",
                occurrence.action
            ),
        );
    }

    Refused::new(
        "event_kind_undeclared",
        format!(
            "this partition's schema declares no `{}` event of `{}`; it declares {}",
            occurrence.kind,
            occurrence.action,
            kinds_for_action.join(", ")
        ),
    )
}

/// Checks one leaf against the signature: that it is declared, and that its type matches.
///
/// `required` says what an undeclared path means. In the logged bag it is a refusal; in the
/// request context it is a Cedar-only field the event schema does not describe, which is passed
/// through — see the two call sites, which is where that difference is explained.
fn check_leaf(
    signature: &Signature,
    bag: &str,
    path: &mut Vec<String>,
    value: &DogwoodValue,
    required: bool,
) -> Result<(), Refused> {
    let declared = signature.fields.iter().find(|field| field.path == *path);
    if let Some(field) = declared {
        return match compatible(&field.declared, value) {
            true => Ok(()),
            // A leaf whose type the renderer does not spell in a form this can read is not
            // reported as wrong — `compatible` answers `true` for those. What reaches here is a
            // leaf whose declared type is one of the shapes it does read, carrying something else.
            false => Err(Refused::new(
                "event_field_mistyped",
                format!(
                    "`{bag}.{}` is declared `{}` on a `{}` event of `{}`, and carries {}",
                    path.join("."),
                    field.declared,
                    signature.kind,
                    signature.action,
                    value::render(value)
                ),
            )),
        };
    }
    if let DogwoodValue::Object(fields) = value {
        // Not a declared leaf, and a record: a group, so descend. A record that *is* a declared
        // leaf was answered above — upstream's matching reads both a whole record and its members,
        // and it is the declaration that says which this is.
        for (name, held) in fields {
            path.push(name.clone());
            let checked = check_leaf(signature, bag, path, held, required);
            path.pop();
            checked?;
        }

        return Ok(());
    }
    if !required {
        return Ok(());
    }

    Err(Refused::new(
        "event_field_undeclared",
        format!(
            "`{bag}.{}` is not a field this partition's schema declares on a `{}` event of `{}`",
            path.join("."),
            signature.kind,
            signature.action
        ),
    ))
}

/// Whether a value can be what the schema declared, as far as the declaration can be read.
///
/// Upstream renders a field's type with Cedar's own printer and says so explicitly: the spelling
/// is for display and coarse classification, not a stable machine format, and a consumer wanting a
/// firm contract should match the leading token. So this matches the leading token, and answers
/// `true` for anything it does not recognise — a record type by name, an extension type — rather
/// than refusing a value because this build could not read the word for its type. Refusing on
/// unfamiliarity would turn a Cedar upgrade into an outage.
fn compatible(declared: &str, value: &DogwoodValue) -> bool {
    // The `EntityTypes` rendering: a `principalType(A)` field, kept as its full declared set.
    if declared.contains(" | ") || declared.contains("::") {
        return match value {
            DogwoodValue::Entity { ty, .. } => declared
                .split(" | ")
                .any(|held| entity_type_matches(held.trim(), ty)),
            _ => false,
        };
    }
    let token = declared
        .split(|character: char| character.is_whitespace() || character == '<')
        .find(|part| !part.is_empty())
        .unwrap_or(declared);

    match token {
        "String" => matches!(value, DogwoodValue::String(_)),
        "Long" => matches!(value, DogwoodValue::Int(_)),
        "Bool" | "Boolean" => matches!(value, DogwoodValue::Bool(_)),
        "decimal" | "Decimal" => matches!(value, DogwoodValue::Decimal(_)),
        "Set" => matches!(value, DogwoodValue::Array(_)),
        _ => true,
    }
}

/// Whether a declared entity-type name names the type an entity reference carries.
///
/// The declared set comes from the action schema **as written**: upstream renders it from Cedar's
/// raw names, so an entity declared inside `namespace Drupe` appears as `OAuthUser`, while the
/// reference on the wire is the resolved `Drupe::OAuthUser`. Matching only on equality would
/// reject every namespaced schema; matching only on the last segment would let `Other::OAuthUser`
/// pass for `Drupe::OAuthUser`. So a qualified declaration is compared whole, and an unqualified
/// one against the reference's own last segment — which is what an unqualified name means.
fn entity_type_matches(declared: &str, ty: &str) -> bool {
    if declared.contains("::") {
        return declared == ty;
    }

    ty.rsplit("::").next() == Some(declared)
}

/// A qualified action, as a Cedar entity reference.
///
/// `Acme::Action::Transfer` names the action entity `Acme::Action::"Transfer"`, which is the form
/// a schema lookup takes. The last segment is the id and everything before it is the type.
fn action_uid(action: &str) -> String {
    match action.rsplit_once("::") {
        Some((namespace, id)) => format!("{namespace}::\"{id}\""),
        None => format!("\"{action}\""),
    }
}

/// The value a pin takes, read from the request root its schema names.
fn pin_value(occurrence: &Occurrence, pin: &Pin) -> Result<DogwoodValue, Refused> {
    match &pin.source {
        PinSource::Principal => Ok(DogwoodValue::Entity {
            ty: occurrence.principal.kind.clone(),
            id: occurrence.principal.id.clone(),
        }),
        PinSource::Resource => Ok(DogwoodValue::Entity {
            ty: occurrence.resource.kind.clone(),
            id: occurrence.resource.id.clone(),
        }),
        PinSource::Context(path) => read_path(&occurrence.request_context, path)
            .cloned()
            .ok_or_else(|| {
                Refused::new(
                    "event_pin_source_absent",
                    format!(
                        "this partition's schema pins `{}` to `{}`, and the request carries no \
                         such value. A pin decides which history the event belongs to, so it is \
                         not something to leave unset",
                        pin.field.join("."),
                        pin.source.describe()
                    ),
                )
            }),
    }
}

/// One value of a bag, by dotted path.
fn read_path<'a>(
    bag: &'a BTreeMap<String, DogwoodValue>,
    path: &[String],
) -> Option<&'a DogwoodValue> {
    let (head, rest) = path.split_first()?;
    let mut held = bag.get(head)?;
    for segment in rest {
        let DogwoodValue::Object(fields) = held else {
            return None;
        };
        held = fields.get(segment)?;
    }

    Some(held)
}

#[cfg(test)]
mod tests {

    #![allow(clippy::expect_used)]

    use super::*;

    /// The history an occurrence belongs to, as a test spells it.
    ///
    /// The plane hashes the pin names and values into the digest the record carries; a test needs
    /// only *a* string that is the same for the same key and different for a different one, and
    /// joining the canonical values is that. What matters here is that two principals are two
    /// histories, which is the property these tests are about.
    fn history(checked: &Checked) -> String {
        checked.pin_values().join("\u{1f}")
    }

    use crate::artifact::{ArtifactBlob, ArtifactType};
    use serde_json::{Value as Json, json};

    /// Upstream's own example: policy, action schema, and the event schema that is its default.
    const POLICY: &str = include_str!("../../tests/fixtures/dogwood/read-login-not-logout.dw");
    const ACTION_SCHEMA: &str =
        include_str!("../../tests/fixtures/dogwood/read-login-not-logout.cedarschema");
    const EVENT_SCHEMA: &str = include_str!("../../tests/fixtures/dogwood/pinned.dwschema");
    /// Upstream's session-pinned alternative, whose pin is a bare top-level logged field.
    const SESSION_PINNED: &str =
        include_str!("../../tests/fixtures/dogwood/session-pinned.dwschema");

    fn artifact(type_name: &str, data: &str) -> (&'static dyn ArtifactType, ArtifactBlob) {
        let held = crate::artifact::artifact_type(type_name).expect("a registered artifact");

        (
            held,
            ArtifactBlob {
                name: held.canonical_filename().unwrap_or("program").to_owned(),
                media_type: held.media_type().to_owned(),
                data: data.as_bytes().to_vec(),
            },
        )
    }

    fn bundle(parts: Vec<(&str, &str)>) -> Artifacts {
        let mut artifacts = Artifacts::default();
        for (type_name, data) in parts {
            let (held, blob) = artifact(type_name, data);
            artifacts.insert(held, blob);
        }

        artifacts
    }

    fn example() -> Box<dyn Evaluator> {
        compile_with(vec![
            (registry::ACTION_SCHEMA, ACTION_SCHEMA),
            (registry::EVENT_SCHEMA, EVENT_SCHEMA),
        ])
        .expect("upstream's own example compiles")
    }

    fn compile_with(parts: Vec<(&str, &str)>) -> Result<Box<dyn Evaluator>, String> {
        compile_policy_with(POLICY, parts)
    }

    fn compile_policy_with(
        policy: &str,
        parts: Vec<(&str, &str)>,
    ) -> Result<Box<dyn Evaluator>, String> {
        super::super::Dogwood.compile(
            &[StoredPolicy {
                id: "01a0-read-login-not-logout".to_owned(),
                alias: Some("read_login_not_logout".to_owned()),
                source: policy.as_bytes().to_vec(),
            }],
            &bundle(parts),
        )
    }

    /// One occurrence of upstream's trace, in Permguard's own event contract.
    fn occurrence(at: i64, action: &str, kind: &str, user: &str, fields: Json) -> Occurrence {
        let instant = permguard_events::index::render_epoch_seconds(at)
            .expect("the trace's timepoints are instants");
        let body: super::super::occurrence::OccurrenceBody = serde_json::from_value(json!({
            "event_id": format!("{action}-{kind}-{at}"),
            "kind": kind,
            "action": action,
            "principal": format!("Drupe::OAuthUser::\"{user}\""),
            "resource": "Drupe::Gateway::\"gw1\"",
            "logged": fields,
            "request_context": {"input": fields["input"]},
            "occurred_at": instant,
        }))
        .expect("the body parses");

        body.read().expect("the occurrence is well formed")
    }

    /// The whole point: upstream's policy, upstream's schema, upstream's trace, upstream's answers.
    #[test]
    fn the_upstream_example_reproduces_the_verdicts_upstream_records() {
        let compiled = example();
        let temporal = compiled.temporal().expect("a Dogwood partition remembers");

        // `expected.out` records four verdicts; the `Login::response` between them is history-only
        // and produces none, which is why it is not in that list.
        let trace: Vec<(i64, &str, &str, &str, Json)> = vec![
            (
                0,
                "Drupe::Action::Login",
                "request",
                "alice",
                json!({"input": {"user": "alice", "server": "s1"}}),
            ),
            (
                5,
                "Drupe::Action::Login",
                "response",
                "alice",
                json!({"input": {"user": "alice", "server": "s1"}, "output": {}}),
            ),
            (
                100,
                "Drupe::Action::Read",
                "request",
                "alice",
                json!({"input": {"user": "alice", "document": "doc1"}}),
            ),
            (
                4000,
                "Drupe::Action::Read",
                "request",
                "alice",
                json!({"input": {"user": "alice", "document": "doc4"}}),
            ),
            (
                4100,
                "Drupe::Action::Read",
                "request",
                "bob",
                json!({"input": {"user": "bob", "document": "doc2"}}),
            ),
        ];

        let mut verdicts = Vec::new();
        for (at, action, kind, user, fields) in trace {
            let event = occurrence(at, action, kind, user, fields);
            let checked = temporal
                .check(&event)
                .unwrap_or_else(|refused| panic!("@{at} {action}::{kind}: {refused}"));
            match temporal.apply(&history(&checked), &event, &checked) {
                Applied::Observed => assert!(!checked.decides, "@{at} decided nothing"),
                Applied::Decided(verdict) => {
                    assert!(verdict.error.is_none(), "@{at}: {verdict:?}");
                    verdicts.push((at, verdict.permitted));
                }
            }
        }

        assert_eq!(
            verdicts,
            vec![(0, false), (100, true), (4000, false), (4100, false)],
            "upstream records DENY, ALLOW, DENY, DENY for this trace"
        );
    }

    /// The permit cites the Permguard identity of the policy, not an index into a joined string.
    #[test]
    fn a_verdict_cites_the_permguard_policy_that_decided_it() {
        let compiled = example();
        let temporal = compiled.temporal().expect("it remembers");

        for (at, action, kind, fields) in [
            (
                0,
                "Drupe::Action::Login",
                "response",
                json!({"input": {"user": "alice", "server": "s1"}, "output": {}}),
            ),
            (
                100,
                "Drupe::Action::Read",
                "request",
                json!({"input": {"user": "alice", "document": "doc1"}}),
            ),
        ] {
            let event = occurrence(at, action, kind, "alice", fields);
            let checked = temporal.check(&event).expect("well formed");
            if let Applied::Decided(verdict) = temporal.apply(&history(&checked), &event, &checked)
            {
                assert!(verdict.permitted, "the login is inside the window");
                assert_eq!(verdict.determining, ["01a0-read-login-not-logout"]);
            }
        }
    }

    #[test]
    fn the_contract_is_read_from_the_loaded_schemas() {
        let compiled = example();
        let contract = compiled
            .temporal()
            .expect("it remembers")
            .contract()
            .clone();

        assert_eq!(contract.max_window_seconds, DEFAULT_MAX_WINDOW_SECONDS);
        assert_eq!(contract.kinds, ["error", "request", "response"]);
        assert_eq!(contract.decision_kinds, ["request"]);
        // The pinned schema's universal symmetric pin: one history per principal.
        assert_eq!(contract.history_pins, [vec!["callerPrincipal".to_owned()]]);
        assert!(contract.is_partitioned());
        assert!(contract.decides("request"));
        assert!(!contract.decides("response"));

        let read = contract
            .signature("Drupe::Action::Read", "request")
            .expect("the schema derives it");
        assert!(read.decision);
        assert!(
            read.fields
                .iter()
                .any(|field| field.path == ["input", "user"]),
            "the action schema's `ReadInput` is spliced into the event"
        );
        assert_eq!(read.pins.len(), 1);
        assert_eq!(read.pins[0].field, ["callerPrincipal"]);
        assert_eq!(read.pins[0].source, PinSource::Principal);
    }

    /// The pin is derived, and its value is the one a history key is built from.
    #[test]
    fn the_history_key_is_derived_from_the_request_and_not_from_the_caller() {
        let compiled = example();
        let temporal = compiled.temporal().expect("it remembers");
        let event = occurrence(
            100,
            "Drupe::Action::Read",
            "request",
            "alice",
            json!({"input": {"user": "alice", "document": "doc1"}}),
        );
        let checked = temporal.check(&event).expect("well formed");

        assert_eq!(checked.pin_names(), ["callerPrincipal"]);
        assert_eq!(
            checked.pin_values(),
            [value::canonical(&DogwoodValue::Entity {
                ty: "Drupe::OAuthUser".to_owned(),
                id: "alice".to_owned(),
            })]
        );
        // Two principals are two histories, so their keys differ.
        let other = occurrence(
            100,
            "Drupe::Action::Read",
            "request",
            "bob",
            json!({"input": {"user": "bob", "document": "doc1"}}),
        );
        assert_ne!(
            checked.pin_values(),
            temporal.check(&other).expect("well formed").pin_values()
        );
    }

    /// A caller that sends the pinned field with another value is choosing its own history.
    #[test]
    fn a_pin_the_caller_contradicts_is_refused_rather_than_resolved() {
        let compiled = example();
        let temporal = compiled.temporal().expect("it remembers");
        let mut event = occurrence(
            100,
            "Drupe::Action::Read",
            "request",
            "alice",
            json!({"input": {"user": "alice", "document": "doc1"}}),
        );
        event.logged.insert(
            "callerPrincipal".to_owned(),
            DogwoodValue::Entity {
                ty: "Drupe::OAuthUser".to_owned(),
                id: "mallory".to_owned(),
            },
        );

        let refused = temporal
            .check(&event)
            .expect_err("a pin is not the caller's to set");
        assert_eq!(refused.code, "event_pin_contradicted");

        // The same value the schema derives is not a contradiction: a caller may state it.
        event.logged.insert(
            "callerPrincipal".to_owned(),
            DogwoodValue::Entity {
                ty: "Drupe::OAuthUser".to_owned(),
                id: "alice".to_owned(),
            },
        );
        assert!(temporal.check(&event).is_ok());
    }

    #[test]
    fn an_undeclared_logged_field_is_refused_and_named() {
        let compiled = example();
        let temporal = compiled.temporal().expect("it remembers");
        let event = occurrence(
            100,
            "Drupe::Action::Read",
            "request",
            "alice",
            json!({"input": {"user": "alice", "document": "doc1", "smuggled": "x"}}),
        );

        let refused = temporal
            .check(&event)
            .expect_err("the schema declares no such field");
        assert_eq!(refused.code, "event_field_undeclared");
        assert!(
            refused.message.contains("logged.input.smuggled"),
            "{refused}"
        );
    }

    #[test]
    fn a_logged_field_of_the_wrong_type_is_refused() {
        let compiled = example();
        let temporal = compiled.temporal().expect("it remembers");
        let event = occurrence(
            100,
            "Drupe::Action::Read",
            "request",
            "alice",
            json!({"input": {"user": 7, "document": "doc1"}}),
        );

        let refused = temporal
            .check(&event)
            .expect_err("`user` is declared `String`");
        assert_eq!(refused.code, "event_field_mistyped");
        assert!(refused.message.contains("logged.input.user"), "{refused}");
    }

    #[test]
    fn an_action_or_kind_the_schema_does_not_derive_is_refused_by_name() {
        let compiled = example();
        let temporal = compiled.temporal().expect("it remembers");

        let unknown_kind = occurrence(
            100,
            "Drupe::Action::Read",
            "invented",
            "alice",
            json!({"input": {"user": "alice", "document": "doc1"}}),
        );
        assert_eq!(
            temporal
                .check(&unknown_kind)
                .expect_err("no such kind")
                .code,
            "event_kind_undeclared"
        );

        let unknown_action = occurrence(
            100,
            "Drupe::Action::Teleport",
            "request",
            "alice",
            json!({"input": {"user": "alice"}}),
        );
        assert_eq!(
            temporal
                .check(&unknown_action)
                .expect_err("no such action")
                .code,
            "event_action_undeclared"
        );
    }

    /// A principal of a type the action does not admit reaches no policy, so nothing decides it.
    #[test]
    fn a_principal_the_action_does_not_admit_is_refused_rather_than_implicitly_denied() {
        let compiled = example();
        let temporal = compiled.temporal().expect("it remembers");
        let mut event = occurrence(
            100,
            "Drupe::Action::Read",
            "request",
            "alice",
            json!({"input": {"user": "alice", "document": "doc1"}}),
        );
        event.principal.kind = "Drupe::Gateway".to_owned();

        let refused = temporal
            .check(&event)
            .expect_err("`Read` admits no Gateway principal");
        assert_eq!(refused.code, "event_principal_not_admitted");
    }

    /// An attributed entity the action schema does not describe is refused before a decision.
    #[test]
    fn an_entity_store_that_does_not_conform_is_refused_before_authorization() {
        let compiled = example();
        let temporal = compiled.temporal().expect("it remembers");
        let mut event = occurrence(
            100,
            "Drupe::Action::Read",
            "request",
            "alice",
            json!({"input": {"user": "alice", "document": "doc1"}}),
        );
        event
            .entities
            .push(super::super::occurrence::AttributedEntity {
                uid: super::super::occurrence::EntityRef {
                    kind: "Drupe::OAuthUser".to_owned(),
                    id: "alice".to_owned(),
                },
                // `OAuthUser` declares `id: String`, and nothing called `rank`.
                attrs: [("rank".to_owned(), DogwoodValue::Int(1))]
                    .into_iter()
                    .collect(),
                parents: Vec::new(),
            });

        let refused = temporal
            .check(&event)
            .expect_err("Cedar reads an unrecognised store as an empty one");
        assert_eq!(refused.code, "event_entities_rejected");
    }

    /// The stateless PDP has no history to decide a Dogwood policy against, and says so.
    #[test]
    fn the_stateless_interface_refuses_rather_than_deciding_without_the_history() {
        let verdict = example().evaluate(&Query::default());

        assert!(!verdict.permitted);
        let reason = verdict.error.expect("a refusal says why");
        assert!(
            reason.contains("permguard.api.pdp.temporal.v1alpha1"),
            "{reason}"
        );
    }

    #[test]
    fn a_partition_without_an_action_schema_does_not_compile() {
        let refused = compile_with(vec![(registry::EVENT_SCHEMA, EVENT_SCHEMA)])
            .err()
            .expect("there is nothing to lower against");

        assert!(refused.contains("action schema"), "{refused}");
    }

    #[test]
    fn the_max_window_directive_is_read_from_the_event_schema() {
        assert_eq!(
            max_window_seconds("decision event <A>::request { ...inputs(A) }"),
            Ok(DEFAULT_MAX_WINDOW_SECONDS)
        );
        assert_eq!(max_window_seconds("max_window = 30m\n"), Ok(1800));
        assert_eq!(
            max_window_seconds("// a comment\nmax_window = 7d\n"),
            Ok(604_800)
        );
        assert_eq!(max_window_seconds("max_window = 90s\n"), Ok(90));
        assert!(
            max_window_seconds("max_window = 5w\n").is_err(),
            "`w` is not a unit"
        );
        assert!(max_window_seconds("max_window = h\n").is_err(), "no amount");
        assert!(max_window_seconds("max_window 24h\n").is_err(), "no `=`");
    }

    /// The corpus: what upstream's grammar accepts and refuses, checked against this copy of it.
    ///
    /// This parser mirrors a grammar it cannot import — upstream keeps `event_schema` crate-private
    /// — so the only thing standing between the two is a list of cases. Each one below is read off
    /// `event_schema/grammar.pest` and `event_schema/parse.rs` rather than invented, and each is
    /// one that a line-by-line reading got wrong.
    #[test]
    fn the_parser_matches_the_grammar_it_mirrors() {
        // `WHITESPACE` includes newlines, and neither `max_window_decl` nor `interval` is atomic,
        // so upstream accepts the tokens split across lines and spaced apart.
        for accepted in [
            "max_window = 24h",
            "max_window=24h",
            "max_window   =   24h",
            "max_window\n=\n24h",
            "max_window = 24 h",
            "max_window\t=\t24\th",
            "// leading comment\n// another\nmax_window = 24h",
            "max_window = 24h // trailing",
        ] {
            assert_eq!(
                max_window_seconds(accepted),
                Ok(86_400),
                "upstream accepts `{}`",
                accepted.escape_debug()
            );
        }

        // `kw_max_window` ends where an identifier would continue, so these are not the directive
        // at all — and a schema without one takes the default rather than being refused.
        for defaulted in [
            "",
            "   \n\n  ",
            "// only a comment",
            "decision event <A>::request { ...inputs(A) }",
            "max_windows = 24h",
            "max_window_extra = 24h",
        ] {
            assert_eq!(
                max_window_seconds(defaulted),
                Ok(DEFAULT_MAX_WINDOW_SECONDS),
                "no directive in `{}`",
                defaulted.escape_debug()
            );
        }

        // `build_max_window` refuses a zero interval outright. As a retention floor, accepting it
        // would say every event may be deleted the moment it lands.
        for zero in ["max_window = 0s", "max_window = 0h", "max_window = 000d"] {
            let refused = max_window_seconds(zero).expect_err("upstream refuses a zero window");
            assert!(refused.contains("zero"), "{zero}: {refused}");
        }

        // `time_unit` is exactly `s`, `m`, `h`, `d`; `integer` is exactly `ASCII_DIGIT+`.
        for refused in [
            "max_window = 5w",
            "max_window = 5",
            "max_window = -5m",
            "max_window = +5m",
            "max_window = 5.5h",
            "max_window =",
            "max_window = m",
            "max_window 24h",
        ] {
            assert!(
                max_window_seconds(refused).is_err(),
                "upstream refuses `{}`",
                refused.escape_debug()
            );
        }

        // Every unit, at the boundary where the multiplication is what it says.
        assert_eq!(max_window_seconds("max_window = 1s"), Ok(1));
        assert_eq!(max_window_seconds("max_window = 1m"), Ok(60));
        assert_eq!(max_window_seconds("max_window = 1h"), Ok(3_600));
        assert_eq!(max_window_seconds("max_window = 1d"), Ok(86_400));

        // A number no window could mean overflows rather than wrapping into a small one.
        assert!(
            max_window_seconds("max_window = 99999999999999999999d").is_err(),
            "out of range is refused, not wrapped"
        );
    }

    /// Every window this parser reads is one the retention floor can be computed from.
    ///
    /// The property that matters downstream: a schema either yields a positive number of seconds
    /// or refuses. There is no third answer, and in particular never a zero or negative floor —
    /// which would tell the journal every event is immediately deletable.
    #[test]
    fn a_window_is_positive_or_it_is_a_refusal() {
        for amount in [1u64, 2, 7, 59, 60, 61, 3_599, 3_600, 100_000] {
            for unit in ["s", "m", "h", "d"] {
                let source = format!("max_window = {amount}{unit}");
                let held = max_window_seconds(&source).unwrap_or_else(|error| {
                    panic!("`{source}` should read: {error}");
                });
                assert!(held > 0, "`{source}` read as {held}");
            }
        }
    }

    /// A raised `max_window` is read as raised, and it is the number the store keeps history for.
    #[test]
    fn a_raised_max_window_reaches_the_contract() {
        let raised = format!("max_window = 48h\n{EVENT_SCHEMA}");
        let compiled = compile_with(vec![
            (registry::ACTION_SCHEMA, ACTION_SCHEMA),
            (registry::EVENT_SCHEMA, &raised),
        ])
        .expect("it compiles");

        assert_eq!(
            compiled
                .temporal()
                .expect("it remembers")
                .contract()
                .max_window_seconds,
            48 * 3600
        );
    }

    /// Without an event schema the partition gets Dogwood's declared defaults, not no schema.
    #[test]
    fn a_partition_with_no_event_schema_gets_the_runtimes_own_default() {
        let compiled = compile_with(vec![(registry::ACTION_SCHEMA, ACTION_SCHEMA)])
            .expect("the event schema is optional");
        let contract = compiled.temporal().expect("it remembers").contract();

        assert_eq!(contract.decision_kinds, ["request"]);
        assert!(
            contract.is_partitioned(),
            "Dogwood's default pins `callerPrincipal` on every kind"
        );
    }

    /// The limitation upstream's public builder imposes, refused where an operator can see it.
    #[test]
    fn a_pin_this_build_cannot_write_refuses_the_load() {
        // A schema of its own, because upstream's example declares no `context.sessionId` and
        // Dogwood would refuse the pin's *source* before Permguard reached the pin's *target*.
        const WITH_SESSION: &str = r#"namespace Drupe {
  type ReadInput = { document: String, user: String };
  entity Gateway;
  entity OAuthUser = { id: String };
  action "Read" appliesTo {
    principal: [OAuthUser],
    resource: [Gateway],
    context: { input: ReadInput, sessionId: String }
  };
}
"#;
        const PERMIT: &str = "permit (principal, action == Drupe::Action::\"Read\", resource);\n";
        let refused = compile_policy_with(
            PERMIT,
            vec![
                (registry::ACTION_SCHEMA, WITH_SESSION),
                (registry::EVENT_SCHEMA, SESSION_PINNED),
            ],
        )
        .err()
        .expect("a pin nobody can write would put every session in one history");

        assert!(refused.contains("sessionId"), "{refused}");
        assert!(refused.contains("callerPrincipal"), "{refused}");
    }

    /// A field that would be dropped is refused rather than accepted and dropped.
    #[test]
    fn a_top_level_logged_field_is_refused_rather_than_silently_dropped() {
        let compiled = example();
        let temporal = compiled.temporal().expect("it remembers");
        let mut event = occurrence(
            100,
            "Drupe::Action::Read",
            "request",
            "alice",
            json!({"input": {"user": "alice", "document": "doc1"}}),
        );
        // Declared by the pinned schema, and with nowhere to go through the public builder.
        event.logged.insert(
            "requestId".to_owned(),
            DogwoodValue::String("u2".to_owned()),
        );

        let refused = temporal.check(&event).expect_err("it would be dropped");
        assert_eq!(refused.code, "event_field_not_carriable");
        assert!(refused.message.contains("logged.requestId"), "{refused}");
    }

    const PROVIDERS: &str = r#"{
  "availableProviders": {
    "Strings::Matches": {
      "argumentTypes": [{"paramType": "string"}, {"paramType": "string"}],
      "outputType": {
        "paramType": "record",
        "fields": {"matched": {"paramType": "bool"}},
        "required": ["matched"]
      },
      "implementation": {"kind": "rhai", "scriptFile": "matches.rhai"}
    }
  }
}"#;
    const PROGRAM: &str =
        "fn evaluate(pattern, text) { #{ matched: regex_is_match(pattern, text) } }\n";

    #[test]
    fn a_provider_script_is_resolved_from_the_ledger_and_not_from_the_host() {
        let mut artifacts = bundle(vec![
            (registry::ACTION_SCHEMA, ACTION_SCHEMA),
            (registry::PROVIDERS, PROVIDERS),
        ]);
        let (held, mut blob) = artifact(registry::RHAI_PROVIDER, PROGRAM);
        blob.name = "matches.rhai".to_owned();
        artifacts.insert(held, blob);

        let declarations = provider_declarations(PROVIDERS.as_bytes(), &artifacts)
            .expect("the script is carried by the partition");
        let declaration = declarations
            .get("Strings::Matches")
            .expect("it is declared");
        assert!(
            matches!(
                declaration.implementation.as_ref(),
                Some(dogwood_language::Implementation::Rhai { script: Some(held), script_file: None })
                    if held == PROGRAM
            ),
            "the reference is folded into the inline script"
        );
    }

    #[test]
    fn a_provider_script_the_partition_does_not_carry_refuses_the_load() {
        let artifacts = bundle(vec![
            (registry::ACTION_SCHEMA, ACTION_SCHEMA),
            (registry::PROVIDERS, PROVIDERS),
        ]);

        let refused = provider_declarations(PROVIDERS.as_bytes(), &artifacts)
            .expect_err("there is no filesystem to fall back to");
        assert!(refused.contains("matches.rhai"), "{refused}");
        assert!(refused.contains("carries none"), "{refused}");
    }

    #[test]
    fn a_provider_script_no_declaration_references_refuses_the_load() {
        let mut artifacts = bundle(vec![
            (registry::ACTION_SCHEMA, ACTION_SCHEMA),
            (registry::PROVIDERS, PROVIDERS),
        ]);
        for name in ["matches.rhai", "orphan.rhai"] {
            let (held, mut blob) = artifact(registry::RHAI_PROVIDER, PROGRAM);
            blob.name = name.to_owned();
            artifacts.insert(held, blob);
        }

        let refused = provider_declarations(PROVIDERS.as_bytes(), &artifacts)
            .expect_err("a program nothing names is unaccounted for");
        assert!(refused.contains("orphan.rhai"), "{refused}");
    }

    #[test]
    fn a_provider_stating_both_a_script_and_a_file_refuses_the_load() {
        let both = PROVIDERS.replace(
            r#""implementation": {"kind": "rhai", "scriptFile": "matches.rhai"}"#,
            r#""implementation": {"kind": "rhai", "script": "fn evaluate(a, b) { #{ matched: true } }", "scriptFile": "matches.rhai"}"#,
        );
        let artifacts = bundle(vec![(registry::ACTION_SCHEMA, ACTION_SCHEMA)]);

        let refused = provider_declarations(both.as_bytes(), &artifacts)
            .expect_err("which of the two runs is not something to guess");
        assert!(refused.contains("scriptFile"), "{refused}");
    }

    /// A late arrival is answered by rebuilding, and the rebuilt history is the whole run.
    #[test]
    fn a_rebuild_replays_the_ordered_history_and_replaces_what_was_there() {
        let compiled = example();
        let temporal = compiled.temporal().expect("it remembers");

        // A read with no login before it is denied.
        let read = occurrence(
            100,
            "Drupe::Action::Read",
            "request",
            "alice",
            json!({"input": {"user": "alice", "document": "doc1"}}),
        );
        let checked = temporal.check(&read).expect("well formed");
        assert_eq!(
            temporal.apply(&history(&checked), &read, &checked),
            Applied::Decided(Verdict::deny(Vec::new())),
            "nothing has happened yet"
        );

        // The login arrives late — it happened *before* the read this engine has already seen.
        // Inserting it would either corrupt the window or be silently ignored; rebuilding replays
        // the whole ordered run, and the answer changes because the history did.
        let login = occurrence(
            5,
            "Drupe::Action::Login",
            "response",
            "alice",
            json!({"input": {"user": "alice", "server": "s1"}, "output": {}}),
        );
        temporal
            .rebuild(&history(&checked), &[login, read.clone()])
            .expect("the partition rebuilds");

        let checked = temporal.check(&read).expect("well formed");
        match temporal.apply(&history(&checked), &read, &checked) {
            Applied::Decided(verdict) => assert!(
                verdict.permitted,
                "the rebuilt history contains the login: {verdict:?}"
            ),
            other => panic!("a decision kind decided nothing: {other:?}"),
        }
    }

    /// Two principals are two histories, and one cannot see the other's events.
    ///
    /// # What this is actually about
    ///
    /// The example's schema pins `callerPrincipal`, and the policy never mentions the principal at
    /// all — the separation is not a condition somebody wrote and could have forgotten, it is a
    /// property of which history the question is asked in. So the test is the negative: alice's
    /// login must not permit bob's read, and the only reason it does not is that they are not in
    /// the same history.
    #[test]
    fn one_principals_login_does_not_permit_anothers_read() {
        let compiled = example();
        let temporal = compiled.temporal().expect("it remembers");

        let login = occurrence(
            5,
            "Drupe::Action::Login",
            "response",
            "alice",
            json!({"input": {"user": "alice", "server": "s1"}, "output": {}}),
        );
        let checked = temporal.check(&login).expect("well formed");
        let alice = history(&checked);
        assert_eq!(
            temporal.apply(&alice, &login, &checked),
            Applied::Observed,
            "a history-only kind"
        );

        // Alice reads: permitted, because her login is in her history.
        let read = occurrence(
            100,
            "Drupe::Action::Read",
            "request",
            "alice",
            json!({"input": {"user": "alice", "document": "doc1"}}),
        );
        let checked = temporal.check(&read).expect("well formed");
        assert_eq!(
            history(&checked),
            alice,
            "the same caller, the same history"
        );
        match temporal.apply(&alice, &read, &checked) {
            Applied::Decided(verdict) => assert!(verdict.permitted, "{verdict:?}"),
            other => panic!("{other:?}"),
        }

        // Bob reads: denied, and his engine has never been told anything.
        let read = occurrence(
            101,
            "Drupe::Action::Read",
            "request",
            "bob",
            json!({"input": {"user": "bob", "document": "doc1"}}),
        );
        let checked = temporal.check(&read).expect("well formed");
        let bob = history(&checked);
        assert_ne!(bob, alice, "a different caller is a different history");
        assert_eq!(
            temporal.observed(&bob),
            0,
            "and it starts cold, which is what tells a plane to replay before deciding"
        );
        match temporal.apply(&bob, &read, &checked) {
            Applied::Decided(verdict) => assert!(
                !verdict.permitted,
                "alice's login is not in bob's history: {verdict:?}"
            ),
            other => panic!("{other:?}"),
        }
    }

    /// Holding a bounded number of histories evicts the coldest, and eviction changes no verdict.
    ///
    /// # What this is actually about
    ///
    /// A schema that pins the caller has one history per caller, and a tenant has as many callers
    /// as it has. Keeping an engine for each would make this plane's memory a function of somebody
    /// else's user base — a caller-controlled allocation, which is the thing a multi-tenant plane
    /// must never have.
    ///
    /// So there is a bound, and the safety of the bound is the whole assertion: an evicted history
    /// reads as *cold* rather than as empty-and-answered, which is what makes the plane replay it
    /// from the durable journal before it decides again. The answer after eviction is the answer
    /// before it; only the cost differs.
    #[test]
    fn evicting_a_cold_history_costs_a_replay_and_never_an_answer() {
        let compiled = example();
        let temporal = compiled.temporal().expect("it remembers");

        let login_of = |user: &str| {
            occurrence(
                5,
                "Drupe::Action::Login",
                "response",
                user,
                json!({"input": {"user": user, "server": "s1"}, "output": {}}),
            )
        };
        let read_of = |user: &str| {
            occurrence(
                100,
                "Drupe::Action::Read",
                "request",
                user,
                json!({"input": {"user": user, "document": "doc1"}}),
            )
        };

        // The first caller logs in and reads: permitted, from a warm history.
        let login = login_of("first");
        let checked = temporal.check(&login).expect("well formed");
        let first = history(&checked);
        temporal.apply(&first, &login, &checked);
        assert!(temporal.observed(&first) > 0, "warm");

        // Then more callers than the bound holds, each touching its own history.
        for at in 0..=super::HOT_HISTORIES {
            let user = format!("crowd-{at}");
            let held = login_of(&user);
            let checked = temporal.check(&held).expect("well formed");
            temporal.apply(&history(&checked), &held, &checked);
        }

        assert_eq!(
            temporal.observed(&first),
            0,
            "the coldest history was evicted, and reads as cold rather than as empty"
        );

        // Replayed from what the journal holds — which is what the plane does on seeing `0` — the
        // verdict is the one it was before the eviction.
        temporal
            .rebuild(&first, &[login_of("first")])
            .expect("an evicted history is rebuilt from the durable record");
        let read = read_of("first");
        let checked = temporal.check(&read).expect("well formed");
        match temporal.apply(&first, &read, &checked) {
            Applied::Decided(verdict) => assert!(
                verdict.permitted,
                "eviction changed a verdict, which is the one thing it may not do: {verdict:?}"
            ),
            other => panic!("{other:?}"),
        }
    }

    /// A rebuild that cannot be built leaves the partition deciding against what it had.
    #[test]
    fn a_rebuild_that_fails_does_not_empty_the_history() {
        let compiled = example();
        let temporal = compiled.temporal().expect("it remembers");

        let login = occurrence(
            5,
            "Drupe::Action::Login",
            "response",
            "alice",
            json!({"input": {"user": "alice", "server": "s1"}, "output": {}}),
        );
        let checked = temporal.check(&login).expect("well formed");
        assert_eq!(
            temporal.apply(&history(&checked), &login, &checked),
            Applied::Observed
        );

        // A logged bag whose group is a bare value rather than a record of fields cannot become an
        // event, so the replay fails where it is attempted.
        let mut broken = login.clone();
        broken
            .logged
            .insert("input".to_owned(), DogwoodValue::Int(7));
        let refused = temporal
            .rebuild(&history(&checked), &[broken])
            .expect_err("an unreplayable history is not a history");
        assert_eq!(refused.code, "history_not_replayable");

        // And the login is still there: the read that depends on it is still permitted.
        let read = occurrence(
            100,
            "Drupe::Action::Read",
            "request",
            "alice",
            json!({"input": {"user": "alice", "document": "doc1"}}),
        );
        let checked = temporal.check(&read).expect("well formed");
        match temporal.apply(&history(&checked), &read, &checked) {
            Applied::Decided(verdict) => assert!(verdict.permitted, "{verdict:?}"),
            other => panic!("{other:?}"),
        }
    }
}
