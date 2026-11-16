// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What a Dogwood partition is, read from its sources: parsed, lowered as one set, validated,
//! and described by the contract its schemas derive. The validating half, with no decision point
//! in it: `validate_bundle` checks a pushed partition with exactly this, and the evaluating half
//! (`compiled`, with the `evaluate` feature) builds its runtime over the same result, so a set
//! that validates here is a set that loads there.

use std::collections::BTreeMap;

use cedar_policy::Schema;
use dogwood_language::{
    Authorizer, EventFieldType, EventPinRoot, LoweredPolicySet, ParsedPolicySet, PolicySchema,
    ProviderDeclarations, ServiceSchema, Validator,
};
use permguard_language_core::artifact::Artifacts;
use permguard_language_core::evaluate::StoredPolicy;
use permguard_language_core::temporal::{Contract, Field, Pin, PinSource, Signature};

use super::artifacts as registry;

/// The default furthest-back window, when the event schema declares none.
///
/// Upstream's `DEFAULT_MAX_WINDOW`, kept crate-private there, so it is stated here and held to
/// upstream by a test that lowers a schema with a longer `within` and expects the refusal.
pub const DEFAULT_MAX_WINDOW_SECONDS: i64 = 24 * 3600;

/// A partition that parses, lowers and validates, with everything its runtime is built from.
///
/// A build that only validates reads the contract and the projections and builds no runtime, so
/// the rest is held for the evaluating half alone.
#[cfg_attr(not(feature = "evaluate"), allow(dead_code))]
pub(crate) struct Analyzed {
    /// What a fresh authorizer is built from, for a cold history or a rebuild.
    pub(crate) inputs: Inputs,
    /// The lowered Cedar schema, for the checks that happen before a decision.
    pub(crate) cedar_schema: Schema,
    /// What the schemas say of the partition: its kinds, its pins, its window.
    pub(crate) contract: Contract,
    /// The Permguard policy identity owning each rule of the joined set, by rule index.
    pub(crate) owners: Vec<String>,
    pub(crate) identities: Vec<String>,
    pub(crate) footprint: usize,
    /// The leaves of each action's context, by qualified action: one side of a version 2
    /// occurrence's projection.
    pub(crate) context: BTreeMap<String, super::projection::Side>,
    /// The one-sided fields `projections.json` declares, when the partition carries it.
    pub(crate) projections: Option<super::projection::Projections>,
}

/// Parses, lowers and validates a partition's policies against the artifacts it carries.
pub(crate) fn analyze(
    policies: &[StoredPolicy],
    artifacts: &Artifacts,
) -> Result<Analyzed, String> {
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
        let parsed = ParsedPolicySet::parse(text, &service)
            .map_err(|error| format!("dogwood: policy {} does not parse: {error}", stored.id))?;
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

    // DOGWOOD-07: the annotations this build reads are the ones upstream parsed, policy by
    // policy — an alias is identity, and two readings of one source must not differ. The file's
    // own rule (one `@id` at most) is held at load too, for a ledger pushed before it.
    let mut read_ids: Vec<Option<String>> = Vec::new();
    for stored in policies {
        let text = super::source_of(&stored.source, "a Dogwood policy")?;
        let read = super::annotations::read(text)?;
        super::annotations::alias_of(&read)
            .map_err(|error| format!("policy {}: {error}", stored.id))?;
        for annotations in read {
            read_ids.push(
                annotations
                    .into_iter()
                    .find(|annotation| annotation.key == super::annotations::ID)
                    .and_then(|annotation| annotation.raw),
            );
        }
    }
    let lowered_ids: Vec<Option<String>> = lowered
        .rules()
        .map(|rule| {
            lowered
                .as_cedar()
                .policy(&cedar_policy::PolicyId::new(&rule.cedar_policy_id))
                .map(|policy| policy.annotation(super::annotations::ID).map(str::to_owned))
                .ok_or_else(|| {
                    format!(
                        "dogwood: the lowered set names rule `{}` and holds no such policy",
                        rule.cedar_policy_id
                    )
                })
        })
        .collect::<Result<_, _>>()?;
    super::annotations::agrees_with(&read_ids, &lowered_ids)?;

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
    // What a version 2 occurrence projects into: the action's context, and the one-sided
    // fields the author declared (TL-5c). Read for every partition; checked against the
    // manifest's input at load (`check_input`).
    let context = super::projection::context_leaves(action_source)?;
    let projections = artifacts
        .bytes(registry::PROJECTIONS)
        .map(super::projection::Projections::parse)
        .transpose()?;
    // The *augmented* schema: the action schema plus what lowering added to it (the hoisted
    // `context.providers.<id>` fields). Kept beside the authorizer because an attributed
    // entity store has to be checked against it before a decision, and afterwards is too
    // late — Cedar reads an entity it does not recognise as having no attributes, so a
    // mistyped store weakens a policy rather than failing it.
    let cedar_schema = lowered.cedar_schema().clone();
    // What the compiled set keeps, conservatively (LANG-07, DOGWOOD-08 for the set): measured,
    // the lowered policy set, schemas and contract weigh a fixed ~70 KiB plus under 3 bytes per
    // authored byte; the estimate is 128 KiB plus 8 times, which `tests/footprint.rs` proves is
    // never below what the engine retains. Each history's warm authorizer is DOGWOOD-02, not this.
    let footprint =
        (128 * 1024_usize).saturating_add((source.len() + artifacts.footprint()).saturating_mul(8));
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

    Ok(Analyzed {
        inputs,
        cedar_schema,
        contract,
        owners,
        identities,
        footprint,
        context,
        projections,
    })
}

/// Whether the partition's contents fit the input its manifest declares: a version 2 partition
/// declares its one-sided fields (TL-5c), and no other carries declarations nothing reads.
pub(crate) fn check_input(
    contract: &Contract,
    context: &BTreeMap<String, super::projection::Side>,
    projections: Option<&super::projection::Projections>,
    input: Option<&str>,
) -> Result<(), String> {
    if input == Some(super::occurrence::EVENT_TYPE_V2) {
        return super::projection::check_complete(
            &contract.signatures,
            context,
            &projections.cloned().unwrap_or_default(),
        );
    }
    if projections.is_some() {
        return Err(format!(
            "dogwood: the partition carries `{}`, which only a partition whose input is `{}` \
             reads; declarations nothing reads are not kept",
            registry::PROJECTIONS_FILENAME,
            super::occurrence::EVENT_TYPE_V2
        ));
    }

    Ok(())
}

/// The service schema: the event schema, macros and providers this partition carries.
///
/// Absence is a choice made explicitly. A partition with no event schema gets Dogwood's declared
/// defaults, which pin `callerPrincipal` on every kind — not "no schema", which would be a
/// partition whose history is scoped by nothing.
pub(crate) fn service_schema(artifacts: &Artifacts) -> Result<ServiceSchema, String> {
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
pub(crate) fn provider_declarations(
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
pub(crate) fn contract_of(
    lowered: &LoweredPolicySet,
    artifacts: &Artifacts,
) -> Result<Contract, String> {
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
pub(crate) fn check_pins_are_injectable(contract: &Contract) -> Result<(), String> {
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
pub(crate) fn injectable(path: &[String]) -> bool {
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
pub(crate) fn max_window_seconds(source: &str) -> Result<i64, String> {
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
pub(crate) fn skip_trivia(source: &str) -> &str {
    let mut rest = source.trim_start();
    while let Some(after) = rest.strip_prefix("//") {
        let line_end = after.find(['\n', '\r']).unwrap_or(after.len());
        rest = after[line_end..].trim_start();
    }

    rest
}

/// As much of `rest` as is worth quoting back in a refusal.
pub(crate) fn first_word(rest: &str) -> &str {
    let end = rest
        .find(|character: char| character.is_whitespace())
        .unwrap_or(rest.len());

    &rest[..end.min(24)]
}

/// One of Dogwood's pins, in Permguard's own terms.
pub(crate) fn read_pin(pin: &dogwood_language::EventPin) -> Pin {
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
pub(crate) fn declared_type(field_type: &EventFieldType) -> String {
    match field_type {
        EventFieldType::Cedar(rendered) => rendered.clone(),
        // An injected `principalType(A)` field: its full declared set, not one collapsed name.
        EventFieldType::EntityTypes(types) => types.join(" | "),
    }
}

/// A namespace path and a bare action id, rejoined as a policy names them.
pub(crate) fn qualified(namespace: &[String], action: &str) -> String {
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
#[cfg_attr(not(feature = "evaluate"), allow(dead_code))]
pub(crate) struct Inputs {
    /// Every policy of the partition, joined as they were lowered.
    pub(crate) source: String,
    /// The action schema, verbatim.
    pub(crate) action_schema: String,
    /// The rest of the partition's artifacts.
    pub(crate) artifacts: Artifacts,
    /// Whether the schema declares a universal symmetric pin.
    pub(crate) partitioned: bool,
}

impl Inputs {
    /// A fresh authorizer over an already-lowered set.
    pub(crate) fn authorizer(&self, lowered: LoweredPolicySet) -> Result<Authorizer, String> {
        let mut builder = Authorizer::builder(lowered);
        if self.partitioned {
            builder = builder.partition_temporal();
        }

        builder
            .build()
            .map_err(|error| format!("dogwood: the authorizer does not build: {error}"))
    }

    /// A fresh authorizer, lowered again from these inputs.
    #[cfg_attr(not(feature = "evaluate"), allow(dead_code))]
    pub(crate) fn rebuild(&self) -> Result<Authorizer, String> {
        let schema = PolicySchema::from_cedarschema_str(&self.action_schema)
            .map_err(|error| format!("dogwood: the action schema is not usable: {error}"))?;
        let service = service_schema(&self.artifacts)?;
        let lowered = LoweredPolicySet::from_str(&self.source, &service, &schema)
            .map_err(|error| format!("dogwood: the partition does not lower: {error}"))?;

        self.authorizer(lowered)
    }
}
