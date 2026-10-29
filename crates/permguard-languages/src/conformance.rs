// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The conformance gate of each runtime (TL-6): the eight items the languages model requires before
//! a language may be called production-ready, as code the binary carries.
//!
//! | Item               | What passing it means                                                      |
//! | ------------------ | -------------------------------------------------------------------------- |
//! | `golden_vectors`   | descriptor, manifest, request, verdict and error vectors                   |
//! | `upstream_corpus`  | the engine's own corpus reproduced, pinned to the locked revision          |
//! | `adversarial`      | parser, schema, alias, input-depth and resource-exhaustion tests           |
//! | `replay`           | the same answers on two platforms                                          |
//! | `differential`     | an engine upgrade cannot land without re-recording and reviewing vectors   |
//! | `fault_injection`  | panic, timeout, memory pressure and a corrupted cache, each failing closed |
//! | `stored_objects`   | what older versions stored is read, or refused by an explicit migration    |
//!
//! The fault injection evidence names its fault: `panic=`, `timeout=`, `memory=` and `cache=`, and
//! the item passes only with all four. The stored objects a runtime's ledgers hold are the shared
//! mirror layout and manifests, which every runtime cites, and the runtime's own artifact and event
//! versions where it has more than one.
//! | `supply_chain`     | SBOM, licence, vulnerability and dependency-feature review                 |
//!
//! An item is `Passing` with its evidence — tests as `<crate>/<path>::<function>`, CI jobs as
//! `ci:<job>`, release configuration as `file:<path>#<text>` — or `Open` with the reason. The
//! conformance test `permguard-languages/tests/gate_evidence.rs` fails when an evidence does not
//! exist, so the record claims no more than the repository proves; CI passing is the evidence
//! passing. A runtime whose gate has an open item is not production-ready: a `production` or
//! `regulated` Host refuses to load it, and discovery says which items are open.

use serde::Serialize;

/// The gate's identifier, as discovery publishes it.
pub const GATE: &str = permguard_core::domains::interface::LANGUAGE_CONFORMANCE_V1;

/// One item of the languages model's conformance gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Item {
    GoldenVectors,
    UpstreamCorpus,
    Adversarial,
    Replay,
    Differential,
    FaultInjection,
    StoredObjects,
    SupplyChain,
}

/// Every item, in the languages model's order.
pub const ITEMS: [Item; 8] = [
    Item::GoldenVectors,
    Item::UpstreamCorpus,
    Item::Adversarial,
    Item::Replay,
    Item::Differential,
    Item::FaultInjection,
    Item::StoredObjects,
    Item::SupplyChain,
];

impl Item {
    /// The item's name, as discovery and refusals write it.
    pub fn name(self) -> &'static str {
        match self {
            Self::GoldenVectors => "golden_vectors",
            Self::UpstreamCorpus => "upstream_corpus",
            Self::Adversarial => "adversarial",
            Self::Replay => "replay",
            Self::Differential => "differential",
            Self::FaultInjection => "fault_injection",
            Self::StoredObjects => "stored_objects",
            Self::SupplyChain => "supply_chain",
        }
    }
}

/// Where an item stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Proven by these tests, CI jobs and release files.
    Passing(&'static [&'static str]),
    /// Not proven, and why.
    Open(&'static str),
}

/// One item of one runtime's gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Record {
    pub item: Item,
    pub state: State,
}

const fn passing(item: Item, evidence: &'static [&'static str]) -> Record {
    Record {
        item,
        state: State::Passing(evidence),
    }
}

const fn open(item: Item, reason: &'static str) -> Record {
    Record {
        item,
        state: State::Open(reason),
    }
}

/// The fault labels the `fault_injection` item requires, each at least once.
pub const FAULTS: [&str; 4] = ["panic", "timeout", "memory", "cache"];

/// The shared stored objects every runtime's ledgers are made of: the mirror layout, its
/// manifests' former interface names, the catalog.
const SHARED_STORED: [&str; 3] = [
    "permguard-data-plane/tests/legacy_fixtures.rs::test_the_v1_mirror_fixture_is_read_by_the_current_code",
    "permguard-languages/src/registry.rs::the_interfaces_former_name_still_loads_and_means_the_same_thing",
    "permguard-std/tests/legacy_fixtures.rs::test_the_v1_catalog_fixture_is_read_by_the_current_code",
];

const CEDAR: &[Record] = &[
    passing(
        Item::GoldenVectors,
        &[
            "permguard-languages/tests/descriptor_vectors.rs::test_every_descriptor_equals_its_golden_vector",
            "permguard-languages/tests/algebra_vectors.rs::test_every_row_of_the_algebra_resolves_as_the_vectors_state",
            "permguard-languages/tests/language_vectors.rs::test_cedar_answers_its_golden_vectors",
            "permguard-languages/tests/language_vectors.rs::test_every_runtimes_vectors_cover_the_whole_algebra",
        ],
    ),
    passing(
        Item::UpstreamCorpus,
        &[
            "permguard-languages/tests/cedar_corpus.rs::test_cedar_reproduces_the_upstream_integration_corpus",
            "permguard-languages/tests/cedar_corpus.rs::test_the_vendored_corpus_is_the_one_its_source_names",
        ],
    ),
    passing(
        Item::Adversarial,
        &[
            "permguard-languages/src/cedar/mod.rs::the_alias_is_the_parsed_annotation_and_nothing_that_looks_like_one",
            "permguard-languages/src/cedar/mod.rs::broken_cedar_is_refused",
            "permguard-languages/src/cedar/mod.rs::semicolons_inside_strings_do_not_split",
            "permguard-languages/src/cedar/mod.rs::schema_validation",
            "permguard-languages/src/cedar/evaluate.rs::deep_expressions_large_sets_and_large_graphs_stay_inside_limits",
            "permguard-languages/src/cedar/evaluate.rs::one_value_has_one_authority_between_the_store_and_the_properties",
            "permguard-languages/src/cedar/evaluate.rs::a_policy_that_does_not_satisfy_the_schema_refuses_the_load",
            "permguard-languages/src/cedar/evaluate.rs::a_request_missing_its_parts_is_an_input_the_engine_rejects",
        ],
    ),
    passing(
        Item::Replay,
        &[
            "ci:check",
            "ci:languages-macos",
            "permguard-languages/src/cedar/evaluate.rs::golden_results_hold_across_a_recompile",
        ],
    ),
    passing(
        Item::Differential,
        &[
            "permguard-languages/tests/language_vectors.rs::test_cedar_answers_its_golden_vectors",
            "permguard-languages/tests/cedar_corpus.rs::test_the_vendored_corpus_is_the_one_its_source_names",
            "permguard-languages/tests/descriptor_vectors.rs::test_every_engine_is_the_one_cargo_lock_pins",
        ],
    ),
    passing(
        Item::FaultInjection,
        &[
            // The evaluation path every runtime's partition runs on, Cedar's included.
            "panic=permguard-languages/src/evaluate.rs::a_partition_that_panics_makes_the_whole_request_indeterminate",
            "panic=permguard-languages/src/evaluate.rs::a_panic_in_the_one_partition_the_caller_runs_is_an_evaluation_failure",
            "panic=permguard-languages/src/guard.rs::every_guarded_entry_refuses_instead_of_panicking",
            "timeout=permguard-languages/src/cedar/evaluate.rs::a_partition_reached_past_its_deadline_fails_closed",
            // Cedar runs in-process and terminates by construction: its memory is bounded by the
            // input's depth, width and the graph's hierarchy, refused before evaluation, and by the
            // cache's byte bound, which charges at least what the engine retains.
            "memory=permguard-languages/src/cedar/evaluate.rs::deep_expressions_large_sets_and_large_graphs_stay_inside_limits",
            "memory=permguard-languages/tests/footprint.rs::test_every_runtimes_footprint_is_at_least_what_its_engine_retains",
            "memory=permguard-data-plane/src/authz/cache.rs::the_byte_bound_evicts_too",
            "cache=permguard-data-plane/tests/examples.rs::a_corrupted_mirror_fails_a_cold_load_and_never_changes_a_warm_answer",
        ],
    ),
    passing(Item::StoredObjects, &SHARED_STORED),
    passing(Item::SupplyChain, SUPPLY_CHAIN),
];

const REGO: &[Record] = &[
    passing(
        Item::GoldenVectors,
        &[
            "permguard-languages/tests/descriptor_vectors.rs::test_every_descriptor_equals_its_golden_vector",
            "permguard-languages/tests/algebra_vectors.rs::test_every_row_of_the_algebra_resolves_as_the_vectors_state",
            "permguard-languages/tests/language_vectors.rs::test_rego_answers_its_golden_vectors",
            "permguard-languages/tests/language_vectors.rs::test_every_runtimes_vectors_cover_the_whole_algebra",
        ],
    ),
    passing(
        Item::UpstreamCorpus,
        &[
            "permguard-languages/tests/opa_corpus.rs::test_rego_reproduces_the_upstream_opa_conformance_cases",
            "permguard-languages/tests/opa_corpus.rs::test_the_vendored_opa_cases_are_the_ones_their_source_names",
        ],
    ),
    passing(
        Item::Adversarial,
        &[
            "permguard-languages/src/rego/parsed.rs::brackets_nest_at_most_the_bound_and_deeper_is_refused_before_the_parser",
            "permguard-languages/src/rego/parsed.rs::many_moderately_nested_literals_exhaust_the_parse_work_budget",
            "permguard-languages/src/rego/parsed.rs::brackets_in_strings_raw_strings_and_comments_are_not_syntax",
            "permguard-languages/src/rego/parsed.rs::a_built_in_outside_the_allow_list_is_refused",
            "permguard-languages/src/rego/parsed.rs::a_refused_built_in_named_by_index_or_substituted_is_refused",
            "permguard-languages/src/rego/parsed.rs::only_the_metadata_heading_the_package_carries_its_alias",
            "permguard-languages/src/rego/mod.rs::a_schema_that_reaches_for_the_network_does_not_compile",
            "permguard-languages/src/rego/evaluate.rs::a_hostile_rule_is_stopped_by_the_execution_budget_and_is_an_evaluation_failure",
            "permguard-languages/src/rego/evaluate.rs::a_document_the_schema_refuses_never_reaches_a_rule",
        ],
    ),
    passing(Item::Replay, &["ci:check", "ci:languages-macos"]),
    passing(
        Item::Differential,
        &[
            "permguard-languages/tests/language_vectors.rs::test_rego_answers_its_golden_vectors",
            "permguard-languages/tests/opa_corpus.rs::test_the_vendored_opa_cases_are_the_ones_their_source_names",
            "permguard-languages/tests/descriptor_vectors.rs::test_every_engine_is_the_one_cargo_lock_pins",
        ],
    ),
    passing(
        Item::FaultInjection,
        &[
            "panic=permguard-languages/src/evaluate.rs::a_partition_that_panics_makes_the_whole_request_indeterminate",
            "panic=permguard-languages/tests/worker.rs::a_worker_that_panics_is_replaced",
            "timeout=permguard-languages/src/rego/evaluate.rs::a_hostile_rule_is_stopped_by_the_decisions_deadline_long_before_the_rule_budget",
            "timeout=permguard-languages/src/rego/evaluate.rs::many_expensive_rules_share_one_decreasing_budget",
            "timeout=permguard-languages/tests/worker.rs::a_worker_past_its_deadline_is_killed_and_replaced",
            // From `production` Rego runs in its supervised worker, under `RLIMIT_AS`.
            "memory=permguard-languages/tests/rego_supervised.rs::a_rego_partition_that_exhausts_its_address_space_fails_closed",
            "memory=permguard-languages/tests/rego_supervised.rs::rego_requires_isolation_from_production",
            "cache=permguard-data-plane/tests/examples.rs::a_corrupted_mirror_fails_a_cold_load_and_never_changes_a_warm_answer",
        ],
    ),
    passing(
        Item::StoredObjects,
        &[
            SHARED_STORED[0],
            SHARED_STORED[1],
            SHARED_STORED[2],
            // A partition whose schema is the older `permguard.rego.schema.v1` still loads, typing
            // what it typed.
            "permguard-languages/src/rego/evaluate.rs::the_whole_input_schema_types_every_member_and_excludes_v1",
        ],
    ),
    passing(Item::SupplyChain, SUPPLY_CHAIN),
];

const DOGWOOD: &[Record] = &[
    open(
        Item::GoldenVectors,
        "Dogwood's verdicts are proven by unit tests and the example's cases, with no recorded \
         manifest, request and verdict vector file of its own",
    ),
    passing(
        Item::UpstreamCorpus,
        &[
            "permguard-languages/src/dogwood/compiled.rs::the_upstream_example_reproduces_the_verdicts_upstream_records",
            "permguard-languages/tests/dogwood_parity.rs::test_the_max_window_this_build_reads_is_the_one_upstream_enforces",
            "permguard-languages/tests/dogwood_parity.rs::test_the_id_this_build_reads_is_the_one_upstream_parses",
        ],
    ),
    passing(
        Item::Adversarial,
        &[
            "permguard-languages/src/dogwood/occurrence.rs::an_unknown_field_is_refused_rather_than_ignored",
            "permguard-languages/src/dogwood/occurrence.rs::a_value_that_cannot_be_represented_exactly_is_refused_by_position",
            "permguard-languages/src/dogwood/annotations.rs::an_unclosed_source_is_refused_rather_than_read_short",
            "permguard-languages/src/dogwood/compiled.rs::a_pin_the_caller_contradicts_is_refused_rather_than_resolved",
            "permguard-languages/src/dogwood/compiled.rs::an_entity_store_that_does_not_conform_is_refused_before_authorization",
            "permguard-languages/src/dogwood/compiled.rs::one_principals_login_does_not_permit_anothers_read",
        ],
    ),
    passing(Item::Replay, &["ci:check", "ci:languages-macos"]),
    passing(
        Item::Differential,
        &[
            "permguard-languages/tests/dogwood_parity.rs::test_the_vectors_name_the_locked_upstream_version",
            "permguard-languages/tests/descriptor_vectors.rs::test_every_engine_is_the_one_cargo_lock_pins",
        ],
    ),
    open(
        Item::FaultInjection,
        "panic, timeout and memory are proven (a runaway provider, a replay past its deadline, the \
         warm history's byte budget), and no corrupted-store test runs a Dogwood ledger",
    ),
    passing(
        Item::StoredObjects,
        &[
            SHARED_STORED[0],
            SHARED_STORED[1],
            SHARED_STORED[2],
            "permguard-languages/src/dogwood/compiled.rs::a_version_1_history_replays_into_a_version_2_partition",
            "permguard-languages/src/dogwood/occurrence.rs::each_event_version_is_read_by_its_own_contract",
        ],
    ),
    passing(Item::SupplyChain, SUPPLY_CHAIN),
];

/// The review every engine shares: the dependency gate, the release SBOMs, the features.
const SUPPLY_CHAIN: &[&str] = &[
    "ci:supply-chain",
    "file:.goreleaser-pro.yaml#sboms",
    "permguard-languages/tests/engine_features.rs::test_every_engine_is_pinned_without_defaults_and_names_its_descriptor_features",
    "permguard-languages/tests/descriptor_vectors.rs::test_every_engine_is_the_one_cargo_lock_pins",
];

/// The gate of the runtime `language`; empty for a name this build does not carry.
pub fn gate(language: &str) -> &'static [Record] {
    match language {
        "cedar" => CEDAR,
        "rego" => REGO,
        "dogwood" => DOGWOOD,
        _ => &[],
    }
}

/// The items of `language`'s gate that are not passing, in the model's order; every item for a
/// runtime with no gate.
pub fn open_items(language: &str) -> Vec<Item> {
    let records = gate(language);
    ITEMS
        .into_iter()
        .filter(|item| {
            !records
                .iter()
                .any(|record| record.item == *item && matches!(record.state, State::Passing(_)))
        })
        .collect()
}

/// Whether every item of `language`'s gate passes.
pub fn production_ready(language: &str) -> bool {
    open_items(language).is_empty()
}

/// The gate's result as discovery publishes it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Summary {
    pub gate: &'static str,
    pub production_ready: bool,
    pub open: Vec<&'static str>,
}

/// `language`'s gate result.
pub fn summary(language: &str) -> Summary {
    let open = open_items(language);
    Summary {
        gate: GATE,
        production_ready: open.is_empty(),
        open: open.into_iter().map(Item::name).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_runtime_this_build_carries_has_a_record_for_every_item_once() {
        for language in crate::languages() {
            let records = gate(language.name());
            let items: Vec<Item> = records.iter().map(|record| record.item).collect();
            assert_eq!(items, ITEMS.to_vec(), "{}", language.name());
            for record in records {
                match record.state {
                    State::Passing(evidence) => {
                        assert!(
                            !evidence.is_empty(),
                            "{}: {:?}",
                            language.name(),
                            record.item
                        );
                    }
                    State::Open(reason) => assert!(!reason.is_empty()),
                }
            }
        }
    }

    #[test]
    fn cedar_and_rego_are_production_ready_and_dogwood_says_what_is_open() {
        assert!(production_ready("cedar"), "{:?}", open_items("cedar"));
        assert!(production_ready("rego"), "{:?}", open_items("rego"));
        assert_eq!(
            open_items("dogwood"),
            vec![Item::GoldenVectors, Item::FaultInjection]
        );
        assert_eq!(
            summary("dogwood"),
            Summary {
                gate: GATE,
                production_ready: false,
                open: vec!["golden_vectors", "fault_injection"],
            }
        );
        // A name nobody carries passes nothing.
        assert_eq!(open_items("cobol"), ITEMS.to_vec());
        assert!(!production_ready("cobol"));
    }
}
