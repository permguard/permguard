// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The stable codes a refusal carries, written once.
//!
//! A [`crate::ApiError`] names the exact condition with a `code`: the string a script, an SDK or a
//! runbook branches on. The class decides the transport status; the code decides what the caller
//! does next. A code is therefore a contract, and a contract is spelled in one place. A test in this
//! crate scans the workspace for a code literal that this module does not list and fails when it
//! finds one, so a new condition is registered before it is answered.
//!
//! Codes are grouped by the contract that names them. A code that no contract document names yet is
//! kept under [`legacy`] until the document that owns it is written; it is never silently renamed,
//! because a client may already branch on it.

/// Codes every surface may answer.
pub mod common {
    /// The request named something that does not exist here.
    pub const NOT_FOUND: &str = "not_found";
    /// The caller is sound and the service failed.
    pub const INTERNAL: &str = "internal";
    /// The service cannot answer right now and a retry is reasonable.
    pub const UNAVAILABLE: &str = "unavailable";
    /// A well-formed request the world disagrees with, when no finer code applies.
    pub const CONFLICT: &str = "conflict";
    /// A request the transport could not even parse as the contract's shape.
    pub const INVALID_ARGUMENT: &str = "invalid_argument";
    /// A bound of the service was reached.
    pub const EXHAUSTED: &str = "exhausted";
    /// A contract id that was retired; a manifest or request naming it is refused.
    pub const INTERFACE_RETIRED: &str = "interface_retired";
    /// Required credentials are absent or invalid.
    pub const UNAUTHENTICATED: &str = "unauthenticated";
    /// An authenticated principal has no grant covering the resource.
    pub const FORBIDDEN: &str = "forbidden";
    /// A cursor that was edited or issued under another key.
    pub const FORGED: &str = "forged";
}

/// The catalog of zones and ledgers.
pub mod catalog {
    pub const NAME_TAKEN: &str = "name_taken";
    pub const NOT_EMPTY: &str = "not_empty";
    pub const INVALID_NAME: &str = "invalid_name";
    pub const CATALOG_FAILED: &str = "catalog_failed";
}

/// `permguard.api.pdp.native.v1`.
pub mod pdp_native {
    pub const ZONE_REQUIRED: &str = "zone_required";
    pub const LEDGER_REQUIRED: &str = "ledger_required";
    pub const PARTITION_UNKNOWN: &str = "partition_unknown";
    pub const PARTITION_INPUT_REQUIRED: &str = "partition_input_required";
    pub const PARTITION_INPUT_TYPE_REQUIRED: &str = "partition_input_type_required";
    pub const PARTITION_INPUT_TYPE_UNKNOWN: &str = "partition_input_type_unknown";
    pub const PARTITION_INPUT_TYPE_MISMATCH: &str = "partition_input_type_mismatch";
    pub const PARTITION_INPUT_TYPE_INCOMPATIBLE: &str = "partition_input_type_incompatible";
    pub const PARTITION_INPUT_MALFORMED: &str = "partition_input_malformed";
    pub const PARTITION_INPUT_SCHEMA: &str = "partition_input_schema";
    pub const PARTITION_INPUT_TOO_LARGE: &str = "partition_input_too_large";
    pub const PARTITION_INPUT_UNSUPPORTED: &str = "partition_input_unsupported";
    pub const REQUEST_ID_REPEATED: &str = "request_id_repeated";
    /// A `request_nonce` asked for a signed response and no permitted signer is available.
    pub const RESPONSE_SIGNING_UNAVAILABLE: &str = "response_signing_unavailable";
    pub const EVALUATIONS_SEMANTIC: &str = "evaluations_semantic";
    pub const FIELD_REQUIRED: &str = "field_required";
    pub const FIELD_UNSUPPORTED: &str = "field_unsupported";
    pub const FIELD_REMOVED: &str = "field_removed";
    pub const FIELD_RESERVED: &str = "field_reserved";
    pub const TOO_MANY_EVALUATIONS: &str = "too_many_evaluations";
}

/// `permguard.api.pdp.temporal.v1alpha1`.
pub mod pdp_temporal {
    pub const EVENT_REQUIRED: &str = "event_required";
    pub const EVENT_MALFORMED: &str = "event_malformed";
    pub const EVENT_NOT_CANONICAL: &str = "event_not_canonical";
    pub const EVENT_TYPE_UNSUPPORTED: &str = "event_type_unsupported";
    pub const EVENT_VALUE_UNREPRESENTABLE: &str = "event_value_unrepresentable";
    pub const EVENT_ACTION_MALFORMED: &str = "event_action_malformed";
    pub const EVENT_ACTION_UNQUALIFIED: &str = "event_action_unqualified";
    pub const EVENT_ACTION_UNDECLARED: &str = "event_action_undeclared";
    pub const EVENT_KIND_UNDECLARED: &str = "event_kind_undeclared";
    pub const EVENT_KIND_DISAGREES: &str = "event_kind_disagrees";
    pub const EVENT_FIELD_UNDECLARED: &str = "event_field_undeclared";
    pub const EVENT_FIELD_MISTYPED: &str = "event_field_mistyped";
    pub const EVENT_FIELD_NOT_CARRIABLE: &str = "event_field_not_carriable";
    pub const EVENT_BAG_NOT_GROUPED: &str = "event_bag_not_grouped";
    pub const EVENT_BAGS_DISAGREE: &str = "event_bags_disagree";
    pub const EVENT_PIN_CONTRADICTED: &str = "event_pin_contradicted";
    pub const EVENT_PIN_SOURCE_ABSENT: &str = "event_pin_source_absent";
    pub const EVENT_PRINCIPAL_NOT_ADMITTED: &str = "event_principal_not_admitted";
    pub const EVENT_RESOURCE_NOT_ADMITTED: &str = "event_resource_not_admitted";
    pub const EVENT_ENTITIES_REJECTED: &str = "event_entities_rejected";
    pub const EVENT_ENTITY_MALFORMED: &str = "event_entity_malformed";
    pub const EVENT_TIME_NOT_CANONICAL: &str = "event_time_not_canonical";
    pub const EVENT_AHEAD_OF_CLOCK: &str = "event_ahead_of_clock";
    pub const EVENT_TOO_LATE: &str = "event_too_late";
    pub const EVENT_ID_CONFLICT: &str = "event_id_conflict";
    pub const EVENT_ROUTING_CONFLICT: &str = "event_routing_conflict";
    pub const EVENT_HISTORY_DISAGREES: &str = "event_history_disagrees";
    pub const EVENT_NOT_DURABLE: &str = "event_not_durable";
    pub const EVENT_OUTCOME_NOT_DURABLE: &str = "event_outcome_not_durable";
    pub const EVENT_SUBMISSION_AT_CAPACITY: &str = "event_submission_at_capacity";
    pub const EVENT_APPLICATION_INCOMPLETE: &str = "event_application_incomplete";
    pub const EVENT_OUT_OF_ORDER: &str = "event_out_of_order";
    pub const STORE_REQUIRED: &str = "store_required";
}

/// Evidence streams: shipping, ingest and reads.
pub mod stream {
    pub const BATCH_UNATTRIBUTABLE: &str = "batch_unattributable";
    pub const BATCH_UNVERIFIABLE: &str = "batch_unverifiable";
    pub const BATCH_UNREGISTERED: &str = "batch_unregistered";
    pub const BATCH_REJECTED: &str = "batch_rejected";
    pub const MALFORMED_BATCH: &str = "malformed_batch";
    pub const STREAM_FORKED: &str = "stream_forked";
    pub const STREAM_CONFLICT: &str = "stream_conflict";
    pub const STREAM_CLOSED: &str = "stream_closed";
    pub const STREAM_REQUIRED: &str = "stream_required";
    pub const SCOPE_REQUIRED: &str = "scope_required";
    pub const SCOPE_UNKNOWN: &str = "scope_unknown";
    pub const STORE_UNKNOWN: &str = "store_unknown";
    pub const STORE_UNAVAILABLE: &str = "store_unavailable";
    pub const EVENT_STORE_UNAVAILABLE: &str = "event_store_unavailable";
    pub const KEYS_UNAVAILABLE: &str = "keys_unavailable";
    pub const SIGNER_MALFORMED: &str = "signer_malformed";
    pub const LEDGER_NOT_HELD: &str = "ledger_not_held";
    pub const OFFSET_EXPIRED: &str = "offset_expired";
    pub const OFFSET_INVALID: &str = "offset_invalid";
    pub const SEARCH_EXHAUSTED: &str = "search_exhausted";
    pub const GONE: &str = "gone";
    pub const DEFERRED: &str = "deferred";
    pub const FORK: &str = "fork";
    pub const UNVERIFIABLE: &str = "unverifiable";
    pub const UNSUPPORTED: &str = "unsupported";
    pub const CLOSED: &str = "closed";
    pub const ACK_AHEAD: &str = "ack_ahead";
    pub const UNSHIPPABLE: &str = "unshippable";
    pub const READ_REFUSED: &str = "read_refused";
    pub const DECISION_NOT_FOUND: &str = "decision_not_found";
    pub const EVENT_NOT_FOUND: &str = "event_not_found";
    pub const QUOTA_EXHAUSTED: &str = "quota_exhausted";
    /// The acknowledgement for a batch ahead of the store: resend from `expected_seq`.
    pub const OUT_OF_ORDER: &str = "out_of_order";
}

/// Ledger objects and NOTP.
pub mod notp {
    pub const NOT_FAST_FORWARD: &str = "not_fast_forward";
    pub const NOT_A_ROOT: &str = "not_a_root";
    pub const NOT_REACHABLE: &str = "not_reachable";
    pub const OBJECT_REJECTED: &str = "object_rejected";
    pub const COMMIT_REJECTED: &str = "commit_rejected";
    pub const MANIFEST_MISSING: &str = "manifest_missing";
    pub const MANIFEST_REJECTED: &str = "manifest_rejected";
    pub const POLICY_ID_MISMATCH: &str = "policy_id_mismatch";
    pub const POLICY_ID_REJECTED: &str = "policy_id_rejected";
    pub const POLICY_ALIAS_REJECTED: &str = "policy_alias_rejected";
    pub const MEDIA_TYPE_UNREGISTERED: &str = "media_type_unregistered";
    pub const PAYLOAD_MALFORMED: &str = "payload_malformed";
    pub const FIELD_UNKNOWN: &str = "field_unknown";
    pub const GRAMMAR: &str = "grammar";
    pub const KIND_MISMATCH: &str = "kind_mismatch";
    pub const LIMIT: &str = "limit";
    pub const RUNTIME_GATE: &str = "runtime_gate";
    pub const SCHEMA_MISSING: &str = "schema_missing";
    pub const SCHEMA_UNSATISFIED: &str = "schema_unsatisfied";
    pub const VALUE_UNREPRESENTABLE: &str = "value_unrepresentable";
    pub const PARTITION_FAILED: &str = "partition_failed";
    pub const PARTITION_EVALUATION_FAILED: &str = "partition_evaluation_failed";
}

/// Codes the command line and the client answer for their own failures.
pub mod client {
    pub const USAGE: &str = "usage";
    pub const TRANSPORT_FAILED: &str = "transport_failed";
    pub const CONNECT_FAILED: &str = "connect_failed";
    pub const CONNECTION_REFUSED: &str = "connection_refused";
    pub const RESOLVE_FAILED: &str = "resolve_failed";
    pub const MALFORMED_RESPONSE: &str = "malformed_response";
    pub const DECISION_LOG_UNREACHABLE: &str = "decision_log_unreachable";
    pub const EVENT_STORE_UNREACHABLE: &str = "event_store_unreachable";
    pub const TLS_UNSUPPORTED: &str = "tls_unsupported";
    pub const TLS_EXPECTED: &str = "tls_expected";
    pub const TLS_SERVER_NAME_INVALID: &str = "tls_server_name_invalid";
    pub const TLS_NO_TRUST_ANCHORS: &str = "tls_no_trust_anchors";
    pub const TLS_MATERIAL_UNREADABLE: &str = "tls_material_unreadable";
    pub const TLS_HANDSHAKE_FAILED: &str = "tls_handshake_failed";
    pub const TLS_CLIENT_IDENTITY_REJECTED: &str = "tls_client_identity_rejected";
    pub const TLS_CLIENT_IDENTITY_INCOMPLETE: &str = "tls_client_identity_incomplete";
    pub const TLS_CLIENT_CERTIFICATE_REQUIRED: &str = "tls_client_certificate_required";
    pub const EVENT_EXPORT_MALFORMED: &str = "event_export_malformed";
    pub const EVENT_EXPORT_TRUNCATED: &str = "event_export_truncated";
    pub const EVENT_EXPORT_TYPE_UNSUPPORTED: &str = "event_export_type_unsupported";
    pub const EVENT_EXPORT_UNREADABLE: &str = "event_export_unreadable";
    pub const EVENT_KEYS_REQUIRED: &str = "event_keys_required";
    pub const EVENTS_UNVERIFIED: &str = "events_unverified";
    pub const EXPORT_TRUNCATED: &str = "export_truncated";
    pub const KEYS_EMPTY: &str = "keys_empty";
    pub const KEYS_MALFORMED: &str = "keys_malformed";
    pub const KEYS_UNREADABLE: &str = "keys_unreadable";
}

/// Codes in use that no contract document names yet.
///
/// Each one is kept until the document that owns it is written; renaming one is a contract change.
pub mod legacy {
    /// Reason words a decision response carries; outcomes, not refusals, but branched on the same way.
    pub const PERMITTED: &str = "permitted";
    pub const DENIED: &str = "denied";
    pub const REJECTED: &str = "rejected";
    pub const NOT_PERMITTED: &str = "not_permitted";
}

/// Every code of this module as `(name, value)`, for vectors and the registration lint.
pub fn all() -> Vec<(&'static str, &'static str)> {
    macro_rules! entries {
        ($($module:ident :: $name:ident),* $(,)?) => {
            vec![$((concat!(stringify!($module), ".", stringify!($name)), $module::$name)),*]
        };
    }

    entries![
        common::NOT_FOUND,
        common::INTERNAL,
        common::UNAVAILABLE,
        common::CONFLICT,
        common::INVALID_ARGUMENT,
        common::EXHAUSTED,
        common::INTERFACE_RETIRED,
        common::UNAUTHENTICATED,
        common::FORBIDDEN,
        common::FORGED,
        catalog::NAME_TAKEN,
        catalog::NOT_EMPTY,
        catalog::INVALID_NAME,
        catalog::CATALOG_FAILED,
        pdp_native::ZONE_REQUIRED,
        pdp_native::LEDGER_REQUIRED,
        pdp_native::PARTITION_UNKNOWN,
        pdp_native::PARTITION_INPUT_REQUIRED,
        pdp_native::PARTITION_INPUT_TYPE_REQUIRED,
        pdp_native::PARTITION_INPUT_TYPE_UNKNOWN,
        pdp_native::PARTITION_INPUT_TYPE_MISMATCH,
        pdp_native::PARTITION_INPUT_TYPE_INCOMPATIBLE,
        pdp_native::PARTITION_INPUT_MALFORMED,
        pdp_native::PARTITION_INPUT_SCHEMA,
        pdp_native::PARTITION_INPUT_TOO_LARGE,
        pdp_native::PARTITION_INPUT_UNSUPPORTED,
        pdp_native::REQUEST_ID_REPEATED,
        pdp_native::RESPONSE_SIGNING_UNAVAILABLE,
        pdp_native::EVALUATIONS_SEMANTIC,
        pdp_native::FIELD_REQUIRED,
        pdp_native::FIELD_UNSUPPORTED,
        pdp_native::FIELD_REMOVED,
        pdp_native::FIELD_RESERVED,
        pdp_native::TOO_MANY_EVALUATIONS,
        pdp_temporal::EVENT_REQUIRED,
        pdp_temporal::EVENT_MALFORMED,
        pdp_temporal::EVENT_NOT_CANONICAL,
        pdp_temporal::EVENT_TYPE_UNSUPPORTED,
        pdp_temporal::EVENT_VALUE_UNREPRESENTABLE,
        pdp_temporal::EVENT_ACTION_MALFORMED,
        pdp_temporal::EVENT_ACTION_UNQUALIFIED,
        pdp_temporal::EVENT_ACTION_UNDECLARED,
        pdp_temporal::EVENT_KIND_UNDECLARED,
        pdp_temporal::EVENT_KIND_DISAGREES,
        pdp_temporal::EVENT_FIELD_UNDECLARED,
        pdp_temporal::EVENT_FIELD_MISTYPED,
        pdp_temporal::EVENT_FIELD_NOT_CARRIABLE,
        pdp_temporal::EVENT_BAG_NOT_GROUPED,
        pdp_temporal::EVENT_BAGS_DISAGREE,
        pdp_temporal::EVENT_PIN_CONTRADICTED,
        pdp_temporal::EVENT_PIN_SOURCE_ABSENT,
        pdp_temporal::EVENT_PRINCIPAL_NOT_ADMITTED,
        pdp_temporal::EVENT_RESOURCE_NOT_ADMITTED,
        pdp_temporal::EVENT_ENTITIES_REJECTED,
        pdp_temporal::EVENT_ENTITY_MALFORMED,
        pdp_temporal::EVENT_TIME_NOT_CANONICAL,
        pdp_temporal::EVENT_AHEAD_OF_CLOCK,
        pdp_temporal::EVENT_TOO_LATE,
        pdp_temporal::EVENT_ID_CONFLICT,
        pdp_temporal::EVENT_ROUTING_CONFLICT,
        pdp_temporal::EVENT_HISTORY_DISAGREES,
        pdp_temporal::EVENT_NOT_DURABLE,
        pdp_temporal::EVENT_OUTCOME_NOT_DURABLE,
        pdp_temporal::EVENT_SUBMISSION_AT_CAPACITY,
        pdp_temporal::EVENT_APPLICATION_INCOMPLETE,
        pdp_temporal::EVENT_OUT_OF_ORDER,
        pdp_temporal::STORE_REQUIRED,
        stream::BATCH_UNATTRIBUTABLE,
        stream::BATCH_UNVERIFIABLE,
        stream::BATCH_UNREGISTERED,
        stream::BATCH_REJECTED,
        stream::MALFORMED_BATCH,
        stream::STREAM_FORKED,
        stream::STREAM_CONFLICT,
        stream::STREAM_CLOSED,
        stream::STREAM_REQUIRED,
        stream::SCOPE_REQUIRED,
        stream::SCOPE_UNKNOWN,
        stream::STORE_UNKNOWN,
        stream::STORE_UNAVAILABLE,
        stream::EVENT_STORE_UNAVAILABLE,
        stream::KEYS_UNAVAILABLE,
        stream::SIGNER_MALFORMED,
        stream::LEDGER_NOT_HELD,
        stream::OFFSET_EXPIRED,
        stream::OFFSET_INVALID,
        stream::SEARCH_EXHAUSTED,
        stream::GONE,
        stream::DEFERRED,
        stream::FORK,
        stream::UNVERIFIABLE,
        stream::UNSUPPORTED,
        stream::CLOSED,
        stream::ACK_AHEAD,
        stream::UNSHIPPABLE,
        stream::READ_REFUSED,
        stream::DECISION_NOT_FOUND,
        stream::EVENT_NOT_FOUND,
        stream::QUOTA_EXHAUSTED,
        stream::OUT_OF_ORDER,
        notp::NOT_FAST_FORWARD,
        notp::NOT_A_ROOT,
        notp::NOT_REACHABLE,
        notp::OBJECT_REJECTED,
        notp::COMMIT_REJECTED,
        notp::MANIFEST_MISSING,
        notp::MANIFEST_REJECTED,
        notp::POLICY_ID_MISMATCH,
        notp::POLICY_ID_REJECTED,
        notp::POLICY_ALIAS_REJECTED,
        notp::MEDIA_TYPE_UNREGISTERED,
        notp::PAYLOAD_MALFORMED,
        notp::FIELD_UNKNOWN,
        notp::GRAMMAR,
        notp::KIND_MISMATCH,
        notp::LIMIT,
        notp::RUNTIME_GATE,
        notp::SCHEMA_MISSING,
        notp::SCHEMA_UNSATISFIED,
        notp::VALUE_UNREPRESENTABLE,
        notp::PARTITION_FAILED,
        notp::PARTITION_EVALUATION_FAILED,
        client::USAGE,
        client::TRANSPORT_FAILED,
        client::CONNECT_FAILED,
        client::CONNECTION_REFUSED,
        client::RESOLVE_FAILED,
        client::MALFORMED_RESPONSE,
        client::DECISION_LOG_UNREACHABLE,
        client::EVENT_STORE_UNREACHABLE,
        client::TLS_UNSUPPORTED,
        client::TLS_EXPECTED,
        client::TLS_SERVER_NAME_INVALID,
        client::TLS_NO_TRUST_ANCHORS,
        client::TLS_MATERIAL_UNREADABLE,
        client::TLS_HANDSHAKE_FAILED,
        client::TLS_CLIENT_IDENTITY_REJECTED,
        client::TLS_CLIENT_IDENTITY_INCOMPLETE,
        client::TLS_CLIENT_CERTIFICATE_REQUIRED,
        client::EVENT_EXPORT_MALFORMED,
        client::EVENT_EXPORT_TRUNCATED,
        client::EVENT_EXPORT_TYPE_UNSUPPORTED,
        client::EVENT_EXPORT_UNREADABLE,
        client::EVENT_KEYS_REQUIRED,
        client::EVENTS_UNVERIFIED,
        client::EXPORT_TRUNCATED,
        client::KEYS_EMPTY,
        client::KEYS_MALFORMED,
        client::KEYS_UNREADABLE,
        legacy::PERMITTED,
        legacy::DENIED,
        legacy::REJECTED,
        legacy::NOT_PERMITTED,
    ]
}

/// Whether `code` is registered.
pub fn is_registered(code: &str) -> bool {
    all().iter().any(|(_, value)| *value == code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_codes_are_snake_case_and_unique() {
        let entries = all();
        for (index, (name, value)) in entries.iter().enumerate() {
            assert!(
                value
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
                "{name} is not snake_case: {value}"
            );
            for (other, other_value) in &entries[index + 1..] {
                assert_ne!(value, other_value, "{name} and {other} share a code");
            }
        }
    }
}
