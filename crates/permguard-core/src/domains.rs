// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Every string that names a Permguard artifact on a wire or under a hash, written once.
//!
//! A domain string is part of what a signature or a digest means: `SHA-256("permguard.decision.v1\n"
//! || bytes)` and `SHA-256("permguard.event.record.v1\n" || bytes)` can never collide, because the
//! prefix is different, and a decision batch can never be replayed as an event batch, because the
//! protected `typ` is different. That property holds only while every crate spells each string the
//! same way, so the strings live here and nowhere else. A test in this crate scans the workspace
//! for a domain literal outside this module and fails the build when it finds one.
//!
//! The registry is append-only within a major protocol version. A retired string stays here, marked
//! as legacy, so that evidence written under it remains verifiable for its retention lifetime.
//!
//! # Families
//!
//! * [`digest`] — prefixes of digests and MACs. Each ends with `\n` so that concatenation is never
//!   ambiguous; the terminal byte is part of the constant.
//! * [`protected`] — protected `typ` and COSE content-type values of signed containers.
//! * [`interface`] — evaluation interfaces and service contracts, as manifests and discovery spell
//!   them.
//! * [`media`] — media types of ledger objects and transfer bodies.
//! * [`record`] — envelope names of evidence records.
//! * [`artifact`], [`input`], [`event`], [`producer`] — the registered type names a manifest, a request
//!   or a stream record asserts.
//! * [`capability`] — capability URNs a discovery document lists.
//! * [`annotation`] — tree-entry annotations of the object model.
//! * [`format`] — format labels of files the Host writes.
//! * [`kdf`] — labels inside HKDF `info` tuples.
//! * [`grpc`] — the gRPC services the lifecycle gate names: the planes' own, open in every phase,
//!   and those with a discovery or key method open before Ready.

/// Prefixes of digests and MACs. Every value ends with `\n`.
pub mod digest {
    /// A ring's public-set digest.
    pub const KEY_SET: &str = "permguard.key-set.v1\n";
    /// An audit record.
    pub const AUDIT_RECORD: &str = "permguard.audit.record.v1\n";
    /// An audit pseudonym.
    pub const AUDIT_PSEUDONYM: &str = "permguard.audit.pseudonym.v1\n";
    /// The external witness of a Host identity: over `INIT`, `VOLUME_ID` and the first identity
    /// fingerprint (WP-2.2).
    pub const HOST_IDENTITY_WITNESS: &str = "permguard.host.identity.witness.v1\n";
    /// A Host succession record, as the next record and the identity document cite it (WP-2.2).
    pub const HOST_SUCCESSION: &str = "permguard.host.succession.v1\n";
    /// A session `hello`, as the transcript cites it (WP-2.3).
    pub const HOST_SESSION_HELLO: &str = "permguard.host.session.hello.v1\n";
    /// A session `challenge`, as the transcript cites it (WP-2.3).
    pub const HOST_SESSION_CHALLENGE: &str = "permguard.host.session.challenge.v1\n";
    /// The witness of a secret at one version, and of a delivered zone key (WP-3.3).
    pub const SECRET_WITNESS: &str = "permguard.secret.witness.v1\n";
    /// A decision record.
    pub const DECISION_RECORD: &str = "permguard.decision.v1\n";
    /// A normalized evaluation request, as a signed decision response cites it.
    pub const DECISION_REQUEST: &str = "permguard.decision.request.v1\n";
    /// An unsigned decision-response body, as a signed decision response cites it.
    pub const DECISION_RESPONSE_BODY: &str = "permguard.decision.response-body.v1\n";
    /// An event record.
    pub const EVENT_RECORD: &str = "permguard.event.record.v1\n";
    /// The caller's occurrence, before stream fields are added.
    pub const EVENT_OCCURRENCE: &str = "permguard.event.occurrence.v1\n";
    /// A history key over ordered pin values.
    pub const EVENT_HISTORY: &str = "permguard.event.history.v1\n";
    /// A keyed decision-input tag.
    pub const INPUT_TAG: &str = "permguard.input.v1\n";
    /// The v1 cursor MAC; legacy, verified only by the v1 codec.
    pub const STREAM_CURSOR_V1: &str = "permguard.stream.cursor.v1\n";
    /// The v2 cursor MAC, carrying key id and expiry.
    pub const STREAM_CURSOR_V2: &str = "permguard.stream.cursor.v2\n";
    /// The digest of a normalized filter set bound into a cursor.
    pub const STREAM_FILTERS: &str = "permguard.stream.filters.v1\n";
    /// A NOTP ref-state digest.
    pub const NOTP_REF_STATE: &str = "permguard.notp.ref-state.v1\n";
    /// A language descriptor, over its RFC 8785 canonical JSON.
    pub const LANGUAGE_DESCRIPTOR: &str = "permguard.language.descriptor.v1\n";
    /// Content-derived policy identity. No terminal byte: the input is authored bytes of fixed length.
    pub const POLICY_ID: &str = "permguard.policy.id.v1";
}

/// Protected `typ` values and COSE content types of signed containers.
pub mod protected {
    pub const HOST_IDENTITY: &str = "permguard.host.identity.v1";
    pub const HOST_PROOF: &str = "permguard.host.proof.v1";
    pub const HOST_SESSION: &str = "permguard.host.session.v1";
    pub const HOST_SUCCESSION: &str = "permguard.host.succession.v1";
    pub const HOST_RING_BINDING: &str = "permguard.host.ring-binding.v1";
    pub const HOST_GRANT: &str = "permguard.host.grant.v1";
    pub const MEMBERSHIP_MANIFEST: &str = "permguard.membership.manifest.v1";
    pub const MEMBERSHIP_LEASE: &str = "permguard.membership.lease.v1";
    pub const OPERATION_PLAN: &str = "permguard.operation.plan.v1";
    pub const SNAPSHOT_MANIFEST: &str = "permguard.snapshot.manifest.v1";
    pub const LEDGER_EXPORT: &str = "permguard.ledger.export.v1";
    pub const STREAM_RUN: &str = "permguard.stream.run.v1";
    pub const AUDIT_CHECKPOINT: &str = "permguard.audit.checkpoint.v1";
    pub const DECISION_BATCH: &str = "permguard.decision.batch.v1";
    pub const EVENT_BATCH: &str = "permguard.event.batch.v1";
    pub const DECISION_RESPONSE: &str = "permguard.decision.response.v1";
    /// The NOTP head statement, a COSE content type rather than a bare name.
    pub const NOTP_HEAD: &str = "application/vnd.permguard.head.v1+cbor";
}

/// Record-type names carried inside evidence records, distinct from the digest prefixes.
pub mod record {
    /// The envelope name of a decision record.
    pub const DECISION_V1: &str = "permguard.decision.v1";
    /// The envelope name of an event record.
    pub const EVENT_V1: &str = "permguard.event.record.v1";
}

/// Evaluation interfaces and service contracts.
pub mod interface {
    /// The stateless decision interface.
    pub const PDP_NATIVE_V1: &str = "permguard.api.pdp.native.v1";
    /// The temporal decision interface.
    pub const PDP_TEMPORAL_V1ALPHA1: &str = "permguard.api.pdp.temporal.v1alpha1";
    /// The legacy spelling of [`PDP_NATIVE_V1`]: accepted in manifests, never generated.
    pub const PDP_V1_LEGACY: &str = "permguard.pdp.v1";
    /// Decision evidence shipping and reads.
    pub const DECISIONS_NATIVE_V1: &str = "permguard.api.decisions.native.v1";
    /// Event evidence shipping, import and reads.
    pub const EVENTS_NATIVE_V1ALPHA1: &str = "permguard.api.events.native.v1alpha1";
    /// The archive format `events export` writes.
    pub const EVENTS_EXPORT_V1ALPHA1: &str = "permguard.events.export.v1alpha1";
}

/// Media types of ledger objects and transfer bodies.
pub mod media {
    pub const NOTP_V1_CBOR: &str = "application/vnd.permguard.notp.v1+cbor";
    pub const MANIFEST_V1_CBOR: &str = "application/vnd.permguard.manifest.v1+cbor";
    /// The prefix every policy media type shares.
    pub const POLICY_PREFIX: &str = "application/vnd.permguard.policy.";
    pub const POLICY_CEDAR: &str = "application/vnd.permguard.policy.cedar";
    pub const POLICY_REGO: &str = "application/vnd.permguard.policy.rego";
    pub const POLICY_DOGWOOD: &str = "application/vnd.permguard.policy.dogwood";
    pub const SCHEMA_CEDAR: &str = "application/vnd.permguard.schema.cedar";
    pub const SCHEMA_REGO_JSON: &str = "application/vnd.permguard.schema.rego+json";
    /// The whole-input Rego schema, `permguard.rego.schema.v2`, authored as `.regoinput`.
    pub const SCHEMA_REGO_INPUT_JSON: &str = "application/vnd.permguard.schema.rego.input+json";
    pub const DOGWOOD_ACTION_SCHEMA: &str = "application/vnd.permguard.dogwood.action-schema";
    pub const DOGWOOD_EVENT_SCHEMA: &str = "application/vnd.permguard.dogwood.event-schema";
    pub const DOGWOOD_MACROS: &str = "application/vnd.permguard.dogwood.macros";
    pub const DOGWOOD_PROVIDERS: &str = "application/vnd.permguard.dogwood.providers";
    pub const DOGWOOD_PROVIDER_RHAI: &str = "application/vnd.permguard.dogwood.provider.rhai";
}

/// Registered artifact types a partition declares.
pub mod artifact {
    pub const CEDAR_SCHEMA_V1: &str = "permguard.cedar.schema.v1";
    pub const REGO_SCHEMA_V1: &str = "permguard.rego.schema.v1";
    /// The whole-input Rego schema the `regulated` profile requires.
    pub const REGO_SCHEMA_V2: &str = "permguard.rego.schema.v2";
    pub const DOGWOOD_ACTION_SCHEMA_V1: &str = "permguard.dogwood.action-schema.v1";
    pub const DOGWOOD_EVENT_SCHEMA_V1: &str = "permguard.dogwood.event-schema.v1";
    pub const DOGWOOD_MACROS_V1: &str = "permguard.dogwood.macros.v1";
    pub const DOGWOOD_PROVIDERS_V1: &str = "permguard.dogwood.providers.v1";
    pub const DOGWOOD_PROVIDER_RHAI_V1: &str = "permguard.dogwood.provider.rhai.v1";
}

/// Registered partition-input types a request asserts.
pub mod input {
    pub const CEDAR_ENTITIES_V1: &str = "permguard.cedar.entities.v1";
    pub const REGO_DATA_V1: &str = "permguard.rego.data.v1";
}

/// Registered event types a temporal occurrence carries.
pub mod event {
    pub const DOGWOOD_V1: &str = "permguard.dogwood.event.v1";
}

/// Registered producer classes of event streams.
pub mod producer {
    pub const DATA_PLANE_V1: &str = "permguard.event.producer.data-plane.v1";
}

/// The URN prefixes of subjects.
pub mod subject {
    /// A Host: `urn:permguard:host:v1:<host_id>` (WP-2.2).
    pub const HOST_V1_PREFIX: &str = "urn:permguard:host:v1:";
}

/// Capability URNs listed by discovery documents.
pub mod capability {
    pub const PDP_V1_PREFIX: &str = "urn:permguard:pdp:v1:";
    pub const PDP_V1_STORE_IN_PAYLOAD: &str = "urn:permguard:pdp:v1:store-in-payload";
    pub const PDP_V1_PROFILE_SELECTION: &str = "urn:permguard:pdp:v1:profile-selection";
    pub const PDP_V1_PARTITION_INPUTS: &str = "urn:permguard:pdp:v1:partition-inputs";
    pub const PDP_V1_PRINCIPAL: &str = "urn:permguard:pdp:v1:principal";
    pub const PDP_V1_STRUCTURED_REASONS: &str = "urn:permguard:pdp:v1:structured-reasons";
    pub const PDP_V1_BOXCARRING: &str = "urn:permguard:pdp:v1:boxcarring";
    pub const TEMPORAL_V1ALPHA1_STORE_IN_PAYLOAD: &str =
        "urn:permguard:pdp:temporal:v1alpha1:store-in-payload";
    pub const TEMPORAL_V1ALPHA1_TYPED_EVENTS: &str =
        "urn:permguard:pdp:temporal:v1alpha1:typed-events";
    pub const TEMPORAL_V1ALPHA1_SCHEMA_DERIVED_PINS: &str =
        "urn:permguard:pdp:temporal:v1alpha1:schema-derived-pins";
    pub const TEMPORAL_V1ALPHA1_HISTORY_RECEIPTS: &str =
        "urn:permguard:pdp:temporal:v1alpha1:history-receipts";
    pub const TEMPORAL_V1ALPHA1_DURABLE_BEFORE_DECIDED: &str =
        "urn:permguard:pdp:temporal:v1alpha1:durable-before-decided";
}

/// Tree-entry annotations of the object model.
pub mod annotation {
    pub const POLICY_ID: &str = "permguard.policy.id";
    pub const POLICY_ALIAS: &str = "permguard.policy.alias";
    pub const POLICY_KIND: &str = "permguard.policy.kind";
}

/// The controls of the assurance profiles and the relaxations a profile may permit, as discovery
/// and `GET /host/v1/status` publish them (WP-2.8, owner decision of 2026-10-06).
pub mod assurance {
    pub const EVIDENCE_REQUIRED: &str = "evidence.required";
    pub const SCHEMA_PARTITION: &str = "schema.partition";
    pub const SCHEMA_WARNINGS_AS_ERRORS: &str = "schema.warnings_as_errors";
    pub const SCHEMA_REGO_INPUT: &str = "schema.rego_input";
    pub const INTERFACES_EXPLICIT: &str = "interfaces.explicit";
    pub const ENGINE_BOUNDED: &str = "engine.bounded";
    pub const RUNTIME_EXPERIMENTAL_GATED: &str = "runtime.experimental_gated";
    pub const RUNTIME_EXPERIMENTAL_FORBIDDEN: &str = "runtime.experimental_forbidden";
    pub const PROVIDER_SUPERVISED: &str = "provider.supervised";
    pub const GRPC_LOSSLESS_SUBSET: &str = "grpc.lossless_subset";
    pub const GRPC_STRICT_DECODER: &str = "grpc.strict_decoder";
    pub const CUSTODY_ENCRYPTED: &str = "custody.encrypted";
    pub const CUSTODY_HSM: &str = "custody.hsm";
    pub const AUDIT_EXTERNAL_CHECKPOINTS: &str = "audit.external_checkpoints";
    pub const IDENTITY_WITNESS: &str = "identity.witness";
    pub const OPERATIONS_DUAL_CONTROL: &str = "operations.dual_control";
    pub const TLS_1_3_ONLY: &str = "tls.1_3_only";
    pub const RELAX_EVIDENCE_BEST_EFFORT: &str = "evidence.best_effort";
    pub const RELAX_SCHEMA_REGO_INPUT_ABSENT: &str = "schema.rego_input_absent";
    pub const RELAX_GRPC_TRANSPORT_PARITY_PARTIAL: &str = "grpc.transport_parity_partial";
    pub const RELAX_TLS_1_2_COMPAT: &str = "tls.1_2_compat";
    pub const RELAX_CUSTODY_PLAINTEXT: &str = "custody.plaintext";
}

/// Format labels of files the Host writes, bound into their associated data.
pub mod format {
    /// A private key sealed at rest under envelope encryption.
    pub const SEALED_KEY_V1: &str = "permguard.sealed-key.v1";
    /// The source marker of the grant store's snapshot (`permguard_host::authz::store`).
    pub const AUTHZ_SNAPSHOT_V1: &str = "permguard.host.authz.snapshot.v1";
}

/// The 8-byte magics opening every file the storage library writes (`permguard_host::storage`).
pub mod magic {
    /// A journal segment: its header, the header's checksum, then frames.
    pub const JOURNAL_SEGMENT: &str = "PGJRNSEG";
    /// A replaceable view: a whole file replaced atomically.
    pub const VIEW: &str = "PGSVIEW\0";
    /// A snapshot cache, rebuilt from its authoritative journal.
    pub const SNAPSHOT: &str = "PGSSNAP\0";
    /// A tombstone: a deletion in progress, durable before the file is removed.
    pub const TOMBSTONE: &str = "PGSTOMB\0";
}

/// The gRPC services a plane answers in every lifecycle phase (P2): info, health and discovery,
/// which are how a client finds out when to come back. Every other service is a domain route,
/// refused with `plane_not_ready` until the plane is Ready.
pub mod grpc {
    pub const CONTROL_PLANE: &str = "permguard.control.v1.ControlPlane";
    pub const DATA_PLANE: &str = "permguard.data.v1.DataPlane";
    /// The other services with a discovery or key method open before Ready, named with it.
    pub const GIT_LIKE_STORE: &str = "permguard.control.v1.GitLikeStore";
    pub const EVENT_LOG: &str = "permguard.control.v1.EventLog";
    pub const DECISION_LOG: &str = "permguard.control.v1.DecisionLog";
    pub const POLICY_DECISION_POINT: &str = "permguard.data.v1.PolicyDecisionPoint";
    pub const TEMPORAL_POLICY_DECISION_POINT: &str =
        "permguard.data.v1.TemporalPolicyDecisionPoint";
    /// The Host API services the Host listener serves (WP-2.5); membership and evidence arrive
    /// with their packages.
    pub const HOST_IDENTITY_SERVICE: &str = "permguard.host.v1.IdentityService";
    pub const HOST_GRANT_SERVICE: &str = "permguard.host.v1.GrantService";
    pub const HOST_KEY_SERVICE: &str = "permguard.host.v1.KeyService";
    pub const HOST_OPERATIONS_SERVICE: &str = "permguard.host.v1.OperationsService";
}

/// Labels inside HKDF `info` tuples.
pub mod kdf {
    /// The first element of every info tuple.
    pub const LABEL: &str = "permguard.kdf.v1";
    pub const HOST_LOCAL: &str = "host-local";
    pub const ZONE_ROOT: &str = "zone-root";
    pub const ZONE_USE: &str = "zone-use";
    /// The purpose of audit pseudonyms: Host-local, or a zone's shared user pseudonyms (WP-3.3).
    pub const AUDIT_PSEUDONYM: &str = "audit.pseudonym";
    /// The purpose of decision input tags, distributed per ledger (WP-3.3).
    pub const DECISION_COMMITMENT: &str = "decision.commitment";
    /// The purpose of read-offset MACs, Host-local per API (WP-3.3).
    pub const STREAM_CURSOR: &str = "stream.cursor";
}

/// Every constant of this module as `(name, value)`, for vectors and lints.
///
/// The name is the path below `domains`, so `digest::DECISION_RECORD` is `"digest.DECISION_RECORD"`.
pub fn all() -> Vec<(&'static str, &'static str)> {
    vec![
        ("digest.KEY_SET", digest::KEY_SET),
        ("digest.AUDIT_RECORD", digest::AUDIT_RECORD),
        ("digest.AUDIT_PSEUDONYM", digest::AUDIT_PSEUDONYM),
        (
            "digest.HOST_IDENTITY_WITNESS",
            digest::HOST_IDENTITY_WITNESS,
        ),
        ("digest.HOST_SUCCESSION", digest::HOST_SUCCESSION),
        ("digest.HOST_SESSION_HELLO", digest::HOST_SESSION_HELLO),
        (
            "digest.HOST_SESSION_CHALLENGE",
            digest::HOST_SESSION_CHALLENGE,
        ),
        ("digest.SECRET_WITNESS", digest::SECRET_WITNESS),
        ("digest.DECISION_RECORD", digest::DECISION_RECORD),
        ("digest.DECISION_REQUEST", digest::DECISION_REQUEST),
        (
            "digest.DECISION_RESPONSE_BODY",
            digest::DECISION_RESPONSE_BODY,
        ),
        ("digest.EVENT_RECORD", digest::EVENT_RECORD),
        ("digest.EVENT_OCCURRENCE", digest::EVENT_OCCURRENCE),
        ("digest.EVENT_HISTORY", digest::EVENT_HISTORY),
        ("digest.INPUT_TAG", digest::INPUT_TAG),
        ("digest.STREAM_CURSOR_V1", digest::STREAM_CURSOR_V1),
        ("digest.STREAM_CURSOR_V2", digest::STREAM_CURSOR_V2),
        ("digest.STREAM_FILTERS", digest::STREAM_FILTERS),
        ("digest.NOTP_REF_STATE", digest::NOTP_REF_STATE),
        ("digest.LANGUAGE_DESCRIPTOR", digest::LANGUAGE_DESCRIPTOR),
        ("digest.POLICY_ID", digest::POLICY_ID),
        ("protected.HOST_IDENTITY", protected::HOST_IDENTITY),
        ("protected.HOST_PROOF", protected::HOST_PROOF),
        ("protected.HOST_SESSION", protected::HOST_SESSION),
        ("protected.HOST_SUCCESSION", protected::HOST_SUCCESSION),
        ("protected.HOST_RING_BINDING", protected::HOST_RING_BINDING),
        ("protected.HOST_GRANT", protected::HOST_GRANT),
        (
            "protected.MEMBERSHIP_MANIFEST",
            protected::MEMBERSHIP_MANIFEST,
        ),
        ("protected.MEMBERSHIP_LEASE", protected::MEMBERSHIP_LEASE),
        ("protected.OPERATION_PLAN", protected::OPERATION_PLAN),
        ("protected.SNAPSHOT_MANIFEST", protected::SNAPSHOT_MANIFEST),
        ("protected.LEDGER_EXPORT", protected::LEDGER_EXPORT),
        ("protected.STREAM_RUN", protected::STREAM_RUN),
        ("protected.AUDIT_CHECKPOINT", protected::AUDIT_CHECKPOINT),
        ("protected.DECISION_BATCH", protected::DECISION_BATCH),
        ("protected.EVENT_BATCH", protected::EVENT_BATCH),
        ("protected.DECISION_RESPONSE", protected::DECISION_RESPONSE),
        ("protected.NOTP_HEAD", protected::NOTP_HEAD),
        ("record.DECISION_V1", record::DECISION_V1),
        ("record.EVENT_V1", record::EVENT_V1),
        ("interface.PDP_NATIVE_V1", interface::PDP_NATIVE_V1),
        (
            "interface.PDP_TEMPORAL_V1ALPHA1",
            interface::PDP_TEMPORAL_V1ALPHA1,
        ),
        ("interface.PDP_V1_LEGACY", interface::PDP_V1_LEGACY),
        (
            "interface.DECISIONS_NATIVE_V1",
            interface::DECISIONS_NATIVE_V1,
        ),
        (
            "interface.EVENTS_NATIVE_V1ALPHA1",
            interface::EVENTS_NATIVE_V1ALPHA1,
        ),
        (
            "interface.EVENTS_EXPORT_V1ALPHA1",
            interface::EVENTS_EXPORT_V1ALPHA1,
        ),
        ("media.NOTP_V1_CBOR", media::NOTP_V1_CBOR),
        ("media.MANIFEST_V1_CBOR", media::MANIFEST_V1_CBOR),
        ("media.POLICY_PREFIX", media::POLICY_PREFIX),
        ("media.POLICY_CEDAR", media::POLICY_CEDAR),
        ("media.POLICY_REGO", media::POLICY_REGO),
        ("media.POLICY_DOGWOOD", media::POLICY_DOGWOOD),
        ("media.SCHEMA_CEDAR", media::SCHEMA_CEDAR),
        ("media.SCHEMA_REGO_JSON", media::SCHEMA_REGO_JSON),
        (
            "media.SCHEMA_REGO_INPUT_JSON",
            media::SCHEMA_REGO_INPUT_JSON,
        ),
        ("media.DOGWOOD_ACTION_SCHEMA", media::DOGWOOD_ACTION_SCHEMA),
        ("media.DOGWOOD_EVENT_SCHEMA", media::DOGWOOD_EVENT_SCHEMA),
        ("media.DOGWOOD_MACROS", media::DOGWOOD_MACROS),
        ("media.DOGWOOD_PROVIDERS", media::DOGWOOD_PROVIDERS),
        ("media.DOGWOOD_PROVIDER_RHAI", media::DOGWOOD_PROVIDER_RHAI),
        ("artifact.CEDAR_SCHEMA_V1", artifact::CEDAR_SCHEMA_V1),
        ("artifact.REGO_SCHEMA_V1", artifact::REGO_SCHEMA_V1),
        ("artifact.REGO_SCHEMA_V2", artifact::REGO_SCHEMA_V2),
        (
            "artifact.DOGWOOD_ACTION_SCHEMA_V1",
            artifact::DOGWOOD_ACTION_SCHEMA_V1,
        ),
        (
            "artifact.DOGWOOD_EVENT_SCHEMA_V1",
            artifact::DOGWOOD_EVENT_SCHEMA_V1,
        ),
        ("artifact.DOGWOOD_MACROS_V1", artifact::DOGWOOD_MACROS_V1),
        (
            "artifact.DOGWOOD_PROVIDERS_V1",
            artifact::DOGWOOD_PROVIDERS_V1,
        ),
        (
            "artifact.DOGWOOD_PROVIDER_RHAI_V1",
            artifact::DOGWOOD_PROVIDER_RHAI_V1,
        ),
        ("input.CEDAR_ENTITIES_V1", input::CEDAR_ENTITIES_V1),
        ("input.REGO_DATA_V1", input::REGO_DATA_V1),
        ("event.DOGWOOD_V1", event::DOGWOOD_V1),
        ("producer.DATA_PLANE_V1", producer::DATA_PLANE_V1),
        ("subject.HOST_V1_PREFIX", subject::HOST_V1_PREFIX),
        ("capability.PDP_V1_PREFIX", capability::PDP_V1_PREFIX),
        (
            "capability.PDP_V1_STORE_IN_PAYLOAD",
            capability::PDP_V1_STORE_IN_PAYLOAD,
        ),
        (
            "capability.PDP_V1_PROFILE_SELECTION",
            capability::PDP_V1_PROFILE_SELECTION,
        ),
        (
            "capability.PDP_V1_PARTITION_INPUTS",
            capability::PDP_V1_PARTITION_INPUTS,
        ),
        ("capability.PDP_V1_PRINCIPAL", capability::PDP_V1_PRINCIPAL),
        (
            "capability.PDP_V1_STRUCTURED_REASONS",
            capability::PDP_V1_STRUCTURED_REASONS,
        ),
        (
            "capability.PDP_V1_BOXCARRING",
            capability::PDP_V1_BOXCARRING,
        ),
        (
            "capability.TEMPORAL_V1ALPHA1_STORE_IN_PAYLOAD",
            capability::TEMPORAL_V1ALPHA1_STORE_IN_PAYLOAD,
        ),
        (
            "capability.TEMPORAL_V1ALPHA1_TYPED_EVENTS",
            capability::TEMPORAL_V1ALPHA1_TYPED_EVENTS,
        ),
        (
            "capability.TEMPORAL_V1ALPHA1_SCHEMA_DERIVED_PINS",
            capability::TEMPORAL_V1ALPHA1_SCHEMA_DERIVED_PINS,
        ),
        (
            "capability.TEMPORAL_V1ALPHA1_HISTORY_RECEIPTS",
            capability::TEMPORAL_V1ALPHA1_HISTORY_RECEIPTS,
        ),
        (
            "capability.TEMPORAL_V1ALPHA1_DURABLE_BEFORE_DECIDED",
            capability::TEMPORAL_V1ALPHA1_DURABLE_BEFORE_DECIDED,
        ),
        ("annotation.POLICY_ID", annotation::POLICY_ID),
        ("annotation.POLICY_ALIAS", annotation::POLICY_ALIAS),
        ("annotation.POLICY_KIND", annotation::POLICY_KIND),
        ("assurance.EVIDENCE_REQUIRED", assurance::EVIDENCE_REQUIRED),
        ("assurance.SCHEMA_PARTITION", assurance::SCHEMA_PARTITION),
        (
            "assurance.SCHEMA_WARNINGS_AS_ERRORS",
            assurance::SCHEMA_WARNINGS_AS_ERRORS,
        ),
        ("assurance.SCHEMA_REGO_INPUT", assurance::SCHEMA_REGO_INPUT),
        (
            "assurance.INTERFACES_EXPLICIT",
            assurance::INTERFACES_EXPLICIT,
        ),
        ("assurance.ENGINE_BOUNDED", assurance::ENGINE_BOUNDED),
        (
            "assurance.RUNTIME_EXPERIMENTAL_GATED",
            assurance::RUNTIME_EXPERIMENTAL_GATED,
        ),
        (
            "assurance.RUNTIME_EXPERIMENTAL_FORBIDDEN",
            assurance::RUNTIME_EXPERIMENTAL_FORBIDDEN,
        ),
        (
            "assurance.PROVIDER_SUPERVISED",
            assurance::PROVIDER_SUPERVISED,
        ),
        (
            "assurance.GRPC_LOSSLESS_SUBSET",
            assurance::GRPC_LOSSLESS_SUBSET,
        ),
        (
            "assurance.GRPC_STRICT_DECODER",
            assurance::GRPC_STRICT_DECODER,
        ),
        ("assurance.CUSTODY_ENCRYPTED", assurance::CUSTODY_ENCRYPTED),
        ("assurance.CUSTODY_HSM", assurance::CUSTODY_HSM),
        (
            "assurance.AUDIT_EXTERNAL_CHECKPOINTS",
            assurance::AUDIT_EXTERNAL_CHECKPOINTS,
        ),
        ("assurance.IDENTITY_WITNESS", assurance::IDENTITY_WITNESS),
        (
            "assurance.OPERATIONS_DUAL_CONTROL",
            assurance::OPERATIONS_DUAL_CONTROL,
        ),
        ("assurance.TLS_1_3_ONLY", assurance::TLS_1_3_ONLY),
        (
            "assurance.RELAX_EVIDENCE_BEST_EFFORT",
            assurance::RELAX_EVIDENCE_BEST_EFFORT,
        ),
        (
            "assurance.RELAX_SCHEMA_REGO_INPUT_ABSENT",
            assurance::RELAX_SCHEMA_REGO_INPUT_ABSENT,
        ),
        (
            "assurance.RELAX_GRPC_TRANSPORT_PARITY_PARTIAL",
            assurance::RELAX_GRPC_TRANSPORT_PARITY_PARTIAL,
        ),
        (
            "assurance.RELAX_TLS_1_2_COMPAT",
            assurance::RELAX_TLS_1_2_COMPAT,
        ),
        (
            "assurance.RELAX_CUSTODY_PLAINTEXT",
            assurance::RELAX_CUSTODY_PLAINTEXT,
        ),
        ("format.SEALED_KEY_V1", format::SEALED_KEY_V1),
        ("format.AUTHZ_SNAPSHOT_V1", format::AUTHZ_SNAPSHOT_V1),
        ("magic.JOURNAL_SEGMENT", magic::JOURNAL_SEGMENT),
        ("magic.SNAPSHOT", magic::SNAPSHOT),
        ("magic.TOMBSTONE", magic::TOMBSTONE),
        ("magic.VIEW", magic::VIEW),
        ("kdf.LABEL", kdf::LABEL),
        ("kdf.HOST_LOCAL", kdf::HOST_LOCAL),
        ("kdf.ZONE_ROOT", kdf::ZONE_ROOT),
        ("kdf.ZONE_USE", kdf::ZONE_USE),
        ("kdf.AUDIT_PSEUDONYM", kdf::AUDIT_PSEUDONYM),
        ("kdf.DECISION_COMMITMENT", kdf::DECISION_COMMITMENT),
        ("kdf.STREAM_CURSOR", kdf::STREAM_CURSOR),
        ("grpc.CONTROL_PLANE", grpc::CONTROL_PLANE),
        ("grpc.DATA_PLANE", grpc::DATA_PLANE),
        ("grpc.GIT_LIKE_STORE", grpc::GIT_LIKE_STORE),
        ("grpc.EVENT_LOG", grpc::EVENT_LOG),
        ("grpc.DECISION_LOG", grpc::DECISION_LOG),
        ("grpc.POLICY_DECISION_POINT", grpc::POLICY_DECISION_POINT),
        (
            "grpc.TEMPORAL_POLICY_DECISION_POINT",
            grpc::TEMPORAL_POLICY_DECISION_POINT,
        ),
        ("grpc.HOST_IDENTITY_SERVICE", grpc::HOST_IDENTITY_SERVICE),
        ("grpc.HOST_GRANT_SERVICE", grpc::HOST_GRANT_SERVICE),
        ("grpc.HOST_KEY_SERVICE", grpc::HOST_KEY_SERVICE),
        (
            "grpc.HOST_OPERATIONS_SERVICE",
            grpc::HOST_OPERATIONS_SERVICE,
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_every_digest_prefix_ends_with_the_terminal_byte_except_policy_id() {
        for (name, value) in all() {
            if name.starts_with("digest.") && name != "digest.POLICY_ID" {
                assert!(value.ends_with('\n'), "{name} lacks its terminal byte");
            } else {
                assert!(!value.ends_with('\n'), "{name} must not end with a newline");
            }
        }
    }

    #[test]
    fn test_no_two_names_share_a_value_and_no_two_values_share_a_name() {
        let entries = all();
        for (index, (name, value)) in entries.iter().enumerate() {
            for (other_name, other_value) in &entries[index + 1..] {
                assert_ne!(name, other_name, "duplicate name");
                assert_ne!(value, other_value, "{name} and {other_name} share a value");
            }
        }
    }
}
