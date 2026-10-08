// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The CBOR label registries of `contracts/cbor/`, against the encoders and decoders that own them.
//!
//! Each registry names the labels, types and cardinalities of one artifact family. Here a realistic
//! value of every root is built through the owning crate's public API, encoded, decoded with the
//! canonical decoder and walked against the registry: a label the code writes and the registry
//! does not list, a required label the code leaves out, or a value of another type fails. Then
//! every closed map of every sample gains one unknown label, and the owning decoder must refuse
//! it; a tuple gains one trailing element, with the same expectation. A registry that drifts from
//! the code, or a decoder that starts skipping what it does not know, fails here.

use std::collections::{BTreeMap, BTreeSet};

use permguard_notp::{
    CommitPushRequest, CommitPushResponse, FetchObjectsRequest, FetchObjectsResponse,
    NegotiatePullRequest, NegotiatePullResponse, NegotiatePushRequest, NegotiatePushResponse,
    ObjectClaim, UploadObjectsRequest, UploadObjectsResponse,
};
use permguard_objects::Digest;
use permguard_objects::cbor::{self, Value};
use permguard_objects::crypto::kdf;
use permguard_objects::crypto::seal::{self, Binding, LocalKeyWrap, SealedKey};
use permguard_objects::crypto::suite::{SigningKey, Suite};
use permguard_objects::crypto::thumbprint::{self, KeySet};
use permguard_objects::manifest::{
    ArtifactContract, HistoryScope, InputContract, KIND_POLICY, Manifest, PROFILE_PDP_NATIVE_V1,
    Partition, Profile, Requirement, Runtime,
};
use permguard_objects::object::{self, Blob, Commit, Kind, Tree, TreeEntry};
use permguard_objects::semver::Constraint;
use permguard_objects::statement::{HeadStatement, SignedHead, StatementError};
use serde_json::Value as Json;

/// Every registry file. A new file under `contracts/cbor/` is listed here and given samples below,
/// or the wiring test fails: a registry nothing checks is a registry that drifts.
const REGISTRIES: [&str; 12] = [
    "audit.json",
    "grant.json",
    "head-statement.json",
    "identity.json",
    "kdf.json",
    "key-set.json",
    "layout.json",
    "manifest.json",
    "mutation.json",
    "notp.json",
    "objects.json",
    "sealed-key.json",
];

/// The one encoding every registry states.
const ENCODING: &str =
    "deterministic CBOR (RFC 8949 core deterministic), integers in the signed 64-bit range";

/// The labels the negative vectors add. No registry may use them, or the vector would be known.
const UNKNOWN_INT: i64 = 99;
const UNKNOWN_TEXT: &str = "unknown";

const HOST_ID: [u8; 16] = [
    0x01, 0x98, 0xf2, 0xaa, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 0x01,
];
const ZONE_ID: [u8; 16] = [
    0x01, 0x98, 0xf3, 0xbb, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 0x02,
];
const SCOPE_ID: [u8; 16] = [
    0x01, 0x98, 0xf4, 0xcc, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 0x03,
];
/// The RFC 8037 appendix A.3 thumbprint, and the thumbprint spelling of 32 zero bytes.
const THUMBPRINT_A: &str = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k";
const THUMBPRINT_B: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const HEAD_KID: &str = "control.attest:kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k";

/// Whether the owning decoder accepted the bytes, and why not when it did not.
type Decoder = Box<dyn Fn(&[u8]) -> Result<(), String>>;

/// One encoded value of a registry root.
struct Sample {
    root: &'static str,
    bytes: Vec<u8>,
    /// The optional fields this sample sets, as `map.field`; every other optional must be absent.
    optional: &'static [&'static str],
    /// The public decoder of the root, when one exists.
    decoder: Option<Decoder>,
}

fn sample(
    root: &'static str,
    bytes: Vec<u8>,
    optional: &'static [&'static str],
    decoder: Option<Decoder>,
) -> Sample {
    Sample {
        root,
        bytes,
        optional,
        decoder,
    }
}

fn verdict<T, E: std::fmt::Debug>(result: Result<T, E>) -> Result<(), String> {
    result.map(|_| ()).map_err(|error| format!("{error:?}"))
}

fn registry(file: &str) -> Json {
    let path = permguard_conformance::contracts::root()
        .join("cbor")
        .join(file);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|error| panic!("{file}: not JSON: {error}"))
}

fn roots(registry: &Json) -> Vec<&str> {
    match &registry["root"] {
        Json::String(root) => vec![root.as_str()],
        Json::Array(roots) => roots
            .iter()
            .map(|root| root.as_str().expect("a root is a name"))
            .collect(),
        other => panic!("`root` is a name or a list of names, not {other}"),
    }
}

/// The type of a root: a registered map or a registered tuple of that name.
fn root_type(registry: &Json, root: &str) -> String {
    if registry["maps"].get(root).is_some() {
        format!("map:{root}")
    } else {
        format!("array:{root}")
    }
}

fn fields(map: &Json) -> &Vec<Json> {
    map["fields"].as_array().expect("`fields` is an array")
}

fn text_of<'a>(json: &'a Json, member: &str) -> &'a str {
    json[member]
        .as_str()
        .unwrap_or_else(|| panic!("`{member}` is text in {json}"))
}

/// Whether a decoded map key is this registered label.
fn is_label(key: &Value, label: &Json, keys: &str) -> bool {
    match (keys, key) {
        ("int", Value::Int(key)) => label.as_i64() == Some(*key),
        ("text", Value::Text(key)) => label.as_str() == Some(key.as_str()),
        _ => false,
    }
}

fn const_matches(expected: &Json, value: &Value) -> bool {
    match (expected, value) {
        (Json::Number(expected), Value::Int(value)) => expected.as_i64() == Some(*value),
        (Json::String(expected), Value::Text(value)) => expected == value,
        (Json::Bool(expected), Value::Bool(value)) => expected == value,
        _ => false,
    }
}

/// The inner type of `outer<inner>`, when `ty` has that shape.
fn generic<'a>(ty: &'a str, outer: &str) -> Option<&'a str> {
    ty.strip_prefix(outer)?.strip_suffix('>')
}

/// Walks decoded values against one registry and remembers what it saw.
struct Walk<'a> {
    file: &'a str,
    registry: &'a Json,
    maps: BTreeSet<String>,
    arrays: BTreeSet<String>,
    /// Optional fields set by the current sample.
    sample_optional: BTreeSet<String>,
    /// Optional fields seen set, and seen left out, across every sample.
    present: BTreeSet<String>,
    absent: BTreeSet<String>,
}

impl<'a> Walk<'a> {
    fn new(file: &'a str, registry: &'a Json) -> Self {
        Self {
            file,
            registry,
            maps: BTreeSet::new(),
            arrays: BTreeSet::new(),
            sample_optional: BTreeSet::new(),
            present: BTreeSet::new(),
            absent: BTreeSet::new(),
        }
    }

    fn check(&mut self, ty: &str, value: &Value, at: &str) {
        let file = self.file;
        let fits = match ty {
            "uint" => matches!(value, Value::Int(n) if *n >= 0),
            "int" => matches!(value, Value::Int(_)),
            "text" => matches!(value, Value::Text(_)),
            "bytes" => matches!(value, Value::Bytes(_)),
            "bool" => matches!(value, Value::Bool(_)),
            "scalar" => {
                matches!(value, Value::Text(_) | Value::Bool(_))
                    || matches!(value, Value::Int(n) if *n >= 0)
            }
            "digest" => matches!(value, Value::Text(t) if Digest::parse(t).is_ok()),
            _ => {
                if let Some(expected) = ty.strip_prefix("const:") {
                    let expected: Json = serde_json::from_str(expected)
                        .unwrap_or_else(|_| panic!("{file}: {at}: `{ty}` is not a JSON constant"));
                    const_matches(&expected, value)
                } else if let Some(name) = ty.strip_prefix("map:") {
                    self.check_map(name, value, at);
                    true
                } else if let Some(name) = ty.strip_prefix("array:") {
                    self.check_tuple(name, value, at);
                    true
                } else if let Some(inner) = ty.strip_prefix("cbor:") {
                    let Value::Bytes(bytes) = value else {
                        panic!(
                            "{file}: {at}: expected a byte string holding {inner}, got {value:?}"
                        );
                    };
                    let decoded = cbor::decode_canonical(bytes).unwrap_or_else(|error| {
                        panic!("{file}: {at}: the embedded bytes are not canonical CBOR: {error}")
                    });
                    self.check(inner, &decoded, at);
                    true
                } else if let Some(inner) = generic(ty, "array<") {
                    let Value::Array(items) = value else {
                        panic!("{file}: {at}: expected {ty}, got {value:?}");
                    };
                    for (index, item) in items.iter().enumerate() {
                        self.check(inner, item, &format!("{at}[{index}]"));
                    }
                    true
                } else if let Some(inner) = generic(ty, "map<text,") {
                    let Value::Map(pairs) = value else {
                        panic!("{file}: {at}: expected {ty}, got {value:?}");
                    };
                    for (key, item) in pairs {
                        let Value::Text(key) = key else {
                            panic!("{file}: {at}: expected text keys, got {key:?}");
                        };
                        self.check(inner, item, &format!("{at}[{key}]"));
                    }
                    true
                } else {
                    panic!("{file}: {at}: `{ty}` is not a registry type");
                }
            }
        };
        assert!(fits, "{file}: {at}: expected {ty}, got {value:?}");
    }

    fn check_map(&mut self, name: &str, value: &Value, at: &str) {
        let file = self.file;
        let registry = self.registry;
        let map = registry["maps"]
            .get(name)
            .unwrap_or_else(|| panic!("{file}: {at}: the map `{name}` is not registered"));
        self.maps.insert(name.to_owned());
        let keys = text_of(map, "keys");
        let Value::Map(pairs) = value else {
            panic!("{file}: {at}: `{name}` must be a map, got {value:?}");
        };
        for (key, item) in pairs {
            let field = fields(map)
                .iter()
                .find(|field| is_label(key, &field["label"], keys))
                .unwrap_or_else(|| {
                    panic!(
                        "{file}: {at}: the code writes {key:?}, which `{name}` does not register"
                    )
                });
            let field_name = text_of(field, "name");
            self.check(text_of(field, "type"), item, &format!("{at}.{field_name}"));
        }
        for field in fields(map) {
            let field_name = text_of(field, "name");
            let present = pairs
                .iter()
                .any(|(key, _)| is_label(key, &field["label"], keys));
            let id = format!("{name}.{field_name}");
            match text_of(field, "occurs") {
                "required" => assert!(present, "{file}: {at}: the required `{id}` is missing"),
                "optional" if present => {
                    self.sample_optional.insert(id.clone());
                    self.present.insert(id);
                }
                "optional" => {
                    self.absent.insert(id);
                }
                other => panic!("{file}: `{id}` occurs `{other}`"),
            }
        }
    }

    fn check_tuple(&mut self, name: &str, value: &Value, at: &str) {
        let file = self.file;
        let registry = self.registry;
        let positions = registry["arrays"][name]
            .as_array()
            .unwrap_or_else(|| panic!("{file}: {at}: the tuple `{name}` is not registered"));
        self.arrays.insert(name.to_owned());
        let Value::Array(items) = value else {
            panic!("{file}: {at}: `{name}` must be an array, got {value:?}");
        };
        assert_eq!(
            items.len(),
            positions.len(),
            "{file}: {at}: `{name}` has {} positions",
            positions.len()
        );
        for (item, position) in items.iter().zip(positions) {
            let position_name = text_of(position, "name");
            self.check(
                text_of(position, "type"),
                item,
                &format!("{at}.{position_name}"),
            );
        }
    }
}

/// Every value derived from `value` by adding one unknown label to one closed map, or one
/// trailing element to one tuple, with where the change was made.
fn mutations(registry: &Json, ty: &str, value: &Value, at: &str) -> Vec<(String, Value)> {
    let mut out = Vec::new();
    if let Some(name) = ty.strip_prefix("map:") {
        let map = &registry["maps"][name];
        let keys = text_of(map, "keys");
        let Value::Map(pairs) = value else {
            return out;
        };
        let unknown = if keys == "int" {
            Value::Int(UNKNOWN_INT)
        } else {
            Value::Text(UNKNOWN_TEXT.to_owned())
        };
        let mut extended = pairs.clone();
        extended.push((unknown.clone(), Value::Int(0)));
        out.push((format!("{at} + {unknown:?}"), Value::Map(extended)));
        for (index, (key, item)) in pairs.iter().enumerate() {
            let Some(field) = fields(map)
                .iter()
                .find(|field| is_label(key, &field["label"], keys))
            else {
                continue;
            };
            let inner_at = format!("{at}.{}", text_of(field, "name"));
            for (path, mutated) in mutations(registry, text_of(field, "type"), item, &inner_at) {
                let mut copy = pairs.clone();
                copy[index].1 = mutated;
                out.push((path, Value::Map(copy)));
            }
        }
    } else if let Some(name) = ty.strip_prefix("array:") {
        let positions = registry["arrays"][name]
            .as_array()
            .expect("a registered tuple");
        let Value::Array(items) = value else {
            return out;
        };
        let mut extended = items.clone();
        extended.push(Value::Int(0));
        out.push((format!("{at} + trailing element"), Value::Array(extended)));
        for (index, (item, position)) in items.iter().zip(positions).enumerate() {
            let inner_at = format!("{at}.{}", text_of(position, "name"));
            for (path, mutated) in mutations(registry, text_of(position, "type"), item, &inner_at) {
                let mut copy = items.clone();
                copy[index] = mutated;
                out.push((path, Value::Array(copy)));
            }
        }
    } else if let Some(inner) = ty.strip_prefix("cbor:") {
        let Value::Bytes(bytes) = value else {
            return out;
        };
        let decoded = cbor::decode_canonical(bytes).expect("embedded canonical CBOR");
        for (path, mutated) in mutations(registry, inner, &decoded, at) {
            let bytes = cbor::encode(&mutated).expect("a mutated value encodes");
            out.push((path, Value::Bytes(bytes)));
        }
    } else if let Some(inner) = generic(ty, "array<") {
        let Value::Array(items) = value else {
            return out;
        };
        for (index, item) in items.iter().enumerate() {
            for (path, mutated) in mutations(registry, inner, item, &format!("{at}[{index}]")) {
                let mut copy = items.clone();
                copy[index] = mutated;
                out.push((path, Value::Array(copy)));
            }
        }
    } else if let Some(inner) = generic(ty, "map<text,") {
        let Value::Map(pairs) = value else {
            return out;
        };
        for (index, (key, item)) in pairs.iter().enumerate() {
            for (path, mutated) in mutations(registry, inner, item, &format!("{at}[{key:?}]")) {
                let mut copy = pairs.clone();
                copy[index].1 = mutated;
                out.push((path, Value::Map(copy)));
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------------------------
// Samples, built through the owning crates' public API.

fn ed25519() -> SigningKey {
    let pkcs8 = SigningKey::generate_pkcs8(Suite::Ed25519Sha256V1).expect("a key is minted");
    SigningKey::from_pkcs8(Suite::Ed25519Sha256V1, &pkcs8).expect("the key reads back")
}

fn head_statement() -> HeadStatement {
    HeadStatement {
        zone: "0198f2aa-0000-7000-8000-000000000001".into(),
        ledger: "0198f3bb-0000-7000-8000-000000000002".into(),
        r#ref: "main".into(),
        digest: Digest::compute(b"commit"),
        counter: 42,
        signed_at: 1_787_836_802,
    }
}

fn signed_head(key: &SigningKey) -> Vec<u8> {
    SignedHead::sign_with(&head_statement(), HEAD_KID.as_bytes(), |bytes| {
        key.sign(bytes)
            .map(|signature| signature.to_vec())
            .map_err(|error| StatementError::Signer(error.to_string()))
    })
    .expect("the statement signs")
    .encode()
    .expect("the envelope encodes")
}

/// Signs an envelope again over whatever protected header and payload it now carries, so a
/// mutated envelope is refused for what it says and never merely for a stale signature. The
/// structure is RFC 9052's `Sig_structure` for COSE_Sign1 with empty external data.
fn resign(envelope: &[u8], key: &SigningKey) -> Vec<u8> {
    let Ok(Value::Array(mut items)) = cbor::decode_canonical(envelope) else {
        return envelope.to_vec();
    };
    if let (Some(Value::Bytes(protected)), Some(Value::Bytes(payload))) =
        (items.first(), items.get(2))
        && items.len() > 3
    {
        let to_sign = cbor::encode(&Value::Array(vec![
            Value::Text("Signature1".into()),
            Value::Bytes(protected.clone()),
            Value::Bytes(Vec::new()),
            Value::Bytes(payload.clone()),
        ]))
        .expect("the signature structure encodes");
        items[3] = Value::Bytes(key.sign(&to_sign).expect("it signs").to_vec());
    }
    cbor::encode(&Value::Array(items)).expect("the envelope encodes")
}

fn objects_samples() -> Vec<Sample> {
    let decoder =
        || -> Option<Decoder> { Some(Box::new(|bytes: &[u8]| verdict(object::decode(bytes)))) };
    let blob = Blob {
        media_type: "application/vnd.permguard.policy.cedar".into(),
        data: b"permit(principal, action, resource);".to_vec(),
    }
    .encode()
    .expect("the blob encodes");
    let tree = Tree {
        entries: vec![
            TreeEntry {
                kind: Kind::Blob,
                digest: Digest::compute(&blob),
                name: "access.cedar".into(),
                annotations: BTreeMap::from([
                    (
                        "permguard.policy.id".to_owned(),
                        "0198f5dd-0000-8000-8000-000000000004".to_owned(),
                    ),
                    ("permguard.policy.kind".to_owned(), "policy".to_owned()),
                ]),
            },
            TreeEntry {
                kind: Kind::Tree,
                digest: Digest::compute(b"partition"),
                name: "app".into(),
                annotations: BTreeMap::new(),
            },
        ],
    }
    .encode()
    .expect("the tree encodes");
    let commit = Commit {
        tree: Digest::compute(&tree),
        manifest: Digest::compute(b"manifest"),
        predecessors: vec![Digest::compute(b"parent")],
        author: "alice@example.com".into(),
        author_at: 1_787_836_802,
        message: "add the access policy".into(),
    }
    .encode()
    .expect("the commit encodes");
    vec![
        sample("blob", blob, &[], decoder()),
        sample("tree", tree, &[], decoder()),
        sample("commit", commit, &[], decoder()),
    ]
}

fn requirement(name: &str, constraint: &str) -> Requirement {
    Requirement {
        name: name.into(),
        constraint: Constraint::parse(constraint).expect("a constraint of the grammar"),
    }
}

fn manifest(partitions: BTreeMap<String, Partition>) -> Manifest {
    let names = partitions.keys().cloned().collect();
    Manifest {
        kind: KIND_POLICY.into(),
        name: "acme-authz".into(),
        description: "Acme authorization".into(),
        author: "Acme".into(),
        license: "Apache-2.0".into(),
        runtimes: BTreeMap::from([(
            "cedar".to_owned(),
            Runtime {
                language: requirement("cedar", ">=4.0.0"),
                engine: requirement("permguard", ">=0.1.0 <0.2.0"),
            },
        )]),
        partitions,
        profiles: BTreeMap::from([(
            "pdp".to_owned(),
            Profile {
                r#type: PROFILE_PDP_NATIVE_V1.into(),
                partitions: names,
            },
        )]),
    }
}

fn manifest_samples() -> Vec<Sample> {
    let decoder =
        || -> Option<Decoder> { Some(Box::new(|bytes: &[u8]| verdict(Manifest::decode(bytes)))) };
    let plain = Partition {
        runtime: "cedar".into(),
        media_types: vec!["application/vnd.permguard.policy.cedar".into()],
        schema: true,
        artifacts: Vec::new(),
        history: None,
        input: None,
    };
    let typed = Partition {
        runtime: "cedar".into(),
        media_types: vec!["application/vnd.permguard.policy.cedar".into()],
        schema: false,
        artifacts: vec![ArtifactContract {
            r#type: "permguard.cedar.schema.v1".into(),
            required: true,
        }],
        history: Some(HistoryScope::Global),
        input: Some(InputContract {
            r#type: "permguard.cedar.entities.v1".into(),
            required: true,
        }),
    };
    let minimal = manifest(BTreeMap::from([("app".to_owned(), plain.clone())]))
        .encode()
        .expect("the manifest encodes");
    let full = manifest(BTreeMap::from([
        ("app".to_owned(), plain),
        ("events".to_owned(), typed),
    ]))
    .encode()
    .expect("the manifest encodes");
    vec![
        sample("manifest", minimal, &[], decoder()),
        sample(
            "manifest",
            full,
            &[
                "partition.input",
                "partition.artifacts",
                "partition.history",
            ],
            decoder(),
        ),
    ]
}

fn head_statement_samples() -> Vec<Sample> {
    let key = ed25519();
    let public = key.public_key().to_vec();
    let envelope = signed_head(&key);
    let decoder: Decoder = Box::new(move |bytes: &[u8]| {
        let envelope = resign(bytes, &key);
        let signed = SignedHead::decode(&envelope).map_err(|error| format!("{error:?}"))?;
        verdict(signed.verify(&public))
    });
    vec![sample("cose_sign1", envelope, &[], Some(decoder))]
}

fn grant_samples() -> Vec<Sample> {
    use permguard_core::authz::{Principal, Selector};
    use permguard_host::authz::record::{GrantId, GrantRecord, Status, Transition};
    use permguard_host::operations::journal::OperationId;

    let record = GrantRecord {
        grant_id: GrantId::from_bytes(HOST_ID),
        principal_id: Principal::new("spiffe://acme/billing").expect("a principal"),
        operations: vec!["catalog.read".to_owned(), "policy.push".to_owned()],
        selector: Selector::parse("plane/control/zone/billing/*").expect("a selector"),
        resource_types: vec!["*".to_owned()],
        constraints: std::collections::BTreeMap::from([("note".to_owned(), "billing".to_owned())]),
        revision: 3,
        status: Status::Active,
        issued_by: "cert:sha256:ab".to_owned(),
        issued_at: 1_759_000_000,
        expires_at: Some(1_790_000_000),
        operation_id: Some(OperationId::from_bytes(ZONE_ID)),
    };
    let mut open_ended = record.clone();
    open_ended.expires_at = None;
    open_ended.operation_id = None;
    open_ended.constraints.clear();
    let decoder = || -> Option<Decoder> {
        Some(Box::new(|bytes: &[u8]| verdict(GrantRecord::decode(bytes))))
    };
    vec![
        sample(
            "grant_record",
            record.encode().expect("the record encodes"),
            &["grant_record.expires_at", "grant_record.operation_id"],
            decoder(),
        ),
        sample(
            "grant_record",
            open_ended.encode().expect("the record encodes"),
            &[],
            decoder(),
        ),
        sample(
            "transition",
            Transition {
                grant_id: GrantId::from_bytes(HOST_ID),
                revision: 4,
                at: 1_759_000_100,
                by: "cert:sha256:ab".to_owned(),
                operation_id: None,
            }
            .encode()
            .expect("the transition encodes"),
            &[],
            Some(Box::new(|bytes: &[u8]| verdict(Transition::decode(bytes)))),
        ),
        sample(
            "transition",
            Transition {
                grant_id: GrantId::from_bytes(HOST_ID),
                revision: 5,
                at: 1_759_000_200,
                by: "expiry".to_owned(),
                operation_id: Some(OperationId::from_bytes(ZONE_ID)),
            }
            .encode()
            .expect("the transition encodes"),
            &["transition.operation_id"],
            Some(Box::new(|bytes: &[u8]| verdict(Transition::decode(bytes)))),
        ),
    ]
}

fn identity_samples() -> Vec<Sample> {
    use permguard_host::identity::record::{Boot, Document, Init, Succession, zero_digest};
    use permguard_objects::crypto::suite::Suite;

    let host_id = HOST_ID;
    let first = Document {
        host_id,
        subject: permguard_host::identity::record::subject(&host_id),
        epoch: 1,
        suite: Suite::Ed25519Sha256V1,
        public_key: vec![7; 32],
        fingerprint: format!("sha256:{}", "ab".repeat(32)),
        last_succession: None,
        protocols: vec!["permguard.host.session.v1".to_owned()],
        revision: 1,
        issued_at: 1_800_000_000,
    };
    let later = Document {
        epoch: 2,
        last_succession: Some(zero_digest()),
        revision: 2,
        ..first.clone()
    };
    let documents =
        || -> Option<Decoder> { Some(Box::new(|bytes: &[u8]| verdict(Document::decode(bytes)))) };
    vec![
        sample(
            "identity_document",
            first.encode().expect("encodes"),
            &[],
            documents(),
        ),
        sample(
            "identity_document",
            later.encode().expect("encodes"),
            &["identity_document.last_succession"],
            documents(),
        ),
        sample(
            "succession_record",
            Succession {
                host_id,
                from_epoch: 1,
                to_epoch: 2,
                fingerprint: format!("sha256:{}", "cd".repeat(32)),
                public_key: vec![8; 32],
                previous: zero_digest(),
                at: 1_800_000_100,
            }
            .encode()
            .expect("encodes"),
            &[],
            Some(Box::new(|bytes: &[u8]| verdict(Succession::decode(bytes)))),
        ),
        sample(
            "init",
            Init {
                host_id,
                volume_id: ZONE_ID,
                fingerprint: format!("sha256:{}", "ab".repeat(32)),
                created_at: 1_800_000_000,
            }
            .encode()
            .expect("encodes"),
            &[],
            Some(Box::new(|bytes: &[u8]| verdict(Init::decode(bytes)))),
        ),
        sample(
            "boot",
            Boot {
                boot_id: ZONE_ID,
                generation: 3,
            }
            .encode()
            .expect("encodes"),
            &[],
            Some(Box::new(|bytes: &[u8]| verdict(Boot::decode(bytes)))),
        ),
    ]
}

fn mutation_samples() -> Vec<Sample> {
    use permguard_host::operations::journal::{
        Commit, Entry, Initiator, Intent, OperationId, RequestKey, decode_snapshot, encode_snapshot,
    };

    let id = OperationId::from_bytes(ZONE_ID);
    let intent = Entry::Intent(Intent {
        operation_id: id,
        at: 1_800_000_000,
        domain: "grants".to_owned(),
        operation: "grants.revoke.run".to_owned(),
        action: "host.grant.revoked".to_owned(),
        initiator: Initiator::Principal("spiffe://acme/operators/root".to_owned()),
        request: Some(RequestKey {
            request_id: "r-1".to_owned(),
            digest: "ab".repeat(32),
        }),
        target: Some("0198f4cc".repeat(4)),
    });
    let system = Entry::Intent(Intent {
        operation_id: id,
        at: 1_800_000_000,
        domain: "grants".to_owned(),
        operation: "grants.expire".to_owned(),
        action: "host.grant.expired".to_owned(),
        initiator: Initiator::System("expiry".to_owned()),
        request: None,
        target: None,
    });
    let commit = Entry::Commit(Commit {
        operation_id: id,
        at: 1_800_000_001,
        revision: 7,
        target: Some("0198f4cc".repeat(4)),
        result: Some(b"{\"revision\":7}".to_vec()),
        reconciled: false,
    });
    let reconciled = Entry::Commit(Commit {
        operation_id: id,
        at: 1_800_000_002,
        revision: 7,
        target: None,
        result: None,
        reconciled: true,
    });
    let failed = Entry::Failed {
        operation_id: id,
        at: 1_800_000_003,
        reason: "refused by the domain".to_owned(),
    };
    let projected = Entry::Projected {
        operation_id: id,
        at: 1_800_000_004,
    };
    let entries =
        || -> Option<Decoder> { Some(Box::new(|bytes: &[u8]| verdict(Entry::decode(bytes)))) };
    vec![
        sample(
            "mutation_intent",
            intent.encode().expect("encodes"),
            &[
                "mutation_intent.request_id",
                "mutation_intent.request_digest",
                "mutation_intent.target",
            ],
            entries(),
        ),
        sample(
            "mutation_intent",
            system.encode().expect("encodes"),
            &[],
            entries(),
        ),
        sample(
            "mutation_commit",
            commit.encode().expect("encodes"),
            &["mutation_commit.target", "mutation_commit.result"],
            entries(),
        ),
        sample(
            "mutation_commit",
            reconciled.encode().expect("encodes"),
            &[],
            entries(),
        ),
        sample(
            "mutation_failed",
            failed.encode().expect("encodes"),
            &[],
            entries(),
        ),
        sample(
            "mutation_projected",
            projected.encode().expect("encodes"),
            &[],
            entries(),
        ),
        sample(
            "mutation_snapshot",
            encode_snapshot(1_800_000_005, &[intent, commit, projected]).expect("encodes"),
            &[],
            Some(Box::new(|bytes: &[u8]| verdict(decode_snapshot(bytes)))),
        ),
    ]
}

fn sealed_key_samples() -> Vec<Sample> {
    let nonce = [9u8; seal::NONCE_LEN];
    let kid = thumbprint::kid("host.identity", THUMBPRINT_A);
    let binding = Binding {
        host_id: &HOST_ID,
        ring: "host.identity",
        kid: &kid,
        suite: Suite::Ed25519Sha256V1,
    };
    let sealed = SealedKey {
        kek_ref: "file:/etc/permguard/kek".into(),
        kek_version: 3,
        wrap_algorithm: LocalKeyWrap::ALGORITHM.into(),
        wrapped_dek: vec![7; seal::NONCE_LEN + seal::DEK_LEN + seal::TAG_LEN],
        content_algorithm: seal::CONTENT_ALGORITHM.into(),
        unique_nonce: nonce,
        ciphertext: vec![5; 83 + seal::TAG_LEN],
    }
    .encode()
    .expect("the sealed key encodes");
    let content = binding
        .content_context(seal::CONTENT_ALGORITHM, &nonce)
        .expect("the content context encodes");
    let wrap = binding
        .wrap_context(
            "file:/etc/permguard/kek",
            3,
            LocalKeyWrap::ALGORITHM,
            seal::CONTENT_ALGORITHM,
            &nonce,
        )
        .expect("the wrap context encodes");
    vec![
        sample(
            "sealed_key",
            sealed,
            &[],
            Some(Box::new(|bytes: &[u8]| verdict(SealedKey::decode(bytes)))),
        ),
        // The contexts are associated data, recomputed by both sides and never decoded.
        sample("content_context", content, &[], None),
        sample("wrap_context", wrap, &[], None),
    ]
}

fn key_set_samples() -> Vec<Sample> {
    let set = KeySet::new(
        "control.attest",
        7,
        Suite::Ed25519Sha256V1,
        &[THUMBPRINT_A, THUMBPRINT_B],
    )
    .expect("a valid set")
    .encode()
    .expect("the set encodes");
    vec![sample(
        "key_set",
        set,
        &[],
        Some(Box::new(|bytes: &[u8]| verdict(KeySet::decode(bytes)))),
    )]
}

fn kdf_samples() -> Vec<Sample> {
    let decoder =
        || -> Option<Decoder> { Some(Box::new(|bytes: &[u8]| verdict(kdf::Info::decode(bytes)))) };
    vec![
        sample(
            "host_local_info",
            kdf::host_local_info("audit.pseudonym", &HOST_ID, "zones/acme", 2)
                .expect("the tuple encodes"),
            &[],
            decoder(),
        ),
        sample(
            "zone_root_info",
            kdf::zone_root_info(&ZONE_ID, 1).expect("the tuple encodes"),
            &[],
            decoder(),
        ),
        sample(
            "zone_use_info",
            kdf::zone_use_info("decisions.mac", &ZONE_ID, &SCOPE_ID, 1).expect("the tuple encodes"),
            &[],
            decoder(),
        ),
    ]
}

fn notp_samples() -> Vec<Sample> {
    let statement = signed_head(&ed25519());
    let head = Digest::compute(b"head");
    let old = Digest::compute(b"old");
    let object = Blob {
        media_type: "application/vnd.permguard.policy.cedar".into(),
        data: b"permit(principal, action, resource);".to_vec(),
    }
    .encode()
    .expect("the blob encodes");
    let missing = vec![Digest::compute(&object), Digest::compute(b"tree")];
    let commit_response = CommitPushResponse {
        head: head.clone(),
        counter: 2,
        statement: statement.clone(),
    }
    .encode()
    .expect("it encodes");
    vec![
        // The `GET ref` answer has no public encoder: the control plane writes it inline with the
        // labels of the commit answer, so those bytes are its sample. The client reads it with a
        // private, closed decoder, so no refusal is asserted here.
        sample("ref_answer", commit_response.clone(), &[], None),
        sample(
            "negotiate_push_request",
            NegotiatePushRequest {
                r#ref: "main".into(),
                new_head: head.clone(),
                expected_old: Some(old.clone()),
                closure: vec![
                    ObjectClaim {
                        digest: Digest::compute(&object),
                        size: object.len() as u64,
                    },
                    ObjectClaim {
                        digest: Digest::compute(b"tree"),
                        size: 120,
                    },
                ],
            }
            .encode()
            .expect("it encodes"),
            &["negotiate_push_request.expected_old"],
            Some(Box::new(|bytes: &[u8]| {
                verdict(NegotiatePushRequest::decode(bytes))
            })),
        ),
        sample(
            "negotiate_push_request",
            NegotiatePushRequest {
                r#ref: "main".into(),
                new_head: head.clone(),
                expected_old: None,
                closure: Vec::new(),
            }
            .encode()
            .expect("it encodes"),
            &[],
            Some(Box::new(|bytes: &[u8]| {
                verdict(NegotiatePushRequest::decode(bytes))
            })),
        ),
        sample(
            "negotiate_push_response",
            NegotiatePushResponse {
                missing: missing.clone(),
                max_batch_bytes: 8 << 20,
                max_batch_objects: 512,
                compression: Some("deflate".into()),
            }
            .encode()
            .expect("it encodes"),
            &["negotiate_push_response.compression"],
            Some(Box::new(|bytes: &[u8]| {
                verdict(NegotiatePushResponse::decode(bytes))
            })),
        ),
        sample(
            "negotiate_push_response",
            NegotiatePushResponse {
                missing: Vec::new(),
                max_batch_bytes: 8 << 20,
                max_batch_objects: 512,
                compression: None,
            }
            .encode()
            .expect("it encodes"),
            &[],
            Some(Box::new(|bytes: &[u8]| {
                verdict(NegotiatePushResponse::decode(bytes))
            })),
        ),
        sample(
            "upload_objects_request",
            UploadObjectsRequest {
                objects: vec![object.clone()],
                compression: Some("deflate".into()),
            }
            .encode()
            .expect("it encodes"),
            &["upload_objects_request.compression"],
            Some(Box::new(|bytes: &[u8]| {
                verdict(UploadObjectsRequest::decode(bytes))
            })),
        ),
        sample(
            "upload_objects_request",
            UploadObjectsRequest {
                objects: vec![object.clone()],
                compression: None,
            }
            .encode()
            .expect("it encodes"),
            &[],
            Some(Box::new(|bytes: &[u8]| {
                verdict(UploadObjectsRequest::decode(bytes))
            })),
        ),
        sample(
            "upload_objects_response",
            UploadObjectsResponse {
                received: missing.clone(),
            }
            .encode()
            .expect("it encodes"),
            &[],
            Some(Box::new(|bytes: &[u8]| {
                verdict(UploadObjectsResponse::decode(bytes))
            })),
        ),
        sample(
            "commit_push_request",
            CommitPushRequest {
                r#ref: "main".into(),
                new_head: head.clone(),
                expected_old: Some(old.clone()),
            }
            .encode()
            .expect("it encodes"),
            &["commit_push_request.expected_old"],
            Some(Box::new(|bytes: &[u8]| {
                verdict(CommitPushRequest::decode(bytes))
            })),
        ),
        sample(
            "commit_push_request",
            CommitPushRequest {
                r#ref: "main".into(),
                new_head: head.clone(),
                expected_old: None,
            }
            .encode()
            .expect("it encodes"),
            &[],
            Some(Box::new(|bytes: &[u8]| {
                verdict(CommitPushRequest::decode(bytes))
            })),
        ),
        sample(
            "commit_push_response",
            commit_response,
            &[],
            Some(Box::new(|bytes: &[u8]| {
                verdict(CommitPushResponse::decode(bytes))
            })),
        ),
        sample(
            "negotiate_pull_request",
            NegotiatePullRequest {
                r#ref: "main".into(),
                at: Some(head.clone()),
                have: vec![old.clone()],
            }
            .encode()
            .expect("it encodes"),
            &["negotiate_pull_request.at"],
            Some(Box::new(|bytes: &[u8]| {
                verdict(NegotiatePullRequest::decode(bytes))
            })),
        ),
        sample(
            "negotiate_pull_request",
            NegotiatePullRequest {
                r#ref: "main".into(),
                at: None,
                have: Vec::new(),
            }
            .encode()
            .expect("it encodes"),
            &[],
            Some(Box::new(|bytes: &[u8]| {
                verdict(NegotiatePullRequest::decode(bytes))
            })),
        ),
        sample(
            "negotiate_pull_response",
            NegotiatePullResponse {
                head: head.clone(),
                counter: 2,
                statement: statement.clone(),
                missing: missing.clone(),
                max_batch_bytes: 8 << 20,
                max_batch_objects: 512,
                compression: Some("deflate".into()),
            }
            .encode()
            .expect("it encodes"),
            &["negotiate_pull_response.compression"],
            Some(Box::new(|bytes: &[u8]| {
                verdict(NegotiatePullResponse::decode(bytes))
            })),
        ),
        sample(
            "negotiate_pull_response",
            NegotiatePullResponse {
                head,
                counter: 2,
                statement,
                missing: Vec::new(),
                max_batch_bytes: 8 << 20,
                max_batch_objects: 512,
                compression: None,
            }
            .encode()
            .expect("it encodes"),
            &[],
            Some(Box::new(|bytes: &[u8]| {
                verdict(NegotiatePullResponse::decode(bytes))
            })),
        ),
        sample(
            "fetch_objects_request",
            FetchObjectsRequest {
                digests: missing.clone(),
                accept_compression: Some("deflate".into()),
            }
            .encode()
            .expect("it encodes"),
            &["fetch_objects_request.accept_compression"],
            Some(Box::new(|bytes: &[u8]| {
                verdict(FetchObjectsRequest::decode(bytes))
            })),
        ),
        sample(
            "fetch_objects_request",
            FetchObjectsRequest {
                digests: missing,
                accept_compression: None,
            }
            .encode()
            .expect("it encodes"),
            &[],
            Some(Box::new(|bytes: &[u8]| {
                verdict(FetchObjectsRequest::decode(bytes))
            })),
        ),
        sample(
            "fetch_objects_response",
            FetchObjectsResponse {
                objects: vec![object.clone()],
                compression: Some("deflate".into()),
            }
            .encode()
            .expect("it encodes"),
            &["fetch_objects_response.compression"],
            Some(Box::new(|bytes: &[u8]| {
                verdict(FetchObjectsResponse::decode(bytes))
            })),
        ),
        sample(
            "fetch_objects_response",
            FetchObjectsResponse {
                objects: vec![object],
                compression: None,
            }
            .encode()
            .expect("it encodes"),
            &[],
            Some(Box::new(|bytes: &[u8]| {
                verdict(FetchObjectsResponse::decode(bytes))
            })),
        ),
    ]
}

fn samples(file: &str) -> Vec<Sample> {
    match file {
        "head-statement.json" => head_statement_samples(),
        "kdf.json" => kdf_samples(),
        "key-set.json" => key_set_samples(),
        "manifest.json" => manifest_samples(),
        "notp.json" => notp_samples(),
        "objects.json" => objects_samples(),
        "sealed-key.json" => sealed_key_samples(),
        "grant.json" => grant_samples(),
        "layout.json" => layout_samples(),
        "audit.json" => audit_samples(),
        "mutation.json" => mutation_samples(),
        "identity.json" => identity_samples(),
        other => panic!("{other} has no samples: wire it into `samples`"),
    }
}

fn audit_samples() -> Vec<Sample> {
    use permguard_host::audit::record::{AuditRecord, FactValue, TrailMeta, genesis};
    use permguard_objects::digest::Digest;

    let full = AuditRecord {
        trail: "security:host".to_owned(),
        seq: 4,
        operation_id: Some([7; 16]),
        phase: Some("applied".to_owned()),
        host_id: HOST_ID,
        boot_id: ZONE_ID,
        component: "host".to_owned(),
        action: "host.grant.issued".to_owned(),
        principal: "v1:2dbdd0064034d27f36f3e44f4e8466b2".to_owned(),
        resource: "host".to_owned(),
        target: Some("grant/0198f4cc".to_owned()),
        outcome: "ok".to_owned(),
        facts: std::collections::BTreeMap::from([
            ("count".to_owned(), FactValue::Uint(3)),
            ("forced".to_owned(), FactValue::Bool(false)),
            ("reason".to_owned(), FactValue::Text("quota".to_owned())),
        ]),
        build: "9.9.9".to_owned(),
        config_revision: Digest::compute(b"settings"),
        at: 1_800_000_000,
        monotonic_offset: 1_500,
        previous: genesis(),
    };
    let simple = AuditRecord {
        operation_id: None,
        phase: None,
        target: None,
        facts: std::collections::BTreeMap::new(),
        ..full.clone()
    };
    let records = || -> Option<Decoder> {
        Some(Box::new(|bytes: &[u8]| verdict(AuditRecord::decode(bytes))))
    };
    vec![
        sample(
            "audit_record",
            full.encode().expect("encodes"),
            &[
                "audit_record.operation_id",
                "audit_record.phase",
                "audit_record.target",
            ],
            records(),
        ),
        sample(
            "audit_record",
            simple.encode().expect("encodes"),
            &[],
            records(),
        ),
        sample(
            "trail_meta",
            TrailMeta {
                class: "security".to_owned(),
                resource: "plane/control/zone/z1".to_owned(),
            }
            .encode()
            .expect("encodes"),
            &[],
            Some(Box::new(|bytes: &[u8]| verdict(TrailMeta::decode(bytes)))),
        ),
    ]
}

fn layout_samples() -> Vec<Sample> {
    use permguard_host::storage::migrate::{
        Generation, LayoutManifest, MigrationCommit, MigrationIntent,
    };
    use permguard_objects::digest::Digest;

    let old = Generation {
        version: 1,
        generation: 1,
        directory: "data/notes/g1".to_owned(),
    };
    let new = Generation {
        version: 2,
        generation: 2,
        directory: "data/notes/g2".to_owned(),
    };
    let old_digests = std::collections::BTreeMap::from([
        ("alpha".to_owned(), Digest::compute(b"first note")),
        ("beta".to_owned(), Digest::compute(b"second note")),
    ]);
    let new_digests = std::collections::BTreeMap::from([
        ("a/alpha".to_owned(), Digest::compute(b"first note")),
        ("b/beta".to_owned(), Digest::compute(b"second note")),
        ("INDEX".to_owned(), Digest::compute(b"alpha\nbeta\n")),
    ]);
    let committed = LayoutManifest {
        subsystem: "notes".to_owned(),
        active: new.clone(),
        previous: Some(old.clone()),
        switched_at: 1_800_000_000,
    };
    let finalized = LayoutManifest {
        previous: None,
        ..committed.clone()
    };
    let intent = MigrationIntent {
        subsystem: "notes".to_owned(),
        from: old.clone(),
        to: new.clone(),
        old_digests: old_digests.clone(),
        backup: Some("s3://backups/notes/2026-10-07".to_owned()),
        at: 1_800_000_000,
    };
    let mut no_backup = intent.clone();
    no_backup.backup = None;
    let commit = MigrationCommit {
        subsystem: "notes".to_owned(),
        from: old,
        to: new,
        old_digests,
        new_digests,
        backup: Some("s3://backups/notes/2026-10-07".to_owned()),
        committed_at: 1_800_000_000,
    };
    let mut commit_no_backup = commit.clone();
    commit_no_backup.backup = None;
    let manifests = || -> Option<Decoder> {
        Some(Box::new(|bytes: &[u8]| {
            verdict(LayoutManifest::decode(bytes))
        }))
    };
    let intents = || -> Option<Decoder> {
        Some(Box::new(|bytes: &[u8]| {
            verdict(MigrationIntent::decode(bytes))
        }))
    };
    let commits = || -> Option<Decoder> {
        Some(Box::new(|bytes: &[u8]| {
            verdict(MigrationCommit::decode(bytes))
        }))
    };
    vec![
        sample(
            "layout_manifest",
            committed.encode().expect("encodes"),
            &["layout_manifest.previous"],
            manifests(),
        ),
        sample(
            "layout_manifest",
            finalized.encode().expect("encodes"),
            &[],
            manifests(),
        ),
        sample(
            "migration_intent",
            intent.encode().expect("encodes"),
            &["migration_intent.backup"],
            intents(),
        ),
        sample(
            "migration_intent",
            no_backup.encode().expect("encodes"),
            &[],
            intents(),
        ),
        sample(
            "migration_commit",
            commit.encode().expect("encodes"),
            &["migration_commit.backup"],
            commits(),
        ),
        sample(
            "migration_commit",
            commit_no_backup.encode().expect("encodes"),
            &[],
            commits(),
        ),
    ]
}

// ---------------------------------------------------------------------------------------------
// The checks.

/// Every sample of `file` decodes to exactly the registered labels and types, every map and tuple
/// of the registry is exercised, and every optional field is seen both set and left out.
fn assert_samples_match(file: &str) {
    let registry = registry(file);
    let roots = roots(&registry);
    let mut walk = Walk::new(file, &registry);
    for sample in samples(file) {
        assert!(
            roots.contains(&sample.root),
            "{file}: `{}` is not a root",
            sample.root
        );
        let value = cbor::decode_canonical(&sample.bytes)
            .unwrap_or_else(|error| panic!("{file}: `{}` is not canonical: {error}", sample.root));
        walk.sample_optional.clear();
        walk.check(&root_type(&registry, sample.root), &value, sample.root);
        let expected: BTreeSet<String> = sample.optional.iter().map(|&id| id.to_owned()).collect();
        assert_eq!(
            walk.sample_optional, expected,
            "{file}: `{}` sets exactly the optional fields it was built with",
            sample.root
        );
    }

    let registered_maps: BTreeSet<String> = registry["maps"]
        .as_object()
        .expect("`maps` is an object")
        .keys()
        .cloned()
        .collect();
    let registered_arrays: BTreeSet<String> = registry["arrays"]
        .as_object()
        .expect("`arrays` is an object")
        .keys()
        .cloned()
        .collect();
    assert_eq!(walk.maps, registered_maps, "{file}: every map is exercised");
    assert_eq!(
        walk.arrays, registered_arrays,
        "{file}: every tuple is exercised"
    );
    let optional: BTreeSet<String> = registry["maps"]
        .as_object()
        .expect("`maps` is an object")
        .iter()
        .flat_map(|(name, map)| {
            fields(map)
                .iter()
                .filter(|field| field["occurs"] == "optional")
                .map(move |field| format!("{name}.{}", text_of(field, "name")))
        })
        .collect();
    assert_eq!(
        walk.present, optional,
        "{file}: every optional field is set by some sample"
    );
    assert_eq!(
        walk.absent, optional,
        "{file}: every optional field is left out by some sample"
    );
}

/// Every closed map of every sample with a public decoder, given one unknown label, is refused;
/// so is every tuple given one trailing element.
fn assert_unknown_labels_refused(file: &str) {
    let registry = registry(file);
    let mut accepted = Vec::new();
    let mut misattributed = Vec::new();
    let mut checked = 0usize;
    for sample in samples(file) {
        let Some(decoder) = &sample.decoder else {
            continue;
        };
        if let Err(error) = decoder(&sample.bytes) {
            panic!(
                "{file}: the unaltered `{}` must decode first: {error}",
                sample.root
            );
        }
        let value = cbor::decode_canonical(&sample.bytes).expect("a sample is canonical");
        for (path, mutated) in mutations(
            &registry,
            &root_type(&registry, sample.root),
            &value,
            sample.root,
        ) {
            let bytes = cbor::encode(&mutated).expect("a mutated value encodes");
            checked += 1;
            match decoder(&bytes) {
                Ok(()) => accepted.push(path),
                // The mutation is re-encoded canonically and a signed envelope is re-signed, so a
                // refusal for canonicality or a signature would be a refusal for the wrong reason:
                // the test would pass without the decoder ever looking at the label.
                Err(error) => {
                    let lowered = error.to_lowercase();
                    if lowered.contains("canonical") || lowered.contains("signature") {
                        misattributed.push(format!("{path}: {error}"));
                    }
                }
            }
        }
    }
    assert!(checked > 0, "{file}: no negative vector was checked");
    assert!(
        misattributed.is_empty(),
        "{file}: refused for another reason than the unknown label: {misattributed:#?}"
    );
    assert!(
        accepted.is_empty(),
        "{file}: the decoder accepted an unknown label at: {accepted:#?}"
    );
}

#[test]
fn test_every_registry_file_is_wired_into_this_test() {
    let directory = permguard_conformance::contracts::root().join("cbor");
    let on_disk: BTreeSet<String> = std::fs::read_dir(&directory)
        .unwrap_or_else(|error| panic!("{}: {error}", directory.display()))
        .map(|entry| {
            entry
                .expect("a directory entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .filter(|name| name.ends_with(".json"))
        .collect();
    let wired: BTreeSet<String> = REGISTRIES.iter().map(|&name| name.to_owned()).collect();
    assert_eq!(
        on_disk, wired,
        "every registry under contracts/cbor/ is listed in REGISTRIES"
    );
}

/// The registry's own shape: known members, the one encoding, unique labels of the declared key
/// type, consecutive tuple positions, types that resolve, and nothing unreachable from a root.
#[test]
fn test_every_registry_is_well_formed() {
    for file in REGISTRIES {
        let registry = registry(file);
        let members: BTreeSet<&str> = registry
            .as_object()
            .expect("a registry is an object")
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            members,
            BTreeSet::from([
                "artifact",
                "authority",
                "encoding",
                "maps",
                "arrays",
                "root"
            ]),
            "{file}: exactly the registry members"
        );
        assert!(!text_of(&registry, "artifact").is_empty(), "{file}");
        assert!(!text_of(&registry, "authority").is_empty(), "{file}");
        assert_eq!(text_of(&registry, "encoding"), ENCODING, "{file}");

        let maps = registry["maps"].as_object().expect("`maps` is an object");
        let arrays = registry["arrays"]
            .as_object()
            .expect("`arrays` is an object");
        let mut types = Vec::new();
        for (name, map) in maps {
            let keys = text_of(map, "keys");
            assert!(
                keys == "int" || keys == "text",
                "{file}: `{name}` keys are int or text"
            );
            let mut labels = BTreeSet::new();
            let mut names = BTreeSet::new();
            for field in fields(map) {
                let field_members: BTreeSet<&str> = field
                    .as_object()
                    .expect("a field is an object")
                    .keys()
                    .map(String::as_str)
                    .collect();
                assert!(
                    field_members.is_subset(&BTreeSet::from([
                        "label",
                        "name",
                        "type",
                        "occurs",
                        "note",
                        "grpc_field",
                        "grpc_note",
                    ])) && ["label", "name", "type", "occurs"]
                        .iter()
                        .all(|member| field_members.contains(member)),
                    "{file}: `{name}` field members: {field}"
                );
                let label = &field["label"];
                match keys {
                    "int" => assert!(
                        label.as_i64().is_some_and(|label| label != UNKNOWN_INT),
                        "{file}: `{name}` labels are integers other than {UNKNOWN_INT}"
                    ),
                    _ => assert!(
                        label.as_str().is_some_and(|label| label != UNKNOWN_TEXT),
                        "{file}: `{name}` labels are text other than `{UNKNOWN_TEXT}`"
                    ),
                }
                assert!(
                    labels.insert(label.to_string()),
                    "{file}: `{name}` repeats {label}"
                );
                assert!(
                    names.insert(text_of(field, "name")),
                    "{file}: `{name}` repeats a field name"
                );
                assert!(
                    matches!(text_of(field, "occurs"), "required" | "optional"),
                    "{file}: `{name}` occurs is required or optional"
                );
                types.push(text_of(field, "type").to_owned());
            }
        }
        for (name, positions) in arrays {
            let positions = positions.as_array().expect("a tuple is an array");
            assert!(!positions.is_empty(), "{file}: `{name}` has positions");
            for (index, position) in positions.iter().enumerate() {
                assert_eq!(
                    position["position"].as_u64(),
                    Some(index as u64),
                    "{file}: `{name}` positions are consecutive from 0"
                );
                types.push(text_of(position, "type").to_owned());
            }
        }

        // Every type resolves, and every map and tuple is reached from a root.
        let mut reached = BTreeSet::new();
        let mut pending: Vec<String> = roots(&registry)
            .into_iter()
            .map(|root| root_type(&registry, root))
            .collect();
        for ty in &types {
            assert_type_resolves(file, &registry, ty);
        }
        while let Some(ty) = pending.pop() {
            assert_type_resolves(file, &registry, &ty);
            let mut inner = ty.as_str();
            loop {
                if let Some(rest) = inner.strip_prefix("cbor:") {
                    inner = rest;
                } else if let Some(rest) = generic(inner, "array<") {
                    inner = rest;
                } else if let Some(rest) = generic(inner, "map<text,") {
                    inner = rest;
                } else {
                    break;
                }
            }
            if let Some(name) = inner.strip_prefix("map:")
                && reached.insert(format!("map:{name}"))
            {
                pending.extend(
                    fields(&maps[name])
                        .iter()
                        .map(|f| text_of(f, "type").to_owned()),
                );
            } else if let Some(name) = inner.strip_prefix("array:")
                && reached.insert(format!("array:{name}"))
            {
                pending.extend(
                    arrays[name]
                        .as_array()
                        .expect("a tuple")
                        .iter()
                        .map(|p| text_of(p, "type").to_owned()),
                );
            }
        }
        let registered: BTreeSet<String> = maps
            .keys()
            .map(|name| format!("map:{name}"))
            .chain(arrays.keys().map(|name| format!("array:{name}")))
            .collect();
        assert_eq!(
            reached, registered,
            "{file}: every map and tuple is reached from a root"
        );
    }
}

fn assert_type_resolves(file: &str, registry: &Json, ty: &str) {
    match ty {
        "uint" | "int" | "text" | "bytes" | "bool" | "digest" | "scalar" => {}
        _ => {
            if let Some(constant) = ty.strip_prefix("const:") {
                let constant: Json = serde_json::from_str(constant)
                    .unwrap_or_else(|_| panic!("{file}: `{ty}` is not a JSON constant"));
                assert!(
                    constant.is_string() || constant.is_i64() || constant.is_boolean(),
                    "{file}: `{ty}` is a text, integer or boolean constant"
                );
            } else if let Some(name) = ty.strip_prefix("map:") {
                assert!(
                    registry["maps"].get(name).is_some(),
                    "{file}: `{ty}` names no map"
                );
            } else if let Some(name) = ty.strip_prefix("array:") {
                assert!(
                    registry["arrays"].get(name).is_some(),
                    "{file}: `{ty}` names no tuple"
                );
            } else if let Some(inner) = ty
                .strip_prefix("cbor:")
                .or_else(|| generic(ty, "array<"))
                .or_else(|| generic(ty, "map<text,"))
            {
                assert_type_resolves(file, registry, inner);
            } else {
                panic!("{file}: `{ty}` is not a registry type");
            }
        }
    }
}

#[test]
fn test_identity_records_match_their_registry() {
    assert_samples_match("identity.json");
}

#[test]
fn test_identity_records_refuse_unknown_labels() {
    assert_unknown_labels_refused("identity.json");
}

#[test]
fn test_mutation_entries_match_their_registry() {
    assert_samples_match("mutation.json");
}

#[test]
fn test_mutation_entries_refuse_unknown_labels() {
    assert_unknown_labels_refused("mutation.json");
}

#[test]
fn test_audit_records_match_their_registry() {
    assert_samples_match("audit.json");
}

#[test]
fn test_audit_records_refuse_unknown_labels() {
    assert_unknown_labels_refused("audit.json");
}

#[test]
fn test_layout_records_match_their_registry() {
    assert_samples_match("layout.json");
}

#[test]
fn test_layout_records_refuse_unknown_labels() {
    assert_unknown_labels_refused("layout.json");
}

#[test]
fn test_grant_record_matches_its_registry() {
    assert_samples_match("grant.json");
}

#[test]
fn test_grant_record_refuses_unknown_labels() {
    assert_unknown_labels_refused("grant.json");
}

#[test]
fn test_head_statement_matches_its_registry() {
    assert_samples_match("head-statement.json");
}

#[test]
fn test_head_statement_refuses_unknown_labels() {
    assert_unknown_labels_refused("head-statement.json");
}

#[test]
fn test_kdf_tuples_match_their_registry() {
    assert_samples_match("kdf.json");
}

#[test]
fn test_kdf_tuples_refuse_a_trailing_element() {
    assert_unknown_labels_refused("kdf.json");
}

#[test]
fn test_key_set_matches_its_registry() {
    assert_samples_match("key-set.json");
}

#[test]
fn test_key_set_refuses_unknown_labels() {
    assert_unknown_labels_refused("key-set.json");
}

#[test]
fn test_manifest_matches_its_registry() {
    assert_samples_match("manifest.json");
}

#[test]
fn test_manifest_refuses_unknown_labels() {
    assert_unknown_labels_refused("manifest.json");
}

#[test]
fn test_notp_messages_match_their_registry() {
    assert_samples_match("notp.json");
}

#[test]
fn test_notp_messages_refuse_unknown_labels() {
    assert_unknown_labels_refused("notp.json");
}

#[test]
fn test_objects_match_their_registry() {
    assert_samples_match("objects.json");
}

#[test]
fn test_objects_refuse_unknown_labels() {
    assert_unknown_labels_refused("objects.json");
}

#[test]
fn test_sealed_key_matches_its_registry() {
    assert_samples_match("sealed-key.json");
}

#[test]
fn test_sealed_key_refuses_unknown_labels() {
    assert_unknown_labels_refused("sealed-key.json");
}
