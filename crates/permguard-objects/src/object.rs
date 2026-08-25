// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The three structural objects — blob, tree, commit — with their canonical
//! encodings, strict decodings, and structural validation. Everything the
//! domain defines is a blob with a media type; the structural layer never
//! interprets content.

use std::collections::BTreeMap;
use std::fmt;

use crate::cbor::{self, CborError, Value};
use crate::digest::{Digest, DigestError};
use crate::grammar::{self, GrammarError};
use crate::limits;

/// The structural kind of an object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Blob = 1,
    Tree = 2,
    Commit = 3,
}

impl Kind {
    fn from_i64(n: i64) -> Result<Self, ObjectError> {
        match n {
            1 => Ok(Kind::Blob),
            2 => Ok(Kind::Tree),
            3 => Ok(Kind::Commit),
            _ => Err(ObjectError::Schema("unknown kind")),
        }
    }
}

/// A blob: opaque authored bytes plus what they are.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Blob {
    pub media_type: String,
    pub data: Vec<u8>,
}

/// One entry of a tree: the role of an object at a place.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeEntry {
    pub kind: Kind,
    pub digest: Digest,
    pub name: String,
    /// Sorted by construction; string values only.
    pub annotations: BTreeMap<String, String>,
}

/// A tree: entries sorted by name, unique names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tree {
    pub entries: Vec<TreeEntry>,
}

/// A commit: only client-determined fields, per the specification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commit {
    pub tree: Digest,
    pub manifest: Digest,
    pub predecessors: Vec<Digest>,
    pub author: String,
    pub author_at: i64,
    pub message: String,
}

/// Any decoded object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Object {
    Blob(Blob),
    Tree(Tree),
    Commit(Commit),
}

impl Object {
    pub fn kind(&self) -> Kind {
        match self {
            Object::Blob(_) => Kind::Blob,
            Object::Tree(_) => Kind::Tree,
            Object::Commit(_) => Kind::Commit,
        }
    }
}

// CBOR integer keys, normative.
const KEY_KIND: i64 = 1;
const KEY_BLOB_MEDIA_TYPE: i64 = 2;
const KEY_BLOB_DATA: i64 = 3;
const KEY_TREE_ENTRIES: i64 = 2;
const KEY_ENTRY_KIND: i64 = 1;
const KEY_ENTRY_DIGEST: i64 = 2;
const KEY_ENTRY_NAME: i64 = 3;
const KEY_ENTRY_ANNOTATIONS: i64 = 4;
const KEY_COMMIT_TREE: i64 = 2;
const KEY_COMMIT_MANIFEST: i64 = 3;
const KEY_COMMIT_PREDECESSORS: i64 = 4;
const KEY_COMMIT_AUTHOR: i64 = 5;
const KEY_COMMIT_AUTHOR_AT: i64 = 6;
const KEY_COMMIT_MESSAGE: i64 = 7;

impl Blob {
    pub fn encode(&self) -> Result<Vec<u8>, ObjectError> {
        self.validate()?;
        let value = Value::Map(vec![
            (Value::Int(KEY_KIND), Value::Int(Kind::Blob as i64)),
            (
                Value::Int(KEY_BLOB_MEDIA_TYPE),
                Value::Text(self.media_type.clone()),
            ),
            (Value::Int(KEY_BLOB_DATA), Value::Bytes(self.data.clone())),
        ]);
        finish_encode(&value)
    }

    fn validate(&self) -> Result<(), ObjectError> {
        if self.media_type.is_empty() || self.media_type.len() > 255 {
            return Err(ObjectError::Schema("media_type length"));
        }
        Ok(())
    }
}

impl TreeEntry {
    fn to_value(&self) -> Value {
        let annotations = self
            .annotations
            .iter()
            .map(|(k, v)| (Value::Text(k.clone()), Value::Text(v.clone())))
            .collect();
        Value::Map(vec![
            (Value::Int(KEY_ENTRY_KIND), Value::Int(self.kind as i64)),
            (
                Value::Int(KEY_ENTRY_DIGEST),
                Value::Text(self.digest.to_string()),
            ),
            (Value::Int(KEY_ENTRY_NAME), Value::Text(self.name.clone())),
            (Value::Int(KEY_ENTRY_ANNOTATIONS), Value::Map(annotations)),
        ])
    }

    fn validate(&self) -> Result<(), ObjectError> {
        grammar::validate_entry_name(&self.name)?;
        if self.kind == Kind::Commit {
            return Err(ObjectError::Schema(
                "tree entry may reference a blob or a tree, never a commit",
            ));
        }
        if self.annotations.len() > limits::MAX_ANNOTATIONS_PER_ENTRY {
            return Err(ObjectError::Limit("annotations per entry"));
        }
        for (key, value) in &self.annotations {
            grammar::validate_annotation_key(key)?;
            if value.len() > limits::MAX_ANNOTATION_VALUE_BYTES {
                return Err(ObjectError::Limit("annotation value bytes"));
            }
        }
        Ok(())
    }
}

impl Tree {
    pub fn encode(&self) -> Result<Vec<u8>, ObjectError> {
        self.validate()?;
        let entries = self.entries.iter().map(TreeEntry::to_value).collect();
        let value = Value::Map(vec![
            (Value::Int(KEY_KIND), Value::Int(Kind::Tree as i64)),
            (Value::Int(KEY_TREE_ENTRIES), Value::Array(entries)),
        ]);
        finish_encode(&value)
    }

    fn validate(&self) -> Result<(), ObjectError> {
        if self.entries.len() > limits::MAX_TREE_ENTRIES {
            return Err(ObjectError::Limit("entries per tree"));
        }
        let mut previous: Option<&str> = None;
        for entry in &self.entries {
            entry.validate()?;
            if let Some(prev) = previous
                && prev >= entry.name.as_str()
            {
                return Err(ObjectError::Schema(
                    "entries must be sorted by name and unique",
                ));
            }
            previous = Some(&entry.name);
        }
        Ok(())
    }
}

impl Commit {
    pub fn encode(&self) -> Result<Vec<u8>, ObjectError> {
        self.validate()?;
        let predecessors = self
            .predecessors
            .iter()
            .map(|d| Value::Text(d.to_string()))
            .collect();
        let value = Value::Map(vec![
            (Value::Int(KEY_KIND), Value::Int(Kind::Commit as i64)),
            (
                Value::Int(KEY_COMMIT_TREE),
                Value::Text(self.tree.to_string()),
            ),
            (
                Value::Int(KEY_COMMIT_MANIFEST),
                Value::Text(self.manifest.to_string()),
            ),
            (
                Value::Int(KEY_COMMIT_PREDECESSORS),
                Value::Array(predecessors),
            ),
            (
                Value::Int(KEY_COMMIT_AUTHOR),
                Value::Text(self.author.clone()),
            ),
            (Value::Int(KEY_COMMIT_AUTHOR_AT), Value::Int(self.author_at)),
            (
                Value::Int(KEY_COMMIT_MESSAGE),
                Value::Text(self.message.clone()),
            ),
        ]);
        finish_encode(&value)
    }

    fn validate(&self) -> Result<(), ObjectError> {
        if self.predecessors.len() > limits::MAX_PREDECESSORS {
            return Err(ObjectError::Limit("predecessors"));
        }
        if self.predecessors.len() == 2 && self.predecessors[0] == self.predecessors[1] {
            return Err(ObjectError::Schema("duplicate predecessors"));
        }
        Ok(())
    }
}

fn finish_encode(value: &Value) -> Result<Vec<u8>, ObjectError> {
    let bytes = cbor::encode(value);
    if bytes.len() > limits::MAX_OBJECT_BYTES {
        return Err(ObjectError::Limit("object bytes"));
    }
    Ok(bytes)
}

/// Decode one object from its canonical bytes — the ingest path. Rejects
/// non-canonical encodings, unknown keys, wrong types, over-limit sizes,
/// and every grammar violation. The bytes hash to the object's identity.
pub fn decode(bytes: &[u8]) -> Result<Object, ObjectError> {
    if bytes.len() > limits::MAX_OBJECT_BYTES {
        return Err(ObjectError::Limit("object bytes"));
    }
    let value = cbor::decode_canonical(bytes)?;
    let map = as_map(&value)?;
    let kind = Kind::from_i64(get_int(map, KEY_KIND)?)?;
    let object = match kind {
        Kind::Blob => {
            expect_keys(map, &[KEY_KIND, KEY_BLOB_MEDIA_TYPE, KEY_BLOB_DATA])?;
            let blob = Blob {
                media_type: get_text(map, KEY_BLOB_MEDIA_TYPE)?,
                data: get_bytes(map, KEY_BLOB_DATA)?,
            };
            blob.validate()?;
            Object::Blob(blob)
        }
        Kind::Tree => {
            expect_keys(map, &[KEY_KIND, KEY_TREE_ENTRIES])?;
            let entries = get_array(map, KEY_TREE_ENTRIES)?
                .iter()
                .map(decode_entry)
                .collect::<Result<Vec<_>, _>>()?;
            let tree = Tree { entries };
            tree.validate()?;
            Object::Tree(tree)
        }
        Kind::Commit => {
            expect_keys(
                map,
                &[
                    KEY_KIND,
                    KEY_COMMIT_TREE,
                    KEY_COMMIT_MANIFEST,
                    KEY_COMMIT_PREDECESSORS,
                    KEY_COMMIT_AUTHOR,
                    KEY_COMMIT_AUTHOR_AT,
                    KEY_COMMIT_MESSAGE,
                ],
            )?;
            let predecessors = get_array(map, KEY_COMMIT_PREDECESSORS)?
                .iter()
                .map(|v| match v {
                    Value::Text(t) => Ok(Digest::parse(t)?),
                    _ => Err(ObjectError::Schema("predecessor must be a digest string")),
                })
                .collect::<Result<Vec<_>, ObjectError>>()?;
            let commit = Commit {
                tree: Digest::parse(&get_text(map, KEY_COMMIT_TREE)?)?,
                manifest: Digest::parse(&get_text(map, KEY_COMMIT_MANIFEST)?)?,
                predecessors,
                author: get_text(map, KEY_COMMIT_AUTHOR)?,
                author_at: get_int(map, KEY_COMMIT_AUTHOR_AT)?,
                message: get_text(map, KEY_COMMIT_MESSAGE)?,
            };
            commit.validate()?;
            Object::Commit(commit)
        }
    };
    Ok(object)
}

fn decode_entry(value: &Value) -> Result<TreeEntry, ObjectError> {
    let map = as_map(value)?;
    expect_keys(
        map,
        &[
            KEY_ENTRY_KIND,
            KEY_ENTRY_DIGEST,
            KEY_ENTRY_NAME,
            KEY_ENTRY_ANNOTATIONS,
        ],
    )?;
    let kind = Kind::from_i64(get_int(map, KEY_ENTRY_KIND)?)?;
    let annotations_value = map
        .iter()
        .find(|(k, _)| *k == Value::Int(KEY_ENTRY_ANNOTATIONS))
        .map(|(_, v)| v)
        .ok_or(ObjectError::Schema("missing annotations"))?;
    let Value::Map(pairs) = annotations_value else {
        return Err(ObjectError::Schema("annotations must be a map"));
    };
    let mut annotations = BTreeMap::new();
    for (k, v) in pairs {
        let (Value::Text(key), Value::Text(value)) = (k, v) else {
            return Err(ObjectError::Schema(
                "annotations must map strings to strings",
            ));
        };
        annotations.insert(key.clone(), value.clone());
    }
    let entry = TreeEntry {
        kind,
        digest: Digest::parse(&get_text(map, KEY_ENTRY_DIGEST)?)?,
        name: get_text(map, KEY_ENTRY_NAME)?,
        annotations,
    };
    entry.validate()?;
    Ok(entry)
}

fn as_map(value: &Value) -> Result<&[(Value, Value)], ObjectError> {
    match value {
        Value::Map(pairs) => Ok(pairs),
        _ => Err(ObjectError::Schema("object must be a map")),
    }
}

fn expect_keys(map: &[(Value, Value)], allowed: &[i64]) -> Result<(), ObjectError> {
    for (key, _) in map {
        match key {
            Value::Int(k) if allowed.contains(k) => {}
            _ => return Err(ObjectError::Schema("unknown key")),
        }
    }
    for required in allowed {
        if !map.iter().any(|(k, _)| *k == Value::Int(*required)) {
            return Err(ObjectError::Schema("missing key"));
        }
    }
    Ok(())
}

fn get_int(map: &[(Value, Value)], key: i64) -> Result<i64, ObjectError> {
    match lookup(map, key)? {
        Value::Int(n) => Ok(*n),
        _ => Err(ObjectError::Schema("expected integer")),
    }
}

fn get_text(map: &[(Value, Value)], key: i64) -> Result<String, ObjectError> {
    match lookup(map, key)? {
        Value::Text(t) => Ok(t.clone()),
        _ => Err(ObjectError::Schema("expected text")),
    }
}

fn get_bytes(map: &[(Value, Value)], key: i64) -> Result<Vec<u8>, ObjectError> {
    match lookup(map, key)? {
        Value::Bytes(b) => Ok(b.clone()),
        _ => Err(ObjectError::Schema("expected bytes")),
    }
}

fn get_array(map: &[(Value, Value)], key: i64) -> Result<&[Value], ObjectError> {
    match lookup(map, key)? {
        Value::Array(items) => Ok(items),
        _ => Err(ObjectError::Schema("expected array")),
    }
}

fn lookup(map: &[(Value, Value)], key: i64) -> Result<&Value, ObjectError> {
    map.iter()
        .find(|(k, _)| *k == Value::Int(key))
        .map(|(_, v)| v)
        .ok_or(ObjectError::Schema("missing key"))
}

/// Why an object was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjectError {
    Cbor(CborError),
    Digest(DigestError),
    Grammar(GrammarError),
    /// A structural rule of the object schema.
    Schema(&'static str),
    /// A limit of the model.
    Limit(&'static str),
}

impl fmt::Display for ObjectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ObjectError::Cbor(e) => write!(f, "encoding: {e}"),
            ObjectError::Digest(e) => write!(f, "digest: {e}"),
            ObjectError::Grammar(e) => write!(f, "grammar: {e}"),
            ObjectError::Schema(what) => write!(f, "schema: {what}"),
            ObjectError::Limit(what) => write!(f, "limit exceeded: {what}"),
        }
    }
}

impl std::error::Error for ObjectError {}

impl From<CborError> for ObjectError {
    fn from(e: CborError) -> Self {
        ObjectError::Cbor(e)
    }
}

impl From<DigestError> for ObjectError {
    fn from(e: DigestError) -> Self {
        ObjectError::Digest(e)
    }
}

impl From<GrammarError> for ObjectError {
    fn from(e: GrammarError) -> Self {
        ObjectError::Grammar(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_blob() -> Blob {
        Blob {
            media_type: "application/vnd.permguard.policy.cedar".into(),
            data: b"permit(principal, action, resource);".to_vec(),
        }
    }

    #[test]
    fn blob_round_trips_and_is_deterministic() {
        let blob = sample_blob();
        let bytes = blob.encode().unwrap();
        assert_eq!(bytes, blob.encode().unwrap());
        assert_eq!(decode(&bytes).unwrap(), Object::Blob(blob));
    }

    #[test]
    fn tree_round_trips_sorted() {
        let blob_digest = Digest::compute(b"x");
        let mut annotations = BTreeMap::new();
        annotations.insert("permguard.policy.id".to_string(), "abc".to_string());
        let tree = Tree {
            entries: vec![
                TreeEntry {
                    kind: Kind::Blob,
                    digest: blob_digest.clone(),
                    name: "a.cedar".into(),
                    annotations,
                },
                TreeEntry {
                    kind: Kind::Tree,
                    digest: blob_digest,
                    name: "sub".into(),
                    annotations: BTreeMap::new(),
                },
            ],
        };
        let bytes = tree.encode().unwrap();
        assert_eq!(decode(&bytes).unwrap(), Object::Tree(tree));
    }

    #[test]
    fn unsorted_tree_is_rejected() {
        let digest = Digest::compute(b"x");
        let tree = Tree {
            entries: vec![
                TreeEntry {
                    kind: Kind::Blob,
                    digest: digest.clone(),
                    name: "b".into(),
                    annotations: BTreeMap::new(),
                },
                TreeEntry {
                    kind: Kind::Blob,
                    digest,
                    name: "a".into(),
                    annotations: BTreeMap::new(),
                },
            ],
        };
        assert!(matches!(tree.encode(), Err(ObjectError::Schema(_))));
    }

    #[test]
    fn commit_round_trips() {
        let commit = Commit {
            tree: Digest::compute(b"tree"),
            manifest: Digest::compute(b"manifest"),
            predecessors: vec![Digest::compute(b"parent")],
            author: "nicola.gallo@nitroagility.com".into(),
            author_at: 1_787_836_800,
            message: "Restrict billing view".into(),
        };
        let bytes = commit.encode().unwrap();
        assert_eq!(decode(&bytes).unwrap(), Object::Commit(commit));
    }

    #[test]
    fn commit_rejects_three_or_duplicate_predecessors() {
        let d = Digest::compute(b"p");
        let mut commit = Commit {
            tree: Digest::compute(b"tree"),
            manifest: Digest::compute(b"manifest"),
            predecessors: vec![d.clone(), d.clone()],
            author: "a".into(),
            author_at: 0,
            message: String::new(),
        };
        assert!(commit.encode().is_err());
        commit.predecessors = vec![
            Digest::compute(b"1"),
            Digest::compute(b"2"),
            Digest::compute(b"3"),
        ];
        assert!(commit.encode().is_err());
    }

    #[test]
    fn entry_may_not_reference_a_commit() {
        let tree = Tree {
            entries: vec![TreeEntry {
                kind: Kind::Commit,
                digest: Digest::compute(b"x"),
                name: "c".into(),
                annotations: BTreeMap::new(),
            }],
        };
        assert!(matches!(tree.encode(), Err(ObjectError::Schema(_))));
    }

    #[test]
    fn unknown_keys_are_rejected() {
        // A valid blob, plus key 9 → must be refused on decode.
        let value = Value::Map(vec![
            (Value::Int(1), Value::Int(1)),
            (
                Value::Int(2),
                Value::Text("application/vnd.permguard.policy.cedar".into()),
            ),
            (Value::Int(3), Value::Bytes(vec![1])),
            (Value::Int(9), Value::Int(0)),
        ]);
        let bytes = cbor::encode(&value);
        assert!(matches!(decode(&bytes), Err(ObjectError::Schema(_))));
    }

    #[test]
    fn non_canonical_bytes_are_rejected() {
        let mut bytes = sample_blob().encode().unwrap();
        // Corrupt the map into a non-canonical (still decodable) form by
        // re-encoding the length long-form: simplest is appending a byte.
        bytes.push(0x00);
        assert!(decode(&bytes).is_err());
    }
}
