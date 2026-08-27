// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The `examples/release-pipeline` lab, decided by the real decision path.
//!
//! The manifest, the policies and the requests are read from the example
//! directory — the same files its README tells a reader to apply — and every
//! decision is asserted, together with the policy that made it. An edit that
//! changes what the example decides fails here, rather than in the terminal of
//! whoever followed the README next.
//!
//! What each case is there to show:
//!
//! | | |
//! | --- | --- |
//! | the org chart decides who may act at all | `release-create-*` |
//! | a guardrail overrides an entitlement — separation of duties | `signoff-separation-of-duties-deny` |
//! | machine identities answer under a profile of their own | `artifact-*`, `deploy-*` |
//! | the same person, refused and then allowed, on context alone | `rollback-*` |
//! | and the two ways of saying no: a deny, and nothing permitting | citations below |

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::Deserialize;
use serde_json::Value;

use permguard_control_client::objects;
use permguard_control_client::store::FsStore;
use permguard_core::Metrics;
use permguard_data_plane::authz::cache::Cache;
use permguard_data_plane::authz::decide::Decider;
use permguard_data_plane::authz::store::Identity;
use permguard_data_plane::authz::wire;
use permguard_languages::registry;
use permguard_objects::manifest::{Manifest, Partition, Profile, Requirement, Runtime};
use permguard_objects::object::{Blob, Commit, Kind, Tree, TreeEntry};
use permguard_objects::policy_id::{ANNOTATION_POLICY_ID, ANNOTATION_POLICY_KIND};
use permguard_objects::semver::Constraint;

const ZONE: &str = "delivery";
const LEDGER: &str = "release-pipeline";

/// Every request in the lab, the decision it must get, and the policies that
/// must be cited for it. An empty list is the other way of saying no: nothing
/// permitted the request, and there is no policy to name.
const EXPECTED: &[(&str, bool, &[&str])] = &[
    ("release-create-permit.json", true, &["release-authors"]),
    ("release-create-deny.json", false, &[]),
    ("signoff-permit.json", true, &["release-approvers"]),
    (
        "signoff-separation-of-duties-deny.json",
        false,
        &["delivery-guardrails"],
    ),
    (
        "signoff-untested-deny.json",
        false,
        &["delivery-guardrails"],
    ),
    ("artifact-upload-permit.json", true, &["pipeline-workloads"]),
    ("artifact-sign-deny.json", false, &[]),
    ("deploy-permit.json", true, &["pipeline-workloads"]),
    ("deploy-scan-failed-deny.json", false, &[]),
    ("rollback-deny.json", false, &["delivery-guardrails"]),
    (
        "rollback-during-incident-permit.json",
        true,
        &["rollback-responders"],
    ),
];

fn example() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/release-pipeline")
}

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "pg-release-pipeline-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch directory is created");

    dir
}

// The manifest as the file spells it. Read rather than restated, so that a
// partition or a profile renamed in the lab reaches this test.
#[derive(Deserialize)]
struct FileManifest {
    metadata: FileMetadata,
    runtimes: BTreeMap<String, FileRuntime>,
    partitions: BTreeMap<String, FilePartition>,
    profiles: BTreeMap<String, FileProfile>,
}

#[derive(Deserialize)]
struct FileMetadata {
    kind: String,
    name: String,
    description: String,
    author: String,
    license: String,
}

#[derive(Deserialize)]
struct FileRuntime {
    language: FileRequirement,
    engine: FileRequirement,
}

#[derive(Deserialize)]
struct FileRequirement {
    name: String,
    constraint: String,
}

#[derive(Deserialize)]
struct FilePartition {
    runtime: String,
    schema: bool,
}

#[derive(Deserialize)]
struct FileProfile {
    #[serde(rename = "type")]
    r#type: String,
    partitions: Vec<String>,
}

fn manifest() -> Manifest {
    let text = std::fs::read_to_string(example().join("manifest.yml"))
        .expect("the example carries a manifest");
    let file: FileManifest = serde_norway::from_str(&text).expect("the manifest parses");

    let runtimes = file
        .runtimes
        .into_iter()
        .map(|(name, runtime)| {
            let requirement = |declared: FileRequirement| Requirement {
                name: declared.name,
                constraint: Constraint::parse(&declared.constraint).expect("a constraint"),
            };

            (
                name,
                Runtime {
                    language: requirement(runtime.language),
                    engine: requirement(runtime.engine),
                },
            )
        })
        .collect();

    let partitions = file
        .partitions
        .into_iter()
        .map(|(name, partition)| {
            let media_types = match partition.runtime.as_str() {
                "cedar" => vec![
                    registry::MEDIA_TYPE_POLICY_CEDAR.to_owned(),
                    registry::MEDIA_TYPE_SCHEMA_CEDAR.to_owned(),
                ],
                _ => vec![registry::MEDIA_TYPE_POLICY_REGO.to_owned()],
            };

            (
                name,
                Partition {
                    runtime: partition.runtime,
                    media_types,
                    schema: partition.schema,
                },
            )
        })
        .collect();

    let profiles = file
        .profiles
        .into_iter()
        .map(|(name, profile)| {
            (
                name,
                Profile {
                    r#type: profile.r#type,
                    partitions: profile.partitions,
                },
            )
        })
        .collect();

    Manifest {
        kind: file.metadata.kind,
        name: file.metadata.name,
        description: file.metadata.description,
        author: file.metadata.author,
        license: file.metadata.license,
        runtimes,
        partitions,
        profiles,
    }
}

/// One policy as the lab keeps it: the source, and the alias the author wrote
/// on it. The alias is the identity here too, so an assertion can name a policy
/// the way the README does instead of by a digest.
struct Policy {
    alias: String,
    media_type: &'static str,
    source: Vec<u8>,
}

/// `@alias("x")` for Cedar, `#   alias: x` in the Rego metadata header. The
/// same two places the CLI reads them from.
fn alias_of(path: &Path, source: &str) -> String {
    if let Some(rest) = source.split("@alias(\"").nth(1) {
        return rest
            .split('"')
            .next()
            .expect("an alias is closed")
            .to_owned();
    }

    for line in source.lines() {
        let line = line.trim_start_matches('#').trim();
        if let Some(alias) = line.strip_prefix("alias:") {
            return alias.trim().to_owned();
        }
    }

    panic!("{} carries no alias", path.display())
}

/// The policies of one partition, read off disk in a stable order.
fn policies(directory: &str, extension: &str, media_type: &'static str) -> Vec<Policy> {
    let mut found = Vec::new();
    let path = example().join(directory);

    let mut names: Vec<PathBuf> = std::fs::read_dir(&path)
        .unwrap_or_else(|_| panic!("{} exists", path.display()))
        .map(|entry| entry.expect("a directory entry").path())
        .filter(|entry| entry.extension().is_some_and(|found| found == extension))
        .collect();
    names.sort();

    for name in names {
        let source = std::fs::read_to_string(&name).expect("a policy is readable");
        found.push(Policy {
            alias: alias_of(&name, &source),
            media_type,
            source: source.into_bytes(),
        });
    }

    assert!(!found.is_empty(), "{} holds no policy", path.display());

    found
}

/// Writes the mirror a synchronization round would leave: the objects of the
/// example's own commit, a verified checkpoint, and the identity file.
fn provision(root: &Path) -> Manifest {
    let manifest = manifest();
    let path = root.join(format!("{ZONE}-id")).join(format!("{LEDGER}-id"));
    std::fs::create_dir_all(&path).expect("the mirror directory is created");
    let store = FsStore::new(&path);

    let put = |media_type: &str, data: &[u8]| {
        let blob = Blob {
            media_type: media_type.to_owned(),
            data: data.to_vec(),
        };

        objects::put(&store, "objects", &blob.encode().expect("the blob encodes"))
            .expect("the blob is stored")
    };

    let manifest_digest = put(permguard_objects::manifest::MEDIA_TYPE, &manifest.encode());

    // Driven by the manifest rather than by a list here: a partition *is* a
    // directory, and the language it runs decides what is read out of it. Splitting
    // a partition in the example reaches this test without a line changing in it.
    let mut root_entries = Vec::new();
    for (partition_name, partition) in &manifest.partitions {
        let language = &manifest
            .runtimes
            .get(&partition.runtime)
            .unwrap_or_else(|| panic!("{partition_name} names an undeclared runtime"))
            .language
            .name;
        let (extension, media_type) = match language.as_str() {
            "cedar" => ("cedar", registry::MEDIA_TYPE_POLICY_CEDAR),
            "rego" => ("rego", registry::MEDIA_TYPE_POLICY_REGO),
            other => panic!("the example runs `{other}`, which this test cannot read"),
        };

        let mut entries = Vec::new();
        for policy in policies(partition_name, extension, media_type) {
            let digest = put(policy.media_type, &policy.source);
            let mut annotations = BTreeMap::new();
            annotations.insert(ANNOTATION_POLICY_ID.to_owned(), policy.alias.clone());
            annotations.insert(ANNOTATION_POLICY_KIND.to_owned(), "policy".to_owned());
            entries.push(TreeEntry {
                kind: Kind::Blob,
                digest,
                name: format!("{}.policy", policy.alias),
                annotations,
            });
        }
        if partition.schema {
            let schema = std::fs::read(example().join(partition_name).join("model.cedarschema"))
                .unwrap_or_else(|_| {
                    panic!("{partition_name} declares a schema and carries no model.cedarschema")
                });
            entries.push(TreeEntry {
                kind: Kind::Blob,
                digest: put(registry::MEDIA_TYPE_SCHEMA_CEDAR, &schema),
                name: "schema.cedarschema".to_owned(),
                annotations: BTreeMap::new(),
            });
        }
        entries.sort_by(|left, right| left.name.cmp(&right.name));
        let tree = Tree { entries };
        root_entries.push(TreeEntry {
            kind: Kind::Tree,
            digest: objects::put(&store, "objects", &tree.encode().expect("the tree encodes"))
                .expect("the tree is stored"),
            name: partition_name.clone(),
            annotations: BTreeMap::new(),
        });
    }
    root_entries.sort_by(|left, right| left.name.cmp(&right.name));

    let root_tree = Tree {
        entries: root_entries,
    };
    let tree_digest = objects::put(
        &store,
        "objects",
        &root_tree.encode().expect("the root tree encodes"),
    )
    .expect("the tree is stored");

    let commit = Commit {
        tree: tree_digest,
        manifest: manifest_digest,
        predecessors: Vec::new(),
        author: "tests".to_owned(),
        author_at: 1_700_000_000,
        message: "the release-pipeline example".to_owned(),
    };
    let head = objects::put(
        &store,
        "objects",
        &commit.encode().expect("the commit encodes"),
    )
    .expect("the commit is stored");

    permguard_control_client::checkpoint::write(
        &store,
        "refs/main",
        &permguard_control_client::checkpoint::Checkpoint {
            head: head.to_string(),
            counter: 1,
        },
    )
    .expect("the checkpoint is written");

    permguard_data_plane::authz::store::record(
        &path,
        &Identity {
            zone_id: format!("{ZONE}-id"),
            zone_name: ZONE.to_owned(),
            ledger_id: format!("{LEDGER}-id"),
            ledger_name: LEDGER.to_owned(),
            server: "http://127.0.0.1:7556".to_owned(),
        },
    )
    .expect("the identity is recorded");

    manifest
}

/// One of the lab's request files, addressed at the mirror above.
fn request(name: &str) -> wire::CheckRequest {
    let text = std::fs::read_to_string(example().join("requests").join(name))
        .unwrap_or_else(|_| panic!("{name} is readable"));
    let mut payload: Value = serde_json::from_str(&text)
        .unwrap_or_else(|error| panic!("{name} is not JSON the CLI would accept either: {error}"));

    let object = payload
        .as_object_mut()
        .unwrap_or_else(|| panic!("{name} is a JSON object"));
    object.insert("zone".to_owned(), Value::String(ZONE.to_owned()));
    object.insert("ledger".to_owned(), Value::String(LEDGER.to_owned()));

    serde_json::from_value(payload)
        .unwrap_or_else(|error| panic!("{name} is not a decision request: {error}"))
}

#[tokio::test]
async fn every_request_in_the_example_decides_the_way_its_readme_says() {
    let root = scratch("decides").join("mirrors");
    provision(&root);
    let decider = Arc::new(Decider::new(
        root.clone(),
        Arc::new(Cache::new(64, 8 * 1024 * 1024)),
        Metrics::none(),
        None,
        256,
    ));

    for (name, expected, citations) in EXPECTED {
        let answer = decider
            .decide(&request(name), None)
            .await
            .unwrap_or_else(|error| panic!("{name}: the ledger is not served: {error:?}"));

        assert_eq!(
            answer.decision, *expected,
            "{name} decided {} instead",
            answer.decision
        );

        let context = answer
            .context
            .unwrap_or_else(|| panic!("{name}: a decision carries its context"));
        assert_eq!(
            context.policies,
            citations
                .iter()
                .map(|alias| (*alias).to_owned())
                .collect::<Vec<String>>(),
            "{name} cited something other than the policies the README names"
        );
    }
}

/// The point of the three partitions: a profile compiles what it names and nothing
/// else, so the guardrails are not loaded to answer a pipeline request and the
/// pipeline rules are not loaded to answer a person's. Two partitions running the
/// same language is what makes that separation expressible at all — merge them and
/// every profile pays for every module, quietly.
#[test]
fn each_profile_loads_only_the_partitions_it_needs() {
    let manifest = manifest();

    assert_eq!(
        manifest.profiles.get("admin").map(|p| p.partitions.clone()),
        Some(vec!["admin-cedar".to_owned(), "admin-rego".to_owned()]),
        "what a person asks is answered by the org chart and the guardrails together"
    );
    assert_eq!(
        manifest
            .profiles
            .get("pipeline")
            .map(|p| p.partitions.clone()),
        Some(vec!["pipeline-rego".to_owned()]),
        "what the pipeline asks is answered by the rules for machines, alone"
    );

    assert_eq!(
        manifest
            .partitions
            .get("admin-rego")
            .map(|p| p.runtime.clone()),
        manifest
            .partitions
            .get("pipeline-rego")
            .map(|p| p.runtime.clone()),
        "both Rego partitions run the same runtime — they are split by what is asked"
    );
    assert!(
        manifest
            .partitions
            .get("admin-cedar")
            .is_some_and(|p| p.schema),
        "the Cedar partition carries a schema, and the example depends on it being checked"
    );
    for rego in ["admin-rego", "pipeline-rego"] {
        assert!(
            manifest.partitions.get(rego).is_some_and(|p| !p.schema),
            "{rego} must not declare a schema: Rego has none, and the engine refuses one"
        );
    }

    // And no partition holds a module belonging to the other side.
    let aliases = |partition: &str, extension: &str| -> Vec<String> {
        policies(partition, extension, registry::MEDIA_TYPE_POLICY_REGO)
            .into_iter()
            .map(|policy| policy.alias)
            .collect()
    };
    assert_eq!(aliases("admin-rego", "rego"), vec!["delivery-guardrails"]);
    assert_eq!(aliases("pipeline-rego", "rego"), vec!["pipeline-workloads"]);
}
