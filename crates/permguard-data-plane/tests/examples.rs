// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Every example under `examples/`, decided by the real decision path.
//!
//! The manifest, the policies and the requests are read from the example directory —
//! the same files its README tells a reader to apply — and so are the expectations:
//! **the `tests/*.yml` `permguard test` reads**. There is no table of expected answers
//! here, deliberately. One would be a second copy of what each example claims, free to
//! drift from the first, and a case added to an example would be covered by the CLI and
//! silently not by this.
//!
//! So the two paths share their expectations and differ only in how the answer is
//! reached: `permguard test` compiles the workspace and evaluates it; this drives the
//! real `Decider` against a mirror built out of the same objects an `apply` pushes.
//! Between them, an example cannot claim something neither path can produce.

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
const LEDGER: &str = "the-example";

/// Every example, and where its cases live.
const EXAMPLES: &[&str] = &["basics", "release-pipeline"];

/// One case, as `examples/*/tests/*.yml` spells it.
///
/// The shape is `permguard_cli::engine::workspace::cases`, restated here rather than
/// depended on: a server's tests reaching into the CLI to read a file would be a worse
/// coupling than three structs. What must not be duplicated is the *expectations*, and
/// those are read, not restated.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    name: String,
    request: String,
    #[serde(default)]
    profile: Option<String>,
    expect: Expectation,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Expectation {
    #[serde(default)]
    decision: Option<String>,
    #[serde(default)]
    policies: Option<Vec<String>>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    evaluations: Option<BTreeMap<String, String>>,
}

fn example(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples")
        .join(name)
}

/// The cases an example claims, read from the files the CLI reads.
fn cases(name: &str) -> Vec<(String, Case)> {
    let directory = example(name).join("tests");
    let mut files: Vec<PathBuf> = std::fs::read_dir(&directory)
        .unwrap_or_else(|_| panic!("{} exists", directory.display()))
        .map(|entry| entry.expect("a directory entry").path())
        .filter(|path| {
            path.extension()
                .is_some_and(|found| found == "yml" || found == "yaml")
        })
        .collect();
    files.sort();

    let mut found = Vec::new();
    for file in files {
        let text = std::fs::read_to_string(&file).expect("a case file is readable");
        let read: Vec<Case> = serde_norway::from_str(&text)
            .unwrap_or_else(|error| panic!("{}: {error}", file.display()));
        for case in read {
            found.push((name.to_owned(), case));
        }
    }

    assert!(!found.is_empty(), "{name} claims nothing");

    found
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

fn manifest(name: &str) -> Manifest {
    let text = std::fs::read_to_string(example(name).join("manifest.yml"))
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

/// One entry per policy the file holds: Cedar splits at each `@alias`, Rego does not split.
fn split(source: &str, extension: &str) -> Vec<String> {
    if extension != "cedar" {
        return vec![source.to_owned()];
    }

    let mut found: Vec<String> = Vec::new();
    for line in source.lines() {
        if line.starts_with("@alias(") {
            found.push(String::new());
        }
        if let Some(current) = found.last_mut() {
            current.push_str(line);
            current.push('\n');
        }
    }

    assert!(
        !found.is_empty(),
        "a Cedar file with no `@alias` on any policy"
    );

    found
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
fn policies(
    example_name: &str,
    directory: &str,
    extension: &str,
    media_type: &'static str,
) -> Vec<Policy> {
    let mut found = Vec::new();
    let path = example(example_name).join(directory);

    let mut names: Vec<PathBuf> = std::fs::read_dir(&path)
        .unwrap_or_else(|_| panic!("{} exists", path.display()))
        .map(|entry| entry.expect("a directory entry").path())
        .filter(|entry| entry.extension().is_some_and(|found| found == extension))
        .collect();
    names.sort();

    for name in names {
        let source = std::fs::read_to_string(&name).expect("a policy is readable");

        // A file is presentation; a policy is content. The CLI extracts **each policy as
        // its own object**, so a Cedar file holding two of them is two policies on the
        // wire — and a plane handed the whole file would refuse it as one that does not
        // parse. A Rego module is indivisible, and stays one.
        for text in split(&source, extension) {
            found.push(Policy {
                alias: alias_of(&name, &text),
                media_type,
                source: text.into_bytes(),
            });
        }
    }

    assert!(!found.is_empty(), "{} holds no policy", path.display());

    found
}

/// Writes the mirror a synchronization round would leave: the objects of the
/// example's own commit, a verified checkpoint, and the identity file.
fn provision(root: &Path, name: &str) -> Manifest {
    let manifest = manifest(name);
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
        for policy in policies(name, partition_name, extension, media_type) {
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
            let schema =
                std::fs::read(example(name).join(partition_name).join("model.cedarschema"))
                    .unwrap_or_else(|_| {
                        panic!(
                            "{partition_name} declares a schema and carries no model.cedarschema"
                        )
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

/// The request a case names, addressed at the mirror above.
///
/// The path is relative to the case file, `..` included, exactly as the CLI resolves it.
fn request(example_name: &str, case: &Case) -> wire::CheckRequest {
    let path = example(example_name)
        .join("tests")
        .join(&case.request)
        .canonicalize()
        .unwrap_or_else(|_| panic!("{} names no request at {}", case.name, case.request));
    let text = std::fs::read_to_string(&path).expect("a request is readable");
    let mut payload: Value = serde_json::from_str(&text).unwrap_or_else(|error| {
        panic!(
            "{}: not JSON the CLI would accept either: {error}",
            case.name
        )
    });

    let object = payload
        .as_object_mut()
        .unwrap_or_else(|| panic!("{} is a JSON object", case.request));
    object.insert("zone".to_owned(), Value::String(ZONE.to_owned()));
    object.insert("ledger".to_owned(), Value::String(LEDGER.to_owned()));
    if let Some(profile) = &case.profile {
        object.insert("profile".to_owned(), Value::String(profile.clone()));
    }

    serde_json::from_value(payload)
        .unwrap_or_else(|error| panic!("{}: not a decision request: {error}", case.name))
}

/// Every case of every example, decided by the real decision path.
#[tokio::test]
async fn every_example_decides_the_way_its_cases_say_it_does() {
    let mut checked = 0;

    for name in EXAMPLES {
        let root = scratch(name).join("mirrors");
        provision(&root, name);
        let decider = Arc::new(Decider::new(
            root.clone(),
            Arc::new(Cache::new(64, 8 * 1024 * 1024)),
            Metrics::none(),
            None,
            256,
        ));

        for (_, case) in cases(name) {
            // A request may be refused two ways, and a case expecting an error means either: the
            // plane declines to read it at all — a reserved field, an override naming a partition
            // nobody has — or it reads it and an engine cannot evaluate it. The CLI reports both
            // as an error, so this must too, or the two would judge the same case differently.
            let answer = match decider.decide(&request(name, &case), None).await {
                Ok(answer) => answer,
                Err(error) => {
                    let refusal = format!(
                        "{}: {}",
                        error.code(),
                        error.disclosed_message(permguard_core::Disclosure::Full)
                    );
                    let wanted =
                        case.expect.error.as_deref().unwrap_or_else(|| {
                            panic!("{name}/{}: not served: {refusal}", case.name)
                        });
                    assert!(
                        refusal.contains(wanted),
                        "{name}/{}: expected a refusal saying `{wanted}`, got `{refusal}`",
                        case.name
                    );
                    checked += 1;

                    continue;
                }
            };
            let context = answer.context.as_ref();
            let refused = context
                .and_then(|context| context.reason_admin.as_ref())
                .filter(|reason| reason.code == "500")
                .map(|reason| reason.message.clone());

            if let Some(wanted) = &case.expect.error {
                let found = refused.as_deref().unwrap_or_else(|| {
                    panic!(
                        "{name}/{}: expected a refusal saying `{wanted}`, and it was evaluated",
                        case.name
                    )
                });
                assert!(
                    found.contains(wanted.as_str()),
                    "{name}/{}: expected a refusal saying `{wanted}`, got `{found}`",
                    case.name
                );
            } else if let Some(found) = &refused {
                panic!("{name}/{}: could not be evaluated: {found}", case.name);
            }

            if let Some(wanted) = &case.expect.decision {
                let wanted_permit = wanted == "permit";
                assert_eq!(
                    answer.decision, wanted_permit,
                    "{name}/{}: expected {wanted}",
                    case.name
                );
            }

            // A boxcarred request has no single policy to cite, so a case names the
            // policies only for a plain one — which is what the CLI does too.
            if let Some(wanted) = &case.expect.policies {
                let cited: Vec<String> = context
                    .map(|context| context.policies.clone())
                    .unwrap_or_default();
                // The mirror stores each policy under its alias, which is what the CLI's
                // reports name too — so a citation is comparable to a case as it stands.
                assert_eq!(
                    &cited, wanted,
                    "{name}/{}: cited something other than the policies its case names",
                    case.name
                );
            }

            if let Some(wanted) = &case.expect.evaluations {
                let held = answer
                    .evaluations
                    .as_ref()
                    .unwrap_or_else(|| panic!("{name}/{}: not answered as a batch", case.name));
                for (request_id, decision) in wanted {
                    let found = held
                        .iter()
                        .find(|evaluation| {
                            evaluation.request_id.as_deref() == Some(request_id.as_str())
                        })
                        .unwrap_or_else(|| {
                            panic!("{name}/{}: no evaluation named `{request_id}`", case.name)
                        });
                    let got = if found.decision { "permit" } else { "deny" };
                    assert_eq!(
                        got, decision,
                        "{name}/{}: `{request_id}` expected {decision}",
                        case.name
                    );
                }
            }

            checked += 1;
        }
    }

    assert!(checked > 12, "only {checked} cases were decided");
}

/// The point of the release pipeline's three partitions: a profile compiles what it
/// names and nothing else.
#[test]
fn each_profile_loads_only_the_partitions_it_needs() {
    let manifest = manifest("release-pipeline");

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
}
