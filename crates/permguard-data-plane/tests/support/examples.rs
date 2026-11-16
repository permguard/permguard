// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The repository's examples as verified mirrors, and the cases each claims: the manifest, the
//! policies and the requests read from the files its README applies, never restated here.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde_json::Value;

use permguard_client::objects;
use permguard_client::store::FsStore;
use permguard_data_plane::authz::store::Identity;
use permguard_data_plane::authz::wire;
use permguard_languages::registry;
use permguard_objects::manifest::Manifest;
use permguard_objects::object::{Blob, Commit, Kind, Tree, TreeEntry};
use permguard_objects::policy_id::{ANNOTATION_POLICY_ID, ANNOTATION_POLICY_KIND};

/// The authority every mirror of these tests lives under (WP-7.2a): a mirror in a configured URL's
/// shape is never served since WP-7.7.
pub const MIRROR_AUTHORITY: &str = "11111111111111111111111111111111";
/// The task the mirrors of these tests were listed by: the local task.
pub const MIRROR_TASK: &str = "00000000-0000-0000-0000-000000000000/local";

pub const ZONE: &str = "delivery";
pub const LEDGER: &str = "the-example";

/// Every example, and where its cases live.
pub const EXAMPLES: &[&str] = &["basics", "release-pipeline"];

/// One case, as `examples/*/tests/*.yml` spells it.
///
/// The shape is `permguard_cli::engine::workspace::cases`, restated here rather than
/// depended on: a server's tests reaching into the CLI to read a file would be a worse
/// coupling than three structs. What must not be duplicated is the *expectations*, and
/// those are read, not restated.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Case {
    pub name: String,
    pub request: String,
    #[serde(default)]
    pub profile: Option<String>,
    pub expect: Expectation,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Expectation {
    #[serde(default)]
    pub decision: Option<String>,
    #[serde(default)]
    pub policies: Option<Vec<String>>,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub evaluations: Option<BTreeMap<String, String>>,
}

pub fn example(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../examples")
        .join(name)
}

/// The cases an example claims, read from the files the CLI reads.
pub fn cases(name: &str) -> Vec<(String, Case)> {
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

/// The example's authored manifest, as the model.
///
/// Read through `permguard_languages::manifest_file` — the same conversion the CLI performs when
/// it builds a workspace. This test used to restate the YAML shape in its own structs and default
/// the media types by hand; the day a partition gained a field, the copy here kept parsing and
/// silently produced a different manifest than the one the example ships.
pub fn manifest(name: &str) -> Manifest {
    let bytes =
        std::fs::read(example(name).join("manifest.yml")).expect("the example carries a manifest");

    permguard_languages::manifest_file::from_yaml(&bytes).expect("the manifest is well formed")
}

/// One policy as the lab keeps it: the source, and the alias the author wrote
/// on it. The alias is the identity here too, so an assertion can name a policy
/// the way the README does instead of by a digest.
pub struct Policy {
    pub alias: String,
    pub media_type: &'static str,
    pub source: Vec<u8>,
}

/// One entry per policy the file holds: Cedar splits at each `@alias`, Rego does not split.
pub fn split(source: &str, extension: &str) -> Vec<String> {
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
pub fn alias_of(path: &Path, source: &str) -> String {
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
pub fn policies(
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
pub fn provision(root: &Path, name: &str) -> Manifest {
    provision_as(root, name, &format!("{ZONE}-id"), &format!("{LEDGER}-id"))
}

/// [`provision`], the zone and the ledger under `zone_id` and `ledger_id`: UUIDs where the
/// decision log keys its tags and pseudonyms by them.
pub fn provision_as(root: &Path, name: &str, zone_id: &str, ledger_id: &str) -> Manifest {
    let manifest = manifest(name);
    let path = root.join(MIRROR_AUTHORITY).join(zone_id).join(ledger_id);
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

    let manifest_digest = put(
        permguard_objects::manifest::MEDIA_TYPE,
        &manifest.encode().expect("it encodes"),
    );

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
            // Found by the language's own schema extensions and stored under the language's own
            // schema media type — asked, not assumed. `model.cedarschema` was hard-coded here,
            // which meant a second language with a schema would have gone looking for a Cedar
            // file that was never there.
            let plugin = permguard_languages::language(language)
                .unwrap_or_else(|| panic!("this build carries `{language}`"));
            let authoring = plugin
                .authoring()
                .unwrap_or_else(|| panic!("`{language}` can be authored"));
            let directory = example(name).join(partition_name);
            let found = std::fs::read_dir(&directory)
                .expect("the partition is a directory")
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .find(|path| {
                    path.extension()
                        .and_then(std::ffi::OsStr::to_str)
                        .is_some_and(|extension| {
                            authoring.schema_file_extensions().contains(&extension)
                        })
                })
                .unwrap_or_else(|| {
                    panic!("{partition_name} declares a schema and carries no schema file")
                });
            let schema = std::fs::read(&found).expect("the schema reads");
            let media_type = plugin
                .schema_media_type()
                .unwrap_or_else(|| panic!("`{language}` has a schema media type"));
            let file_name = found
                .file_name()
                .and_then(std::ffi::OsStr::to_str)
                .expect("a name")
                .to_owned();
            entries.push(TreeEntry {
                kind: Kind::Blob,
                digest: put(media_type, &schema),
                name: file_name,
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

    permguard_client::checkpoint::write(
        &store,
        "refs/main",
        &permguard_client::checkpoint::Checkpoint {
            head: head.to_string(),
            counter: 1,
            ref_digest: None,
            ..Default::default()
        },
    )
    .expect("the checkpoint is written");

    permguard_data_plane::authz::store::record(
        &path,
        &Identity {
            task: Some(MIRROR_TASK.to_owned()),
            authority: Some(MIRROR_AUTHORITY.to_owned()),
            zone_id: zone_id.to_owned(),
            zone_name: ZONE.to_owned(),
            ledger_id: ledger_id.to_owned(),
            ledger_name: LEDGER.to_owned(),
            server: "http://127.0.0.1:6443".to_owned(),
        },
    )
    .expect("the identity is recorded");

    manifest
}

/// The request a case names, addressed at the mirror above.
///
/// The path is relative to the case file, `..` included, exactly as the CLI resolves it.
pub fn request(example_name: &str, case: &Case) -> wire::CheckRequest {
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
