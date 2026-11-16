// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The repository's examples as verified mirrors, and the cases each claims: the manifest, the
//! policies and the requests read from the files its README applies, never restated here.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde_json::Value;

use permguard_data_plane::authz::store::Identity;
use permguard_data_plane::authz::wire;
use permguard_languages::registry;
use permguard_mirror::objects;
use permguard_mirror::store::FsStore;
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
    /// The occurrences that happened first, in order: a temporal case is a claim about order.
    #[serde(default)]
    pub events: Vec<String>,
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
    /// The file it was read from, by name.
    pub file: String,
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

/// `@alias("x")` for Cedar, `#   alias: x` in the Rego metadata header, `@id("x")` for Dogwood.
/// The same places the CLI reads them from.
pub fn alias_of(path: &Path, source: &str) -> String {
    if path.extension().is_some_and(|extension| extension == "dw") {
        return match source.split("@id(\"").nth(1) {
            Some(rest) => rest.split('"').next().expect("an id is closed").to_owned(),
            // A reserved artifact, a macro library say, is no policy: named by its file.
            None => path
                .file_stem()
                .and_then(std::ffi::OsStr::to_str)
                .expect("a name")
                .to_owned(),
        };
    }
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
                file: name
                    .file_name()
                    .and_then(std::ffi::OsStr::to_str)
                    .expect("a name")
                    .to_owned(),
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
    provision_manifest(root, name, manifest(name), zone_id, ledger_id)
}

/// The example's manifest with only what `language` runs: its runtime, the partitions on it and
/// the profiles over them. What an author publishes for a Data Plane built with that language
/// alone, from the same file; narrowed before it is read, since a build reads no manifest naming a
/// language it does not carry.
pub fn manifest_narrowed_to(name: &str, language: &str) -> Manifest {
    use serde_norway::Value as Yaml;

    let bytes =
        std::fs::read(example(name).join("manifest.yml")).expect("the example carries a manifest");
    let mut document: Yaml = serde_norway::from_slice(&bytes).expect("the manifest is YAML");
    let named = |value: &Yaml, key: &str| value.get(key).and_then(Yaml::as_str).map(str::to_owned);

    let runtimes = document
        .get_mut("runtimes")
        .and_then(Yaml::as_mapping_mut)
        .expect("the manifest declares runtimes");
    runtimes.retain(|_, runtime| {
        runtime
            .get("language")
            .and_then(|declared| named(declared, "name"))
            .as_deref()
            == Some(language)
    });
    let kept: Vec<Yaml> = runtimes.keys().cloned().collect();

    let partitions = document
        .get_mut("partitions")
        .and_then(Yaml::as_mapping_mut)
        .expect("the manifest declares partitions");
    partitions.retain(|_, partition| {
        partition
            .get("runtime")
            .is_some_and(|runtime| kept.contains(runtime))
    });
    let kept: Vec<Yaml> = partitions.keys().cloned().collect();

    let profiles = document
        .get_mut("profiles")
        .and_then(Yaml::as_mapping_mut)
        .expect("the manifest declares profiles");
    for (_, profile) in profiles.iter_mut() {
        if let Some(listed) = profile
            .get_mut("partitions")
            .and_then(Yaml::as_sequence_mut)
        {
            listed.retain(|partition| kept.contains(partition));
        }
    }
    profiles.retain(|_, profile| {
        profile
            .get("partitions")
            .and_then(Yaml::as_sequence)
            .is_some_and(|listed| !listed.is_empty())
    });

    let narrowed = serde_norway::to_string(&document).expect("the narrowed manifest is YAML");
    permguard_languages::manifest_file::from_yaml(narrowed.as_bytes())
        .expect("the narrowed manifest is well formed")
}

/// [`provision_as`], with the manifest the mirror is to hold: the example's policies, under
/// `manifest` in place of the one its directory carries.
pub fn provision_manifest(
    root: &Path,
    name: &str,
    manifest: Manifest,
    zone_id: &str,
    ledger_id: &str,
) -> Manifest {
    provision_named(root, name, manifest, (zone_id, ZONE), (ledger_id, LEDGER))
}

/// [`provision_manifest`], the zone and the ledger under the names a request addresses them by:
/// an example whose requests name their store carries its own.
pub fn provision_named(
    root: &Path,
    name: &str,
    manifest: Manifest,
    zone: (&str, &str),
    ledger: (&str, &str),
) -> Manifest {
    provision_with_artifacts(root, name, manifest, zone, ledger, &[])
}

/// [`provision_named`], with typed artifacts the example's directory does not carry, each by its
/// registered type: what a stricter assurance profile requires of a partition, supplied by the
/// test that asks for that profile.
pub fn provision_with_artifacts(
    root: &Path,
    name: &str,
    manifest: Manifest,
    (zone_id, zone_name): (&str, &str),
    (ledger_id, ledger_name): (&str, &str),
    supplied: &[(&str, &[u8])],
) -> Manifest {
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
            "dogwood" => ("dw", permguard_languages::MEDIA_TYPE_POLICY_DOGWOOD),
            other => panic!("the example runs `{other}`, which this test cannot read"),
        };

        let mut entries = Vec::new();
        // The typed artifacts a partition declares, each under the file name its type reserves:
        // found by that name, and never read as a policy, whatever its extension.
        let mut reserved = Vec::new();
        for contract in &partition.artifacts {
            let artifact = permguard_languages::artifact::artifact_type(&contract.r#type)
                .unwrap_or_else(|| panic!("`{}` is a registered artifact", contract.r#type));
            let given = supplied
                .iter()
                .find(|(supplied_type, _)| *supplied_type == contract.r#type)
                .map(|(_, source)| source.to_vec());
            // A type that reserves no file name is found by its media type, under any name: the
            // example's directory cannot say which file it is, so only a test supplies one.
            let (file_name, source) = match (artifact.canonical_filename(), given) {
                (Some(file_name), Some(source)) => (file_name.to_owned(), source),
                (None, Some(source)) => (format!("{}.artifact", contract.r#type), source),
                (Some(file_name), None) => {
                    let file = example(name).join(partition_name).join(file_name);
                    if !file.is_file() {
                        assert!(
                            !contract.required,
                            "{partition_name} requires `{}` and carries no {file_name}",
                            contract.r#type
                        );
                        continue;
                    }
                    (
                        file_name.to_owned(),
                        std::fs::read(&file).expect("the artifact reads"),
                    )
                }
                (None, None) => continue,
            };
            reserved.push(file_name.clone());
            entries.push(TreeEntry {
                kind: Kind::Blob,
                digest: put(artifact.media_type(), &source),
                name: file_name,
                annotations: BTreeMap::new(),
            });
        }
        for policy in policies(name, partition_name, extension, media_type)
            .into_iter()
            .filter(|policy| !reserved.contains(&policy.file))
        {
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
        message: format!("the {name} example"),
    };
    let head = objects::put(
        &store,
        "objects",
        &commit.encode().expect("the commit encodes"),
    )
    .expect("the commit is stored");

    permguard_mirror::checkpoint::write(
        &store,
        "refs/main",
        &permguard_mirror::checkpoint::Checkpoint {
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
            zone_name: zone_name.to_owned(),
            ledger_id: ledger_id.to_owned(),
            ledger_name: ledger_name.to_owned(),
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

/// Seconds since the epoch of a `YYYY-MM-DDTHH:MM:SSZ` instant, as the examples write them.
fn epoch_of(instant: &str) -> i64 {
    let number = |range: std::ops::Range<usize>| -> i64 {
        instant
            .get(range)
            .and_then(|digits| digits.parse().ok())
            .unwrap_or_else(|| panic!("`{instant}` is an instant of the examples"))
    };
    let (year, month, day) = (number(0..4), number(5..7), number(8..10));
    // Days from the civil date, the proleptic Gregorian calendar.
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let of_era = year.rem_euclid(400);
    let of_year = (153 * ((month + 9) % 12) + 2) / 5 + day - 1;
    let days = era * 146_097 + of_era * 365 + of_era / 4 - of_era / 100 + of_year - 719_468;
    days * 86_400 + number(11..13) * 3_600 + number(14..16) * 60 + number(17..19)
}

/// The `YYYY-MM-DDTHH:MM:SSZ` instant of seconds since the epoch.
fn instant_of(epoch: i64) -> String {
    let days = epoch.div_euclid(86_400);
    let of_day = epoch.rem_euclid(86_400);
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let of_era = shifted.rem_euclid(146_097);
    let year_of_era = (of_era - of_era / 1_460 + of_era / 36_524 - of_era / 146_096) / 365;
    let of_year = of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * of_year + 2) / 153;
    let day = of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        of_day / 3_600,
        of_day % 3_600 / 60,
        of_day % 60
    )
}

/// One occurrence of a temporal example's timeline.
pub struct Occurrence {
    /// The file it was read from, relative to the example's cases.
    pub file: String,
    /// The submission, its instant moved as the whole timeline was.
    pub submission: Value,
    /// What the example's cases say it decides; `None` for an occurrence that is history alone.
    pub decision: Option<bool>,
}

/// A temporal example as one history: every occurrence its cases name, once, in the order they
/// happened, with what each decides where a case says so.
///
/// The fixtures keep fixed instants, for reproducible offline cases; a live plane accepts an
/// occurrence only near its own clock. So the whole timeline is moved, every interval kept, to end
/// `ends_before_now` seconds before now: the order and the windows are the example's.
pub fn timeline(name: &str, ends_before_now: i64) -> Vec<Occurrence> {
    let mut decisions: BTreeMap<String, Option<bool>> = BTreeMap::new();
    for (_, case) in cases(name) {
        for event in &case.events {
            decisions.entry(event.clone()).or_insert(None);
        }
        let Some(wanted) = case.expect.decision.as_deref() else {
            continue;
        };
        let held = decisions.entry(case.request.clone()).or_insert(None);
        let wanted = Some(wanted == "permit");
        assert!(
            held.is_none() || *held == wanted,
            "{name}: two cases decide {} differently",
            case.request
        );
        *held = wanted;
    }

    let mut found: Vec<(i64, Occurrence)> = decisions
        .into_iter()
        .map(|(file, decision)| {
            let path = example(name).join("tests").join(&file);
            let text = std::fs::read_to_string(&path)
                .unwrap_or_else(|_| panic!("{} is readable", path.display()));
            let submission: Value = serde_json::from_str(&text).expect("an occurrence is JSON");
            let at = submission["event"]["data"]["occurred_at"]
                .as_str()
                .map(epoch_of)
                .unwrap_or_else(|| panic!("{file} states when it occurred"));
            (
                at,
                Occurrence {
                    file,
                    submission,
                    decision,
                },
            )
        })
        .collect();
    found.sort_by_key(|(at, _)| *at);

    let last = found.last().map_or(0, |(at, _)| *at);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("a clock after the epoch")
        .as_secs() as i64;
    let moved = now - ends_before_now - last;
    found
        .into_iter()
        .map(|(at, mut occurrence)| {
            occurrence.submission["event"]["data"]["occurred_at"] =
                Value::String(instant_of(at + moved));
            occurrence
        })
        .collect()
}
