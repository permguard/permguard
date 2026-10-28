// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The Helm chart, rendered (TD-1): what `helm template` produces for a values file, and what it
//! refuses to produce.
//!
//! | Area             | Proven here                                                                                     |
//! | ---------------- | ----------------------------------------------------------------------------------------------- |
//! | groups           | two groups render disjoint workloads, Services, memberships, NetworkPolicies and scale policies |
//! | stateful groups  | a StatefulSet, one claim template, claims retained on scale-down and deletion, `ReadWriteOncePod` |
//! | scale-down       | `preStop` runs `drain` and the grace period is the one shutdown budget                          |
//! | refusals         | duplicate names, overlapping or wide selectors, ephemeral evidence, unsafe deletion, autoscaling |
//! | assurance        | the profile rendered per group; what `regulated` and `production` refuse                         |
//! | compatibility    | the legacy single group becomes `groups[0]`, and never beside `groups`                          |
//!
//! `helm` must be on the `PATH`: the CI jobs that run the workspace's tests install it.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Deserialize as _;
use serde_json::{Value, json};

/// What every render states so the public listeners pass the TLS check (WP-2.11).
const BASE: &str = "\
controlPlane:
  tls: { secretName: control-plane-tls }
dataPlane:
  tls: { secretName: data-plane-tls }
";

/// The storage, backup and objectives declarations every `production` render needs (TS-5).
fn production_controls() -> PathBuf {
    chart().join("ci/production-controls.yaml")
}

fn chart() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../charts/permguard")
}

/// The release the chart deploys by default: its `appVersion`, which every release moves.
fn app_version() -> String {
    let text = std::fs::read_to_string(chart().join("Chart.yaml")).expect("Chart.yaml is readable");
    text.lines()
        .find_map(|line| line.strip_prefix("appVersion:"))
        .map(|value| value.trim().trim_matches('"').to_owned())
        .expect("Chart.yaml names its appVersion")
}

fn scratch(tag: &str) -> PathBuf {
    let directory = std::env::temp_dir().join(format!(
        "pg-chart-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).expect("the scratch directory is created");
    directory
}

/// The rendered documents, or helm's error.
struct Rendered(Vec<Value>);

fn render_with(values: &str, extra: &[&str]) -> Result<Rendered, String> {
    let directory = scratch("values");
    let base = directory.join("base.yaml");
    let file = directory.join("values.yaml");
    std::fs::write(&base, BASE).expect("the base values are written");
    std::fs::write(&file, values).expect("the values are written");
    let output = Command::new("helm")
        .arg("template")
        .arg("permguard")
        .arg(chart())
        .args(["--namespace", "pg", "-f"])
        .arg(&base)
        .arg("-f")
        .arg(production_controls())
        .arg("-f")
        .arg(&file)
        .args(extra)
        .output()
        .expect("helm runs: install it and put it on the PATH");
    let _ = std::fs::remove_dir_all(&directory);
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).into_owned());
    }
    let text = String::from_utf8(output.stdout).expect("the render is UTF-8");
    let documents = serde_norway::Deserializer::from_str(&text)
        .map(|document| Value::deserialize(document).expect("each document is YAML"))
        .filter(|document| !document.is_null())
        .collect();
    Ok(Rendered(documents))
}

fn render(values: &str) -> Rendered {
    render_with(values, &[]).unwrap_or_else(|error| panic!("the chart renders: {error}"))
}

/// `render` with image verification on (TD-4), as a `regulated` workload requires: the verifier,
/// the token Secret and placeholder digests, from `ci/image-verification.yaml`.
fn render_verified(values: &str) -> Rendered {
    let filled = chart().join("ci/image-verification.yaml");
    render_with(
        values,
        &[
            "-f",
            filled.to_str().expect("UTF-8"),
            "--set",
            "imageVerification.enabled=true,imageVerification.tokenSecret.name=gh-token",
        ],
    )
    .unwrap_or_else(|error| panic!("the chart renders: {error}"))
}

/// Asserts the render fails, and that its message says `why`.
fn refused(values: &str, why: &str) {
    match render_with(values, &[]) {
        Ok(_) => panic!("the chart rendered values it must refuse ({why}):\n{values}"),
        Err(error) => assert!(error.contains(why), "refused, but not for `{why}`: {error}"),
    }
}

impl Rendered {
    fn all(&self, kind: &str) -> Vec<&Value> {
        self.0.iter().filter(|doc| doc["kind"] == kind).collect()
    }

    fn get(&self, kind: &str, name: &str) -> &Value {
        self.0
            .iter()
            .find(|doc| doc["kind"] == kind && doc["metadata"]["name"] == name)
            .unwrap_or_else(|| panic!("no {kind} named {name}: {:#?}", self.names()))
    }

    fn has(&self, kind: &str, name: &str) -> bool {
        self.0
            .iter()
            .any(|doc| doc["kind"] == kind && doc["metadata"]["name"] == name)
    }

    fn names(&self) -> Vec<String> {
        self.0
            .iter()
            .map(|doc| format!("{} {}", doc["kind"], doc["metadata"]["name"]))
            .collect()
    }

    /// The Plane configuration a ConfigMap carries, as data.
    fn config(&self, name: &str) -> Value {
        let text = self.get("ConfigMap", name)["data"]["config.yml"]
            .as_str()
            .expect("the ConfigMap carries config.yml");
        serde_norway::from_str(text).expect("config.yml is YAML")
    }
}

/// Whether a label selector selects an object carrying `labels`.
fn selects(selector: &Value, labels: &Value) -> bool {
    selector
        .as_object()
        .expect("a selector is a map")
        .iter()
        .all(|(key, value)| labels.get(key) == Some(value))
}

fn labels(doc: &Value) -> &Value {
    &doc["metadata"]["labels"]
}

fn pod_labels(workload: &Value) -> &Value {
    &workload["spec"]["template"]["metadata"]["labels"]
}

/// Two groups: the shape F-18 asks for.
const TWO_GROUPS: &str = "\
dataPlane:
  groups:
    - name: billing
      selector: plane/data/zone/billing/*
      replicas: 3
    - name: people
      selector: plane/data/zone/people/*
      replicas: 2
      podDisruptionBudget: { budget: minAvailable, value: 1 }
";

#[test]
fn two_groups_render_disjoint_workloads_services_memberships_and_policies() {
    let rendered = render(TWO_GROUPS);
    let groups = [
        ("billing", "plane/data/zone/billing/*", 3),
        ("people", "plane/data/zone/people/*", 2),
    ];
    for (name, selector, replicas) in groups {
        let base = format!("permguard-data-plane-{name}");
        let workload = rendered.get("StatefulSet", &base);
        assert_eq!(
            workload["spec"]["replicas"], replicas,
            "{name}: its own scale"
        );
        assert_eq!(labels(workload)["permguard.com/group"], name);
        let mine = &workload["spec"]["selector"]["matchLabels"];
        assert!(selects(mine, pod_labels(workload)));

        // Its Service, its NetworkPolicy and its budget select its pods and no other group's.
        let service = &rendered.get("Service", &base)["spec"]["selector"];
        let policy = &rendered.get("NetworkPolicy", &base)["spec"]["podSelector"]["matchLabels"];
        let budget = &rendered.get("PodDisruptionBudget", &base)["spec"]["selector"]["matchLabels"];
        for (other, _, _) in groups {
            let theirs =
                pod_labels(rendered.get("StatefulSet", &format!("permguard-data-plane-{other}")));
            let same = other == name;
            assert_eq!(
                selects(service, theirs),
                same,
                "{name}'s Service and {other}'s pods"
            );
            assert_eq!(
                selects(policy, theirs),
                same,
                "{name}'s policy and {other}'s pods"
            );
            assert_eq!(
                selects(budget, theirs),
                same,
                "{name}'s budget and {other}'s pods"
            );
        }

        // The policy admits the group's listener flows and nothing else.
        let rules = rendered.get("NetworkPolicy", &base)["spec"]["ingress"].clone();
        assert_eq!(
            rules,
            json!([
                { "ports": [{ "port": 7443, "protocol": "TCP" }] },
                { "ports": [{ "port": 5443, "protocol": "TCP" }] }
            ])
        );

        // Its membership: exactly its selector, on every task.
        let membership = rendered.get("ConfigMap", &format!("{base}-membership"));
        assert_eq!(membership["data"]["selector"], selector);
        let tasks: Value =
            serde_json::from_str(membership["data"]["tasks.json"].as_str().unwrap()).unwrap();
        for task in tasks.as_array().unwrap() {
            assert_eq!(task["selector"], selector, "{name}: {task}");
        }
    }
    // One public Service per group, and none shared: no Service named after the Plane alone.
    assert!(!rendered.has("Service", "permguard-data-plane"));
    assert!(!rendered.has("StatefulSet", "permguard-data-plane"));
}

#[test]
fn the_host_volume_is_a_directory_inside_the_mount_claimed_by_every_pod() {
    let rendered = render(TWO_GROUPS);
    let container = &rendered.get("StatefulSet", "permguard-data-plane-billing")["spec"]["template"]
        ["spec"]["containers"][0];
    let mount = container["volumeMounts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|mount| mount["name"] == "state")
        .unwrap();
    assert_eq!(mount["mountPath"], "/var/lib/permguard");
    // The environment is read over the file, and the image names the mount: both say the subdirectory.
    let env = container["env"].as_array().unwrap();
    assert!(env.contains(&json!({
        "name": "PERMGUARD_WORKING_DIR",
        "value": "/var/lib/permguard/volume"
    })));
    assert_eq!(
        rendered.config("permguard-data-plane-billing")["working_dir"],
        "/var/lib/permguard/volume"
    );
    // Before every start, the orchestrator's claim moves forward, on that same directory.
    let init = &rendered.get("StatefulSet", "permguard-data-plane-billing")["spec"]["template"]["spec"]
        ["initContainers"];
    assert_eq!(init.as_array().unwrap().len(), 1);
    assert_eq!(
        init[0]["args"],
        json!([
            "volume",
            "claim",
            "--volume",
            "/var/lib/permguard/volume",
            "--next",
            "--create"
        ])
    );
    assert_eq!(
        init[0]["volumeMounts"][0]["mountPath"],
        "/var/lib/permguard"
    );
    assert_eq!(init[0]["image"], container["image"]);
}

#[test]
fn group_names_are_labels_and_object_names_only() {
    let rendered = render(TWO_GROUPS);
    let mut config = rendered.config("permguard-data-plane-billing");
    // The group's Service is where it is reached, and the only place its name appears.
    let advertised = config["dataPlane"]["public"]["http"]
        .as_object_mut()
        .unwrap()
        .remove("advertised_url")
        .unwrap();
    assert_eq!(advertised, "https://permguard-data-plane-billing:7443");
    // Otherwise the configuration never names the group: identity is the Host's, from its volume.
    let text = serde_json::to_string(&config).unwrap();
    assert!(!text.contains("billing"), "{text}");
    assert!(!text.contains("host_id"), "{text}");
}

#[test]
fn replicas_of_a_group_share_one_configuration() {
    let rendered = render(TWO_GROUPS);
    let workload = rendered.get("StatefulSet", "permguard-data-plane-billing");
    let volumes = workload["spec"]["template"]["spec"]["volumes"]
        .as_array()
        .unwrap();
    let config = volumes
        .iter()
        .find(|volume| volume["name"] == "config")
        .unwrap();
    assert_eq!(config["configMap"]["name"], "permguard-data-plane-billing");
    // No instance value: the pod template has no per-replica environment or argument.
    let container = &workload["spec"]["template"]["spec"]["containers"][0];
    assert_eq!(container["args"], json!(["/etc/permguard/config.yml"]));
}

#[test]
fn every_group_renders_its_assurance_profile() {
    let rendered = render(
        "\
dataPlane:
  groups:
    - name: lab
      selector: plane/data/zone/lab/*
      assurance: { profile: development }
      evidence: { mode: disabled }
      persistence: { enabled: false }
    - name: serving
      selector: plane/data/zone/serving/*
",
    );
    for (group, profile) in [("lab", "development"), ("serving", "production")] {
        let base = format!("permguard-data-plane-{group}");
        assert_eq!(rendered.config(&base)["assurance"]["profile"], profile);
        let kind = if group == "lab" {
            "Deployment"
        } else {
            "StatefulSet"
        };
        let workload = rendered.get(kind, &base);
        assert_eq!(
            pod_labels(workload)["permguard.com/assurance-profile"],
            profile
        );
    }
    // The control plane states its profile too.
    assert_eq!(
        rendered.config("permguard-control-plane")["assurance"]["profile"],
        "production"
    );
}

#[test]
fn a_persistent_group_is_a_statefulset_with_one_claim_template_and_retained_claims() {
    let rendered = render(TWO_GROUPS);
    let workload = rendered.get("StatefulSet", "permguard-data-plane-billing");
    let templates = workload["spec"]["volumeClaimTemplates"].as_array().unwrap();
    assert_eq!(
        templates.len(),
        1,
        "one claim per replica, from one template"
    );
    assert_eq!(templates[0]["metadata"]["name"], "state");
    assert_eq!(
        workload["spec"]["persistentVolumeClaimRetentionPolicy"],
        json!({ "whenScaled": "Retain", "whenDeleted": "Retain" })
    );
    assert_eq!(
        workload["spec"]["serviceName"],
        "permguard-data-plane-billing-headless"
    );
    // Each replica's name reaches its operations surface, never the public port: that is routed
    // by the group's Service to ready replicas alone.
    let headless = rendered.get("Service", "permguard-data-plane-billing-headless");
    assert_eq!(headless["spec"]["clusterIP"], "None");
    let ports: Vec<&Value> = headless["spec"]["ports"]
        .as_array()
        .unwrap()
        .iter()
        .collect();
    assert_eq!(ports.len(), 1);
    assert_eq!(ports[0]["name"], "telemetry");
    // The state volume is the claim, never an emptyDir beside it.
    let volumes = workload["spec"]["template"]["spec"]["volumes"]
        .as_array()
        .unwrap();
    assert!(volumes.iter().all(|volume| volume["name"] != "state"));
    assert!(rendered.all("PersistentVolumeClaim").is_empty());
}

#[test]
fn read_write_once_pod_from_production_where_the_cluster_supports_it() {
    let modes = |values: &str, kube: &str| {
        let rendered = render_with(values, &["--kube-version", kube]).unwrap();
        rendered.get("StatefulSet", "permguard-data-plane-billing")["spec"]["volumeClaimTemplates"]
            [0]["spec"]["accessModes"]
            .clone()
    };
    assert_eq!(modes(TWO_GROUPS, "1.31.0"), json!(["ReadWriteOncePod"]));
    // Before the mode is generally available, the exclusive single-node mode.
    assert_eq!(modes(TWO_GROUPS, "1.28.0"), json!(["ReadWriteOnce"]));
    let development = "\
dataPlane:
  groups:
    - name: billing
      selector: plane/data/*
      assurance: { profile: development }
";
    assert_eq!(modes(development, "1.31.0"), json!(["ReadWriteOnce"]));
    // Storage that does not offer it is stated by the group.
    let stated = "\
dataPlane:
  groups:
    - name: billing
      selector: plane/data/*
      persistence: { accessModes: [ReadWriteOnce] }
";
    assert_eq!(modes(stated, "1.31.0"), json!(["ReadWriteOnce"]));
}

#[test]
fn a_shared_access_mode_is_refused() {
    for mode in ["ReadWriteMany", "ReadOnlyMany"] {
        refused(
            &format!(
                "\
dataPlane:
  groups:
    - name: billing
      selector: plane/data/*
      persistence: {{ accessModes: [{mode}] }}
"
            ),
            "one volume has one writer",
        );
    }
}

#[test]
fn the_prestop_hook_requests_a_drain_inside_one_grace_budget() {
    let rendered = render(
        "\
dataPlane:
  groups:
    - name: billing
      selector: plane/data/*
      shutdown: { timeoutSeconds: 40, drainTimeoutSeconds: 32 }
",
    );
    let pod =
        &rendered.get("StatefulSet", "permguard-data-plane-billing")["spec"]["template"]["spec"];
    let container = &pod["containers"][0];
    // The hook asks for the drain and returns: it runs inside the server's container, which ends
    // with the server.
    assert_eq!(
        container["lifecycle"]["preStop"]["exec"]["command"],
        json!(["/usr/local/bin/permguard", "drain"])
    );
    // One budget: the drain starts when the hook asks, and the grace period is the shutdown's 40
    // seconds plus the signal's.
    assert_eq!(pod["terminationGracePeriodSeconds"], 45);
    let config = rendered.config("permguard-data-plane-billing");
    assert_eq!(config["shutdown"]["timeout"], "40s");
    assert_eq!(config["shutdown"]["drain_timeout"], "32s");
}

#[test]
fn a_drain_budget_that_leaves_no_time_to_release_is_refused() {
    refused(
        "\
dataPlane:
  groups:
    - name: billing
      selector: plane/data/*
      shutdown: { timeoutSeconds: 30, drainTimeoutSeconds: 30 }
",
        "drainTimeoutSeconds",
    );
}

#[test]
fn a_stateless_group_is_a_deployment_only_without_evidence_or_history() {
    let rendered = render(
        "\
dataPlane:
  groups:
    - name: edge
      selector: plane/data/*
      assurance: { profile: development }
      evidence: { mode: disabled }
      persistence: { enabled: false }
",
    );
    let workload = rendered.get("Deployment", "permguard-data-plane-edge");
    let volumes = workload["spec"]["template"]["spec"]["volumes"]
        .as_array()
        .unwrap();
    let state = volumes
        .iter()
        .find(|volume| volume["name"] == "state")
        .unwrap();
    assert!(state.get("emptyDir").is_some());
    let log = &rendered.config("permguard-data-plane-edge")["dataPlane"]["decisions"]["log"];
    assert_eq!(
        log["enabled"], "false",
        "discovery says evidence is disabled"
    );
}

#[test]
fn a_required_stream_without_persistent_storage_is_refused() {
    refused(
        "\
dataPlane:
  groups:
    - name: edge
      selector: plane/data/*
      assurance: { profile: development }
      evidence: { mode: required }
      persistence: { enabled: false }
",
        "without persistent storage",
    );
    refused(
        "\
dataPlane:
  groups:
    - name: edge
      selector: plane/data/*
      assurance: { profile: development }
      evidence: { mode: disabled }
      persistence: { enabled: false }
      extraConfig:
        dataPlane: { events: { enabled: \"true\" } }
        experimental: { dogwood: { enabled: \"true\" } }
",
        "the temporal interface with ephemeral state",
    );
}

#[test]
fn evidence_modes_follow_the_group_profile() {
    let log = |profile: &str, mode: &str| {
        let rendered = render(&format!(
            "\
dataPlane:
  groups:
    - name: billing
      selector: plane/data/*
      assurance: {{ profile: {profile} }}
      evidence: {{ mode: {mode} }}
"
        ));
        rendered.config("permguard-data-plane-billing")["dataPlane"]["decisions"]["log"].clone()
    };
    // The decision log's own vocabulary (WP-6.1): `mode`, and `enabled` agreeing with it.
    assert_eq!(
        log("production", "required"),
        json!({ "enabled": "true", "mode": "required" })
    );
    assert_eq!(
        log("development", "disabled"),
        json!({ "enabled": "false", "mode": "disabled" })
    );
    for profile in ["production", "regulated"] {
        refused(
            &format!(
                "\
dataPlane:
  groups:
    - name: billing
      selector: plane/data/*
      assurance: {{ profile: {profile} }}
      evidence: {{ mode: disabled }}
"
            ),
            "evidence mode",
        );
    }
    // `best-effort` is refused at every profile: the server does not serve it yet.
    for profile in ["development", "production"] {
        refused(
            &format!(
                "\
dataPlane:
  groups:
    - name: billing
      selector: plane/data/*
      assurance: {{ profile: {profile} }}
      evidence: {{ mode: best-effort }}
"
            ),
            "does not serve",
        );
    }
    refused(
        "\
dataPlane:
  groups:
    - name: billing
      selector: plane/data/*
      evidence: { mode: unrecorded }
",
        "evidence.mode",
    );
    // The mode has one source: a log the configuration states otherwise is refused.
    for stated in ["on_full: open", "mode: disabled", "enabled: \"false\""] {
        refused(
            &format!(
                "\
dataPlane:
  groups:
    - name: billing
      selector: plane/data/*
      extraConfig:
        dataPlane: {{ decisions: {{ log: {{ {stated} }} }} }}
"
            ),
            "two sources",
        );
    }
}

#[test]
fn unsafe_claim_deletion_is_refused() {
    for policy in ["whenScaled", "whenDeleted"] {
        refused(
            &format!(
                "\
dataPlane:
  groups:
    - name: billing
      selector: plane/data/*
      persistence: {{ retention: {{ {policy}: Delete }} }}
"
            ),
            "deletion is a separate verified operation",
        );
    }
}

#[test]
fn autoscaling_a_persistent_group_is_refused_without_drain_recovery() {
    refused(
        "\
dataPlane:
  groups:
    - name: billing
      selector: plane/data/*
      autoscaling: { enabled: true, minReplicas: 2, maxReplicas: 6 }
",
        "drain recovery",
    );
}

#[test]
fn each_group_has_its_own_disruption_budget_and_autoscaler() {
    let rendered = render(
        "\
dataPlane:
  groups:
    - name: front
      selector: plane/data/zone/front/*
      assurance: { profile: development }
      evidence: { mode: disabled }
      persistence: { enabled: false }
      autoscaling: { enabled: true, minReplicas: 2, maxReplicas: 9 }
    - name: back
      selector: plane/data/zone/back/*
      replicas: 4
      podDisruptionBudget: { budget: minAvailable, value: 3 }
",
    );
    let hpa = rendered.get("HorizontalPodAutoscaler", "permguard-data-plane-front");
    assert_eq!(hpa["spec"]["scaleTargetRef"]["kind"], "Deployment");
    assert_eq!(
        hpa["spec"]["scaleTargetRef"]["name"],
        "permguard-data-plane-front"
    );
    assert_eq!(hpa["spec"]["maxReplicas"], 9);
    assert!(!rendered.has("HorizontalPodAutoscaler", "permguard-data-plane-back"));
    // An autoscaled workload leaves the replica count to the autoscaler.
    assert!(
        rendered.get("Deployment", "permguard-data-plane-front")["spec"]
            .get("replicas")
            .is_none()
    );
    assert_eq!(
        rendered.get("PodDisruptionBudget", "permguard-data-plane-back")["spec"]["minAvailable"],
        3
    );
    assert_eq!(
        rendered.get("PodDisruptionBudget", "permguard-data-plane-front")["spec"]["maxUnavailable"],
        1
    );
}

#[test]
fn every_group_has_distinct_probes_and_spreads_its_replicas() {
    let rendered = render(TWO_GROUPS);
    let workload = rendered.get("StatefulSet", "permguard-data-plane-billing");
    let container = &workload["spec"]["template"]["spec"]["containers"][0];
    for probe in ["startupProbe", "readinessProbe", "livenessProbe"] {
        assert!(container.get(probe).is_some(), "{probe}");
    }
    assert_ne!(container["readinessProbe"], container["livenessProbe"]);
    let anti = &workload["spec"]["template"]["spec"]["affinity"]["podAntiAffinity"]["preferredDuringSchedulingIgnoredDuringExecution"]
        [0]["podAffinityTerm"]["labelSelector"]["matchLabels"];
    assert_eq!(anti["permguard.com/group"], "billing");
}

#[test]
fn the_membership_manifest_names_exactly_the_group_selector_and_its_tasks() {
    let rendered = render(
        "\
dataPlane:
  groups:
    - name: billing
      selector: plane/data/zone/billing/*
      tasks:
        - type: policy.mirror
          selector: plane/data/zone/billing/ledger/main
",
    );
    let membership = rendered.get("ConfigMap", "permguard-data-plane-billing-membership");
    assert_eq!(membership["data"]["selector"], "plane/data/zone/billing/*");
    assert_eq!(membership["data"]["min_assurance"], "production");
    let tasks: Value =
        serde_json::from_str(membership["data"]["tasks.json"].as_str().unwrap()).unwrap();
    let by_type: BTreeMap<String, &Value> = tasks
        .as_array()
        .unwrap()
        .iter()
        .map(|task| (task["type"].as_str().unwrap().to_owned(), task))
        .collect();
    assert_eq!(
        by_type.keys().cloned().collect::<Vec<_>>(),
        ["decisions.ship", "policy.mirror"],
        "required evidence ships decisions; no temporal history, no events"
    );
    let mirror = by_type["policy.mirror"];
    assert_eq!(mirror["selector"], "plane/data/zone/billing/ledger/main");
    assert_eq!(mirror["provider_role"], "coordinator");
    assert_eq!(mirror["consumer_role"], "member");
    assert_eq!(mirror["version"], 1);
    assert_eq!(mirror["resource_types"], json!(["policy"]));
    let ship = by_type["decisions.ship"];
    assert_eq!(ship["selector"], "plane/data/zone/billing/*");
    assert_eq!(ship["provider_role"], "member");
    assert_eq!(ship["consumer_role"], "coordinator");
    assert_eq!(ship["required"], true);
    assert_eq!(
        ship["limits"],
        json!({
            "max_body_bytes": 1_048_576,
            "max_concurrency": 4,
            "max_rate_per_minute": 600,
            "max_batch_records": 1000,
            "retention_seconds": 86_400
        })
    );
    // The task contract fields, and nothing else.
    for task in tasks.as_array().unwrap() {
        let mut keys: Vec<&str> = task
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "assurance_requirements",
                "consumer_role",
                "limits",
                "provider_role",
                "required",
                "resource_types",
                "selector",
                "task_id",
                "type",
                "version"
            ]
        );
    }
}

#[test]
fn a_temporal_group_ships_its_events() {
    let rendered = render(
        "\
dataPlane:
  groups:
    - name: history
      selector: plane/data/*
      replicas: 1
      extraConfig:
        dataPlane: { events: { enabled: \"true\" } }
        experimental: { dogwood: { enabled: \"true\" } }
",
    );
    let membership = rendered.get("ConfigMap", "permguard-data-plane-history-membership");
    let tasks = membership["data"]["tasks.json"].as_str().unwrap();
    assert!(tasks.contains("\"events.ship\""), "{tasks}");
}

#[test]
fn a_temporal_group_replicates_only_with_a_declared_shared_consistency() {
    let temporal = |replicas: u32, pull: &str| {
        format!(
            "\
dataPlane:
  groups:
    - name: history
      selector: plane/data/*
      replicas: {replicas}
      extraConfig:
        dataPlane: {{ events: {{ enabled: \"true\"{pull} }} }}
        experimental: {{ dogwood: {{ enabled: \"true\" }} }}
"
        )
    };
    refused(&temporal(3, ""), "declared shared consistency");
    refused(
        &temporal(3, ", pull: { mode: local }"),
        "declared shared consistency",
    );
    let rendered = render(&temporal(
        3,
        ", pull: { mode: shared-eventual, ledgers: [{ zone: acme, ledger: main }] }",
    ));
    let workload = rendered.get("StatefulSet", "permguard-data-plane-history");
    assert_eq!(
        workload["spec"]["replicas"], 3,
        "history never forces one replica"
    );
    // A single temporal replica needs no declaration.
    render(&temporal(1, ""));
}

#[test]
fn duplicate_group_names_are_refused() {
    refused(
        "\
dataPlane:
  groups:
    - name: billing
      selector: plane/data/zone/a/*
    - name: billing
      selector: plane/data/zone/b/*
",
        "duplicate group name",
    );
    for name in ["Billing", "-billing", "billing_eu", ""] {
        refused(
            &format!(
                "\
dataPlane:
  groups:
    - name: \"{name}\"
      selector: plane/data/*
"
            ),
            "is not a group name",
        );
    }
    refused(
        "\
dataPlane:
  groups:
    - name: a-group-name-long-enough-to-overflow-the-statefulset-name
      selector: plane/data/*
",
        "too long",
    );
}

#[test]
fn overlapping_group_selectors_are_refused() {
    for (first, second) in [
        ("plane/data/*", "plane/data/zone/people/*"),
        (
            "plane/data/zone/people/*",
            "plane/data/zone/people/ledger/main",
        ),
        ("plane/data/zone/people", "plane/data/zone/people"),
        (
            "plane/data/zone/people/ledger/main",
            "plane/data/zone/people/*",
        ),
    ] {
        refused(
            &format!(
                "\
dataPlane:
  groups:
    - name: first
      selector: {first}
    - name: second
      selector: {second}
"
            ),
            "overlap",
        );
    }
    // A node without `/*` and its descendants are disjoint: the exact form covers the node alone.
    render(
        "\
dataPlane:
  groups:
    - name: first
      selector: plane/data/zone/people
    - name: second
      selector: plane/data/zone/people/ledger/main
",
    );
}

#[test]
fn a_task_selector_wider_than_its_group_is_refused() {
    for task in [
        "plane/data/*",
        "plane/data/zone/billing",
        "plane/data/zone/other/*",
    ] {
        refused(
            &format!(
                "\
dataPlane:
  groups:
    - name: billing
      selector: plane/data/zone/billing/ledger/main
      tasks:
        - type: policy.mirror
          selector: {task}
"
            ),
            "wider than its membership",
        );
    }
    refused(
        "\
dataPlane:
  groups:
    - name: billing
      selector: plane/data/*
      tasks:
        - type: policy.push
",
        "is not a membership task",
    );
}

#[test]
fn a_selector_outside_the_data_plane_is_refused() {
    for selector in [
        "host",
        "host/*",
        "plane/control/*",
        "plane/control/zone/acme",
    ] {
        refused(
            &format!(
                "\
dataPlane:
  groups:
    - name: billing
      selector: \"{selector}\"
"
            ),
            "outside the data plane",
        );
    }
}

#[test]
fn a_malformed_group_selector_is_refused() {
    for selector in [
        "plane/data/zone/*/ledger/main",
        "plane/data/ledger/main",
        "plane/data/zone/a b",
        "plane/data/zone//*",
        "",
    ] {
        refused(
            &format!(
                "\
dataPlane:
  groups:
    - name: billing
      selector: \"{selector}\"
"
            ),
            "is not a selector",
        );
    }
}

const PKCS11: &str = "
      assurance:
        profile: regulated
        custody:
          provider: pkcs11
          pkcs11: { module: /usr/lib/softhsm/libsofthsm2.so, tokenLabel: permguard, pinRef: hsm-pin }
";

#[test]
fn a_regulated_group_without_hsm_or_kms_custody_is_refused() {
    let group = |assurance: &str| {
        format!(
            "\
dataPlane:
  groups:
    - name: vault
      selector: plane/data/*
{assurance}"
        )
    };
    refused(
        &group("      assurance: { profile: regulated }\n"),
        "HSM or KMS",
    );
    refused(
        &group("      assurance: { profile: regulated, custody: { provider: file } }\n"),
        "HSM or KMS",
    );
    refused(
        &group("      assurance: { profile: regulated, custody: { provider: pkcs11 } }\n"),
        "pkcs11.module, pkcs11.tokenLabel and pkcs11.pinRef",
    );
    refused(
        &group(
            "      assurance: { profile: regulated, custody: { provider: pkcs11, pkcs11: { module: /m.so, pinRef: p } } }\n",
        ),
        "pkcs11.tokenLabel",
    );
    refused(
        &group(
            "      assurance: { profile: regulated, custody: { provider: kms, kms: { address: https://vault:8200 } } }\n",
        ),
        "kms.tokenRef",
    );
    refused(
        &group(
            "      assurance: { profile: regulated, custody: { provider: kms, kms: { address: http://vault:8200, tokenRef: t } } }\n",
        ),
        "`https://`",
    );
    // A ring overridden below the Host's custody is refused the same way.
    refused(
        &group(
            "      assurance:\n        profile: regulated\n        custody:\n          provider: pkcs11\n          pkcs11: { module: /m.so, tokenLabel: t, pinRef: p }\n          operations: file\n",
        ),
        "host.operations",
    );
    // Stated through the environment instead of the values, it is still read.
    refused(
        &format!(
            "{}      extraEnv: [{{ name: PERMGUARD_KEYS_IDENTITY_CUSTODY, value: file }}]\n",
            group(PKCS11)
        ),
        "host.identity",
    );
}

#[test]
fn a_regulated_group_with_pkcs11_or_kms_custody_renders() {
    let rendered = render_verified(&format!(
        "\
dataPlane:
  groups:
    - name: vault
      selector: plane/data/*{PKCS11}"
    ));
    let config = rendered.config("permguard-data-plane-vault");
    assert_eq!(config["assurance"]["profile"], "regulated");
    assert_eq!(config["operations"]["keys"]["custody"], "pkcs11");
    assert_eq!(
        config["operations"]["keys"]["pkcs11"],
        json!({
            "module": "/usr/lib/softhsm/libsofthsm2.so",
            "token_label": "permguard",
            "pin_ref": "hsm-pin"
        })
    );
    let rendered = render_verified(
        "\
dataPlane:
  groups:
    - name: vault
      selector: plane/data/*
      assurance:
        profile: regulated
        custody:
          provider: file
          identity: kms
          operations: pkcs11
          kms: { address: \"https://vault:8200\", tokenRef: vault-token }
          pkcs11: { module: /usr/lib/softhsm/libsofthsm2.so, tokenLabel: permguard, pinRef: hsm-pin }
",
    );
    let keys = &rendered.config("permguard-data-plane-vault")["operations"]["keys"];
    assert_eq!(keys["rings"]["host.identity"]["custody"], "kms");
    assert_eq!(keys["rings"]["host.operations"]["custody"], "pkcs11");
    assert_eq!(keys["kms"]["token_ref"], "vault-token");
    // TS-4: `host.operations` opens a decision stream's run while the decision waits, and a remote
    // KMS is not allowed on the decision path: a Data Plane that records evidence refuses it.
    refused(
        "\
dataPlane:
  groups:
    - name: vault
      selector: plane/data/*
      assurance:
        profile: regulated
        custody:
          provider: file
          identity: kms
          operations: kms
          kms: { address: \"https://vault:8200\", tokenRef: vault-token }
",
        "decision path",
    );
    // The all-in-one records decisions through its configuration, and is refused the same way.
    refused(
        "\
allInOne:
  enabled: true
  tls: { secretName: aio-tls }
  persistence: { enabled: true }
  assurance:
    profile: production
    custody:
      provider: file
      operations: kms
      kms: { address: \"https://vault:8200\", tokenRef: vault-token }
  extraConfig: { dataPlane: { decisions: { log: { enabled: \"true\" } } } }
controlPlane: { enabled: false }
dataPlane: { enabled: false }
",
        "decision path",
    );
}

#[test]
fn a_regulated_group_refuses_tls_relaxations_and_lesser_evidence() {
    let regulated = |extra: &str| {
        let tls = if extra.contains("TERMINATED") {
            "  tls: { secretName: \"\", terminatedUpstream: true }\n"
        } else {
            ""
        };
        format!(
            "\
dataPlane:
{tls}  groups:
    - name: vault
      selector: plane/data/*{PKCS11}{extra}"
        )
    };
    refused(&regulated("      # TERMINATED\n"), "terminated upstream");
    refused(
        &regulated("      extraConfig: { tls: { min_version: \"1.2\" } }\n"),
        "TLS 1.3 only",
    );
    refused(
        &regulated(
            "      extraEnv: [{ name: PERMGUARD_PUBLIC_HTTP_TLS_MIN_VERSION, value: v1.2 }]\n",
        ),
        "TLS 1.3 only",
    );
    refused(
        &regulated("      extraConfig: { experimental: { dogwood: { enabled: \"true\" } } }\n"),
        "experimental",
    );
}

#[test]
fn development_custody_in_a_production_group_is_refused() {
    refused(
        "\
dataPlane:
  groups:
    - name: billing
      selector: plane/data/*
      assurance: { custody: { provider: development } }
",
        "development` custody",
    );
    refused(
        "\
dataPlane:
  groups:
    - name: billing
      selector: plane/data/*
      extraConfig: { operations: { keys: { custody: development } } }
",
        "development` custody",
    );
    // The control plane is held to the same rule.
    refused(
        "\
controlPlane:
  extraConfig: { operations: { keys: { custody: development } } }
",
        "development` custody",
    );
    // Where the profile is `development`, it is what it is for.
    render(
        "\
dataPlane:
  groups:
    - name: billing
      selector: plane/data/*
      assurance: { profile: development, custody: { provider: development } }
",
    );
}

#[test]
fn an_unknown_profile_is_refused() {
    refused(
        "\
dataPlane:
  groups:
    - name: billing
      selector: plane/data/*
      assurance: { profile: strict }
",
        "is not an assurance profile",
    );
}

#[test]
fn the_legacy_single_group_translates_into_groups_zero() {
    let rendered = render(
        "\
dataPlane:
  replicaCount: 2
  podDisruptionBudget: { budget: minAvailable, value: 1 }
",
    );
    let workload = rendered.get("StatefulSet", "permguard-data-plane-default");
    assert_eq!(workload["spec"]["replicas"], 2);
    assert_eq!(labels(workload)["permguard.com/group"], "default");
    let membership = rendered.get("ConfigMap", "permguard-data-plane-default-membership");
    assert_eq!(membership["data"]["selector"], "plane/data/*");
    assert_eq!(
        rendered.get("PodDisruptionBudget", "permguard-data-plane-default")["spec"]["minAvailable"],
        1
    );
    // The shipped defaults are the same single group.
    let defaults = render("{}\n");
    assert_eq!(
        defaults.get("StatefulSet", "permguard-data-plane-default")["spec"]["replicas"],
        3
    );
    assert_eq!(defaults.all("StatefulSet").len(), 1);
}

#[test]
fn legacy_values_beside_groups_are_refused() {
    for legacy in [
        "replicaCount: 2",
        "autoscaling: { enabled: false }",
        "persistence: { enabled: true }",
        "podDisruptionBudget: { enabled: true }",
    ] {
        refused(
            &format!(
                "\
dataPlane:
  {legacy}
  groups:
    - name: billing
      selector: plane/data/*
"
            ),
            "two sources of truth",
        );
    }
}

#[test]
fn no_rendered_object_terminates_a_peer_session() {
    let rendered = render(TWO_GROUPS);
    // No Ingress, no Gateway, no mesh object that could terminate TLS in front of a Host.
    for kind in [
        "Ingress",
        "Gateway",
        "HTTPRoute",
        "TLSRoute",
        "VirtualService",
    ] {
        assert!(rendered.all(kind).is_empty(), "{kind}");
    }
    // Services pass TCP through.
    for service in rendered.all("Service") {
        for port in service["spec"]["ports"].as_array().unwrap() {
            assert_eq!(port["protocol"], "TCP", "{service}");
        }
    }
}

#[test]
fn the_shipped_values_files_render() {
    let production = std::fs::read_to_string(chart().join("values-production.yaml")).unwrap();
    // The production baseline verifies images (TD-4): it renders once a deployment names the
    // verifier and the digests, as `ci/image-verification.yaml` does with placeholders.
    let error = render_with(&production, &[])
        .err()
        .expect("refused as it ships");
    assert!(
        error.contains("imageVerification.verifier.image"),
        "{error}"
    );
    let filled = chart().join("ci/image-verification.yaml");
    let rendered = render_with(&production, &["-f", filled.to_str().unwrap()])
        .unwrap_or_else(|error| panic!("the filled baseline renders: {error}"));
    let groups = rendered.all("StatefulSet");
    assert!(!groups.is_empty());
    for workload in groups {
        assert_eq!(
            workload["spec"]["persistentVolumeClaimRetentionPolicy"]["whenScaled"],
            "Retain"
        );
        let pod = &workload["spec"]["template"]["spec"];
        assert_eq!(pod["initContainers"][0]["name"], "verify-image");
    }
}

/// Placeholder digests, as a deployment states them (TD-4).
const DIGEST: &str = "sha256:1111111111111111111111111111111111111111111111111111111111111111";

fn verified(extra: &str) -> String {
    format!(
        "\
imageVerification:
  enabled: true
  verifier: {{ image: \"registry.example/verifier@{DIGEST}\" }}
  tokenSecret: {{ name: gh-token }}
controlPlane:
  digest: \"{DIGEST}\"
  hostListener: {{ enabled: true, tls: {{ secretName: control-plane-host }} }}
dataPlane:
  digest: \"{DIGEST}\"
  hostListener: {{ enabled: true, tls: {{ secretName: data-plane-host }} }}
  drainController: {{ enabled: true, digest: \"{DIGEST}\", tls: {{ secretName: reclaim-operator }} }}
  groups:
    - name: billing
      selector: plane/data/zone/billing/*
    - name: edge
      selector: plane/data/zone/edge/*
      assurance: {{ profile: development }}
      evidence: {{ mode: disabled }}
      persistence: {{ enabled: false }}
{extra}"
    )
}

/// Asserts `pod` starts with the verifier, which verifies the image every other container runs,
/// by digest, under the release's provenance policy.
fn starts_verified(what: &str, pod: &Value) {
    let init = pod["initContainers"].as_array().expect("init containers");
    let verify = &init[0];
    assert_eq!(verify["name"], "verify-image", "{what}");
    assert_eq!(
        verify["image"],
        format!("registry.example/verifier@{DIGEST}"),
        "{what}"
    );
    let image = pod["containers"][0]["image"].as_str().expect("an image");
    assert!(image.ends_with(&format!("@{DIGEST}")), "{what}: {image}");
    for other in init
        .iter()
        .skip(1)
        .chain(pod["containers"].as_array().unwrap())
    {
        assert_eq!(
            other["image"], image,
            "{what}: every Permguard container runs it"
        );
    }
    assert_eq!(
        verify["args"],
        json!([
            "attestation",
            "verify",
            format!("oci://{image}"),
            "--repo",
            "permguard/permguard",
            "--signer-workflow",
            "permguard/permguard/.github/workflows/release-build.yml",
            "--source-ref",
            format!("refs/tags/v{}", app_version()),
            "--deny-self-hosted-runners"
        ]),
        "{what}"
    );
    assert_eq!(
        verify["env"][0],
        json!({ "name": "GH_TOKEN", "valueFrom": { "secretKeyRef": { "name": "gh-token", "key": "token" } } }),
        "{what}: the token from its Secret"
    );
    assert_eq!(
        verify["securityContext"]["readOnlyRootFilesystem"], true,
        "{what}"
    );
    assert!(
        pod["volumes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|volume| volume["name"] == "verify-image-home"),
        "{what}: the verifier's home"
    );
}

#[test]
fn image_verification_runs_first_in_every_permguard_pod_on_the_digest_it_runs() {
    let rendered = render(&verified(""));
    starts_verified(
        "control plane",
        &rendered.get("Deployment", "permguard-control-plane")["spec"]["template"]["spec"],
    );
    starts_verified(
        "stateful group",
        &rendered.get("StatefulSet", "permguard-data-plane-billing")["spec"]["template"]["spec"],
    );
    starts_verified(
        "stateless group",
        &rendered.get("Deployment", "permguard-data-plane-edge")["spec"]["template"]["spec"],
    );
    starts_verified(
        "drain controller",
        &rendered.get("CronJob", "permguard-data-plane-billing-reclaim")["spec"]["jobTemplate"]["spec"]
            ["template"]["spec"],
    );
    let template =
        rendered.get("ConfigMap", "permguard-data-plane-billing-drain-job")["data"]["job.json"]
            .as_str()
            .unwrap()
            .replace("__CLAIM__", "state-permguard-data-plane-billing-2")
            .replace("__JOB__", "permguard-data-plane-billing-drain-2")
            .replace("__ORDINAL__", "2");
    let job: Value = serde_json::from_str(&template).expect("the template is JSON");
    starts_verified("drain Job", &job["spec"]["template"]["spec"]);
    // The claim follows the verification, never precedes it.
    let stateful =
        &rendered.get("StatefulSet", "permguard-data-plane-billing")["spec"]["template"]["spec"];
    assert_eq!(stateful["initContainers"][1]["name"], "claim");

    let all_in_one = render(&format!(
        "\
imageVerification:
  enabled: true
  verifier: {{ image: \"registry.example/verifier@{DIGEST}\" }}
  tokenSecret: {{ name: gh-token }}
allInOne: {{ enabled: true, digest: \"{DIGEST}\", tls: {{ secretName: aio-tls }} }}
controlPlane: {{ enabled: false }}
dataPlane: {{ enabled: false }}
"
    ));
    starts_verified(
        "all-in-one",
        &all_in_one.get("Deployment", "permguard-all-in-one")["spec"]["template"]["spec"],
    );
}

#[test]
fn image_verification_is_off_by_default_and_changes_nothing() {
    let rendered = render("");
    for kind in ["Deployment", "StatefulSet"] {
        for workload in rendered.all(kind) {
            let pod = &workload["spec"]["template"]["spec"];
            let names: Vec<&Value> = pod["initContainers"]
                .as_array()
                .map(|init| init.iter().map(|container| &container["name"]).collect())
                .unwrap_or_default();
            assert!(!names.contains(&&json!("verify-image")), "{names:?}");
            let image = pod["containers"][0]["image"].as_str().unwrap();
            assert!(image.ends_with(&format!(":{}", app_version())), "{image}");
        }
    }
}

#[test]
fn image_verification_refuses_a_tag_an_unpinned_verifier_or_no_token() {
    // A component without its digest: a tag resolved later is not what was verified.
    for component in ["controlPlane", "dataPlane", "dataPlane.drainController"] {
        let values = verified("").replace(
            &match component {
                "controlPlane" => format!("controlPlane:\n  digest: \"{DIGEST}\"\n"),
                "dataPlane" => format!("dataPlane:\n  digest: \"{DIGEST}\"\n"),
                _ => format!("enabled: true, digest: \"{DIGEST}\","),
            },
            &match component {
                "controlPlane" => "controlPlane:\n".to_owned(),
                "dataPlane" => "dataPlane:\n".to_owned(),
                _ => "enabled: true,".to_owned(),
            },
        );
        assert_ne!(values, verified(""), "{component}");
        refused(&values, &format!("{component}.digest is \"\""));
    }
    refused(
        &verified("").replace(&format!("verifier@{DIGEST}"), "verifier:2.98.0"),
        "name the verifier by digest",
    );
    refused(
        &verified("").replace(
            "tokenSecret: { name: gh-token }",
            "tokenSecret: { name: \"\" }",
        ),
        "imageVerification.tokenSecret.name is empty",
    );
    refused(
        &verified("").replace(
            &format!("controlPlane:\n  digest: \"{DIGEST}\""),
            "controlPlane:\n  digest: latest",
        ),
        "controlPlane.digest is \"latest\"",
    );
}

#[test]
fn a_regulated_workload_runs_only_verified_images() {
    let group = format!(
        "\
dataPlane:
  groups:
    - name: vault
      selector: plane/data/*{PKCS11}"
    );
    refused(
        &group,
        "the `regulated` profile runs only images verified before start",
    );
    let rendered = render_verified(&group);
    let pod =
        &rendered.get("StatefulSet", "permguard-data-plane-vault")["spec"]["template"]["spec"];
    assert_eq!(pod["initContainers"][0]["name"], "verify-image");
}

#[test]
fn the_blueprint_group_example_renders_as_written() {
    // The example of `11-architecture-deployment-conformance.md`, with selectors in the grammar
    // the Host reads (the example's `…/ledger/*` is no selector: see the blueprint question).
    // `autoscaling: { minReplicas, maxReplicas }` turns autoscaling on, and a group that keeps a
    // volume cannot autoscale before drain recovery: the example's second group is refused today.
    refused(
        "\
dataPlane:
  groups:
    - name: billing
      selector: plane/data/zone/018f/*
      replicas: 3
      service: { enabled: true }
      evidence: { mode: required }
      assurance: { profile: production }
      persistence: { enabled: true, retainOnScaleDown: true }
    - name: people
      selector: plane/data/zone/0190/*
      autoscaling: { minReplicas: 2, maxReplicas: 10 }
      evidence: { mode: required }
      assurance: { profile: production }
      persistence: { enabled: true, retainOnScaleDown: true }
",
        "drain recovery",
    );
    let rendered = render(
        "\
dataPlane:
  groups:
    - name: billing
      selector: plane/data/zone/018f/*
      replicas: 3
      persistence: { enabled: true, retainOnScaleDown: true }
    - name: edge
      selector: plane/data/zone/0190/*
      assurance: { profile: development }
      evidence: { mode: disabled }
      persistence: { enabled: false }
      autoscaling: { minReplicas: 2, maxReplicas: 10 }
",
    );
    assert_eq!(
        rendered.get("HorizontalPodAutoscaler", "permguard-data-plane-edge")["spec"]["maxReplicas"],
        10
    );
    // `enabled: false` keeps it off whatever the bounds say.
    let off = render(
        "\
dataPlane:
  groups:
    - name: edge
      selector: plane/data/*
      assurance: { profile: development }
      evidence: { mode: disabled }
      persistence: { enabled: false }
      autoscaling: { enabled: false, minReplicas: 2, maxReplicas: 10 }
",
    );
    assert!(off.all("HorizontalPodAutoscaler").is_empty());
    // The blueprint's `…/ledger/*` is refused as the Host refuses it.
    refused(
        "\
dataPlane:
  groups:
    - name: billing
      selector: plane/data/zone/018f/ledger/*
",
        "is not a selector",
    );
    refused(
        "\
dataPlane:
  groups:
    - name: billing
      selector: plane/data/*
      persistence: { retainOnScaleDown: false }
",
        "retainOnScaleDown",
    );
}

#[test]
fn a_key_a_group_does_not_know_is_refused() {
    refused(
        "\
dataPlane:
  groups:
    - name: billing
      selector: plane/data/*
      replica: 3
",
        "additional properties 'replica' not allowed",
    );
    refused(
        "\
dataPlane:
  groups:
    - name: billing
      selector: plane/data/*
      persistence: { retainOnScaledown: true }
",
        "additional properties 'retainOnScaledown' not allowed",
    );
}

#[test]
fn the_legacy_service_translates_and_is_refused_beside_groups() {
    let rendered = render("dataPlane:\n  service: { type: NodePort }\n");
    assert_eq!(
        rendered.get("Service", "permguard-data-plane-default")["spec"]["type"],
        "NodePort"
    );
    refused(
        "\
dataPlane:
  service: { type: NodePort }
  groups:
    - name: billing
      selector: plane/data/*
",
        "two sources of truth",
    );
}

#[test]
fn custody_references_are_checked_at_every_profile() {
    refused(
        "\
dataPlane:
  groups:
    - name: billing
      selector: plane/data/*
      assurance: { custody: { provider: pkcs11 } }
",
        "pkcs11.module",
    );
    refused(
        "\
dataPlane:
  groups:
    - name: billing
      selector: plane/data/*
      assurance: { custody: { identity: kms } }
",
        "kms.address and kms.tokenRef",
    );
    // Two sources of one custody are refused rather than one silently winning.
    refused(
        "\
dataPlane:
  groups:
    - name: billing
      selector: plane/data/*
      assurance: { custody: { provider: file } }
      extraConfig: { operations: { keys: { custody: pkcs11 } } }
",
        "two sources of the same custody",
    );
}

#[test]
fn a_regulated_host_is_not_served_in_development_mode() {
    refused(
        &format!(
            "\
developmentMode: true
dataPlane:
  groups:
    - name: vault
      selector: plane/data/*{PKCS11}"
        ),
        "not served in developmentMode",
    );
}

#[test]
fn an_unquoted_tls_minimum_is_read_too() {
    refused(
        &format!(
            "\
dataPlane:
  groups:
    - name: vault
      selector: plane/data/*{PKCS11}      extraConfig: {{ tls: {{ min_version: 1.2 }} }}
"
        ),
        "TLS 1.3 only",
    );
}

#[test]
fn a_descending_task_under_an_exact_membership_is_wider() {
    // The membership covers the zone node alone; a task over everything below it is wider.
    refused(
        "\
dataPlane:
  groups:
    - name: billing
      selector: plane/data/zone/billing
      tasks:
        - type: policy.mirror
          selector: plane/data/zone/billing/*
",
        "wider than its membership",
    );
    render(
        "\
dataPlane:
  groups:
    - name: billing
      selector: plane/data/zone/billing
      tasks:
        - type: policy.mirror
          selector: plane/data/zone/billing
",
    );
}

#[test]
fn development_custody_of_one_ring_is_refused_above_development() {
    for ring in ["identity", "operations"] {
        refused(
            &format!(
                "\
dataPlane:
  groups:
    - name: billing
      selector: plane/data/*
      assurance: {{ custody: {{ {ring}: development }} }}
"
            ),
            "development` custody",
        );
    }
}

#[test]
fn a_group_states_its_own_network_peers() {
    let rendered = render(
        "\
dataPlane:
  groups:
    - name: billing
      selector: plane/data/zone/billing/*
      networkPolicy:
        public: { from: [{ podSelector: { matchLabels: { app: billing-pep } } }] }
        telemetry: { from: [{ namespaceSelector: { matchLabels: { team: billing-ops } } }] }
    - name: people
      selector: plane/data/zone/people/*
",
    );
    let billing = &rendered.get("NetworkPolicy", "permguard-data-plane-billing")["spec"]["ingress"];
    assert_eq!(
        billing[0]["from"],
        json!([{ "podSelector": { "matchLabels": { "app": "billing-pep" } } }])
    );
    assert_eq!(
        billing[1]["from"],
        json!([{ "namespaceSelector": { "matchLabels": { "team": "billing-ops" } } }])
    );
    // The other group keeps the chart-wide peers: any.
    let people = &rendered.get("NetworkPolicy", "permguard-data-plane-people")["spec"]["ingress"];
    assert!(people[0].get("from").is_none() && people[1].get("from").is_none());
}

/// The values the drain controller needs (TD-2): the Host listeners and the controller's Secret.
const CONTROLLER: &str = "\
controlPlane:
  hostListener: { enabled: true, tls: { secretName: control-plane-host } }
dataPlane:
  hostListener: { enabled: true, tls: { secretName: data-plane-host } }
  drainController: { enabled: true, tls: { secretName: reclaim-operator } }
";

fn with_controller(groups: &str) -> String {
    format!("{CONTROLLER}{groups}")
}

const AUTOSCALED: &str = "  groups:
    - name: billing
      selector: plane/data/*
      autoscaling: { minReplicas: 2, maxReplicas: 6 }
      persistence:
        storageClass: csi-qualified
        takeover: { qualified: true, driver: ebs.csi.aws.com, storageClass: csi-qualified, evidence: \"qualification-2026-10-26\" }
";

#[test]
fn autoscaling_a_persistent_group_needs_the_controller_stabilization_and_qualified_takeover() {
    // Everything stated: it renders.
    render(&with_controller(AUTOSCALED));
    // Without the drain controller.
    refused(&format!("dataPlane:\n{AUTOSCALED}"), "drain recovery");
    // Without a qualified takeover, or with one of another storage class.
    for (from, to) in [
        ("qualified: true", "qualified: false"),
        ("evidence: \"qualification-2026-10-26\"", "evidence: \"\""),
        ("driver: ebs.csi.aws.com", "driver: \"\""),
    ] {
        refused(
            &with_controller(&AUTOSCALED.replace(from, to)),
            "takeover qualified",
        );
    }
    refused(
        &with_controller(&AUTOSCALED.replace(
            "storageClass: csi-qualified, evidence",
            "storageClass: other, evidence",
        )),
        "the storage class the claims are made from",
    );
    // A stabilization shorter than a drain, the controller's period and its recovery Job: 30 +
    // 300 + 600 seconds by default.
    refused(
        &with_controller(&AUTOSCALED.replace(
            "maxReplicas: 6 }",
            "maxReplicas: 6, scaleDownStabilizationSeconds: 929 }",
        )),
        "scaleDownStabilizationSeconds",
    );
    render(&with_controller(&AUTOSCALED.replace(
        "maxReplicas: 6 }",
        "maxReplicas: 6, scaleDownStabilizationSeconds: 930 }",
    )));
    // A schedule whose period the chart cannot read.
    refused(
        &with_controller(AUTOSCALED).replace(
            "drainController: { enabled: true,",
            "drainController: { enabled: true, schedule: \"0 * * * *\",",
        ),
        "the drain controller's period",
    );
}

#[test]
fn a_drain_job_deadline_shorter_than_a_drain_is_refused() {
    refused(
        &with_controller("  groups:\n    - name: billing\n      selector: plane/data/*\n").replace(
            "drainController: { enabled: true,",
            "drainController: { enabled: true, jobDeadlineSeconds: 89,",
        ),
        "every drain Job would end as a forced timeout",
    );
    render(
        &with_controller("  groups:\n    - name: billing\n      selector: plane/data/*\n").replace(
            "drainController: { enabled: true,",
            "drainController: { enabled: true, jobDeadlineSeconds: 90,",
        ),
    );
}

#[test]
fn nothing_may_reach_a_drain_job() {
    let rendered = render(&with_controller(
        "  groups:\n    - name: billing\n      selector: plane/data/*\n",
    ));
    let policy = rendered.get("NetworkPolicy", "permguard-data-plane-drain");
    assert_eq!(policy["spec"]["ingress"], json!([]));
    assert_eq!(
        policy["spec"]["podSelector"]["matchLabels"]["app.kubernetes.io/component"],
        "data-plane-drain"
    );
}

#[test]
fn an_autoscaled_persistent_group_renders_its_stabilization() {
    let rendered = render(&with_controller(AUTOSCALED));
    let hpa = rendered.get("HorizontalPodAutoscaler", "permguard-data-plane-billing");
    assert_eq!(hpa["spec"]["scaleTargetRef"]["kind"], "StatefulSet");
    assert_eq!(
        hpa["spec"]["behavior"]["scaleDown"],
        json!({
            "stabilizationWindowSeconds": 1200,
            "policies": [{ "type": "Pods", "value": 1, "periodSeconds": 1200 }]
        })
    );
}

#[test]
fn the_drain_controller_renders_a_fenced_recovery_job_and_least_privilege() {
    let rendered = render(&with_controller(
        "  groups:
    - name: billing
      selector: plane/data/zone/billing/*
    - name: edge
      selector: plane/data/zone/edge/*
      assurance: { profile: development }
      evidence: { mode: disabled }
      persistence: { enabled: false }
",
    ));
    // A stateless group keeps no claim: no Job, no CronJob.
    assert!(!rendered.has("ConfigMap", "permguard-data-plane-edge-drain-job"));
    assert!(!rendered.has("CronJob", "permguard-data-plane-edge-reclaim"));

    let template =
        rendered.get("ConfigMap", "permguard-data-plane-billing-drain-job")["data"]["job.json"]
            .as_str()
            .unwrap()
            .replace("__CLAIM__", "state-permguard-data-plane-billing-2")
            .replace("__JOB__", "permguard-data-plane-billing-drain-2")
            .replace("__ORDINAL__", "2");
    let job: Value = serde_json::from_str(&template).expect("the template is JSON");
    assert_eq!(job["kind"], "Job");
    assert_eq!(
        job["metadata"]["name"],
        "permguard-data-plane-billing-drain-2"
    );
    // One attempt, bounded: a Job its deadline ends is a forced timeout.
    assert_eq!(job["spec"]["backoffLimit"], 0);
    assert_eq!(job["spec"]["activeDeadlineSeconds"], 600);
    let pod = &job["spec"]["template"]["spec"];
    assert_eq!(pod["restartPolicy"], "Never");
    let state = pod["volumes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|volume| volume["name"] == "state")
        .unwrap();
    assert_eq!(
        state["persistentVolumeClaim"]["claimName"],
        "state-permguard-data-plane-billing-2"
    );
    // Fenced: its own claim generation first, then the same server as a recovery drain.
    assert_eq!(
        pod["initContainers"][0]["args"],
        json!([
            "volume",
            "claim",
            "--volume",
            "/var/lib/permguard/volume",
            "--next",
            "--create"
        ])
    );
    let env = pod["containers"][0]["env"].as_array().unwrap();
    assert!(env.contains(&json!({ "name": "PERMGUARD_SHUTDOWN_RECOVER_DRAIN", "value": "true" })));
    // The same group configuration, Host listener included.
    let volumes: Vec<&Value> = pod["volumes"].as_array().unwrap().iter().collect();
    assert!(
        volumes
            .iter()
            .any(|volume| volume["configMap"]["name"] == "permguard-data-plane-billing")
    );
    assert!(
        volumes
            .iter()
            .any(|volume| volume["secret"]["secretName"] == "data-plane-host")
    );
    // No Service and no group policy selects it: it serves nobody.
    let labels = &job["spec"]["template"]["metadata"]["labels"];
    let group_pods = &rendered.get("Service", "permguard-data-plane-billing")["spec"]["selector"];
    assert!(!selects(group_pods, labels));

    let cron = rendered.get("CronJob", "permguard-data-plane-billing-reclaim");
    assert_eq!(cron["spec"]["concurrencyPolicy"], "Forbid");
    let container = &cron["spec"]["jobTemplate"]["spec"]["template"]["spec"]["containers"][0];
    let args: Vec<&str> = container["args"]
        .as_array()
        .unwrap()
        .iter()
        .map(|arg| arg.as_str().unwrap())
        .collect();
    let after = |flag: &str| args[args.iter().position(|arg| *arg == flag).unwrap() + 1];
    assert_eq!(
        after("--host-endpoint"),
        "https://permguard-control-plane-host:5444"
    );
    assert_eq!(
        after("--selector"),
        "app.kubernetes.io/instance=permguard,app.kubernetes.io/component=data-plane,permguard.com/group=billing"
    );
    assert!(args.windows(2).any(|pair| pair == ["reclaim", "run"]));
    assert_eq!(
        cron["spec"]["jobTemplate"]["spec"]["template"]["spec"]["serviceAccountName"],
        "permguard-reclaim"
    );

    // The Role: exactly what the controller does, in this namespace.
    assert_eq!(
        rendered.get("Role", "permguard-reclaim")["rules"],
        json!([
            { "apiGroups": ["apps"], "resources": ["statefulsets"], "verbs": ["get", "list"] },
            { "apiGroups": [""], "resources": ["persistentvolumeclaims"], "verbs": ["get", "list", "delete"] },
            { "apiGroups": ["batch"], "resources": ["jobs"], "verbs": ["get", "list", "create", "delete"] },
            { "apiGroups": [""], "resources": ["pods"], "verbs": ["get", "list"] },
            { "apiGroups": [""], "resources": ["pods/log"], "verbs": ["get"] }
        ])
    );
    assert!(rendered.all("ClusterRole").is_empty());
}

#[test]
fn the_drain_controller_prerequisites_are_refused() {
    let groups = "  groups:\n    - name: billing\n      selector: plane/data/*\n";
    refused(
        &with_controller(groups).replace(
            "  hostListener: { enabled: true, tls: { secretName: data-plane-host } }\n",
            "",
        ),
        "needs dataPlane.hostListener",
    );
    refused(
        &with_controller(groups).replace("tls: { secretName: reclaim-operator }", ""),
        "names no Secret",
    );
    refused(
        &with_controller(groups).replace(
            "controlPlane:\n  hostListener: { enabled: true, tls: { secretName: control-plane-host } }\n",
            "",
        ),
        "names no coordinator",
    );
    refused(
        &with_controller(groups).replace(
            "drainController: { enabled: true,",
            "drainController: { enabled: true, coordinator: \"http://coordinator:5444\",",
        ),
        "over https only",
    );
    refused(
        &with_controller(
            "  groups:\n    - name: a-group-name-of-twenty-two\n      selector: plane/data/*\n",
        ),
        "at most 44 characters",
    );
}

#[test]
fn the_host_listener_serves_mutual_tls_from_its_secret() {
    let rendered = render(&with_controller(
        "  groups:\n    - name: billing\n      selector: plane/data/*\n",
    ));
    for (config, port) in [
        ("permguard-data-plane-billing", 5444),
        ("permguard-control-plane", 5444),
    ] {
        let admin = &rendered.config(config)["admin"];
        assert_eq!(admin["addr"], format!("0.0.0.0:{port}"));
        assert_eq!(
            admin["tls"],
            json!({
                "cert": "/etc/permguard-host-tls/tls.crt",
                "key": "/etc/permguard-host-tls/tls.key",
                "client_ca": "/etc/permguard-host-tls/ca.crt"
            })
        );
    }
    assert_eq!(
        rendered.config("permguard-control-plane")["admin"]["advertised_url"],
        "https://permguard-control-plane-host:5444"
    );
    let service = rendered.get("Service", "permguard-control-plane-host");
    assert_eq!(service["spec"]["ports"][0]["port"], 5444);
    let headless = rendered.get("Service", "permguard-data-plane-billing-headless");
    assert!(
        headless["spec"]["ports"]
            .as_array()
            .unwrap()
            .iter()
            .any(|port| port["name"] == "host")
    );
    let policy = &rendered.get("NetworkPolicy", "permguard-data-plane-billing")["spec"]["ingress"];
    assert_eq!(policy[2]["ports"][0]["port"], 5444);

    refused(
        "controlPlane:\n  hostListener: { enabled: true }\n",
        "names no tls.secretName",
    );
    refused(
        "\
controlPlane:
  hostListener: { enabled: true, tls: { secretName: h } }
  extraConfig: { admin: { addr: 0.0.0.0:1 } }
",
        "two sources of the Host listener",
    );
    refused(
        "controlPlane:\n  extraConfig: { telemetry: { addr: 0.0.0.0:1 } }\n",
        "the older spelling",
    );
    // The `host` section a values file adds merges with the one the chart renders.
    let rendered = render(
        "controlPlane:\n  extraConfig: { host: { principals: [{ san_uri: \"spiffe://acme/ops\" }] } }\n",
    );
    let host = &rendered.config("permguard-control-plane")["host"];
    assert_eq!(host["addr"], "0.0.0.0:5443");
    assert_eq!(host["principals"][0]["san_uri"], "spiffe://acme/ops");
}

#[test]
fn every_host_keeps_its_volume_in_a_directory_inside_the_mount_under_its_claim() {
    let env_of = |container: &Value| container["env"].as_array().unwrap().clone();
    let working_dir =
        json!({ "name": "PERMGUARD_WORKING_DIR", "value": "/var/lib/permguard/volume" });
    // The control plane, persistent: the claim first, the volume directory inside the mount.
    let rendered = render("persistence: { enabled: true }\n");
    let pod = &rendered.get("Deployment", "permguard-control-plane")["spec"]["template"]["spec"];
    assert_eq!(
        pod["initContainers"][0]["args"],
        json!([
            "volume",
            "claim",
            "--volume",
            "/var/lib/permguard/volume",
            "--next",
            "--create"
        ])
    );
    assert!(env_of(&pod["containers"][0]).contains(&working_dir));
    assert_eq!(
        rendered.config("permguard-control-plane")["working_dir"],
        "/var/lib/permguard/volume"
    );
    // Without a volume there is no claim to move, and the directory is still inside the mount.
    let rendered = render("{}\n");
    let pod = &rendered.get("Deployment", "permguard-control-plane")["spec"]["template"]["spec"];
    assert!(pod.get("initContainers").is_none());
    assert!(env_of(&pod["containers"][0]).contains(&working_dir));
    // The all-in-one, the same way.
    let rendered = render(
        "\
allInOne: { enabled: true, tls: { secretName: aio-tls } }
controlPlane: { enabled: false }
dataPlane: { enabled: false }
persistence: { enabled: true }
",
    );
    let pod = &rendered.get("Deployment", "permguard-all-in-one")["spec"]["template"]["spec"];
    assert_eq!(pod["initContainers"][0]["name"], "claim");
    assert!(env_of(&pod["containers"][0]).contains(&working_dir));
}

/// TS-5: every Host's configuration carries the release's storage, backup and objectives
/// declarations, a unit's `extraConfig` over them; every pod runs non-root, unprivileged, and the
/// kubelet applies the fsGroup to the mount's root only.
#[test]
fn every_host_declares_its_storage_backups_and_objectives_and_runs_non_root() {
    let rendered = render(TWO_GROUPS);
    for name in ["permguard-control-plane", "permguard-data-plane-billing"] {
        let config = rendered.config(name);
        assert_eq!(
            config["storage"]["qualified"][0]["evidence"], "QUAL-CI",
            "{name}"
        );
        assert_eq!(config["operations"]["backup"]["retention"], "90d", "{name}");
        assert_eq!(config["objectives"]["key_recovery_owner"], "ci", "{name}");
    }
    let pod =
        &rendered.get("StatefulSet", "permguard-data-plane-billing")["spec"]["template"]["spec"];
    assert_eq!(pod["securityContext"]["runAsNonRoot"], true);
    assert_eq!(pod["securityContext"]["runAsUser"], 65532);
    assert_eq!(
        pod["securityContext"]["fsGroupChangePolicy"],
        "OnRootMismatch"
    );
    let container = &pod["containers"][0]["securityContext"];
    assert_eq!(container["privileged"], false);
    assert_eq!(container["allowPrivilegeEscalation"], false);
    // A unit's own configuration wins over the release's.
    let own = render(
        "\
controlPlane:
  extraConfig: { objectives: { key_recovery_owner: platform-team } }
",
    );
    assert_eq!(
        own.config("permguard-control-plane")["objectives"]["key_recovery_owner"],
        "platform-team"
    );
}

/// TS-5: from `production` a Host without qualified storage is refused at render, as Bootstrap
/// refuses it; `production` accepts the published compatibility mode, `regulated` never; a
/// qualified entry names its encryption mechanism, revision and expiry.
#[test]
fn a_production_host_without_qualified_storage_is_refused() {
    refused(
        "\
hostControls:
  storage: { qualified: [] }
",
        "serves only on qualified storage",
    );
    // TS-5: the compatibility mode relaxes nothing from `production`.
    refused(
        "\
hostControls:
  storage: { compatibility_mode: \"true\", qualified: [] }
",
        "relaxes nothing from `production`",
    );
    refused(
        "\
hostControls:
  storage:
    qualified:
      - { storage_class: fast, driver: csi, filesystem: ext4, version: \"6.8\", evidence: Q-1, revision: \"1\", expires_at: \"2027-01-01T00:00:00Z\" }
",
        "names its encryption",
    );
    render(
        "\
hostControls:
  storage:
    qualified:
      - { storage_class: fast, driver: csi, filesystem: ext4, version: \"6.8\", evidence: Q-1, encryption: kms, revision: \"1\", expires_at: \"2027-01-01T00:00:00Z\" }
",
    );
    refused(
        "\
hostControls:
  storage: { qualified: [] }
controlPlane:
  assurance: { profile: regulated, custody: { provider: kms, kms: { address: \"https://kms\", tokenRef: t } } }
",
        "serves only on qualified storage",
    );
}

/// TS-5: from `production` a backup policy left incomplete, an objective left out, a root or
/// privileged pod, or the fsGroup re-applied at every remount is refused at render.
#[test]
fn a_production_host_missing_a_control_is_refused() {
    for (values, why) in [
        (
            "hostControls:\n  backup: { recovery_key: null }\n",
            "encrypts every backup under a recovery key",
        ),
        (
            "hostControls:\n  backup: { recovery_key: null, recovery_key_id: \"kms:x\" }\n",
            "a provider's recovery_key_id alone proves no key",
        ),
        (
            "hostControls:\n  backup: { destruction: null }\n",
            "hostControls.backup.destruction",
        ),
        (
            "hostControls:\n  objectives: { mirror_staleness: null }\n",
            "hostControls.objectives.mirror_staleness",
        ),
        (
            "podSecurityContext: { runAsUser: 0 }\n",
            "dedicated non-root user",
        ),
        (
            "podSecurityContext: { runAsNonRoot: false }\n",
            "dedicated non-root user",
        ),
        (
            "securityContext: { privileged: true }\n",
            "runs unprivileged",
        ),
        (
            "securityContext: { allowPrivilegeEscalation: true }\n",
            "runs unprivileged",
        ),
        (
            "podSecurityContext: { fsGroupChangePolicy: Always }\n",
            "fsGroupChangePolicy OnRootMismatch",
        ),
    ] {
        refused(values, why);
    }
    // Below `production` the Host reports what it would refuse, and the chart lets it.
    render(
        "\
controlPlane: { assurance: { profile: development } }
dataPlane: { groupDefaults: { assurance: { profile: development } }, groups: [ { name: dev, selector: plane/data/*, evidence: { mode: disabled }, persistence: { enabled: false } } ] }
hostControls: { storage: {}, backup: {}, objectives: {} }
",
    );
}
