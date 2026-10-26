// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! `permguard reclaim run`: the drain controller (TD-2).
//!
//! A data plane group that keeps a volume retains its claims when it scales down, because a claim
//! may hold evidence its replica did not ship. This command decides, claim by claim, what happens
//! to the retained claims of a group's ordinals above its replicas, and deletes one only on proof:
//!
//! ```text
//! retained claim, ordinal ≥ replicas, no Pod of that ordinal
//!   ─▶ no drain Job: create it (the group's own image and configuration, on this claim, under a
//!      new claim generation, `shutdown.recover_drain`)
//!   ─▶ Job running: wait
//!   ─▶ Job failed or timed out: keep the claim, say so — an incomplete drain never authorizes it
//!   ─▶ Job succeeded: read the claim generation its init container wrote and the receipt it
//!      printed; verify the receipt under the verification bundle and the member's pin the
//!      coordinator holds; ask the coordinator's frontier for every stream it names
//!   ─▶ every check holds, and the ordinal is still above the replicas with no Pod: delete the
//!      claim under its UID, then the Job
//! ```
//!
//! The receipt says what the volume held; the coordinator's frontier says it arrived. Anything
//! short of both keeps the claim, and the line printed for it says which check failed.

use std::path::PathBuf;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde_json::Value;

use permguard_host::api::drain::DrainReceiptExport;
use permguard_host::operations::drain::{self, DrainReceipt};

use crate::args::{Globals, ReclaimRun};
use crate::failure::Failure;
use crate::trace::Trace;

/// The name of the volume claim template the chart gives every stateful group.
const TEMPLATE: &str = "state";

/// The init container that moves the claim, and the container that serves, in a group's Pods.
const CLAIM_CONTAINER: &str = "claim";
const SERVER_CONTAINER: &str = "data-plane";

/// What the placeholder of the drain Job template is replaced by.
const CLAIM_PLACEHOLDER: &str = "__CLAIM__";
const JOB_PLACEHOLDER: &str = "__JOB__";
const ORDINAL_PLACEHOLDER: &str = "__ORDINAL__";

/// One group workload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Workload {
    pub name: String,
    pub replicas: u32,
}

/// One retained claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claim {
    pub name: String,
    pub uid: String,
    /// Already being deleted.
    pub deleting: bool,
}

/// Where a drain Job stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JobState {
    Running,
    Succeeded,
    /// Failed, or ended by its deadline: a forced timeout.
    Failed(String),
}

/// What this command asks of the cluster: the release's namespace, nothing else.
pub trait Cluster {
    fn workloads(&self, selector: &str) -> Result<Vec<Workload>, String>;
    fn workload(&self, name: &str) -> Result<Option<Workload>, String>;
    fn claims(&self, selector: &str) -> Result<Vec<Claim>, String>;
    fn pod_exists(&self, name: &str) -> Result<bool, String>;
    fn job(&self, name: &str) -> Result<Option<JobState>, String>;
    fn create_job(&self, manifest: &Value) -> Result<(), String>;
    /// The log of `container` in the Job's Pod.
    fn job_log(&self, job: &str, container: &str) -> Result<String, String>;
    /// Deletes the claim, only if it is still the one `uid` names.
    fn delete_claim(&self, name: &str, uid: &str) -> Result<(), String>;
    fn delete_job(&self, name: &str) -> Result<(), String>;
}

/// What this command asks of the coordinator the group's replicas ship to.
pub trait Coordinator {
    /// The first identity fingerprint the coordinator pins for the member Host `host_id` (UUID
    /// text), from its memberships; `None` when it holds no membership of that Host.
    fn pin_of(&self, host_id: &str) -> Result<Option<String>, String>;
    /// How far the coordinator acknowledges the run `run` of the producer `producer` (hex) of
    /// the stream `plane`/`stream_type` of `resource`; `None` when it holds no such run.
    fn acknowledged(
        &self,
        plane: &str,
        stream_type: &str,
        resource: &str,
        producer: &str,
        run: &str,
    ) -> Result<Option<u64>, String>;
}

/// What became of one claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// A Pod of that ordinal exists, or the ordinal is within the replicas again.
    InUse,
    /// Already being deleted by somebody.
    Deleting,
    /// Its drain Job was created.
    DrainStarted(String),
    /// Its drain Job is running.
    Draining(String),
    /// Kept: why.
    Kept(String),
    /// Deleted, its drain receipt and the coordinator's frontier having proven it shipped.
    Reclaimed { host_id: String, streams: usize },
}

impl Outcome {
    pub fn label(&self) -> &'static str {
        match self {
            Self::InUse => "in-use",
            Self::Deleting => "deleting",
            Self::DrainStarted(_) => "drain-started",
            Self::Draining(_) => "draining",
            Self::Kept(_) => "kept",
            Self::Reclaimed { .. } => "reclaimed",
        }
    }

    pub fn detail(&self) -> String {
        match self {
            Self::InUse => "a Pod of this ordinal exists, or the group needs it again".to_owned(),
            Self::Deleting => "already being deleted".to_owned(),
            Self::DrainStarted(job) => format!("the drain Job {job} is created"),
            Self::Draining(job) => format!("the drain Job {job} is running"),
            Self::Kept(why) => why.clone(),
            Self::Reclaimed { host_id, streams } => format!(
                "Host {host_id} drained: its receipt verifies and the coordinator acknowledges \
                 its {streams} stream run(s); the claim is deleted"
            ),
        }
    }
}

/// The ordinal of `claim` in `workload`: `state-<workload>-<n>`.
fn ordinal(claim: &str, workload: &str) -> Option<u32> {
    claim
        .strip_prefix(TEMPLATE)?
        .strip_prefix('-')?
        .strip_prefix(workload)?
        .strip_prefix('-')?
        .parse()
        .ok()
        .filter(|_| {
            // `state-<workload>-<n>` exactly: no other workload whose name extends this one.
            claim
                .rsplit_once('-')
                .is_some_and(|(head, _)| head == format!("{TEMPLATE}-{workload}"))
        })
}

/// The drain Job's name for one ordinal: within the 63 characters a label value takes.
pub fn job_name(workload: &str, ordinal: u32) -> String {
    format!("{workload}-drain-{ordinal}")
}

/// Runs one pass over every group `selector` names, answering each retained claim's outcome.
pub fn reclaim(
    cluster: &dyn Cluster,
    coordinator: &dyn Coordinator,
    selector: &str,
    template: &str,
) -> Result<Vec<(String, Outcome)>, String> {
    let mut outcomes = Vec::new();
    let claims = cluster.claims(selector)?;
    for workload in cluster.workloads(selector)? {
        for claim in &claims {
            let Some(ordinal) = ordinal(&claim.name, &workload.name) else {
                continue;
            };
            if ordinal < workload.replicas {
                continue;
            }
            let outcome = one(cluster, coordinator, &workload, claim, ordinal, template)
                .unwrap_or_else(Outcome::Kept);
            outcomes.push((claim.name.clone(), outcome));
        }
    }
    Ok(outcomes)
}

fn one(
    cluster: &dyn Cluster,
    coordinator: &dyn Coordinator,
    workload: &Workload,
    claim: &Claim,
    ordinal: u32,
    template: &str,
) -> Result<Outcome, String> {
    if claim.deleting {
        return Ok(Outcome::Deleting);
    }
    let pod = format!("{}-{ordinal}", workload.name);
    if cluster.pod_exists(&pod)? {
        return Ok(Outcome::InUse);
    }
    let job = job_name(&workload.name, ordinal);
    match cluster.job(&job)? {
        None => {
            let manifest = template
                .replace(CLAIM_PLACEHOLDER, &claim.name)
                .replace(JOB_PLACEHOLDER, &job)
                .replace(ORDINAL_PLACEHOLDER, &ordinal.to_string());
            let manifest: Value = serde_json::from_str(&manifest)
                .map_err(|error| format!("the drain Job template is not JSON: {error}"))?;
            cluster.create_job(&manifest)?;
            Ok(Outcome::DrainStarted(job))
        }
        Some(JobState::Running) => Ok(Outcome::Draining(job)),
        Some(JobState::Failed(why)) => Ok(Outcome::Kept(format!(
            "the drain Job {job} did not complete ({why}): an incomplete drain or a forced \
             timeout never authorizes deleting the claim; it keeps its evidence for a fenced \
             recovery"
        ))),
        Some(JobState::Succeeded) => {
            let proven = prove(cluster, coordinator, &job)?;
            let proven = match proven {
                Ok(proven) => proven,
                Err(why) => return Ok(Outcome::Kept(why)),
            };
            // Checked again right before the delete: the group may have scaled back up.
            let current = cluster
                .workload(&workload.name)?
                .ok_or_else(|| format!("the workload {} is gone", workload.name))?;
            if ordinal < current.replicas || cluster.pod_exists(&pod)? {
                return Ok(Outcome::InUse);
            }
            cluster.delete_claim(&claim.name, &claim.uid)?;
            cluster.delete_job(&job)?;
            Ok(Outcome::Reclaimed {
                host_id: proven.0,
                streams: proven.1,
            })
        }
    }
}

/// The proof a succeeded drain Job left: `Ok(Ok((host id, streams)))` when every check holds,
/// `Ok(Err(why))` when one does not.
fn prove(
    cluster: &dyn Cluster,
    coordinator: &dyn Coordinator,
    job: &str,
) -> Result<Result<(String, usize), String>, String> {
    let claimed = cluster.job_log(job, CLAIM_CONTAINER)?;
    let Some(claimed) = claimed_volume(&claimed) else {
        return Ok(Err(format!(
            "the drain Job {job} logged no claim of its volume: the receipt cannot be bound to it"
        )));
    };
    let served = cluster.job_log(job, SERVER_CONTAINER)?;
    let Some(export) = printed_receipt(&served) else {
        return Ok(Err(format!(
            "the drain Job {job} printed no drain receipt: its drain did not complete"
        )));
    };
    Ok(check(coordinator, &export, &claimed))
}

/// The volume and the generation the claim container's `volume claim` wrote:
/// `the volume at <path> (id <hex>) is claimed at generation <n> (was <m>)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claimed {
    pub volume_id: String,
    pub generation: u64,
}

fn claimed_volume(log: &str) -> Option<Claimed> {
    log.lines().rev().find_map(|line| {
        let (_, rest) = line.split_once(" (id ")?;
        let (volume_id, rest) = rest.split_once(") is claimed at generation ")?;
        let generation = rest.split_whitespace().next()?.parse().ok()?;
        (volume_id.len() == 32 && volume_id.bytes().all(|byte| byte.is_ascii_hexdigit())).then(
            || Claimed {
                volume_id: volume_id.to_owned(),
                generation,
            },
        )
    })
}

/// The receipt line a recovery drain printed.
fn printed_receipt(log: &str) -> Option<DrainReceiptExport> {
    log.lines().rev().find_map(|line| {
        let line = line.trim();
        if !line.starts_with("{\"drain_receipt\"") {
            return None;
        }
        let mut value: Value = serde_json::from_str(line).ok()?;
        serde_json::from_value(value.get_mut("drain_receipt")?.take()).ok()
    })
}

/// Checks one printed receipt: it verifies under the bundle and the pin the coordinator holds for
/// the Host it names, it is of the claim generation the Job's own claim wrote, and the coordinator
/// acknowledges every stream run it names through its last sequence.
pub fn check(
    coordinator: &dyn Coordinator,
    export: &DrainReceiptExport,
    job_claim: &Claimed,
) -> Result<(String, usize), String> {
    let decode = |text: &str, what: &str| {
        B64.decode(text)
            .map_err(|_| format!("the receipt's {what} is not base64url"))
    };
    let envelope = decode(&export.receipt, "envelope")?;
    let manifest = decode(&export.bundle.manifest, "bundle manifest")?;
    let items = export
        .bundle
        .items
        .iter()
        .map(|item| decode(item, "bundle item"))
        .collect::<Result<Vec<_>, _>>()?;
    // Which Host the receipt claims to be, read before it is verified only to find the pin to
    // verify it against: nothing else of it is trusted before the verification.
    let claimed = permguard_objects::cose::Sign1::decode(&envelope)
        .map_err(|error| format!("the receipt is not a signed envelope: {error}"))
        .and_then(|sign1| DrainReceipt::decode(sign1.payload_unverified()))?;
    let host_id = uuid_text(&claimed.host_id);
    let pin = coordinator.pin_of(&host_id)?.ok_or_else(|| {
        format!(
            "the coordinator holds no membership of Host {host_id}: nothing pins the identity \
             the receipt names"
        )
    })?;
    let receipt = drain::verify(&envelope, &manifest, &items, &pin)
        .map_err(|error| format!("the receipt of Host {host_id} does not verify: {error}"))?;
    if receipt.generation != job_claim.generation {
        return Err(format!(
            "the receipt is of claim generation {}, and the drain Job claimed {}: it is not this \
             run's",
            receipt.generation, job_claim.generation
        ));
    }
    if hex(&receipt.volume_id) != job_claim.volume_id {
        return Err(format!(
            "the receipt names volume {}, and the drain Job claimed volume {}: it is not this \
             claim's",
            hex(&receipt.volume_id),
            job_claim.volume_id
        ));
    }
    let producer = hex(&receipt.host_id);
    for stream in &receipt.streams {
        let acknowledged = coordinator.acknowledged(
            &stream.plane,
            &stream.stream_type,
            &stream.resource,
            &producer,
            &stream.run,
        )?;
        match acknowledged {
            Some(through) if through >= stream.last_seq => {}
            Some(through) => {
                return Err(format!(
                    "the coordinator acknowledges {}/{} of {} run {} through {through} of {}",
                    stream.plane, stream.stream_type, stream.resource, stream.run, stream.last_seq
                ));
            }
            None => {
                return Err(format!(
                    "the coordinator holds no run {} of {}/{} of {} from Host {host_id}",
                    stream.run, stream.plane, stream.stream_type, stream.resource
                ));
            }
        }
    }
    Ok((host_id, receipt.streams.len()))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A 16-byte id as a UUID's text.
fn uuid_text(bytes: &[u8; 16]) -> String {
    let hex = hex(bytes);
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

/// The coordinator, through its Host listener.
pub struct HostCoordinator(pub Box<dyn permguard_control_client::host::Host>);

impl Coordinator for HostCoordinator {
    fn pin_of(&self, host_id: &str) -> Result<Option<String>, String> {
        let members = self
            .0
            .members(None)
            .map_err(|failure| failure.to_string())?;
        Ok(members
            .members
            .into_iter()
            // Only a membership the coordinator approved and still holds active pins an identity:
            // a pending one was never approved, a suspended or revoked one may be why the claim
            // is in question (after the review).
            .find(|member| {
                member.role == "coordinator"
                    && member.status == "active"
                    && member.member.host_id == host_id
            })
            .map(|member| member.member.fingerprint))
    }

    fn acknowledged(
        &self,
        plane: &str,
        stream_type: &str,
        resource: &str,
        producer: &str,
        run: &str,
    ) -> Result<Option<u64>, String> {
        let frontier = self
            .0
            .stream_frontier(&permguard_control_client::host::StreamName {
                plane,
                stream_type,
                resource,
            })
            .map_err(|failure| failure.to_string())?;
        Ok(frontier
            .consumer
            .into_iter()
            .find(|held| held.producer == producer && held.run == run)
            .map(|held| held.acked))
    }
}

/// The Kubernetes API of the namespace this command runs in, as its ServiceAccount.
pub struct Kube {
    client: permguard_control_client::http::Client,
    endpoint: permguard_control_client::Endpoint,
    namespace: String,
}

/// Where the in-cluster credentials are mounted.
const SERVICE_ACCOUNT: &str = "/var/run/secrets/kubernetes.io/serviceaccount";

impl Kube {
    /// The in-cluster API, or the one `api` names (with `token_file` and `ca_file`).
    pub fn connect(
        namespace: Option<String>,
        api: Option<String>,
        token_file: Option<PathBuf>,
        ca_file: Option<PathBuf>,
    ) -> Result<Self, String> {
        let account = PathBuf::from(SERVICE_ACCOUNT);
        let url = match api {
            Some(api) => api,
            None => {
                let host = std::env::var("KUBERNETES_SERVICE_HOST")
                    .map_err(|_| "not in a cluster: name the API with --kube-api".to_owned())?;
                let port = std::env::var("KUBERNETES_SERVICE_PORT").unwrap_or("443".to_owned());
                if host.contains(':') {
                    format!("https://[{host}]:{port}")
                } else {
                    format!("https://{host}:{port}")
                }
            }
        };
        let namespace = match namespace {
            Some(namespace) => namespace,
            None => std::fs::read_to_string(account.join("namespace"))
                .map(|text| text.trim().to_owned())
                .map_err(|_| "no namespace: name it with --namespace".to_owned())?,
        };
        let endpoint =
            permguard_control_client::Endpoint::parse(&url).map_err(|error| error.to_string())?;
        let token_file = token_file.or_else(|| {
            let token = account.join("token");
            token.exists().then_some(token)
        });
        let ca_file = ca_file.or_else(|| {
            let ca = account.join("ca.crt");
            (endpoint.is_tls() && ca.exists()).then_some(ca)
        });
        let token = match token_file {
            Some(path) => Some(permguard_control_client::tls::Credential::new(
                std::fs::read_to_string(&path)
                    .map_err(|error| format!("reading {}: {error}", path.display()))?
                    .trim()
                    .as_bytes()
                    .to_vec(),
            )),
            None => None,
        };
        let tls = permguard_control_client::tls::TlsOptions {
            ca_file,
            token,
            ..Default::default()
        };
        let client = permguard_control_client::http::Client::new(
            std::time::Duration::from_secs(30),
            tls,
            endpoint.is_tls(),
        )
        .map_err(|error| error.to_string())?;
        Ok(Self {
            client,
            endpoint,
            namespace,
        })
    }

    fn call(
        &self,
        method: &str,
        path: &str,
        body: Option<&Value>,
    ) -> Result<(u16, String), String> {
        let body = body.map(Value::to_string);
        let answer = self
            .client
            .request(&self.endpoint, method, path, body.as_deref())
            .map_err(|error| format!("{method} {path}: {error}"))?;
        Ok((answer.status, answer.body))
    }

    fn json(&self, path: &str) -> Result<Option<Value>, String> {
        match self.call("GET", path, None)? {
            (404, _) => Ok(None),
            (200, body) => serde_json::from_str(&body)
                .map(Some)
                .map_err(|error| format!("GET {path}: not JSON: {error}")),
            (status, body) => Err(format!("GET {path}: {status} {}", short(&body))),
        }
    }

    fn ns(&self, group: &str, kind: &str) -> String {
        format!("{group}/namespaces/{}/{kind}", self.namespace)
    }
}

fn short(body: &str) -> &str {
    &body[..body.len().min(300)]
}

/// A label selector, as a query value.
fn query(selector: &str) -> String {
    selector
        .bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (byte as char).to_string()
            }
            other => format!("%{other:02X}"),
        })
        .collect()
}

fn workload_of(item: &Value) -> Option<Workload> {
    Some(Workload {
        name: item["metadata"]["name"].as_str()?.to_owned(),
        replicas: u32::try_from(item["spec"]["replicas"].as_u64().unwrap_or(1)).ok()?,
    })
}

impl Cluster for Kube {
    fn workloads(&self, selector: &str) -> Result<Vec<Workload>, String> {
        let path = format!(
            "/{}?labelSelector={}",
            self.ns("apis/apps/v1", "statefulsets"),
            query(selector)
        );
        let list = self.json(&path)?.ok_or("no StatefulSet API")?;
        Ok(list["items"]
            .as_array()
            .map(|items| items.iter().filter_map(workload_of).collect())
            .unwrap_or_default())
    }

    fn workload(&self, name: &str) -> Result<Option<Workload>, String> {
        let path = format!("/{}/{name}", self.ns("apis/apps/v1", "statefulsets"));
        Ok(self.json(&path)?.as_ref().and_then(workload_of))
    }

    fn claims(&self, selector: &str) -> Result<Vec<Claim>, String> {
        let path = format!(
            "/{}?labelSelector={}",
            self.ns("api/v1", "persistentvolumeclaims"),
            query(selector)
        );
        let list = self.json(&path)?.ok_or("no claim API")?;
        Ok(list["items"]
            .as_array()
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| {
                        Some(Claim {
                            name: item["metadata"]["name"].as_str()?.to_owned(),
                            uid: item["metadata"]["uid"].as_str()?.to_owned(),
                            deleting: !item["metadata"]["deletionTimestamp"].is_null(),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default())
    }

    fn pod_exists(&self, name: &str) -> Result<bool, String> {
        let path = format!("/{}/{name}", self.ns("api/v1", "pods"));
        Ok(self.json(&path)?.is_some())
    }

    fn job(&self, name: &str) -> Result<Option<JobState>, String> {
        let path = format!("/{}/{name}", self.ns("apis/batch/v1", "jobs"));
        let Some(job) = self.json(&path)? else {
            return Ok(None);
        };
        let conditions = job["status"]["conditions"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        let holds = |kind: &str| {
            conditions
                .iter()
                .find(|condition| condition["type"] == kind && condition["status"] == "True")
        };
        if holds("Complete").is_some() {
            return Ok(Some(JobState::Succeeded));
        }
        if let Some(failed) = holds("Failed") {
            return Ok(Some(JobState::Failed(
                failed["reason"].as_str().unwrap_or("Failed").to_owned(),
            )));
        }
        Ok(Some(JobState::Running))
    }

    fn create_job(&self, manifest: &Value) -> Result<(), String> {
        let path = format!("/{}", self.ns("apis/batch/v1", "jobs"));
        match self.call("POST", &path, Some(manifest))? {
            (200..=202, _) => Ok(()),
            (status, body) => Err(format!("creating the drain Job: {status} {}", short(&body))),
        }
    }

    fn job_log(&self, job: &str, container: &str) -> Result<String, String> {
        let path = format!(
            "/{}?labelSelector={}",
            self.ns("api/v1", "pods"),
            query(&format!("job-name={job}"))
        );
        let pods = self.json(&path)?.ok_or("no Pod API")?;
        // The Job runs one Pod at a time and never retries (`backoffLimit: 0`): the newest is it.
        let pod = pods["items"]
            .as_array()
            .and_then(|items| {
                items.iter().max_by_key(|item| {
                    item["metadata"]["creationTimestamp"]
                        .as_str()
                        .unwrap_or_default()
                        .to_owned()
                })
            })
            .and_then(|item| item["metadata"]["name"].as_str())
            .ok_or_else(|| format!("the drain Job {job} has no Pod"))?
            .to_owned();
        let path = format!(
            "/{}/{pod}/log?container={container}&tailLines=2000",
            self.ns("api/v1", "pods")
        );
        match self.call("GET", &path, None)? {
            (200, body) => Ok(body),
            (status, body) => Err(format!("GET {path}: {status} {}", short(&body))),
        }
    }

    fn delete_claim(&self, name: &str, uid: &str) -> Result<(), String> {
        let path = format!("/{}/{name}", self.ns("api/v1", "persistentvolumeclaims"));
        let options = serde_json::json!({
            "kind": "DeleteOptions",
            "apiVersion": "v1",
            "preconditions": { "uid": uid },
        });
        match self.call("DELETE", &path, Some(&options))? {
            (200 | 202, _) => Ok(()),
            (status, body) => Err(format!("deleting {name}: {status} {}", short(&body))),
        }
    }

    fn delete_job(&self, name: &str) -> Result<(), String> {
        let path = format!("/{}/{name}", self.ns("apis/batch/v1", "jobs"));
        let options = serde_json::json!({
            "kind": "DeleteOptions",
            "apiVersion": "v1",
            "propagationPolicy": "Background",
        });
        match self.call("DELETE", &path, Some(&options))? {
            (200 | 202 | 404, _) => Ok(()),
            (status, body) => Err(format!("deleting {name}: {status} {}", short(&body))),
        }
    }
}

/// `permguard reclaim run`.
pub fn run(
    globals: &Globals,
    trace: &Trace,
    args: ReclaimRun,
) -> Result<std::process::ExitCode, Failure> {
    let template = std::fs::read_to_string(&args.job_template).map_err(|error| {
        Failure::usage(format!(
            "--job-template {}: {error}",
            args.job_template.display()
        ))
    })?;
    let cluster = Kube::connect(
        args.namespace,
        args.kube_api,
        args.kube_token_file,
        args.kube_ca,
    )
    .map_err(Failure::usage)?;
    let coordinator = HostCoordinator(super::host::online_host(globals, trace, false)?);
    let outcomes =
        reclaim(&cluster, &coordinator, &args.selector, &template).map_err(Failure::usage)?;
    let mut kept = false;
    for (claim, outcome) in &outcomes {
        kept |= matches!(outcome, Outcome::Kept(_));
        println!(
            "{}",
            serde_json::json!({
                "claim": claim,
                "outcome": outcome.label(),
                "detail": outcome.detail(),
            })
        );
    }
    // Keeping a claim is the answer when the proof is missing, not a failure of this run.
    let _ = kept;
    Ok(std::process::ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests;
