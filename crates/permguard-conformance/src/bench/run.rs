// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! One benchmark run, end to end: probe the machine, start the server once per evidence mode, apply
//! the dataset, climb the ladder on every interface and workload, and write what was measured.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use super::load::{self, Target};
use super::report::{self, Build, Configuration, Measurement, Report, Run, Slo, Storage};
use super::server::{self, Binaries};

/// The settings a report records the value of, capacity first.
pub const CAPACITY_SETTINGS: [&str; 8] = [
    "PERMGUARD_EVALUATION_CONCURRENCY",
    "PERMGUARD_EVALUATION_QUEUE",
    "PERMGUARD_MAX_BLOCKING",
    "PERMGUARD_LIMITS_CONCURRENT_REQUESTS",
    "PERMGUARD_LIMITS_REQUEST_TIMEOUT",
    "PERMGUARD_LIMITS_CONNECTIONS",
    "PERMGUARD_LIMITS_CONNECTIONS_PER_PEER",
    "PERMGUARD_AUTHZ_MAX_EVALUATIONS",
];

/// The memory budgets a report records the value of.
pub const MEMORY_SETTINGS: [&str; 8] = [
    "PERMGUARD_AUTHZ_CACHE_PARTITIONS",
    "PERMGUARD_AUTHZ_CACHE_BYTES",
    "PERMGUARD_AUTHZ_CACHE_ZONE_PARTITIONS",
    "PERMGUARD_AUTHZ_CACHE_ZONE_BYTES",
    "PERMGUARD_EVENTS_WARM_BYTES",
    "PERMGUARD_EVENTS_WARM_ZONE_BYTES",
    "PERMGUARD_EVENTS_WARM_PARTITION_BYTES",
    "PERMGUARD_DECISIONS_LOG_SPOOL_BYTES",
];

/// What a run is asked to do.
#[derive(Debug, Clone)]
pub struct Options {
    pub binaries: Binaries,
    /// The example workspace the dataset is, and the name the report gives it.
    pub example: PathBuf,
    pub dataset_name: String,
    /// The languages the example's workspace is initialized with.
    pub languages: String,
    /// The storage class of `directory`, as the operator of the run declares it.
    pub storage_class: String,
    /// Where the servers' volumes live: on the storage being measured.
    pub directory: PathBuf,
    pub ladder: Vec<usize>,
    pub step: Duration,
    pub warmup: Duration,
    pub slo: Slo,
    pub interfaces: Vec<String>,
    pub evidence: Vec<String>,
    /// Capacity settings passed to the server, by environment name.
    pub settings: BTreeMap<String, String>,
    pub revision: Option<String>,
}

/// The value in force of each of `keys`: what the run set, what every run sets, or this build's
/// default.
fn in_force(keys: &[&str], settings: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    let mut passed: BTreeMap<String, String> = server::defaults()
        .iter()
        .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
        .collect();
    passed.extend(settings.clone());
    let settings = &passed;
    let defaults: BTreeMap<String, String> = permguard_core::Config::default()
        .effective_settings()
        .into_iter()
        .filter_map(|setting| setting.value.map(|value| (setting.key, value)))
        .collect();
    keys.iter()
        .map(|key| {
            let value = settings
                .get(*key)
                .or_else(|| defaults.get(*key))
                .cloned()
                .unwrap_or_else(|| "unset".to_owned());
            ((*key).to_owned(), value)
        })
        .collect()
}

/// The release binary's own version line.
fn version(binaries: &Binaries) -> String {
    std::process::Command::new(&binaries.server)
        .arg("--version")
        .output()
        .ok()
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .filter(|version| !version.is_empty())
        .unwrap_or_else(|| "unknown".to_owned())
}

/// Runs the benchmark. `progress` hears a line per step.
pub fn run(options: &Options, progress: &mut dyn FnMut(&str)) -> Result<Report, String> {
    std::fs::create_dir_all(&options.directory).map_err(|error| error.to_string())?;
    let dataset = server::dataset(&options.example, &options.dataset_name)?;
    let platform = super::probe::platform();
    let storage = Storage {
        class: options.storage_class.clone(),
        fsync_probe: super::probe::fsync(&options.directory, 200)
            .map_err(|error| format!("probing the storage: {error}"))?,
    };
    progress(&format!(
        "{} on {} {} ({} cores), storage `{}`: fsync p50 {} µs, p99 {} µs",
        options.dataset_name,
        platform.os,
        platform.arch,
        platform.logical_cores,
        storage.class,
        storage.fsync_probe.p50_us,
        storage.fsync_probe.p99_us
    ));
    let mut runs = Vec::new();
    for evidence in &options.evidence {
        let directory = options.directory.join(format!("server-{evidence}"));
        let server = server::start(&options.binaries, &directory, evidence, &options.settings)?;
        server::apply(
            &options.binaries,
            &server,
            &options.example,
            &options.languages,
        )
        .map_err(|error| format!("{error}\n{}", server.log_tail()))?;
        let process = super::probe::Process::new(server.pid());
        for interface in &options.interfaces {
            let target = Target {
                interface: interface.clone(),
                http: server.data_http.clone(),
                grpc: server.data_grpc.clone(),
            };
            for workload in &dataset.workloads {
                let requests = load::requests(&options.example, workload)?;
                load::wait_serving(&target, &requests, Duration::from_secs(120))
                    .map_err(|error| format!("{error}\n{}", server.log_tail()))?;
                // Warm: every partition compiled and every client path exercised; discarded.
                load::step(&target, &requests, 2, options.warmup, None)?;
                let mut steps = Vec::new();
                for &concurrency in &options.ladder {
                    let step = load::step(
                        &target,
                        &requests,
                        concurrency,
                        options.step,
                        Some(&process),
                    )?;
                    progress(&format!(
                        "{interface} {evidence} {}: c={concurrency} ok={} refused={} errors={} p50={:.2}ms p99={:.2}ms {:.0} rps",
                        workload.name,
                        step.ok,
                        step.refused,
                        step.errors,
                        step.latency_ms.p50,
                        step.latency_ms.p99,
                        step.throughput_rps
                    ));
                    steps.push(step);
                }
                runs.push(Run {
                    interface: interface.clone(),
                    evidence: evidence.clone(),
                    workload: workload.name.clone(),
                    refusal_point: report::refusal_point(&steps),
                    steps,
                });
            }
        }
        drop(server);
    }
    let capacity = report::capacity(&runs, &options.slo);
    Ok(Report {
        schema: report::SCHEMA.to_owned(),
        build: Build {
            version: version(&options.binaries),
            revision: options.revision.clone(),
        },
        platform,
        storage,
        dataset,
        configuration: Configuration {
            assurance_profile: "development".to_owned(),
            transport: "plaintext on loopback".to_owned(),
            authentication: "none: the run grants `decision.evaluate` to every caller".to_owned(),
            process: "permguard-all-in-one, Control and Data Planes in one process".to_owned(),
            settings: in_force(&CAPACITY_SETTINGS, &options.settings),
            memory_budgets: in_force(&MEMORY_SETTINGS, &options.settings),
        },
        measurement: Measurement {
            model: "closed loop, one connection per client".to_owned(),
            clients: "on the same host as the server, one thread each".to_owned(),
            client_timeout_seconds: load::CLIENT_TIMEOUT.as_secs_f64(),
            step_seconds: options.step.as_secs_f64(),
            warmup_seconds: options.warmup.as_secs_f64(),
            process_method: super::probe::method().to_owned(),
        },
        runs,
        slo: options.slo.clone(),
        capacity,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_a_setting_the_run_passed_wins_over_the_builds_default() {
        let mut settings = BTreeMap::new();
        settings.insert("PERMGUARD_MAX_BLOCKING".to_owned(), "7".to_owned());
        let values = in_force(&CAPACITY_SETTINGS, &settings);
        assert_eq!(values["PERMGUARD_MAX_BLOCKING"], "7");
        // What every run passes is what was in force, unless the run said otherwise.
        assert_eq!(values["PERMGUARD_LIMITS_CONNECTIONS_PER_PEER"], "0");
        settings.insert(
            "PERMGUARD_LIMITS_CONNECTIONS_PER_PEER".to_owned(),
            "9".to_owned(),
        );
        let values = in_force(&CAPACITY_SETTINGS, &settings);
        assert_eq!(values["PERMGUARD_LIMITS_CONNECTIONS_PER_PEER"], "9");
        // The others read back as this build renders them, never as an empty value.
        for key in CAPACITY_SETTINGS.iter().chain(MEMORY_SETTINGS.iter()) {
            let values = in_force(&[key], &BTreeMap::new());
            assert_ne!(values[*key], "unset", "{key} has no default in force");
        }
    }
}
