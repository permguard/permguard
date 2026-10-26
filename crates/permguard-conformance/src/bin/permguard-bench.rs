// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! `permguard-bench`: the release benchmark (TS-3), and the capacity a deployment reads off a report.
//!
//! ```text
//! permguard-bench run --server target/release/permguard-all-in-one --cli target/release/permguard \
//!     --storage-class "github-hosted runner, ephemeral SSD" --out permguard-benchmark.json
//! permguard-bench capacity permguard-benchmark.json
//! permguard-bench gate --server target/release/permguard-all-in-one --cli target/release/permguard \
//!     --out permguard-gate.json
//! ```

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand};

use permguard_conformance::bench::report::{Report, Slo};
use permguard_conformance::bench::run::{Options, run};
use permguard_conformance::bench::server::{Binaries, EVIDENCE_MODES};

#[derive(Parser)]
#[command(name = "permguard-bench", about = "The Permguard release benchmark.")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Measures the release binaries and writes the report.
    Run(Box<RunArgs>),
    /// Prints the capacity settings a report allows, per interface and evidence mode; fails when
    /// any of them sustained no step of the ladder within the objective.
    Capacity {
        /// The report to read.
        report: PathBuf,
    },
    /// The serving gate (TS-4): the candidate meets its objective with its headroom, refuses
    /// typed within bounds past its request bound, and reaches no network from a decision.
    Gate(Box<GateArgs>),
}

#[derive(clap::Args)]
struct GateArgs {
    /// The candidate's `permguard-all-in-one`.
    #[arg(long)]
    server: PathBuf,
    /// The candidate's `permguard` CLI.
    #[arg(long)]
    cli: PathBuf,
    #[arg(long, default_value = "examples/basics")]
    example: PathBuf,
    #[arg(long)]
    directory: Option<PathBuf>,
    #[arg(long, default_value = "bench/slo.json")]
    slo: PathBuf,
    #[arg(long, value_delimiter = ',', default_value = "http,grpc")]
    interfaces: Vec<String>,
    #[arg(long, value_delimiter = ',', default_value = "disabled,required")]
    evidence: Vec<String>,
    #[arg(long, default_value_t = 5.0)]
    step_seconds: f64,
    #[arg(long, default_value_t = 2.0)]
    warmup_seconds: f64,
    /// Where the verdict is written.
    #[arg(long)]
    out: PathBuf,
}

#[derive(clap::Args)]
struct RunArgs {
    /// The `permguard-all-in-one` binary to measure.
    #[arg(long)]
    server: PathBuf,
    /// The `permguard` CLI that applies the dataset.
    #[arg(long)]
    cli: PathBuf,
    /// The example workspace the dataset is.
    #[arg(long, default_value = "examples/basics")]
    example: PathBuf,
    /// What the volume's storage is, as the operator of the run knows it.
    #[arg(long)]
    storage_class: String,
    /// Where the servers' volumes live: on the storage being measured.
    #[arg(long)]
    directory: Option<PathBuf>,
    /// The offered concurrencies, in order.
    #[arg(
        long,
        value_delimiter = ',',
        default_value = "1,2,4,8,16,32,64,128,256,512"
    )]
    ladder: Vec<usize>,
    /// Seconds per step.
    #[arg(long, default_value_t = 10.0)]
    step_seconds: f64,
    /// Seconds of discarded warm-up per workload.
    #[arg(long, default_value_t = 3.0)]
    warmup_seconds: f64,
    /// The published objective.
    #[arg(long, default_value = "bench/slo.json")]
    slo: PathBuf,
    #[arg(long, value_delimiter = ',', default_value = "http,grpc")]
    interfaces: Vec<String>,
    #[arg(long, value_delimiter = ',', default_value = "disabled,required")]
    evidence: Vec<String>,
    /// A capacity setting for the server, `NAME=VALUE`, repeatable.
    #[arg(long = "set", value_name = "NAME=VALUE")]
    settings: Vec<String>,
    /// The source revision measured.
    #[arg(long)]
    revision: Option<String>,
    /// Where the report is written.
    #[arg(long)]
    out: PathBuf,
}

fn main() -> ExitCode {
    match Cli::parse().command {
        Command::Run(args) => match measure(*args) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("permguard-bench: {error}");
                ExitCode::FAILURE
            }
        },
        Command::Capacity { report } => match capacity(&report) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("permguard-bench: {error}");
                ExitCode::FAILURE
            }
        },
        Command::Gate(args) => match serving_gate(*args) {
            Ok(true) => ExitCode::SUCCESS,
            Ok(false) => {
                eprintln!("permguard-bench: the serving gate failed");
                ExitCode::FAILURE
            }
            Err(error) => {
                eprintln!("permguard-bench: {error}");
                ExitCode::FAILURE
            }
        },
    }
}

fn serving_gate(args: GateArgs) -> Result<bool, String> {
    let slo = Slo::parse(
        &std::fs::read_to_string(&args.slo)
            .map_err(|error| format!("{}: {error}", args.slo.display()))?,
    )
    .map_err(|error| format!("{}: {error}", args.slo.display()))?;
    let dataset = permguard_conformance::bench::server::dataset(&args.example, "")?;
    let mut languages: Vec<String> = dataset
        .workloads
        .iter()
        .flat_map(|workload| workload.runtimes.clone())
        .collect();
    languages.sort();
    languages.dedup();
    let defaulted = args.directory.is_none();
    let directory = args.directory.clone().unwrap_or_else(|| {
        std::env::temp_dir().join(format!("permguard-gate-{}", std::process::id()))
    });
    let options = permguard_conformance::bench::gate::Options {
        binaries: Binaries {
            server: args.server,
            cli: args.cli,
        },
        example: args.example,
        languages: languages.join(","),
        directory: directory.clone(),
        slo,
        interfaces: args.interfaces,
        evidence: args.evidence,
        step: Duration::from_secs_f64(args.step_seconds),
        warmup: Duration::from_secs_f64(args.warmup_seconds),
    };
    let verdict =
        permguard_conformance::bench::gate::gate(&options, &mut |line| eprintln!("{line}"))?;
    let mut text = serde_json::to_string_pretty(&verdict).map_err(|error| error.to_string())?;
    text.push('\n');
    std::fs::write(&args.out, text).map_err(|error| format!("{}: {error}", args.out.display()))?;
    if defaulted {
        let _ = std::fs::remove_dir_all(&directory);
    }
    Ok(verdict.passed)
}

fn measure(args: RunArgs) -> Result<(), String> {
    if let Some(unknown) = args
        .evidence
        .iter()
        .find(|mode| !EVIDENCE_MODES.contains(&mode.as_str()))
    {
        return Err(format!("no evidence mode `{unknown}`"));
    }
    if args.ladder.is_empty() || args.ladder.contains(&0) {
        return Err("the ladder is one or more concurrencies above zero".to_owned());
    }
    let slo = Slo::parse(
        &std::fs::read_to_string(&args.slo)
            .map_err(|error| format!("{}: {error}", args.slo.display()))?,
    )
    .map_err(|error| format!("{}: {error}", args.slo.display()))?;
    let mut settings = BTreeMap::new();
    for setting in &args.settings {
        let (name, value) = setting
            .split_once('=')
            .filter(|(name, _)| name.starts_with("PERMGUARD_"))
            .ok_or_else(|| format!("`{setting}` is not PERMGUARD_NAME=VALUE"))?;
        settings.insert(name.to_owned(), value.to_owned());
    }
    let dataset = permguard_conformance::bench::server::dataset(&args.example, "")?;
    let mut languages: Vec<String> = dataset
        .workloads
        .iter()
        .flat_map(|workload| workload.runtimes.clone())
        .collect();
    languages.sort();
    languages.dedup();
    let defaulted = args.directory.is_none();
    let directory = args.directory.clone().unwrap_or_else(|| {
        std::env::temp_dir().join(format!("permguard-bench-{}", std::process::id()))
    });
    let options = Options {
        binaries: Binaries {
            server: args.server,
            cli: args.cli,
        },
        dataset_name: args.example.to_string_lossy().into_owned(),
        example: args.example,
        languages: languages.join(","),
        storage_class: args.storage_class,
        directory: directory.clone(),
        ladder: args.ladder,
        step: Duration::from_secs_f64(args.step_seconds),
        warmup: Duration::from_secs_f64(args.warmup_seconds),
        slo,
        interfaces: args.interfaces,
        evidence: args.evidence,
        settings,
        revision: args.revision,
    };
    let report = run(&options, &mut |line| eprintln!("{line}"))?;
    let mut text = serde_json::to_string_pretty(&report).map_err(|error| error.to_string())?;
    text.push('\n');
    std::fs::write(&args.out, text).map_err(|error| format!("{}: {error}", args.out.display()))?;
    // Only a directory the run chose itself is removed: one an operator named stays theirs.
    if defaulted {
        let _ = std::fs::remove_dir_all(&directory);
    }
    eprintln!("report written to {}", args.out.display());
    Ok(())
}

fn capacity(path: &PathBuf) -> Result<(), String> {
    let report: Report = serde_json::from_str(
        &std::fs::read_to_string(path).map_err(|error| format!("{}: {error}", path.display()))?,
    )
    .map_err(|error| format!("{}: {error}", path.display()))?;
    if report.schema != permguard_conformance::bench::report::SCHEMA {
        return Err(format!("`{}` is not a benchmark report", report.schema));
    }
    println!(
        "measured on {} {} ({} cores), storage `{}`, {} — headroom {:.0}%",
        report.platform.os,
        report.platform.arch,
        report.platform.logical_cores,
        report.storage.class,
        report.build.version,
        report.slo.headroom * 100.0
    );
    let mut unsustained = Vec::new();
    for capacity in &report.capacity {
        match capacity.recommended_concurrent_requests {
            Some(limit) => println!(
                "{} {}: sustained {}{} concurrent within the objective; PERMGUARD_LIMITS_CONCURRENT_REQUESTS={limit}",
                capacity.interface,
                capacity.evidence,
                if capacity.ladder_exhausted {
                    "at least "
                } else {
                    ""
                },
                capacity.sustained_concurrency.unwrap_or_default()
            ),
            None => {
                println!(
                    "{} {}: no step met the objective on this platform",
                    capacity.interface, capacity.evidence
                );
                unsustained.push(format!("{} {}", capacity.interface, capacity.evidence));
            }
        }
    }
    if unsustained.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "no capacity within the objective for {}",
            unsustained.join(", ")
        ))
    }
}
